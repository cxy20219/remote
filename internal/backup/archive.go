package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// member 是待打包的一个文件。included 的文件都会先整份读进内存再算 sha256，
// 这样 manifest 可以在写下第一个 tar 成员之前就完整生成。
type member struct {
	path string
	data []byte
	mode os.FileMode
}

// checksumFile 流式计算文件 sha256 与大小。
func checksumFile(path string) (sum string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err = io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// writeChecksumSidecar 写独立的 .sha256 文件（sha256sum 兼容格式）。
func writeChecksumSidecar(archivePath, sum string) error {
	path := archivePath + ".sha256"
	content := fmt.Sprintf("%s  %s\n", sum, filepath.Base(archivePath))
	return writeFileAtomic(path, []byte(content), 0o644)
}

// verifyArchiveChecksum 在解包之前先核对整包 sha256。
//
// 没有 .sha256 就拒绝恢复：没有它，「这个包是不是原样」只能靠 manifest 里的
// 逐文件哈希，而 manifest 本身就在包里——篡改者可以连它一起改。
func verifyArchiveChecksum(archivePath string) (string, error) {
	sidecar := archivePath + ".sha256"
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%s not found: refusing to restore an archive that cannot be verified (keep the .sha256 next to the archive)", sidecar)
		}
		return "", err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s is empty", sidecar)
	}
	want := strings.ToLower(fields[0])
	if len(fields) > 1 {
		if name := fields[1]; name != filepath.Base(archivePath) {
			return "", fmt.Errorf("%s describes %q, not %q", sidecar, name, filepath.Base(archivePath))
		}
	}
	got, _, err := checksumFile(archivePath)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("%s does not match %s (want %s, got %s); the archive was modified or corrupted",
			filepath.Base(archivePath), sidecar, want, got)
	}
	return got, nil
}

// writeArchive 原子写出归档：manifest.json 第一个成员，其余按路径排序，
// 写 tmp → fsync → rename → fsync 目录。
func writeArchive(archivePath string, manifestBytes []byte, members []member, now time.Time) (err error) {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		return err
	}
	ordered := append([]member(nil), members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })

	tmp := archivePath + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	discard := func(cause error) error {
		file.Close()
		os.Remove(tmp)
		return cause
	}

	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)

	writeEntry := func(name string, data []byte, mode os.FileMode) error {
		header := &tar.Header{
			Name:     name,
			Mode:     int64(mode.Perm()),
			Size:     int64(len(data)),
			ModTime:  now.UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		_, err := tarWriter.Write(data)
		return err
	}

	if err := writeEntry(ManifestPath, manifestBytes, 0o600); err != nil {
		return discard(err)
	}
	for _, entry := range ordered {
		if err := writeEntry(entry.path, entry.data, entry.mode); err != nil {
			return discard(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return discard(err)
	}
	if err := gzipWriter.Close(); err != nil {
		return discard(err)
	}
	if err := file.Sync(); err != nil {
		return discard(err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, archivePath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readArchive 把归档解到 destDir，返回 manifest 与「实际解出了哪些路径」。
//
// 防御点全部在这里：第一个成员必须是 manifest.json；路径必须命中白名单；
// 不允许重复成员、符号链接、目录项、大小超限。解包阶段就拒绝，绝不先落地再检查。
func readArchive(archivePath, destDir string) (Manifest, map[string]bool, error) {
	var manifest Manifest

	file, err := os.Open(archivePath)
	if err != nil {
		return manifest, nil, err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return manifest, nil, fmt.Errorf("%s is not a gzip archive: %w", filepath.Base(archivePath), err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	extracted := make(map[string]bool)
	haveManifest := false
	first := true
	var total int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, nil, fmt.Errorf("read archive: %w", err)
		}

		if first {
			if header.Name != ManifestPath {
				return manifest, nil, fmt.Errorf("not a goremote backup: the first member is %q, want %q", header.Name, ManifestPath)
			}
			first = false
		}
		if err := validateMemberPath(header.Name); err != nil {
			return manifest, nil, err
		}
		if extracted[header.Name] {
			return manifest, nil, fmt.Errorf("archive contains %q more than once", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			return manifest, nil, fmt.Errorf("archive entry %q is not a regular file", header.Name)
		}
		if header.Size < 0 || header.Size > maxMemberBytes {
			return manifest, nil, fmt.Errorf("archive entry %q is %d bytes, over the %d byte limit", header.Name, header.Size, maxMemberBytes)
		}
		total += header.Size
		if total > maxTotalBytes {
			return manifest, nil, fmt.Errorf("archive expands to more than %d bytes", maxTotalBytes)
		}

		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size))
		if err != nil {
			return manifest, nil, fmt.Errorf("read archive entry %q: %w", header.Name, err)
		}
		if int64(len(data)) != header.Size {
			return manifest, nil, fmt.Errorf("archive entry %q is truncated", header.Name)
		}
		extracted[header.Name] = true

		if header.Name == ManifestPath {
			if err := json.Unmarshal(data, &manifest); err != nil {
				return manifest, nil, fmt.Errorf("parse manifest.json: %w", err)
			}
			haveManifest = true
			continue
		}

		target := filepath.Join(destDir, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return manifest, nil, err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return manifest, nil, fmt.Errorf("extract %q: %w", header.Name, err)
		}
	}

	if !haveManifest {
		return manifest, nil, fmt.Errorf("archive has no %s", ManifestPath)
	}
	return manifest, extracted, nil
}

// writeFileAtomic 写 tmp → fsync → rename，用于密钥文件与校验和这类
// 「要么是旧内容、要么是完整新内容」的小文件。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	// OpenFile 的权限只在创建时生效，残留的 .tmp 可能带着旧权限。
	if err := file.Chmod(mode); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
