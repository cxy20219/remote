package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"goremote/internal/backup"
)

// 退出码：0 成功，1 执行失败，2 用法错误。恢复脚本靠它判断能不能继续。
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const backupUsage = `usage: goremote-server backup --data DIR --certs DIR --out DIR [options]

Writes goremote-backup-<UTC>.tar.gz plus a .sha256 sidecar into --out.
The archive always contains data/server-state.json, the optional
data/blacklist.json, and the TLS keypair from --certs.

  --include-key         also pack the state key (requires --state-env-file);
                        the file name gets a .with-key marker
  --state-env-file FILE 0600 file holding GOREMOTE_STATE_KEY=...
  --allow-plaintext     allow backing up a state file that is not encrypted
`

const restoreUsage = `usage: goremote-server restore --from ARCHIVE [options]

Validates the whole archive, loads the state offline, then swaps the data
directory atomically. The previous data dir is kept as data.bak-<UTC>.

  --data DIR            target data directory (default ./data)
  --certs DIR           target certs directory (default ./certs)
  --key-file FILE       0600 file holding the state key (or set GOREMOTE_STATE_KEY)
  --install-key         write the archived state key to --state-env-file
  --state-env-file FILE destination for --install-key; refuses to overwrite
                        a different existing key
  --restore-certs       also replace the certs directory
  --dry-run             validate and print the plan, change nothing
  --yes                 required to apply; without it the restore is refused
`

func runBackup(args []string) int {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { fmt.Fprint(os.Stderr, backupUsage) }

	dataDir := flags.String("data", "./data", "data directory holding server-state.json")
	certsDir := flags.String("certs", "./certs", "certs directory holding server.crt / server.key")
	outDir := flags.String("out", ".", "directory the archive is written to")
	includeKey := flags.Bool("include-key", false, "include the state encryption key")
	stateEnvFile := flags.String("state-env-file", "", "0600 file holding GOREMOTE_STATE_KEY=...")
	allowPlaintext := flags.Bool("allow-plaintext", false, "allow backing up a state file that is not encrypted")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n\n%s", flags.Arg(0), backupUsage)
		return exitUsage
	}

	result, err := backup.Create(backup.CreateOptions{
		DataDir:        *dataDir,
		CertsDir:       *certsDir,
		OutDir:         *outDir,
		IncludeKey:     *includeKey,
		StateEnvFile:   *stateEnvFile,
		AllowPlaintext: *allowPlaintext,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
		return exitError
	}

	mode := "encrypted"
	switch {
	case result.Manifest.ContainsPlaintextSecrets:
		mode = "plaintext"
	case result.Manifest.ContainsStateKey:
		mode = "encrypted (key included)"
	}
	fmt.Printf("archive      : %s\n", result.Archive)
	fmt.Printf("sha256       : %s\n", result.SHA256)
	fmt.Printf("size         : %d bytes\n", result.Size)
	fmt.Printf("state        : schema %d, %s, %d devices, %d tunnels\n",
		result.Manifest.StateSchema, mode, result.Runtime.Devices, result.Runtime.Tunnels)
	fmt.Printf("files        : %d\n", len(result.Manifest.Files))
	fmt.Printf("secrets      : state key %s, TLS key %s, plaintext secrets %s\n",
		included(result.Manifest.ContainsStateKey),
		included(result.Manifest.ContainsTLSKey),
		included(result.Manifest.ContainsPlaintextSecrets))
	fmt.Printf("checksum file: %s.sha256\n", result.Archive)
	return exitOK
}

func runRestore(args []string) int {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { fmt.Fprint(os.Stderr, restoreUsage) }

	from := flags.String("from", "", "backup archive to restore (required)")
	dataDir := flags.String("data", "./data", "target data directory")
	certsDir := flags.String("certs", "./certs", "target certs directory")
	keyFile := flags.String("key-file", "", "0600 file holding the state key")
	installKey := flags.Bool("install-key", false, "write the archived state key to --state-env-file")
	stateEnvFile := flags.String("state-env-file", "", "destination for --install-key")
	restoreCerts := flags.Bool("restore-certs", false, "also replace the certs directory")
	dryRun := flags.Bool("dry-run", false, "validate and print the plan, change nothing")
	yes := flags.Bool("yes", false, "confirm the destructive restore")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n\n%s", flags.Arg(0), restoreUsage)
		return exitUsage
	}
	if *from == "" {
		fmt.Fprintf(os.Stderr, "--from is required\n\n%s", restoreUsage)
		return exitUsage
	}

	_, err := backup.Restore(backup.RestoreOptions{
		Archive:      *from,
		DataDir:      *dataDir,
		CertsDir:     *certsDir,
		KeyFile:      *keyFile,
		Key:          os.Getenv("GOREMOTE_STATE_KEY"),
		InstallKey:   *installKey,
		StateEnvFile: *stateEnvFile,
		RestoreCerts: *restoreCerts,
		DryRun:       *dryRun,
		Yes:          *yes,
		Out:          os.Stdout,
	})
	if errors.Is(err, backup.ErrConfirmationRequired) {
		fmt.Fprintf(os.Stderr, "\n%s\n", err)
		return exitError
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nrestore failed: %v\n", err)
		return exitError
	}
	return exitOK
}

func included(value bool) string {
	if value {
		return "included"
	}
	return "not included"
}
