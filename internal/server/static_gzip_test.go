package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"goremote/web"
)

func staticTestFS(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		t.Fatalf("fs.Sub(web.StaticFS): %v", err)
	}
	return sub
}

// 预压缩副本会被 go:embed 打进二进制。它和 .html 一旦不同步，编译、vet 都
// 不会报错，线上却会一直发旧页面——所以这里按内容逐字节校验。
func TestStaticGzipCopiesMatchSource(t *testing.T) {
	sub := staticTestFS(t)
	for _, name := range []string{"index.html", "login.html", "setup.html"} {
		raw, err := fs.ReadFile(sub, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		gzBytes, err := fs.ReadFile(sub, name+".gz")
		if err != nil {
			t.Fatalf("read %s.gz: %v (run 'make static-gz' and commit it)", name, err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
		if err != nil {
			t.Fatalf("%s.gz is not valid gzip: %v", name, err)
		}
		plain, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("decompress %s.gz: %v", name, err)
		}
		if err := zr.Close(); err != nil {
			t.Fatalf("close %s.gz reader: %v", name, err)
		}
		if !bytes.Equal(plain, raw) {
			t.Fatalf("%s.gz is stale (%d bytes decompressed vs %d bytes source); run 'make static-gz' and commit it",
				name, len(plain), len(raw))
		}
		if len(gzBytes) >= len(raw) {
			t.Fatalf("%s.gz is not smaller than the source (%d >= %d bytes)", name, len(gzBytes), len(raw))
		}
	}
}

// 协商边界：不带头、identity 发原文；gzip 及其参数发压缩；显式 q=0 必须
// 回落原文（否则会给不收 gzip 的客户端发乱码）。
func TestServeStaticHTMLNegotiatesGzip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sub := staticTestFS(t)

	raw, err := fs.ReadFile(sub, "login.html")
	if err != nil {
		t.Fatalf("read login.html: %v", err)
	}
	gzBytes, err := fs.ReadFile(sub, "login.html.gz")
	if err != nil {
		t.Fatalf("read login.html.gz: %v", err)
	}

	cases := []struct {
		name         string
		acceptEnc    string
		wantGzip     bool
		wantEncoding string
	}{
		{name: "no accept-encoding", acceptEnc: "", wantGzip: false},
		{name: "identity only", acceptEnc: "identity", wantGzip: false},
		{name: "plain gzip", acceptEnc: "gzip", wantGzip: true, wantEncoding: "gzip"},
		{name: "gzip with q", acceptEnc: "br, gzip;q=0.8", wantGzip: true, wantEncoding: "gzip"},
		{name: "gzip q=0", acceptEnc: "gzip;q=0", wantGzip: false},
		{name: "gzip q=0.0 spaces", acceptEnc: "deflate, gzip; q=0.0", wantGzip: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, "/login.html", nil)
			if tc.acceptEnc != "" {
				c.Request.Header.Set("Accept-Encoding", tc.acceptEnc)
			}

			serveStaticHTML(c, sub, "login.html")

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
			if got := recorder.Header().Get("Content-Encoding"); got != tc.wantEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tc.wantEncoding)
			}
			if got := recorder.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Fatalf("Vary = %q, want Accept-Encoding", got)
			}
			if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("Content-Type = %q", got)
			}

			body := recorder.Body.Bytes()
			if tc.wantGzip {
				if !bytes.Equal(body, gzBytes) {
					t.Fatal("gzip response body is not the precompressed copy")
				}
				return
			}
			if !bytes.Equal(body, raw) {
				t.Fatalf("plain response body (%d bytes) does not match login.html (%d bytes)", len(body), len(raw))
			}
		})
	}
}

// 引擎级：三个页面在真实路由上都要按 Accept-Encoding 出压缩内容。/ 需要
// 管理员会话，登录页公开，setup.html 在未初始化时公开。
func TestStaticPagesServeGzipOverEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sub := staticTestFS(t)

	config, _ := newTestConfig(t)
	srv := mustNewServer(t, config, web.StaticFS)
	// NewServer 只建对象，Start 才会起监听；这里手动装好路由表打真实路由。
	srv.engine = gin.New()
	srv.registerRoutes()
	token, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	cases := []struct {
		name   string
		path   string
		auth   bool
		source string
	}{
		{name: "login page", path: "/login.html", source: "login.html"},
		{name: "index page", path: "/", auth: true, source: "index.html"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := fs.ReadFile(sub, tc.source)
			if err != nil {
				t.Fatalf("read %s: %v", tc.source, err)
			}

			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			request.Header.Set("Accept-Encoding", "gzip, deflate, br")
			if tc.auth {
				request.AddCookie(&http.Cookie{Name: "go_remote_token", Value: token})
			}
			recorder := httptest.NewRecorder()
			srv.engine.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200 (body %q)", tc.path, recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("GET %s Content-Encoding = %q, want gzip", tc.path, got)
			}
			if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("GET %s Content-Type = %q", tc.path, got)
			}

			zr, err := gzip.NewReader(bytes.NewReader(recorder.Body.Bytes()))
			if err != nil {
				t.Fatalf("GET %s body is not gzip: %v", tc.path, err)
			}
			plain, err := io.ReadAll(zr)
			if err != nil {
				t.Fatalf("decompress GET %s body: %v", tc.path, err)
			}
			if !bytes.Equal(plain, raw) {
				t.Fatalf("GET %s decompressed body does not match %s", tc.path, tc.source)
			}
		})
	}

	// 不带 Accept-Encoding 的普通访问仍要拿到原文（老代理/脚本路径）。
	request := httptest.NewRequest(http.MethodGet, "/login.html", nil)
	recorder := httptest.NewRecorder()
	srv.engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /login.html without gzip = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("plain GET should not set Content-Encoding, got %q", got)
	}
	raw, _ := fs.ReadFile(sub, "login.html")
	if !bytes.Equal(recorder.Body.Bytes(), raw) {
		t.Fatal("plain GET body does not match login.html")
	}
}
