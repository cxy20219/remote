package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"goremote/web"
)

// Swagger UI 默认不注册路由；显式开启后才由认证保护的路由提供。
func TestSwaggerRouteRespectsConfig(t *testing.T) {
	if swaggerDefaultEnabled {
		t.Fatal("swagger must default to disabled: the API docs are a debug-only surface")
	}

	gin.SetMode(gin.TestMode)

	get := func(t *testing.T, srv *Server, token string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
		request.AddCookie(&http.Cookie{Name: "go_remote_token", Value: token})
		recorder := httptest.NewRecorder()
		srv.engine.ServeHTTP(recorder, request)
		return recorder.Code
	}

	newServer := func(t *testing.T, enabled bool) (*Server, string) {
		t.Helper()
		config, _ := newTestConfig(t)
		config.Swagger.Enabled = enabled
		srv := mustNewServer(t, config, web.StaticFS)
		srv.engine = gin.New()
		srv.registerRoutes()
		token, err := srv.adminAuth.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		return srv, token
	}

	disabled, disabledToken := newServer(t, false)
	if code := get(t, disabled, disabledToken); code != http.StatusNotFound {
		t.Fatalf("swagger with default/disabled config = %d, want 404", code)
	}

	enabled, enabledToken := newServer(t, true)
	if code := get(t, enabled, enabledToken); code != http.StatusOK {
		t.Fatalf("swagger when explicitly enabled = %d, want 200", code)
	}
}
