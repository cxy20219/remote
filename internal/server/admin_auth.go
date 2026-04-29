package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type adminSession struct {
	token     string
	expiresAt time.Time
}

type AdminAuth struct {
	password string
	sessions map[string]*adminSession
	mu       sync.RWMutex
}

func NewAdminAuth(password string) *AdminAuth {
	return &AdminAuth{
		password: password,
		sessions: make(map[string]*adminSession),
	}
}

func (a *AdminAuth) Login(password string) (string, bool) {
	if a.password == "" || password != a.password {
		return "", false
	}
	token := uuid.New().String()
	a.mu.Lock()
	a.sessions[token] = &adminSession{
		token:     token,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	a.mu.Unlock()
	return token, true
}

func (a *AdminAuth) Validate(token string) bool {
	if token == "" {
		return false
	}
	a.mu.RLock()
	s, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(s.expiresAt) {
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		return false
	}
	return true
}

func (a *AdminAuth) Logout(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

func (s *Server) handleLogin(c *gin.Context) {
	if s.adminAuth == nil || s.adminAuth.password == "" {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "token": ""})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	token, ok := s.adminAuth.Login(req.Password)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	c.SetCookie("go_remote_token", token, 86400, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "token": token})
}

func (s *Server) handleLogout(c *gin.Context) {
	token, _ := c.Cookie("go_remote_token")
	if token != "" && s.adminAuth != nil {
		s.adminAuth.Logout(token)
	}
	c.SetCookie("go_remote_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleCheckAuth(c *gin.Context) {
	if s.adminAuth == nil || s.adminAuth.password == "" {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}

	token, _ := c.Cookie("go_remote_token")
	if s.adminAuth.Validate(token) {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"authenticated": false})
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.adminAuth == nil || s.adminAuth.password == "" {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if path == "/login.html" {
			c.Next()
			return
		}

		token, _ := c.Cookie("go_remote_token")
		if s.adminAuth.Validate(token) {
			c.Next()
			return
		}

		if c.GetHeader("Accept") == "application/json" || len(path) >= 4 && path[:4] == "/api" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Redirect(http.StatusFound, "/login.html")
		c.Abort()
		return
	}
}
