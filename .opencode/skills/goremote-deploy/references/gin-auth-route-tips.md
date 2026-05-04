# Gin 路由与管理员认证实现经验

## 1. 路由规划：Public vs Protected

**规则**：
- **公开路由**：直接在 `engine` 上注册，放在 `protected` 分组之前
- **受保护路由**：放在 `group` 内，挂载 `authMiddleware`

```go
// ✅ 公开路由
s.engine.GET("/health", s.handleHealth)
s.engine.POST("/api/login", s.handleLogin)

// ✅ 受保护路由
protected := s.engine.Group("/")
protected.Use(s.authMiddleware())
{
    protected.GET("/api/clients", s.handleAPIClients)
}
```

## 2. Middleware 重定向循环

### 问题

未登录用户访问 `/login.html` 时，middleware 检测到未认证，又重定向回 `/login.html`，形成循环。

### 解决

在 middleware 中先对 `/login.html` 放行：

```go
func (s *Server) authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.URL.Path == "/login.html" {
            c.Next()
            return
        }
        // ... 其余认证逻辑
    }
}
```

## 3. `ShouldBindJSON` 需要正确的 Content-Type

```bash
# ✅ 必须带 Content-Type 头
curl -X POST -H 'Content-Type: application/json' -d '{"password":"admin123"}'
```

## 4. Cookie 设置与路径

```go
c.SetCookie("go_remote_token", token, 86400, "/", "", false, true)
//                  name      value   maxAge path domain secure httpOnly
```

## 5. Middleware 返回格式自动适配

```go
if strings.Contains(c.GetHeader("Accept"), "application/json") {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
} else {
    c.Redirect(http.StatusFound, "/login.html")
}
```