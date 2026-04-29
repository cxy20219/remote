# Gin 路由与管理员认证实现经验

## 1. 路由规划：Public vs Protected

### 问题
新加的 `/api/login`、`/api/check-auth`、`/login.html` 返回 404。

### 原因
Gin 的路由分组（Group）与引擎级路由（engine.GET）是独立注册的，但 `protected` 组中的 `StaticFile` 或 `Static` 路由可能意外拦截了本应是公开的路径。

### 规则
- **公开路由**（不需要认证）：直接在 `engine` 上注册，放在 `protected` 分组之前
- **受保护路由**：放在 `group` 内，挂载 `authMiddleware`

```go
// ✅ 公开路由
s.engine.GET("/health", s.handleHealth)
s.engine.POST("/api/login", s.handleLogin)
s.engine.StaticFile("/login.html", "./static/login.html")

// ✅ 受保护路由
protected := s.engine.Group("/")
protected.Use(s.authMiddleware())
{
    protected.GET("/api/clients", s.handleAPIClients)
    protected.StaticFile("/", "./static/index.html")
}
```

### 常见错误
```go
// ❌ login.html 放在 protected 组内 → 重定向循环
protected.StaticFile("/login.html", "./static/login.html")
```

---

## 2. Middleware 重定向循环

### 问题
未登录用户访问 `/login.html` 时，middleware 检测到未认证，又重定向回 `/login.html`，形成循环。

### 解决
middleware 中先对 `/login.html` 放行：

```go
func (s *Server) authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 登录页面永远放行
        if c.Request.URL.Path == "/login.html" {
            c.Next()
            return
        }
        // ... 其余认证逻辑
    }
}
```

更优方案：直接把 `/login.html` 注册在 engine 上（公开路由），绕过 middleware。

---

## 3. Gin 中 `Static` vs `StaticFile` 的区别

| 方法 | 用途 | 路由模式 |
|---|---|---|
| `engine.Static("/static", "./static")` | 挂载整个静态目录 | `/static/*filepath` |
| `engine.StaticFile("/", "./static/index.html")` | 单个文件路由 | 精确匹配 `/` |
| `engine.StaticFile("/login.html", "./static/login.html")` | 单文件 | 精确匹配 `/login.html` |

注意：`Static("/static", ...)` 和 `StaticFile("/", ...)` 之间不冲突，但如果有通配路由可能意外拦截。

---

## 4. `ShouldBindJSON` 需要正确的 Content-Type

### 问题
```go
func (s *Server) handleLogin(c *gin.Context) {
    var req struct { Password string `json:"password"` }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }
}
```

`curl -X POST -d '{"password":"admin123"}'` 返回 `invalid request`。

### 原因
`ShouldBindJSON` 要求 `Content-Type: application/json` 头。

### 正确调用
```bash
# ✅ 必须带 Content-Type 头
curl -X POST -H 'Content-Type: application/json' -d '{"password":"admin123"}'

# ✅ 用文件传 JSON 也需指定 Content-Type
curl -X POST -H 'Content-Type: application/json' -d @file.json
```

---

## 5. Cookie 设置与路径

### `SetCookie` 参数
```go
c.SetCookie("go_remote_token", token, 86400, "/", "", false, true)
//                  name      value   maxAge path domain secure httpOnly
```

- `maxAge`: 秒，`86400` = 24h
- `path`: `"/"` 使 cookie 对整个站点生效
- `domain`: 空字符串 = 当前请求域名
- `secure`: `false`（开发环境 HTTP 可用）
- `httpOnly`: `true`（JS 不可读，防 XSS）

### 清除 Cookie（登出）
```go
c.SetCookie("go_remote_token", "", -1, "/", "", false, true)
```

---

## 6. Middleware 返回格式自动适配

未认证时有两种返回方式：
- **浏览器请求**（Accept: text/html）→ 302 重定向到 `/login.html`
- **API 请求**（Accept: application/json）→ 401 JSON

```go
if strings.Contains(c.GetHeader("Accept"), "application/json") {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
} else {
    c.Redirect(http.StatusFound, "/login.html")
}
```
