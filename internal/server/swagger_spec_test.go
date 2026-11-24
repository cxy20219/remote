package server

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"goremote/docs"
	"goremote/web"
)

// swaggerExemptRoutes 是不进 API 规范的路由：静态页、agent 的 WebSocket 入口
// 与 swagger UI 自身。除此之外，注册了的每个路由都必须在 docs/ 里出现，反之
// 亦然——这条断言就是「swagger 与实现对齐」的机器判据，不依赖 CI 里跑 swag。
var swaggerExemptRoutes = map[string]bool{
	"GET /ws":                true,
	"GET /":                  true,
	"GET /login.html":        true,
	"GET /setup.html":        true,
	"GET /static/*filepath":  true,
	"HEAD /static/*filepath": true,
	"GET /swagger/*any":      true,
}

// normalizeSwaggerPath 把 gin 的路由参数语法换成 OpenAPI 的花括号写法：
// :id → {id}，通配符 *ip → {ip}（自动封禁的 IPv6 /64 键带斜杠，只能走通配符）。
func normalizeSwaggerPath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if len(segment) > 1 && (segment[0] == ':' || segment[0] == '*') {
			segments[i] = "{" + segment[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

func readSwaggerSpec(t *testing.T) map[string]map[string]json.RawMessage {
	t.Helper()
	doc := docs.SwaggerInfo.ReadDoc()
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(doc), &spec); err != nil {
		t.Fatalf("embedded swagger doc is not valid JSON: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("embedded swagger doc has no paths; regenerate it with scripts/gen-swagger.sh")
	}
	return spec.Paths
}

// TestSwaggerCoversEveryAPIRoute 双向比对「注册的路由」与「文档里的 path+method」。
// 少一条说明加了路由没写注解；多一条说明删了路由没重新生成文档。
//
// 已知边界：这条测试只到 path+method 粒度，不校验请求/响应字段、参数与状态码。
// 字段级漂移由 CI 的 swagger job 兜底——它重跑 scripts/gen-swagger.sh 并要求
// docs/ 生成后没有任何改动，所以「改了 struct 的 json tag 但没重新生成」会在
// 那里红。不要在这条测试里再叠一层字段断言。
func TestSwaggerCoversEveryAPIRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, _ := newTestConfig(t)
	srv := NewServer(config, web.StaticFS)
	srv.engine = gin.New()
	srv.registerRoutes()

	documented := make(map[string]bool)
	paths := readSwaggerSpec(t)
	for path, operations := range paths {
		for method := range operations {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	registered := make(map[string]bool)
	for _, route := range srv.engine.Routes() {
		// 豁免表按 gin 的原始写法匹配（*filepath 归一化之后就不再是那个键）。
		if swaggerExemptRoutes[route.Method+" "+route.Path] {
			continue
		}
		registered[route.Method+" "+normalizeSwaggerPath(route.Path)] = true
	}

	var undocumented, stale []string
	for key := range registered {
		if !documented[key] {
			undocumented = append(undocumented, key)
		}
	}
	for key := range documented {
		if !registered[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(stale)

	if len(undocumented) > 0 {
		t.Errorf("these routes are registered but missing from docs/swagger.* (add swag annotations and re-run scripts/gen-swagger.sh):\n  %s",
			strings.Join(undocumented, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("these operations are documented but no longer registered (re-run scripts/gen-swagger.sh):\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// TestSwaggerExposesTunnelRateFields 钉住速率字段真的出现在公开文档里：隧道实时
// 速率是面板状态列的唯一数据源，字段名一旦在文档里消失，接入方就看不到它。
func TestSwaggerExposesTunnelRateFields(t *testing.T) {
	doc := docs.SwaggerInfo.ReadDoc()
	var spec struct {
		Definitions map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal([]byte(doc), &spec); err != nil {
		t.Fatalf("embedded swagger doc is not valid JSON: %v", err)
	}

	view, ok := spec.Definitions["server.TunnelView"]
	if !ok {
		t.Fatal("docs/swagger.* has no server.TunnelView definition; the tunnel API is no longer documented")
	}
	for _, field := range []string{"rx_bytes", "tx_bytes", "rx_rate", "tx_rate"} {
		if _, ok := view.Properties[field]; !ok {
			t.Errorf("server.TunnelView in docs/swagger.* is missing %q; re-run scripts/gen-swagger.sh", field)
		}
	}
}
