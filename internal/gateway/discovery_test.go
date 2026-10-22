package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

type discoveryTool struct {
	tool    *mcp.Tool
	handler mcp.ToolHandler
}

// Each credential has its own real SDK server, so both tools/list and tools/call
// exercise per-user downstream authentication rather than a shared fake catalog.
func discoveryDownstream(t *testing.T, catalogs map[string][]discoveryTool, listed func(string)) *httptest.Server {
	t.Helper()
	handlers := make(map[string]http.Handler)
	for token, tools := range catalogs {
		server := mcp.NewServer(&mcp.Implementation{Name: "discovery-fixture", Version: "1"}, nil)
		for _, tool := range tools {
			server.AddTool(tool.tool, tool.handler)
		}
		handlers["Bearer "+token] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := handlers[r.Header.Get("Authorization")]
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if listed != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var request struct{ Method string }
			_ = json.Unmarshal(body, &request)
			if request.Method == "tools/list" {
				listed(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func discoveryResult(value any) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "synthetic result"}}, StructuredContent: value}
}

func discoveryJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func discoveryContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDynamicDiscoveryPreservesSchemasAndForwardsArguments(t *testing.T) {
	ctx := discoveryContext(t)
	sum := &mcp.Tool{
		Name: "sum", Title: "Add a vector", Description: "Sum numeric values with a scale factor.",
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"values":{"type":"array","items":{"type":"number"},"minItems":1},"scale":{"type":"number","default":1}},"required":["values","scale"],"additionalProperties":false}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"total":{"type":"number"}},"required":["total"],"additionalProperties":false}`),
	}
	selectTool := &mcp.Tool{
		Name: "select", Description: "Select a string at a zero-based offset.",
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"choices":{"type":"array","items":{"type":"string"}},"offset":{"type":"integer","minimum":0},"options":{"type":"object","properties":{"uppercase":{"type":"boolean"}},"required":["uppercase"],"additionalProperties":false}},"required":["choices","offset","options"],"additionalProperties":false}`),
		OutputSchema: json.RawMessage(`{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":1}`),
	}
	var hiddenCalls atomic.Int32
	downstream := discoveryDownstream(t, map[string][]discoveryTool{"math-secret": {
		{sum, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Values []float64 `json:"values"`
				Scale  float64   `json:"scale"`
			}
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, err
			}
			var total float64
			for _, value := range in.Values {
				total += value * in.Scale
			}
			return discoveryResult(map[string]any{"total": total}), nil
		}},
		{selectTool, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in struct {
				Choices []string `json:"choices"`
				Offset  int      `json:"offset"`
				Options struct {
					Uppercase bool `json:"uppercase"`
				} `json:"options"`
			}
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				return nil, err
			}
			if in.Offset >= len(in.Choices) {
				return nil, errors.New("offset out of range")
			}
			selected := in.Choices[in.Offset]
			if in.Options.Uppercase {
				selected = strings.ToUpper(selected)
			}
			return discoveryResult([]string{selected}), nil
		}},
		{&mcp.Tool{Name: "hidden", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			hiddenCalls.Add(1)
			return discoveryResult(map[string]any{"secret": true}), nil
		}},
	}}, nil)
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "math", Endpoint: downstream.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"math__sum", "math__select"}, Credentials: map[string]string{"math": "math-secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("discovery issues: %+v", issues)
	}
	if got := g.Names("alice"); !reflect.DeepEqual(got, []string{"math__select", "math__sum"}) {
		t.Fatalf("catalog=%v", got)
	}
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	client := connect(t, upstream.URL, "alice-token")
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(listed.Tools))
	}
	wantTools := map[string]*mcp.Tool{"math__sum": sum, "math__select": selectTool}
	for _, got := range listed.Tools {
		want, ok := wantTools[got.Name]
		if !ok {
			t.Fatalf("unexpected exposed tool %q", got.Name)
		}
		if got.Description != want.Description || got.Title != want.Title || !reflect.DeepEqual(discoveryJSON(t, got.InputSchema), discoveryJSON(t, want.InputSchema)) || !reflect.DeepEqual(discoveryJSON(t, got.OutputSchema), discoveryJSON(t, want.OutputSchema)) {
			t.Errorf("tool metadata or schema changed for %s: got=%+v want=%+v", got.Name, got, want)
		}
	}
	for _, tc := range []struct {
		name string
		args map[string]any
		want any
	}{
		{"math__sum", map[string]any{"values": []float64{1.5, -2, 4}, "scale": 2.5}, map[string]any{"total": 8.75}},
		{"math__select", map[string]any{"choices": []string{"first", "second"}, "offset": 1, "options": map[string]any{"uppercase": true}}, []string{"SECOND"}},
	} {
		result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil || result == nil || result.IsError {
			t.Fatalf("%s: result=%+v err=%v", tc.name, result, err)
		}
		if !reflect.DeepEqual(discoveryJSON(t, result.StructuredContent), discoveryJSON(t, tc.want)) {
			t.Errorf("%s: result=%v want=%v", tc.name, result.StructuredContent, tc.want)
		}
	}
	if _, err := g.Call(ctx, "alice", "math__hidden", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("policy-hidden direct call: %v", err)
	}
	if result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "math__hidden", Arguments: map[string]any{}}); err == nil && result != nil && !result.IsError {
		t.Fatal("policy-hidden tool callable through MCP")
	}
	if hiddenCalls.Load() != 0 {
		t.Fatal("policy-hidden call reached downstream")
	}
}

func TestDynamicDiscoveryIsolatesPerUserCatalogsAndCredentials(t *testing.T) {
	ctx := discoveryContext(t)
	var mu sync.Mutex
	listed := map[string]int{}
	catalogs := map[string][]discoveryTool{}
	for _, user := range []string{"alice", "bob"} {
		for _, name := range []string{"common", user + "_only"} {
			catalogs[user+"-downstream"] = append(catalogs[user+"-downstream"], discoveryTool{
				tool: &mcp.Tool{Name: name, Description: user + " catalog", InputSchema: json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"}},"required":["count"],"additionalProperties":false}`)},
				handler: func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return discoveryResult(map[string]any{"user": user, "tool": req.Params.Name}), nil
				},
			})
		}
	}
	downstream := discoveryDownstream(t, catalogs, func(token string) {
		mu.Lock()
		defer mu.Unlock()
		listed[token]++
	})
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "work", Endpoint: downstream.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"work__common", "work__alice_only", "work__bob_only"}, Credentials: map[string]string{"work": "alice-downstream"}},
		"bob":   {Token: "bob-token", Allowed: []string{"work__common", "work__alice_only", "work__bob_only"}, Credentials: map[string]string{"work": "bob-downstream"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("discovery issues: %+v", issues)
	}
	mu.Lock()
	for _, token := range []string{"alice-downstream", "bob-downstream"} {
		if listed[token] == 0 {
			t.Errorf("tools/list never used credential %q", token)
		}
	}
	mu.Unlock()
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	for _, user := range []string{"alice", "bob"} {
		want := []string{"work__common", "work__" + user + "_only"}
		sort.Strings(want)
		if got := g.Names(user); !reflect.DeepEqual(got, want) {
			t.Errorf("%s names=%v want=%v", user, got, want)
		}
		client := connect(t, upstream.URL, user+"-token")
		tools, err := client.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(tools.Tools) != len(want) {
			t.Fatalf("%s tool count=%d want=%d", user, len(tools.Tools), len(want))
		}
		for _, tool := range tools.Tools {
			if tool.Description != user+" catalog" {
				t.Errorf("%s received another user's metadata: %+v", user, tool)
			}
		}
		other := "alice"
		if user == "alice" {
			other = "bob"
		}
		if _, err := g.Call(ctx, user, "work__"+other+"_only", map[string]any{"count": 1}); !errors.Is(err, gateway.ErrDenied) {
			t.Errorf("%s used other user's discovered tool: %v", user, err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		user := []string{"alice", "bob"}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := g.Call(ctx, user, "work__common", map[string]any{"count": 3})
			if err != nil || result == nil || result.IsError {
				t.Errorf("%s call: result=%v err=%v", user, result, err)
				return
			}
			if got := discoveryJSON(t, result.StructuredContent); !reflect.DeepEqual(got, map[string]any{"user": user, "tool": "common"}) {
				t.Errorf("credential crossover: user=%s result=%v", user, got)
			}
		}()
	}
	wg.Wait()
}

// Only tools/list is overridden. Initialization, protocol negotiation, and calls
// remain the official SDK's implementation.
func discoveryCatalogServer(t *testing.T, page func(cursor string, request int) (any, int)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "paged-fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "available", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return discoveryResult(map[string]any{"ok": true}), nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var requests atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer downstream-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &request)
		if request.Method != "tools/list" {
			handler.ServeHTTP(w, r)
			return
		}
		result, status := page(request.Params.Cursor, int(requests.Add(1)))
		if status != http.StatusOK {
			http.Error(w, "synthetic internal failure", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(downstream.Close)
	return downstream, &requests
}

func discoveryCatalogTool(name string) map[string]any {
	return map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}}
}

func discoverySingleConfig(endpoint string) gateway.Config {
	return gateway.Config{Systems: []gateway.System{{Name: "test", Endpoint: endpoint}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"test__available"}, Credentials: map[string]string{"test": "downstream-secret"}},
	}}
}

func TestDynamicDiscoveryFailureDropsOnlyAffectedSystem(t *testing.T) {
	ctx := discoveryContext(t)
	var failed atomic.Bool
	unreliable, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
		if failed.Load() {
			return nil, http.StatusServiceUnavailable
		}
		return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
	})
	healthy, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
		return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
	})
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "healthy", Endpoint: healthy.URL}, {Name: "unreliable", Endpoint: unreliable.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"healthy__available", "unreliable__available"}, Credentials: map[string]string{"healthy": "downstream-secret", "unreliable": "downstream-secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("initial discovery: %+v", issues)
	}
	if got := g.Names("alice"); len(got) != 2 {
		t.Fatalf("initial tools=%v", got)
	}
	failed.Store(true)
	if issues := g.Refresh(ctx); len(issues) != 1 {
		t.Fatalf("expected one failed system, got %+v", issues)
	}
	if got := g.Names("alice"); !reflect.DeepEqual(got, []string{"healthy__available"}) {
		t.Fatalf("failed system retained or healthy system lost: %v", got)
	}
	if _, err := g.Call(ctx, "alice", "unreliable__available", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("stale catalog callable: %v", err)
	}
	if result, err := g.Call(ctx, "alice", "healthy__available", map[string]any{}); err != nil || result == nil || result.IsError {
		t.Fatalf("healthy tool unavailable: result=%+v err=%v", result, err)
	}
	failed.Store(false)
	if issues := g.Refresh(ctx); len(issues) != 0 || len(g.Names("alice")) != 2 {
		t.Fatalf("recovered system not rediscovered: issues=%+v names=%v", issues, g.Names("alice"))
	}
}

func TestDynamicDiscoveryNoArgumentTool(t *testing.T) {
	ctx := discoveryContext(t)
	downstream, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
		return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
	})
	g, err := gateway.New(discoverySingleConfig(downstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("discovery issues: %+v", issues)
	}
	if result, err := g.Call(ctx, "alice", "test__available", nil); err != nil || result == nil || result.IsError {
		t.Fatalf("omitted direct arguments: result=%+v err=%v", result, err)
	}
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	client := connect(t, upstream.URL, "alice-token")
	if result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "test__available"}); err != nil || result == nil || result.IsError {
		t.Fatalf("omitted MCP arguments: result=%+v err=%v", result, err)
	}
	names := g.Names("alice")
	names[0] = "test__changed"
	if got := g.Names("alice"); !reflect.DeepEqual(got, []string{"test__available"}) {
		t.Fatalf("caller mutated catalog through Names: %v", got)
	}
}

func TestDynamicDiscoveryRejectsEntireMalformedCatalog(t *testing.T) {
	for _, name := range []string{"", "two words", "route__spoof", "../escape", "https://evil.example/tool", "unicode-工具", "line\nbreak", strings.Repeat("x", 123)} {
		t.Run("name_"+name, func(t *testing.T) {
			assertRejectedDiscoveryCatalog(t, []any{discoveryCatalogTool("available"), discoveryCatalogTool(name)})
		})
	}
	for _, tc := range []struct {
		name   string
		schema any
	}{
		{"missing", nil},
		{"string", "not a schema"},
		{"array_root", map[string]any{"type": "array", "items": map[string]any{"type": "number"}}},
		{"invalid_property_type", map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "not-a-type"}}}},
		{"unresolvable_reference", map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"$ref": "#/missing"}}}},
		{"forbidden_header_mapping", map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "x-mcp-header": "Authorization"}}}},
		{"sdk_filtered_header_mapping", map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "x-mcp-header": "X Invalid"}}}},
	} {
		t.Run("input_"+tc.name, func(t *testing.T) {
			bad := discoveryCatalogTool("bad")
			bad["inputSchema"] = tc.schema
			assertRejectedDiscoveryCatalog(t, []any{discoveryCatalogTool("available"), bad}, "test__bad")
		})
	}
	t.Run("invalid_output_schema", func(t *testing.T) {
		bad := discoveryCatalogTool("bad")
		bad["outputSchema"] = map[string]any{"type": "not-a-type"}
		assertRejectedDiscoveryCatalog(t, []any{discoveryCatalogTool("available"), bad}, "test__bad")
	})
	t.Run("nil_tool", func(t *testing.T) {
		assertRejectedDiscoveryCatalog(t, []any{discoveryCatalogTool("available"), nil})
	})
	t.Run("duplicate_name", func(t *testing.T) {
		assertRejectedDiscoveryCatalog(t, []any{discoveryCatalogTool("available"), discoveryCatalogTool("available")})
	})
}

func TestDynamicDiscoveryRejectsUnsafeSchemaReferences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema string
	}{
		{"root_self_ref", `{"type":"object","$ref":"#"}`},
		{"root_dynamic_self_ref", `{"type":"object","$dynamicAnchor":"node","$dynamicRef":"#node"}`},
		{"nested_self_ref", `{"type":"object","properties":{"child":{"$ref":"#"}}}`},
		{"nested_dynamic_ref", `{"type":"object","properties":{"child":{"$dynamicRef":"#node"}},"$dynamicAnchor":"node"}`},
		{"array_item_ref", `{"type":"object","properties":{"children":{"type":"array","items":{"$ref":"#"}}}}`},
		{"composition_ref", `{"type":"object","allOf":[{"$ref":"#"}]}`},
		{"draft7_dependency_ref", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","dependencies":{"value":{"$ref":"#"}}}`},
		{"draft7_nested_dependency_ref", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","dependencies":{"value":{"properties":{"nested":{"$ref":"#"}}}}}`},
		{"remote_ref", `{"type":"object","$ref":"https://schemas.example.invalid/unsupported"}`},
	} {
		for _, field := range []string{"inputSchema", "outputSchema"} {
			t.Run(tc.name+"_"+field, func(t *testing.T) {
				bad := discoveryCatalogTool("bad")
				bad[field] = json.RawMessage(tc.schema)
				downstream, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
					return map[string]any{"tools": []any{discoveryCatalogTool("available"), bad}}, http.StatusOK
				})
				cfg := discoverySingleConfig(downstream.URL)
				user := cfg.Users["alice"]
				user.Allowed = append(user.Allowed, "test__bad")
				cfg.Users["alice"] = user
				g, err := gateway.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				// Never call a tool containing a recursive schema. Rejection must
				// happen during discovery before argument validation is possible.
				if issues := g.Refresh(discoveryContext(t)); len(issues) == 0 {
					t.Fatal("unsafe schema reference accepted during discovery")
				}
				if names := g.Names("alice"); len(names) != 0 {
					t.Fatalf("reference-bearing system partially published: %v", names)
				}
			})
		}
	}
}

func TestDynamicDiscoveryPreservesLiteralSchemaKeywordData(t *testing.T) {
	ctx := discoveryContext(t)
	schema := json.RawMessage(`{
		"type":"object",
		"properties":{
			"x-mcp-header":{"type":"string"},
			"$ref":{"type":"string"},
			"$dynamicRef":{"type":"string"},
			"type":{"type":"string"},
			"metadata":{"type":"object","additionalProperties":true,
				"default":{"x-mcp-header":"literal-default","$ref":"#","$dynamicRef":"#","type":"not-a-schema-type"}}
		},
		"required":["x-mcp-header","$ref"],
		"additionalProperties":false,
		"examples":[{"x-mcp-header":"literal-example","$ref":"#","$dynamicRef":"#","type":"not-a-schema-type"}],
		"default":{"x-mcp-header":"literal-default","$ref":"#","$dynamicRef":"#","type":"not-a-schema-type"}
	}`)
	downstream := discoveryDownstream(t, map[string][]discoveryTool{"literal-secret": {
		{&mcp.Tool{Name: "literal", Description: "Preserve ordinary JSON keys without interpreting them as schema keywords.", InputSchema: schema, OutputSchema: schema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var value map[string]any
			if err := json.Unmarshal(req.Params.Arguments, &value); err != nil {
				return nil, err
			}
			return discoveryResult(value), nil
		}},
	}}, nil)
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "data", Endpoint: downstream.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"data__literal"}, Credentials: map[string]string{"data": "literal-secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("ordinary property names or literal example/default data rejected: %+v", issues)
	}
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	client := connect(t, upstream.URL, "alice-token")
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Name != "data__literal" {
		t.Fatalf("unexpected catalog: %+v", listed)
	}
	for _, got := range []any{listed.Tools[0].InputSchema, listed.Tools[0].OutputSchema} {
		if !reflect.DeepEqual(discoveryJSON(t, got), discoveryJSON(t, schema)) {
			t.Fatalf("schema containing literal keyword data changed: got=%v want=%s", got, schema)
		}
	}
	args := map[string]any{"x-mcp-header": "ordinary header property", "$ref": "#", "$dynamicRef": "#", "type": "not-a-schema-type", "metadata": map[string]any{"x-mcp-header": "literal", "$ref": "#"}}
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "data__literal", Arguments: args})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ordinary keyword-named properties not callable: result=%+v err=%v", result, err)
	}
	if got := discoveryJSON(t, result.StructuredContent); !reflect.DeepEqual(got, discoveryJSON(t, args)) {
		t.Fatalf("literal property values changed: got=%v want=%v", got, args)
	}
}

func assertRejectedDiscoveryCatalog(t *testing.T, tools []any, allowed ...string) {
	t.Helper()
	downstream, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
		return map[string]any{"tools": tools}, http.StatusOK
	})
	cfg := discoverySingleConfig(downstream.URL)
	user := cfg.Users["alice"]
	user.Allowed = append(user.Allowed, allowed...)
	cfg.Users["alice"] = user
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := discoveryContext(t)
	if issues := g.Refresh(ctx); len(issues) == 0 {
		t.Fatal("malformed system catalog was accepted")
	}
	if names := g.Names("alice"); len(names) != 0 {
		t.Fatalf("partial malformed system catalog published: %v", names)
	}
	if _, err := g.Call(ctx, "alice", "test__available", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("tool from rejected catalog callable: %v", err)
	}
}

func TestDynamicDiscoveryPaginationAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		page     func(string, int) (any, int)
		accepted bool
		requests int32
	}{
		{"two_pages", func(cursor string, request int) (any, int) {
			if request == 1 && cursor == "" {
				return map[string]any{"tools": []any{discoveryCatalogTool("other")}, "nextCursor": "next"}, http.StatusOK
			}
			if request == 2 && cursor == "next" {
				return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
			}
			return nil, http.StatusBadRequest
		}, true, 2},
		{"duplicate_across_pages", func(_ string, request int) (any, int) {
			result := map[string]any{"tools": []any{discoveryCatalogTool("available")}}
			if request == 1 {
				result["nextCursor"] = "next"
			}
			return result, http.StatusOK
		}, false, 2},
		{"cursor_cycle", func(_ string, request int) (any, int) {
			return map[string]any{"tools": []any{discoveryCatalogTool(fmt.Sprintf("tool%d", request))}, "nextCursor": "same"}, http.StatusOK
		}, false, 2},
		{"sixteen_page_boundary", func(_ string, request int) (any, int) {
			if request == 16 {
				return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
			}
			return map[string]any{"tools": []any{}, "nextCursor": fmt.Sprintf("page%d", request+1)}, http.StatusOK
		}, true, 16},
		{"seventeenth_page_rejected", func(_ string, request int) (any, int) {
			return map[string]any{"tools": []any{}, "nextCursor": fmt.Sprintf("page%d", request+1)}, http.StatusOK
		}, false, 16},
		{"128_tool_boundary", func(string, int) (any, int) {
			tools := []any{discoveryCatalogTool("available")}
			for i := 1; i < 128; i++ {
				tools = append(tools, discoveryCatalogTool(fmt.Sprintf("tool%d", i)))
			}
			return map[string]any{"tools": tools}, http.StatusOK
		}, true, 1},
		{"129_tools_rejected", func(string, int) (any, int) {
			tools := []any{discoveryCatalogTool("available")}
			for i := 1; i < 129; i++ {
				tools = append(tools, discoveryCatalogTool(fmt.Sprintf("tool%d", i)))
			}
			return map[string]any{"tools": tools}, http.StatusOK
		}, false, 1},
		{"129_tools_across_pages_rejected", func(_ string, request int) (any, int) {
			if request == 2 {
				return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
			}
			tools := []any{}
			for i := 0; i < 128; i++ {
				tools = append(tools, discoveryCatalogTool(fmt.Sprintf("tool%d", i)))
			}
			return map[string]any{"tools": tools, "nextCursor": "last"}, http.StatusOK
		}, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			downstream, requests := discoveryCatalogServer(t, tc.page)
			g, err := gateway.New(discoverySingleConfig(downstream.URL))
			if err != nil {
				t.Fatal(err)
			}
			issues := g.Refresh(discoveryContext(t))
			if tc.accepted {
				if len(issues) != 0 || !reflect.DeepEqual(g.Names("alice"), []string{"test__available"}) {
					t.Fatalf("valid paged catalog rejected: issues=%+v names=%v", issues, g.Names("alice"))
				}
			} else if len(issues) == 0 || len(g.Names("alice")) != 0 {
				t.Fatalf("invalid paged catalog accepted: issues=%+v names=%v", issues, g.Names("alice"))
			}
			if got := requests.Load(); got != tc.requests {
				t.Errorf("tools/list requests=%d want=%d", got, tc.requests)
			}
		})
	}
}

func TestDynamicDiscoveryRejectsAmbiguousSystemAndWildcardPolicy(t *testing.T) {
	for _, name := range []string{"", "bad__system", "bad/system", "工具", "bad system"} {
		cfg := gateway.Config{Systems: []gateway.System{{Name: name, Endpoint: "http://127.0.0.1:9000"}}}
		if _, err := gateway.New(cfg); err == nil {
			t.Errorf("accepted invalid system name %q", name)
		}
	}
	for _, allowed := range []string{"*", "test__*", "test__available*", "test__other__available", "available", "other__available"} {
		cfg := discoverySingleConfig("http://127.0.0.1:9000")
		user := cfg.Users["alice"]
		user.Allowed = []string{allowed}
		cfg.Users["alice"] = user
		if _, err := gateway.New(cfg); err == nil {
			t.Errorf("accepted non-explicit or invalid policy %q", allowed)
		}
	}
}
