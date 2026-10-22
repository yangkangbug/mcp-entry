package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// These are wire-catalog tests: the downstream SDK never gets a chance to
// pre-filter the synthetic malformed schema before the gateway receives it.
func TestAuthorizedCatalogViewSchemaIsolation(t *testing.T) {
	for _, field := range []string{"inputSchema", "outputSchema"} {
		for _, kind := range []string{"pattern", "patternProperties", "header", "header_alias"} {
			for _, allowed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/allowed=%t", field, kind, allowed), func(t *testing.T) {
					var logs bytes.Buffer
					previous := log.Writer()
					log.SetOutput(&logs)
					defer log.SetOutput(previous)
					bad := discoveryCatalogTool("CANARY_forbidden")
					property := map[string]any{"type": "string"}
					schema := map[string]any{"type": "object", "properties": map[string]any{"CANARY_property": property}}
					switch kind {
					case "pattern":
						property["pattern"] = `^(?!CANARY_expression)[a-z]+$`
					case "patternProperties":
						schema["patternProperties"] = map[string]any{`^(?!CANARY_expression)[a-z]+$`: map[string]any{"type": "string"}}
					case "header":
						property["x-mcp-header"] = "CANARY Invalid Header"
					case "header_alias":
						property["X-MCP-Header"] = "CANARY Invalid Header"
					}
					bad[field] = schema
					f := newSchemaReferenceFixture(t, func() []any { return []any{discoveryCatalogTool("available"), bad} })
					cfg := discoverySingleConfig(f.server.URL)
					if allowed {
						u := cfg.Users["alice"]
						u.Allowed = append(u.Allowed, "test__CANARY_forbidden")
						cfg.Users["alice"] = u
					}
					g, err := gateway.New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer g.Close()
					ctx := discoveryContext(t)
					issues := g.Refresh(ctx)
					if allowed {
						if len(issues) != 1 || len(g.Names("alice")) != 0 {
							t.Fatalf("authorized invalid schema must reject the entire view: issues=%+v names=%v", issues, g.Names("alice"))
						}
					} else {
						if len(issues) != 0 || !reflect.DeepEqual(g.Names("alice"), []string{"test__available"}) {
							t.Fatalf("unauthorized schema blocked authorized tool: issues=%+v names=%v", issues, g.Names("alice"))
						}
						if result, err := g.Call(ctx, "alice", "test__available", map[string]any{}); err != nil || result.IsError {
							t.Fatalf("authorized call failed: %v", err)
						}
					}
					beforeRequests, beforeCalls := f.requests.Load(), f.calls.Load()
					for _, name := range []string{"test__CANARY_forbidden"} {
						if _, err := g.Call(ctx, "alice", name, map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
							t.Fatalf("forbidden call: %v", err)
						}
					}
					if allowed {
						if _, err := g.Call(ctx, "alice", "test__available", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
							t.Fatalf("partial authorized view callable: %v", err)
						}
					}
					if f.requests.Load() != beforeRequests || f.calls.Load() != beforeCalls {
						t.Fatal("denied call contacted downstream")
					}
					if strings.Contains(logs.String()+fmt.Sprint(issues), "CANARY") {
						t.Fatal("schema or tool name leaked through SDK logs or diagnostics")
					}
				})
			}
		}
	}
}

func TestAuthorizedCatalogViewWholeCatalogSafety(t *testing.T) {
	single := func(tools ...any) func(string, int) (any, int) {
		return func(string, int) (any, int) { return map[string]any{"tools": tools}, http.StatusOK }
	}
	oversized := discoveryCatalogTool("forbidden")
	oversized["description"] = strings.Repeat("x", 64<<10)
	deep := discoveryCatalogTool("forbidden")
	var nested any = "leaf"
	for i := 0; i < gateway.MaxSchemaDepth+2; i++ {
		nested = map[string]any{"nested": nested}
	}
	deep["inputSchema"] = map[string]any{"type": "object", "default": nested}
	wide := discoveryCatalogTool("forbidden")
	wide["inputSchema"] = map[string]any{"type": "object", "default": make([]any, gateway.MaxSchemaRawNodes+1)}
	cases := []struct {
		name string
		page func(string, int) (any, int)
	}{
		{"wide_unauthorized_schema", single(discoveryCatalogTool("available"), wide)},
		{"missing_unauthorized_schema", single(discoveryCatalogTool("available"), map[string]any{"name": "forbidden"})},
		{"malformed_unauthorized_schema", single(discoveryCatalogTool("available"), map[string]any{"name": "forbidden", "inputSchema": map[string]any{"type": "object", "properties": []any{}}})},
		{"null_unauthorized_entry", single(discoveryCatalogTool("available"), nil)},
		{"invalid_unauthorized_name", single(discoveryCatalogTool("available"), discoveryCatalogTool("invalid name"))},
		{"missing_tools", func(string, int) (any, int) { return map[string]any{}, http.StatusOK }},
		{"null_tools", func(string, int) (any, int) { return map[string]any{"tools": nil}, http.StatusOK }},
		{"oversized_unauthorized_tool", single(discoveryCatalogTool("available"), oversized)},
		{"deep_unauthorized_schema", single(discoveryCatalogTool("available"), deep)},
		{"duplicate_unauthorized_across_pages", func(_ string, n int) (any, int) {
			if n == 1 {
				return map[string]any{"tools": []any{discoveryCatalogTool("available"), discoveryCatalogTool("forbidden")}, "nextCursor": "last"}, http.StatusOK
			}
			return map[string]any{"tools": []any{discoveryCatalogTool("forbidden")}}, http.StatusOK
		}},
		{"full_catalog_count_across_pages", func(_ string, n int) (any, int) {
			if n == 1 {
				return map[string]any{"tools": []any{discoveryCatalogTool("available")}, "nextCursor": "last"}, http.StatusOK
			}
			tools := []any{}
			for i := 0; i < gateway.MaxToolsPerSystem; i++ {
				tools = append(tools, discoveryCatalogTool(fmt.Sprintf("forbidden%d", i)))
			}
			return map[string]any{"tools": tools}, http.StatusOK
		}},
		{"full_catalog_bytes_across_pages", func(_ string, n int) (any, int) {
			tools := []any{}
			for i := 0; i < 10; i++ {
				tool := discoveryCatalogTool(fmt.Sprintf("forbidden%d_%d", n, i))
				tool["description"] = strings.Repeat("x", 60<<10)
				tools = append(tools, tool)
			}
			if n == 1 {
				tools = append(tools, discoveryCatalogTool("available"))
				return map[string]any{"tools": tools, "nextCursor": "last"}, http.StatusOK
			}
			return map[string]any{"tools": tools}, http.StatusOK
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			downstream, _ := discoveryCatalogServer(t, tc.page)
			g, err := gateway.New(discoverySingleConfig(downstream.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			ctx := discoveryContext(t)
			issues := g.Refresh(ctx)
			if len(issues) != 1 || len(g.Names("alice")) != 0 {
				t.Fatalf("unsafe full catalog admitted: issues=%+v names=%v", issues, g.Names("alice"))
			}
			if _, err := g.Call(ctx, "alice", "test__available", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
				t.Fatalf("rejected view callable: %v", err)
			}
		})
	}
}

func TestAuthorizedCatalogViewPolicyExpansionNeedsFreshDiscovery(t *testing.T) {
	var discovered atomic.Int32
	f := newSchemaReferenceFixture(t, func() []any {
		discovered.Add(1)
		return []any{discoveryCatalogTool("available"), discoveryCatalogTool("sibling")}
	})
	cfg := discoverySingleConfig(f.server.URL)
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ctx := discoveryContext(t)
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatal(issues)
	}
	identity := gateway.Identity{Tenant: "demo", Principal: "alice"}
	p, err := g.Policy(identity)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"test__available", "test__sibling"}
	p, err = g.SetPolicy(identity, p.Version, allowed)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the caller-owned slice cannot alter the published policy or snapshot.
	allowed[1] = "test__unsafe"
	before := f.requests.Load()
	if _, err := g.Call(ctx, "alice", "test__sibling", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("expansion reused previously unauthorized metadata: %v", err)
	}
	if f.requests.Load() != before || discovered.Load() != 1 {
		t.Fatal("denied expanded tool caused downstream traffic")
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatal(issues)
	}
	if !reflect.DeepEqual(g.Names("alice"), []string{"test__available", "test__sibling"}) {
		t.Fatalf("fresh discovery did not use immutable policy: %v", g.Names("alice"))
	}
	if _, err := g.Call(ctx, "alice", "test__sibling", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedCatalogViewPolicyChangeDuringDiscovery(t *testing.T) {
	for _, kind := range []string{"expand", "revoke", "rebind", "policy_aba"} {
		t.Run(kind, func(t *testing.T) {
			var block atomic.Bool
			barrier := newRevocationBarrier(t)
			downstream, _ := discoveryCatalogServer(t, func(_ string, _ int) (any, int) {
				if block.Load() {
					barrier.block(context.Background())
				}
				return map[string]any{"tools": []any{discoveryCatalogTool("available"), discoveryCatalogTool("sibling")}}, http.StatusOK
			})
			t.Cleanup(barrier.open)
			cfg := discoverySingleConfig(downstream.URL)
			g, err := gateway.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			ctx := discoveryContext(t)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatal(issues)
			}
			identity := gateway.Identity{Tenant: "demo", Principal: "alice"}
			block.Store(true)
			done := make(chan struct{})
			go func() { g.Refresh(ctx); close(done) }()
			barrier.wait(t, ctx)
			p, err := g.Policy(identity)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expand":
				_, err = g.SetPolicy(identity, p.Version, []string{"test__available", "test__sibling"})
			case "revoke":
				_, err = g.SetPolicy(identity, p.Version, nil)
			case "rebind":
				var b gateway.BindingInfo
				b, err = g.Binding(identity, "test")
				if err == nil {
					_, err = g.ReplaceBinding(identity, "test", b.Generation, "downstream-secret")
				}
			case "policy_aba":
				p, err = g.SetPolicy(identity, p.Version, nil)
				if err == nil {
					_, err = g.SetPolicy(identity, p.Version, []string{"test__available"})
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			block.Store(false)
			barrier.open()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("refresh did not finish")
			}
			if len(g.Names("alice")) != 0 {
				t.Fatalf("old snapshot republished after %s: %v", kind, g.Names("alice"))
			}
			if kind != "revoke" {
				if issues := g.Refresh(ctx); len(issues) != 0 {
					t.Fatal(issues)
				}
				if len(g.Names("alice")) == 0 {
					t.Fatal("fresh authorized view missing")
				}
			}
		})
	}
}

func TestAuthorizedCatalogViewOverlappingRefreshKeepsNewest(t *testing.T) {
	for _, oldFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("older_fails=%t", oldFails), func(t *testing.T) {
			barrier := newRevocationBarrier(t)
			downstream, _ := discoveryCatalogServer(t, func(_ string, n int) (any, int) {
				if n == 1 {
					barrier.block(context.Background())
					if oldFails {
						return nil, http.StatusInternalServerError
					}
					return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
				}
				return map[string]any{"tools": []any{discoveryCatalogTool("sibling")}}, http.StatusOK
			})
			t.Cleanup(barrier.open)
			cfg := discoverySingleConfig(downstream.URL)
			u := cfg.Users["alice"]
			u.Allowed = append(u.Allowed, "test__sibling")
			cfg.Users["alice"] = u
			g, err := gateway.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			ctx := discoveryContext(t)
			id := gateway.Identity{Tenant: "demo", Principal: "alice"}
			done := make(chan struct{})
			go func() { g.RefreshBinding(ctx, id, "test"); close(done) }()
			barrier.wait(t, ctx)
			if issues := g.RefreshBinding(ctx, id, "test"); len(issues) != 0 {
				t.Fatal(issues)
			}
			if !reflect.DeepEqual(g.Names("alice"), []string{"test__sibling"}) {
				t.Fatal("newer refresh did not publish")
			}
			barrier.open()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("old refresh did not finish")
			}
			if !reflect.DeepEqual(g.Names("alice"), []string{"test__sibling"}) {
				t.Fatalf("older discovery replaced or erased the newer view: %v", g.Names("alice"))
			}
		})
	}
}
