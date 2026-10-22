package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

func TestSchemaAdmissionDiscoveryAtomicDiagnostics(t *testing.T) {
	for _, field := range []string{"inputSchema", "outputSchema"} {
		for _, keyword := range []string{"pattern", "patternProperties"} {
			for _, authorized := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s_%s_authorized_%t", field, keyword, authorized), func(t *testing.T) {
					var logs bytes.Buffer
					oldWriter := log.Writer()
					log.SetOutput(&logs)
					defer log.SetOutput(oldWriter)
					var failed atomic.Bool
					bad := discoveryCatalogTool("CANARY_unauthorized_tool")
					expression := `^(?!CANARY_regex)[a-z]+$`
					if keyword == "pattern" {
						bad[field] = map[string]any{"type": "object", "properties": map[string]any{"CANARY_property": map[string]any{"type": "string", "pattern": expression}}}
					} else {
						bad[field] = map[string]any{"type": "object", "patternProperties": map[string]any{expression: map[string]any{"type": "string"}}}
					}
					broken, requests := discoveryCatalogServer(t, func(string, int) (any, int) {
						tools := []any{discoveryCatalogTool("available")}
						if failed.Load() {
							tools = append(tools, bad)
						}
						return map[string]any{"tools": tools}, http.StatusOK
					})
					healthy, _ := discoveryCatalogServer(t, func(string, int) (any, int) {
						return map[string]any{"tools": []any{discoveryCatalogTool("available")}}, http.StatusOK
					})
					cfg := gateway.Config{Systems: []gateway.System{{Name: "healthy", Endpoint: healthy.URL}, {Name: "broken", Endpoint: broken.URL}}, Users: map[string]gateway.User{"alice": {Token: "alice-token", Allowed: []string{"healthy__available", "broken__available"}, Credentials: map[string]string{"healthy": "downstream-secret", "broken": "downstream-secret"}}}}
					if authorized {
						user := cfg.Users["alice"]
						user.Allowed = append(user.Allowed, "broken__CANARY_unauthorized_tool")
						cfg.Users["alice"] = user
					}
					opts := recoveryOptions(t)
					g := recoveryOpen(t, cfg, opts)
					ctx := discoveryContext(t)
					if issues := g.Refresh(ctx); len(issues) != 0 || len(g.Names("alice")) != 2 {
						t.Fatalf("initial discovery failed: %+v", issues)
					}
					failed.Store(true)
					before := requests.Load()
					issues := g.Refresh(ctx)
					if len(issues) != 1 || issues[0].Failure == nil {
						t.Fatalf("missing failure: %+v", issues)
					}
					f := issues[0].Failure
					if f.Code != gateway.FailureSchemaAdmission || f.SchemaReason != gateway.SchemaRegexpInvalidOrUnsupported || f.Phase != gateway.FailureDiscovery || f.HTTPStatus != 0 || f.OutcomeUnknown {
						t.Fatalf("bad diagnostic: %+v", f)
					}
					if requests.Load() != before+1 {
						t.Fatal("discovery retried")
					}
					if got := g.Names("alice"); !reflect.DeepEqual(got, []string{"healthy__available"}) {
						t.Fatalf("atomic isolation changed: %v", got)
					}
					for _, name := range []string{"broken__available", "broken__CANARY_unauthorized_tool"} {
						if _, err := g.Call(ctx, "alice", name, map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
							t.Fatal("rejected catalog callable")
						}
					}
					if result, err := g.Call(ctx, "alice", "healthy__available", map[string]any{}); err != nil || result.IsError {
						t.Fatal("healthy binding affected")
					}
					page, err := g.Audit(gateway.Identity{Tenant: "demo", Principal: "alice"}, 0, 100)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, event := range page.Events {
						if event.Result == gateway.AuditResultSchemaRejected {
							found = true
							if event.ToolID != "" {
								t.Fatal("unauthorized tool identifier retained")
							}
						}
					}
					if !found {
						t.Fatal("missing safe terminal audit category")
					}
					data, _ := json.Marshal(struct {
						Issues any
						Audit  any
						Status any
					}{issues, page, g.AuditStatus()})
					output := string(data) + fmt.Sprint(issues) + f.Error() + logs.String()
					if strings.Contains(output, "CANARY") || strings.Contains(output, expression) {
						t.Fatal("schema/tool canary leaked through diagnostics, status, audit, or logs")
					}
					recoveryClose(t, g)
					opts.Initialize = false
					reopened := recoveryOpen(t, cfg, opts)
					restored, err := reopened.Audit(gateway.Identity{Tenant: "demo", Principal: "alice"}, 0, 100)
					if err != nil || !reflect.DeepEqual(page.Events, restored.Events) {
						t.Fatal("schema audit category failed persistent reopen")
					}
				})
			}
		}
	}
}

func TestSchemaAdmissionValidRegexpEnforcedBeforeDispatch(t *testing.T) {
	for _, schema := range []string{
		`{"type":"object","properties":{"value":{"type":"string","pattern":"^[a-z]{1,4}$"}},"required":["value"]}`,
		`{"type":"object","patternProperties":{"^value$":{"type":"string","pattern":"^[a-z]{1,4}$"}},"additionalProperties":false}`,
	} {
		var calls atomic.Int32
		downstream := discoveryDownstream(t, map[string][]discoveryTool{"downstream-secret": {{tool: &mcp.Tool{Name: "available", InputSchema: json.RawMessage(schema)}, handler: func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls.Add(1)
			return discoveryResult(map[string]any{"ok": true}), nil
		}}}}, nil)
		g, err := gateway.New(discoverySingleConfig(downstream.URL))
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		ctx := discoveryContext(t)
		if issues := g.Refresh(ctx); len(issues) != 0 {
			t.Fatal(issues)
		}
		if _, err := g.Call(ctx, "alice", "test__available", map[string]any{"value": "12345"}); err == nil {
			t.Fatal("invalid regex argument accepted")
		}
		if calls.Load() != 0 {
			t.Fatal("invalid argument dispatched")
		}
		result, err := g.Call(ctx, "alice", "test__available", map[string]any{"value": "abc"})
		if err != nil || result.IsError || calls.Load() != 1 {
			t.Fatal("valid regexp argument rejected")
		}
	}
}
