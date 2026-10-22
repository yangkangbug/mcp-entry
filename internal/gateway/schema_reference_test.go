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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// Only discovery is overridden. Initialization and calls use the real SDK, and
// every downstream HTTP request is counted to distinguish validation before
// connection from rejection by a downstream handler.
type schemaReferenceFixture struct {
	server   *httptest.Server
	requests atomic.Int32
	calls    atomic.Int32
}

func newSchemaReferenceFixture(t *testing.T, catalog func() []any) *schemaReferenceFixture {
	t.Helper()
	fixture := &schemaReferenceFixture{}
	server := mcp.NewServer(&mcp.Implementation{Name: "bounded-reference-fixture", Version: "1"}, nil)
	for _, name := range []string{"available", "sibling", "unsafe"} {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			fixture.calls.Add(1)
			var value any
			if err := json.Unmarshal(request.Params.Arguments, &value); err != nil {
				return nil, err
			}
			return discoveryResult(value), nil
		})
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer downstream-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Method != "tools/list" {
			handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"tools": catalog()}})
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func schemaReferenceTool(name string, input, output any) map[string]any {
	tool := map[string]any{"name": name, "inputSchema": input}
	if output != nil {
		tool["outputSchema"] = output
	}
	return tool
}

func newSchemaReferenceGateway(t *testing.T, fixture *schemaReferenceFixture) *gateway.Gateway {
	t.Helper()
	cfg := discoverySingleConfig(fixture.server.URL)
	user := cfg.Users["alice"]
	user.Allowed = []string{"test__available", "test__sibling", "test__unsafe"}
	cfg.Users["alice"] = user
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func assertSchemaReferenceCallRejected(t *testing.T, ctx context.Context, g *gateway.Gateway, fixture *schemaReferenceFixture, args any) {
	t.Helper()
	requests, calls := fixture.requests.Load(), fixture.calls.Load()
	if result, err := g.Call(ctx, "alice", "test__available", args); err == nil {
		t.Fatalf("invalid arguments accepted: result=%+v", result)
	}
	if got := fixture.requests.Load(); got != requests {
		t.Fatalf("invalid arguments contacted downstream: requests=%d, before=%d", got, requests)
	}
	if got := fixture.calls.Load(); got != calls {
		t.Fatalf("invalid arguments reached handler: calls=%d, before=%d", got, calls)
	}
}

func TestBoundedSchemaReferencesPreserveDefinitionsAndValidateNestedArguments(t *testing.T) {
	for _, tc := range []struct {
		name, draft, definitions string
	}{
		{"default_defs", "", "$defs"},
		{"draft2020_defs", "https://json-schema.org/draft/2020-12/schema", "$defs"},
		{"draft7_definitions", "http://json-schema.org/draft-07/schema#", "definitions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			schema := map[string]any{
				"type": "object",
				tc.definitions: map[string]any{
					"amount": map[string]any{"type": "integer", "minimum": 1},
					"row": map[string]any{
						"type": "object", "properties": map[string]any{"amount": map[string]any{"$ref": "#/" + tc.definitions + "/amount"}},
						"required": []any{"amount"}, "additionalProperties": false,
					},
				},
				"properties": map[string]any{"rows": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"$ref": "#/" + tc.definitions + "/row"}}},
				"required":   []any{"rows"}, "additionalProperties": false,
			}
			if tc.draft != "" {
				schema["$schema"] = tc.draft
			}
			fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", schema, schema)} })
			g := newSchemaReferenceGateway(t, fixture)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatalf("bounded definition references rejected: %+v", issues)
			}
			upstream := httptest.NewServer(g.Handler())
			t.Cleanup(upstream.Close)
			client := connect(t, upstream.URL, "alice-token")
			listed, err := client.ListTools(ctx, nil)
			if err != nil || len(listed.Tools) != 1 {
				t.Fatalf("list referenced tool: listed=%+v err=%v", listed, err)
			}
			for _, got := range []any{listed.Tools[0].InputSchema, listed.Tools[0].OutputSchema} {
				if !reflect.DeepEqual(discoveryJSON(t, got), discoveryJSON(t, schema)) {
					t.Fatalf("reference-bearing schema was rewritten or flattened: got=%v want=%v", got, schema)
				}
			}
			valid := map[string]any{"rows": []any{map[string]any{"amount": 2}, map[string]any{"amount": 5}}}
			result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "test__available", Arguments: valid})
			if err != nil || result == nil || result.IsError {
				t.Fatalf("valid nested reference arguments failed: result=%+v err=%v", result, err)
			}
			if !reflect.DeepEqual(discoveryJSON(t, result.StructuredContent), discoveryJSON(t, valid)) || fixture.calls.Load() != 1 {
				t.Fatalf("valid arguments changed or called more than once: result=%v calls=%d", result.StructuredContent, fixture.calls.Load())
			}
			for _, args := range []any{
				map[string]any{"rows": []any{map[string]any{"amount": "2"}}},
				map[string]any{"rows": []any{map[string]any{"amount": 0}}},
				map[string]any{"rows": []any{map[string]any{}}},
				map[string]any{"rows": []any{map[string]any{"amount": 2, "unexpected": true}}},
				map[string]any{"rows": []any{}},
			} {
				assertSchemaReferenceCallRejected(t, ctx, g, fixture, args)
			}
			requests := fixture.requests.Load()
			result, err = client.CallTool(ctx, &mcp.CallToolParams{Name: "test__available", Arguments: map[string]any{"rows": []any{map[string]any{"amount": "bad"}}}})
			if err == nil && result != nil && !result.IsError {
				t.Fatal("invalid nested reference arguments accepted through MCP")
			}
			if fixture.requests.Load() != requests || fixture.calls.Load() != 1 {
				t.Fatal("invalid MCP arguments reached downstream")
			}
		})
	}
}

func TestBoundedSchemaReferencesDecodePointersAndBooleanTargets(t *testing.T) {
	for _, tc := range []struct {
		name, key, reference string
		target               any
		accepted             bool
	}{
		{"tilde_escape", "a~b", "#/$defs/a~0b", map[string]any{"type": "string"}, true},
		{"slash_escape", "a/b", "#/$defs/a~1b", map[string]any{"type": "string"}, true},
		{"percent_space", "a b", "#/$defs/a%20b", map[string]any{"type": "string"}, true},
		{"percent_unicode", "值", "#/$defs/%E5%80%BC", map[string]any{"type": "string"}, true},
		{"percent_then_pointer_escape", "a~/b", "#/$defs/a%7E0%7E1b", map[string]any{"type": "string"}, true},
		{"true_target", "allow", "#/$defs/allow", true, true},
		{"false_target", "deny", "#/$defs/deny", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			schema := map[string]any{"type": "object", "$defs": map[string]any{tc.key: tc.target}, "properties": map[string]any{"value": map[string]any{"$ref": tc.reference}}, "required": []any{"value"}}
			fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", schema, schema)} })
			g := newSchemaReferenceGateway(t, fixture)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatalf("valid JSON Pointer or boolean target rejected: %+v", issues)
			}
			args := map[string]any{"value": "valid"}
			if !tc.accepted {
				assertSchemaReferenceCallRejected(t, ctx, g, fixture, args)
				return
			}
			if result, err := g.Call(ctx, "alice", "test__available", args); err != nil || result == nil || result.IsError {
				t.Fatalf("valid pointer target rejected arguments: result=%+v err=%v", result, err)
			}
			if fixture.calls.Load() != 1 {
				t.Fatalf("handler calls=%d, want 1", fixture.calls.Load())
			}
		})
	}
}

func TestBoundedSchemaReferencesRespectDraftSiblingSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, draft string
		ignore      bool
	}{
		{"draft7_ignores_ref_sibling", "http://json-schema.org/draft-07/schema#", true},
		{"draft2020_applies_ref_sibling", "https://json-schema.org/draft/2020-12/schema", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			schema := map[string]any{
				"$schema": tc.draft, "type": "object", "definitions": map[string]any{"text": map[string]any{"type": "string"}},
				"properties": map[string]any{"value": map[string]any{"$ref": "#/definitions/text", "minLength": 3}}, "required": []any{"value"},
			}
			fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", schema, nil)} })
			g := newSchemaReferenceGateway(t, fixture)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatalf("reference sibling schema rejected: %+v", issues)
			}
			if result, err := g.Call(ctx, "alice", "test__available", map[string]any{"value": "long"}); err != nil || result == nil || result.IsError {
				t.Fatalf("valid sibling arguments: result=%+v err=%v", result, err)
			}
			assertSchemaReferenceCallRejected(t, ctx, g, fixture, map[string]any{"value": 7})
			if tc.ignore {
				if result, err := g.Call(ctx, "alice", "test__available", map[string]any{"value": "x"}); err != nil || result == nil || result.IsError {
					t.Fatalf("draft7 ref sibling was incorrectly applied: result=%+v err=%v", result, err)
				}
			} else {
				assertSchemaReferenceCallRejected(t, ctx, g, fixture, map[string]any{"value": "x"})
			}
		})
	}
}

// Repeated references form a DAG, not a cycle. Its compact serialized form must
// not bypass the expanded-validation-work bound.
func schemaReferenceDAG(levels int) map[string]any {
	definitions := map[string]any{"d0": true}
	for i := 1; i <= levels; i++ {
		ref := "#/$defs/d" + fmt.Sprint(i-1)
		definitions["d"+fmt.Sprint(i)] = map[string]any{"allOf": []any{map[string]any{"$ref": ref}, map[string]any{"$ref": ref}}}
	}
	return map[string]any{"type": "object", "$defs": definitions, "$ref": "#/$defs/d" + fmt.Sprint(levels)}
}

func TestBoundedSchemaReferencesRejectUnsafeTargetsWithoutExternalIO(t *testing.T) {
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		externalRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"object"}`)
	}))
	t.Cleanup(external.Close)
	for _, tc := range []struct {
		name   string
		schema any
	}{
		{"external_http", map[string]any{"type": "object", "$ref": external.URL + "/schema.json"}},
		{"relative_document", json.RawMessage(`{"type":"object","$ref":"schema.json#/$defs/value"}`)},
		{"anchor", json.RawMessage(`{"type":"object","$defs":{"value":{"$anchor":"value","type":"string"}},"properties":{"value":{"$ref":"#value"}}}`)},
		{"empty_reference", json.RawMessage(`{"type":"object","$ref":""}`)},
		{"dynamic_reference", json.RawMessage(`{"type":"object","$defs":{"value":{"type":"string"}},"properties":{"value":{"$dynamicRef":"#/$defs/value"}}}`)},
		{"missing_target", json.RawMessage(`{"type":"object","properties":{"value":{"$ref":"#/$defs/missing"}}}`)},
		{"scalar_target", json.RawMessage(`{"type":"object","title":"not a schema","properties":{"value":{"$ref":"#/title"}}}`)},
		{"array_target", json.RawMessage(`{"type":"object","required":["value"],"properties":{"value":{"$ref":"#/required"}}}`)},
		{"schema_container_target", json.RawMessage(`{"type":"object","$defs":{"value":{"type":"string"}},"properties":{"value":{"$ref":"#/$defs"}}}`)},
		{"default_data_target", json.RawMessage(`{"type":"object","default":{"type":"string"},"properties":{"value":{"$ref":"#/default"}}}`)},
		{"enum_data_target", json.RawMessage(`{"type":"object","enum":[{"type":"string"}],"properties":{"value":{"$ref":"#/enum/0"}}}`)},
		{"nested_id", json.RawMessage(`{"type":"object","$defs":{"value":{"$id":"nested","type":"string"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"unused_nested_id", json.RawMessage(`{"type":"object","$defs":{"value":{"type":"string"},"unused":{"$id":"nested","type":"number"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"nested_schema", json.RawMessage(`{"type":"object","$defs":{"value":{"$schema":"http://json-schema.org/draft-07/schema#","type":"string"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"unused_nested_schema", json.RawMessage(`{"type":"object","$defs":{"value":{"type":"string"},"unused":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"number"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"root_cycle", json.RawMessage(`{"type":"object","$ref":"#"}`)},
		{"nested_cycle", json.RawMessage(`{"type":"object","properties":{"child":{"$ref":"#"}}}`)},
		{"mutual_cycle", json.RawMessage(`{"type":"object","$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"properties":{"value":{"$ref":"#/$defs/a"}}}`)},
		{"unused_cycle", json.RawMessage(`{"type":"object","$defs":{"unused":{"$ref":"#/$defs/unused"}}}`)},
		{"unused_mutual_cycle", json.RawMessage(`{"type":"object","$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}}}`)},
		{"expanded_dag_bomb", schemaReferenceDAG(14)},
	} {
		for _, field := range []string{"inputSchema", "outputSchema"} {
			t.Run(tc.name+"_"+field, func(t *testing.T) {
				ctx := discoveryContext(t)
				bad := discoveryCatalogTool("unsafe")
				bad[field] = tc.schema
				fixture := newSchemaReferenceFixture(t, func() []any { return []any{discoveryCatalogTool("available"), bad} })
				g := newSchemaReferenceGateway(t, fixture)
				if issues := g.Refresh(ctx); len(issues) != 1 {
					t.Fatalf("unsafe schema did not reject the complete system catalog: %+v", issues)
				}
				if names := g.Names("alice"); len(names) != 0 {
					t.Fatalf("unsafe catalog partially published: %v", names)
				}
				requests := fixture.requests.Load()
				for _, name := range []string{"test__available", "test__unsafe"} {
					if _, err := g.Call(ctx, "alice", name, map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
						t.Fatalf("rejected catalog tool %s callable: %v", name, err)
					}
				}
				if fixture.requests.Load() != requests || fixture.calls.Load() != 0 {
					t.Fatal("rejected schema reached downstream")
				}
				if got := externalRequests.Load(); got != 0 {
					t.Fatalf("schema resolution performed external I/O: requests=%d", got)
				}
			})
		}
	}
}

func TestBoundedSchemaReferencesClearStaleSystemWithoutAffectingHealthySystem(t *testing.T) {
	ctx := discoveryContext(t)
	valid := json.RawMessage(`{"type":"object","$defs":{"text":{"type":"string"}},"properties":{"value":{"$ref":"#/$defs/text"}}}`)
	var reject atomic.Bool
	changing := newSchemaReferenceFixture(t, func() []any {
		tools := []any{schemaReferenceTool("available", valid, valid), schemaReferenceTool("sibling", valid, nil)}
		if reject.Load() {
			tools = append(tools, schemaReferenceTool("unsafe", valid, json.RawMessage(`{"type":"object","$ref":"#/$defs/missing"}`)))
		}
		return tools
	})
	healthy := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", valid, valid)} })
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "changing", Endpoint: changing.server.URL}, {Name: "healthy", Endpoint: healthy.server.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"changing__available", "changing__sibling", "changing__unsafe", "healthy__available"}, Credentials: map[string]string{"changing": "downstream-secret", "healthy": "downstream-secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantAll := []string{"changing__available", "changing__sibling", "healthy__available"}
	if issues := g.Refresh(ctx); len(issues) != 0 || !reflect.DeepEqual(g.Names("alice"), wantAll) {
		t.Fatalf("initial catalogs: issues=%+v names=%v", issues, g.Names("alice"))
	}
	reject.Store(true)
	if issues := g.Refresh(ctx); len(issues) != 1 || issues[0].System != "changing" {
		t.Fatalf("reference failure was not isolated to changing system: %+v", issues)
	}
	if names := g.Names("alice"); !reflect.DeepEqual(names, []string{"healthy__available"}) {
		t.Fatalf("stale/partial catalog retained, or healthy catalog dropped: %v", names)
	}
	requests := changing.requests.Load()
	for _, name := range []string{"changing__available", "changing__sibling", "changing__unsafe"} {
		if _, err := g.Call(ctx, "alice", name, map[string]any{"value": "valid"}); !errors.Is(err, gateway.ErrDenied) {
			t.Fatalf("stale or invalid tool %s callable: %v", name, err)
		}
	}
	if changing.requests.Load() != requests || changing.calls.Load() != 0 {
		t.Fatal("stale or partially published system contacted downstream")
	}
	if result, err := g.Call(ctx, "alice", "healthy__available", map[string]any{"value": "valid"}); err != nil || result == nil || result.IsError || healthy.calls.Load() != 1 {
		t.Fatalf("healthy reference tool unavailable: result=%+v err=%v calls=%d", result, err, healthy.calls.Load())
	}
	reject.Store(false)
	if issues := g.Refresh(ctx); len(issues) != 0 || !reflect.DeepEqual(g.Names("alice"), wantAll) {
		t.Fatalf("corrected reference catalog did not recover: issues=%+v names=%v", issues, g.Names("alice"))
	}
}

func TestBoundedSchemaReferencesPreserveLiteralKeywordData(t *testing.T) {
	ctx := discoveryContext(t)
	schema := json.RawMessage(`{
		"type":"object",
		"$defs":{"literal":{"type":"object","properties":{
			"$ref":{"type":"string"},"$dynamicRef":{"type":"string"},"$id":{"type":"string"},"$schema":{"type":"string"},"x-mcp-header":{"type":"string"}
		},"additionalProperties":false,"default":{"$ref":"#","$dynamicRef":"#","$id":"nested","$schema":"not-a-draft","x-mcp-header":"Authorization"}}},
		"properties":{"payload":{"$ref":"#/$defs/literal"}},"required":["payload"],"additionalProperties":false,
		"examples":[{"$ref":"#","$dynamicRef":"#","$id":"nested","$schema":"not-a-draft","x-mcp-header":"Authorization"}]
	}`)
	fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", schema, schema)} })
	g := newSchemaReferenceGateway(t, fixture)
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("literal data mistaken for schema keywords in reference-bearing schema: %+v", issues)
	}
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	client := connect(t, upstream.URL, "alice-token")
	listed, err := client.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 {
		t.Fatalf("list literal-data reference tool: listed=%+v err=%v", listed, err)
	}
	for _, got := range []any{listed.Tools[0].InputSchema, listed.Tools[0].OutputSchema} {
		if !reflect.DeepEqual(discoveryJSON(t, got), discoveryJSON(t, schema)) {
			t.Fatalf("literal-data reference schema changed: got=%v want=%s", got, schema)
		}
	}
	args := map[string]any{"payload": map[string]any{"$ref": "#", "$dynamicRef": "#", "$id": "nested", "$schema": "not-a-draft", "x-mcp-header": "literal value"}}
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "test__available", Arguments: args})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("literal keyword arguments rejected: result=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(discoveryJSON(t, result.StructuredContent), discoveryJSON(t, args)) || fixture.calls.Load() != 1 {
		t.Fatalf("literal values changed or handler count wrong: result=%v calls=%d", result.StructuredContent, fixture.calls.Load())
	}
}

func TestBoundedSchemaReferencesRejectExpensiveArgumentsBeforeDownstream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema any
		args   func() any
	}{
		{"input_depth", json.RawMessage(`{"type":"object","$defs":{"any":true},"additionalProperties":{"$ref":"#/$defs/any"}}`), func() any {
			var value any = "leaf"
			for i := 0; i < 34; i++ {
				value = map[string]any{"nested": value}
			}
			return value
		}},
		{"input_nodes", json.RawMessage(`{"type":"object","$defs":{"any":true},"additionalProperties":{"$ref":"#/$defs/any"}}`), func() any {
			values := make([]any, 4100)
			for i := range values {
				values[i] = i
			}
			return map[string]any{"values": values}
		}},
		{"schema_instance_work", schemaReferenceDAG(8), func() any {
			values := make([]any, 3000)
			for i := range values {
				values[i] = i
			}
			return map[string]any{"values": values}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", tc.schema, nil)} })
			g := newSchemaReferenceGateway(t, fixture)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatalf("schema within discovery budgets rejected: %+v", issues)
			}
			if result, err := g.Call(ctx, "alice", "test__available", map[string]any{"value": "small"}); err != nil || result == nil || result.IsError {
				t.Fatalf("small arguments rejected: result=%+v err=%v", result, err)
			}
			args := tc.args()
			encoded, err := json.Marshal(args)
			if err != nil || len(encoded) >= 64<<10 {
				t.Fatalf("fixture would hit preexisting byte limit instead: bytes=%d err=%v", len(encoded), err)
			}
			assertSchemaReferenceCallRejected(t, ctx, g, fixture, args)
			if fixture.calls.Load() != 1 {
				t.Fatalf("only small call should reach handler: calls=%d", fixture.calls.Load())
			}
		})
	}
}

func TestBoundedSchemaReferencesRejectKeywordCasefoldAliases(t *testing.T) {
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		externalRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"object"}`)
	}))
	t.Cleanup(external.Close)
	cases := []struct {
		name   string
		schema any
	}{
		{"uppercase_self_ref", json.RawMessage(`{"type":"object","$REF":"#"}`)},
		{"mixed_case_self_ref", json.RawMessage(`{"type":"object","$ReF":"#"}`)},
		{"uppercase_external_ref", map[string]any{"type": "object", "$REF": external.URL + "/schema.json"}},
		{"uppercase_dynamic_ref", json.RawMessage(`{"type":"object","$DYNAMICREF":"#"}`)},
		{"mixed_case_dynamic_ref", json.RawMessage(`{"type":"object","$DynamicRef":"#"}`)},
		{"uppercase_containing_keyword", json.RawMessage(`{"type":"object","PROPERTIES":{"child":{"$ref":"#"}}}`)},
		{"mixed_case_containing_keyword", json.RawMessage(`{"type":"object","Properties":{"child":{"$ref":"#"}}}`)},
		{"nested_ref_alias", json.RawMessage(`{"type":"object","properties":{"child":{"$ReF":"#"}}}`)},
		{"nested_container_alias", json.RawMessage(`{"type":"object","properties":{"child":{"type":"object","PROPERTIES":{"grandchild":{"$REF":"#"}}}}}`)},
		{"canonical_ref_alias_collision", json.RawMessage(`{"type":"object","$defs":{"value":true},"$ref":"#/$defs/value","$REF":"#"}`)},
		{"canonical_properties_alias_collision", json.RawMessage(`{"type":"object","properties":{"safe":{"type":"string"}},"PROPERTIES":{"child":{"$REF":"#"}}}`)},
		{"unicode_properties_long_s", json.RawMessage(`{"type":"object","propertieſ":{"child":{"$ref":"#"}}}`)},
		{"unicode_defs_long_s", json.RawMessage(`{"type":"object","$defſ":{"unused":{"$REF":"#"}}}`)},
		{"nested_id_alias", json.RawMessage(`{"type":"object","$defs":{"value":{"$ID":"nested","type":"string"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"nested_schema_alias", json.RawMessage(`{"type":"object","$defs":{"value":{"$SCHEMA":"http://json-schema.org/draft-07/schema#","type":"string"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
		{"uppercase_header_mapping", json.RawMessage(`{"type":"object","properties":{"value":{"type":"string","X-MCP-HEADER":"Authorization"}}}`)},
		{"mixed_case_header_mapping", json.RawMessage(`{"type":"object","$defs":{"value":{"type":"string","X-Mcp-Header":"Authorization"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`)},
	}
	// Case-fold rejection applies to every typed schema keyword, not just the
	// currently known reference-bearing attack shapes. Otherwise a new traversal
	// or validator change could reopen the gap between map and typed decoding.
	keywords := map[string]any{
		"$id": "urn:synthetic:alias", "$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": "#/$defs/value", "$comment": "annotation",
		"$defs": map[string]any{"value": true}, "definitions": map[string]any{"value": true}, "dependencies": map[string]any{"value": []any{"other"}},
		"$anchor": "anchor", "$dynamicAnchor": "anchor", "$dynamicRef": "#/$defs/value", "$vocabulary": map[string]any{},
		"title": "title", "description": "description", "default": map[string]any{}, "deprecated": false, "readOnly": false, "writeOnly": false, "examples": []any{},
		"type": "object", "enum": []any{map[string]any{}}, "const": map[string]any{}, "multipleOf": 1, "minimum": 0, "maximum": 10,
		"exclusiveMinimum": 0, "exclusiveMaximum": 10, "minLength": 0, "maxLength": 10, "pattern": "^value$",
		"prefixItems": []any{true}, "items": true, "minItems": 0, "maxItems": 10, "additionalItems": true, "uniqueItems": false,
		"contains": true, "minContains": 0, "maxContains": 10, "unevaluatedItems": true,
		"minProperties": 0, "maxProperties": 10, "required": []any{}, "dependentRequired": map[string]any{},
		"properties": map[string]any{"value": true}, "patternProperties": map[string]any{"^value$": true}, "additionalProperties": true,
		"propertyNames": true, "unevaluatedProperties": true, "allOf": []any{true}, "anyOf": []any{true}, "oneOf": []any{true}, "not": false,
		"if": true, "then": true, "else": false, "dependentSchemas": map[string]any{"value": true},
		"contentEncoding": "base64", "contentMediaType": "application/json", "contentSchema": true, "format": "email", "x-mcp-header": "Authorization",
	}
	for keyword, value := range keywords {
		cases = append(cases, struct {
			name   string
			schema any
		}{"keyword_" + keyword, map[string]any{"type": "object", "$defs": map[string]any{"value": true}, strings.ToUpper(keyword): value}})
	}
	for _, tc := range cases {
		for _, field := range []string{"inputSchema", "outputSchema"} {
			t.Run(tc.name+"_"+field, func(t *testing.T) {
				ctx := discoveryContext(t)
				bad := discoveryCatalogTool("unsafe")
				bad[field] = tc.schema
				fixture := newSchemaReferenceFixture(t, func() []any { return []any{discoveryCatalogTool("available"), bad} })
				g := newSchemaReferenceGateway(t, fixture)
				if issues := g.Refresh(ctx); len(issues) != 1 {
					// In particular, never Validate a recursive aliased schema when
					// testing a vulnerable implementation: stop after discovery.
					t.Fatalf("case-fold keyword alias was not rejected during discovery: %+v", issues)
				}
				if names := g.Names("alice"); len(names) != 0 {
					t.Fatalf("alias-bearing catalog partially published: %v", names)
				}
				requests := fixture.requests.Load()
				for _, name := range []string{"test__available", "test__unsafe"} {
					if _, err := g.Call(ctx, "alice", name, map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
						t.Fatalf("rejected alias catalog tool %s callable: %v", name, err)
					}
				}
				if fixture.requests.Load() != requests || fixture.calls.Load() != 0 {
					t.Fatal("rejected alias catalog contacted downstream")
				}
				if got := externalRequests.Load(); got != 0 {
					t.Fatalf("aliased reference performed external I/O: requests=%d", got)
				}
			})
		}
	}
}

func TestBoundedSchemaReferencesPreserveCasefoldAliasDataNames(t *testing.T) {
	ctx := discoveryContext(t)
	literalNames := []string{"$REF", "$ReF", "$DYNAMICREF", "$ID", "$SCHEMA", "PROPERTIES", "propertieſ", "$DEFS", "$defſ", "X-MCP-HEADER", "MINIMUM"}
	definitions := map[string]any{}
	properties := map[string]any{}
	args := map[string]any{}
	for _, name := range literalNames {
		// Definition names and property names are data, even when their spelling
		// case-folds to a typed schema keyword. Only schema-position keys matter.
		definitions[name] = map[string]any{"type": "string"}
		properties[name] = map[string]any{"$ref": "#/$defs/" + name}
		args[name] = "literal " + name
	}
	annotation := map[string]any{"$REF": "#", "$DYNAMICREF": "#", "$ID": "nested", "$SCHEMA": "not-a-draft", "PROPERTIES": map[string]any{"child": map[string]any{"$REF": "#"}}, "X-MCP-HEADER": "Authorization"}
	schema := map[string]any{
		"type": "object", "$defs": definitions, "properties": properties, "additionalProperties": false,
		"default": annotation, "examples": []any{annotation},
	}
	fixture := newSchemaReferenceFixture(t, func() []any { return []any{schemaReferenceTool("available", schema, schema)} })
	g := newSchemaReferenceGateway(t, fixture)
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("literal alias names or annotation data rejected: %+v", issues)
	}
	upstream := httptest.NewServer(g.Handler())
	t.Cleanup(upstream.Close)
	client := connect(t, upstream.URL, "alice-token")
	listed, err := client.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 {
		t.Fatalf("list literal alias tool: listed=%+v err=%v", listed, err)
	}
	for _, got := range []any{listed.Tools[0].InputSchema, listed.Tools[0].OutputSchema} {
		if !reflect.DeepEqual(discoveryJSON(t, got), discoveryJSON(t, schema)) {
			t.Fatalf("literal alias schema changed: got=%v want=%v", got, schema)
		}
	}
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "test__available", Arguments: args})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("literal alias arguments rejected: result=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(discoveryJSON(t, result.StructuredContent), discoveryJSON(t, args)) || fixture.calls.Load() != 1 {
		t.Fatalf("literal alias values changed or handler count wrong: result=%v calls=%d", result.StructuredContent, fixture.calls.Load())
	}
}
