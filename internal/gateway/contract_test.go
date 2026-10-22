package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

const (
	contractRequestID = "request:a__0007/%2F?x=1+ 终"
	contractTaskID    = "task:c__0009/%2F?opaque=+"
	contractParentID  = "parent:b__0003/..#unchanged"
	contractCursor    = "cursor:a__A+/=%3F"
	contractKey       = "key:c__001/%2F+unchanged"
)

type contractCall struct {
	system, name, user string
	args               map[string]any
}

type contractTask struct {
	owner, requestID, parentID, key string
	status                          string
	businessSuccess, isError        bool
}

// The three services deliberately own their business semantics. The gateway
// sees only tool descriptions, opaque JSON arguments, and ordinary MCP results.
type contractFixture struct {
	gateway   *gateway.Gateway
	server    *httptest.Server
	endpoints map[string]string
	tools     map[string][]*mcp.Tool
	mu        sync.Mutex
	calls     []contractCall
	status    []int
	tasks     map[string]contractTask
	writes    int
	submits   int
	dropKey   string
	drops     int
}

func contractTools() map[string][]*mcp.Tool {
	no, yes := false, true
	newTool := func(name, title, description, input string, readOnly bool) *mcp.Tool {
		return &mcp.Tool{
			Name: name, Title: title, Description: description,
			Annotations: &mcp.ToolAnnotations{
				Title: "Annotation " + title, ReadOnlyHint: readOnly,
				DestructiveHint: &yes, IdempotentHint: readOnly, OpenWorldHint: &no,
			},
			Meta: mcp.Meta{"synthetic.example/contract": map[string]any{
				"version": 7, "business_name": name, "flags": []any{false, "unchanged"},
			}},
			Icons:        []mcp.Icon{{Source: "data:image/svg+xml;base64,PHN2Zy8+", MIMEType: "image/svg+xml", Sizes: []string{"any"}, Theme: mcp.IconThemeDark}},
			InputSchema:  json.RawMessage(input),
			OutputSchema: json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string"},"task_id":{"type":"string"},"parent_task_id":{"type":"string"},"cursor":{"type":"string","default":"business-output-default"},"status":{"type":"string"},"business_success":{"type":"boolean"}},"additionalProperties":true}`),
		}
	}
	return map[string][]*mcp.Tool{
		"a": {newTool("query", "Synchronous query", "Return a page without interpreting its business cursor.", `{"type":"object","properties":{"query":{"type":"string"},"request_id":{"type":"string"},"parent_task_id":{"type":"string"},"cursor":{"type":"string","default":"business-input-default"},"limit":{"type":"integer","minimum":1,"default":25},"options":{"type":"object","properties":{"mode":{"type":"string","default":"business-mode-default"}},"additionalProperties":false}},"required":["query","request_id"],"additionalProperties":false}`, true)},
		"b": {newTool("write", "Controlled write", "The service requires an explicit confirm=true argument.", `{"type":"object","properties":{"value":{"type":"string"},"request_id":{"type":"string"},"parent_task_id":{"type":"string"},"confirm":{"type":"boolean","default":false}},"required":["value","request_id"],"additionalProperties":false}`, false)},
		"c": {
			newTool("submit", "Submit asynchronous work", "Submit once; use the separate query tool for business progress.", `{"type":"object","properties":{"request_id":{"type":"string"},"parent_task_id":{"type":"string"},"idempotency_key":{"type":"string"},"payload":{"type":"object"}},"required":["request_id","parent_task_id","idempotency_key","payload"],"additionalProperties":false}`, false),
			newTool("query", "Query asynchronous work", "The downstream authenticates ownership independently of any user argument.", `{"type":"object","properties":{"task_id":{"type":"string"},"request_id":{"type":"string"},"parent_task_id":{"type":"string"},"user":{"type":"string"},"cursor":{"type":"string","default":"business-task-cursor-default"}},"required":["task_id","request_id"],"additionalProperties":false}`, true),
		},
	}
}

func newContractFixture(t *testing.T) *contractFixture {
	t.Helper()
	f := &contractFixture{tools: contractTools(), tasks: map[string]contractTask{}, endpoints: map[string]string{}}
	users := map[string]gateway.User{}
	for _, user := range []string{"alice", "bob"} {
		users[user] = gateway.User{
			Token:       "entry-" + user,
			Allowed:     []string{"a__query", "b__write", "c__submit", "c__query"},
			Credentials: map[string]string{},
		}
	}
	var systems []gateway.System
	for _, system := range []string{"a", "b", "c"} {
		handlers := map[string]http.Handler{}
		for _, user := range []string{"alice", "bob"} {
			token := "synthetic-" + system + "-" + user
			users[user].Credentials[system] = token
			server := mcp.NewServer(&mcp.Implementation{Name: "synthetic-" + system, Version: "1"}, nil)
			for _, tool := range f.tools[system] {
				// The raw API must not apply defaults or typed output conversion.
				server.AddTool(tool, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return f.call(system, user, req)
				})
			}
			handlers["Bearer "+token] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		}
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h, ok := handlers[r.Header.Get("Authorization")]
			if !ok {
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
				Method string `json:"method"`
				Params struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &request)
			if request.Method != "tools/call" {
				h.ServeHTTP(w, r)
				return
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			f.mu.Lock()
			f.status = append(f.status, response.Code)
			drop := system == "c" && request.Params.Name == "submit" && f.dropKey != "" && request.Params.Arguments["idempotency_key"] == f.dropKey
			if drop {
				f.drops++
			}
			f.mu.Unlock()
			if drop {
				// The service committed the operation, but no response reaches the
				// caller. This is not evidence that submitting again is safe.
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack synthetic response: %v", err)
					return
				}
				_ = conn.Close()
				return
			}
			for name, values := range response.Header() {
				w.Header()[name] = append([]string(nil), values...)
			}
			w.WriteHeader(response.Code)
			_, _ = w.Write(response.Body.Bytes())
		}))
		t.Cleanup(downstream.Close)
		f.endpoints[system] = downstream.URL
		systems = append(systems, gateway.System{Name: system, Endpoint: downstream.URL})
	}
	var err error
	f.gateway, err = gateway.New(gateway.Config{Systems: systems, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if issues := f.gateway.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("discover contract services: %v", issues)
	}
	f.server = httptest.NewServer(f.gateway.Handler())
	t.Cleanup(f.server.Close)
	return f
}

func (f *contractFixture) call(system, user string, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, contractCall{system, req.Params.Name, user, args})
	switch system + "__" + req.Params.Name {
	case "a__query":
		return contractQueryResult(args), nil
	case "b__write":
		if args["confirm"] != true {
			return contractWriteResult(args, false), nil
		}
		f.writes++
		return contractWriteResult(args, true), nil
	case "c__submit":
		key, _ := args["idempotency_key"].(string)
		task, exists := f.tasks[contractTaskID]
		if !exists || task.owner != user || task.key != key {
			task = contractTask{
				owner: user, requestID: args["request_id"].(string), parentID: args["parent_task_id"].(string),
				key: key, status: "accepted",
			}
			f.tasks[contractTaskID] = task
			f.submits++
		}
		return contractTaskResult(task), nil
	case "c__query":
		id, _ := args["task_id"].(string)
		task, exists := f.tasks[id]
		if !exists || task.owner != user {
			return contractDeniedResult(args), nil
		}
		return contractTaskResult(task), nil
	default:
		return nil, fmt.Errorf("unexpected synthetic tool %q", req.Params.Name)
	}
}

func contractQueryResult(args map[string]any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Meta: mcp.Meta{"synthetic.example/result": map[string]any{"request_id": args["request_id"], "source": "a"}},
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Verbatim result, not generated from structuredContent.\n第二行", Meta: mcp.Meta{"part": "text"}, Annotations: &mcp.Annotations{Audience: []mcp.Role{"user"}, Priority: 0.7}},
			&mcp.ImageContent{Data: []byte{0, 1, 2, 255}, MIMEType: "image/png", Meta: mcp.Meta{"part": "image"}},
			&mcp.AudioContent{Data: []byte{3, 4, 5}, MIMEType: "audio/wav", Meta: mcp.Meta{"part": "audio"}},
			&mcp.ResourceLink{URI: "synthetic:///a/result?cursor=a__opaque", Name: "a__business-resource", Title: "Original resource title", Description: "Not a routed tool name", MIMEType: "text/plain", Meta: mcp.Meta{"part": "link"}},
		},
		StructuredContent: map[string]any{
			"request_id": args["request_id"], "parent_task_id": args["parent_task_id"],
			"cursor": contractCursor, "items": []any{map[string]any{"name": "a__query", "value": 0, "present": false}},
		},
	}
}

func contractWriteResult(args map[string]any, confirmed bool) *mcp.CallToolResult {
	status := "confirmation_required"
	if confirmed {
		status = "written"
	}
	return &mcp.CallToolResult{
		Meta:    mcp.Meta{"synthetic.example/result": "controlled-write"},
		Content: []mcp.Content{&mcp.TextContent{Text: "Downstream write status: " + status}},
		StructuredContent: map[string]any{
			"request_id": args["request_id"], "parent_task_id": args["parent_task_id"],
			"status": status, "business_success": confirmed,
		},
		IsError: !confirmed,
	}
}

func contractTaskResult(task contractTask) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Meta:    mcp.Meta{"synthetic.example/result": map[string]any{"owner_checked_by": "c", "retry_after_seconds": 17}},
		Content: []mcp.Content{&mcp.TextContent{Text: "Downstream task status: " + task.status, Meta: mcp.Meta{"task_id": contractTaskID}}},
		StructuredContent: map[string]any{
			"request_id": task.requestID, "task_id": contractTaskID, "parent_task_id": task.parentID,
			"idempotency_key": task.key, "status": task.status, "business_success": task.businessSuccess,
			"result": map[string]any{"code": "business-code__unchanged", "failed_items": []any{"item:c__002"}},
		},
		IsError: task.isError,
	}
}

func contractDeniedResult(args map[string]any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Meta:              mcp.Meta{"synthetic.example/result": "downstream-owner-denial"},
		Content:           []mcp.Content{&mcp.TextContent{Text: "Task unavailable for the authenticated downstream user."}},
		StructuredContent: map[string]any{"task_id": args["task_id"], "request_id": args["request_id"], "status": "owner_denied", "business_success": false},
		IsError:           true,
	}
}

func contractJSON(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func contractEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(contractJSON(t, got), contractJSON(t, want)) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Fatalf("%s changed:\n got %s\nwant %s", label, g, w)
	}
}

func contractEqualResult(t *testing.T, label, system string, got, want *mcp.CallToolResult) {
	t.Helper()
	// SDK v1.7.0 adds these envelope fields when sending a complete result.
	// The gateway must preserve even the downstream implementation metadata,
	// rather than replacing it with its own identity.
	wire := contractJSON(t, want).(map[string]any)
	wire["resultType"] = "complete"
	wire["_meta"].(map[string]any)[mcp.MetaKeyServerInfo] = map[string]any{"name": "synthetic-" + system, "version": "1"}
	contractEqual(t, label, got, wire)
}

func contractCallTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return result
}

func (f *contractFixture) assertCalls(t *testing.T, want ...contractCall) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != len(want) {
		t.Fatalf("downstream calls=%d, want %d (no implicit submit, polling, or retry): %+v", len(f.calls), len(want), f.calls)
	}
	for i, got := range f.calls {
		if got.system != want[i].system || got.name != want[i].name || got.user != want[i].user {
			t.Fatalf("call %d routed or authenticated incorrectly: %+v; want %+v", i, got, want[i])
		}
		contractEqual(t, fmt.Sprintf("call %d arguments", i), got.args, want[i].args)
	}
	for _, status := range f.status {
		if status != http.StatusOK {
			t.Fatalf("synthetic MCP tool HTTP status=%d; want 200 even for business failures", status)
		}
	}
}

func TestToolContractOnlyNamesAreNamespaced(t *testing.T) {
	f := newContractFixture(t)
	for _, user := range []string{"alice", "bob"} {
		t.Run(user, func(t *testing.T) {
			session := connect(t, f.server.URL, "entry-"+user)
			list, err := session.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]*mcp.Tool{}
			for _, tool := range list.Tools {
				got[tool.Name] = tool
			}
			if len(list.Tools) != 4 || len(got) != 4 {
				t.Fatalf("tool catalog=%v; want four distinct namespaced tools", got)
			}
			for system, tools := range f.tools {
				for _, tool := range tools {
					want := *tool
					want.Name = system + "__" + tool.Name
					contractEqual(t, "tool metadata and schemas", got[want.Name], &want)
				}
			}
		})
	}
	f.assertCalls(t)
}

func TestToolContractSynchronousArgumentsAndResultsRemainOpaque(t *testing.T) {
	f := newContractFixture(t)
	session := connect(t, f.server.URL, "entry-alice")
	var wantCalls []contractCall
	for _, args := range []map[string]any{
		{"query": "a__query", "request_id": contractRequestID, "parent_task_id": contractParentID, "options": map[string]any{}},
		{"query": "a__query", "request_id": contractRequestID, "parent_task_id": contractParentID, "cursor": contractCursor, "limit": 3, "options": map[string]any{"mode": "verbatim__mode"}},
	} {
		before := contractJSON(t, args)
		got := contractCallTool(t, session, "a__query", args)
		contractEqualResult(t, "synchronous result content/structuredContent/_meta", "a", got, contractQueryResult(args))
		contractEqual(t, "caller-owned arguments", args, before)
		wantCalls = append(wantCalls, contractCall{"a", "query", "alice", args})
		f.assertCalls(t, wantCalls...)
	}
	// Exercise the public direct-call API as well as the SDK-facing handler.
	args := map[string]any{"query": "direct", "request_id": contractRequestID}
	got, err := f.gateway.Call(context.Background(), "bob", "a__query", args)
	if err != nil {
		t.Fatal(err)
	}
	contractEqualResult(t, "direct call result", "a", got, contractQueryResult(args))
	wantCalls = append(wantCalls, contractCall{"a", "query", "bob", args})
	f.assertCalls(t, wantCalls...)
}

func TestToolContractResultsMatchDirectSDKBaseline(t *testing.T) {
	f := newContractFixture(t)
	entry := connect(t, f.server.URL, "entry-alice")
	var wantCalls []contractCall
	for _, tc := range []struct {
		system, name string
		args         map[string]any
	}{
		{"a", "query", map[string]any{"query": "opaque", "request_id": contractRequestID, "cursor": contractCursor}},
		{"b", "write", map[string]any{"value": "opaque", "request_id": contractRequestID, "confirm": false}},
		{"c", "submit", contractSubmitArgs()},
	} {
		t.Run(tc.system, func(t *testing.T) {
			direct := connect(t, f.endpoints[tc.system], "synthetic-"+tc.system+"-alice")
			baseline := contractCallTool(t, direct, tc.name, tc.args)
			proxied := contractCallTool(t, entry, tc.system+"__"+tc.name, tc.args)
			// Compare every supported result field against the real downstream
			// wire representation, including SDK-added fields and custom _meta.
			contractEqual(t, "direct SDK versus gateway result", proxied, baseline)
			want := contractCall{tc.system, tc.name, "alice", tc.args}
			wantCalls = append(wantCalls, want, want)
			f.assertCalls(t, wantCalls...)
		})
	}
}

func TestToolContractConfirmationIsNeverInvented(t *testing.T) {
	f := newContractFixture(t)
	session := connect(t, f.server.URL, "entry-alice")
	var wantCalls []contractCall
	for _, tc := range []struct {
		name      string
		confirm   any
		confirmed bool
	}{{"omitted", nil, false}, {"false", false, false}, {"explicit_true", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"value": "b__write", "request_id": contractRequestID, "parent_task_id": contractParentID}
			if tc.confirm != nil {
				args["confirm"] = tc.confirm
			}
			got := contractCallTool(t, session, "b__write", args)
			contractEqualResult(t, "controlled write result including isError", "b", got, contractWriteResult(args, tc.confirmed))
			wantCalls = append(wantCalls, contractCall{"b", "write", "alice", args})
			f.assertCalls(t, wantCalls...)
			f.mu.Lock()
			writes := f.writes
			f.mu.Unlock()
			wantWrites := 0
			if tc.confirmed {
				wantWrites = 1
			}
			if writes != wantWrites {
				t.Fatalf("business writes=%d, want %d", writes, wantWrites)
			}
		})
	}
}

func contractSubmitArgs() map[string]any {
	return map[string]any{
		"request_id": contractRequestID, "parent_task_id": contractParentID, "idempotency_key": contractKey,
		"payload": map[string]any{"name": "c__submit", "confirm": false, "count": 0},
	}
}

func TestToolContractAsynchronousProgressAndOwnershipStayDownstream(t *testing.T) {
	f := newContractFixture(t)
	alice := connect(t, f.server.URL, "entry-alice")
	bob := connect(t, f.server.URL, "entry-bob")
	submit := contractSubmitArgs()
	task := contractTask{owner: "alice", requestID: contractRequestID, parentID: contractParentID, key: contractKey, status: "accepted"}
	got := contractCallTool(t, alice, "c__submit", submit)
	contractEqualResult(t, "accepted submit is not completed work", "c", got, contractTaskResult(task))
	wantCalls := []contractCall{{"c", "submit", "alice", submit}}
	f.assertCalls(t, wantCalls...)

	// A caller can explicitly repeat an idempotent request; only the service
	// interprets its key. The gateway must neither cache it nor change the key.
	got = contractCallTool(t, alice, "c__submit", submit)
	contractEqualResult(t, "explicit idempotent submit", "c", got, contractTaskResult(task))
	wantCalls = append(wantCalls, contractCall{"c", "submit", "alice", submit})
	f.assertCalls(t, wantCalls...)
	f.mu.Lock()
	submits := f.submits
	f.mu.Unlock()
	if submits != 1 {
		t.Fatalf("downstream idempotency lost: business submissions=%d", submits)
	}

	query := map[string]any{"task_id": contractTaskID, "request_id": contractRequestID, "parent_task_id": contractParentID, "cursor": contractCursor}
	for _, tc := range []struct {
		name, status string
		isError      bool
	}{
		{"accepted", "accepted", false},
		{"queued", "queued", false},
		{"running", "running", false},
		{"completed_business_failure", "completed", false},
		{"completed_tool_error", "completed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task.status, task.isError = tc.status, tc.isError
			f.mu.Lock()
			f.tasks[contractTaskID] = task
			f.mu.Unlock()
			got := contractCallTool(t, alice, "c__query", query)
			contractEqualResult(t, "task status and business failure", "c", got, contractTaskResult(task))
			wantCalls = append(wantCalls, contractCall{"c", "query", "alice", query})
			f.assertCalls(t, wantCalls...)
		})
	}

	spoof := map[string]any{"task_id": contractTaskID, "request_id": "bob-request__opaque", "user": "alice"}
	got = contractCallTool(t, bob, "c__query", spoof)
	contractEqualResult(t, "downstream owner denial despite spoofed user", "c", got, contractDeniedResult(spoof))
	wantCalls = append(wantCalls, contractCall{"c", "query", "bob", spoof})
	f.assertCalls(t, wantCalls...)

	// The denial must not poison the owning user's access or produce a gateway
	// task-ownership cache. Both subsequent queries reach the service again.
	got = contractCallTool(t, alice, "c__query", query)
	contractEqualResult(t, "owner still sees exact task result", "c", got, contractTaskResult(task))
	wantCalls = append(wantCalls, contractCall{"c", "query", "alice", query})
	unknown := map[string]any{"task_id": "unseen:c__task/%2F", "request_id": contractRequestID}
	got = contractCallTool(t, alice, "c__query", unknown)
	contractEqualResult(t, "unknown task checked downstream", "c", got, contractDeniedResult(unknown))
	wantCalls = append(wantCalls, contractCall{"c", "query", "alice", unknown})
	time.Sleep(50 * time.Millisecond)
	f.assertCalls(t, wantCalls...)
}

func TestToolContractLostSubmitResponseDoesNotResubmitOrPoll(t *testing.T) {
	f := newContractFixture(t)
	submit := contractSubmitArgs()
	f.mu.Lock()
	f.dropKey = contractKey
	f.mu.Unlock()
	got, err := f.gateway.Call(context.Background(), "alice", "c__submit", submit)
	if got != nil || err == nil || !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "not retried") {
		t.Fatalf("lost response must leave an unknown outcome, not success or safe-to-retry: result=%v error=%v", got, err)
	}
	wantCalls := []contractCall{{"c", "submit", "alice", submit}}
	f.assertCalls(t, wantCalls...)
	f.mu.Lock()
	submits, drops := f.submits, f.drops
	f.mu.Unlock()
	if submits != 1 || drops != 1 {
		t.Fatalf("submission repeated after response loss: submissions=%d lost responses=%d", submits, drops)
	}

	// A caller with a business task identifier can make a separate explicit
	// query after an unknown submission outcome. No resubmission is required.
	alice := connect(t, f.server.URL, "entry-alice")
	query := map[string]any{"task_id": contractTaskID, "request_id": contractRequestID}
	task := contractTask{owner: "alice", requestID: contractRequestID, parentID: contractParentID, key: contractKey, status: "accepted"}
	got = contractCallTool(t, alice, "c__query", query)
	contractEqualResult(t, "explicit query after unknown outcome", "c", got, contractTaskResult(task))
	wantCalls = append(wantCalls, contractCall{"c", "query", "alice", query})
	time.Sleep(50 * time.Millisecond)
	f.assertCalls(t, wantCalls...)
}
