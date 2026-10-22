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
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// These are application compatibility tests, not a complete MCP conformance
// suite. The modern fixture uses the official SDK. The synthetic legacy fixture
// forces initialize negotiation and POST-response framing that a current SDK
// server would otherwise negotiate automatically. The 2024-11-05 transport was
// HTTP+SSE, not Streamable HTTP, and is intentionally outside this matrix.
const protocolModern = "2026-07-28"

type protocolInput struct {
	Message string `json:"message"`
}

type protocolOutput struct {
	User    string `json:"user"`
	Message string `json:"message"`
}

type protocolRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Name            string         `json:"name"`
		Arguments       protocolInput  `json:"arguments"`
		Meta            map[string]any `json:"_meta"`
	} `json:"params"`
}

type protocolRecord struct {
	Method, Token, Session, Version, RequestedVersion, MetaVersion string
	ResponseType                                                   string
}

type protocolLog struct {
	mu      sync.Mutex
	records []protocolRecord
}

func (l *protocolLog) add(r *http.Request, request protocolRequest) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	method := request.Method
	if method == "" {
		method = r.Method
	}
	metaVersion, _ := request.Params.Meta[mcp.MetaKeyProtocolVersion].(string)
	l.records = append(l.records, protocolRecord{
		Method: method, Token: r.Header.Get("Authorization"), Session: r.Header.Get("Mcp-Session-Id"),
		Version: r.Header.Get("Mcp-Protocol-Version"), RequestedVersion: request.Params.ProtocolVersion,
		MetaVersion: metaVersion,
	})
	return len(l.records) - 1
}

func (l *protocolLog) response(index int, contentType string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records[index].ResponseType = contentType
}

func (l *protocolLog) snapshot() []protocolRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]protocolRecord(nil), l.records...)
}

func (l *protocolLog) count(method string) int {
	count := 0
	for _, record := range l.snapshot() {
		if record.Method == method {
			count++
		}
	}
	return count
}

func protocolAssertDiscoveryCredentials(t *testing.T, log *protocolLog) {
	t.Helper()
	counts := map[string]int{}
	for _, record := range log.snapshot() {
		if record.Method == "tools/list" {
			counts[record.Token]++
		}
	}
	want := map[string]int{"Bearer synthetic-downstream-alice": 1, "Bearer synthetic-downstream-bob": 1}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("discovery did not use each user's own credential: got=%v want=%v", counts, want)
	}
}

type protocolWriter struct {
	http.ResponseWriter
	log   *protocolLog
	index int
}

func (w *protocolWriter) WriteHeader(status int) {
	w.log.response(w.index, w.Header().Get("Content-Type"))
	w.ResponseWriter.WriteHeader(status)
}

func (w *protocolWriter) Write(b []byte) (int, error) {
	w.log.response(w.index, w.Header().Get("Content-Type"))
	return w.ResponseWriter.Write(b)
}

func (w *protocolWriter) Flush() {
	w.log.response(w.index, w.Header().Get("Content-Type"))
	w.ResponseWriter.(http.Flusher).Flush()
}

func (w *protocolWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func protocolConfig(endpoint string) gateway.Config {
	return gateway.Config{
		Systems: []gateway.System{{Name: "test", Endpoint: endpoint}},
		Users: map[string]gateway.User{
			"alice": {Token: "synthetic-entry-alice", Allowed: []string{"test__echo"}, Credentials: map[string]string{"test": "synthetic-downstream-alice"}},
			"bob":   {Token: "synthetic-entry-bob", Allowed: []string{"test__echo"}, Credentials: map[string]string{"test": "synthetic-downstream-bob"}},
		},
	}
}

func protocolGateway(t *testing.T, endpoint string) *gateway.Gateway {
	t.Helper()
	g, err := gateway.New(protocolConfig(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func protocolRefresh(t *testing.T, g *gateway.Gateway) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatalf("discovery failed: %v", issues)
	}
}

func protocolAssertResult(t *testing.T, result *mcp.CallToolResult, err error, user, message string) {
	t.Helper()
	if err != nil || result == nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("call result=%+v error=%v", result, err)
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok || content.Text != user+":"+message {
		t.Fatalf("unexpected text content: %+v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var output protocolOutput
	if err := json.Unmarshal(encoded, &output); err != nil || output != (protocolOutput{user, message}) {
		t.Fatalf("identity/result changed: output=%+v error=%v", output, err)
	}
}

func protocolSDKFixture(t *testing.T, jsonResponse bool) (*gateway.Gateway, *protocolLog) {
	t.Helper()
	log := &protocolLog{}
	handlers := map[string]http.Handler{}
	for _, user := range []string{"alice", "bob"} {
		server := mcp.NewServer(&mcp.Implementation{Name: "protocol-fixture", Version: "1"}, nil)
		mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Synthetic protocol echo"},
			func(_ context.Context, _ *mcp.CallToolRequest, input protocolInput) (*mcp.CallToolResult, protocolOutput, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: user + ":" + input.Message}}}, protocolOutput{user, input.Message}, nil
			})
		handlers["Bearer synthetic-downstream-"+user] = mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: jsonResponse})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var request protocolRequest
		if len(body) != 0 {
			if err := json.Unmarshal(body, &request); err != nil {
				t.Errorf("decode request: %v", err)
			}
		}
		index := log.add(r, request)
		handler, ok := handlers[r.Header.Get("Authorization")]
		if !ok {
			t.Error("downstream received a missing, upstream, or unknown credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(&protocolWriter{ResponseWriter: w, log: log, index: index}, r)
	}))
	t.Cleanup(server.Close)
	return protocolGateway(t, server.URL), log
}

func TestProtocolModernJSONAndSSE(t *testing.T) {
	var baselineTools, baselineResult []byte
	for _, format := range []string{"json", "sse"} {
		t.Run(format, func(t *testing.T) {
			g, log := protocolSDKFixture(t, format == "json")
			protocolRefresh(t, g)
			entry := httptest.NewServer(g.Handler())
			t.Cleanup(entry.Close)
			for _, user := range []string{"alice", "bob"} {
				session := connect(t, entry.URL, "synthetic-entry-"+user)
				if got := session.InitializeResult().ProtocolVersion; got != protocolModern {
					t.Fatalf("upstream negotiated %q, want %q", got, protocolModern)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				list, err := session.ListTools(ctx, nil)
				if err != nil || len(list.Tools) != 1 || list.Tools[0].Name != "test__echo" {
					t.Fatalf("tools/list=%+v error=%v", list, err)
				}
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "test__echo", Arguments: protocolInput{"hello"}})
				protocolAssertResult(t, result, err, user, "hello")
				if user == "alice" {
					toolsJSON, _ := json.Marshal(list)
					resultJSON, _ := json.Marshal(result)
					if baselineTools == nil {
						baselineTools, baselineResult = toolsJSON, resultJSON
					} else if !bytes.Equal(toolsJSON, baselineTools) || !bytes.Equal(resultJSON, baselineResult) {
						t.Fatalf("JSON and SSE application results differ: list=%s result=%s", toolsJSON, resultJSON)
					}
				}
			}
			// Parallel sessions must retain the caller's downstream identity in both
			// framing modes, rather than sharing one user's authenticated discovery.
			type identityResult struct {
				user string
				cleanupCallResult
			}
			outcomes := make(chan identityResult, 8)
			var workers sync.WaitGroup
			for i := 0; i < 8; i++ {
				user := []string{"alice", "bob"}[i%2]
				workers.Add(1)
				go func() {
					defer workers.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					result, err := g.Call(ctx, user, "test__echo", protocolInput{"parallel"})
					outcomes <- identityResult{user, cleanupCallResult{result, err}}
				}()
			}
			workers.Wait()
			close(outcomes)
			for outcome := range outcomes {
				protocolAssertResult(t, outcome.result, outcome.err, outcome.user, "parallel")
			}
			protocolAssertDiscoveryCredentials(t, log)
			wantType := "application/json"
			if format == "sse" {
				wantType = "text/event-stream"
			}
			for _, record := range log.snapshot() {
				if record.Method != "server/discover" && record.Method != "tools/list" && record.Method != "tools/call" {
					t.Errorf("unexpected modern request: %+v", record)
				}
				if record.Session != "" || record.Version != protocolModern || record.MetaVersion != protocolModern {
					t.Errorf("modern per-request negotiation metadata missing: %+v", record)
				}
				if (record.Method == "tools/list" || record.Method == "tools/call") && !strings.HasPrefix(record.ResponseType, wantType) {
					t.Errorf("did not exercise %s response: %+v", format, record)
				}
			}
		})
	}
}

const (
	protocolCallNormal int32 = iota
	protocolCallWaitBeforeResult
	protocolCallWaitAfterResult
	protocolCallTruncated
	protocolCallDisconnected
	protocolCallOversized
	protocolCallOversizedComments
)

type protocolLegacyFixture struct {
	server       *httptest.Server
	log          protocolLog
	version      string
	sse          bool
	fallbackHTTP bool
	eventID      bool
	callMode     atomic.Int32
	oversizeList atomic.Bool
	sequence     atomic.Int32
	callBlock    *cleanupBlock
	deleteBlock  *cleanupBlock
	teardown     chan struct{}
	stopOnce     sync.Once
	mu           sync.Mutex
	sessions     map[string]string
}

func newProtocolLegacyFixture(t *testing.T, version, format string) (*protocolLegacyFixture, *gateway.Gateway) {
	t.Helper()
	f := &protocolLegacyFixture{
		version: version, sse: format == "sse", sessions: map[string]string{}, teardown: make(chan struct{}),
		callBlock: newCleanupBlock(), deleteBlock: newCleanupBlock(),
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocolRequest
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		index := f.log.add(r, request)
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer synthetic-downstream-")
		if user != "alice" && user != "bob" {
			t.Error("missing or incorrect downstream credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			// Standalone SSE and stream resumption are outside this gateway's scope.
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if request.Method != "server/discover" && request.Method != "initialize" {
			f.mu.Lock()
			owner := f.sessions[r.Header.Get("Mcp-Session-Id")]
			f.mu.Unlock()
			if owner != user || r.Header.Get("Mcp-Protocol-Version") != f.version {
				t.Errorf("session identity or negotiated version changed: method=%s owner=%q user=%q version=%q", request.Method, owner, user, r.Header.Get("Mcp-Protocol-Version"))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		if r.Method == http.MethodDelete {
			if f.deleteBlock.enabled.Load() {
				f.deleteBlock.wait(r.Context(), f.teardown)
			}
			f.mu.Lock()
			delete(f.sessions, r.Header.Get("Mcp-Session-Id"))
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if len(request.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if request.Method == "server/discover" {
			w.Header().Set("Content-Type", "application/json")
			if f.fallbackHTTP {
				w.WriteHeader(http.StatusNotFound)
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			}
			return
		}
		var result any
		switch request.Method {
		case "initialize":
			id := fmt.Sprintf("synthetic-session-%d", f.sequence.Add(1))
			f.mu.Lock()
			f.sessions[id] = user
			f.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			result = map[string]any{"protocolVersion": f.version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "legacy-protocol-fixture", "version": "1"}}
		case "tools/list":
			tool := map[string]any{"name": "echo", "description": "Synthetic protocol echo", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}, "required": []string{"message"}}}
			if f.oversizeList.Load() {
				tool["description"] = strings.Repeat("x", (1<<20)+1)
			}
			result = map[string]any{"tools": []any{tool}}
		case "tools/call":
			if request.Params.Name != "echo" {
				t.Errorf("gateway failed to restore downstream tool name: %q", request.Params.Name)
			}
			message := request.Params.Arguments.Message
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": user + ":" + message}}, "structuredContent": protocolOutput{user, message}}
			if f.callMode.Load() == protocolCallOversized {
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": strings.Repeat("x", (1<<20)+1)}}}
			}
		default:
			t.Errorf("unexpected JSON-RPC method %q", request.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		if err != nil {
			t.Errorf("encode result: %v", err)
			return
		}
		if !f.sse {
			w.Header().Set("Content-Type", "application/json")
			f.log.response(index, "application/json")
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		f.log.response(index, "text/event-stream")
		_, _ = io.WriteString(w, ": synthetic heartbeat\r\n\r\n")
		w.(http.Flusher).Flush()
		if request.Method == "tools/call" {
			switch f.callMode.Load() {
			case protocolCallWaitBeforeResult:
				f.callBlock.wait(r.Context(), f.teardown)
				return
			case protocolCallTruncated, protocolCallDisconnected:
				if f.eventID {
					_, _ = io.WriteString(w, "id: synthetic-event-1\ndata:\n\n")
				}
				if f.callMode.Load() == protocolCallTruncated {
					_, _ = w.Write(append([]byte("event: message\ndata: "), body[:len(body)/2]...))
				}
				w.(http.Flusher).Flush()
				if f.callMode.Load() == protocolCallDisconnected {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("disconnect fixture: %v", err)
					} else {
						_ = conn.Close()
					}
				}
				return
			case protocolCallOversizedComments:
				// No individual event is large. The total response byte limit must
				// still apply to comments/heartbeats before the eventual result.
				comment := ": " + strings.Repeat("x", 1024) + "\n\n"
				for i := 0; i < 1024; i++ {
					if _, err := io.WriteString(w, comment); err != nil {
						return
					}
				}
			}
		}
		_, _ = fmt.Fprintf(w, "event: message\r\ndata: %s\r\n\r\n", body)
		w.(http.Flusher).Flush()
		if request.Method == "tools/call" && f.callMode.Load() == protocolCallWaitAfterResult {
			f.callBlock.wait(r.Context(), f.teardown)
		}
	}))
	t.Cleanup(func() {
		f.stop()
		f.server.CloseClientConnections()
		f.server.Close()
	})
	return f, protocolGateway(t, f.server.URL)
}

func (f *protocolLegacyFixture) stop() { f.stopOnce.Do(func() { close(f.teardown) }) }

func TestProtocolLegacyInitializeJSONAndSSE(t *testing.T) {
	for _, version := range []string{"2025-03-26", "2025-06-18", "2025-11-25"} {
		t.Run(version, func(t *testing.T) {
			var baseline []byte
			for _, format := range []string{"json", "sse"} {
				t.Run(format, func(t *testing.T) {
					f, g := newProtocolLegacyFixture(t, version, format)
					protocolRefresh(t, g)
					for _, user := range []string{"alice", "bob"} {
						if names := g.Names(user); !reflect.DeepEqual(names, []string{"test__echo"}) {
							t.Fatalf("tools/list names=%v", names)
						}
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						result, err := g.Call(ctx, user, "test__echo", protocolInput{"hello"})
						protocolAssertResult(t, result, err, user, "hello")
						if user == "alice" {
							encoded, _ := json.Marshal(result)
							if baseline == nil {
								baseline = encoded
							} else if !bytes.Equal(encoded, baseline) {
								t.Fatalf("JSON and SSE results differ: %s != %s", encoded, baseline)
							}
						}
					}
					protocolAssertDiscoveryCredentials(t, &f.log)
					for _, method := range []string{"server/discover", "initialize", "notifications/initialized", "DELETE"} {
						if count := f.log.count(method); count != 4 {
							t.Errorf("%s count=%d, want four independent discovery/call sessions", method, count)
						}
					}
					if count := f.log.count("GET"); count != 0 {
						t.Errorf("unexpected standalone SSE request count=%d", count)
					}
					for _, record := range f.log.snapshot() {
						switch record.Method {
						case "server/discover":
							if record.Version != protocolModern || record.MetaVersion != protocolModern {
								t.Errorf("modern discovery probe changed: %+v", record)
							}
						case "initialize":
							if record.RequestedVersion != "2025-11-25" {
								t.Errorf("legacy fallback advertised version=%q", record.RequestedVersion)
							}
						default:
							if record.Version != version || record.Session == "" {
								t.Errorf("server-selected legacy version/session was not used: %+v", record)
							}
						}
					}
				})
			}
		})
	}
}

func TestProtocolInitializeFallbackAfterHTTP404(t *testing.T) {
	f, g := newProtocolLegacyFixture(t, "2025-11-25", "sse")
	f.fallbackHTTP = true
	protocolRefresh(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := g.Call(ctx, "alice", "test__echo", protocolInput{"fallback"})
	protocolAssertResult(t, result, err, "alice", "fallback")
	if f.log.count("initialize") != 3 || f.log.count("tools/call") != 1 {
		t.Fatalf("fallback handshake or tool execution count changed: %+v", f.log.snapshot())
	}
}

// The public SDK intentionally negotiates the latest protocol. These direct
// legacy requests verify that the gateway's SDK-backed HTTP handler also serves
// clients which explicitly initialize with an older Streamable HTTP version.
func TestProtocolUpstreamLegacyVersions(t *testing.T) {
	for _, format := range []string{"json", "sse"} {
		t.Run("downstream_"+format, func(t *testing.T) {
			g, _ := protocolSDKFixture(t, format == "json")
			protocolRefresh(t, g)
			server := httptest.NewServer(g.Handler())
			t.Cleanup(server.Close)
			for _, version := range []string{"2025-03-26", "2025-06-18", "2025-11-25"} {
				t.Run(version, func(t *testing.T) {
					initialize := protocolLegacyRPC(t, server.URL, version, 1, "initialize", map[string]any{
						"protocolVersion": version, "capabilities": map[string]any{},
						"clientInfo": map[string]any{"name": "synthetic-legacy-client", "version": "1"},
					})
					var negotiated mcp.InitializeResult
					if err := json.Unmarshal(initialize, &negotiated); err != nil || negotiated.ProtocolVersion != version {
						t.Fatalf("upstream selected version=%q, want %q; error=%v", negotiated.ProtocolVersion, version, err)
					}
					protocolLegacyRPC(t, server.URL, version, 0, "notifications/initialized", map[string]any{})
					listed := protocolLegacyRPC(t, server.URL, version, 2, "tools/list", map[string]any{})
					var list mcp.ListToolsResult
					if err := json.Unmarshal(listed, &list); err != nil || len(list.Tools) != 1 || list.Tools[0].Name != "test__echo" {
						t.Fatalf("legacy tools/list=%s error=%v", listed, err)
					}
					called := protocolLegacyRPC(t, server.URL, version, 3, "tools/call", map[string]any{
						"name": "test__echo", "arguments": protocolInput{"legacy-client"},
					})
					var result mcp.CallToolResult
					if err := json.Unmarshal(called, &result); err != nil {
						t.Fatal(err)
					}
					protocolAssertResult(t, &result, nil, "alice", "legacy-client")
				})
			}
		})
	}
}

func protocolLegacyRPC(t *testing.T, endpoint, version string, id int, method string, params any) json.RawMessage {
	t.Helper()
	message := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != 0 {
		message["id"] = id
	}
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer synthetic-entry-alice")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", version)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if id == 0 {
		if response.StatusCode != http.StatusAccepted {
			t.Fatalf("notification status=%d, want 202", response.StatusCode)
		}
		return nil
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("legacy %s status=%d content-type=%q", method, response.StatusCode, response.Header.Get("Content-Type"))
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.JSONRPC != "2.0" || envelope.ID != id || len(envelope.Error) != 0 || len(envelope.Result) == 0 {
		t.Fatalf("invalid legacy %s envelope: %+v", method, envelope)
	}
	return envelope.Result
}

func protocolStartCall(t *testing.T, f *protocolLegacyFixture, g *gateway.Gateway, ctx context.Context) <-chan cleanupCallResult {
	t.Helper()
	result := make(chan cleanupCallResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		value, err := g.Call(ctx, "alice", "test__echo", protocolInput{"confirmed"})
		result <- cleanupCallResult{value, err}
	}()
	t.Cleanup(func() {
		f.stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("protocol call did not exit after fixture teardown")
		}
	})
	return result
}

func TestProtocolSSECancellationBeforeResult(t *testing.T) {
	f, g := newProtocolLegacyFixture(t, "2025-11-25", "sse")
	protocolRefresh(t, g)
	f.callMode.Store(protocolCallWaitBeforeResult)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := protocolStartCall(t, f, g, ctx)
	requestCtx := cleanupReceive(t, f.callBlock.started, time.Second, "open SSE response")
	cancel()
	got := cleanupReceive(t, result, time.Second, "canceled SSE call")
	if got.err == nil || got.result != nil || !strings.Contains(got.err.Error(), "outcome may be unknown; not retried") {
		t.Fatalf("cancellation was not reported as an unconfirmed outcome: %+v", got)
	}
	cleanupAssertReleased(t, f.callBlock, requestCtx)
	if calls := f.log.count("tools/call"); calls != 1 {
		t.Fatalf("canceled tool execution count=%d", calls)
	}
}

func TestProtocolSSEConfirmedResultSurvivesCleanupCancellation(t *testing.T) {
	f, g := newProtocolLegacyFixture(t, "2025-11-25", "sse")
	protocolRefresh(t, g)
	f.callMode.Store(protocolCallWaitAfterResult)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := protocolStartCall(t, f, g, ctx)
	streamCtx := cleanupReceive(t, f.callBlock.started, time.Second, "SSE response held open after result")
	// DELETE starts only once the gateway has received the complete tool result.
	deleteCtx := cleanupReceive(t, f.deleteBlock.started, time.Second, "cleanup after confirmed SSE result")
	cancel()
	got := cleanupReceive(t, result, time.Second, "confirmed result after cleanup cancellation")
	protocolAssertResult(t, got.result, got.err, "alice", "confirmed")
	cleanupAssertReleased(t, f.callBlock, streamCtx)
	cleanupAssertReleased(t, f.deleteBlock, deleteCtx)
	if calls := f.log.count("tools/call"); calls != 1 {
		t.Fatalf("confirmed tool execution count=%d", calls)
	}
}

func TestProtocolBrokenSSENeverReplaysTool(t *testing.T) {
	for _, mode := range []struct {
		name string
		mode int32
	}{{"truncated", protocolCallTruncated}, {"disconnected", protocolCallDisconnected}} {
		for _, eventID := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/event_id_%t", mode.name, eventID), func(t *testing.T) {
				f, g := newProtocolLegacyFixture(t, "2025-11-25", "sse")
				f.eventID = eventID
				protocolRefresh(t, g)
				f.callMode.Store(mode.mode)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				result, err := g.Call(ctx, "alice", "test__echo", protocolInput{"unknown"})
				if err == nil || result != nil || !strings.Contains(err.Error(), "outcome may be unknown; not retried") {
					t.Fatalf("broken stream produced a confirmed outcome: result=%+v error=%v", result, err)
				}
				if ctx.Err() != nil {
					t.Fatal("broken stream was not detected before caller deadline")
				}
				if calls := f.log.count("tools/call"); calls != 1 {
					t.Fatalf("ambiguous tool outcome was replayed: count=%d", calls)
				}
				if count := f.log.count("GET"); count != 0 {
					t.Fatalf("unexpected SSE resume/standalone GET count=%d", count)
				}
			})
		}
	}
}

func TestProtocolResponseByteBound(t *testing.T) {
	for _, format := range []string{"json", "sse"} {
		t.Run(format, func(t *testing.T) {
			f, g := newProtocolLegacyFixture(t, "2025-11-25", format)
			protocolRefresh(t, g)
			f.callMode.Store(protocolCallOversized)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := g.Call(ctx, "alice", "test__echo", protocolInput{"oversized"})
			if err == nil || result != nil {
				t.Fatalf("oversized %s result accepted: result=%+v error=%v", format, result, err)
			}
			if calls := f.log.count("tools/call"); calls != 1 {
				t.Fatalf("oversized result caused replay: count=%d", calls)
			}
			f.oversizeList.Store(true)
			issues := g.Refresh(ctx)
			if len(issues) != 2 || len(g.Names("alice")) != 0 || len(g.Names("bob")) != 0 {
				t.Fatalf("oversized catalog did not fail closed: issues=%v alice=%v bob=%v", issues, g.Names("alice"), g.Names("bob"))
			}
			if ctx.Err() != nil {
				t.Fatal("response size failure depended on caller deadline")
			}
		})
	}
}

func TestProtocolSSEAggregateResponseByteBound(t *testing.T) {
	f, g := newProtocolLegacyFixture(t, "2025-11-25", "sse")
	protocolRefresh(t, g)
	f.callMode.Store(protocolCallOversizedComments)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := g.Call(ctx, "alice", "test__echo", protocolInput{"after-heartbeats"})
	if err == nil || result != nil || ctx.Err() != nil {
		t.Fatalf("aggregate SSE bound failed: result=%+v error=%v context=%v", result, err, ctx.Err())
	}
	if f.log.count("tools/call") != 1 || f.log.count("GET") != 0 {
		t.Fatal("oversized SSE stream was replayed or resumed")
	}
}
