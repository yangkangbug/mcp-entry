package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// cleanupBlock observes the lifetime of a real HTTP request. Teardown can also
// release it, so a failed cancellation regression never hangs server.Close.
// Tests require release through the request context, not this teardown escape.
type cleanupBlock struct {
	enabled atomic.Bool
	active  atomic.Int32
	started chan context.Context
	ended   chan bool
}

func newCleanupBlock() *cleanupBlock {
	return &cleanupBlock{started: make(chan context.Context, 16), ended: make(chan bool, 16)}
}

func (b *cleanupBlock) wait(ctx context.Context, teardown <-chan struct{}) {
	b.active.Add(1)
	b.started <- ctx
	canceled := false
	select {
	case <-ctx.Done():
		canceled = true
	case <-teardown:
	}
	b.active.Add(-1)
	b.ended <- canceled
}

type cleanupFixture struct {
	server                            *httptest.Server
	requests, calls, lists            atomic.Int32
	deletes, initializations          atomic.Int32
	paginate                          atomic.Bool
	deleteBlock, callBlock, listBlock *cleanupBlock
	teardown                          chan struct{}
	stopOnce                          sync.Once
	mu                                sync.Mutex
	sessions                          map[string]bool
}

// This deliberately implements the legacy, stateful Streamable HTTP handshake:
// server/discover is unsupported and initialize returns a session ID. Otherwise
// the SDK may negotiate its newer sessionless mode, never exercising DELETE.
func newCleanupFixture(t *testing.T) (*cleanupFixture, *gateway.Gateway) {
	t.Helper()
	f := &cleanupFixture{
		deleteBlock: newCleanupBlock(), callBlock: newCleanupBlock(), listBlock: newCleanupBlock(),
		teardown: make(chan struct{}), sessions: map[string]bool{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-downstream" {
			t.Error("missing or incorrect downstream credential")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
				t.Error("DELETE did not address an initialized session")
				http.Error(w, "unknown session", http.StatusNotFound)
				return
			}
			f.deletes.Add(1)
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
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("invalid JSON-RPC request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(request.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Method == "server/discover" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			return
		}
		var result any
		switch request.Method {
		case "initialize":
			id := fmt.Sprintf("synthetic-session-%d", f.initializations.Add(1))
			f.mu.Lock()
			f.sessions[id] = true
			f.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			result = map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "cleanup-fixture", "version": "1"}}
		case "tools/list", "tools/call":
			if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
				t.Errorf("%s did not address an initialized session", request.Method)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if request.Method == "tools/call" {
				f.calls.Add(1)
				if f.callBlock.enabled.Load() {
					f.callBlock.wait(r.Context(), f.teardown)
					return
				}
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "confirmed-success"}}}
			} else {
				f.lists.Add(1)
				if f.listBlock.enabled.Load() && request.Params.Cursor == "next" {
					f.listBlock.wait(r.Context(), f.teardown)
					return
				}
				list := map[string]any{"tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{"type": "object"}}}}
				if f.paginate.Load() {
					list["nextCursor"] = "next"
				}
				result = list
			}
		default:
			t.Errorf("unexpected JSON-RPC method: %s", request.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(func() {
		f.stop()
		f.server.CloseClientConnections()
		f.server.Close()
	})
	g, err := gateway.New(gateway.Config{
		Systems: []gateway.System{{Name: "test", Endpoint: f.server.URL}},
		Users:   map[string]gateway.User{"u": {Token: "synthetic", Allowed: []string{"test__echo"}, Credentials: map[string]string{"test": "synthetic-downstream"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, g
}

func (f *cleanupFixture) stop() { f.stopOnce.Do(func() { close(f.teardown) }) }

func (f *cleanupFixture) hasSession(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[id]
}

func cleanupSeedCatalog(t *testing.T, g *gateway.Gateway) {
	t.Helper()
	if issues := g.Refresh(context.Background()); len(issues) != 0 {
		t.Fatalf("initial discovery failed: %v", issues)
	}
}

// Test operations run concurrently only to coordinate cancellation and enforce
// a watchdog. Every goroutine is joined, including on a failed assertion.
func cleanupStart[T any](t *testing.T, f *cleanupFixture, operation func() T) <-chan T {
	t.Helper()
	result := make(chan T, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- operation()
	}()
	t.Cleanup(func() {
		f.stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("operation did not exit after fixture teardown")
		}
	})
	return result
}

func cleanupReceive[T any](t *testing.T, ch <-chan T, limit time.Duration, description string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(limit):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}

func cleanupAssertReleased(t *testing.T, b *cleanupBlock, requestCtx context.Context) {
	t.Helper()
	cleanupReceive(t, requestCtx.Done(), time.Second, "HTTP request context cancellation")
	if !cleanupReceive(t, b.ended, time.Second, "HTTP handler release") {
		t.Fatal("handler was released by teardown rather than request cancellation")
	}
	if active := b.active.Load(); active != 0 {
		t.Fatalf("blocked HTTP handlers still active: %d", active)
	}
}

type cleanupCallResult struct {
	result *mcp.CallToolResult
	err    error
}

func cleanupCall(g *gateway.Gateway, ctx context.Context) cleanupCallResult {
	result, err := g.Call(ctx, "u", "test__echo", map[string]any{})
	return cleanupCallResult{result, err}
}

func cleanupAssertSuccess(t *testing.T, f *cleanupFixture, got cleanupCallResult) {
	t.Helper()
	if got.err != nil || got.result == nil || got.result.IsError || len(got.result.Content) != 1 {
		t.Fatalf("confirmed success was lost during cleanup: result=%+v err=%v", got.result, got.err)
	}
	text, ok := got.result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "confirmed-success" {
		t.Fatalf("confirmed result changed: %+v", got.result)
	}
	if calls := f.calls.Load(); calls != 1 {
		t.Fatalf("tool execution count=%d, want exactly one", calls)
	}
}

func cleanupAssertCatalog(t *testing.T, g *gateway.Gateway, issues []gateway.DiscoveryIssue) {
	t.Helper()
	if names := g.Names("u"); len(issues) != 0 || len(names) != 1 || names[0] != "test__echo" {
		t.Fatalf("validated catalog was lost during cleanup: issues=%v names=%v", issues, names)
	}
}

func TestCallCleanupRespectsCallerDeadline(t *testing.T) {
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := cleanupStart(t, f, func() cleanupCallResult { return cleanupCall(g, ctx) })
	requestCtx := cleanupReceive(t, f.deleteBlock.started, time.Second, "session DELETE")
	got := cleanupReceive(t, result, time.Second, "bounded call cleanup")
	elapsed := time.Since(start)
	// The operation's child deadline may fire just before its parent's timer.
	cleanupReceive(t, ctx.Done(), time.Second, "caller deadline")
	if elapsed >= time.Second || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("cleanup exceeded caller deadline: elapsed=%s ctx=%v", elapsed, ctx.Err())
	}
	cleanupAssertSuccess(t, f, got)
	cleanupAssertReleased(t, f.deleteBlock, requestCtx)
	if deletes := f.deletes.Load(); deletes != 2 {
		t.Fatalf("DELETE count=%d, want one discovery and one call cleanup", deletes)
	}
}

func TestCallCancellationBeforeOperationSendsNothing(t *testing.T) {
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	before := f.requests.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := cleanupCall(g, ctx)
	if got.err == nil || got.result != nil {
		t.Fatalf("canceled operation succeeded: %+v", got)
	}
	if sent := f.requests.Load() - before; sent != 0 || f.calls.Load() != 0 {
		t.Fatalf("canceled operation sent requests: requests=%d tool calls=%d", sent, f.calls.Load())
	}
}

func TestCallCancellationDuringExecutionIsNotRetried(t *testing.T) {
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	f.callBlock.enabled.Store(true)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := cleanupStart(t, f, func() cleanupCallResult { return cleanupCall(g, ctx) })
	requestCtx := cleanupReceive(t, f.callBlock.started, time.Second, "tools/call")
	cancel()
	got := cleanupReceive(t, result, time.Second, "canceled tool call")
	if got.err == nil || got.result != nil || !strings.Contains(got.err.Error(), "not retried") {
		t.Fatalf("unexpected canceled call result: result=%+v err=%v", got.result, got.err)
	}
	cleanupAssertReleased(t, f.callBlock, requestCtx)
	if calls := f.calls.Load(); calls != 1 {
		t.Fatalf("canceled tool call retried: calls=%d", calls)
	}
	if active := f.deleteBlock.active.Load(); active != 0 {
		t.Fatalf("canceled call left DELETE handler active: %d", active)
	}
}

func TestCallCancellationDuringCleanupPreservesSuccess(t *testing.T) {
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := cleanupStart(t, f, func() cleanupCallResult { return cleanupCall(g, ctx) })
	requestCtx := cleanupReceive(t, f.deleteBlock.started, time.Second, "session DELETE after confirmed success")
	cancel()
	got := cleanupReceive(t, result, time.Second, "canceled session cleanup")
	cleanupAssertSuccess(t, f, got)
	cleanupAssertReleased(t, f.deleteBlock, requestCtx)
}

func TestDiscoveryCleanupRespectsCallerDeadline(t *testing.T) {
	f, g := newCleanupFixture(t)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := cleanupStart(t, f, func() []gateway.DiscoveryIssue { return g.Refresh(ctx) })
	requestCtx := cleanupReceive(t, f.deleteBlock.started, time.Second, "discovery session DELETE")
	issues := cleanupReceive(t, result, time.Second, "bounded discovery cleanup")
	elapsed := time.Since(start)
	// The operation's child deadline may fire just before its parent's timer.
	cleanupReceive(t, ctx.Done(), time.Second, "caller deadline")
	if elapsed >= time.Second || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("cleanup exceeded caller deadline: elapsed=%s ctx=%v", elapsed, ctx.Err())
	}
	cleanupAssertCatalog(t, g, issues)
	cleanupAssertReleased(t, f.deleteBlock, requestCtx)
	if f.lists.Load() != 1 || f.deletes.Load() != 1 {
		t.Fatalf("unexpected discovery requests: lists=%d deletes=%d", f.lists.Load(), f.deletes.Load())
	}
}

func TestDiscoveryCleanupRespectsInternalDeadline(t *testing.T) {
	f, g := newCleanupFixture(t)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	result := cleanupStart(t, f, func() []gateway.DiscoveryIssue { return g.Refresh(ctx) })
	requestCtx := cleanupReceive(t, f.deleteBlock.started, time.Second, "discovery session DELETE")
	issues := cleanupReceive(t, result, 7*time.Second, "internal five-second discovery deadline")
	if elapsed := time.Since(start); elapsed < 4*time.Second || elapsed >= 7*time.Second || ctx.Err() != nil {
		t.Fatalf("cleanup ignored internal discovery deadline: elapsed=%s caller ctx=%v", elapsed, ctx.Err())
	}
	cleanupAssertCatalog(t, g, issues)
	cleanupAssertReleased(t, f.deleteBlock, requestCtx)
}

func TestDiscoveryInterruptedListDoesNotPublishPartialCatalog(t *testing.T) {
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	before := f.lists.Load()
	f.paginate.Store(true)
	f.listBlock.enabled.Store(true)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := cleanupStart(t, f, func() []gateway.DiscoveryIssue { return g.Refresh(ctx) })
	requestCtx := cleanupReceive(t, f.listBlock.started, time.Second, "second tools/list page")
	cancel()
	issues := cleanupReceive(t, result, time.Second, "interrupted discovery")
	if names := g.Names("u"); len(issues) != 1 || len(names) != 0 {
		t.Fatalf("partial or stale catalog published: issues=%v names=%v", issues, names)
	}
	cleanupAssertReleased(t, f.listBlock, requestCtx)
	if lists := f.lists.Load() - before; lists != 2 {
		t.Fatalf("unexpected or retried list requests: %d", lists)
	}
	if f.calls.Load() != 0 || f.deleteBlock.active.Load() != 0 {
		t.Fatalf("interrupted discovery leaked work: calls=%d active DELETE=%d", f.calls.Load(), f.deleteBlock.active.Load())
	}
}
