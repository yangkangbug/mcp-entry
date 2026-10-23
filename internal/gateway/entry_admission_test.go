package gateway

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Synthetic in-memory revision change isolates the admission fence from storage.
func advanceSyntheticEntry(g *Gateway, id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := clonePrincipal(g.principals[id])
	p.entry.Generation++
	g.principals[id] = p
	g.invalidateLocked(id, "")
	g.cancelOperationsLocked(id, "")
}

func TestEntryRevisionRejectsStaleContext(t *testing.T) {
	g, _, _, _ := accountFixture(t)
	identity := Identity{"demo", "alice"}
	ctx := withEntryRevision(context.Background(), identity, 1)
	advanceSyntheticEntry(g, "alice")
	if _, err := g.accountBindings(ctx, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale metadata: %v", err)
	}
	if issues := g.RefreshBinding(ctx, identity, "crm"); len(issues) == 0 {
		t.Fatal("stale discovery admitted")
	}
	if _, err := g.Call(ctx, "alice", "crm__echo", map[string]any{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale call: %v", err)
	}
	if _, err := g.replaceBinding(identity, "crm", 1, "a-replacement", g.principals["alice"].entry.ExpiresAt, true, 1); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale replace: %v", err)
	}
	if _, err := g.revokeBinding(identity, "crm", 1, true, 1); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale revoke: %v", err)
	}
}

type entryPauseReader struct {
	io.Reader
	once            sync.Once
	started, resume chan struct{}
}

func (r *entryPauseReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started); <-r.resume })
	return r.Reader.Read(p)
}
func TestAccountRotationDuringBodyReadCannotMutate(t *testing.T) {
	g, h, token, _ := accountFixture(t)
	body := &entryPauseReader{Reader: strings.NewReader(`{"expected_generation":1,"credential":"a-replacement"}`), started: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/account/api/bindings/crm", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, req); close(done) }()
	<-body.started
	advanceSyntheticEntry(g, "alice")
	close(body.resume)
	<-done
	if w.Code != 403 {
		t.Fatalf("stale write status %d: %s", w.Code, w.Body)
	}
	b, _ := g.Binding(Identity{"demo", "alice"}, "crm")
	if b.Generation != 1 {
		t.Fatal("stale entry mutated binding")
	}
}

func TestEntryRotationCapturedHandlerSessionRejected(t *testing.T) {
	g, _, _ := clientFixture(t)
	server := httptest.NewServer(g.state.Load().handlers["alice"])
	defer server.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "entry-fence-test", Version: "1"}, nil)
	session, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: server.URL, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	advanceSyntheticEntry(g, "alice")
	if _, err := session.ListTools(context.Background(), nil); err == nil {
		t.Fatal("old captured handler accepted list")
	}
	if result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: clientConnectionsTool, Arguments: map[string]any{}}); err == nil && !result.IsError {
		t.Fatal("old captured handler accepted control call")
	}
}
