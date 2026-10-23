package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// revocationBarrier orders races by observable events, never scheduler sleeps.
// Cleanup releases a failed test's waiter before httptest.Server.Close runs.
type revocationBarrier struct {
	entered, release chan struct{}
	once             sync.Once
}

func newRevocationBarrier(t *testing.T) *revocationBarrier {
	b := &revocationBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(b.open)
	return b
}
func (b *revocationBarrier) open() { b.once.Do(func() { close(b.release) }) }
func (b *revocationBarrier) wait(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-b.entered:
	case <-ctx.Done():
		t.Fatal("barrier not reached")
	}
}
func (b *revocationBarrier) block(ctx context.Context) {
	select {
	case b.entered <- struct{}{}:
	case <-ctx.Done():
		return
	}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

type revocationFixture struct {
	server          *httptest.Server
	requests, calls atomic.Int32
	mu              sync.Mutex
	gateMethod      string
	gate            *revocationBarrier
	failCall        bool
}

func newRevocationFixture(t *testing.T) *revocationFixture {
	f := &revocationFixture{}
	handlers := map[string]http.Handler{}
	for _, identity := range []string{"east", "west"} {
		srv := mcp.NewServer(&mcp.Implementation{Name: "revocation-fixture", Version: "1"}, nil)
		srv.AddTool(&mcp.Tool{Name: "whoami", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return discoveryResult(map[string]any{"identity": identity}), nil
		})
		handlers["Bearer synthetic-"+identity] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		handler, ok := handlers[r.Header.Get("Authorization")]
		if !ok {
			http.Error(w, "wrong binding", 401)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var message struct{ Method string }
		_ = json.Unmarshal(body, &message)
		if message.Method == "tools/call" {
			f.calls.Add(1)
		}
		f.mu.Lock()
		gate, method, fail := f.gate, f.gateMethod, f.failCall
		f.mu.Unlock()
		if gate != nil && message.Method == method && r.Header.Get("Authorization") == "Bearer synthetic-east" {
			gate.block(r.Context())
		}
		if fail && message.Method == "tools/call" {
			http.Error(w, "synthetic lost outcome", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *revocationFixture) block(method string, b *revocationBarrier, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateMethod = method
	f.gate = b
	f.failCall = fail
}

type revocationArguments struct {
	barrier *revocationBarrier
	ctx     context.Context
}

func (a revocationArguments) MarshalJSON() ([]byte, error) {
	a.barrier.block(a.ctx)
	return []byte(`{}`), nil
}

type revocationOutcome struct {
	result *mcp.CallToolResult
	err    error
}

func revocationAwait(t *testing.T, ctx context.Context, ch <-chan revocationOutcome) revocationOutcome {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-ctx.Done():
		t.Fatal("ordered operation did not finish")
		return revocationOutcome{}
	}
}

var revocationEast = gateway.Identity{Tenant: "east", Principal: "same-display-user"}
var revocationWest = gateway.Identity{Tenant: "west", Principal: "same-display-user"}

func newRevocationGateway(t *testing.T, f *revocationFixture) *gateway.Gateway {
	t.Helper()
	g, err := gateway.New(gateway.Config{
		Systems: []gateway.System{{Name: "shared", Endpoint: f.server.URL}},
		Users: map[string]gateway.User{
			"east-user": {Tenant: revocationEast.Tenant, Principal: revocationEast.Principal, Token: "entry-east", Allowed: []string{"shared__whoami"}, Credentials: map[string]string{"shared": "synthetic-east"}},
			"west-user": {Tenant: revocationWest.Tenant, Principal: revocationWest.Principal, Token: "entry-west", Allowed: []string{"shared__whoami"}, Credentials: map[string]string{"shared": "synthetic-west"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(discoveryContext(t)); len(issues) != 0 {
		t.Fatal(issues)
	}
	return g
}
func assertRevocationDenied(t *testing.T, ctx context.Context, g *gateway.Gateway, f *revocationFixture, id string) {
	t.Helper()
	before := f.requests.Load()
	assertRevocationDeniedCall(t, ctx, g, f, id)
	if got := f.requests.Load(); got != before {
		t.Fatalf("denied request contacted downstream: before=%d after=%d", before, got)
	}
}

// During an already-running refresh, other authorized identities may still make
// discovery requests. Denial must prevent business dispatch, not that unrelated
// traffic. The caller retains the full transport assertion after refresh exits.
func assertRevocationDeniedCall(t *testing.T, ctx context.Context, g *gateway.Gateway, f *revocationFixture, id string) {
	t.Helper()
	before := f.calls.Load()
	if names := g.Names(id); len(names) != 0 {
		t.Fatalf("revoked identity lists tools: %v", names)
	}
	result, err := g.Call(ctx, id, "shared__whoami", map[string]any{"tenant": "west", "principal": "same-display-user", "binding": "forged"})
	if !errors.Is(err, gateway.ErrDenied) || result != nil {
		t.Fatalf("revoked call result=%v error=%v", result, err)
	}
	if got := f.calls.Load(); got != before {
		t.Fatalf("denied request dispatched a business call: before=%d after=%d", before, got)
	}
}
func assertRevocationIdentity(t *testing.T, ctx context.Context, g *gateway.Gateway, id, want string) {
	t.Helper()
	result, err := g.Call(ctx, id, "shared__whoami", map[string]any{"tenant": "forged", "user": "other-user"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("call %s: result=%v err=%v", id, result, err)
	}
	if got := discoveryJSON(t, result.StructuredContent); !reflect.DeepEqual(got, map[string]any{"identity": want}) {
		t.Fatalf("cross-tenant credential mixup: got=%v want=%s", got, want)
	}
}

func TestRevocationTenantIsolation(t *testing.T) {
	ctx := discoveryContext(t)
	f := newRevocationFixture(t)
	g := newRevocationGateway(t, f)
	east, err := g.Binding(revocationEast, "shared")
	if err != nil {
		t.Fatal(err)
	}
	west, err := g.Binding(revocationWest, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if east.ID == west.ID {
		t.Fatal("tenant bindings share identity")
	}
	for i := 0; i < 3; i++ {
		assertRevocationIdentity(t, ctx, g, "east-user", "east")
		assertRevocationIdentity(t, ctx, g, "west-user", "west")
	}
	if _, err := g.RevokeBinding(revocationEast, "shared", east.Generation); err != nil {
		t.Fatal(err)
	}
	assertRevocationDenied(t, ctx, g, f, "east-user")
	assertRevocationIdentity(t, ctx, g, "west-user", "west")
	if _, err := g.RevokeBinding(revocationEast, "shared", east.Generation); !errors.Is(err, gateway.ErrConflict) {
		t.Fatalf("stale revocation accepted: %v", err)
	}
	if _, err := g.ReplaceBinding(revocationEast, "shared", east.Generation, "synthetic-east"); !errors.Is(err, gateway.ErrConflict) {
		t.Fatalf("stale replacement accepted: %v", err)
	}
	assertRevocationDenied(t, ctx, g, f, "east-user")
}

type revocationMutation struct {
	name  string
	apply func(*testing.T, *gateway.Gateway)
}

func revocationMutations() []revocationMutation {
	return []revocationMutation{
		{"disabled", func(t *testing.T, g *gateway.Gateway) {
			t.Helper()
			p, err := g.Policy(revocationEast)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.DisablePrincipal(revocationEast, p.Version); err != nil {
				t.Fatal(err)
			}
		}},
		{"binding", func(t *testing.T, g *gateway.Gateway) {
			t.Helper()
			b, err := g.Binding(revocationEast, "shared")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.RevokeBinding(revocationEast, "shared", b.Generation); err != nil {
				t.Fatal(err)
			}
		}},
		{"policy", func(t *testing.T, g *gateway.Gateway) {
			t.Helper()
			p, err := g.Policy(revocationEast)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.SetPolicy(revocationEast, p.Version, nil); err != nil {
				t.Fatal(err)
			}
		}},
	}
}

func TestRevocationOldHandlerAndSession(t *testing.T) {
	for _, mutation := range revocationMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			// Keep the exact handler and session created before the mutation.
			front := httptest.NewServer(g.Handler())
			t.Cleanup(front.Close)
			client := connect(t, front.URL, "entry-east")
			listed, err := client.ListTools(ctx, nil)
			if err != nil || len(listed.Tools) != 1 {
				t.Fatalf("initial list=%v err=%v", listed, err)
			}
			mutation.apply(t, g)
			before := f.requests.Load()
			listed, err = client.ListTools(ctx, nil)
			if err == nil && len(listed.Tools) != 0 {
				t.Fatalf("old session retained revoked list: %v", listed.Tools)
			}
			result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "shared__whoami", Arguments: map[string]any{}})
			if err == nil && (result == nil || !result.IsError) {
				t.Fatalf("old session bypassed revocation: result=%v", result)
			}
			assertRevocationDenied(t, ctx, g, f, "east-user")
			if f.requests.Load() != before {
				t.Fatal("old handler/session reached downstream")
			}
			assertRevocationIdentity(t, ctx, g, "west-user", "west")
		})
	}
}

func TestRevocationSlowDiscoveryCannotRepublish(t *testing.T) {
	for _, mutation := range revocationMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			f.block("tools/list", barrier, false)
			finished := make(chan struct{})
			go func() { g.Refresh(ctx); close(finished) }()
			barrier.wait(t, ctx)
			mutation.apply(t, g)
			assertRevocationDeniedCall(t, ctx, g, f, "east-user")
			barrier.open()
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("discovery failed to finish")
			}
			assertRevocationDenied(t, ctx, g, f, "east-user")
			assertRevocationIdentity(t, ctx, g, "west-user", "west")
		})
	}
}

func TestRevocationPreparationRechecksAdmission(t *testing.T) {
	for _, mutation := range revocationMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			finished := make(chan revocationOutcome, 1)
			before := f.requests.Load()
			go func() {
				result, err := g.Call(ctx, "east-user", "shared__whoami", revocationArguments{barrier, ctx})
				finished <- revocationOutcome{result, err}
			}()
			barrier.wait(t, ctx)
			mutation.apply(t, g)
			barrier.open()
			outcome := revocationAwait(t, ctx, finished)
			if !errors.Is(outcome.err, gateway.ErrDenied) || outcome.result != nil {
				t.Fatalf("stale preparation admitted: %+v", outcome)
			}
			if f.requests.Load() != before {
				t.Fatal("revoke-before-admission contacted downstream")
			}
		})
	}
}

func TestRevocationAdmittedCallKeepsOutcomeWithoutReplay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "pending_success"
		if fail {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			f.block("tools/call", barrier, fail)
			finished := make(chan revocationOutcome, 1)
			go func() {
				result, err := g.Call(ctx, "east-user", "shared__whoami", map[string]any{})
				finished <- revocationOutcome{result, err}
			}()
			barrier.wait(t, ctx)
			// The downstream has observed tools/call, proving admission won the race.
			revocationMutations()[1].apply(t, g)
			barrier.open()
			outcome := revocationAwait(t, ctx, finished)
			if fail {
				if outcome.err == nil || outcome.result != nil || !strings.Contains(outcome.err.Error(), "unknown") {
					t.Fatalf("unknown outcome falsely resolved: %+v", outcome)
				}
			} else {
				if outcome.err != nil {
					if !strings.Contains(outcome.err.Error(), "unknown") {
						t.Fatalf("in-flight operation falsely reported rolled back or denied: %+v", outcome)
					}
				} else if outcome.result == nil || outcome.result.IsError {
					t.Fatalf("invalid in-flight success: %+v", outcome)
				}
			}
			if calls := f.calls.Load(); calls != 1 {
				t.Fatalf("admitted operation replayed: calls=%d", calls)
			}
			assertRevocationDenied(t, ctx, g, f, "east-user")
		})
	}
}

// ABA-style restoration must not revive a captured admission or discovery epoch.
func revocationRestore(t *testing.T, g *gateway.Gateway, kind string) {
	t.Helper()
	if kind == "binding" {
		b, err := g.Binding(revocationEast, "shared")
		if err != nil {
			t.Fatal(err)
		}
		b, err = g.RevokeBinding(revocationEast, "shared", b.Generation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = g.ReplaceBinding(revocationEast, "shared", b.Generation, "synthetic-east"); err != nil {
			t.Fatal(err)
		}
	} else {
		p, err := g.Policy(revocationEast)
		if err != nil {
			t.Fatal(err)
		}
		p, err = g.SetPolicy(revocationEast, p.Version, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = g.SetPolicy(revocationEast, p.Version, []string{"shared__whoami"}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRevocationRestoreRejectsStalePreparation(t *testing.T) {
	for _, kind := range []string{"binding", "policy"} {
		t.Run(kind, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			finished := make(chan revocationOutcome, 1)
			go func() {
				result, err := g.Call(ctx, "east-user", "shared__whoami", revocationArguments{barrier, ctx})
				finished <- revocationOutcome{result, err}
			}()
			barrier.wait(t, ctx)
			revocationRestore(t, g, kind)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatal(issues)
			}
			before := f.requests.Load()
			barrier.open()
			outcome := revocationAwait(t, ctx, finished)
			if !errors.Is(outcome.err, gateway.ErrDenied) || outcome.result != nil {
				t.Fatalf("old revision admitted after restore: %+v", outcome)
			}
			if f.requests.Load() != before {
				t.Fatal("stale revision contacted downstream")
			}
			assertRevocationIdentity(t, ctx, g, "east-user", "east")
		})
	}
}
func TestRevocationRestoreRejectsStaleDiscovery(t *testing.T) {
	for _, kind := range []string{"binding", "policy"} {
		t.Run(kind, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			f.block("tools/list", barrier, false)
			finished := make(chan struct{})
			go func() { g.Refresh(ctx); close(finished) }()
			barrier.wait(t, ctx)
			revocationRestore(t, g, kind)
			barrier.open()
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("discovery failed to finish")
			}
			assertRevocationDenied(t, ctx, g, f, "east-user")
			f.block("", nil, false)
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatal(issues)
			}
			assertRevocationIdentity(t, ctx, g, "east-user", "east")
		})
	}
}

func TestRevocationPreservesConfirmedResultDuringCleanup(t *testing.T) {
	// Reuse the independent legacy wire fixture so DELETE is guaranteed to occur
	// after the SDK has decoded the complete success response.
	ctx := discoveryContext(t)
	f, g := newCleanupFixture(t)
	cleanupSeedCatalog(t, g)
	f.deleteBlock.enabled.Store(true)
	finished := make(chan revocationOutcome, 1)
	go func() {
		result, err := g.Call(ctx, "u", "test__echo", map[string]any{})
		finished <- revocationOutcome{result, err}
	}()
	select {
	case <-f.deleteBlock.started:
	case <-ctx.Done():
		t.Fatal("confirmed call never reached cleanup")
	}
	identity := gateway.Identity{Tenant: "demo", Principal: "u"}
	b, err := g.Binding(identity, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.RevokeBinding(identity, "test", b.Generation); err != nil {
		t.Fatal(err)
	}
	outcome := revocationAwait(t, ctx, finished)
	if outcome.err != nil || outcome.result == nil || outcome.result.IsError {
		t.Fatalf("revocation erased confirmed success: %+v", outcome)
	}
	if f.calls.Load() != 1 {
		t.Fatal("confirmed call replayed")
	}
	if names := g.Names("u"); len(names) != 0 {
		t.Fatalf("revocation lost after cleanup: %v", names)
	}
}

func TestRevocationDisabledIdentityCannotBeRestoredByPolicyOrBinding(t *testing.T) {
	ctx := discoveryContext(t)
	f := newRevocationFixture(t)
	g := newRevocationGateway(t, f)
	initial, err := g.Policy(revocationEast)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := g.DisablePrincipal(revocationEast, initial.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Disabled || disabled.Version <= initial.Version {
		t.Fatalf("disable not versioned: %+v", disabled)
	}
	if _, err := g.SetPolicy(revocationEast, disabled.Version, []string{"shared__whoami"}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("policy restored disabled principal: %v", err)
	}
	binding, err := g.Binding(revocationEast, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if binding.State != gateway.BindingRevoked {
		t.Fatalf("disabled principal retained binding: %+v", binding)
	}
	if _, err := g.ReplaceBinding(revocationEast, "shared", binding.Generation, "synthetic-east"); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("replacement restored disabled principal: %v", err)
	}
	before := f.requests.Load()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	request.Header.Set("Authorization", "Bearer entry-east")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Session-Id", "borrowed-west-session")
	response := httptest.NewRecorder()
	g.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled bearer/session accepted: status=%d", response.Code)
	}
	if f.requests.Load() != before {
		t.Fatal("disabled bearer reached downstream")
	}
	assertRevocationDenied(t, ctx, g, f, "east-user")
	assertRevocationIdentity(t, ctx, g, "west-user", "west")
}

func TestRevocationBindingInvalidationIsLocalToSystem(t *testing.T) {
	ctx := discoveryContext(t)
	f := newRevocationFixture(t)
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "shared", Endpoint: f.server.URL}, {Name: "other", Endpoint: f.server.URL}}, Users: map[string]gateway.User{
		"east-user": {Tenant: "east", Principal: "same-display-user", Token: "entry-east", Allowed: []string{"shared__whoami", "other__whoami"}, Credentials: map[string]string{"shared": "synthetic-east", "other": "synthetic-east"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(ctx); len(issues) != 0 {
		t.Fatal(issues)
	}
	b, err := g.Binding(revocationEast, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.RevokeBinding(revocationEast, "shared", b.Generation); err != nil {
		t.Fatal(err)
	}
	if names := g.Names("east-user"); !reflect.DeepEqual(names, []string{"other__whoami"}) {
		t.Fatalf("binding revoke invalidated unrelated system: %v", names)
	}
	before := f.requests.Load()
	if _, err := g.Call(ctx, "east-user", "shared__whoami", nil); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("revoked system call: %v", err)
	}
	if f.requests.Load() != before {
		t.Fatal("revoked system reached downstream")
	}
	result, err := g.Call(ctx, "east-user", "other__whoami", nil)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("unrelated binding denied: result=%v error=%v", result, err)
	}
	front := httptest.NewServer(g.Handler())
	t.Cleanup(front.Close)
	client := connect(t, front.URL, "entry-east")
	listed, err := client.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "other__whoami" {
		t.Fatalf("binding revoke disabled entry identity: list=%v error=%v", listed, err)
	}
}

type revocationBody struct {
	io.Reader
	barrier *revocationBarrier
	ctx     context.Context
	once    sync.Once
}

func (b *revocationBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.barrier.block(b.ctx) })
	return b.Reader.Read(p)
}
func (b *revocationBody) Close() error { return nil }

func TestRevocationCapturedSDKHandlerRechecksAfterBodyWait(t *testing.T) {
	for _, method := range []string{"tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			ctx := discoveryContext(t)
			f := newRevocationFixture(t)
			g := newRevocationGateway(t, f)
			barrier := newRevocationBarrier(t)
			payload := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"name":"shared__whoami","arguments":{}}}`
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", nil).WithContext(ctx)
			request.Body = &revocationBody{Reader: strings.NewReader(payload), barrier: barrier, ctx: ctx}
			request.Header.Set("Authorization", "Bearer entry-east")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("Mcp-Protocol-Version", "2025-03-26")
			response := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() { g.Handler().ServeHTTP(response, request); close(finished) }()
			// HTTP auth and internal handler selection have finished when SDK reads body.
			barrier.wait(t, ctx)
			if method == "tools/list" {
				revocationRestore(t, g, "binding")
				if issues := g.Refresh(ctx); len(issues) != 0 {
					t.Fatal(issues)
				}
			} else {
				revocationMutations()[1].apply(t, g)
			}
			before := f.requests.Load()
			barrier.open()
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("captured SDK handler did not finish")
			}
			if response.Code != http.StatusOK {
				t.Fatalf("fixture did not exercise SDK RPC: status=%d body=%s", response.Code, response.Body.String())
			}
			var rpc struct {
				Result struct {
					Tools   []json.RawMessage `json:"tools"`
					IsError bool              `json:"isError"`
				}
				Error json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &rpc); err != nil {
				t.Fatal(err)
			}
			if method == "tools/list" {
				if len(rpc.Error) > 0 || len(rpc.Result.Tools) != 0 {
					t.Fatalf("captured handler published stale catalog: %s", response.Body.String())
				}
			} else if len(rpc.Error) == 0 && !rpc.Result.IsError {
				t.Fatalf("captured handler bypassed revocation: %s", response.Body.String())
			}
			if f.requests.Load() != before {
				t.Fatal("captured stale handler contacted downstream")
			}
		})
	}
}
