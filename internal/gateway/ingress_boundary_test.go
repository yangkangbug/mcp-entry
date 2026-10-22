package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func boundaryFixture(t *testing.T, global, principal int) (*Gateway, string, string) {
	t.Helper()
	a := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	b := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	g, err := New(Config{Users: map[string]User{
		"alice": {Token: a, TokenExpiresAt: time.Now().Add(time.Hour)},
		"bob":   {Token: b, TokenExpiresAt: time.Now().Add(time.Hour)},
	}, Ingress: IngressConfig{Global: AdmissionLimit{global, 100000, 100000}, Principal: AdmissionLimit{principal, 100000, 100000}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g, a, b
}

func boundaryRequest(h http.Handler, token, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080"+path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func boundaryAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("handler barrier timed out")
	}
}

func boundaryActive(t *testing.T, g *Gateway, want int) {
	t.Helper()
	g.ingress.mu.Lock()
	defer g.ingress.mu.Unlock()
	if g.ingress.global.active != want {
		t.Fatalf("active=%d want=%d", g.ingress.global.active, want)
	}
}

func TestIngressBoundarySharedRoutesCancelAndRecovery(t *testing.T) {
	g, a, _ := boundaryFixture(t, 1, 1)
	account, err := g.AccountHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	entered, leave, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(leave) })
	hold := g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-leave; w.WriteHeader(204) }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		r := httptest.NewRequest("GET", "http://127.0.0.1:8080/held", nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+a)
		hold.ServeHTTP(httptest.NewRecorder(), r)
	}()
	boundaryAwait(t, entered)
	cancel()
	// Cancellation is not completion: every route still shares the held slot.
	for _, h := range []http.Handler{g.Handler(), g.Handler(), account, g.GuardHTTP(http.NotFoundHandler())} {
		if w := boundaryRequest(h, "", "/unknown"); w.Code != 429 {
			t.Fatalf("held request bypass: %d", w.Code)
		}
	}
	boundaryActive(t, g, 1)
	release.Do(func() { close(leave) })
	boundaryAwait(t, done)
	boundaryActive(t, g, 0)
	if w := boundaryRequest(g.GuardHTTP(http.NotFoundHandler()), a, "/recovered"); w.Code != 404 {
		t.Fatalf("recovery: %d", w.Code)
	}
}

func TestIngressBoundaryPrincipalIsolationAndNestedGuard(t *testing.T) {
	g, a, b := boundaryFixture(t, 3, 1)
	entered, leave, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(leave) })
	h := g.GuardHTTP(g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(entered)
			<-leave
		}
		w.WriteHeader(204)
	})))
	go func() { defer close(done); boundaryRequest(h, a, "/hold") }()
	boundaryAwait(t, entered)
	boundaryActive(t, g, 1)
	if w := boundaryRequest(h, a, "/other"); w.Code != 429 {
		t.Fatalf("same principal: %d", w.Code)
	}
	if w := boundaryRequest(h, b, "/other"); w.Code != 204 {
		t.Fatalf("isolated principal: %d", w.Code)
	}
	release.Do(func() { close(leave) })
	boundaryAwait(t, done)
	if w := boundaryRequest(h, a, "/other"); w.Code != 204 {
		t.Fatalf("recovery: %d", w.Code)
	}
	boundaryActive(t, g, 0)
	if got := g.RejectionStatus().HTTP[RejectionIngressPrincipal].Count; got != 1 {
		t.Fatalf("principal denials %d", got)
	}
}

func TestIngressBoundaryReleaseOnEveryReturn(t *testing.T) {
	for _, status := range []int{200, 204, 400, 401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			g, a, _ := boundaryFixture(t, 1, 1)
			h := g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			for i := 0; i < 3; i++ {
				if w := boundaryRequest(h, a, "/"); w.Code != status {
					t.Fatalf("status=%d", w.Code)
				}
			}
			boundaryActive(t, g, 0)
		})
	}
	t.Run("panic unwinds", func(t *testing.T) {
		g, a, _ := boundaryFixture(t, 1, 1)
		h := g.GuardHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("synthetic") }))
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			boundaryRequest(h, a, "/")
		}()
		boundaryActive(t, g, 0)
		if w := boundaryRequest(g.GuardHTTP(http.NotFoundHandler()), a, "/"); w.Code != 404 {
			t.Fatal(w.Code)
		}
	})
}

func TestIngressBoundaryNoNestedRateChargeOrHandlerReset(t *testing.T) {
	g, a, _ := boundaryFixture(t, 2, 2)
	g.ingress.mu.Lock()
	g.ingress.global.limit.RatePerSecond = math.SmallestNonzeroFloat64
	g.ingress.global.tokens = 2
	g.ingress.principals[Identity{"demo", "alice"}].limit.RatePerSecond = math.SmallestNonzeroFloat64
	g.ingress.principals[Identity{"demo", "alice"}].tokens = 2
	g.ingress.mu.Unlock()
	for i := 0; i < 2; i++ {
		// Each new Handler and each outer wrapper must share exactly one admission.
		r := httptest.NewRequest("GET", "http://127.0.0.1:8080/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+a)
		r.Header.Set("Origin", "https://synthetic.invalid")
		w := httptest.NewRecorder()
		g.GuardHTTP(g.GuardHTTP(g.Handler())).ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := boundaryRequest(g.Handler(), a, "/mcp"); w.Code != 429 {
		t.Fatalf("new handler reset tokens: %d", w.Code)
	}
	g.ingress.mu.Lock()
	defer g.ingress.mu.Unlock()
	if got := g.ingress.principals[Identity{"demo", "alice"}].tokens; got != 0 {
		t.Fatalf("principal debit %g", got)
	}
}

func TestIngressBoundaryUntrustedCardinalityAndObservations(t *testing.T) {
	g, a, _ := boundaryFixture(t, 8, 4)
	account, err := g.AccountHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	before := g.AuditStatus()
	h := g.GuardHTTP(http.NotFoundHandler())
	for i := 0; i < 500; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/url-canary-%d", i), nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer token-canary-%d", i))
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("ip-canary-%d", i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	if w := accountRequest(account, "GET", "/account/api/bindings", "invalid-token-canary", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := accountRequest(account, "POST", "/account/api/bindings/crm", a, `{"unexpected":"tool-name-canary"}`, nil); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := accountRequest(account, "GET", "/account/api/bindings", a, "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"principal":"alice"`) {
		t.Fatalf("success changed: %d %s", w.Code, w.Body.String())
	}
	g.ingress.mu.Lock()
	buckets := len(g.ingress.principals)
	g.ingress.mu.Unlock()
	if buckets != 2 {
		t.Fatalf("attacker grew principal buckets to %d", buckets)
	}
	if after := g.AuditStatus(); !reflect.DeepEqual(before, after) {
		t.Fatalf("rejections changed mandatory journal: before=%+v after=%+v", before, after)
	}
	status := g.RejectionStatus()
	if status.HTTP[RejectionRequest].Count != 501 || status.HTTP[RejectionAuthentication].Count != 1 {
		t.Fatalf("observations: %+v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"token-canary", "url-canary", "ip-canary", "tool-name-canary", a} {
		if strings.Contains(string(encoded), canary) {
			t.Fatal("snapshot leaked request metadata")
		}
	}
	if len(encoded) > 2048 {
		t.Fatalf("snapshot grew: %d bytes", len(encoded))
	}
	status.HTTP[RejectionRequest].Count = 0
	if g.RejectionStatus().HTTP[RejectionRequest].Count != 501 {
		t.Fatal("snapshot aliases mutable state")
	}
	fresh, _, _ := boundaryFixture(t, 8, 4)
	if fresh.RejectionStatus().HTTP[RejectionRequest].Count != 0 {
		t.Fatal("nondurable observations carried over")
	}
}

// A bounded, deterministic synthetic load harness, not a throughput/SLA test.
// Barriers hold all slots while concurrent excess attempts must return without
// queuing; healthy authenticated work is checked after every overload wave.
func TestIngressBoundarySustainedOverloadRecovery(t *testing.T) {
	g, a, _ := boundaryFixture(t, 4, 4)
	var active, peak, accepted, rejected atomic.Int64
	for wave := 0; wave < 12; wave++ {
		entered, leave := make(chan struct{}, 4), make(chan struct{})
		var release sync.Once
		h := g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			accepted.Add(1)
			entered <- struct{}{}
			<-leave
			w.WriteHeader(204)
		}))
		var held sync.WaitGroup
		held.Add(4)
		for i := 0; i < 4; i++ {
			go func() { defer held.Done(); boundaryRequest(h, "", "/hold") }()
		}
		for i := 0; i < 4; i++ {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				release.Do(func() { close(leave) })
				t.Fatal("load barrier")
			}
		}
		var excess sync.WaitGroup
		excess.Add(24)
		finished := make(chan struct{})
		for i := 0; i < 24; i++ {
			go func() {
				defer excess.Done()
				if w := boundaryRequest(h, "", "/excess"); w.Code == 429 {
					rejected.Add(1)
				} else {
					t.Errorf("full global cap allowed %d", w.Code)
				}
			}()
		}
		go func() { excess.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			release.Do(func() { close(leave) })
			held.Wait()
			t.Fatal("excess attempts queued")
		}
		release.Do(func() { close(leave) })
		held.Wait()
		if w := boundaryRequest(g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })), a, "/healthy"); w.Code != 204 {
			t.Fatalf("recovery wave %d: %d", wave, w.Code)
		}
	}
	boundaryActive(t, g, 0)
	if accepted.Load() != 48 || rejected.Load() != 288 || peak.Load() != 4 || active.Load() != 0 {
		t.Fatalf("accepted=%d rejected=%d peak=%d active=%d", accepted.Load(), rejected.Load(), peak.Load(), active.Load())
	}
	t.Logf("synthetic guarded overload: attempts=336 accepted=%d rejected=%d peak-active=%d healthy-recoveries=12; no fairness claim while global cap full", accepted.Load(), rejected.Load(), peak.Load())
}

func TestIngressBoundaryMCPOperationDenialHTTP200(t *testing.T) {
	g, _, a, _ := accountFixture(t)
	call := func(name, arguments string) *httptest.ResponseRecorder {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+a)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2025-03-26")
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		return w
	}
	before := g.AuditStatus()
	for _, name := range []string{"unknown-tool-canary", "unknown-tool-canary-2"} {
		w := call(name, `{}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"error"`) {
			t.Fatalf("denial response: %d %s", w.Code, w.Body.String())
		}
	}
	status := g.RejectionStatus()
	if status.Operations[RejectionOperationProtocol-RejectionOperationAuthorization].Count != 2 {
		t.Fatalf("missing operation denial evidence: %+v", status)
	}
	for _, counter := range status.HTTP {
		if counter.Count != 0 {
			t.Fatal("HTTP 200 denial misclassified as HTTP error")
		}
	}
	if !reflect.DeepEqual(before, g.AuditStatus()) {
		t.Fatal("unknown tool denials grew mandatory journal")
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "unknown-tool-canary") {
		t.Fatal("tool canary retained")
	}
	w := call("crm__echo", `{"message":"unchanged-success-canary"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"structuredContent":{"message":"unchanged-success-canary","system":"crm","user":"alice"}`) {
		t.Fatalf("successful MCP result changed: %d %s", w.Code, w.Body.String())
	}
	boundaryActive(t, g, 0)
}

func TestIngressBoundaryRejectionCounterSaturates(t *testing.T) {
	g, _, _ := boundaryFixture(t, 1, 1)
	g.rejections.mu.Lock()
	g.rejections.status.HTTP[RejectionRequest].Count = math.MaxUint64
	g.rejections.mu.Unlock()
	boundaryRequest(g.GuardHTTP(http.NotFoundHandler()), "", "/")
	c := g.RejectionStatus().HTTP[RejectionRequest]
	if c.Count != math.MaxUint64 || !c.Saturated || c.Last.IsZero() {
		t.Fatalf("counter wrapped or lacked saturation evidence: %+v", c)
	}
}

type boundaryDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *boundaryDeadlineWriter) SetReadDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	return nil
}

func TestIngressBoundaryReadDeadlineAndBodyLimit(t *testing.T) {
	g, a, _ := boundaryFixture(t, 1, 1)
	var readErr error
	var received int
	h := g.GuardHTTP(g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		received = len(data)
		readErr = err
		if err != nil {
			http.Error(w, "request too large", 413)
			return
		}
		w.WriteHeader(204)
	})))
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/unknown", strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	r.Header.Set("Authorization", "Bearer "+a)
	w := &boundaryDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	start := time.Now()
	h.ServeHTTP(w, r)
	end := time.Now()
	if w.Code != 413 || received != 64<<10 || readErr == nil {
		t.Fatalf("body bound: status=%d read=%d err=%v", w.Code, received, readErr)
	}
	if len(w.deadlines) != 1 || w.deadlines[0].Before(start.Add(IngressReadTimeout)) || w.deadlines[0].After(end.Add(IngressReadTimeout)) {
		t.Fatalf("read deadline not retained exactly once: %v", w.deadlines)
	}
	boundaryActive(t, g, 0)
	early := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), early)
	defer cancel()
	short := httptest.NewRequest("GET", "http://127.0.0.1:8080/unknown", nil).WithContext(ctx)
	shortWriter := &boundaryDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(shortWriter, short)
	if len(shortWriter.deadlines) != 1 || !shortWriter.deadlines[0].Equal(early) {
		t.Fatalf("request deadline extended: %v", shortWriter.deadlines)
	}
	r = httptest.NewRequest("GET", "http://127.0.0.1:8080/unknown", nil)
	r.Header.Set("X-Oversized", strings.Repeat("x", IngressMaxHeaderBytes+1))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, r)
	if recorder.Code != 431 {
		t.Fatalf("header bound: %d", recorder.Code)
	}
	boundaryActive(t, g, 0)
}

// Clamp only nonzero deadlines for a fast real net/http unread-body regression.
// A reset to zero must reach the actual connection so this detects drain hangs.
type boundaryShortDeadlineWriter struct{ http.ResponseWriter }

func (w boundaryShortDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w boundaryShortDeadlineWriter) SetReadDeadline(d time.Time) error {
	if !d.IsZero() {
		d = time.Now().Add(100 * time.Millisecond)
	}
	return http.NewResponseController(w.ResponseWriter).SetReadDeadline(d)
}

func TestIngressBoundaryEarlyDenialUnreadBodyCloses(t *testing.T) {
	g, _, _ := boundaryFixture(t, 2, 1)
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.Handler().ServeHTTP(boundaryShortDeadlineWriter{w}, r) }))
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// No body bytes follow; handler returns 401 before reading any body.
	if _, err := fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\n", server.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("early rejection response stuck draining unread body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("status %d", response.StatusCode)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("unread body retained connection after read deadline")
	}
	boundaryActive(t, g, 0)
}

func TestIngressBoundaryCompletedBodyKeepAlive(t *testing.T) {
	g, _, _ := boundaryFixture(t, 2, 1)
	h := g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		w.Write(data)
	}))
	server := httptest.NewServer(h)
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\nping", server.Listener.Addr()); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(data) != "ping" {
			t.Fatalf("keepalive response %d: %s %v", response.StatusCode, data, err)
		}
	}
	boundaryActive(t, g, 0)
}

func TestIngressBoundaryDeadlineBeforeGlobalRejection(t *testing.T) {
	g, _, _ := boundaryFixture(t, 1, 1)
	release, ok := g.ingress.acquire(&g.ingress.global)
	if !ok {
		t.Fatal("fixture acquire")
	}
	defer release()
	w := &boundaryDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	g.GuardHTTP(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("POST", "http://127.0.0.1:8080/", nil))
	if w.Code != 429 || len(w.deadlines) != 1 || w.deadlines[0].IsZero() {
		t.Fatalf("global denial missing drain deadline: %d %v", w.Code, w.deadlines)
	}
}
