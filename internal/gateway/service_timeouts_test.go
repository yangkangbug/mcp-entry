package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceTimeoutConfig(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `{"call_ms":30000}`, `{"discovery_ms":5000,"call_ms":30000,"response_header_ms":0}`, `{"discovery_ms":null,"call_ms":30000,"response_header_ms":5000}`, `{"discovery_ms":5000,"call_ms":-1,"response_header_ms":5000}`, `{"discovery_ms":5000,"call_ms":120001,"response_header_ms":5000}`, `{"discovery_ms":5000,"call_ms":10000,"response_header_ms":10001}`, `{"discovery_ms":1.5,"call_ms":30000,"response_header_ms":5000}`, `{"discovery_ms":5000,"call_ms":30000,"response_header_ms":5000,"extra":1}`} {
		t.Run(value, func(t *testing.T) {
			cfg, err := LoadConfig(strings.NewReader(`{"systems":[{"name":"svc","endpoint":"http://127.0.0.1:1","timeouts":` + value + `}],"users":{}}`))
			if err == nil {
				var g *Gateway
				g, err = New(cfg)
				if g != nil {
					g.Close()
				}
			}
			if err == nil {
				t.Fatal("invalid timeouts accepted")
			}
		})
	}
	for _, c := range []*TimeoutConfig{nil, {5000, 30000, 25000}, {120000, 120000, 120000}} {
		cfg := Config{Systems: []System{{Name: "svc", Endpoint: "http://127.0.0.1:1", Timeouts: c}}}
		g, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		s := g.systems["svc"]
		b := s.timeoutBudgets()
		if s.transport.(*endpointTransport).base.ResponseHeaderTimeout != b.responseHeader {
			t.Fatal("transport ignored budget")
		}
		if downstreamOperationClient(context.Background(), "synthetic", s).Timeout != b.client {
			t.Fatal("client cap ignored budget")
		}
		if c == nil && b != (timeoutBudgets{5 * time.Second, 10 * time.Second, 5 * time.Second, 12 * time.Second}) {
			t.Fatal("legacy defaults changed")
		}
		if c != nil {
			c.CallMS = 1
			if s.timeoutBudgets().call == time.Millisecond || s.Timeouts.CallMS == 1 {
				t.Fatal("config aliases runtime")
			}
		}
	}
}

// The full gateway uses its actual legacy five-second header timer here. The
// synthetic remote deliberately finishes after cancellation: a timeout is not
// rollback, and the terminal audit must never be rewritten to claim success.
func TestServiceTimeoutRealFiveSecondBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		body        bool
		profile     *TimeoutConfig
		wantTimeout bool
	}{
		{"legacy_headers", false, nil, true},
		{"configured_headers", false, &TimeoutConfig{5000, 8000, 7000}, false},
		{"legacy_body", true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				switch req.Method {
				case "initialize":
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"synthetic","version":"1"}}}`, req.ID)
				case "notifications/initialized", "notifications/cancelled":
					w.WriteHeader(202)
				case "tools/list":
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"slow","inputSchema":{"type":"object"}}]}}`, req.ID)
				case "tools/call":
					calls.Add(1)
					if tc.body {
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
					}
					time.Sleep(5500 * time.Millisecond) // Intentionally ignores request cancellation.
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"synthetic-result-canary"}]}}`, req.ID)
					close(done)
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			g, err := New(Config{Systems: []System{{Name: "svc", Endpoint: server.URL, Timeouts: tc.profile}}, Users: map[string]User{"u": {Token: "entry-synthetic", Allowed: []string{"svc__slow"}, Credentials: map[string]string{"svc": "credential-canary"}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if issues := g.Refresh(context.Background()); len(issues) > 0 {
				t.Fatal(issues)
			}
			start := time.Now()
			result, err := g.Call(context.Background(), "u", "svc__slow", map[string]any{})
			if tc.wantTimeout {
				var f *DownstreamFailure
				if !errors.As(err, &f) || f.Code != FailureTimeout || f.Phase != FailureCall || !f.OutcomeUnknown || f.HTTPStatus != 0 || result != nil {
					t.Fatalf("incorrect evidence: %v", err)
				}
				if time.Since(start) < 5*time.Second {
					t.Fatal("did not exercise actual five-second boundary")
				}
			} else if err != nil || result == nil {
				t.Fatalf("configured/body control failed: %v", err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("remote did not finish")
			}
			if calls.Load() != 1 {
				t.Fatal("call retried")
			}
			g.mu.Lock()
			page, err := g.auditRing.Read(AuditFilter{})
			g.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			var requestID string
			terminal := 0
			for _, e := range page.Events {
				if e.Action != AuditActionCall {
					continue
				}
				if e.Phase == AuditPhaseStart {
					requestID = e.RequestID
				}
				if e.Phase == AuditPhaseTerminal {
					terminal++
					if e.RequestID != requestID || e.OutcomeUnknown != tc.wantTimeout {
						t.Fatalf("audit correlation/outcome: %+v", e)
					}
					if tc.wantTimeout && e.Result != AuditResultTimeout {
						t.Fatal("late completion rewrote timeout")
					}
				}
			}
			if terminal != 1 {
				t.Fatal("missing single terminal audit")
			}
			encoded, _ := json.Marshal(page)
			for _, canary := range []string{server.URL, "credential-canary", "synthetic-result-canary"} {
				if strings.Contains(string(encoded), canary) {
					t.Fatal("audit leaked canary")
				}
			}
		})
	}
}

func TestServiceTimeoutDiscoveryClipsLargerHeader(t *testing.T) {
	teardown := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-teardown:
		}
	}))
	defer server.Close()
	defer close(teardown)
	g, err := New(Config{Systems: []System{{Name: "svc", Endpoint: server.URL, Timeouts: &TimeoutConfig{100, 1000, 900}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = g.discover(parent, g.systems["svc"], "synthetic", nil)
	var f *DownstreamFailure
	if !errors.As(err, &f) || f.Code != FailureTimeout || f.Phase != FailureConnect || parent.Err() != nil {
		t.Fatalf("discovery failed to clip header: %v / %v", err, parent.Err())
	}
}

func TestServiceTimeoutLegacySystemEncoding(t *testing.T) {
	// Frozen field layout from fe28d7a, including order and omitempty behavior.
	type legacySystem struct {
		QuotaSubject string         `json:"quota_subject,omitempty"`
		Name         string         `json:"name"`
		Endpoint     string         `json:"endpoint"`
		Auth         AuthConfig     `json:"auth,omitempty"`
		Network      *NetworkPolicy `json:"network,omitempty"`
	}
	for _, s := range []System{{Name: "svc", Endpoint: "http://127.0.0.1:1", Auth: AuthConfig{Mode: "bearer"}}, {QuotaSubject: "bucket", Name: "svc", Endpoint: "https://example.invalid/mcp", Auth: AuthConfig{Mode: "api_key", Header: "X-API-Key"}, Network: &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}}}} {
		got, _ := json.Marshal(s)
		old, _ := json.Marshal(legacySystem{s.QuotaSubject, s.Name, s.Endpoint, s.Auth, s.Network})
		if string(got) != string(old) {
			t.Fatalf("historical topology bytes changed: %s != %s", got, old)
		}
	}
}

func TestServiceTimeoutStrictDraftAndLoad(t *testing.T) {
	g, err := New(maintenanceConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	valid := `{"discovery_ms":5000,"call_ms":30000,"response_header_ms":25000}`
	for _, fragment := range []string{
		`"Timeouts":null`, `"TIMEOUTS":` + valid,
		`"timeouts":` + valid + `,"timeouts":null`,
		`"timeouts":null,"Timeouts":` + valid,
		`"timeouts":{"discovery_ms":5000,"discovery_ms":null,"call_ms":30000,"response_header_ms":25000}`,
		`"timeouts":{"discovery_ms":5000,"Discovery_ms":5000,"call_ms":30000,"response_header_ms":25000}`,
		`"timeouts":{"Discovery_ms":5000,"call_ms":30000,"response_header_ms":25000}`,
		`"timeouts":{"discovery_ms":null,"call_ms":30000,"response_header_ms":25000}`,
		`"timeouts":{"discovery_ms":5000,"call_ms":30000,"response_header_ms":25000,"unknown":1}`,
	} {
		body := `{"systems":[{"name":"svc","endpoint":"http://127.0.0.1:1",` + fragment + `}]}`
		if _, err := LoadConfig(strings.NewReader(body)); err == nil {
			t.Fatalf("LoadConfig accepted %s", fragment)
		}
		w := adminRequest(h, "POST", "/admin/api/config/validate", body, maintenanceToken(99), nil)
		if w.Code != 400 {
			t.Fatalf("draft accepted %s: %d", fragment, w.Code)
		}
	}
	body := `{"systems":[{"name":"svc","endpoint":"http://127.0.0.1:1","timeouts":` + valid + `}]}`
	w := adminRequest(h, "POST", "/admin/api/config/validate", body, maintenanceToken(99), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"call_ms":30000`) || !strings.Contains(w.Body.String(), `"applied":false`) {
		t.Fatalf("valid draft not retained unapplied: %d %s", w.Code, w.Body)
	}
}

func TestServiceTimeoutConfiguredOperationAndCleanup(t *testing.T) {
	for _, stage := range []string{"discovery_body", "call_body", "parent", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			entered := make(chan struct{}, 1)
			teardown := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stall := func() {
					entered <- struct{}{}
					select {
					case <-r.Context().Done():
					case <-teardown:
					}
				}
				if r.Method == http.MethodDelete {
					if stage == "cleanup" && calls.Load() > 0 {
						stall()
					}
					w.WriteHeader(204)
					return
				}
				var req struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				switch req.Method {
				case "initialize":
					w.Header().Set("Mcp-Session-Id", "synthetic-session")
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}`, req.ID)
				case "notifications/initialized", "notifications/cancelled":
					w.WriteHeader(202)
				case "tools/list":
					if stage == "discovery_body" {
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
						stall()
						return
					}
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"slow","inputSchema":{"type":"object"}}]}}`, req.ID)
				case "tools/call":
					calls.Add(1)
					if stage != "cleanup" {
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
						stall()
						return
					}
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, req.ID)
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			defer close(teardown)
			profile := &TimeoutConfig{1000, 150, 900}
			if stage == "discovery_body" {
				profile = &TimeoutConfig{100, 1000, 900}
			}
			g, err := New(Config{Systems: []System{{Name: "svc", Endpoint: server.URL, Timeouts: profile}}, Users: map[string]User{"u": {Token: "synthetic-entry", Allowed: []string{"svc__slow"}, Credentials: map[string]string{"svc": "synthetic"}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if stage == "discovery_body" {
				parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_, err := g.discover(parent, g.systems["svc"], "synthetic", map[string]bool{"svc__slow": true})
				var f *DownstreamFailure
				if !errors.As(err, &f) || f.Code != FailureTimeout || f.Phase != FailureDiscovery || f.OutcomeUnknown || parent.Err() != nil {
					t.Fatalf("discovery body evidence: %v", err)
				}
			} else {
				if issues := g.Refresh(context.Background()); len(issues) != 0 {
					t.Fatal(issues)
				}
				budget := 3 * time.Second
				if stage == "parent" {
					budget = 50 * time.Millisecond
				}
				parent, cancel := context.WithTimeout(context.Background(), budget)
				defer cancel()
				result, err := g.Call(parent, "u", "svc__slow", nil)
				if stage == "cleanup" {
					if err != nil || result == nil {
						t.Fatalf("cleanup replaced confirmed result: %v", err)
					}
				} else {
					var f *DownstreamFailure
					if !errors.As(err, &f) || f.Code != FailureTimeout || f.Phase != FailureCall || !f.OutcomeUnknown {
						t.Fatalf("call evidence: %v", err)
					}
				}
				if stage == "parent" {
					// The transport copies the absolute operation deadline onto the
					// SDK's detached request context. Its timer may fire before the
					// parent's timer callback becomes visible; Err is not a clock.
					deadline, ok := parent.Deadline()
					if !ok || time.Now().Before(deadline) {
						t.Fatal("call timed out before the parent deadline")
					}
					select {
					case <-parent.Done():
					case <-time.After(time.Second):
						t.Fatal("parent deadline cancellation did not become visible")
					}
					if !errors.Is(parent.Err(), context.DeadlineExceeded) {
						t.Fatalf("wrong parent cancellation: %v", parent.Err())
					}
				} else if parent.Err() != nil {
					t.Fatal("operation budget incorrectly exhausted the parent")
				}
				if calls.Load() != 1 {
					t.Fatal("unexpected dispatch count")
				}
			}
			select {
			case <-entered:
			default:
				t.Fatal("expected stage not exercised")
			}
		})
	}
}

// Verify deadline selection directly rather than inferring the selected budget
// from scheduler-sensitive wall-clock timing. The SDK can detach its requests
// from the operation context, so the transport must restore the earlier parent
// deadline without extending an even earlier request deadline.
func TestServiceTimeoutParentDeadlinePropagatesToTransport(t *testing.T) {
	parentDeadline := time.Now().Add(time.Minute)
	parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
	defer cancelParent()
	operation, cancelOperation := context.WithTimeout(parent, 2*time.Minute)
	defer cancelOperation()
	for _, stage := range []string{"detached", "later_request", "earlier_request"} {
		t.Run(stage, func(t *testing.T) {
			requestContext := context.Background()
			want := parentDeadline
			if stage != "detached" {
				requestDeadline := parentDeadline.Add(time.Minute)
				if stage == "earlier_request" {
					requestDeadline = parentDeadline.Add(-30 * time.Second)
					want = requestDeadline
				}
				var cancel context.CancelFunc
				requestContext, cancel = context.WithDeadline(requestContext, requestDeadline)
				defer cancel()
			}
			called := false
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				got, ok := r.Context().Deadline()
				if !ok || !got.Equal(want) {
					t.Fatalf("transport deadline = %v (%v), want %v", got, ok, want)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("synthetic"))}, nil
			})
			request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "http://127.0.0.1", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (credentialTransport{base: base, token: "synthetic", operation: operation}).RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if !called {
				t.Fatal("transport was not exercised")
			}
		})
	}
}
