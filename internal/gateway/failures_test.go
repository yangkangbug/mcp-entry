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
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFailureStatusCategories(t *testing.T) {
	cases := []struct {
		status int
		code   FailureCode
	}{
		{401, FailureAuthentication}, {403, FailurePermission}, {429, FailureRateLimit},
		{500, FailureService}, {502, FailureService}, {503, FailureService},
		{408, FailureTimeout}, {504, FailureTimeout}, {302, FailureProtocol}, {404, FailureProtocol},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			ctx, o := withFailureObservation(context.Background())
			o.setPhase(FailureCall)
			o.record(o.epoch, failureEvidence{code: statusFailure(tc.status), status: tc.status})
			f := classifyDownstreamFailure(ctx, FailureCall, errors.New("secret URL?token=secret 401 expired revoked"), true)
			if f.Code != tc.code || f.HTTPStatus != tc.status || !f.OutcomeUnknown || f.Phase != FailureCall {
				t.Fatalf("unexpected failure: %+v", f)
			}
			if strings.Contains(f.Error(), "secret") || strings.Contains(f.Error(), "expired") || strings.Contains(f.Error(), "revoked") {
				t.Fatalf("leaked cause: %s", f)
			}
		})
	}
}

func TestFailureNeverParsesUntrustedText(t *testing.T) {
	for _, message := range []string{"401 Unauthorized", "403", "429 rate limit", "token expired", "timeout", "503", "permission denied"} {
		f := classifyDownstreamFailure(context.Background(), FailureDiscovery, errors.New(message), false)
		if f.Code != FailureProtocol || f.HTTPStatus != 0 || f.OutcomeUnknown {
			t.Fatalf("parsed arbitrary text %q: %+v", message, f)
		}
	}
	if classifyDownstreamFailure(context.Background(), FailureCall, nil, true) != nil {
		t.Fatal("successful result classified")
	}
}

func TestFailureTypedAndContextEvidence(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code FailureCode
	}{{context.DeadlineExceeded, FailureTimeout}, {context.Canceled, FailureCanceled}, {io.ErrUnexpectedEOF, FailureTransport}} {
		f := classifyDownstreamFailure(context.Background(), FailureCall, fmt.Errorf("secret: %w", tc.err), true)
		if f.Code != tc.code {
			t.Fatalf("got %s want %s", f.Code, tc.code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f := classifyDownstreamFailure(ctx, FailureCall, errors.New("SDK stringified cancellation"), true); f.Code != FailureCanceled {
		t.Fatalf("lost context: %+v", f)
	}
}

func TestFailurePhasesIgnoreLateEvidence(t *testing.T) {
	ctx, o := withFailureObservation(context.Background())
	o.setPhase(FailureConnect)
	oldEpoch := o.epoch
	o.record(oldEpoch, failureEvidence{code: FailurePermission, status: 403})
	o.setPhase(FailureCall)
	o.record(oldEpoch, failureEvidence{code: FailureAuthentication, status: 401})
	f := classifyDownstreamFailure(ctx, FailureCall, io.ErrUnexpectedEOF, true)
	if f.Code != FailureTransport || f.HTTPStatus != 0 {
		t.Fatalf("stale phase evidence: %+v", f)
	}
	o.setPhase(FailureCleanup)
	o.record(o.epoch, failureEvidence{code: FailureService, status: 503})
	if f.Code != FailureTransport || f.Phase != FailureCall || !f.OutcomeUnknown {
		t.Fatalf("cleanup mutated prior failure: %+v", f)
	}
}

// Real loopback TLS + SDK tests ensure HTTP evidence survives SDK error wrapping.
func TestFailureSDKConnectHTTPStatus(t *testing.T) {
	for _, status := range []int{401, 403, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := map[string]int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				requests[req.Method]++
				w.Header().Set("X-Secret", "header-secret")
				http.Error(w, "body-secret", status)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ctx, o := withFailureObservation(ctx)
			o.setPhase(FailureConnect)
			client := server.Client()
			client.Transport = observeFailureTransport(ctx, client.Transport)
			session, err := failureTestConnect(ctx, server.URL+"/private-secret", client)
			if session != nil {
				defer session.Close()
			}
			if err == nil {
				t.Fatal("expected failure")
			}
			f := classifyDownstreamFailure(ctx, FailureConnect, err, false)
			if f.Code != statusFailure(status) || f.HTTPStatus != status || f.OutcomeUnknown {
				t.Fatalf("lost HTTP evidence: %+v (raw error omitted)", f)
			}
			if requests["server/discover"] != 1 || requests["initialize"] != 1 {
				t.Fatalf("unexpected negotiation requests: %v", requests)
			}
			encoded, _ := json.Marshal(f)
			if strings.Contains(string(encoded)+f.Error(), "secret") || strings.Contains(string(encoded)+f.Error(), server.URL) {
				t.Fatal("failure leaked downstream data")
			}
		})
	}
}

func failureTestConnect(ctx context.Context, endpoint string, client *http.Client) (*mcp.ClientSession, error) {
	sdk := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	return sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
}

func TestFailureSDKCallJSONAndSSE(t *testing.T) {
	for _, format := range []string{"json", "sse"} {
		for _, status := range []int{200, 401, 403, 429, 503} {
			t.Run(fmt.Sprintf("%s/%d", format, status), func(t *testing.T) {
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "DELETE" {
						w.WriteHeader(204)
						return
					}
					var req struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error("bad request")
						w.WriteHeader(400)
						return
					}
					switch req.Method {
					case "initialize":
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}`, req.ID)
					case "notifications/initialized":
						w.WriteHeader(202)
					case "tools/call":
						calls++
						if status != 200 {
							http.Error(w, "credential expired 401 secret", status)
							return
						}
						payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"401 expired 429 business-secret"}],"structuredContent":{"status":403}}}`, req.ID)
						if format == "sse" {
							w.Header().Set("Content-Type", "text/event-stream")
							fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
						} else {
							w.Header().Set("Content-Type", "application/json")
							io.WriteString(w, payload)
						}
					default:
						w.WriteHeader(400)
					}
				}))
				defer server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ctx, o := withFailureObservation(ctx)
				o.setPhase(FailureConnect)
				client := server.Client()
				client.Transport = observeFailureTransport(ctx, client.Transport)
				session, err := failureTestConnect(ctx, server.URL, client)
				if err != nil {
					t.Fatalf("connect: %v", err)
				}
				defer session.Close()
				o.setPhase(FailureCall)
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "test", Arguments: map[string]any{}})
				if status == 200 {
					if err != nil {
						t.Fatalf("successful business result: %v", err)
					}
					if result == nil || !result.IsError || len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "401 expired 429 business-secret" {
						t.Fatalf("business result changed: %+v", result)
					}
					if classifyDownstreamFailure(ctx, FailureCall, err, true) != nil {
						t.Fatal("business error classified")
					}
				} else {
					if err == nil {
						t.Fatal("expected call error")
					}
					f := classifyDownstreamFailure(ctx, FailureCall, err, true)
					if f.Code != statusFailure(status) || f.HTTPStatus != status || !f.OutcomeUnknown {
						t.Fatalf("lost call evidence: %+v", f)
					}
				}
				if calls != 1 {
					t.Fatalf("call retried: %d", calls)
				}
			})
		}
	}
}

// A rejected modern-protocol probe must not mask the real legacy handshake.
func TestFailureSDKNegotiationUsesLatestStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "server/discover" {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx, o := withFailureObservation(ctx)
	o.setPhase(FailureConnect)
	client := server.Client()
	client.Transport = observeFailureTransport(ctx, client.Transport)
	session, err := failureTestConnect(ctx, server.URL, client)
	if session != nil {
		defer session.Close()
	}
	f := classifyDownstreamFailure(ctx, FailureConnect, err, false)
	if f == nil || f.Code != FailureAuthentication || f.HTTPStatus != 401 {
		t.Fatalf("probe masked handshake: %+v", f)
	}
}

type failureTestRoundTripper func(*http.Request) (*http.Response, error)

func (fn failureTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type failureTestReadCloser struct{ err error }

func (b failureTestReadCloser) Read([]byte) (int, error) { return 0, b.err }
func (b failureTestReadCloser) Close() error             { return nil }
func TestFailureTransportReadEvidenceAndLateReads(t *testing.T) {
	ctx, o := withFailureObservation(context.Background())
	o.setPhase(FailureCall)
	tr := observeFailureTransport(ctx, failureTestRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: failureTestReadCloser{context.DeadlineExceeded}}, nil
	}))
	req, _ := http.NewRequest("POST", "https://localhost/secret", nil)
	response, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
	f := classifyDownstreamFailure(ctx, FailureCall, errors.New("SDK stringified read error"), true)
	if f.Code != FailureTimeout {
		t.Fatalf("lost body timeout: %+v", f)
	}
	o.setPhase(FailureCleanup)
	_, _ = io.ReadAll(response.Body)
	f = classifyDownstreamFailure(ctx, FailureCleanup, errors.New("different failure"), false)
	if f.Code != FailureProtocol || f.OutcomeUnknown {
		t.Fatalf("late body contaminated cleanup: %+v", f)
	}
}
