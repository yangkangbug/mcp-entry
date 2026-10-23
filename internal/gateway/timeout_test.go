package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exercise the real SDK and transport, with short test-only budgets. Headers
// and bodies stall independently; no test depends on an elapsed-time threshold.
func TestFailureSDKTimeoutBoundaries(t *testing.T) {
	for _, stage := range []string{"headers", "json_body", "sse_body"} {
		for _, source := range []string{"parent", "operation", "http_client", "response_headers"} {
			if source == "response_headers" && stage != "headers" {
				continue
			}
			t.Run(stage+"/"+source, func(t *testing.T) {
				var calls atomic.Int32
				ended := make(chan bool, 1)
				teardown := make(chan struct{})
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if r.Method == http.MethodDelete {
						w.WriteHeader(204)
						return
					}
					_ = json.NewDecoder(r.Body).Decode(&req)
					switch req.Method {
					case "initialize":
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}`, req.ID)
					case "notifications/initialized", "notifications/cancelled":
						w.WriteHeader(202)
					case "tools/call":
						if calls.Add(1) == 1 {
							switch stage {
							case "json_body":
								w.Header().Set("Content-Type", "application/json")
								fmt.Fprint(w, `{"jsonrpc":"2.0","id":`)
								w.(http.Flusher).Flush()
							case "sse_body":
								w.Header().Set("Content-Type", "text/event-stream")
								fmt.Fprint(w, "event: message\ndata: ")
								w.(http.Flusher).Flush()
							}
							select {
							case <-r.Context().Done():
								ended <- true
							case <-teardown:
								ended <- false
							}
							return
						}
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"recovered"}]}}`, req.ID)
					default:
						w.WriteHeader(404)
					}
				}))
				defer server.Close()
				defer close(teardown) // Unblock teardown even when a regression fails.
				observationCtx, observation := withFailureObservation(context.Background())
				client := server.Client()
				transport := client.Transport.(*http.Transport)
				if source == "response_headers" {
					transport.ResponseHeaderTimeout = 250 * time.Millisecond
				}
				if source == "http_client" {
					client.Timeout = 250 * time.Millisecond
				}
				client.Transport = observeFailureTransport(observationCtx, transport)
				connectCtx, connectCancel := context.WithTimeout(observationCtx, 5*time.Second)
				defer connectCancel()
				observation.setPhase(FailureConnect)
				session, err := failureTestConnect(connectCtx, server.URL, client)
				if err != nil {
					t.Fatalf("connect: %v", err)
				}
				defer session.Close()

				parentBudget, operationBudget := 5*time.Second, 4*time.Second
				if source == "parent" {
					parentBudget = 250 * time.Millisecond
				}
				if source == "operation" {
					operationBudget = 250 * time.Millisecond
				}
				parent, cancelParent := context.WithTimeout(observationCtx, parentBudget)
				defer cancelParent()
				ctx, cancel := context.WithTimeout(parent, operationBudget)
				defer cancel()
				observation.setPhase(FailureCall)
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "test", Arguments: map[string]any{}})
				if err == nil || result != nil {
					t.Fatal("stalled call returned a confirmed result")
				}
				f := classifyDownstreamFailure(ctx, FailureCall, err, true)
				if f.Code != FailureTimeout || f.Phase != FailureCall || f.HTTPStatus != 0 || !f.OutcomeUnknown {
					t.Fatalf("incorrect timeout evidence: %+v", f)
				}
				if (parent.Err() == context.DeadlineExceeded) != (source == "parent") {
					t.Fatalf("unexpected parent state: %v", parent.Err())
				}
				wantOperationDeadline := source == "parent" || source == "operation"
				if (ctx.Err() == context.DeadlineExceeded) != wantOperationDeadline {
					t.Fatalf("unexpected operation state: %v", ctx.Err())
				}
				select {
				case canceled := <-ended:
					if !canceled {
						t.Fatal("request released only by teardown")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("timed-out request did not release downstream handler")
				}
				if calls.Load() != 1 {
					t.Fatalf("timed-out tool was retried: %d", calls.Load())
				}

				// A fresh operation can use the same endpoint/client after cancellation.
				// This proves local recovery, not remote rollback or session deletion.
				recoveryCtx, recoveryCancel := context.WithTimeout(observationCtx, 3*time.Second)
				defer recoveryCancel()
				observation.setPhase(FailureConnect)
				recovery, err := failureTestConnect(recoveryCtx, server.URL, client)
				if err != nil {
					t.Fatalf("recovery connect: %v", err)
				}
				defer recovery.Close()
				observation.setPhase(FailureCall)
				result, err = recovery.CallTool(recoveryCtx, &mcp.CallToolParams{Name: "test", Arguments: map[string]any{}})
				if err != nil || result == nil || result.IsError {
					t.Fatalf("recovery failed: result=%v error=%v", result, err)
				}
				if calls.Load() != 2 {
					t.Fatalf("unexpected total dispatches: %d", calls.Load())
				}
			})
		}
	}
}

// A declared deadline alone must not turn an unrelated error into a timeout.
// This context models a deadline whose timer callback has not run yet.
type timeoutPendingContext struct {
	context.Context
	deadline time.Time
}

func (c timeoutPendingContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestFailureRequestDeadlineEvidence(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	pending := timeoutPendingContext{context.Background(), time.Now().Add(-time.Second)}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		signal <-chan struct{}
		want   FailureCode
	}{
		{"no_deadline", context.Background(), closed, FailureTransport},
		{"nil_context", nil, closed, FailureTransport},
		{"future_deadline", timeoutPendingContext{context.Background(), time.Now().Add(time.Hour)}, closed, FailureTransport},
		{"elapsed_without_cancel", pending, nil, FailureTransport},
		{"elapsed_with_cancel", pending, closed, FailureTimeout},
		{"explicit_cancel", canceled, closed, FailureCanceled},
		{"cancel_before_elapsed_deadline", timeoutPendingContext{canceled, time.Now().Add(-time.Second)}, closed, FailureCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestFailure(tc.ctx, tc.signal, fmt.Errorf("untrusted timeout text")); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestFailureBodyEOFDeadlineEvidence(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		signal <-chan struct{}
		want   FailureCode
	}{
		{"ordinary_eof", context.Background(), nil, FailureProtocol},
		{"elapsed_without_signal", timeoutPendingContext{context.Background(), time.Now().Add(-time.Second)}, nil, FailureProtocol},
		{"timeout_eof", timeoutPendingContext{context.Background(), time.Now().Add(-time.Second)}, closed, FailureTimeout},
		{"canceled_eof", canceled, nil, FailureCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, o := withFailureObservation(context.Background())
			o.setPhase(FailureCall)
			body := failureBody{ReadCloser: failureTestReadCloser{io.EOF}, observation: o, epoch: o.epoch, requestContext: tc.ctx, requestCancel: tc.signal}
			_, _ = io.ReadAll(&body)
			f := classifyDownstreamFailure(ctx, FailureCall, fmt.Errorf("SDK terminated without response"), true)
			if f.Code != tc.want || !f.OutcomeUnknown {
				t.Fatalf("unexpected evidence: %+v", f)
			}
			if classifyDownstreamFailure(ctx, FailureCall, nil, true) != nil {
				t.Fatal("EOF changed confirmed success")
			}
		})
	}
}
