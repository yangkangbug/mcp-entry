package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOperationTransportBodyLifetime(t *testing.T) {
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requestContext context.Context
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requestContext = r.Context()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("complete"))}, nil
	})
	transport := credentialTransport{token: "synthetic", base: base, operation: operation}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1", nil)
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if requestContext.Err() != nil {
		t.Fatal("request canceled before response body consumption")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "complete" {
		t.Fatalf("body=%q error=%v", body, err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if requestContext.Err() != context.Canceled {
		t.Fatal("body close did not release request context")
	}
	if operation.Err() != nil || req.Context().Err() != nil {
		t.Fatal("parent contexts canceled")
	}
}

func TestOperationTransportErrorReleasesContext(t *testing.T) {
	var requestContext context.Context
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requestContext = r.Context()
		return nil, errors.New("synthetic transport failure")
	})
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1", nil)
	_, err := (credentialTransport{base: base, operation: context.Background()}).RoundTrip(req)
	if err == nil || requestContext.Err() != context.Canceled {
		t.Fatal("failed request context was not released")
	}
}

func TestOperationTransportCancellationDuringBody(t *testing.T) {
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requestContext context.Context
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requestContext = r.Context()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("body"))}, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1", nil)
	response, err := (credentialTransport{base: base, operation: operation}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	cancel()
	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("operation cancellation did not reach response lifetime")
	}
}

func TestAuthTransportReplacesCaseVariantsWithoutMutatingRequest(t *testing.T) {
	for _, auth := range []AuthConfig{{Mode: "bearer"}, {Mode: "raw"}, {Mode: "api_key", Header: "X-API-Key"}} {
		t.Run(auth.Mode, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1", nil)
			req.Header = http.Header{
				"authorization": {"old-lower"}, "Authorization": {"old-upper"},
				"Mcp-Session-Id": {"synthetic-session"},
			}
			if auth.Mode == "api_key" {
				req.Header["x-api-key"] = []string{"old-key-lower"}
				req.Header["X-Api-Key"] = []string{"old-key-upper"}
			}
			original := req.Header.Clone()
			base := roundTripFunc(func(sent *http.Request) (*http.Response, error) {
				name, value := "Authorization", "synthetic"
				if auth.Mode == "bearer" {
					value = "Bearer synthetic"
				} else if auth.Mode == "api_key" {
					name = "X-Api-Key"
				}
				want := http.Header{name: {value}, "Mcp-Session-Id": {"synthetic-session"}}
				if !reflect.DeepEqual(sent.Header, want) {
					t.Fatalf("outbound headers=%v, want %v", sent.Header, want)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			response, err := (credentialTransport{auth: auth, token: "synthetic", base: base}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if !reflect.DeepEqual(req.Header, original) {
				t.Fatal("transport mutated original request headers")
			}
		})
	}
}
