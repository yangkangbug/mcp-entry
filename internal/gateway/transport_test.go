package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
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
