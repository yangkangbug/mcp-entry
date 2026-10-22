package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// FailureCode describes evidence, not credential state or retry safety.
type FailureCode string

const (
	FailureAuthentication FailureCode = "downstream_authentication_failed"
	FailurePermission     FailureCode = "downstream_permission_denied"
	FailureRateLimit      FailureCode = "downstream_rate_limited"
	FailureService        FailureCode = "downstream_service_unavailable"
	FailureTimeout        FailureCode = "downstream_timeout"
	FailureCanceled       FailureCode = "downstream_canceled"
	FailureTransport      FailureCode = "downstream_transport_failed"
	FailureProtocol       FailureCode = "downstream_protocol_failed"
)

type FailurePhase string

const (
	FailureConnect   FailurePhase = "connect"
	FailureDiscovery FailurePhase = "discovery"
	FailureCall      FailurePhase = "call"
	FailureCleanup   FailurePhase = "cleanup"
)

// DownstreamFailure deliberately retains no original error, URL, body, header,
// token, or JSON-RPC data. A downstream 401 is not an entry-authentication 401;
// neither 401 nor 403 establishes that a credential expired or was revoked.
// OutcomeUnknown is independent of category: even an HTTP rejection after a
// tool dispatch is not evidence that the tool had no effects. Nothing retries.
type DownstreamFailure struct {
	Code           FailureCode  `json:"code"`
	Phase          FailurePhase `json:"phase"`
	HTTPStatus     int          `json:"http_status,omitempty"`
	OutcomeUnknown bool         `json:"outcome_unknown"`
}

func (f *DownstreamFailure) Error() string {
	suffix := "; not retried"
	if f.OutcomeUnknown {
		suffix = "; outcome may be unknown; not retried"
	}
	return fmt.Sprintf("%s (%s)%s", f.Code, f.Phase, suffix)
}

type failureObservationKey struct{}
type failureEvidence struct {
	code   FailureCode
	status int
}

// Each operation owns an observation. Epochs prevent late reads from an old
// phase from contaminating later phases. Only bounded safe evidence is stored.
type failureObservation struct {
	mu       sync.Mutex
	phase    FailurePhase
	epoch    uint64
	evidence failureEvidence
}

func withFailureObservation(ctx context.Context) (context.Context, *failureObservation) {
	observation := &failureObservation{}
	return context.WithValue(ctx, failureObservationKey{}, observation), observation
}
func (o *failureObservation) setPhase(phase FailurePhase) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.phase = phase
	o.epoch++
	o.evidence = failureEvidence{}
}
func (o *failureObservation) record(epoch uint64, evidence failureEvidence) {
	if evidence.code == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if epoch == o.epoch && o.evidence.code == "" {
		o.evidence = evidence
	}
}
func statusFailure(status int) FailureCode {
	switch {
	case status == http.StatusUnauthorized:
		return FailureAuthentication
	case status == http.StatusForbidden:
		return FailurePermission
	case status == http.StatusTooManyRequests:
		return FailureRateLimit
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return FailureTimeout
	case status >= 500 && status <= 599:
		return FailureService
	case status < 200 || status >= 300:
		return FailureProtocol
	default:
		return ""
	}
}
func typedFailure(err error) FailureCode {
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	if errors.Is(err, context.Canceled) {
		return FailureCanceled
	}
	var network net.Error
	if errors.As(err, &network) {
		if network.Timeout() {
			return FailureTimeout
		}
		return FailureTransport
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
		return FailureTransport
	}
	return ""
}

// classifyDownstreamFailure must only be called on a failed operation, never on
// a successful CallToolResult (including IsError and arbitrary business data).
// The context carries evidence even where the SDK formats errors with %%v.
func classifyDownstreamFailure(ctx context.Context, phase FailurePhase, err error, outcomeUnknown bool) *DownstreamFailure {
	if err == nil {
		return nil
	}
	f := &DownstreamFailure{Phase: phase, OutcomeUnknown: outcomeUnknown}
	if o, ok := ctx.Value(failureObservationKey{}).(*failureObservation); ok {
		o.mu.Lock()
		if o.phase == phase {
			f.Code, f.HTTPStatus = o.evidence.code, o.evidence.status
		}
		o.mu.Unlock()
	}
	if f.Code == "" {
		f.Code = typedFailure(err)
	}
	// SDK stringification can destroy cancellation identity; the operation
	// context is authoritative and does not require inspecting arbitrary text.
	if f.Code == "" && ctx.Err() != nil {
		f.Code = typedFailure(ctx.Err())
	}
	if f.Code == "" {
		f.Code = FailureProtocol
	}
	return f
}

type failureTransport struct {
	base        http.RoundTripper
	observation *failureObservation
}

func observeFailureTransport(ctx context.Context, base http.RoundTripper) http.RoundTripper {
	o, ok := ctx.Value(failureObservationKey{}).(*failureObservation)
	if !ok {
		return base
	}
	return failureTransport{base: base, observation: o}
}
func (t failureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.observation.mu.Lock()
	// A new request supersedes a failed protocol-negotiation probe. Old body
	// reads cannot replace evidence from the newer request.
	t.observation.epoch++
	t.observation.evidence = failureEvidence{}
	epoch := t.observation.epoch
	t.observation.mu.Unlock()
	response, err := t.base.RoundTrip(r)
	if err != nil {
		code := typedFailure(err)
		if code == "" {
			code = FailureTransport
		}
		t.observation.record(epoch, failureEvidence{code: code})
	} else if response != nil {
		t.observation.record(epoch, failureEvidence{code: statusFailure(response.StatusCode), status: response.StatusCode})
		if response.Body != nil {
			response.Body = &failureBody{ReadCloser: response.Body, observation: t.observation, epoch: epoch}
		}
	}
	return response, err
}

type failureBody struct {
	io.ReadCloser
	observation *failureObservation
	epoch       uint64
}

func (b *failureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		code := typedFailure(err)
		if code == "" {
			code = FailureTransport
		}
		b.observation.record(b.epoch, failureEvidence{code: code})
	}
	return n, err
}
