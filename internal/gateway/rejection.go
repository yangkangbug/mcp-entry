package gateway

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// RejectionKind is a closed set. No attacker-controlled labels are retained.
type RejectionKind uint8

const (
	RejectionIngressGlobal RejectionKind = iota
	RejectionIngressPrincipal
	RejectionAuthentication
	RejectionAuthorization
	RejectionRequest
	RejectionHTTPUnavailable
	RejectionOperationAuthorization
	RejectionOperationArguments
	RejectionOperationAdmission
	RejectionOperationProtocol
	rejectionKindCount
)

// RejectionCounter counts either HTTP responses or operation denials, never a
// combined request total. Counts saturate instead of wrapping.
type RejectionCounter struct {
	Count     uint64
	Last      time.Time
	Saturated bool
}
type RejectionStatus struct {
	Started    time.Time
	HTTP       [6]RejectionCounter
	Operations [4]RejectionCounter
}
type rejectionSummary struct {
	mu     sync.Mutex
	status RejectionStatus
}

func (s *rejectionSummary) record(kind RejectionKind) {
	if kind >= rejectionKindCount {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var c *RejectionCounter
	if kind < RejectionOperationAuthorization {
		c = &s.status.HTTP[kind]
	} else {
		c = &s.status.Operations[kind-RejectionOperationAuthorization]
	}
	if c.Count == math.MaxUint64 {
		c.Saturated = true
	} else {
		c.Count++
	}
	c.Last = time.Now().UTC()
}

// RejectionStatus is a trusted in-process, nondurable operational snapshot. It
// contains no identity, request text or credentials and is not a forensic log.
func (g *Gateway) RejectionStatus() RejectionStatus {
	g.rejections.mu.Lock()
	defer g.rejections.mu.Unlock()
	return g.rejections.status
}

type operationRejectionKey struct{}
type operationRejection struct{ recorded atomic.Bool }

func (g *Gateway) rejectOperation(ctx context.Context, kind RejectionKind) {
	if o, ok := ctx.Value(operationRejectionKey{}).(*operationRejection); ok {
		if o.recorded.Swap(true) {
			return
		}
	}
	g.rejections.record(kind)
}

func (g *Gateway) rejectAdmission(ctx context.Context, err error) {
	var failure *AdmissionFailure
	if errors.As(err, &failure) {
		g.rejectOperation(ctx, RejectionOperationAdmission)
	}
}
