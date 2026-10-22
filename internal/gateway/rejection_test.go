package gateway

import (
	"context"
	"math"
	"sync"
	"testing"
)

func TestRejectionSummarySaturationAndConcurrentDedup(t *testing.T) {
	g, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	g.rejections.status.HTTP[RejectionAuthentication].Count = math.MaxUint64
	g.rejections.record(RejectionAuthentication)
	status := g.RejectionStatus()
	if c := status.HTTP[RejectionAuthentication]; c.Count != math.MaxUint64 || !c.Saturated || c.Last.IsZero() || status.Started.IsZero() {
		t.Fatal(status)
	}
	ctx := context.WithValue(context.Background(), operationRejectionKey{}, &operationRejection{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); g.rejectOperation(ctx, RejectionOperationArguments) }()
	}
	wg.Wait()
	if got := g.RejectionStatus().Operations[RejectionOperationArguments-RejectionOperationAuthorization].Count; got != 1 {
		t.Fatal(got)
	}
	g.rejectAdmission(context.Background(), context.Canceled)
	if g.RejectionStatus().Operations[RejectionOperationAdmission-RejectionOperationAuthorization].Count != 0 {
		t.Fatal("cancellation misclassified as admission rejection")
	}
}

func TestIngressConfigInvalidValues(t *testing.T) {
	for _, limit := range []AdmissionLimit{{MaxConcurrent: -1}, {MaxConcurrent: 1025}, {RatePerSecond: -1}, {RatePerSecond: math.Inf(1)}, {RatePerSecond: math.NaN()}, {RatePerSecond: 100001}, {Burst: -1}, {Burst: 100001}} {
		for _, cfg := range []IngressConfig{{Global: limit}, {Principal: limit}} {
			if _, err := New(Config{Ingress: cfg}); err == nil {
				t.Fatalf("accepted %+v", cfg)
			}
		}
	}
}
