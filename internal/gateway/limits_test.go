package gateway

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func limitFixture(t *testing.T, cfg LimitsConfig) (*admissionLimiter, *time.Time) {
	t.Helper()
	l, err := newAdmissionLimiter(cfg, []Identity{{"a", "one"}, {"a", "two"}, {"b", "one"}}, map[string]string{"crm": "provider", "docs": "provider", "other": ""})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	l.global.last = now
	for _, bs := range []map[string]*admissionBucket{l.tenants, l.systems, l.shared} {
		for _, b := range bs {
			b.last = now
		}
	}
	for _, b := range l.principals {
		b.last = now
	}
	return l, &now
}
func admitted(t *testing.T, l *admissionLimiter, id Identity, system string) *admissionPermit {
	t.Helper()
	p, err := l.acquire(context.Background(), id, system)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func rejected(t *testing.T, l *admissionLimiter, id Identity, system, scope, reason string) {
	t.Helper()
	p, err := l.acquire(context.Background(), id, system)
	if p != nil {
		p.Release()
		t.Fatal("unexpected permit")
	}
	var f *AdmissionFailure
	if !errors.As(err, &f) || f.Scope != scope || f.Reason != reason {
		t.Fatalf("failure %#v, want %s %s", err, scope, reason)
	}
}
func TestAdmissionScopes(t *testing.T) {
	cases := []struct {
		name          string
		cfg           LimitsConfig
		first, second Identity
		system, scope string
	}{
		{"principal", LimitsConfig{Principal: AdmissionLimit{MaxConcurrent: 1}}, Identity{"a", "one"}, Identity{"a", "one"}, "other", "principal"},
		{"tenant", LimitsConfig{Tenant: AdmissionLimit{MaxConcurrent: 1}}, Identity{"a", "one"}, Identity{"a", "two"}, "other", "tenant"},
		{"system", LimitsConfig{System: AdmissionLimit{MaxConcurrent: 1}}, Identity{"a", "one"}, Identity{"b", "one"}, "crm", "system"},
		{"shared", LimitsConfig{SharedQuota: AdmissionLimit{MaxConcurrent: 1}}, Identity{"a", "one"}, Identity{"b", "one"}, "docs", "shared_quota"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, _ := limitFixture(t, c.cfg)
			p := admitted(t, l, c.first, "crm")
			rejected(t, l, c.second, c.system, c.scope, "concurrency")
			p.Release()
			p.Release()
			admitted(t, l, c.second, c.system).Release()
		})
	}
}
func TestAdmissionIndependentPrincipalAndTenant(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{Principal: AdmissionLimit{MaxConcurrent: 1}, Tenant: AdmissionLimit{MaxConcurrent: 2}})
	a := admitted(t, l, Identity{"a", "one"}, "crm")
	defer a.Release()
	b := admitted(t, l, Identity{"a", "two"}, "crm")
	defer b.Release()
	c := admitted(t, l, Identity{"b", "one"}, "crm")
	defer c.Release()
}
func TestAdmissionRateClockAndAtomicDebit(t *testing.T) {
	l, now := limitFixture(t, LimitsConfig{SharedQuota: AdmissionLimit{RatePerSecond: 2, Burst: 1}})
	admitted(t, l, Identity{"a", "one"}, "crm").Release()
	before := l.principals[Identity{"b", "one"}].tokens
	rejected(t, l, Identity{"b", "one"}, "docs", "shared_quota", "rate")
	if l.principals[Identity{"b", "one"}].tokens != before {
		t.Fatal("denial charged another scope")
	}
	*now = now.Add(499 * time.Millisecond)
	rejected(t, l, Identity{"b", "one"}, "docs", "shared_quota", "rate")
	*now = now.Add(time.Millisecond)
	admitted(t, l, Identity{"b", "one"}, "docs").Release()
	*now = now.Add(-time.Hour)
	rejected(t, l, Identity{"b", "one"}, "docs", "shared_quota", "rate")
}
func TestAdmissionCancelAndFailureNoLeaks(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tokens := l.principals[Identity{"a", "one"}].tokens
	if p, err := l.acquire(ctx, Identity{"a", "one"}, "crm"); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v %v", p, err)
	}
	if l.principals[Identity{"a", "one"}].tokens != tokens {
		t.Fatal("canceled request spent tokens")
	}
	func() {
		p := admitted(t, l, Identity{"a", "one"}, "crm")
		defer p.Release() /* simulated downstream failure */
	}()
	for _, b := range l.principals {
		if b.active != 0 {
			t.Fatal("leaked principal permit")
		}
	}
	for _, bs := range []map[string]*admissionBucket{l.tenants, l.systems, l.shared} {
		for _, b := range bs {
			if b.active != 0 {
				t.Fatal("leaked permit")
			}
		}
	}
}
func TestAdmissionConcurrentBarrier(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{SharedQuota: AdmissionLimit{MaxConcurrent: 3}})
	start, release := make(chan struct{}), make(chan struct{})
	var wg, attempted sync.WaitGroup
	var success atomic.Int32
	wg.Add(32)
	attempted.Add(32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			id := Identity{"a", "one"}
			system := "crm"
			if i%2 == 1 {
				id = Identity{"b", "one"}
				system = "docs"
			}
			p, err := l.acquire(context.Background(), id, system)
			if err == nil {
				success.Add(1)
			}
			attempted.Done()
			if p != nil {
				<-release
				p.Release()
				p.Release()
			}
		}(i)
	}
	close(start)
	attempted.Wait()
	if success.Load() != 3 {
		t.Errorf("got %d admissions", success.Load())
	}
	close(release)
	wg.Wait()
	if l.shared["provider"].active != 0 {
		t.Fatal("permit leak")
	}
}
func TestAdmissionBoundedUnknownAndStructuredIdentity(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{})
	for i := 0; i < 1000; i++ {
		rejected(t, l, Identity{"unknown", "unknown"}, "crm", "scope", "unknown")
		rejected(t, l, Identity{"a", "one"}, "unknown", "scope", "unknown")
	}
	if len(l.principals) != 3 || len(l.tenants) != 2 || len(l.systems) != 3 || len(l.shared) != 1 {
		t.Fatal("unknown scopes grew maps")
	}
	other, err := newAdmissionLimiter(LimitsConfig{Principal: AdmissionLimit{MaxConcurrent: 1}}, []Identity{{"a:b", "c"}, {"a", "b:c"}}, map[string]string{"crm": ""})
	if err != nil {
		t.Fatal(err)
	}
	p := admitted(t, other, Identity{"a:b", "c"}, "crm")
	defer p.Release()
	admitted(t, other, Identity{"a", "b:c"}, "crm").Release()
}
func TestAdmissionInvalidConfig(t *testing.T) {
	for _, bad := range []AdmissionLimit{{MaxConcurrent: -1}, {MaxConcurrent: 1025}, {RatePerSecond: -1}, {RatePerSecond: 100001}, {RatePerSecond: math.NaN()}, {RatePerSecond: math.Inf(1)}, {Burst: -1}, {Burst: 100001}} {
		for _, cfg := range []LimitsConfig{{Principal: bad}, {Tenant: bad}, {System: bad}, {SharedQuota: bad}, {Global: bad}} {
			if _, err := newAdmissionLimiter(cfg, nil, nil); err == nil {
				t.Fatalf("accepted %+v", cfg)
			}
		}
	}
	for _, subject := range []string{"bad subject", "bad\nsubject", string(make([]byte, 129))} {
		if _, err := newAdmissionLimiter(LimitsConfig{}, nil, map[string]string{"crm": subject}); err == nil {
			t.Fatal("accepted bad subject")
		}
	}
	if _, err := newAdmissionLimiter(LimitsConfig{}, make([]Identity, 65), nil); err == nil {
		t.Fatal("accepted too many principals")
	}
}

func TestAdmissionGlobalScope(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{Global: AdmissionLimit{MaxConcurrent: 1}})
	p := admitted(t, l, Identity{"a", "one"}, "crm")
	rejected(t, l, Identity{"b", "one"}, "other", "global", "concurrency")
	p.Release()
	admitted(t, l, Identity{"b", "one"}, "other").Release()
	if l.global.active != 0 {
		t.Fatal("global leak")
	}
}

func TestAdmissionRateAllScopes(t *testing.T) {
	low := AdmissionLimit{RatePerSecond: 1, Burst: 1}
	cases := []struct {
		scope  string
		cfg    LimitsConfig
		id     Identity
		system string
	}{
		{"principal", LimitsConfig{Principal: low}, Identity{"a", "one"}, "other"},
		{"tenant", LimitsConfig{Tenant: low}, Identity{"a", "two"}, "other"},
		{"system", LimitsConfig{System: low}, Identity{"b", "one"}, "crm"},
		{"shared_quota", LimitsConfig{SharedQuota: low}, Identity{"b", "one"}, "docs"},
		{"global", LimitsConfig{Global: low}, Identity{"b", "one"}, "other"},
	}
	for _, c := range cases {
		t.Run(c.scope, func(t *testing.T) {
			l, now := limitFixture(t, c.cfg)
			admitted(t, l, Identity{"a", "one"}, "crm").Release()
			rejected(t, l, c.id, c.system, c.scope, "rate")
			*now = now.Add(time.Second)
			admitted(t, l, c.id, c.system).Release()
		})
	}
}

func TestAdmissionCancellationHoldsUntilCleanup(t *testing.T) {
	l, _ := limitFixture(t, LimitsConfig{Global: AdmissionLimit{MaxConcurrent: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	p, err := l.acquire(ctx, Identity{"a", "one"}, "crm")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	// Cancellation signals downstream; capacity must remain held until its
	// actual cleanup completes, otherwise an ignoring backend bypasses the cap.
	rejected(t, l, Identity{"b", "one"}, "other", "global", "concurrency")
	p.Release()
	admitted(t, l, Identity{"b", "one"}, "other").Release()
}
