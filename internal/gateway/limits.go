package gateway

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

// AdmissionLimit controls an independent concurrency cap and token bucket.
// Zero fields select defaults; negative and excessive values are rejected.
type AdmissionLimit struct {
	MaxConcurrent int     `json:"max_concurrent,omitempty"`
	RatePerSecond float64 `json:"rate_per_second,omitempty"`
	Burst         int     `json:"burst,omitempty"`
}

// LimitsConfig applies to all outbound discovery and call operations. Limits
// are local to this gateway process, not a distributed provider quota.
type LimitsConfig struct {
	Global      AdmissionLimit `json:"global,omitempty"`
	Principal   AdmissionLimit `json:"principal,omitempty"`
	Tenant      AdmissionLimit `json:"tenant,omitempty"`
	System      AdmissionLimit `json:"system,omitempty"`
	SharedQuota AdmissionLimit `json:"shared_quota,omitempty"`
}

// AdmissionFailure exposes only fixed scope and reason labels, never identity,
// credentials, arguments, provider errors or quota-subject strings.
type AdmissionFailure struct {
	Scope  string
	Reason string
}

func (e *AdmissionFailure) Error() string { return "downstream admission rejected" }

func normalizeAdmissionLimit(v, defaults AdmissionLimit) (AdmissionLimit, error) {
	if v.MaxConcurrent < 0 || v.MaxConcurrent > 1024 || v.RatePerSecond < 0 || v.RatePerSecond > 100000 || math.IsNaN(v.RatePerSecond) || math.IsInf(v.RatePerSecond, 0) || v.Burst < 0 || v.Burst > 100000 {
		return AdmissionLimit{}, errors.New("invalid admission limit")
	}
	if v.MaxConcurrent == 0 {
		v.MaxConcurrent = defaults.MaxConcurrent
	}
	if v.RatePerSecond == 0 {
		v.RatePerSecond = defaults.RatePerSecond
	}
	if v.Burst == 0 {
		v.Burst = defaults.Burst
	}
	return v, nil
}
func normalizeLimits(v LimitsConfig) (LimitsConfig, error) {
	fields := []*AdmissionLimit{&v.Principal, &v.Tenant, &v.System, &v.SharedQuota, &v.Global}
	defaults := []AdmissionLimit{{8, 20, 32}, {16, 40, 128}, {32, 80, 128}, {16, 40, 128}, {64, 160, 256}}
	for i, p := range fields {
		n, err := normalizeAdmissionLimit(*p, defaults[i])
		if err != nil {
			return LimitsConfig{}, err
		}
		*p = n
	}
	return v, nil
}

type admissionBucket struct {
	limit  AdmissionLimit
	active int
	tokens float64
	last   time.Time
}
type admissionLimiter struct {
	global     *admissionBucket
	mu         sync.Mutex
	now        func() time.Time
	principals map[Identity]*admissionBucket
	tenants    map[string]*admissionBucket
	systems    map[string]*admissionBucket
	shared     map[string]*admissionBucket
	subjects   map[string]string
}

// newAdmissionLimiter allocates only configured scopes (at most 64 principals,
// 64 tenants, 16 systems and 16 shared subjects). Admission never inserts keys.
// systems maps a system name to its optional global shared-quota subject. Equal
// subjects deliberately share a bucket across users, tenants AND systems.
func newAdmissionLimiter(cfg LimitsConfig, identities []Identity, systems map[string]string) (*admissionLimiter, error) {
	cfg, err := normalizeLimits(cfg)
	if err != nil {
		return nil, err
	}
	if len(identities) > 64 || len(systems) > 16 {
		return nil, errors.New("admission scope limit exceeded")
	}
	l := &admissionLimiter{now: time.Now, principals: map[Identity]*admissionBucket{}, tenants: map[string]*admissionBucket{}, systems: map[string]*admissionBucket{}, shared: map[string]*admissionBucket{}, subjects: map[string]string{}}
	now := l.now()
	bucket := func(v AdmissionLimit) *admissionBucket {
		return &admissionBucket{limit: v, tokens: float64(v.Burst), last: now}
	}
	l.global = bucket(cfg.Global)
	for _, id := range identities {
		if id.Tenant == "" || id.Principal == "" || len(id.Tenant) > 128 || len(id.Principal) > 128 {
			return nil, errors.New("invalid admission identity")
		}
		if _, ok := l.principals[id]; ok {
			return nil, errors.New("duplicate admission identity")
		}
		l.principals[id] = bucket(cfg.Principal)
		if l.tenants[id.Tenant] == nil {
			l.tenants[id.Tenant] = bucket(cfg.Tenant)
		}
	}
	for system, subject := range systems {
		if !validPart(system) || len(system) > 64 || len(subject) > 128 {
			return nil, errors.New("invalid admission system or quota subject")
		}
		for _, c := range subject {
			if c < 0x21 || c > 0x7e {
				return nil, errors.New("invalid quota subject")
			}
		}
		l.systems[system] = bucket(cfg.System)
		if subject != "" {
			l.subjects[system] = subject
			if l.shared[subject] == nil {
				l.shared[subject] = bucket(cfg.SharedQuota)
			}
		}
	}
	return l, nil
}

type admissionPermit struct {
	once    sync.Once
	limiter *admissionLimiter
	buckets [5]*admissionBucket
}

// Release must be deferred immediately after successful admission, including
// cancellation and failure paths. It releases concurrency, not rate tokens:
// already attempted operations remain charged. No cancellation watcher can
// release capacity while an uncooperative downstream is still running.
func (p *admissionPermit) Release() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		p.limiter.mu.Lock()
		defer p.limiter.mu.Unlock()
		for _, b := range p.buckets {
			if b != nil {
				b.active--
			}
		}
	})
}

// acquire is fail-fast: no queue, sleepers, timers, goroutines or retry loops.
// All scope checks and debits are atomic. A refusal spends no tokens anywhere.
func (l *admissionLimiter) acquire(ctx context.Context, id Identity, system string) (*admissionPermit, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buckets := [5]*admissionBucket{l.principals[id], l.tenants[id.Tenant], l.systems[system], nil, l.global}
	if buckets[0] == nil || buckets[1] == nil || buckets[2] == nil {
		return nil, &AdmissionFailure{Scope: "scope", Reason: "unknown"}
	}
	if subject := l.subjects[system]; subject != "" {
		buckets[3] = l.shared[subject]
	}
	scopes := [5]string{"principal", "tenant", "system", "shared_quota", "global"}
	now := l.now()
	for i, b := range buckets {
		if b == nil {
			continue
		}
		if now.After(b.last) {
			b.tokens = math.Min(float64(b.limit.Burst), b.tokens+now.Sub(b.last).Seconds()*b.limit.RatePerSecond)
			b.last = now
		}
		if b.active >= b.limit.MaxConcurrent {
			return nil, &AdmissionFailure{Scope: scopes[i], Reason: "concurrency"}
		}
		if b.tokens < 1 {
			return nil, &AdmissionFailure{Scope: scopes[i], Reason: "rate"}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, b := range buckets {
		if b != nil {
			b.active++
			b.tokens--
		}
	}
	return &admissionPermit{limiter: l, buckets: buckets}, nil
}
