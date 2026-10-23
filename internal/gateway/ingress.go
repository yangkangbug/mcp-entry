package gateway

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"
)

// IngressMaxHeaderBytes 是解析后头部的入口预算；宿主仍须限制原始 HTTP 头。
const IngressMaxHeaderBytes = 16 << 10

// IngressReadTimeout 是入口读取预算；请求已有更早截止时间时不将其延长。
const IngressReadTimeout = 15 * time.Second

// IngressConfig is separate from downstream admission; zero fields use defaults.
type IngressConfig struct {
	Global    AdmissionLimit `json:"global,omitempty"`
	Principal AdmissionLimit `json:"principal,omitempty"`
}
type ingressLimiter struct {
	principalLimit AdmissionLimit
	mu             sync.Mutex
	global         admissionBucket
	principals     map[Identity]*admissionBucket
}

func newIngressLimiter(cfg IngressConfig, identities []Identity) (*ingressLimiter, error) {
	global, err := normalizeAdmissionLimit(cfg.Global, AdmissionLimit{128, 320, 512})
	if err != nil {
		return nil, err
	}
	principal, err := normalizeAdmissionLimit(cfg.Principal, AdmissionLimit{16, 40, 64})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	l := &ingressLimiter{principalLimit: principal, global: admissionBucket{limit: global, tokens: float64(global.Burst), last: now}, principals: make(map[Identity]*admissionBucket, len(identities))}
	for _, id := range identities {
		l.principals[id] = &admissionBucket{limit: principal, tokens: float64(principal.Burst), last: now}
	}
	return l, nil
}

// addIdentity 只接受已提交的 managed 身份或已认证的恢复记录，由 limiter 锁保护。
// 仅补缺失桶，不重置旧桶的速率余额及在途计数；入口请求本身不创建身份桶。
func (l *ingressLimiter) addIdentity(id Identity) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.principals[id] == nil {
		l.principals[id] = &admissionBucket{limit: l.principalLimit, tokens: float64(l.principalLimit.Burst), last: time.Now()}
	}
}
func (l *ingressLimiter) principalBucket(id Identity) *admissionBucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.principals[id]
}

// acquire 仅结算一个入口桶；与出站多桶原子准入不同，全局与身份桶分步扣费。
// 返回的释放函数可重复调用，只归还并发槽，不返还已消耗的速率令牌。
func (l *ingressLimiter) acquire(b *admissionBucket) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b == nil {
		return nil, false
	}
	now := time.Now()
	if now.After(b.last) {
		b.tokens = math.Min(float64(b.limit.Burst), b.tokens+now.Sub(b.last).Seconds()*b.limit.RatePerSecond)
		b.last = now
	}
	if b.active >= b.limit.MaxConcurrent || b.tokens < 1 {
		return nil, false
	}
	b.active++
	b.tokens--
	var once sync.Once
	return func() { once.Do(func() { l.mu.Lock(); b.active--; l.mu.Unlock() }) }, true
}

type ingressContextKey struct{}
type ingressScope struct{ gateway *Gateway }

// GuardHTTP bounds shared ingress before parsing or route authentication. The
// identity check here selects a bucket only; routes MUST reauthenticate. A global
// attempt remains charged if the principal bucket refuses it. There is no queue.
// Host servers must bound raw headers and read time, including when the writer
// does not support ResponseController deadlines. No read goroutine is spawned.
func (g *Gateway) GuardHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 同一网关的路由可再次包装 GuardHTTP，但一个请求只能计费一次。
		// 标记携带网关指针，不能替另一个网关实例跳过入口保护。
		if scope, ok := r.Context().Value(ingressContextKey{}).(*ingressScope); ok && scope.gateway == g {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		// Keep the deadline through net/http finishRequest: it may drain an
		// unread rejected body after this handler returns. The host resets the
		// deadline for the next request/stream. Never clear its finite budget.
		deadline := time.Now().Add(IngressReadTimeout)
		if earlier, ok := r.Context().Deadline(); ok && earlier.Before(deadline) {
			deadline = earlier
		}
		_ = controller.SetReadDeadline(deadline)
		release, ok := g.ingress.acquire(&g.ingress.global)
		if !ok {
			g.rejections.record(RejectionIngressGlobal)
			http.Error(w, "request capacity exceeded", http.StatusTooManyRequests)
			return
		}
		defer release()
		size := len(r.Host) + len(r.RequestURI)
		for key, values := range r.Header {
			size += len(key)
			for _, value := range values {
				size += len(value) + 4
			}
			if size > IngressMaxHeaderBytes {
				break
			}
		}
		if size > IngressMaxHeaderBytes {
			g.rejections.record(RejectionRequest)
			http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		// 未认证请求只计入全局桶，不按任意输入创建桶；真正的认证由路由执行。
		if identity, valid := g.authenticateEntry(r); valid {
			releasePrincipal, admitted := g.ingress.acquire(g.ingress.principalBucket(identity))
			if !admitted {
				g.rejections.record(RejectionIngressPrincipal)
				http.Error(w, "request capacity exceeded", http.StatusTooManyRequests)
				return
			}
			defer releasePrincipal()
		}

		r = r.WithContext(context.WithValue(r.Context(), ingressContextKey{}, &ingressScope{g}))
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		observer := &rejectionWriter{ResponseWriter: w, summary: &g.rejections}
		var wrapped http.ResponseWriter = observer
		// 仅在底层支持时暴露 Flusher，既保留流式响应能力，也不伪造可选接口。
		if _, ok := w.(http.Flusher); ok {
			wrapped = &flushingRejectionWriter{observer}
		}
		next.ServeHTTP(wrapped, r)
	})
}

type rejectionWriter struct {
	http.ResponseWriter
	summary *rejectionSummary
	wrote   bool
}

func (w *rejectionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader 只统计第一个最终响应；1xx 不是最终结果，重复写头不重复计数。
func (w *rejectionWriter) WriteHeader(status int) {
	if !w.wrote && status >= 200 {
		w.wrote = true
		switch {
		case status == 401:
			w.summary.record(RejectionAuthentication)
		case status == 403:
			w.summary.record(RejectionAuthorization)
		case status >= 400 && status < 500:
			w.summary.record(RejectionRequest)
		case status >= 500:
			w.summary.record(RejectionHTTPUnavailable)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *rejectionWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

type flushingRejectionWriter struct{ *rejectionWriter }

func (w *flushingRejectionWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	w.ResponseWriter.(http.Flusher).Flush()
}
