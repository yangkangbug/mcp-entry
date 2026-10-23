package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

type discoveryKey struct{ user, system string }

// entryRevision 保存 HTTP 认证时捕获的入口代次；后续读写及最终准入须重新核对，
// 防止解析请求期间发生 token 轮换/撤销后仍沿用旧认证。无此上下文的可信
// 进程内调用仍遵守原有权限契约，不能由外部请求自行选择该路径。
type entryRevisionKey struct{}
type entryRevision struct {
	Identity   Identity
	Generation uint64
}

func withEntryRevision(ctx context.Context, identity Identity, generation uint64) context.Context {
	return context.WithValue(ctx, entryRevisionKey{}, entryRevision{identity, generation})
}
func (g *Gateway) entryRevisionAllowedLocked(ctx context.Context, id string) bool {
	revision, ok := ctx.Value(entryRevisionKey{}).(entryRevision)
	if !ok {
		return true
	}
	p := g.principals[id]
	return p != nil && p.identity == revision.Identity && p.entry.Generation == revision.Generation && g.principalUsableLocked(id)
}

func bindingUsable(b *bindingRecord) bool {
	return b.info.State == BindingActive && b.credential != "" && (b.info.ExpiresAt.IsZero() || time.Now().Before(b.info.ExpiresAt))
}

// principalUsableLocked 是在线可用性检查：维护实例、关闭、禁用、入口撤销
// 或到期均拒绝。它不检查某个下游绑定和工具许可。
func (g *Gateway) principalUsableLocked(id string) bool {
	p := g.principals[id]
	if g.closed || g.maintenance || p == nil || p.disabled || p.entry.Revoked {
		return false
	}
	expiry := g.users[id].TokenExpiresAt
	return expiry.IsZero() || time.Now().Before(expiry)
}

// authenticateEntry 每次从当前摘要表验证 bearer 并检查身份可用性；
// 不把会话 ID、请求中的用户字段或先前认证结果当作后续请求的凭据。
func (g *Gateway) authenticateEntry(r *http.Request) (Identity, bool) {
	if len(r.Header.Values("Authorization")) != 1 {
		return Identity{}, false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return Identity{}, false
	}
	digest := entryTokenDigest(strings.TrimPrefix(auth, "Bearer "))
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, expected := range g.entryTokens {
		if subtle.ConstantTimeCompare(digest[:], expected[:]) == 1 && g.principalUsableLocked(id) {
			return g.principals[id].identity, true
		}
	}
	return Identity{}, false
}
func (g *Gateway) validateAccountAuth() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.users) == 0 {
		return ErrDenied
	}
	for id, user := range g.users {
		if g.principals[id].entry.Revoked {
			continue
		}
		if !g.entryStrong[id] || user.TokenExpiresAt.IsZero() {
			return errors.New("account access requires strong finite entry credentials")
		}
	}
	return nil
}

// AccountBindings exposes only this configured identity's binding metadata.
// Identity 仍须由调用方从已认证请求取得；本方法检查可用性但不证明来访者身份。
func (g *Gateway) AccountBindings(identity Identity) ([]BindingInfo, error) {
	return g.accountBindings(context.Background(), identity)
}
func (g *Gateway) accountBindings(ctx context.Context, identity Identity) ([]BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return nil, err
	}
	if !g.principalUsableLocked(id) || !g.entryRevisionAllowedLocked(ctx, id) {
		return nil, ErrDenied
	}
	result := []BindingInfo{}
	for _, name := range sortedBindingNames(p.bindings) {
		result = append(result, p.bindings[name].info)
	}
	return result, nil
}
func discoveryFailure(id, system, reason string, err error) []DiscoveryIssue {
	issue := DiscoveryIssue{User: id, System: system, Reason: reason}
	var failure *DownstreamFailure
	if errors.As(err, &failure) {
		copy := *failure
		issue.Failure = &copy
	}
	return []DiscoveryIssue{issue}
}

// RefreshBinding has no global discovery queue. Concurrent discovery of the same
// binding supersedes and cancels the older attempt; only the latest may publish.
func (g *Gateway) RefreshBinding(ctx context.Context, identity Identity, system string) []DiscoveryIssue {
	g.mu.Lock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		g.mu.Unlock()
		return discoveryFailure("", system, "identity unavailable", nil)
	}
	b, exists := p.bindings[system]
	if !exists {
		g.mu.Unlock()
		return discoveryFailure(id, system, "system unavailable", nil)
	}
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		return discoveryFailure(id, system, "discovery canceled", classifyDownstreamFailure(ctx, FailureDiscovery, err, false))
	}
	if !g.entryRevisionAllowedLocked(ctx, id) {
		g.mu.Unlock()
		return discoveryFailure(id, system, "entry revision unavailable", ErrDenied)
	}
	if !g.principalUsableLocked(id) {
		g.invalidateLocked(id, system)
		g.mu.Unlock()
		return nil
	}
	allowed := make(map[string]bool)
	for _, name := range p.allowed {
		if strings.HasPrefix(name, system+"__") {
			allowed[name] = true
		}
	}
	if len(allowed) == 0 {
		g.invalidateLocked(id, system)
		g.mu.Unlock()
		return nil
	}
	if !bindingUsable(b) {
		g.invalidateLocked(id, system)
		g.mu.Unlock()
		return discoveryFailure(id, system, "credential unavailable", nil)
	}
	permit, err := g.limiter.acquire(ctx, p.identity, system)
	if err != nil {
		g.rejectAdmission(ctx, err)
		g.mu.Unlock()
		return discoveryFailure(id, system, "discovery admission limited", err)
	}
	started := time.Now()
	event, err := g.startAuditLocked(id, system, "", AuditActionDiscovery)
	if err != nil {
		permit.Release()
		g.mu.Unlock()
		return discoveryFailure(id, system, "audit unavailable", err)
	}
	// 抓取同一锁内的授权版本与凭据供本次发现使用，锁外网络结果不能直接发布。
	generation, version, token := b.info.Generation, p.version, b.credential
	entryGeneration := p.entry.Generation
	key := discoveryKey{id, system}
	if previous, ok := g.operations[g.discoveryEpoch[key]]; ok {
		previous.cancel()
	}
	opCtx, cancel := context.WithCancel(ctx)
	g.nextOperation++
	opID := g.nextOperation
	g.discoveryEpoch[key] = opID
	g.operations[opID] = admittedOperation{id, system, cancel}
	g.operationWG.Add(1)
	connection := g.systems[system]
	g.mu.Unlock()
	entries, err := g.discover(opCtx, connection, token, allowed)
	g.finishOperation(opID, event, started, err, false, permit)
	g.mu.Lock()
	defer g.mu.Unlock()
	cancel()
	p = g.principals[id]
	b = p.bindings[system]
	// 即使取消未能阻止旧网络请求返回，epoch、入口/绑定/策略及运行服务版本
	// 比较也会阻止旧发现覆盖新状态；服务同名不代表仍是同一运行配置。
	if g.discoveryEpoch[key] != opID || g.closed || g.systems[system].revision != connection.revision || p.entry.Generation != entryGeneration || b.info.Generation != generation || p.version != version {
		return discoveryFailure(id, system, "discovery superseded", nil)
	}
	// Replace only this system, preserving unrelated identities and connections.
	old := g.state.Load()
	catalog := map[string]entry{}
	for name, e := range old.catalogs[id] {
		if e.system.Name != system {
			catalog[name] = e
		}
	}
	// 发现失败时只保留其他系统的目录，不回退到本系统旧工具；成功时还需
	// 逐条检查当前到期/禁用状态，不能仅凭发现开始时的授权快照发布。
	if err == nil {
		for name, e := range entries {
			e.generation, e.policyVersion = generation, version
			if g.entryAllowedLocked(id, name, e) {
				catalog[name] = e
			}
		}
	}
	next := &snapshot{catalogs: map[string]map[string]entry{}, handlers: map[string]http.Handler{}}
	for user, cat := range old.catalogs {
		next.catalogs[user] = cat
	}
	for user, handler := range old.handlers {
		next.handlers[user] = handler
	}
	next.catalogs[id] = catalog
	next.handlers[id] = g.toolHandler(id, catalog)
	g.state.Store(next)
	if err != nil {
		return discoveryFailure(id, system, "discovery failed; system catalog unavailable", err)
	}
	return nil
}

func validExpiryDate(t time.Time) bool { return t.IsZero() || (t.Year() >= 1 && t.Year() <= 9999) }

// ValidateTestEntryAuth checks format and finite expiry, not entropy or production
// readiness. At least one currently usable configured identity must remain.
func (g *Gateway) ValidateTestEntryAuth() error {
	if err := g.validateAccountAuth(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range g.users {
		if g.principalUsableLocked(id) {
			return nil
		}
	}
	return errors.New("remote test requires an unexpired active entry identity")
}
