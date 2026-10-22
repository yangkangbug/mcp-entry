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

func bindingUsable(b *bindingRecord) bool {
	return b.info.State == BindingActive && b.credential != "" && (b.info.ExpiresAt.IsZero() || time.Now().Before(b.info.ExpiresAt))
}
func (g *Gateway) principalUsableLocked(id string) bool {
	p := g.principals[id]
	if g.closed || g.maintenance || p == nil || p.disabled || p.entry.Revoked {
		return false
	}
	expiry := g.users[id].TokenExpiresAt
	return expiry.IsZero() || time.Now().Before(expiry)
}
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
		if !g.entryStrong[id] || user.TokenExpiresAt.IsZero() {
			return errors.New("account access requires strong finite entry credentials")
		}
	}
	return nil
}

// AccountBindings exposes only this configured identity's binding metadata.
func (g *Gateway) AccountBindings(identity Identity) ([]BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return nil, err
	}
	if !g.principalUsableLocked(id) {
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
	generation, version, token := b.info.Generation, p.version, b.credential
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
	if g.discoveryEpoch[key] != opID || g.closed || b.info.Generation != generation || p.version != version {
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
