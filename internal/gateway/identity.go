package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var ErrConflict = errors.New("state version conflict")

// Identity is a synthetic, server-configured scope, not an authentication proof.
type Identity struct {
	Tenant    string
	Principal string
}
type BindingState string

const (
	BindingUnbound BindingState = "unbound"
	BindingActive  BindingState = "active"
	BindingRevoked BindingState = "revoked"
)

type BindingInfo struct {
	ID         string
	Tenant     string
	Principal  string
	System     string
	Generation uint64
	ExpiresAt  time.Time `json:",omitzero"`
	State      BindingState
}
type PolicyInfo struct {
	Version  uint64
	Allowed  []string
	Disabled bool
}
type bindingRecord struct {
	info       BindingInfo
	credential string
}
type principalState struct {
	identity Identity
	version  uint64
	allowed  []string
	disabled bool
	bindings map[string]*bindingRecord
}
type admittedOperation struct {
	user, system string
	cancel       context.CancelFunc
}

func (g *Gateway) initializeIdentities() error {
	g.principals = map[string]*principalState{}
	g.identities = map[Identity]string{}
	g.operations = map[uint64]admittedOperation{}
	for id, user := range g.users {
		identity := Identity{user.Tenant, user.Principal}
		if identity.Tenant == "" {
			identity.Tenant = "demo"
		}
		if identity.Principal == "" {
			identity.Principal = id
		}
		if len(identity.Tenant) > 128 || len(identity.Principal) > 128 {
			return errors.New("invalid identity scope")
		}
		if _, exists := g.identities[identity]; exists {
			return errors.New("duplicate identity scope")
		}
		p := &principalState{identity: identity, version: 1, allowed: append([]string(nil), user.Allowed...), bindings: map[string]*bindingRecord{}}
		for name := range g.systems {
			state := BindingUnbound
			if user.Credentials[name] != "" {
				state = BindingActive
			}
			p.bindings[name] = &bindingRecord{info: BindingInfo{ID: fmt.Sprintf("binding-%d", len(g.identities)*len(g.systems)+len(p.bindings)+1), Tenant: identity.Tenant, Principal: identity.Principal, System: name, Generation: 1, State: state}, credential: user.Credentials[name]}
		}
		g.identities[identity] = id
		g.principals[id] = p
		user.Tenant, user.Principal = identity.Tenant, identity.Principal
		user.Allowed, user.Credentials = nil, nil
		g.users[id] = user
	}
	return nil
}
func (g *Gateway) principalLocked(identity Identity) (string, *principalState, error) {
	if g.closed {
		return "", nil, ErrClosed
	}
	id, ok := g.identities[identity]
	if !ok {
		return "", nil, ErrDenied
	}
	return id, g.principals[id], nil
}
func policyInfo(p *principalState) PolicyInfo {
	return PolicyInfo{Version: p.version, Allowed: append([]string(nil), p.allowed...), Disabled: p.disabled}
}

// Policy and all mutation methods are trusted in-process administration only.
// Their Identity argument does not authenticate or authorize an external caller.
func (g *Gateway) Policy(identity Identity) (PolicyInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, p, err := g.principalLocked(identity)
	if err != nil {
		return PolicyInfo{}, err
	}
	return policyInfo(p), nil
}
func (g *Gateway) Binding(identity Identity, system string) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	b, ok := p.bindings[system]
	if !ok {
		return BindingInfo{}, ErrDenied
	}
	return b.info, nil
}
func (g *Gateway) ReplaceBinding(identity Identity, system string, expected uint64, credential string) (BindingInfo, error) {
	return g.ReplaceBindingExpiring(identity, system, expected, credential, time.Time{})
}
func (g *Gateway) ReplaceBindingExpiring(identity Identity, system string, expected uint64, credential string, expiresAt time.Time) (BindingInfo, error) {
	return g.replaceBinding(identity, system, expected, credential, expiresAt, false)
}
func (g *Gateway) replaceOwnBinding(identity Identity, system string, expected uint64, credential string, expiresAt time.Time) (BindingInfo, error) {
	return g.replaceBinding(identity, system, expected, credential, expiresAt, true)
}
func (g *Gateway) replaceBinding(identity Identity, system string, expected uint64, credential string, expiresAt time.Time, own bool) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	b, ok := p.bindings[system]
	if !ok || p.disabled || (own && !g.principalUsableLocked(id)) {
		return BindingInfo{}, ErrDenied
	}
	if b.info.Generation != expected {
		return BindingInfo{}, ErrConflict
	}
	if credential == "" || !validCredential(credential, g.systems[system].Auth) || !validExpiryDate(expiresAt.UTC()) || (!expiresAt.IsZero() && !time.Now().Before(expiresAt)) {
		return BindingInfo{}, errors.New("invalid binding credential")
	}
	p = clonePrincipal(p)
	b = p.bindings[system]
	b.info.Generation++
	b.info.State = BindingActive
	b.info.ExpiresAt = expiresAt.UTC()
	b.credential = credential
	if err := g.publishPrincipalLocked(id, p, system); err != nil {
		return BindingInfo{}, err
	}
	return b.info, nil
}
func (g *Gateway) RevokeBinding(identity Identity, system string, expected uint64) (BindingInfo, error) {
	return g.revokeBinding(identity, system, expected, false)
}
func (g *Gateway) revokeOwnBinding(identity Identity, system string, expected uint64) (BindingInfo, error) {
	return g.revokeBinding(identity, system, expected, true)
}
func (g *Gateway) revokeBinding(identity Identity, system string, expected uint64, own bool) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	b, ok := p.bindings[system]
	if !ok || (own && !g.principalUsableLocked(id)) {
		return BindingInfo{}, ErrDenied
	}
	if b.info.Generation != expected {
		return BindingInfo{}, ErrConflict
	}
	p = clonePrincipal(p)
	b = p.bindings[system]
	b.info.Generation++
	b.info.State = BindingRevoked
	b.credential = ""
	if err := g.publishPrincipalLocked(id, p, system); err != nil {
		return BindingInfo{}, err
	}
	return b.info, nil
}
func (g *Gateway) SetPolicy(identity Identity, expected uint64, allowed []string) (PolicyInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return PolicyInfo{}, err
	}
	if p.disabled {
		return PolicyInfo{}, ErrDenied
	}
	if p.version != expected {
		return PolicyInfo{}, ErrConflict
	}
	if len(allowed) > 2048 {
		return PolicyInfo{}, errors.New("too many policy tools")
	}
	for _, name := range allowed {
		if !validNamespaced(name, g.systems) {
			return PolicyInfo{}, errors.New("invalid policy tool")
		}
	}
	p = clonePrincipal(p)
	p.version++
	p.allowed = append([]string(nil), allowed...)
	if err := g.publishPrincipalLocked(id, p, ""); err != nil {
		return PolicyInfo{}, err
	}
	return policyInfo(p), nil
}
func (g *Gateway) DisablePrincipal(identity Identity, expected uint64) (PolicyInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return PolicyInfo{}, err
	}
	if p.version != expected {
		return PolicyInfo{}, ErrConflict
	}
	p = clonePrincipal(p)
	p.version++
	p.disabled = true
	for _, b := range p.bindings {
		b.info.Generation++
		b.info.State = BindingRevoked
		b.credential = ""
	}
	if err := g.publishPrincipalLocked(id, p, ""); err != nil {
		return PolicyInfo{}, err
	}
	return policyInfo(p), nil
}
func (g *Gateway) cancelOperationsLocked(id, system string) {
	for _, op := range g.operations {
		if op.user == id && (system == "" || op.system == system) {
			op.cancel()
		}
	}
}
func (g *Gateway) allowedLocked(id, name string) bool {
	p := g.principals[id]
	if p == nil || !g.principalUsableLocked(id) {
		return false
	}
	for _, n := range p.allowed {
		if n == name {
			return true
		}
	}
	return false
}
func (g *Gateway) entryAllowedLocked(id, name string, e entry) bool {
	if !g.allowedLocked(id, name) {
		return false
	}
	p := g.principals[id]
	b := p.bindings[e.system.Name]
	return b != nil && bindingUsable(b) && b.info.Generation == e.generation && p.version == e.policyVersion
}
func (g *Gateway) evaluateLocked(id, name string) (entry, bool) {
	e, exists := g.state.Load().catalogs[id][name]
	return e, exists && g.entryAllowedLocked(id, name, e)
}
func (g *Gateway) invalidateLocked(id, system string) {
	old := g.state.Load()
	next := &snapshot{catalogs: map[string]map[string]entry{}, handlers: map[string]http.Handler{}}
	for user, cat := range old.catalogs {
		next.catalogs[user] = cat
	}
	for user, handler := range old.handlers {
		next.handlers[user] = handler
	}
	kept := map[string]entry{}
	for name, e := range old.catalogs[id] {
		if system != "" && e.system.Name != system {
			kept[name] = e
		}
	}
	next.catalogs[id] = kept
	next.handlers[id] = g.toolHandler(id, kept)
	g.state.Store(next)
}
