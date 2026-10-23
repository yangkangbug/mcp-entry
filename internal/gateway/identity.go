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

// BindingInfo 是不含凭据的绑定元数据；Generation 用于乐观并发控制及目录失效。
// State 为 active 不等于此刻可用，调用方还须考虑到期、身份状态和工具策略。
type BindingInfo struct {
	ID         string
	Tenant     string
	Principal  string
	System     string
	Generation uint64
	ExpiresAt  time.Time `json:",omitzero"`
	State      BindingState
}

// PolicyInfo 返回策略版本及显式许可列表；许可不保证下游已发现或当前可用。
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
	entry    EntryInfo
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
		p := &principalState{entry: EntryInfo{Generation: 1, ExpiresAt: user.TokenExpiresAt}, identity: identity, version: 1, allowed: append([]string(nil), user.Allowed...), bindings: map[string]*bindingRecord{}}
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

// principalLocked 要求持有 g.mu，只查身份是否存在及网关是否关闭。
// 禁用、到期和调用权限检查由具体操作完成，不能把查找成功当作授权。
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

// Binding 返回可信调用方指定身份/系统的元数据，包括已撤销或已禁用身份的状态。
// 此读取不返回凭据，也不认证传入的 Identity。
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

// ReplaceBinding 以当前绑定代次为前提替换凭据，且不设置到期时间。
// 成功会使相关目录失效，不授予工具权限，也不自动重新发现下游。
func (g *Gateway) ReplaceBinding(identity Identity, system string, expected uint64, credential string) (BindingInfo, error) {
	return g.ReplaceBindingExpiring(identity, system, expected, credential, time.Time{})
}

// ReplaceBindingExpiring 与 ReplaceBinding 相同，但允许指定未来到期时间；零值表示无到期。
// 这是可信管理入口；外部本人绑定入口还需执行身份可用性和请求认证检查。
func (g *Gateway) ReplaceBindingExpiring(identity Identity, system string, expected uint64, credential string, expiresAt time.Time) (BindingInfo, error) {
	return g.replaceBinding(identity, system, expected, credential, expiresAt, false)
}
func (g *Gateway) replaceOwnBinding(identity Identity, system string, expected uint64, credential string, expiresAt time.Time) (BindingInfo, error) {
	return g.replaceBinding(identity, system, expected, credential, expiresAt, true)
}

// replaceBinding 在同一锁内核对入口认证代次和绑定 CAS；HTTP 自助入口传入
// entryGeneration，可信进程内管理调用可省略，不能把可选参数当作外部免认证开关。
func (g *Gateway) replaceBinding(identity Identity, system string, expected uint64, credential string, expiresAt time.Time, own bool, entryGeneration ...uint64) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	b, ok := p.bindings[system]
	if !ok || p.disabled || (own && !g.principalUsableLocked(id)) || (len(entryGeneration) > 0 && p.entry.Generation != entryGeneration[0]) {
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
	if err := g.publishPrincipalLocked(id, p, system, AuditActionBindingReplace, own); err != nil {
		return BindingInfo{}, err
	}
	return b.info, nil
}

// RevokeBinding 检查 expected 代次后递增代次、撤销绑定并清空内存凭据。
// 取消在途操作是尽力而为，不表示下游已执行的效果能够回滚。
func (g *Gateway) RevokeBinding(identity Identity, system string, expected uint64) (BindingInfo, error) {
	return g.revokeBinding(identity, system, expected, false)
}
func (g *Gateway) revokeOwnBinding(identity Identity, system string, expected uint64) (BindingInfo, error) {
	return g.revokeBinding(identity, system, expected, true)
}

// revokeBinding 与替换使用相同入口代次约束，防止旧 token 已认证的请求在轮换后撤销绑定。
func (g *Gateway) revokeBinding(identity Identity, system string, expected uint64, own bool, entryGeneration ...uint64) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	b, ok := p.bindings[system]
	if !ok || (own && !g.principalUsableLocked(id)) || (len(entryGeneration) > 0 && p.entry.Generation != entryGeneration[0]) {
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
	if err := g.publishPrincipalLocked(id, p, system, AuditActionBindingRevoke, own); err != nil {
		return BindingInfo{}, err
	}
	return b.info, nil
}

// SetPolicy 按 expected 策略版本整体替换显式白名单，不能恢复已禁用身份。
// 成功会清空该身份目录并取消其在途操作；新增许可仍需发现后才能调用。
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
	if err := g.publishPrincipalLocked(id, p, "", AuditActionPolicyUpdate, false); err != nil {
		return PolicyInfo{}, err
	}
	return policyInfo(p), nil
}

// DisablePrincipal 按策略版本禁用身份，同时撤销全部绑定并推进绑定代次。
// 本接口没有对应的恢复操作；替换策略或凭据不能绕过禁用状态。
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
	if err := g.publishPrincipalLocked(id, p, "", AuditActionPrincipalDisable, false); err != nil {
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

// entryAllowedLocked 不只检查工具名，还将目录条目的策略版本和绑定代次
// 与当前身份状态比较，防止旧快照或旧 SDK handler 继续使用过时授权。
func (g *Gateway) entryAllowedLocked(id, name string, e entry) bool {
	if !g.allowedLocked(id, name) {
		return false
	}
	p := g.principals[id]
	b := p.bindings[e.system.Name]
	current, exists := g.systems[e.system.Name]
	return exists && current.revision == e.system.revision && b != nil && bindingUsable(b) && b.info.Generation == e.generation && p.version == e.policyVersion
}
func (g *Gateway) evaluateLocked(id, name string) (entry, bool) {
	e, exists := g.state.Load().catalogs[id][name]
	return e, exists && g.entryAllowedLocked(id, name, e)
}

// invalidateLocked 采用复制后发布：未受影响的只读目录可共享，目标身份重建
// 目录和 handler，绝不原地改动已被并发读者持有的快照。空 system 表示全部失效。
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
