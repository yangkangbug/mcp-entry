package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var errDestructiveConfig = errors.New("unsupported destructive configuration change")
var errInvalidRuntimeConfig = errors.New("invalid runtime configuration")

// runtimeManifest 是 v4 状态的认证扩展；原始 seed 拓扑仍是部署锚点及审计密钥
// AAD，不随运行注册表变化。扩展存在时切换状态 MAC 域，即使只改超时且没有
// 身份记录，删除 manifest 或交给旧读取器也必须拒绝启动，而非退回 seed。
type runtimeManifest struct {
	Format   int      `json:"format"`
	Revision uint64   `json:"revision"`
	Systems  []System `json:"systems"`
}

// revision 限于 JSON/浏览器整数可精确表达的范围，避免前端 CAS 精度丢失。
const maxConfigRevision = uint64(1<<53 - 1)

const runtimeConfigSchema = `CREATE TABLE IF NOT EXISTS runtime_config(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=1),revision INTEGER NOT NULL CHECK(revision>=1),systems_json TEXT NOT NULL)`

func sortedSystems(systems map[string]System) []System {
	result := make([]System, 0, len(systems))
	for _, s := range systems {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// systemDigest 要求传入已排序的规范系统列表；摘要仅标识内容，不替代状态 MAC。
func systemDigest(systems []System) string {
	data, _ := json.Marshal(systems)
	digest := sha256.Sum256(append([]byte("mcp-entry/runtime-systems/v1\x00"), data...))
	return hex.EncodeToString(digest[:])
}
func (s *sqliteStore) runtimeStateEncoding(legacy []byte) []byte {
	if s.runtimeConfig == nil {
		return legacy
	}
	data, _ := json.Marshal(struct {
		Legacy  json.RawMessage
		Runtime *runtimeManifest
	}{legacy, s.runtimeConfig})
	return append([]byte("mcp-entry/runtime-config-state/v1\x00"), data...)
}

// loadRuntimeConfig 在整库 MAC 验证前只检查结构和规范编码，供后续记录校验使用。
// 此时不得编译 transport；认证失败时不能返回网关，也不能回退到启动配置。
func (s *sqliteStore) loadRuntimeConfig(ctx context.Context, g *Gateway) error {
	var count int
	if err := s.conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name='runtime_config'").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if count != 1 || s.version != 4 {
		return ErrStorage
	}
	var format int
	var revision int64
	var data string
	if err := s.conn.QueryRowContext(ctx, "SELECT count(*) FROM runtime_config").Scan(&count); err != nil || count != 1 {
		return ErrStorage
	}
	if err := s.conn.QueryRowContext(ctx, "SELECT format,revision,systems_json FROM runtime_config WHERE id=1").Scan(&format, &revision, &data); err != nil || format != 1 || revision < 1 || uint64(revision) > maxConfigRevision || len(data) > 256<<10 {
		return ErrStorage
	}
	var systems []System
	decoder := json.NewDecoder(bytes.NewBufferString(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&systems); err != nil || systems == nil || len(systems) > 16 {
		return ErrStorage
	}
	canonical, _ := json.Marshal(systems)
	if !bytes.Equal(canonical, []byte(data)) {
		return ErrStorage
	}
	candidate := map[string]System{}
	previous := ""
	for _, system := range systems {
		if !validPart(system.Name) || len(system.Name) > 64 || system.Name <= previous {
			return ErrStorage
		}
		candidate[system.Name] = system
		previous = system.Name
	}
	s.runtimeConfig = &runtimeManifest{format, uint64(revision), systems}
	g.systems = candidate
	return nil
}

// restoreRuntimeSystems 只能在整体状态 MAC 通过后调用，复用 New 的完整配置校验
// 并重建运行传输；启动不恢复发现目录，所有服务仍须重新发现。
func (s *sqliteStore) restoreRuntimeSystems(g *Gateway) error {
	if s.runtimeConfig == nil {
		return nil
	}
	candidate, err := New(Config{Systems: s.runtimeConfig.Systems, Users: map[string]User{}})
	if err != nil {
		return ErrStorage
	}
	defer candidate.Close()
	for name, system := range candidate.systems {
		system.revision = s.runtimeConfig.Revision
		candidate.systems[name] = system
		g.limiter.addSystem(name, system.QuotaSubject)
	}
	g.systems = candidate.systems
	return nil
}
func (g *Gateway) configRevisionLocked() uint64 {
	if g.store != nil && g.store.runtimeConfig != nil {
		return g.store.runtimeConfig.Revision
	}
	return 0
}

// runtimeCandidateLocked 在 g.mu 内做 revision CAS，并只允许新增服务或修改超时。
// 已有端点、认证、网络策略及配额主体均不可偷换；未变服务保留原 revision 与传输。
func (g *Gateway) runtimeCandidateLocked(expected uint64, systems []System) (*runtimeManifest, map[string]System, []string, []string, error) {
	if g.closed || g.auditFault {
		return nil, nil, nil, nil, ErrStorage
	}
	if g.store == nil || g.maintenance {
		return nil, nil, nil, nil, ErrDenied
	}
	if expected != g.configRevisionLocked() || expected >= maxConfigRevision {
		return nil, nil, nil, nil, ErrConflict
	}
	candidate, err := New(Config{Systems: systems, Users: map[string]User{}})
	if err != nil {
		return nil, nil, nil, nil, errInvalidRuntimeConfig
	}
	defer candidate.Close()
	added, updated := []string{}, []string{}
	for name, old := range g.systems {
		next, ok := candidate.systems[name]
		if !ok {
			return nil, nil, nil, nil, errDestructiveConfig
		}
		a, b := old, next
		a.Timeouts = nil
		b.Timeouts = nil
		aj, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		if !bytes.Equal(aj, bj) {
			return nil, nil, nil, nil, errDestructiveConfig
		}
		aj, _ = json.Marshal(old.Timeouts)
		bj, _ = json.Marshal(next.Timeouts)
		if !bytes.Equal(aj, bj) {
			updated = append(updated, name)
			next.revision = expected + 1
		} else {
			next = old
		}
		candidate.systems[name] = next
	}
	for name, next := range candidate.systems {
		if _, ok := g.systems[name]; !ok {
			added = append(added, name)
			next.revision = expected + 1
			candidate.systems[name] = next
		}
	}
	sort.Strings(added)
	sort.Strings(updated)
	if len(added)+len(updated) == 0 {
		return nil, nil, nil, nil, ErrConflict
	}
	manifest := &runtimeManifest{1, expected + 1, sortedSystems(candidate.systems)}
	data, _ := json.Marshal(manifest.Systems)
	if len(data) > 256<<10 {
		return nil, nil, nil, nil, errInvalidRuntimeConfig
	}
	return manifest, candidate.systems, added, updated, nil
}

// applyRuntimeConfigLocked 要求持有 g.mu，将注册表、新绑定、审计检查点和状态 MAC
// 一起提交后再发布内存。与最终业务准入共锁，确保配置切换具有明确的先后边界。
func (g *Gateway) applyRuntimeConfigLocked(manifest *runtimeManifest, systems map[string]System, added, updated []string) error {
	if !g.auditRoomLocked(1) {
		return ErrAuditFull
	}
	s := g.store
	candidate := *s
	candidate.runtimeConfig = manifest
	candidate.records = make(map[string]storedPrincipal, len(s.records))
	// 深复制身份再补新增服务的绑定，不写共享旧状态；禁用身份的新增绑定仍为撤销。
	principals := make(map[string]*principalState, len(g.principals))
	for id, p := range g.principals {
		next := clonePrincipal(p)
		for _, name := range added {
			state := BindingUnbound
			if p.disabled {
				state = BindingRevoked
			}
			next.bindings[name] = &bindingRecord{info: BindingInfo{ID: "service-" + rand.Text(), Tenant: p.identity.Tenant, Principal: p.identity.Principal, System: name, Generation: 1, State: state}}
		}
		r, err := candidate.record(g, id, next)
		if err != nil {
			return ErrStorage
		}
		candidate.records[id] = r
		principals[id] = next
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) && !g.closed {
			g.auditFailureLocked()
		}
	}()
	if _, err = tx.ExecContext(ctx, runtimeConfigSchema); err != nil {
		return ErrStorage
	}
	data, _ := json.Marshal(manifest.Systems)
	if _, err = tx.ExecContext(ctx, "INSERT INTO runtime_config(id,format,revision,systems_json) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET format=excluded.format,revision=excluded.revision,systems_json=excluded.systems_json", manifest.Format, manifest.Revision, string(data)); err != nil {
		return ErrStorage
	}
	for _, r := range candidate.records {
		if err = writePrincipal(ctx, tx, r, false); err != nil {
			return ErrStorage
		}
	}
	event := g.maintenanceAuditEvent(AuditActionConfigApply)
	sequence, head, err := candidate.writeAudit(ctx, tx, event)
	if err != nil {
		return ErrStorage
	}
	if err = candidate.updateAuditManifest(ctx, tx, candidate.records, sequence, head); err != nil {
		return ErrStorage
	}
	// Commit 报错不能证明数据库未落盘；关闭网关，重启时以认证后的持久状态为准。
	if err = tx.Commit(); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	candidate.auditSequence, candidate.auditHead = sequence, head
	*s = candidate
	event.Sequence = sequence
	if err = g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	g.systems = systems
	g.principals = principals
	// 原位扩展桶，保留旧配额与在途 permit；超时变更则使旧目录失效并尽力取消。
	for _, name := range added {
		g.limiter.addSystem(name, systems[name].QuotaSubject)
	}
	for _, name := range updated {
		for id := range principals {
			g.invalidateLocked(id, name)
			g.cancelOperationsLocked(id, name)
		}
	}
	return nil
}

// runtimeServiceRevision 将 SDK handler 捕获的服务版本带到最终准入。
// 即使重新发现后工具同名，旧 handler 也不能借新目录跨越配置版本执行。
type runtimeServiceRevisionKey struct{}
type runtimeServiceRevision struct {
	Name     string
	Revision uint64
}

func runtimeServiceRevisionAllowed(ctx context.Context, system System) bool {
	expected, ok := ctx.Value(runtimeServiceRevisionKey{}).(runtimeServiceRevision)
	return !ok || (expected.Name == system.Name && expected.Revision == system.revision)
}
