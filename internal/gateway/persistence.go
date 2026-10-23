package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrStorage        = errors.New("persistent state unavailable")
	ErrStorageVersion = fmt.Errorf("%w: unsupported schema version", ErrStorage)
	ErrClosed         = errors.New("gateway closed")
)

// PersistenceOptions selects an opt-in local, single-owner synthetic state store.
// Key must be externally supplied, exactly 32 bytes, and kept outside the DB.
// Initialize permits creation only when Path does not exist; it is not an upsert.
type PersistenceOptions struct {
	Path       string
	Key        []byte
	Initialize bool
	Migrate    bool
}

type storedBinding struct {
	System     string
	ID         string
	Generation uint64
	ExpiresAt  time.Time
	State      BindingState
	Credential []byte
}
type storedPrincipal struct {
	EntryGeneration           uint64
	EntryRevoked              bool
	EntryStrong               bool
	UserID, Tenant, Principal string
	TokenHash                 []byte
	TokenExpiresAt            time.Time
	Version                   uint64
	Disabled                  bool
	Allowed                   []string
	Bindings                  []storedBinding
}
type sqliteStore struct {
	runtimeConfig     *runtimeManifest
	auditBaseSequence uint64
	auditBaseHead     string
	auditArchiveHash  string
	version           int
	allowLegacy       bool
	auditKey          []byte
	auditSequence     uint64
	auditHead         string
	auditIDCipher     []byte
	db                *sql.DB
	conn              *sql.Conn
	aead              cipher.AEAD
	macKey            []byte
	topology          []byte
	records           map[string]storedPrincipal
}

// managedUserID 为在线创建身份分配独立的确定性命名空间，不改认证后的 seed 拓扑。
// ID 匹配仅是结构约束，不证明身份可信；managed 记录仍须通过完整状态 MAC。
func managedUserID(identity Identity) string {
	encoded, _ := json.Marshal(identity)
	sum := sha256.Sum256(append([]byte("mcp-entry/managed-user/v1\x00"), encoded...))
	return fmt.Sprintf("managed:%x", sum)
}

func entryTokenDigest(token string) [32]byte {
	return sha256.Sum256([]byte("mcp-entry/entry-token/v1\x00" + token))
}
func derivedKey(key []byte, purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, key, nil, "mcp-entry/persistence/v2/"+purpose, 32)
}

// NewPersistent keeps catalogs transient. Reopening never reimports policies or
// credentials, and rejects bootstrap topology changes instead of merging config.
// Authenticated managed identities are restored from the state records separately.
func NewPersistent(cfg Config, opts PersistenceOptions) (*Gateway, error) {
	if opts.Migrate {
		return nil, ErrStorageVersion
	}
	return newPersistent(cfg, opts, false)
}

// OpenMaintenance 打开既有存储供可信离线维护使用，禁止同时初始化新库。
// 仅显式 Migrate 时允许认证旧版本后升级；维护实例不提供在线业务服务。
func OpenMaintenance(cfg Config, opts PersistenceOptions) (*Gateway, error) {
	if opts.Initialize {
		return nil, ErrStorage
	}
	return newPersistent(cfg, opts, true)
}
func newPersistent(cfg Config, opts PersistenceOptions, maintenance bool) (*Gateway, error) {
	if len(opts.Key) != 32 || opts.Path == "" {
		return nil, ErrStorage
	}
	g, err := newGateway(cfg, opts.Initialize)
	if err != nil {
		return nil, err
	}
	path, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, ErrStorage
	}
	if opts.Initialize {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, ErrStorage
		}
		if err = f.Close(); err != nil {
			return nil, ErrStorage
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<20 {
		return nil, ErrStorage
	}
	// SQLite itself owns inter-process locking. An exclusive connection retains
	// its lock until Close; the file and journal must be on a supported local FS.
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "rw")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrStorage
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	success := false
	defer func() {
		if !success {
			db.Close()
		}
	}()
	credentialKey, err := derivedKey(opts.Key, "credentials")
	if err != nil {
		return nil, ErrStorage
	}
	macKey, err := derivedKey(opts.Key, "metadata")
	if err != nil {
		return nil, ErrStorage
	}
	block, err := aes.NewCipher(credentialKey)
	if err != nil {
		return nil, ErrStorage
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrStorage
	}
	// 拓扑摘要绑定系统配置及身份映射，而非可变策略/凭据；重开时拒绝悄悄
	// 更换路由或身份范围，动态状态则从存储恢复，不能被配置种子覆盖。
	identities := map[string]Identity{}
	for id, p := range g.principals {
		identities[id] = p.identity
	}
	// Runtime budgets do not alter authority or routing. Omit them entirely to
	// preserve the pre-timeouts topology bytes and authenticated existing stores.
	topologySystems := make(map[string]System, len(g.systems))
	for name, system := range g.systems {
		system.Timeouts = nil
		topologySystems[name] = system
	}
	topologyJSON, _ := json.Marshal(struct {
		Systems    map[string]System
		Identities map[string]Identity
	}{topologySystems, identities})
	topology := sha256.Sum256(topologyJSON)
	store := &sqliteStore{version: 4, allowLegacy: maintenance && opts.Migrate, db: db, aead: aead, macKey: macKey, topology: topology[:], records: map[string]storedPrincipal{}}
	auditKey, err := derivedKey(opts.Key, "audit-chain")
	if err != nil {
		return nil, ErrStorage
	}
	store.auditKey = auditKey
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	store.conn = conn
	for _, statement := range []string{"PRAGMA busy_timeout=0", "PRAGMA locking_mode=EXCLUSIVE", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return nil, ErrStorage
		}
	}
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return nil, ErrStorage
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, ErrStorage
	}
	if opts.Initialize {
		err = store.initialize(ctx, g)
	} else {
		err = store.load(ctx, g)
	}
	if err != nil {
		if errors.Is(err, ErrStorageVersion) {
			return nil, ErrStorageVersion
		}
		return nil, ErrStorage
	}
	g.store = store
	g.maintenance = maintenance
	if store.version != 4 {
		if err = g.migrateStorage(ctx); err != nil {
			return nil, ErrStorage
		}
	}
	success = true
	return g, nil
}

const persistentSchema = `
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,topology BLOB NOT NULL,key_check BLOB NOT NULL,state_mac BLOB NOT NULL,audit_sequence INTEGER NOT NULL,audit_head TEXT NOT NULL,audit_id_key BLOB NOT NULL,audit_base_sequence INTEGER NOT NULL,audit_base_head TEXT NOT NULL,audit_archive_hash TEXT NOT NULL);
CREATE TABLE audit(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,mac TEXT NOT NULL);
CREATE TABLE principals(user_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,principal TEXT NOT NULL,token_hash BLOB NOT NULL,token_expires_at TEXT NOT NULL,policy_version INTEGER NOT NULL,disabled INTEGER NOT NULL,allowed TEXT NOT NULL,entry_generation INTEGER NOT NULL,entry_revoked INTEGER NOT NULL,entry_strong INTEGER NOT NULL,UNIQUE(tenant,principal));
CREATE TABLE bindings(user_id TEXT NOT NULL REFERENCES principals(user_id),system TEXT NOT NULL,binding_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,credential BLOB NOT NULL,PRIMARY KEY(user_id,system));`

// bindingAAD 将密文与用户键和完整绑定元数据关联；挪用到另一绑定、代次或
// 状态时解密不再匹配。该编码属于持久认证格式，不能随展示需求调整。
func bindingAAD(id string, p *principalState, b *bindingRecord) []byte {
	data, _ := json.Marshal(struct {
		User    string
		Binding BindingInfo
	}{id, b.info})
	return data
}
func (s *sqliteStore) record(g *Gateway, id string, p *principalState) (storedPrincipal, error) {
	if p.version == 0 || p.version > math.MaxInt64 {
		return storedPrincipal{}, ErrStorage
	}
	token := g.entryTokens[id]
	r := storedPrincipal{EntryGeneration: p.entry.Generation, EntryRevoked: p.entry.Revoked, EntryStrong: g.entryStrong[id], UserID: id, Tenant: p.identity.Tenant, Principal: p.identity.Principal, TokenHash: append([]byte(nil), token[:]...), TokenExpiresAt: g.users[id].TokenExpiresAt, Version: p.version, Disabled: p.disabled, Allowed: append([]string(nil), p.allowed...)}
	for _, name := range sortedBindingNames(p.bindings) {
		b := p.bindings[name]
		if b.info.Generation == 0 || b.info.Generation > math.MaxInt64 {
			return r, ErrStorage
		}
		r.Bindings = append(r.Bindings, storedBinding{System: name, ID: b.info.ID, Generation: b.info.Generation, State: b.info.State, ExpiresAt: b.info.ExpiresAt, Credential: s.aead.Seal(nil, nil, []byte(b.credential), bindingAAD(id, p, b))})
	}
	return r, nil
}
func sortedBindingNames(bindings map[string]*bindingRecord) []string {
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func (s *sqliteStore) stateMAC(records map[string]storedPrincipal) []byte {
	return s.stateMACAt(records, s.auditSequence, s.auditHead)
}

// stateMACAt 先按用户键稳定排序，再认证记录和审计检查点；不能依赖 Go map
// 遍历顺序，否则同一逻辑状态重启后会得到不同的认证输入。
func (s *sqliteStore) stateMACAt(records map[string]storedPrincipal, sequence uint64, head string) []byte {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make([]storedPrincipal, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, records[id])
	}
	encoded := s.runtimeStateEncoding(s.canonicalState(ordered, sequence, head))
	m := hmac.New(sha256.New, s.macKey)
	m.Write(encoded)
	return m.Sum(nil)
}
func writePrincipal(ctx context.Context, tx *sql.Tx, r storedPrincipal, initialize bool) error {
	allowed, _ := json.Marshal(r.Allowed)
	var err error
	if initialize {
		_, err = tx.ExecContext(ctx, "INSERT INTO principals VALUES(?,?,?,?,?,?,?,?,?,?,?)", r.UserID, r.Tenant, r.Principal, r.TokenHash, expiryText(r.TokenExpiresAt), r.Version, r.Disabled, string(allowed), r.EntryGeneration, r.EntryRevoked, r.EntryStrong)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, "UPDATE principals SET policy_version=?,disabled=?,allowed=?,token_hash=?,token_expires_at=?,entry_generation=?,entry_revoked=?,entry_strong=? WHERE user_id=?", r.Version, r.Disabled, string(allowed), r.TokenHash, expiryText(r.TokenExpiresAt), r.EntryGeneration, r.EntryRevoked, r.EntryStrong, r.UserID)
		if err == nil {
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return ErrStorage
			}
		}
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM bindings WHERE user_id=?", r.UserID); err != nil {
		return err
	}
	for _, b := range r.Bindings {
		if _, err = tx.ExecContext(ctx, "INSERT INTO bindings VALUES(?,?,?,?,?,?,?)", r.UserID, b.System, b.ID, b.Generation, b.State, expiryText(b.ExpiresAt), b.Credential); err != nil {
			return err
		}
	}
	return nil
}
func (s *sqliteStore) initialize(ctx context.Context, g *Gateway) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, persistentSchema); err != nil {
		return err
	}
	for id, p := range g.principals {
		r, err := s.record(g, id, p)
		if err != nil {
			return err
		}
		s.records[id] = r
		if err = writePrincipal(ctx, tx, r, true); err != nil {
			return err
		}
	}
	s.auditIDCipher = s.aead.Seal(nil, nil, g.auditIDKey, s.auditIDAAD())
	check := s.aead.Seal(nil, nil, []byte("mcp-entry-state-v4"), s.topology)
	if _, err = tx.ExecContext(ctx, "INSERT INTO meta VALUES(1,4,?,?,?,0,?,?,0,'','')", s.topology, check, s.stateMAC(s.records), "", s.auditIDCipher); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) load(ctx context.Context, g *Gateway) error {
	var integrity string
	if err := s.conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return ErrStorage
	}
	var version int
	var topology, check, mac []byte
	if err := s.conn.QueryRowContext(ctx, "SELECT version,topology,key_check,state_mac FROM meta WHERE id=1").Scan(&version, &topology, &check, &mac); err != nil {
		return ErrStorage
	}
	if version != 4 && !(s.allowLegacy && (version == 2 || version == 3)) {
		return ErrStorageVersion
	}
	s.version = version
	if !bytes.Equal(topology, s.topology) {
		return ErrStorage
	}
	plain, err := s.aead.Open(nil, nil, check, s.topology)
	if err != nil || string(plain) != fmt.Sprintf("mcp-entry-state-v%d", version) {
		return ErrStorage
	}
	if err := s.loadRuntimeConfig(ctx, g); err != nil {
		return err
	}
	if err := s.loadLegacyOrCurrentAudit(ctx, g); err != nil {
		return err
	}
	query := "SELECT user_id,tenant,principal,token_hash,token_expires_at,policy_version,disabled,allowed"
	if s.version == 4 {
		query += ",entry_generation,entry_revoked,entry_strong"
	}
	query += " FROM principals ORDER BY user_id"
	rows, err := s.conn.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	seenIdentities := map[Identity]bool{}
	seenDigests := map[string]bool{}
	for rows.Next() {
		var r storedPrincipal
		var version int64
		var disabled int
		var allowed, expiry string
		entryGeneration, revoked, strong := int64(1), 0, 0
		dest := []any{&r.UserID, &r.Tenant, &r.Principal, &r.TokenHash, &expiry, &version, &disabled, &allowed}
		if s.version == 4 {
			dest = append(dest, &entryGeneration, &revoked, &strong)
		}
		if err = rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		r.TokenExpiresAt, err = parseExpiry(expiry)
		if err != nil {
			rows.Close()
			return ErrStorage
		}
		p, exists := g.principals[r.UserID]
		identity := Identity{r.Tenant, r.Principal}
		// 非 seed 身份只接受 v4 的 managed 命名；未签发身份必须保持撤销，
		// 已签发身份必须有有限到期时间。此处只收集候选，MAC 通过后才恢复身份。
		managed := !exists && s.version == 4 && r.UserID == managedUserID(identity)
		if (!exists && !managed) || len(s.records) >= 64 || (exists && p.identity != identity) || identity.Tenant == "" || identity.Principal == "" || len(identity.Tenant) > 128 || len(identity.Principal) > 128 || seenIdentities[identity] || seenDigests[string(r.TokenHash)] || (managed && strong == 1 && r.TokenExpiresAt.IsZero()) || (managed && strong == 0 && revoked != 1) || len(r.TokenHash) != 32 || entryGeneration < 1 || revoked < 0 || revoked > 1 || strong < 0 || strong > 1 || version < 1 || (disabled != 0 && disabled != 1) || len(allowed) > 512<<10 {
			rows.Close()
			return ErrStorage
		}
		if err = json.Unmarshal([]byte(allowed), &r.Allowed); err != nil || len(r.Allowed) > 2048 {
			rows.Close()
			return ErrStorage
		}
		for _, name := range r.Allowed {
			if !validNamespaced(name, g.systems) {
				rows.Close()
				return ErrStorage
			}
		}
		seenIdentities[identity] = true
		seenDigests[string(r.TokenHash)] = true
		r.EntryGeneration, r.EntryRevoked, r.EntryStrong = uint64(entryGeneration), revoked == 1, strong == 1
		r.Version = uint64(version)
		r.Disabled = disabled == 1
		s.records[r.UserID] = r
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrStorage
	}
	for id := range g.principals {
		if _, exists := s.records[id]; !exists {
			return ErrStorage
		}
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT user_id,system,binding_id,generation,state,expires_at,credential FROM bindings ORDER BY user_id,system")
	if err != nil {
		return err
	}
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		var b storedBinding
		var generation int64
		var expiry string
		if err = rows.Scan(&id, &b.System, &b.ID, &generation, &b.State, &expiry, &b.Credential); err != nil {
			rows.Close()
			return err
		}
		b.ExpiresAt, err = parseExpiry(expiry)
		if err != nil {
			rows.Close()
			return ErrStorage
		}
		r, exists := s.records[id]
		_, systemExists := g.systems[b.System]
		if !exists || !systemExists || len(r.Bindings) >= len(g.systems) || generation < 1 || b.ID == "" || len(b.ID) > 128 || ids[b.ID] || len(b.Credential) > 8192 || (b.State != BindingActive && b.State != BindingUnbound && b.State != BindingRevoked) {
			rows.Close()
			return ErrStorage
		}
		ids[b.ID] = true
		b.Generation = uint64(generation)
		r.Bindings = append(r.Bindings, b)
		s.records[id] = r
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !hmac.Equal(mac, s.stateMAC(s.records)) {
		return ErrStorage
	}
	// 运行服务与 managed 用户同属已认证状态，先恢复服务再解密其绑定。
	if err := s.restoreRuntimeSystems(g); err != nil {
		return err
	}
	// 行结构与整体状态 MAC 都通过后才解密凭据、重建身份；构造期间失败的
	// 网关不会返回给调用方，不能退回配置中的旧凭据继续启动。
	restored := map[string]*principalState{}
	for id, r := range s.records {
		if len(r.Bindings) != len(g.systems) {
			return ErrStorage
		}
		p := &principalState{entry: EntryInfo{Generation: r.EntryGeneration, Revoked: r.EntryRevoked, ExpiresAt: r.TokenExpiresAt}, identity: Identity{r.Tenant, r.Principal}, version: r.Version, disabled: r.Disabled, allowed: append([]string(nil), r.Allowed...), bindings: map[string]*bindingRecord{}}
		for _, sb := range r.Bindings {
			b := &bindingRecord{info: BindingInfo{ID: sb.ID, Tenant: r.Tenant, Principal: r.Principal, System: sb.System, Generation: sb.Generation, State: sb.State, ExpiresAt: sb.ExpiresAt}}
			secret, err := s.aead.Open(nil, nil, sb.Credential, bindingAAD(id, p, b))
			if err != nil {
				return ErrStorage
			}
			b.credential = string(secret)
			if (b.info.State == BindingActive) != (b.credential != "") || !validCredential(b.credential, g.systems[sb.System].Auth) || (p.disabled && b.info.State != BindingRevoked) {
				return ErrStorage
			}
			p.bindings[sb.System] = b
		}
		var digest [32]byte
		copy(digest[:], r.TokenHash)
		g.entryTokens[id] = digest
		g.entryStrong[id] = r.EntryStrong
		u := g.users[id]
		u.TokenExpiresAt = r.TokenExpiresAt
		u.Tenant, u.Principal = r.Tenant, r.Principal
		g.users[id] = u
		// 原位补注册已认证身份的入口/出站桶，不从 bootstrap 重新导入凭据或策略。
		g.identities[p.identity] = id
		g.limiter.addIdentity(p.identity)
		g.ingress.addIdentity(p.identity)
		restored[id] = p
	}
	g.principals = restored
	g.state.Store(g.makeSnapshot(map[string]map[string]entry{}))
	return nil
}
func (s *sqliteStore) persist(g *Gateway, id string, p *principalState, event AuditEvent) error {
	r, err := s.record(g, id, p)
	if err != nil {
		return err
	}
	next := make(map[string]storedPrincipal, len(s.records))
	for id, record := range s.records {
		next[id] = record
	}
	next[id] = r
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = writePrincipal(ctx, tx, r, false); err != nil {
		return err
	}
	sequence, head, err := s.writeAudit(ctx, tx, event)
	if err != nil {
		return err
	}
	if err = s.updateAuditManifest(ctx, tx, next, sequence, head); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.records = next
	s.auditSequence, s.auditHead = sequence, head
	return nil
}

// clonePrincipal 复制所有会被变更路径写入的容器和绑定记录；候选状态可独立
// 修改，提交失败不会泄漏部分更新到当前身份。字符串和值类型直接复用。
func clonePrincipal(p *principalState) *principalState {
	copy := *p
	copy.allowed = append([]string(nil), p.allowed...)
	copy.bindings = map[string]*bindingRecord{}
	for name, b := range p.bindings {
		value := *b
		copy.bindings[name] = &value
	}
	return &copy
}

// publishPrincipalLocked 要求持有 g.mu；持久模式下状态与审计先一起提交，再发布身份、
// 失效目录并取消旧操作。该锁与最终调用准入共享，使撤权和新准入有明确先后。
func (g *Gateway) publishPrincipalLocked(id string, p *principalState, system string, action AuditAction, own bool) error {
	if !g.auditRoomLocked(1) {
		return ErrAuditFull
	}
	actor := AuditActorOperator
	if own {
		actor = AuditActorEntry
	}
	event := g.auditEventLocked(id, system, "", p, action, AuditPhaseCommit, AuditResultSuccess, actor)
	if g.store != nil {
		if err := g.store.persist(g, id, p, event); err != nil {
			g.auditFailureLocked()
			return ErrStorage
		}
	}
	if err := g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	g.principals[id] = p
	g.invalidateLocked(id, system)
	g.cancelOperationsLocked(id, system)
	return nil
}
func (g *Gateway) closeLocked() error {
	g.closed = true
	for _, op := range g.operations {
		op.cancel()
	}
	if g.store != nil {
		connErr := g.store.conn.Close()
		dbErr := g.store.db.Close()
		if dbErr != nil {
			return ErrStorage
		}
		if connErr != nil && !errors.Is(connErr, sql.ErrConnDone) {
			return ErrStorage
		}
		return nil
	}
	return nil
}

// Close stops admission and cancels in-flight operations best effort. It releases
// SQLite ownership, but does not promise downstream rollback or secure erasure.
func (g *Gateway) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g.mu.Lock()
	g.closed = true
	if g.closingContext == nil {
		g.closingContext = ctx
	}
	for _, op := range g.operations {
		op.cancel()
	}
	g.mu.Unlock()
	// 等待时不能持有 g.mu：操作结束仍需取得该锁写终态审计。上面的五秒
	// 上下文限制关闭期间的审计 I/O，不是 Wait 的硬超时或下游回滚保证。
	g.operationWG.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closeLocked()
}

func expiryText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func parseExpiry(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	if len(text) > 40 {
		return time.Time{}, ErrStorage
	}
	t, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || expiryText(t) != text {
		return time.Time{}, ErrStorage
	}
	return t.UTC(), nil
}
