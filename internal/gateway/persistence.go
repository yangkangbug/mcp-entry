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
	UserID, Tenant, Principal string
	TokenHash                 []byte
	TokenExpiresAt            time.Time
	Version                   uint64
	Disabled                  bool
	Allowed                   []string
	Bindings                  []storedBinding
}
type sqliteStore struct {
	db       *sql.DB
	conn     *sql.Conn
	aead     cipher.AEAD
	macKey   []byte
	topology []byte
	records  map[string]storedPrincipal
}

func entryTokenDigest(token string) [32]byte {
	return sha256.Sum256([]byte("mcp-entry/entry-token/v1\x00" + token))
}
func derivedKey(key []byte, purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, key, nil, "mcp-entry/persistence/v2/"+purpose, 32)
}

// NewPersistent keeps catalogs transient. Reopening never reimports policies or
// credentials, and rejects topology/token changes instead of merging config.
func NewPersistent(cfg Config, opts PersistenceOptions) (*Gateway, error) {
	if len(opts.Key) != 32 || opts.Path == "" {
		return nil, ErrStorage
	}
	g, err := New(cfg)
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
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<20 {
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
	identities := map[string]Identity{}
	for id, p := range g.principals {
		identities[id] = p.identity
	}
	topologyJSON, _ := json.Marshal(struct {
		Systems    map[string]System
		Identities map[string]Identity
	}{g.systems, identities})
	topology := sha256.Sum256(topologyJSON)
	store := &sqliteStore{db: db, aead: aead, macKey: macKey, topology: topology[:], records: map[string]storedPrincipal{}}
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
	success = true
	return g, nil
}

const persistentSchema = `
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,topology BLOB NOT NULL,key_check BLOB NOT NULL,state_mac BLOB NOT NULL);
CREATE TABLE principals(user_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,principal TEXT NOT NULL,token_hash BLOB NOT NULL,token_expires_at TEXT NOT NULL,policy_version INTEGER NOT NULL,disabled INTEGER NOT NULL,allowed TEXT NOT NULL,UNIQUE(tenant,principal));
CREATE TABLE bindings(user_id TEXT NOT NULL REFERENCES principals(user_id),system TEXT NOT NULL,binding_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,credential BLOB NOT NULL,PRIMARY KEY(user_id,system));`

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
	r := storedPrincipal{UserID: id, Tenant: p.identity.Tenant, Principal: p.identity.Principal, TokenHash: append([]byte(nil), token[:]...), TokenExpiresAt: g.users[id].TokenExpiresAt, Version: p.version, Disabled: p.disabled, Allowed: append([]string(nil), p.allowed...)}
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
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make([]storedPrincipal, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, records[id])
	}
	encoded, _ := json.Marshal(struct {
		Version  int
		Topology []byte
		Records  []storedPrincipal
	}{2, s.topology, ordered})
	m := hmac.New(sha256.New, s.macKey)
	m.Write(encoded)
	return m.Sum(nil)
}
func writePrincipal(ctx context.Context, tx *sql.Tx, r storedPrincipal, initialize bool) error {
	allowed, _ := json.Marshal(r.Allowed)
	var err error
	if initialize {
		_, err = tx.ExecContext(ctx, "INSERT INTO principals VALUES(?,?,?,?,?,?,?,?)", r.UserID, r.Tenant, r.Principal, r.TokenHash, expiryText(r.TokenExpiresAt), r.Version, r.Disabled, string(allowed))
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, "UPDATE principals SET policy_version=?,disabled=?,allowed=? WHERE user_id=?", r.Version, r.Disabled, string(allowed), r.UserID)
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
	check := s.aead.Seal(nil, nil, []byte("mcp-entry-state-v2"), s.topology)
	if _, err = tx.ExecContext(ctx, "INSERT INTO meta VALUES(1,2,?,?,?)", s.topology, check, s.stateMAC(s.records)); err != nil {
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
	if version != 2 {
		return ErrStorageVersion
	}
	if !bytes.Equal(topology, s.topology) {
		return ErrStorage
	}
	plain, err := s.aead.Open(nil, nil, check, s.topology)
	if err != nil || string(plain) != "mcp-entry-state-v2" {
		return ErrStorage
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT user_id,tenant,principal,token_hash,token_expires_at,policy_version,disabled,allowed FROM principals ORDER BY user_id")
	if err != nil {
		return err
	}
	for rows.Next() {
		var r storedPrincipal
		var version int64
		var disabled int
		var allowed, expiry string
		if err = rows.Scan(&r.UserID, &r.Tenant, &r.Principal, &r.TokenHash, &expiry, &version, &disabled, &allowed); err != nil {
			rows.Close()
			return err
		}
		r.TokenExpiresAt, err = parseExpiry(expiry)
		if err != nil {
			rows.Close()
			return ErrStorage
		}
		p, exists := g.principals[r.UserID]
		token := g.entryTokens[r.UserID]
		if !exists || len(s.records) >= len(g.principals) || p.identity != (Identity{r.Tenant, r.Principal}) || !bytes.Equal(r.TokenHash, token[:]) || !r.TokenExpiresAt.Equal(g.users[r.UserID].TokenExpiresAt) || version < 1 || (disabled != 0 && disabled != 1) || len(allowed) > 512<<10 {
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
		r.Version = uint64(version)
		r.Disabled = disabled == 1
		s.records[r.UserID] = r
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(s.records) != len(g.principals) {
		return ErrStorage
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
	restored := map[string]*principalState{}
	for id, r := range s.records {
		if len(r.Bindings) != len(g.systems) {
			return ErrStorage
		}
		p := &principalState{identity: Identity{r.Tenant, r.Principal}, version: r.Version, disabled: r.Disabled, allowed: append([]string(nil), r.Allowed...), bindings: map[string]*bindingRecord{}}
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
		restored[id] = p
	}
	g.principals = restored
	return nil
}
func (s *sqliteStore) persist(g *Gateway, id string, p *principalState) error {
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
	result, err := tx.ExecContext(ctx, "UPDATE meta SET state_mac=? WHERE id=1", s.stateMAC(next))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrStorage
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.records = next
	return nil
}

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
func (g *Gateway) publishPrincipalLocked(id string, p *principalState, system string) error {
	if g.store != nil {
		if err := g.store.persist(g, id, p); err != nil {
			g.closeLocked()
			return ErrStorage
		}
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
func (g *Gateway) Close() error { g.mu.Lock(); defer g.mu.Unlock(); return g.closeLocked() }

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
