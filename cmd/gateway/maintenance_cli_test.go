package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

func TestMaintenanceCLIPrivateInputsAndVerifiedRotation(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	keyPath := filepath.Join(dir, "key")
	nextPath := filepath.Join(dir, "next-key")
	tokenPath := filepath.Join(dir, "token")
	configPath := filepath.Join(dir, "config.json")
	key := bytes.Repeat([]byte{71}, 32)
	next := bytes.Repeat([]byte{72}, 32)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))
	cfg := gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: "http://127.0.0.1:1/mcp"}}, Users: map[string]gateway.User{"alice": {Token: "synthetic-bootstrap", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic-downstream"}}}}
	raw, _ := json.Marshal(cfg)
	for name, data := range map[string][]byte{keyPath: key, nextPath: next, tokenPath: []byte(token), configPath: raw} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	g, err := gateway.NewPersistent(cfg, gateway.PersistenceOptions{Path: db, Key: key, Initialize: true})
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	base := []string{"-config", configPath, "-db", db, "-key-file", keyPath}
	invoke := func(extra ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := run(append(append([]string{}, base...), extra...), bytes.NewReader(nil), &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), []byte(token)) || bytes.Contains(out.Bytes(), []byte("synthetic-downstream")) {
			t.Fatal("secret output")
		}
		return out.Bytes()
	}
	scope := []string{"-tenant", "demo", "-principal", "alice"}
	invoke(append([]string{"-operation", "replace-entry", "-expected-version", "1", "-entry-file", tokenPath, "-entry-expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, scope...)...)
	var status struct{ Entry gateway.EntryInfo }
	if err := json.Unmarshal(invoke(append([]string{"-operation", "status"}, scope...)...), &status); err != nil || status.Entry.Generation != 2 {
		t.Fatalf("entry status %v", err)
	}
	invoke(append([]string{"-operation", "revoke-entry", "-expected-version", "2"}, scope...)...)
	database, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec("CREATE TRIGGER fail_rotation BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT,'synthetic private provider canary'); END"); err != nil {
		t.Fatal(err)
	}
	database.Close()
	var failed bytes.Buffer
	err = run(append(append([]string{}, base...), "-operation", "rotate-key", "-new-key-file", nextPath), bytes.NewReader(nil), &failed, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") || !strings.Contains(err.Error(), "retain both keys") || strings.Contains(err.Error(), "provider canary") || failed.Len() != 0 {
		t.Fatalf("unsafe rotation failure: %v", err)
	}
	database, err = sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec("DROP TRIGGER fail_rotation"); err != nil {
		t.Fatal(err)
	}
	database.Close()
	invoke("-operation", "rotate-key", "-new-key-file", nextPath)
	if old, err := gateway.NewPersistent(cfg, gateway.PersistenceOptions{Path: db, Key: key}); err == nil {
		old.Close()
		t.Fatal("old key accepted")
	}
	base = []string{"-config", configPath, "-db", db, "-key-file", nextPath}
	var page gateway.AuditPage
	if err := json.Unmarshal(invoke("-operation", "audit-all"), &page); err != nil {
		t.Fatal(err)
	}
	if page.LastSequence != 3 {
		t.Fatalf("audit count %d", page.LastSequence)
	}
	invoke("-operation", "archive-audit", "-archive-file", filepath.Join(dir, "archive.json"), "-expected-version", "3")
	invoke("-operation", "migrate")
}

func TestMaintenanceCLIRejectsFlagMixesBeforeIO(t *testing.T) {
	base := []string{"-db", "missing", "-key-stdin"}
	for _, extra := range [][]string{{"-operation", "migrate", "-tenant", "x"}, {"-operation", "rotate-key"}, {"-operation", "revoke-entry", "-tenant", "x", "-principal", "x", "-expected-version", "1", "-entry-file", "x"}, {"-operation", "archive-audit", "-archive-file", "x"}, {"-entry-file", "x"}, {"-operation", "audit-all", "-limit", "1001"}} {
		reader := &countingReader{}
		if err := run(append(append([]string{}, base...), extra...), reader, io.Discard, io.Discard); err != errOptions || reader.count != 0 {
			t.Fatalf("invalid flags %v: %v", extra, err)
		}
	}
}

func TestEntryFileHygiene(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{81}, 32))
	if err := os.WriteFile(good, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readEntryFile(good); err != nil || got != token {
		t.Fatal("valid token file rejected")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"short": "x", "newline": token + "\n"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readEntryFile(path); err == nil {
			t.Fatal("invalid token length accepted")
		}
	}
	if _, err := readEntryFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(good, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEntryFile(good); err == nil {
		t.Fatal("public token file accepted")
	}
}
