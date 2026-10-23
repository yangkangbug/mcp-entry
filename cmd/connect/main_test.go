//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

func privateFixture(t *testing.T) (string, string, string) {
	t.Helper()
	d := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32))
	e := filepath.Join(d, "entry")
	p := filepath.Join(d, "provider")
	if err := os.WriteFile(e, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("synthetic-provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	return e, p, token
}
func submitArgs(url, e, p string) []string {
	return []string{"--gateway", url, "--entry-file", e, "--credential-file", p, "--service", "crm", "--generation", "1"}
}
func TestConnectSubmissionAndStatus(t *testing.T) {
	e, p, token := privateFixture(t)
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" {
			t.Error("bad auth or target")
		}
		if r.Method == "GET" {
			if r.URL.Path != "/binding/api/services" {
				t.Error("bad path")
			}
			w.Write([]byte(`{"services":[{"system":"crm","generation":2,"state":"active","credential":"should-not-print"}]}`))
			return
		}
		if r.Method != "POST" || r.URL.Path != "/binding/api/credentials" {
			t.Error("bad target")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 3 || body["credential"] != "synthetic-provider-secret" || body["service_id"] != "crm" || body["expected_generation"] != float64(1) {
			t.Error("bad body")
		}
		w.Write([]byte(`{"binding_saved":true,"binding":{"system":"crm","generation":2,"state":"active"},"discovery_status":"unavailable","credential":"should-not-print"}`))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := run(context.Background(), submitArgs(s.URL, e, p), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"binding_saved":true`) || strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "should-not-print") {
		t.Fatal("bad output", out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"--gateway", s.URL, "--entry-file", e, "--status"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "should-not-print") || calls.Load() != 2 {
		t.Fatal("bad status or replay")
	}
}
func TestPrivateFileRejections(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "file")
	for _, mode := range []os.FileMode{0644, 0620, 0604} {
		os.WriteFile(path, []byte("secret"), 0600)
		os.Chmod(path, mode)
		if _, err := readPrivate(path, 20); err == nil {
			t.Fatal("unsafe permissions")
		}
		os.Remove(path)
	}
	os.WriteFile(path, []byte("secret"), 0600)
	link := filepath.Join(d, "link")
	os.Symlink(path, link)
	if _, err := readPrivate(link, 20); err == nil {
		t.Fatal("symlink accepted")
	}
	dirlink := filepath.Join(d, "dirlink")
	os.Symlink(d, dirlink)
	if _, err := readPrivate(filepath.Join(dirlink, "file"), 20); err == nil {
		t.Fatal("parent symlink accepted")
	}
	fifo := filepath.Join(d, "fifo")
	if unix.Mkfifo(fifo, 0600) != nil {
		t.Fatal("fifo fixture")
	}
	if _, err := readPrivate(fifo, 20); err == nil {
		t.Fatal("fifo accepted")
	}
	if _, err := readPrivate(path, 3); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := readPrivate(d, 20); err == nil {
		t.Fatal("directory accepted")
	}
}
func TestTargetRejections(t *testing.T) {
	for _, raw := range []string{"https://127.0.0.1:1234", "http://localhost:1234", "http://example.com:1234", "http://127.0.0.2:1234", "http://127.0.0.1:0", "http://127.0.0.1:1234/", "http://127.0.0.1:1234?", "http://127.0.0.1:1234?q=secret", "http://user@127.0.0.1:1234", "http://127.0.0.1:1234/#x"} {
		if _, err := gatewayURL(raw); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:1234", "http://[::1]:1234"} {
		if _, err := gatewayURL(raw); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRedirectAndUnknownNoRetry(t *testing.T) {
	e, p, _ := privateFixture(t)
	var leaked atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer dest.Close()
	for _, response := range []string{"redirect", "disconnect", "malformed", "wrong-generation", "error-echo"} {
		t.Run(response, func(t *testing.T) {
			var count atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				switch response {
				case "redirect":
					http.Redirect(w, r, dest.URL, http.StatusTemporaryRedirect)
				case "disconnect":
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
				case "malformed":
					w.Write([]byte("synthetic-provider-secret"))
				case "error-echo":
					w.WriteHeader(400)
					w.Write([]byte(`{"error":"synthetic-provider-secret"}`))
				case "wrong-generation":
					w.Write([]byte(`{"binding_saved":true,"binding":{"system":"crm","generation":3,"state":"active"},"discovery_status":"ready"}`))
				}
			}))
			defer s.Close()
			var out bytes.Buffer
			err := run(context.Background(), submitArgs(s.URL, e, p), &out)
			if err == nil || !strings.Contains(err.Error(), "outcome_unknown") || count.Load() != 1 || out.Len() != 0 {
				t.Fatal("unsafe outcome", err, count.Load(), out.String())
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect leaked credentials")
	}
}
func TestCancelAndInputValidation(t *testing.T) {
	e, p, _ := privateFixture(t)
	var count atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := run(ctx, submitArgs(s.URL, e, p), &out); err == nil || !strings.Contains(err.Error(), "outcome_unknown") {
		t.Fatal(err)
	}
	if count.Load() != 0 {
		t.Fatal("canceled dispatch")
	}
	for _, value := range []string{"with newline\n", "", strings.Repeat("x", 4097)} {
		os.WriteFile(p, []byte(value), 0600)
		if err := run(context.Background(), submitArgs(s.URL, e, p), &out); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if count.Load() != 0 {
		t.Fatal("invalid dispatch")
	}
}

func TestKnownSecretCannotAppearInWhitelistedFields(t *testing.T) {
	e, p, token := privateFixture(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"services": []binding{{System: token, Generation: 1, State: "active"}}})
	}))
	defer s.Close()
	var out bytes.Buffer
	err := run(context.Background(), []string{"--gateway", s.URL, "--entry-file", e, "--status"}, &out)
	if err == nil || out.Len() != 0 || strings.Contains(err.Error(), token) {
		t.Fatal("entry reflection", err, out.String())
	}
	// A credential may coincidentally equal a configured service identifier.
	os.WriteFile(p, []byte("crm"), 0600)
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"binding_saved":true,"binding":{"system":"crm","generation":2,"state":"active"},"discovery_status":"ready"}`))
	}))
	defer s2.Close()
	err = run(context.Background(), submitArgs(s2.URL, e, p), &out)
	if err == nil || out.Len() != 0 || !strings.Contains(err.Error(), "outcome_unknown") {
		t.Fatal("provider reflection", err, out.String())
	}
	for _, secret := range []string{"active", "available", "a\"b"} {
		out.Reset()
		err = writeSafeResult(&out, map[string]string{"state": secret}, [][]byte{[]byte(secret)})
		if err == nil || out.Len() != 0 {
			t.Fatal("escaped/status reflection")
		}
	}
}
func TestRawCredentialInteriorSpace(t *testing.T) {
	e, p, _ := privateFixture(t)
	os.WriteFile(p, []byte("Synthetic raw-secret"), 0600)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["credential"] != "Synthetic raw-secret" {
			t.Error("credential altered")
		}
		w.Write([]byte(`{"binding_saved":true,"binding":{"system":"crm","generation":2,"state":"active"},"discovery_status":"ready"}`))
	}))
	defer s.Close()
	var out bytes.Buffer
	if err := run(context.Background(), submitArgs(s.URL, e, p), &out); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{" leading", "trailing "} {
		os.WriteFile(p, []byte(value), 0600)
		if err := run(context.Background(), submitArgs(s.URL, e, p), &out); err == nil {
			t.Fatal("edge whitespace")
		}
	}
}
