package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionsRejectInappropriateFlagsBeforeIO(t *testing.T) {
	base := []string{"-operation", "status", "-db", "missing.db", "-key-stdin", "-tenant", "demo", "-principal", "alice"}
	cases := [][]string{
		{"-tenant", ""}, {"-expected-version", "0"}, {"-system", ""}, {"-allow", ""},
		{"-db", ""}, {"-key-stdin=false"}, {"-init-db=false"}, {"-db", "x"},
		{"-db", "x", "-key-stdin", "-key-file", "x"}, {"-listen", "0.0.0.0:8080"}, {"-listen", "127.0.0.1:invalid"},
		{"-listen", "127.0.0.1:65536"}, {"-listen", "localhost:8080"},
		append(append([]string{}, base...), "-listen", "127.0.0.1:8080"),
		append(append([]string{}, base...), "-init-db=false"),
		append(append([]string{}, base...), "-expected-version", "0"),
		append(append([]string{}, base...), "-allow", ""),
		{"-operation", "revoke-binding", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-system", "crm"},
		{"-operation", "disable-principal", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-expected-version", "1", "-system", ""},
		{"-operation", "set-policy", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-expected-version", "1", "-system", ""},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			reader := &countingReader{}
			var output bytes.Buffer
			err := run(args, reader, &output, &output)
			if !errors.Is(err, errOptions) {
				t.Fatalf("want options error, got %v", err)
			}
			if reader.count != 0 || output.Len() != 0 {
				t.Fatal("invalid options read input or produced output")
			}
		})
	}
}

type countingReader struct{ count int }

func (r *countingReader) Read(p []byte) (int, error) { r.count++; return 0, io.EOF }

func TestOptionParserNeverEchoesSecretValues(t *testing.T) {
	secret := "synthetic-accidentally-pasted-key-canary"
	for _, args := range [][]string{{"-key", secret}, {"-expected-version", secret}, {"-key-stdin=" + secret}, {secret}} {
		var output bytes.Buffer
		_, err := parseOptions(args, &output)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(output.String(), secret) {
			t.Fatal("invalid option value leaked or succeeded")
		}
	}
}

func TestOptionsSupportedModes(t *testing.T) {
	for _, args := range [][]string{
		{}, {"-listen", "[::1]:0"}, {"-db", "x", "-key-file", "key", "-init-db"},
		{"-operation", "status", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-system", "crm"},
		{"-operation", "revoke-binding", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-system", "crm", "-expected-version", "1"},
		{"-operation", "disable-principal", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-expected-version", "1"},
		{"-operation", "set-policy", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-expected-version", "1", "-allow", "crm__echo", "-allow", "docs__echo"},
		{"-operation", "set-policy", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-expected-version", "1"},
	} {
		if _, err := parseOptions(args, io.Discard); err != nil {
			t.Fatalf("supported args %v rejected: %v", args, err)
		}
	}
}

func TestKeyInputBoundedAndPrivate(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	for _, n := range []int{0, 31, 32, 33, 1000} {
		reader := bytes.NewReader(bytes.Repeat([]byte{'k'}, n))
		got, err := readKey(options{db: "x", keyStdin: true}, reader)
		if (err == nil) != (n == 32) {
			t.Fatalf("length %d: %v", n, err)
		}
		if n == 32 && !bytes.Equal(got, key) {
			t.Fatal("key altered")
		}
		if n > 33 && reader.Len() != n-33 {
			t.Fatal("read beyond bounded input")
		}
	}
	path := filepath.Join(t.TempDir(), "synthetic.key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readKey(options{db: "x", keyFile: path}, nil); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("private key: %v", err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(options{db: "x", keyFile: link}, nil); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(options{db: "x", keyFile: path}, nil); err == nil {
		t.Fatal("public key file accepted")
	}
	if _, err := readKey(options{db: "x", keyFile: filepath.Dir(path)}, nil); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestAccountCommandPreflight(t *testing.T) {
	for _, flag := range []string{"-account", "-account=false"} {
		if _, err := parseOptions([]string{"-operation", "status", "-db", "state.sqlite", "-key-stdin", "-tenant", "demo", "-principal", "alice", flag}, io.Discard); err == nil {
			t.Fatal("account flag accepted offline")
		}
	}
	path := filepath.Join(t.TempDir(), "not-created.sqlite")
	err := run([]string{"-config", "../../configs/demo.json", "-account", "-db", path, "-key-stdin", "-init-db"}, strings.NewReader("0123456789abcdef0123456789abcdef"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("weak demo auth enabled account mode")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid account auth created store", err)
	}
}

func TestAuditOptionsBoundedAndOffline(t *testing.T) {
	base := []string{"-operation", "audit", "-db", "x", "-key-stdin", "-tenant", "demo", "-principal", "alice"}
	if _, err := parseOptions(append(base, "-after-sequence", "2", "-limit", "10"), io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"-limit", "0"}, {"-limit", "1001"}, {"-system", "crm"}, {"-expected-version", "0"}, {"-init-db=false"}, {"-listen", "127.0.0.1:0"}} {
		if _, err := parseOptions(append(append([]string{}, base...), extra...), io.Discard); err == nil {
			t.Fatalf("accepted %v", extra)
		}
	}
	if _, err := parseOptions([]string{"-limit", "10"}, io.Discard); err == nil {
		t.Fatal("serve accepted audit flag")
	}
}
