package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

// Nonloopback addresses are parser fixtures only. All actual listeners in these
// tests bind loopback; this suite does not deploy a remotely reachable server.
func TestRemoteOptionsExplicitGate(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8443", "192.0.2.10:8443", "[::]:8443", "[2001:db8::10]:8443"} {
		if _, err := parseOptions([]string{"-listen", address}, io.Discard); !errors.Is(err, errOptions) {
			t.Fatalf("default accepted %q: %v", address, err)
		}
		for _, security := range [][]string{{"-tls-cert", "cert.pem", "-tls-key", "key.pem"}, {"-allow-insecure-http-test"}} {
			args := append([]string{"-listen", address, "-allow-remote-test"}, security...)
			if _, err := parseOptions(args, io.Discard); err != nil {
				t.Fatalf("explicit test mode rejected %q: %v", address, err)
			}
		}
	}
	o, err := parseOptions(nil, io.Discard)
	if err != nil || o.listen != "127.0.0.1:8080" {
		t.Fatalf("loopback default changed: %v", err)
	}
}

func TestRemoteInvalidOptionsBeforeIO(t *testing.T) {
	cases := [][]string{
		{"-allow-remote-test"},
		{"-allow-remote-test", "-listen", "0.0.0.0:8443"},
		{"-tls-cert", "cert.pem"}, {"-tls-key", "key.pem"},
		{"-allow-remote-test", "-tls-cert", "", "-tls-key", "key.pem"},
		{"-allow-remote-test", "-allow-insecure-http-test", "-tls-cert", "cert.pem", "-tls-key", "key.pem"},
		{"-allow-remote-test", "-allow-insecure-http-test", "-account"},
		{"-tls-cert", "cert.pem", "-tls-key", "key.pem", "-account"},
		{"-allow-remote-test", "-allow-insecure-http-test", "-listen", "example.com:8443"},
		{"-allow-remote-test", "-allow-insecure-http-test", "-listen", ":8443"},
		{"-allow-remote-test", "-allow-insecure-http-test", "-listen", "127.0.0.1:65536"},
	}
	for _, flag := range []string{"-allow-remote-test", "-allow-remote-test=false", "-allow-insecure-http-test", "-allow-insecure-http-test=false", "-tls-cert", "-tls-key"} {
		args := []string{"-operation", "status", "-db", "missing.db", "-key-stdin", "-tenant", "demo", "-principal", "alice", flag}
		if strings.HasPrefix(flag, "-tls-") {
			args = append(args, "fixture.pem")
		}
		cases = append(cases, args)
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			reader := &countingReader{}
			var output bytes.Buffer
			err := run(append([]string{"-config", "definitely-does-not-exist.json"}, args...), reader, &output, &output)
			if !errors.Is(err, errOptions) {
				t.Fatalf("want options rejection before configuration I/O, got %v", err)
			}
			if reader.count != 0 || output.Len() != 0 {
				t.Fatal("invalid options read key or emitted output")
			}
		})
	}
	secret := "synthetic-remote-secret-argument-canary"
	for _, args := range [][]string{{"-allow-remote-test=" + secret}, {"-allow-insecure-http-test=" + secret}, {"-tls-cert", secret}, {"-listen", secret, "-allow-remote-test", "-allow-insecure-http-test"}} {
		var output bytes.Buffer
		_, err := parseOptions(args, &output)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(output.String(), secret) {
			t.Fatal("secret argument accepted or disclosed")
		}
	}
}

func remoteConfig(t *testing.T, endpoint string, user gateway.User) string {
	t.Helper()
	cfg := gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: endpoint}}, Users: map[string]gateway.User{"alice": user}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRemoteAuthPreflightBeforePersistence(t *testing.T) {
	strong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))
	for _, user := range []gateway.User{
		{Token: "weak", TokenExpiresAt: time.Now().Add(time.Hour)},
		{Token: strong},
		{Token: strong, TokenExpiresAt: time.Now().Add(-time.Minute)},
	} {
		config := remoteConfig(t, "http://127.0.0.1:1/mcp", user)
		db := filepath.Join(t.TempDir(), "not-created.sqlite")
		reader := &countingReader{}
		err := run([]string{"-config", config, "-allow-remote-test", "-allow-insecure-http-test", "-listen", "127.0.0.1:0", "-db", db, "-key-stdin", "-init-db"}, reader, io.Discard, io.Discard)
		if err == nil {
			t.Fatal("unsafe remote authentication accepted")
		}
		if reader.count != 0 {
			t.Fatal("invalid remote auth read persistence key before rejection")
		}
		if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid remote auth created persistence", err)
		}
	}
}

func TestRemoteUnsafeFilesBeforePersistence(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))
	for _, mode := range []string{"public-config", "symlink-config", "bad-tls", "public-key", "symlink-key"} {
		t.Run(mode, func(t *testing.T) {
			config := remoteConfig(t, "http://127.0.0.1:1/mcp", gateway.User{Token: token, TokenExpiresAt: time.Now().Add(time.Hour)})
			cert, key, _ := remoteCertificate(t)
			switch mode {
			case "public-config":
				if err := os.Chmod(config, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-config":
				link := config + "-link"
				if err := os.Symlink(config, link); err != nil {
					t.Fatal(err)
				}
				config = link
			case "bad-tls":
				if err := os.WriteFile(key, []byte("synthetic-malformed-secret-key-canary"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-key":
				if err := os.Chmod(key, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-key":
				link := key + "-link"
				if err := os.Symlink(key, link); err != nil {
					t.Fatal(err)
				}
				key = link
			}
			db := filepath.Join(t.TempDir(), "not-created.sqlite")
			reader := &countingReader{}
			var output bytes.Buffer
			err := run([]string{"-config", config, "-allow-remote-test", "-tls-cert", cert, "-tls-key", key, "-listen", "127.0.0.1:0", "-db", db, "-key-stdin", "-init-db"}, reader, &output, &output)
			if err == nil {
				t.Fatal("unsafe startup file accepted")
			}
			if reader.count != 0 {
				t.Fatal("unsafe startup consumed persistence key")
			}
			if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe startup created database", err)
			}
			if strings.Contains(err.Error()+output.String(), "synthetic-malformed-secret-key-canary") {
				t.Fatal("TLS error disclosed private key")
			}
		})
	}
}

func remoteCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loopback synthetic test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid fixture certificate")
	}
	return certPath, keyPath, pool
}

type remoteBearerTransport struct {
	base  http.RoundTripper
	token string
}

func (r remoteBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+r.token)
	return r.base.RoundTrip(clone)
}

func TestRemoteExecutableTLSLoopback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM fixture requires Unix")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "gateway")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-buildvcs=false", "-o", binary, "./cmd/gateway")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))
	downstream := httptest.NewServer(mock.Handler("crm", map[string]string{"synthetic-remote-downstream-canary": "alice"}))
	defer downstream.Close()
	config := remoteConfig(t, downstream.URL, gateway.User{Token: token, TokenExpiresAt: time.Now().Add(time.Hour), Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic-remote-downstream-canary"}})
	cert, key, roots := remoteCertificate(t)
	address := cliE2EAddress(t)
	p := cliE2EStart(t, binary, "-config", config, "-listen", address, "-allow-remote-test", "-tls-cert", cert, "-tls-key", key)
	cliE2EReady(t, p, address)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: remoteBearerTransport{base: transport, token: token}, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sdk := mcp.NewClient(&mcp.Implementation{Name: "trusted-tls-fixture", Version: "1"}, nil)
	session, err := sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "https://" + address + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("trusted certificate SDK connection failed", err)
	}
	cliE2ETools(t, session, "crm__echo")
	cliE2ECall(t, session, "crm__echo", "alice", true)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	defer wrong.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: wrong, Timeout: 3 * time.Second}).Get("https://" + address + "/mcp"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted certificate accepted")
	}
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://" + address + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated TLS request status=%d", response.StatusCode)
	}
	p.stop(t)
	for _, secret := range []string{token, "synthetic-remote-downstream-canary", "synthetic-payload-canary-73492"} {
		if strings.Contains(p.log.String(), secret) {
			t.Fatal("TLS executable log exposed secret or payload")
		}
	}
	address = cliE2EAddress(t)
	plain := cliE2EStart(t, binary, "-config", config, "-listen", address, "-allow-remote-test", "-allow-insecure-http-test")
	cliE2EReady(t, plain, address)
	plainSession := cliE2EConnect(t, address, token)
	cliE2ETools(t, plainSession, "crm__echo")
	if err := plainSession.Close(); err != nil {
		t.Fatal(err)
	}
	plain.stop(t)
	logText := strings.ToLower(plain.log.String())
	if !strings.Contains(logText, "insecure") && !strings.Contains(logText, "plaintext") {
		t.Fatal("explicit insecure mode emitted no security warning")
	}
	for _, secret := range []string{token, "synthetic-remote-downstream-canary"} {
		if strings.Contains(plain.log.String(), secret) {
			t.Fatal("plaintext executable log exposed credentials")
		}
	}

	t.Log("actual executable TLS and official SDK verified with trusted fixture CA; unknown CA rejected; only loopback listeners used")
}
