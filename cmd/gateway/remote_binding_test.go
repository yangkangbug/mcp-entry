package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func bindingFlags(origin, cert, key string) []string {
	return []string{"-client-binding", "-allow-remote-test", "-tls-cert", cert, "-tls-key", key, "-binding-public-origin", origin}
}

func TestHTTPSBindingOptionMatrix(t *testing.T) {
	good := bindingFlags("https://binding.example", "cert.pem", "key.pem")
	if _, err := parseOptions(good, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://127.0.0.1:8443", "https://[::1]:8443"} {
		if _, err := parseOptions(bindingFlags(origin, "cert.pem", "key.pem"), io.Discard); err != nil {
			t.Fatal(origin, err)
		}
	}
	cases := [][]string{}
	for i := 0; i < len(good); {
		n := 1
		if strings.HasPrefix(good[i], "-tls-") || good[i] == "-binding-public-origin" {
			n = 2
		}
		args := append([]string{}, good[:i]...)
		args = append(args, good[i+n:]...)
		cases = append(cases, args)
		i += n
	}
	for _, extra := range [][]string{{"-account"}, {"-account=false"}, {"-admin-token-file", "admin"}, {"-allow-insecure-http-test"}, {"-allow-insecure-http-test=false"}, {"-client-binding=false"}, {"-allow-remote-test=false"}, {"-operation", "check-config"}} {
		cases = append(cases, append(append([]string{}, good...), extra...))
	}
	for _, origin := range []string{"", "http://binding.example", "http://localhost", "https://Binding.example", "https://binding.example/", "https://binding.example:443", "https://binding.example:0443", "https://binding.example/path", "https://binding.example?", "https://binding.example#", "https://user@binding.example", "https://binding.example."} {
		cases = append(cases, bindingFlags(origin, "cert.pem", "key.pem"))
	}
	for _, origin := range []string{"", "https://binding.example"} {
		cases = append(cases, []string{"-operation", "status", "-db", "missing.db", "-key-stdin", "-tenant", "demo", "-principal", "alice", "-binding-public-origin", origin})
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			reader := &countingReader{}
			var output bytes.Buffer
			err := run(append([]string{"-config", "missing.json"}, args...), reader, &output, &output)
			if !errors.Is(err, errOptions) || reader.count != 0 || output.Len() != 0 {
				t.Fatalf("not rejected before I/O: %v", err)
			}
		})
	}
}

func TestHTTPSBindingCertificatePreflight(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))
	config := remoteConfig(t, "http://127.0.0.1:1/mcp", gateway.User{Token: token, TokenExpiresAt: time.Now().Add(time.Hour)})
	for _, mode := range []string{"wrong-san", "expired", "future", "common-name-only"} {
		t.Run(mode, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(11), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			origin := "https://127.0.0.1"
			switch mode {
			case "wrong-san":
				origin = "https://binding.example"
			case "expired":
				template.NotAfter = time.Now().Add(-time.Minute)
			case "future":
				template.NotBefore = time.Now().Add(time.Minute)
			case "common-name-only":
				template.IPAddresses = nil
				template.Subject.CommonName = "127.0.0.1"
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			cert := writeOnboardingFile(t, "cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			private := writeOnboardingFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
			db := filepath.Join(t.TempDir(), "not-created.sqlite")
			reader := &countingReader{}
			// 占用地址确保错误来自预检而非监听；数据库和输入密钥均不得触碰。
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			args := append(bindingFlags(origin, cert, private), "-config", config, "-listen", listener.Addr().String(), "-db", db, "-key-stdin", "-init-db")
			err = run(args, reader, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "invalid HTTPS binding certificate") || reader.count != 0 {
				t.Fatalf("preflight failed: %v, key reads %d", err, reader.count)
			}
			if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("database created", err)
			}
		})
	}
	cert, key, _ := remoteCertificate(t)
	cfg, err := readServerTLS(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBindingTLS(cfg, "https://127.0.0.1:8443", time.Now()); err != nil {
		t.Fatal("valid fixture rejected", err)
	}
	if validateBindingTLS(nil, "https://127.0.0.1", time.Now()) == nil {
		t.Fatal("plaintext accepted")
	}
}

func TestHTTPSBindingExecutableDirectTLS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM fixture requires Unix")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "gateway")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-buildvcs=false", "-o", binary, "./cmd/gateway")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))
	const provider = "synthetic-https-binding-provider-canary"
	var businessCalls atomic.Int64
	providerHandler := mock.Handler("crm", map[string]string{provider: "alice"})
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			data, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				t.Error(err)
				http.Error(w, "fixture", 500)
				return
			}
			var rpc struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(data, &rpc)
			if rpc.Method == "tools/call" {
				businessCalls.Add(1)
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		providerHandler.ServeHTTP(w, r)
	}))
	defer downstream.Close()
	config := remoteConfig(t, downstream.URL, gateway.User{Token: token, TokenExpiresAt: time.Now().Add(time.Hour), Allowed: []string{"crm__echo"}})
	cert, key, roots := httpsBindingDNSCertificate(t)
	address := cliE2EAddress(t)
	// DNS SAN 的公共 origin 与实际监听 IP 分离；只替换拨号目标，TLS 名称和信任验证保持开启。
	origin := "https://binding.example.test"
	args := append(bindingFlags(origin, cert, key), "-config", config, "-listen", address)
	p := cliE2EStart(t, binary, args...)
	cliE2EReady(t, p, address)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sdk := mcp.NewClient(&mcp.Implementation{Name: "https-binding-fixture", Version: "1"}, nil)
	session, err := sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: origin + "/mcp", HTTPClient: &http.Client{Transport: remoteBearerTransport{base: transport, token: token}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_entry_connection_begin", Arguments: map[string]any{"service_id": "crm", "expected_generation": 1}})
	if err != nil || result.IsError {
		t.Fatal("begin failed", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	link, err := url.Parse(out["authorization_url"].(string))
	if err != nil || link.Scheme+"://"+link.Host != origin || link.Path != "/binding/" {
		t.Fatal("wrong fixed origin")
	}
	locator, capability, ok := strings.Cut(link.Fragment, ".")
	if !ok {
		t.Fatal("missing capability")
	}
	resp, err := client.Get(link.String())
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("browser page", resp.StatusCode)
	}
	post := func(action string, fields map[string]any, forwarded bool) int {
		t.Helper()
		data, _ := json.Marshal(fields)
		req, _ := http.NewRequestWithContext(ctx, "POST", origin+"/binding/api/session/"+action, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		if forwarded {
			req.Header.Set("Forwarded", "proto=https;host=attacker.example")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		for _, secret := range []string{token, provider, capability} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("response disclosed secret")
			}
		}
		return resp.StatusCode
	}
	fields := map[string]any{"session_locator": locator, "capability": capability}
	if code := post("inspect", fields, true); code == 200 {
		t.Fatal("proxy headers accepted")
	}
	if code := post("inspect", fields, false); code != 200 {
		t.Fatal("inspect", code)
	}
	fields["credential"] = provider
	fields["confirm"] = true
	if code := post("confirm", fields, false); code != 200 {
		t.Fatal("confirm", code)
	}
	if code := post("confirm", fields, false); code != 403 {
		t.Fatal("replay", code)
	}
	for _, path := range []string{"/account", "/admin"} {
		resp, err := client.Get(origin + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatal("remote management exposed", path, resp.StatusCode)
		}
	}
	wrong := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	defer wrong.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: wrong, Timeout: 3 * time.Second}).Get(origin + "/binding/"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted cert accepted")
	}
	wrongName := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "wrong.example.test", MinVersion: tls.VersionTLS12}}
	defer wrongName.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: wrongName, Timeout: 3 * time.Second}).Get(origin + "/binding/"); err == nil {
		resp.Body.Close()
		t.Fatal("wrong certificate hostname accepted")
	}
	status, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_entry_connection_status", Arguments: map[string]any{"session_locator": locator}})
	if err != nil || status.IsError {
		t.Fatal("SDK status failed", err)
	}
	var receipt struct {
		BindingSaved bool   `json:"binding_saved"`
		SaveOutcome  string `json:"save_outcome"`
	}
	if err := json.Unmarshal([]byte(status.Content[0].(*mcp.TextContent).Text), &receipt); err != nil || !receipt.BindingSaved || receipt.SaveOutcome != "saved" {
		t.Fatal("missing saved receipt", err)
	}
	if businessCalls.Load() != 0 {
		t.Fatal("binding dispatched a business call")
	}
	session.Close()
	transport.CloseIdleConnections()
	wrong.CloseIdleConnections()
	wrongName.CloseIdleConnections()
	p.stop(t)
	for _, secret := range []string{token, provider, capability} {
		if strings.Contains(p.log.String(), secret) {
			t.Fatal("log disclosed secret")
		}
	}
}

func httpsBindingDNSCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), DNSNames: []string{"binding.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPath := writeOnboardingFile(t, "cert.pem", certPEM)
	keyPath := writeOnboardingFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid fixture")
	}
	return certPath, keyPath, roots
}
