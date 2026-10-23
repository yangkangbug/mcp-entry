package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const httpsBindingOrigin = "https://connect.example.test"

func httpsBindingFixture(t *testing.T) (*Gateway, http.Handler, string) {
	t.Helper()
	g, _, token, _ := accountFixture(t)
	h, err := g.HTTPSClientBindingHandler(httpsBindingOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return g, h, token
}

func httpsBindingSession(t *testing.T, g *Gateway) map[string]any {
	t.Helper()
	out, err := g.beginConnection(context.Background(), "alice", "crm", 1)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(out["authorization_url"].(string))
	if err != nil || u.Scheme+"://"+u.Host != httpsBindingOrigin || u.Path != "/binding/" || u.RawQuery != "" {
		t.Fatal(out, err)
	}
	locator, capability, ok := strings.Cut(u.Fragment, ".")
	if !ok {
		t.Fatal("missing capability")
	}
	return map[string]any{"session_locator": locator, "capability": capability, "credential": "a-replacement", "confirm": true}
}

func httpsBindingRequest(token, path string, fields map[string]any) *http.Request {
	body, _ := json.Marshal(fields)
	r := httptest.NewRequest("POST", httpsBindingOrigin+path, strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", httpsBindingOrigin)
	return r
}
func httpsBindingServe(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHTTPSBindingCanonicalOrigin(t *testing.T) {
	for _, origin := range []string{httpsBindingOrigin, "https://example.test:8443", "https://127.0.0.1", "https://192.0.2.1:1", "https://[::1]", "https://[2001:db8::1]:65535", "https://xn--bcher-kva.example"} {
		if err := ValidateHTTPSBindingOrigin(origin); err != nil {
			t.Errorf("valid %s: %v", origin, err)
		}
	}
	for _, origin := range []string{"", "http://example.test", "HTTPS://example.test", "https://Example.test", "https://example.test/", "https://example.test?", "https://example.test#", "https://example.test#fragment", "https://user@example.test", "https://example.test:443", "https://example.test:0", "https://example.test:65536", "https://example.test:08443", "https://example.test:", "https://example.test:+80", "https://example.test.", "https://-bad.test", "https://bad-.test", "https://bad_test", "https://a..test", "https://bücher.test", "https://127.1", "https://2130706433", "https://0177.0.0.1", "https://0x7f000001", "https://0.0.0.0", "https://[::]", "https://224.0.0.1", "https://[ff02::1]", "https://[fe80::1%25eth0]", "https://[2001:0db8::1]", "https://[::FFFF:192.0.2.1]", "https://[::ffff:192.0.2.1]", "https://[::ffff:c000:201]", "https://example.test\\evil", "https://" + strings.Repeat("a", 64) + ".test"} {
		if err := ValidateHTTPSBindingOrigin(origin); err == nil {
			t.Errorf("accepted %q", origin)
		}
	}
}

func TestHTTPSBindingTransportBoundary(t *testing.T) {
	g, h, token := httpsBindingFixture(t)
	fields := httpsBindingSession(t, g)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"plaintext", func(r *http.Request) { r.TLS = nil }},
		{"forged_scheme", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "https" }},
		{"proxy_terminated", func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }},
		{"wrong_host", func(r *http.Request) { r.Host = "evil.test" }},
		{"host_case", func(r *http.Request) { r.Host = "Connect.example.test" }},
		{"host_default_port", func(r *http.Request) { r.Host = "connect.example.test:443" }},
		{"missing_origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"wrong_origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }},
		{"null_origin", func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"double_origin", func(r *http.Request) { r.Header.Add("Origin", httpsBindingOrigin) }},
		{"forwarded", func(r *http.Request) { r.Header.Set("Forwarded", "proto=https;host=connect.example.test") }},
		{"forwarded_host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "connect.example.test") }},
		{"unknown_forwarded", func(r *http.Request) { r.Header.Set("X-Forwarded-Anything", "yes") }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "x=y") }},
		{"cross_site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httpsBindingRequest(token, "/binding/api/session/confirm", fields)
			tc.mutate(r)
			w := httpsBindingServe(h, r)
			if w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	b, _ := g.Binding(integratedIdentity, "crm")
	if b.Generation != 1 {
		t.Fatal("transport failure mutated binding")
	}
	if w := httpsBindingServe(h, httpsBindingRequest(token, "/binding/api/session/confirm", fields)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestHTTPSBindingBrowserOnlyAndImmutable(t *testing.T) {
	g, h, token := httpsBindingFixture(t)
	for _, path := range []string{"/binding/api/services", "/binding/api/credentials", "/binding/api/revoke", "/binding/api/credentials/revoke"} {
		r := httpsBindingRequest(token, path, map[string]any{"service_id": "crm", "expected_generation": 1, "credential": "a-replacement"})
		if w := httpsBindingServe(h, r); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/binding/", "/binding/binding.js", "/binding/binding.css"} {
		for _, encrypted := range []bool{false, true} {
			r := httptest.NewRequest("GET", httpsBindingOrigin+path, nil)
			if !encrypted {
				r.TLS = nil
			}
			w := httpsBindingServe(h, r)
			want := 403
			if encrypted {
				want = 200
			}
			if w.Code != want {
				t.Fatal(path, w.Code)
			}
		}
		r := httptest.NewRequest("GET", httpsBindingOrigin+path, nil)
		r.Header.Set("Origin", "https://evil.test")
		if w := httpsBindingServe(h, r); w.Code != 403 {
			t.Fatal("static cross origin", w.Code)
		}
	}
	h2, err := g.HTTPSClientBindingHandler(httpsBindingOrigin)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", httpsBindingOrigin+"/binding/", nil)
	r.TLS = nil
	if w := httpsBindingServe(h2, r); w.Code != 403 {
		t.Fatal("reconstruction downgrade", w.Code)
	}
	for _, origin := range []string{httpsBindingOrigin, "http://127.0.0.1:8080"} {
		if _, err := g.ClientBindingHandler(origin); err == nil {
			t.Fatal("downgrade accepted")
		}
	}
	if _, err := g.HTTPSClientBindingHandler("https://other.test"); err == nil {
		t.Fatal("origin moved")
	}
	local, _, _ := clientFixture(t)
	if _, err := local.HTTPSClientBindingHandler(httpsBindingOrigin); err == nil {
		t.Fatal("local origin moved")
	}
}

func TestHTTPSBindingIndependentAuthenticationAndAtomicCommit(t *testing.T) {
	g, h, token := httpsBindingFixture(t)
	fields := httpsBindingSession(t, g)
	for _, invalid := range []string{"", "wrong-entry"} {
		if w := httpsBindingServe(h, httpsBindingRequest(invalid, "/binding/api/session/confirm", fields)); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- httpsBindingServe(h, httpsBindingRequest(token, "/binding/api/session/confirm", fields)).Code
		}()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 200 {
			successes++
		} else if code != 403 {
			t.Fatal(code)
		}
	}
	if successes != 1 {
		t.Fatal(successes)
	}
	b, _ := g.Binding(integratedIdentity, "crm")
	if b.Generation != 2 {
		t.Fatal(b)
	}
}

func TestHTTPSBindingRealTLSListener(t *testing.T) {
	_, h, _ := httpsBindingFixture(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	r, _ := http.NewRequest("GET", server.URL+"/binding/", nil)
	r.Host = "connect.example.test"
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	// 标准库测试服务器使用合成证书；测试不依赖真实域名、凭据或公网。
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatal("TLS absent")
	}
	plain := httptest.NewServer(h)
	defer plain.Close()
	r, _ = http.NewRequest("GET", plain.URL+"/binding/", nil)
	r.Host = "connect.example.test"
	r.Header.Set("Forwarded", "proto=https")
	response2, err := plain.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()
	if response2.StatusCode != 403 {
		t.Fatal(response2.StatusCode)
	}
}

func TestHTTPSBindingVersionedSession(t *testing.T) {
	for _, kind := range []string{"policy", "binding", "system", "entry"} {
		t.Run(kind, func(t *testing.T) {
			g, h, token := httpsBindingFixture(t)
			fields := httpsBindingSession(t, g)
			g.mu.Lock()
			s := g.connectionSessions[fields["session_locator"].(string)]
			switch kind {
			case "policy":
				s.policy++
			case "binding":
				s.binding++
			case "system":
				s.revision++
			case "entry":
				s.entry++
			}
			g.mu.Unlock()
			if w := httpsBindingServe(h, httpsBindingRequest(token, "/binding/api/session/confirm", fields)); w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
			b, _ := g.Binding(integratedIdentity, "crm")
			if b.Generation != 1 {
				t.Fatal("stale session mutation", b)
			}
		})
	}
}

func TestHTTPSBindingMetadataBrowserOnly(t *testing.T) {
	g, _, _ := httpsBindingFixture(t)
	out, err := g.clientServicesFor("alice")
	if err != nil || out.Submission != "one_time_browser_link" || !strings.Contains(out.Instructions, "direct CLI credential submission is disabled") {
		t.Fatal(out, err)
	}
	local, _, _ := clientFixture(t)
	old, err := local.clientServicesFor("alice")
	if err != nil || old.Submission != "one_time_browser_link_or_private_file_cli" {
		t.Fatal(old, err)
	}
}

func sdkHTTPSBindingRequest() *http.Request {
	r := httptest.NewRequest("POST", httpsBindingOrigin+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

func TestHTTPSBindingSDKTransport(t *testing.T) {
	g, _, _ := httpsBindingFixture(t)
	captured := g.state.Load().handlers["alice"]
	if _, err := g.HTTPSClientBindingHandler(httpsBindingOrigin); err != nil {
		t.Fatal(err)
	}
	current := g.state.Load().handlers["alice"]
	for _, h := range []http.Handler{captured, current} {
		for _, tc := range []struct {
			name   string
			mutate func(*http.Request)
		}{
			{"plaintext", func(r *http.Request) { r.TLS = nil }},
			{"host", func(r *http.Request) { r.Host = "evil.test" }},
			{"origin", func(r *http.Request) { r.Header.Set("Origin", httpsBindingOrigin) }},
			{"empty_origin", func(r *http.Request) { r.Header.Set("Origin", "") }},
			{"forwarded", func(r *http.Request) { r.Header.Set("Forwarded", "proto=https") }},
			{"forwarded_host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "connect.example.test") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := sdkHTTPSBindingRequest()
				tc.mutate(r)
				if w := httpsBindingServe(h, r); w.Code != 403 {
					t.Fatal(w.Code, w.Body.String())
				}
			})
		}
		// 真实TLS到回环LocalAddr，固定DNS Host不被SDK默认localhost策略误拒绝。
		server := httptest.NewTLSServer(h)
		r := sdkHTTPSBindingRequest()
		u, _ := url.Parse(server.URL + "/mcp")
		r.URL = u
		r.RequestURI = ""
		r.Host = "connect.example.test"
		response, err := server.Client().Do(r)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		server.Close()
		if response.StatusCode != 200 {
			t.Fatal("fixed DNS origin rejected", response.StatusCode)
		}
	}
	// 未显式启用HTTPS的默认和loopback模式必须继续保留SDK重绑定防护。
	for _, loopback := range []bool{false, true} {
		local, _, _, _ := accountFixture(t)
		if loopback {
			if _, err := local.ClientBindingHandler("http://127.0.0.1:8080"); err != nil {
				t.Fatal(err)
			}
		}
		server := httptest.NewTLSServer(local.state.Load().handlers["alice"])
		r := sdkHTTPSBindingRequest()
		u, _ := url.Parse(server.URL + "/mcp")
		r.URL = u
		r.RequestURI = ""
		r.Host = "connect.example.test"
		response, err := server.Client().Do(r)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		server.Close()
		if response.StatusCode != 403 {
			t.Fatal("default protection lost", loopback, response.StatusCode)
		}
	}
}
