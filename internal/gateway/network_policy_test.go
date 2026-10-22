package gateway

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{
		"https://user:pass@service.test/mcp", "https://service.test/mcp?q=1", "https://service.test/mcp?", "https://service.test/mcp#", "https://service.test:0/mcp", "https://service.test:65536/mcp", "https://service.test:0443/mcp", "https://service.test:/mcp", "https://Service.test/mcp", "https://service.test./mcp", "https://-service.test/mcp", "https://service..test/mcp", "https://service.test/a/../mcp", "https://service.test/%2emcp", "https://service.test/a//mcp", "https://service.test/a\\mcp", "ftp://service.test/mcp", "https://[fe80::1%25eth0]/mcp", "https://[::ffff:127.0.0.1]/mcp",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := parseNetworkEndpoint(endpoint); err == nil {
				t.Fatal("accepted invalid endpoint")
			}
		})
	}
	for _, endpoint := range []string{"https://service.test:8443/mcp", "https://[::1]/mcp", "http://127.0.0.1:1234/mcp", "https://service.test"} {
		if _, err := parseNetworkEndpoint(endpoint); err != nil {
			t.Fatal(endpoint, err)
		}
	}
}

func TestNetworkPolicyConfig(t *testing.T) {
	for _, ip := range []string{"169.254.169.254", "100.100.100.200", "168.63.129.16", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "fe80::1", "ff02::1", "64:ff9b::a00:1", "2002:a00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::192.168.1.1", "fd00:ec2::254", "10.0.0.0/8", "::ffff:127.0.0.1"} {
		if _, err := compileNetworkPolicy("https://service.test/mcp", &NetworkPolicy{AllowedIPs: []string{ip}}); err == nil {
			t.Fatalf("accepted %s", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "fd00::1", "93.184.216.34"} {
		if _, err := compileNetworkPolicy("https://service.test/mcp", &NetworkPolicy{AllowedIPs: []string{ip}}); err != nil {
			t.Fatal(ip, err)
		}
	}
	for _, endpoint := range []string{"https://127.0.0.1/mcp", "http://localhost/mcp", "http://10.0.0.1/mcp"} {
		if _, err := compileNetworkPolicy(endpoint, nil); err == nil {
			t.Fatal("default expanded", endpoint)
		}
	}
	for _, policy := range []*NetworkPolicy{{}, {AllowedIPs: []string{"127.0.0.1", "127.0.0.1"}}, {AllowedIPs: []string{"127.0.0.1"}, TrustedCAPEM: "bad"}} {
		if _, err := compileNetworkPolicy("https://service.test/mcp", policy); err == nil {
			t.Fatal("bad policy accepted")
		}
	}
	if _, err := compileNetworkPolicy("http://127.0.0.1/mcp", &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}}); err == nil {
		t.Fatal("opt-in plaintext")
	}
	if _, err := compileNetworkPolicy("https://10.0.0.2/mcp", &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}); err == nil {
		t.Fatal("literal not allowed")
	}
}

func TestNetworkDNSPinning(t *testing.T) {
	for _, tt := range []struct {
		name string
		ips  []string
		ok   bool
	}{
		{"private allowed", []string{"10.0.0.1"}, true}, {"private denied", []string{"10.0.0.2"}, false}, {"mixed denied", []string{"10.0.0.1", "169.254.169.254"}, false}, {"mixed unknown", []string{"10.0.0.1", "93.184.216.34"}, false}, {"empty", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var lookup, dial int
			policy := &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}
			rt, err := compileNetworkPolicyWith("https://service.test/mcp", policy, networkDependencies{
				lookup: func(context.Context, string) ([]netip.Addr, error) {
					lookup++
					var ips []netip.Addr
					for _, ip := range tt.ips {
						ips = append(ips, netip.MustParseAddr(ip))
					}
					return ips, nil
				},
				dial: func(_ context.Context, network, addr string) (net.Conn, error) {
					dial++
					if network != "tcp" || addr != "10.0.0.1:443" {
						t.Fatal("unpinned", network, addr)
					}
					return nil, errors.New("synthetic dial")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			policy.AllowedIPs[0] = "169.254.169.254" // Compiled policy must not alias caller data.
			req, _ := http.NewRequest("POST", "https://service.test/mcp", nil)
			rt.RoundTrip(req)
			if lookup != 1 || (dial == 1) != tt.ok {
				t.Fatalf("lookup=%d dial=%d", lookup, dial)
			}
		})
	}
}

func TestNetworkDNSRebindingDenied(t *testing.T) {
	var calls, dials int
	rt, err := compileNetworkPolicyWith("https://service.test/mcp", &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}, networkDependencies{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			calls++
			if calls == 1 {
				return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) { dials++; return nil, errors.New("synthetic") },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		r, _ := http.NewRequest("POST", "https://service.test/mcp", nil)
		rt.RoundTrip(r)
	}
	if calls != 2 || dials != 1 {
		t.Fatalf("DNS calls %d dials %d", calls, dials)
	}
}

func TestNetworkTLSAndRequestGuard(t *testing.T) {
	var reached atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("ambient credential leaked")
		}
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("credential missing")
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	policy := &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}, TrustedCAPEM: ca}
	rt, err := compileNetworkPolicy(srv.URL+"/mcp", policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.TrustedCAPEM = "bad"
	client := &http.Client{Transport: rt, Timeout: time.Second}
	req, _ := http.NewRequest("GET", srv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer synthetic")
	req.Header.Set("Cookie", "secret")
	req.Header.Set("Proxy-Authorization", "secret")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	for _, endpoint := range []string{srv.URL + "/else", srv.URL + "/mcp?other=1", strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/mcp"} {
		r, _ := http.NewRequest("GET", endpoint, nil)
		if _, err := client.Do(r); err == nil {
			t.Fatal("escaped endpoint")
		}
	}
	r, _ := http.NewRequest("GET", srv.URL+"/mcp", nil)
	r.Host = "other.test"
	if _, err := client.Do(r); err == nil {
		t.Fatal("host override")
	}
	if reached.Load() != 1 {
		t.Fatal("guard allowed extra requests", reached.Load())
	}
	// Untrusted CA must fail without reaching HTTP handler.
	untrusted, _ := compileNetworkPolicy(srv.URL+"/mcp", &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}})
	if _, err := (&http.Client{Transport: untrusted, Timeout: time.Second}).Get(srv.URL + "/mcp"); err == nil {
		t.Fatal("accepted untrusted TLS")
	}
	// Trusted cert, wrong DNS name, pinned to the real loopback TLS fixture.
	hostEndpoint := strings.Replace(srv.URL, "127.0.0.1", "wrong.test", 1) + "/mcp"
	mismatched, _ := compileNetworkPolicyWith(hostEndpoint, &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}, TrustedCAPEM: ca}, networkDependencies{lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, dial: (&net.Dialer{}).DialContext})
	if _, err := (&http.Client{Transport: mismatched, Timeout: time.Second}).Get(hostEndpoint); err == nil {
		t.Fatal("accepted wrong TLS name")
	}
	if reached.Load() != 1 {
		t.Fatal("TLS failure reached handler")
	}
}

func TestNetworkRedirectProxyAndCancellation(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", target.URL)
	t.Setenv("HTTPS_PROXY", target.URL)
	t.Setenv("ALL_PROXY", target.URL)
	rt, err := compileNetworkPolicy(srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rt.(*endpointTransport).base.Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
	client := &http.Client{Transport: rt, Timeout: time.Second}
	if _, err := client.Get(srv.URL + "/mcp"); err == nil {
		t.Fatal("redirect not refused")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect target or proxy reached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/mcp", nil)
	if _, err := client.Do(req); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
}

func TestNetworkDNSBudgetAndDialTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	rt, err := compileNetworkPolicyWith("https://service.test:8443/mcp", &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}, networkDependencies{
		lookup: func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() },
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial after failed DNS")
			return nil, errors.New("unexpected")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := rt.(*endpointTransport).base
	start := time.Now()
	if _, err := transport.DialContext(ctx, "tcp", "service.test:8443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost DNS deadline classification", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("caller deadline not honored")
	}
	for _, addr := range []string{"other.test:8443", "service.test:443", "10.0.0.1:8443"} {
		if _, err := transport.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Fatal("wrong dial target", addr)
		}
	}
}

func TestNetworkVerifiedDNSFixture(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	host := "example.com"
	endpoint := strings.Replace(srv.URL, "127.0.0.1", host, 1) + "/mcp"
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	var lookups atomic.Int32
	rt, err := compileNetworkPolicyWith(endpoint, &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}, TrustedCAPEM: ca}, networkDependencies{
		lookup: func(_ context.Context, name string) ([]netip.Addr, error) {
			if name != host {
				t.Error("incorrect DNS name")
			}
			lookups.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		dial: (&net.Dialer{}).DialContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt, Timeout: time.Second}
	for range 2 {
		resp, err := client.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if lookups.Load() != 2 {
		t.Fatal("expected checked fresh DNS per connection", lookups.Load())
	}
}

func TestNetworkDNSFailureClassification(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private resolver detail")} {
		rt, err := compileNetworkPolicyWith("https://service.test/mcp", &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}, networkDependencies{
			lookup: func(context.Context, string) ([]netip.Addr, error) {
				return nil, fmt.Errorf("private DNS diagnostic: %w", cause)
			},
			dial: func(context.Context, string, string) (net.Conn, error) {
				t.Error("dial after failed DNS")
				return nil, errors.New("unexpected")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = rt.(*endpointTransport).base.DialContext(context.Background(), "tcp", "service.test:443")
		expected := cause
		if cause != context.Canceled && cause != context.DeadlineExceeded {
			expected = errNetworkPolicy
		}
		if !errors.Is(err, expected) || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe or lost classification: %v", err)
		}
	}
}

func TestNetworkDNSInternalDeadlineClassification(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rt, err := compileNetworkPolicyWith("https://service.test/mcp", &NetworkPolicy{AllowedIPs: []string{"10.0.0.1"}}, networkDependencies{
		lookup: func(ctx context.Context, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, errors.New("private DNS failure")
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial after failed DNS")
			return nil, errors.New("unexpected")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.(*endpointTransport).base.DialContext(parent, "tcp", "service.test:443")
	if parent.Err() != nil {
		t.Fatal("test exhausted parent rather than internal DNS budget", parent.Err())
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("internal DNS budget lost timeout evidence", err)
	}
}
