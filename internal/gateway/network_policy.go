package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NetworkPolicy opts one fixed system endpoint into HTTPS. Every resolved address
// must appear literally in AllowedIPs, including private and loopback addresses.
// TrustedCAPEM replaces system roots when supplied; it never disables verification.
// This is administrator configuration, never a tool argument or a general proxy.
type NetworkPolicy struct {
	AllowedIPs   []string `json:"allowed_ips"`
	TrustedCAPEM string   `json:"trusted_ca_pem,omitempty"`
}

type networkDependencies struct {
	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func compileNetworkPolicy(endpoint string, policy *NetworkPolicy) (http.RoundTripper, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return compileNetworkPolicyWith(endpoint, policy, networkDependencies{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: d.DialContext,
	})
}

var errNetworkPolicy = errors.New("downstream network policy denied")

func parseNetworkEndpoint(endpoint string) (*url.URL, error) {
	if len(endpoint) == 0 || len(endpoint) > 2048 {
		return nil, errNetworkPolicy
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(endpoint, "#") || u.Host == "" || u.RawPath != "" {
		return nil, errNetworkPolicy
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errNetworkPolicy
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is4In6() {
			return nil, errNetworkPolicy
		}
	} else {
		if len(host) > 253 || host != strings.ToLower(host) {
			return nil, errNetworkPolicy
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errNetworkPolicy
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, errNetworkPolicy
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return nil, errNetworkPolicy
		}
	}
	expectedHost := host
	if strings.Contains(host, ":") {
		expectedHost = "[" + host + "]"
	}
	if port != "" {
		expectedHost += ":" + port
	}
	if expectedHost != u.Host {
		return nil, errNetworkPolicy
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errNetworkPolicy
		}
		for _, c := range segment {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~", c)) {
				return nil, errNetworkPolicy
			}
		}
	}
	if strings.Contains(u.Path, "//") || strings.Contains(endpoint, "%") {
		return nil, errNetworkPolicy
	}
	return u, nil
}

func permittedNetworkIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Preserve the demo loopback exception before denying deprecated ::/96.
	if ip == netip.IPv6Loopback() {
		return true
	}
	// Known metadata/shared-service and unsupported transition destinations
	// remain denied even if configured. This is not a universal metadata detector.
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "240.0.0.0/4", "168.63.129.16/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::/96", "fd00:ec2::254/128"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast() || ip.IsLoopback()
}

func compileNetworkPolicyWith(endpoint string, policy *NetworkPolicy, deps networkDependencies) (http.RoundTripper, error) {
	u, err := parseNetworkEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	allowed := map[netip.Addr]bool{}
	var roots *x509.CertPool
	if policy == nil {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || u.Scheme != "http" || (ip.String() != "127.0.0.1" && ip.String() != "::1") {
			return nil, errNetworkPolicy
		}
		allowed[ip] = true
	} else {
		if u.Scheme != "https" || len(policy.AllowedIPs) == 0 || len(policy.AllowedIPs) > 64 || len(policy.TrustedCAPEM) > 128<<10 {
			return nil, errNetworkPolicy
		}
		for _, raw := range policy.AllowedIPs {
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.Is4In6() || !permittedNetworkIP(ip) || allowed[ip] {
				return nil, errNetworkPolicy
			}
			allowed[ip] = true
		}
		if policy.TrustedCAPEM != "" {
			roots = x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(policy.TrustedCAPEM)) {
				return nil, errNetworkPolicy
			}
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !allowed[ip] {
		return nil, errNetworkPolicy
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(u.Hostname(), port)
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != address {
			return nil, errNetworkPolicy
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
			ips = []netip.Addr{ip}
		} else {
			ips, err = deps.lookup(ctx, u.Hostname())
			if err != nil {
				// Preserve cancellation/timeout classification without leaking resolver
				// errors (which may contain internal hostnames and DNS addresses).
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, context.DeadlineExceeded
				}
				if errors.Is(err, context.Canceled) {
					return nil, context.Canceled
				}
				return nil, errNetworkPolicy
			}
		}
		if len(ips) == 0 || len(ips) > 64 {
			return nil, errNetworkPolicy
		}
		for _, ip := range ips {
			if !permittedNetworkIP(ip) || !allowed[ip.Unmap()] {
				return nil, errNetworkPolicy
			}
		}
		// Dial the checked numeric address, never resolve the hostname a second time.
		// No fallback/retry: a failed connection cannot duplicate a tool operation.
		return deps.dial(ctx, "tcp", net.JoinHostPort(ips[0].Unmap().String(), port))
	}
	return &endpointTransport{endpoint: *u, base: transport}, nil
}

type endpointTransport struct {
	endpoint url.URL
	base     *http.Transport
}

func (t *endpointTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.String() != t.endpoint.String() || (r.Host != "" && r.Host != t.endpoint.Host) {
		return nil, errNetworkPolicy
	}
	copy := r.Clone(r.Context())
	for name := range copy.Header {
		if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Proxy-Authorization") {
			delete(copy.Header, name)
		}
	}
	resp, err := t.base.RoundTrip(copy)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, errors.New("downstream redirect refused")
	}
	return resp, nil
}
