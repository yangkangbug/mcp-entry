package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	toolNamePattern         = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	authHeaderNamePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	bearerCredentialPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
)

// Config is deliberately a local, synthetic-credential configuration, not a vault.
type Config struct {
	Systems []System        `json:"systems"`
	Users   map[string]User `json:"users"`
}

type System struct {
	Name     string     `json:"name"`
	Endpoint string     `json:"endpoint"`
	Auth     AuthConfig `json:"auth,omitempty"`
}

// AuthConfig selects a single administrator-configured credential header.
// Empty mode preserves the Bearer default. It never contains a credential.
type AuthConfig struct {
	Mode   string `json:"mode,omitempty"`
	Header string `json:"header,omitempty"`
}

func normalizeAuth(auth AuthConfig) (AuthConfig, error) {
	if auth.Mode == "" {
		auth.Mode = "bearer"
	}
	switch auth.Mode {
	case "bearer", "raw":
		if auth.Header != "" {
			return AuthConfig{}, errors.New("authentication mode does not accept a header name")
		}
	case "api_key":
		if !validAuthHeader(auth.Header) {
			return AuthConfig{}, errors.New("invalid or reserved authentication header")
		}
		auth.Header = http.CanonicalHeaderKey(auth.Header)
	default:
		return AuthConfig{}, errors.New("unsupported authentication mode")
	}
	return auth, nil
}

func validAuthHeader(name string) bool {
	// Restrict the RFC token grammar further: punctuation and underscores can
	// acquire different meanings in intermediaries. Only this subset is offered.
	if !authHeaderNamePattern.MatchString(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, prefix := range []string{"proxy-", "content-", "accept", "mcp-", "sec-", "if-", "x-forwarded", "x-original-", "x-rewrite-", "x-session", "session", "forwarded", "x-auth-request-", "x-authenticated-", "x-remote-", "x-ssl-", "ssl-", "x-client-cert", "x-http-method"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	switch lower {
	case "authorization", "host", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
		"cookie", "set-cookie", "forwarded", "via", "x-real-ip", "x-client-ip", "true-client-ip", "cf-connecting-ip",
		"origin", "referer", "last-event-id", "user-agent", "cache-control", "pragma", "range", "expect", "date", "max-forwards",
		"www-authenticate", "authentication-info", "session", "x-http-method-override", "x-method-override",
		"traceparent", "tracestate", "baggage", "client-ip", "remote-addr", "remote-user",
		"x-user", "x-username", "x-email", "x-auth-user", "x-auth-email":
		return false
	}
	return true
}

func validCredential(value string, auth AuthConfig) bool {
	// Missing credentials remain a discovery-time failure, not an anonymous mode.
	if value == "" {
		return true
	}
	if len(value) > 4096 || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return auth.Mode != "bearer" || bearerCredentialPattern.MatchString(value)
}

type User struct {
	Token       string            `json:"token"`
	Allowed     []string          `json:"allowed"`
	Credentials map[string]string `json:"credentials"`
}

// LoadConfig rejects unknown fields, trailing documents and oversized configuration.
func LoadConfig(r io.Reader) (Config, error) {
	var cfg Config
	data, err := io.ReadAll(io.LimitReader(r, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return cfg, errors.New("configuration unreadable or too large")
	}
	text := strings.TrimSpace(string(data))
	if len(text) == 0 || text[0] != '{' {
		return cfg, errors.New("configuration must be a JSON object")
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid configuration")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("configuration must contain one JSON object")
	}
	return cfg, nil
}

func validPart(name string) bool {
	return toolNamePattern.MatchString(name) && !strings.Contains(name, "__")
}
func validNamespaced(name string, systems map[string]System) bool {
	parts := strings.Split(name, "__")
	if len(parts) != 2 || !validPart(parts[0]) || !validPart(parts[1]) || !toolNamePattern.MatchString(name) {
		return false
	}
	_, ok := systems[parts[0]]
	return ok
}
func validateEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "http" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}
