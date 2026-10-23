package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	toolNamePattern         = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	authHeaderNamePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	bearerCredentialPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
)

// Config is deliberately a local, synthetic-credential configuration, not a vault.
type Config struct {
	Ingress IngressConfig   `json:"ingress,omitempty"`
	Limits  LimitsConfig    `json:"limits,omitempty"`
	Audit   AuditConfig     `json:"audit,omitempty"`
	Systems []System        `json:"systems"`
	Users   map[string]User `json:"users"`
}

// System 定义管理员配置的固定下游及认证方式；请求参数不能覆盖路由。
// 非空 QuotaSubject 相同的系统共享出站配额桶，不改变各用户的凭据与工具权限。
type System struct {
	QuotaSubject string         `json:"quota_subject,omitempty"`
	Name         string         `json:"name"`
	Endpoint     string         `json:"endpoint"`
	Auth         AuthConfig     `json:"auth,omitempty"`
	Network      *NetworkPolicy `json:"network,omitempty"`
	Timeouts     *TimeoutConfig `json:"timeouts,omitempty"`
	budgets      timeoutBudgets
	transport    http.RoundTripper
}

// UnmarshalJSON keeps strict nested decoding and distinguishes explicit null
// from omission. Programmatic nil Timeouts means the legacy default profile.
func (s *System) UnmarshalJSON(data []byte) error {
	type plain System
	fields, err := uniqueObjectFields(data)
	if err != nil {
		return err
	}
	for key := range fields {
		if strings.EqualFold(key, "timeouts") && key != "timeouts" {
			return errors.New("timeouts field must use canonical spelling")
		}
	}
	if value, ok := fields["timeouts"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return errors.New("timeouts must be an object")
	}
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*s = System(decoded)
	return nil
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

// User 是初始化身份的配置输入：Token 用于入口认证，Credentials 按系统保存
// 下游凭据，两者不可互换；Allowed 是完整公开工具名的显式白名单。
// 重开持久库时，已有授权和凭据以经过认证的存储状态为准，不重新导入这些种子值。
type User struct {
	TokenExpiresAt time.Time         `json:"token_expires_at,omitempty"`
	Tenant         string            `json:"tenant,omitempty"`
	Principal      string            `json:"principal,omitempty"`
	Token          string            `json:"token"`
	Allowed        []string          `json:"allowed"`
	Credentials    map[string]string `json:"credentials"`
}

// LoadConfig rejects unknown fields, trailing documents and oversized configuration.
// 此处只解码配置；系统拓扑、身份唯一性及网络策略等语义校验由构造网关时执行。
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

// uniqueObjectFields rejects duplicate case-insensitive keys before typed JSON
// decoding can silently merge them. Used for the new runtime configuration.
func uniqueObjectFields(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("expected configuration object")
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || seen[strings.ToLower(key)] {
			return nil, errors.New("duplicate configuration field")
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing configuration")
	}
	return fields, nil
}
