package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Config is deliberately a local, synthetic-credential configuration, not a vault.
type Config struct {
	Systems []System        `json:"systems"`
	Users   map[string]User `json:"users"`
}

type System struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
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
