package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

var errCredentials = errors.New("invalid credentials file: use private regular JSON with known users and nonempty, nonconflicting credentials")

// This is a bootstrap input, not an import operation against persisted state.
// Topology, policy, identity and expiry remain exclusively in the config.
func loadCredentials(cfg gateway.Config, path string) (gateway.Config, error) {
	data, err := readTLSMaterial(path, true, 256<<10)
	if err != nil {
		return cfg, errCredentials
	}
	defer clear(data)
	if err := uniqueJSONKeys(json.NewDecoder(bytes.NewReader(data))); err != nil || !credentialFieldsExact(data) {
		return cfg, errCredentials
	}
	var input struct {
		Users map[string]struct {
			Token       *string           `json:"token"`
			Credentials map[string]string `json:"credentials"`
		} `json:"users"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Users) == 0 {
		return cfg, errCredentials
	}
	users := make(map[string]gateway.User, len(cfg.Users))
	for id, user := range cfg.Users {
		users[id] = user
	}
	systems := make(map[string]bool, len(cfg.Systems))
	for _, system := range cfg.Systems {
		systems[system.Name] = true
	}
	for id, source := range input.Users {
		user, ok := users[id]
		if !ok || (source.Token == nil && len(source.Credentials) == 0) {
			return cfg, errCredentials
		}
		if source.Token != nil {
			if *source.Token == "" || user.Token != "" {
				return cfg, errCredentials
			}
			user.Token = *source.Token
		}
		credentials := make(map[string]string, len(user.Credentials)+len(source.Credentials))
		for system, value := range user.Credentials {
			credentials[system] = value
		}
		for system, value := range source.Credentials {
			_, conflict := credentials[system]
			if !systems[system] || conflict || value == "" {
				return cfg, errCredentials
			}
			credentials[system] = value
		}
		user.Credentials = credentials
		users[id] = user
	}
	cfg.Users = users
	return cfg, nil
}

// Reject duplicate object members rather than silently choosing the last secret.
func uniqueJSONKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errCredentials
			}
			seen[name] = true
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	default:
		return errCredentials
	}
	_, err = decoder.Token()
	return err
}

// New validates and constructs only local state. Never Refresh here: a successful
// preflight is not evidence of downstream reachability, discovery or storage health.
func checkConfig(cfg gateway.Config, output io.Writer) error {
	g, err := gateway.New(cfg)
	if err != nil {
		return err
	}
	if err := g.Close(); err != nil {
		return err
	}
	result := struct {
		Valid            bool   `json:"valid"`
		Scope            string `json:"scope"`
		Systems          int    `json:"systems"`
		Users            int    `json:"users"`
		DiscoveryChecked bool   `json:"discovery_checked"`
		StorageChecked   bool   `json:"storage_checked"`
	}{Valid: true, Scope: "bootstrap-config", Systems: len(cfg.Systems), Users: len(cfg.Users)}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("cannot write configuration check result")
	}
	return nil
}

// encoding/json otherwise accepts case-insensitive struct keys and null scalars.
// Keep the secret envelope exact, while user/system IDs remain case-sensitive.
func credentialFieldsExact(data []byte) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || len(root) != 1 {
		return false
	}
	var users map[string]map[string]json.RawMessage
	if json.Unmarshal(root["users"], &users) != nil || len(users) == 0 {
		return false
	}
	for _, fields := range users {
		if len(fields) == 0 {
			return false
		}
		for name, value := range fields {
			if name != "token" && name != "credentials" {
				return false
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return false
			}
		}
	}
	return true
}
