// Command connect submits synthetic credentials directly to a local gateway.
// Secrets are read from private files, never command-line values or environment.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var servicePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var errPrivate = errors.New("invalid private credential file")

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func gatewayURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("gateway must be an explicit synthetic loopback HTTP origin")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, pe := strconv.Atoi(port)
	if err != nil || pe != nil || n < 1 || n > 65535 || (host != "127.0.0.1" && host != "::1") || u.String() != raw {
		return nil, errors.New("gateway must be an explicit synthetic loopback HTTP origin")
	}
	return u, nil
}

type binding struct {
	System     string `json:"system"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
	Discovery  string `json:"discovery_status,omitempty"`
}

func safeBinding(b binding) bool {
	if !servicePattern.MatchString(b.System) || strings.Contains(b.System, "__") || b.Generation == 0 {
		return false
	}
	if b.Discovery != "" && b.Discovery != "available" && b.Discovery != "not_observed" {
		return false
	}
	switch b.State {
	case "unbound", "missing", "active", "expired", "revoked":
		return true
	}
	return false
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	gateway := fs.String("gateway", "", "explicit synthetic loopback gateway origin")
	entryPath := fs.String("entry-file", "", "owner-only gateway credential file")
	credentialPath := fs.String("credential-file", "", "owner-only provider credential file")
	service := fs.String("service", "", "configured service identifier")
	generation := fs.Uint64("generation", 0, "expected binding generation; obtain with --status")
	status := fs.Bool("status", false, "read authorized service status; no mutation")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid options; secrets must only be supplied through private files")
	}
	u, err := gatewayURL(*gateway)
	if err != nil {
		return err
	}
	if *status {
		if *credentialPath != "" || *service != "" || *generation != 0 {
			return errors.New("status cannot include submission options")
		}
	} else if *credentialPath == "" || *generation == 0 || !servicePattern.MatchString(*service) || strings.Contains(*service, "__") {
		return errors.New("submission requires credential-file, service, and nonzero generation")
	}
	entry, err := readPrivate(*entryPath, 43)
	if err != nil {
		return err
	}
	defer clear(entry)
	decoded, err := base64.RawURLEncoding.DecodeString(string(entry))
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != string(entry) {
		clear(decoded)
		return errors.New("invalid gateway credential format")
	}
	clear(decoded)
	method := http.MethodGet
	u.Path = "/binding/api/services"
	var payload []byte
	secrets := [][]byte{entry}
	if !*status {
		credential, err := readPrivate(*credentialPath, 4096)
		if err != nil {
			return err
		}
		defer clear(credential)
		secrets = append(secrets, credential)
		if credential[0] == ' ' || credential[len(credential)-1] == ' ' {
			return errors.New("invalid provider credential format")
		}
		// Only printable ASCII header values are supported by this bounded helper.
		for _, b := range credential {
			if b < 32 || b > 126 {
				return errors.New("invalid provider credential format")
			}
		}
		payload, err = json.Marshal(struct {
			Service    string `json:"service_id"`
			Generation uint64 `json:"expected_generation"`
			Credential string `json:"credential"`
		}{*service, *generation, string(credential)})
		if err != nil {
			return errors.New("invalid submission")
		}
		defer clear(payload)
		method = http.MethodPost
		u.Path = "/binding/api/credentials"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid request")
	}
	req.GetBody = nil // Never replay a secret-bearing request.
	req.Header.Set("Authorization", "Bearer "+string(entry))
	if !*status {
		req.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	unknown := errors.New("outcome_unknown: check --status before any explicit resubmission; no retry performed")
	if err != nil {
		if !*status {
			return unknown
		}
		return errors.New("status unavailable; no retry performed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(data)
	if err != nil || len(data) > 65536 {
		if !*status {
			return unknown
		}
		return errors.New("status unavailable")
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		switch failure.Error {
		case "version_conflict", "permission_denied", "entry_authentication_rejected", "invalid_request", "request_denied", "state_unavailable":
			return errors.New(failure.Error)
		}
		if !*status {
			return unknown
		}
		return errors.New("status unavailable")
	}
	if *status {
		var view struct {
			Services []binding `json:"services"`
		}
		if json.Unmarshal(data, &view) != nil || view.Services == nil {
			return errors.New("invalid status response")
		}
		for _, b := range view.Services {
			if !safeBinding(b) {
				return errors.New("invalid status response")
			}
		}
		return writeSafeResult(out, view, secrets)
	}
	var result struct {
		Saved     bool    `json:"binding_saved"`
		Binding   binding `json:"binding"`
		Discovery string  `json:"discovery_status"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Saved || !safeBinding(result.Binding) || result.Binding.System != *service || result.Binding.Generation != *generation+1 {
		return unknown
	}
	switch result.Discovery {
	case "ready", "unavailable", "not_completed":
	default:
		return unknown
	}
	if err := writeSafeResult(out, result, secrets); err != nil {
		return unknown
	}
	return nil
}

// Defense in depth: even valid-shaped fields from a malicious local endpoint
// cannot reflect a known credential into the terminal or model-visible output.
func writeSafeResult(out io.Writer, value any, secrets [][]byte) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("invalid response")
	}
	defer clear(data)
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		escaped, err := json.Marshal(string(secret))
		if err != nil {
			return errors.New("invalid response")
		}
		found := bytes.Contains(data, secret) || bytes.Contains(data, escaped[1:len(escaped)-1])
		clear(escaped)
		if found {
			return errors.New("invalid response")
		}
	}
	data = append(data, '\n')
	_, err = out.Write(data)
	return err
}
