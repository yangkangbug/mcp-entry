package gateway

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed account_assets/*
var accountAssets embed.FS

// AccountHandler is an opt-in, loopback-only own-account control surface.
// expectedOrigin must be supplied by the listener owner, never copied from a request.
// It does not relax the separate MCP handler's browser restrictions.
func (g *Gateway) AccountHandler(expectedOrigin string) (http.Handler, error) {
	u, err := url.Parse(expectedOrigin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" || u.Host == "" {
		return nil, errors.New("invalid account origin")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || (host != "127.0.0.1" && host != "::1") || u.String() != expectedOrigin {
		return nil, errors.New("invalid account origin")
	}
	if err := g.validateAccountAuth(); err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountHeaders(w)
		if r.Host != u.Host || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("Authorization")) > 1 {
			accountError(w, http.StatusForbidden, "request_denied")
			return
		}
		origin := r.Header.Get("Origin")
		site := r.Header.Get("Sec-Fetch-Site")
		if (origin != "" && origin != expectedOrigin) || (site != "" && site != "same-origin" && site != "none") || (r.Method == http.MethodPost && site != "" && origin != expectedOrigin) {
			accountError(w, http.StatusForbidden, "request_denied")
			return
		}
		if strings.Contains(r.URL.EscapedPath(), "%") {
			accountError(w, http.StatusNotFound, "not_found")
			return
		}
		switch r.URL.Path {
		case "/account", "/account/", "/account/assets/account.js", "/account/assets/account.css":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				accountError(w, http.StatusMethodNotAllowed, "method_not_allowed")
				return
			}
			asset, contentType := "account_assets/index.html", "text/html; charset=utf-8"
			if strings.HasSuffix(r.URL.Path, ".js") {
				asset, contentType = "account_assets/account.js", "text/javascript; charset=utf-8"
			}
			if strings.HasSuffix(r.URL.Path, ".css") {
				asset, contentType = "account_assets/account.css", "text/css; charset=utf-8"
			}
			data, err := accountAssets.ReadFile(asset)
			if err != nil {
				accountError(w, http.StatusServiceUnavailable, "unavailable")
				return
			}
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(data)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/account/api/bindings") {
			accountError(w, http.StatusNotFound, "not_found")
			return
		}
		identity, ok := g.authenticateEntry(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-entry"`)
			accountError(w, http.StatusUnauthorized, "entry_authentication_rejected")
			return
		}
		if r.URL.Path == "/account/api/bindings" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				accountError(w, http.StatusMethodNotAllowed, "method_not_allowed")
				return
			}
			bindings, err := g.AccountBindings(identity)
			if err != nil {
				accountFailure(w, err)
				return
			}
			output := make([]accountBinding, 0, len(bindings))
			for _, b := range bindings {
				output = append(output, accountBindingView(b))
			}
			accountJSON(w, http.StatusOK, struct {
				Tenant    string           `json:"tenant"`
				Principal string           `json:"principal"`
				Bindings  []accountBinding `json:"bindings"`
			}{identity.Tenant, identity.Principal, output})
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			accountError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		suffix := strings.TrimPrefix(r.URL.Path, "/account/api/bindings/")
		revoke := strings.HasSuffix(suffix, "/revoke")
		system := suffix
		if revoke {
			system = strings.TrimSuffix(system, "/revoke")
		}
		if !validPart(system) || len(system) > 64 {
			accountError(w, http.StatusNotFound, "not_found")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
			accountError(w, http.StatusUnsupportedMediaType, "json_required")
			return
		}
		fields, err := decodeAccountObject(w, r)
		if err != nil {
			accountError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var expected uint64
		if err := json.Unmarshal(fields["expected_generation"], &expected); err != nil || expected == 0 {
			accountError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var info BindingInfo
		if revoke {
			if len(fields) != 1 {
				accountError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			info, err = g.revokeOwnBinding(identity, system, expected)
		} else {
			for key := range fields {
				if key != "expected_generation" && key != "credential" && key != "expires_at" {
					accountError(w, http.StatusBadRequest, "invalid_request")
					return
				}
			}
			var credential string
			if err := json.Unmarshal(fields["credential"], &credential); err != nil || credential == "" || len(credential) > 4096 {
				accountError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			var expires time.Time
			if raw, exists := fields["expires_at"]; exists {
				var value string
				if err := json.Unmarshal(raw, &value); err != nil || value == "" {
					accountError(w, http.StatusBadRequest, "invalid_request")
					return
				}
				expires, err = time.Parse(time.RFC3339Nano, value)
				if err != nil || !expires.After(time.Now()) {
					accountError(w, http.StatusBadRequest, "invalid_request")
					return
				}
			}
			info, err = g.replaceOwnBinding(identity, system, expected, credential, expires)
			credential = ""
		}
		if err != nil {
			accountFailure(w, err)
			return
		}
		result := struct {
			Binding accountBinding     `json:"binding"`
			Hint    string             `json:"hint"`
			Failure *DownstreamFailure `json:"discovery_failure,omitempty"`
		}{Binding: accountBindingView(info), Hint: "Binding revoked."}
		if !revoke {
			// Refresh only this own binding, without holding authorization locks
			// during network I/O. Return no other user's discovery issues.
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			issues := g.RefreshBinding(ctx, identity, system)
			cancel()
			result.Hint = "Replacement saved. Discovery completed; tools remain subject to your policy."
			for _, issue := range issues {
				if issue.User == g.identities[identity] && issue.System == system {
					result.Hint = "Replacement saved, but downstream discovery is unavailable. Check status and provider access before replacing again."
					result.Failure = issue.Failure
					if issue.Failure != nil {
						switch issue.Failure.Code {
						case FailureAuthentication:
							result.Hint = "Replacement saved, but the provider rejected authentication. Check the credential and rebind if needed; this does not prove expiry or revocation."
						case FailurePermission:
							result.Hint = "Replacement saved, but the provider denied permission. Check provider permissions; this does not mean the credential expired."
						}
					}
					break
				}
			}
			if ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled) {
				result.Hint = "Replacement saved; discovery did not finish. Check status before retrying."
			}
		}
		accountJSON(w, http.StatusOK, result)
	}), nil
}

type accountBinding struct {
	System     string       `json:"system"`
	Generation uint64       `json:"generation"`
	State      BindingState `json:"state"`
	ExpiresAt  *time.Time   `json:"expires_at,omitempty"`
	Hint       string       `json:"hint,omitempty"`
}

func accountBindingView(b BindingInfo) accountBinding {
	v := accountBinding{System: b.System, Generation: b.Generation, State: b.State}
	if !b.ExpiresAt.IsZero() {
		expiry := b.ExpiresAt
		v.ExpiresAt = &expiry
	}
	if b.State == BindingActive && !b.ExpiresAt.IsZero() && !b.ExpiresAt.After(time.Now()) {
		v.State = BindingState("expired")
	}
	switch v.State {
	case BindingState("expired"):
		v.Hint = "Local expiry reached. Obtain a fresh provider credential and save a replacement."
	case BindingUnbound, BindingRevoked:
		v.Hint = "Save a provider credential to connect."
	case BindingActive:
		v.Hint = "Credential stored. This does not prove current provider access."
	}
	return v
}
func accountHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
}
func accountJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func accountError(w http.ResponseWriter, status int, code string) {
	accountJSON(w, status, struct {
		Error string `json:"error"`
	}{code})
}
func accountFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrConflict):
		accountError(w, http.StatusConflict, "version_conflict")
	case errors.Is(err, ErrDenied):
		accountError(w, http.StatusForbidden, "permission_denied")
	case errors.Is(err, ErrStorage), errors.Is(err, ErrClosed):
		accountError(w, http.StatusServiceUnavailable, "state_unavailable")
	default:
		accountError(w, http.StatusBadRequest, "invalid_request")
	}
}

// Decode a bounded single JSON object and reject duplicate/unknown field ambiguity.
func decodeAccountObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid request")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid request")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("invalid request")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid request")
	}
	return fields, nil
}
