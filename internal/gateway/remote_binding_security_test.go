package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real network requests independently verify that trusted-looking HTTP metadata
// cannot manufacture TLS or identity, and rejected attempts do not consume links.
func TestRemoteBindingSecurityActualTransportAndOtherOwner(t *testing.T) {
	g, _, alice, bob := accountFixture(t)
	h, err := g.HTTPSClientBindingHandler(httpsBindingOrigin)
	if err != nil {
		t.Fatal(err)
	}
	fields := httpsBindingSession(t, g)
	plain := httptest.NewServer(h)
	defer plain.Close()
	encrypted := httptest.NewTLSServer(h)
	defer encrypted.Close()
	post := func(server *httptest.Server, path, token string, body map[string]any, forged bool) (int, string) {
		t.Helper()
		data, _ := json.Marshal(body)
		req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "connect.example.test"
		req.Header.Set("Origin", httpsBindingOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if forged {
			req.Header.Set("Forwarded", "proto=https;host=connect.example.test")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "connect.example.test")
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(result)
	}
	for _, forged := range []bool{false, true} {
		if code, body := post(plain, "/binding/api/session/confirm", alice, fields, forged); code != http.StatusForbidden {
			t.Fatalf("plaintext accepted: %d %s", code, body)
		}
	}
	for _, action := range []string{"inspect", "cancel", "confirm"} {
		submitted := map[string]any{"session_locator": fields["session_locator"], "capability": fields["capability"]}
		if action == "confirm" {
			submitted = fields
		}
		code, body := post(encrypted, "/binding/api/session/"+action, bob, submitted, false)
		if code != http.StatusForbidden || strings.Contains(body, "alice") || strings.Contains(body, fields["capability"].(string)) {
			t.Fatalf("other owner got details/access: %d %s", code, body)
		}
	}
	direct := map[string]any{"service_id": "crm", "expected_generation": 1, "credential": "a-replacement"}
	if code, body := post(encrypted, "/binding/api/credentials", alice, direct, false); code != http.StatusNotFound {
		t.Fatalf("legacy write exposed: %d %s", code, body)
	}
	before, err := g.Binding(integratedIdentity, "crm")
	if err != nil || before.Generation != 1 {
		t.Fatalf("rejections mutated binding: %+v %v", before, err)
	}
	inspect := map[string]any{"session_locator": fields["session_locator"], "capability": fields["capability"]}
	if code, body := post(encrypted, "/binding/api/session/inspect", alice, inspect, false); code != http.StatusOK {
		t.Fatalf("rejections consumed session: %d %s", code, body)
	}
	if code, body := post(encrypted, "/binding/api/session/confirm", alice, fields, false); code != http.StatusOK {
		t.Fatalf("owner save failed: %d %s", code, body)
	}
	after, err := g.Binding(integratedIdentity, "crm")
	if err != nil || after.Generation != 2 {
		t.Fatalf("save not unique: %+v %v", after, err)
	}
}
