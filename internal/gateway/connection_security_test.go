package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func securityLink(t *testing.T, g *Gateway) (string, string) {
	t.Helper()
	out, e := g.beginConnection(context.Background(), "alice", "crm", 1)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(strings.Split(out["authorization_url"].(string), "#")[1], ".")
	return parts[0], parts[1]
}
func securityRequest(h http.Handler, token, action, locator, capability string, extra map[string]any) *httptest.ResponseRecorder {
	fields := map[string]any{"session_locator": locator, "capability": capability}
	for k, v := range extra {
		fields[k] = v
	}
	b, _ := json.Marshal(fields)
	return accountRequest(h, "POST", "/binding/api/session/"+action, token, string(b), nil)
}
func securityConfirm(h http.Handler, token, l, c string) *httptest.ResponseRecorder {
	return securityRequest(h, token, "confirm", l, c, map[string]any{"confirm": true, "credential": "a-replacement"})
}

func TestConnectionSecurityIdentityAndReadBoundary(t *testing.T) {
	g, _, alice, bob := accountFixture(t)
	h, e := g.ClientBindingHandler("http://127.0.0.1:8080")
	if e != nil {
		t.Fatal(e)
	}
	l, c := securityLink(t, g)
	for _, token := range []string{"", bob, "not-user-entry"} {
		for _, action := range []string{"inspect", "confirm", "cancel"} {
			extra := map[string]any{}
			if action == "confirm" {
				extra = map[string]any{"confirm": true, "credential": "a-replacement"}
			}
			w := securityRequest(h, token, action, l, c, extra)
			if w.Code < 400 {
				t.Fatalf("%s unauthorized succeeded", action)
			}
		}
	}
	for _, action := range []string{"inspect", "confirm", "cancel"} {
		w := accountRequest(h, "GET", "/binding/api/session/"+action, alice, "", nil)
		if w.Code < 400 {
			t.Fatal("GET API succeeded")
		}
	}
	w := accountRequest(h, "GET", "/binding/", "", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, key := range []string{"Cache-Control", "Referrer-Policy", "Content-Security-Policy", "X-Frame-Options"} {
		if w.Header().Get(key) == "" {
			t.Fatal("missing", key)
		}
	}
	if w := securityRequest(h, alice, "inspect", l, c, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := securityRequest(h, alice, "confirm", l, c, map[string]any{"confirm": false, "credential": "a-replacement"}); w.Code != 400 {
		t.Fatal("no confirm", w.Code)
	}
	info, _ := g.Binding(integratedIdentity, "crm")
	if info.Generation != 1 {
		t.Fatal("read/reject mutated")
	}
	if w := securityConfirm(h, alice, l, c); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := securityConfirm(h, alice, l, c); w.Code < 400 {
		t.Fatal("replay")
	}
	if w := securityRequest(h, bob, "inspect", l, c, nil); strings.Contains(w.Body.String(), "alice") || strings.Contains(w.Body.String(), c) {
		t.Fatal("leak")
	}
}
func TestConnectionSecurityInvalidation(t *testing.T) {
	for _, which := range []string{"entry", "policy", "binding", "system", "expired", "disabled"} {
		t.Run(which, func(t *testing.T) {
			g, h, token := clientFixture(t)
			l, c := securityLink(t, g)
			switch which {
			case "entry":
				g.mu.Lock()
				p := clonePrincipal(g.principals["alice"])
				p.entry.Generation++
				g.principals["alice"] = p
				g.mu.Unlock()
			case "policy":
				if _, err := g.SetPolicy(integratedIdentity, 1, []string{"crm__echo"}); err != nil {
					t.Fatal(err)
				}
			case "binding":
				if _, err := g.ReplaceBinding(integratedIdentity, "crm", 1, "a-replacement"); err != nil {
					t.Fatal(err)
				}
			case "system":
				g.mu.Lock()
				s := g.systems["crm"]
				s.revision++
				g.systems["crm"] = s
				g.mu.Unlock()
			case "expired":
				g.mu.Lock()
				g.connectionSessions[l].expires = time.Now().Add(-time.Second)
				g.mu.Unlock()
			case "disabled":
				if _, err := g.DisablePrincipal(integratedIdentity, 1); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := g.Binding(integratedIdentity, "crm")
			w := securityConfirm(h, token, l, c)
			if w.Code < 400 {
				t.Fatal("stale succeeded")
			}
			after, _ := g.Binding(integratedIdentity, "crm")
			if after.Generation != before.Generation {
				t.Fatal("stale changed binding")
			}
		})
	}
}
func TestConnectionSecurityRaces(t *testing.T) {
	for _, different := range []bool{true} {
		t.Run(map[bool]string{false: "same", true: "different"}[different], func(t *testing.T) {
			g, h, token := clientFixture(t)
			l, c := securityLink(t, g)
			l2, c2 := l, c
			if different {
				l2, c2 = securityLink(t, g)
			}
			start := make(chan struct{})
			codes := make(chan int, 8)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					ll, cc := l, c
					if i%2 == 1 {
						ll, cc = l2, c2
					}
					codes <- securityConfirm(h, token, ll, cc).Code
				}(i)
			}
			close(start)
			wg.Wait()
			close(codes)
			success := 0
			for code := range codes {
				if code == 200 {
					success++
				}
			}
			if success != 1 {
				t.Fatalf("successes %d", success)
			}
			b, _ := g.Binding(integratedIdentity, "crm")
			if b.Generation != 2 {
				t.Fatal(b.Generation)
			}
		})
	}
}
func TestConnectionSecurityStatusNotInferred(t *testing.T) {
	g, _, _ := clientFixture(t)
	l, _ := securityLink(t, g)
	if _, err := g.ReplaceBinding(integratedIdentity, "crm", 1, "a-replacement"); err != nil {
		t.Fatal(err)
	}
	out, e := g.connectionStatus(context.Background(), "alice", l)
	if e != nil {
		t.Fatal(e)
	}
	if out["binding_saved"] != nil || out["saved_generation"] != nil {
		t.Fatal("external update fabricated receipt", out)
	}
}
func TestConnectionSecurityBoundary(t *testing.T) {
	g, h, token := clientFixture(t)
	l, c := securityLink(t, g)
	b, _ := json.Marshal(map[string]any{"session_locator": l, "capability": c, "credential": "a-replacement", "confirm": true})
	for _, headers := range []map[string]string{{"Origin": "http://evil.invalid"}, {"Sec-Fetch-Site": "cross-site"}, {"Cookie": "session=x"}, {"Content-Type": "text/plain"}} {
		w := accountRequest(h, "POST", "/binding/api/session/confirm", token, string(b), headers)
		if w.Code < 400 {
			t.Fatal("boundary", headers)
		}
	}
	for _, path := range []string{"/binding/api/session/confirm?x=secret", "/binding/api/session/%63onfirm"} {
		w := accountRequest(h, "POST", path, token, string(b), nil)
		if w.Code < 400 {
			t.Fatal("path boundary")
		}
	}
	if _, e := g.ClientBindingHandler("http://127.0.0.1:8081"); e == nil {
		t.Fatal("origin mutable")
	}
	if w := securityConfirm(h, token, l, c); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestConnectionSecurityFailedAttemptCannotReplay(t *testing.T) {
	g, h, token := clientFixture(t)
	l, c := securityLink(t, g)
	w := securityRequest(h, token, "confirm", l, c, map[string]any{"confirm": true, "credential": "bad\nsecret"})
	if w.Code < 400 {
		t.Fatal("invalid credential accepted")
	}
	if w := securityConfirm(h, token, l, c); w.Code < 400 {
		t.Fatal("attempted link reused")
	}
	info, _ := g.Binding(integratedIdentity, "crm")
	if info.Generation != 1 {
		t.Fatal("invalid attempt wrote")
	}
	out, e := g.connectionStatus(context.Background(), "alice", l)
	if e != nil || out["save_outcome"] != "unknown" || out["binding_saved"] != nil {
		t.Fatal("uncertain attempt misreported", out, e)
	}
}
