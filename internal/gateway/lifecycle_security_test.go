package gateway

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIndependentTicketCapacityExpiry(t *testing.T) {
	g, e := NewPersistent(maintenanceConfig(), maintenanceOptions(t))
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	tickets := map[string]lifecycleConfirmation{}
	req := lifecycleRequest{Action: "create_user", Tenant: "review", Principal: "review", Preview: true}
	for i := 0; i < 64; i++ {
		req.Principal = fmt.Sprint(i)
		w := httptest.NewRecorder()
		g.adminLifecycle(w, req, tickets)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	g.adminLifecycle(w, req, tickets)
	if w.Code != 429 {
		t.Fatal("capacity", w.Code)
	}
	for k, v := range tickets {
		v.ExpiresAt = time.Now().Add(-time.Second)
		tickets[k] = v
	}
	req.Preview = false
	req.Confirm = true
	for k := range tickets {
		req.ConfirmationID = k
		break
	}
	w = httptest.NewRecorder()
	g.adminLifecycle(w, req, tickets)
	if w.Code != 409 || len(tickets) != 0 {
		t.Fatal("expired", w.Code, len(tickets))
	}
}
func TestIndependentCreateRotateKeyAndTamper(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, e := NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	h := adminTestHandler(t, g)
	c := lifecyclePreview(t, h, lifecycleRequest{Action: "create_user", Tenant: "review", Principal: "review"})
	if w := lifecyclePost(h, c); w.Code != 200 {
		t.Fatal(w.Code)
	}
	g.Close()
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if e = m.RotateKey(key); e != nil {
		t.Fatal(e)
	}
	m.Close()
	opts.Key = key
	g, e = NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	p, e := g.Policy(Identity{"review", "review"})
	if e != nil || len(p.Allowed) != 0 {
		t.Fatal(e, p)
	}
	g.Close()
	maintenanceSQL(t, opts.Path, "UPDATE principals SET principal='tampered' WHERE tenant='review'")
	if g, e = NewPersistent(cfg, opts); e == nil {
		g.Close()
		t.Fatal("tampering accepted")
	}
}
func TestIndependentCreateAtomicMetaFailure(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, e := NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	h := adminTestHandler(t, g)
	c := lifecyclePreview(t, h, lifecycleRequest{Action: "create_user", Tenant: "review", Principal: "review"})
	if _, e := g.store.conn.ExecContext(context.Background(), "CREATE TRIGGER independent_fail BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT,'synthetic'); END"); e != nil {
		t.Fatal(e)
	}
	w := lifecyclePost(h, c)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"token"`) || !g.closed {
		t.Fatal(w.Code, g.closed, w.Body)
	}
	g.Close()
	maintenanceSQL(t, opts.Path, "DROP TRIGGER independent_fail")
	opts.Initialize = false
	g, e = NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	if _, ok := g.identities[Identity{"review", "review"}]; ok {
		t.Fatal("partial create")
	}
}
