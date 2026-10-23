package gateway

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
)

func independentApply(t *testing.T, g *Gateway, ss []System) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	m, s, a, u, e := g.runtimeCandidateLocked(g.configRevisionLocked(), ss)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.applyRuntimeConfigLocked(m, s, a, u); e != nil {
		t.Fatal(e)
	}
}
func TestIndependentRuntimeRefreshRace(t *testing.T) {
	g, e := NewPersistent(Config{}, maintenanceOptions(t))
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			g.Refresh(context.Background())
		}
	}()
	ss := []System{}
	for i := 0; i < 16; i++ {
		ss = append(ss, System{Name: fmt.Sprintf("s%d", i), Endpoint: "http://127.0.0.1:1/mcp"})
		independentApply(t, g, ss)
	}
	wg.Wait()
}
func TestIndependentRuntimeDowngradeAndKeyRotation(t *testing.T) {
	for _, attack := range []string{"DROP TABLE runtime_config", "DELETE FROM runtime_config", "UPDATE runtime_config SET revision=2"} {
		t.Run(attack, func(t *testing.T) {
			cfg := Config{}
			o := maintenanceOptions(t)
			g, e := NewPersistent(cfg, o)
			if e != nil {
				t.Fatal(e)
			}
			independentApply(t, g, []System{{Name: "s", Endpoint: "http://127.0.0.1:1/mcp"}})
			g.Close()
			o.Initialize = false
			m, e := OpenMaintenance(cfg, o)
			if e != nil {
				t.Fatal(e)
			}
			o.Key = bytes.Repeat([]byte{8}, 32)
			if e = m.RotateKey(o.Key); e != nil {
				t.Fatal(e)
			}
			m.Close()
			g, e = NewPersistent(cfg, o)
			if e != nil {
				t.Fatal(e)
			}
			if len(g.systems) != 1 {
				t.Fatal("lost runtime")
			}
			g.Close()
			maintenanceSQL(t, o.Path, attack)
			g, e = NewPersistent(cfg, o)
			if e == nil {
				g.Close()
				t.Fatal("tamper downgrade accepted")
			}
		})
	}
}
