package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var servers []*http.Server
	start := func(addr string, h http.Handler) string {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		servers = append(servers, s)
		go func() {
			if err := s.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Print(err)
				stop()
			}
		}()
		return "http://" + ln.Addr().String()
	}
	crm := start("127.0.0.1:0", mock.Handler("crm", map[string]string{"mock-crm-alice": "alice", "mock-crm-bob": "bob"}))
	docs := start("127.0.0.1:0", mock.Handler("docs", map[string]string{"mock-docs-alice": "alice"}))
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: crm}, {Name: "docs", Endpoint: docs}}, Users: map[string]gateway.User{
		"alice": {Token: "demo-alice", Allowed: []string{"crm__echo", "docs__echo"}, Credentials: map[string]string{"crm": "mock-crm-alice", "docs": "mock-docs-alice"}},
		"bob":   {Token: "demo-bob", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "mock-crm-bob"}},
	}})
	if err != nil {
		log.Fatal(err)
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, 30*time.Second)
	issues := g.Refresh(discoveryCtx)
	cancelDiscovery()
	for _, issue := range issues {
		log.Printf("discovery unavailable: user=%q system=%q", issue.User, issue.System)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", g.Handler())
	address := start("127.0.0.1:8080", mux)
	log.Printf("NONPRODUCTION SYNTHETIC DEMO: %s/mcp; bearer demo-alice or demo-bob", address)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
}
