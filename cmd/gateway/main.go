// Command gateway starts only the entry point; it never starts downstream services.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

func run() error {
	configPath := flag.String("config", "configs/demo.json", "synthetic local configuration file")
	listen := flag.String("listen", "127.0.0.1:8080", "literal loopback listen address")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return errors.New("listen address must use literal loopback IP")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.New("cannot open configuration")
	}
	cfg, err := gateway.LoadConfig(file)
	file.Close()
	if err != nil {
		return err
	}
	g, err := gateway.New(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	issues := g.Refresh(discoveryCtx)
	cancel()
	for _, issue := range issues {
		log.Printf("discovery unavailable: user=%q system=%q", issue.User, issue.System)
	}
	if ctx.Err() != nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", g.Handler())
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("NONPRODUCTION SYNTHETIC GATEWAY: http://%s/mcp; %d discovery issue(s); no downstreams started", listener.Addr(), len(issues))
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
