// Command mock explicitly starts one fixed, synthetic loopback MCP downstream.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func parse(args []string) (string, string, error) {
	fs := flag.NewFlagSet("mock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	system := fs.String("system", "crm", "crm or docs synthetic system")
	address := fs.String("listen", "127.0.0.1:9001", "literal loopback address")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return "", "", errors.New("invalid mock options: use -system crm|docs -listen literal-loopback:port")
	}
	host, port, err := net.SplitHostPort(*address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 0 || number > 65535 || (host != "127.0.0.1" && host != "::1") || (*system != "crm" && *system != "docs") {
		return "", "", errors.New("mock requires crm or docs and a literal loopback address")
	}
	return *system, *address, nil
}
func run() error {
	system, address, err := parse(os.Args[1:])
	if err != nil {
		return err
	}
	credentials := map[string]string{"mock-crm-alice": "alice", "mock-crm-bob": "bob"}
	if system == "docs" {
		credentials = map[string]string{"mock-docs-alice": "alice"}
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("cannot bind mock listener")
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mux := http.NewServeMux()
	mux.Handle("/mcp", mock.Handler(system, credentials))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("NONPRODUCTION SYNTHETIC MOCK: system=%s http://%s/mcp", system, listener.Addr())
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("mock server stopped")
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.Close()
			return errors.New("mock shutdown incomplete")
		}
		return nil
	}
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
