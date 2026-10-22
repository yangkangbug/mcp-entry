// Command gateway runs a synthetic gateway or a trusted offline operator.
// Remote test ingress requires explicit opt-in and never enables account pages.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

type toolFlags []string

func (t *toolFlags) String() string         { return "" }
func (t *toolFlags) Set(value string) error { *t = append(*t, value); return nil }

type options struct {
	allowRemoteTest, allowInsecureHTTPTest                            bool
	tlsCert, tlsKey                                                   string
	config, listen, db, keyFile, operation, tenant, principal, system string
	keyStdin, initialize, account                                     bool
	expected                                                          uint64
	allowed                                                           toolFlags
}

var errOptions = errors.New("invalid command options; use -help for supported combinations")

func parseOptions(args []string, help io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.allowRemoteTest, "allow-remote-test", false, "serve only: explicitly permit remote synthetic MCP testing; strong finite entry auth required")
	fs.BoolVar(&o.allowInsecureHTTPTest, "allow-insecure-http-test", false, "serve only: explicitly permit plaintext remote testing; credentials are not encrypted")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "serve only: PEM server certificate file")
	fs.StringVar(&o.tlsKey, "tls-key", "", "serve only: private PEM server key file")
	fs.StringVar(&o.config, "config", "configs/demo.json", "synthetic local configuration file")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "serve only: literal IP listen address; loopback unless remote test explicitly enabled")
	fs.StringVar(&o.db, "db", "", "optional local SQLite path; existing file required unless -init-db")
	fs.StringVar(&o.keyFile, "key-file", "", "private regular file containing exactly 32 raw synthetic key bytes")
	fs.BoolVar(&o.keyStdin, "key-stdin", false, "read exactly 32 raw synthetic key bytes followed by EOF from stdin")
	fs.BoolVar(&o.account, "account", false, "serve only: enable local own-binding page; requires strong finite entry credentials")
	fs.BoolVar(&o.initialize, "init-db", false, "serve only: explicitly initialize a nonexistent database")
	fs.StringVar(&o.operation, "operation", "serve", "serve, status, revoke-binding, disable-principal, or set-policy")
	fs.StringVar(&o.tenant, "tenant", "", "offline only: configured synthetic tenant")
	fs.StringVar(&o.principal, "principal", "", "offline only: configured synthetic principal")
	fs.StringVar(&o.system, "system", "", "revoke-binding requires system; status optionally filters system")
	fs.Uint64Var(&o.expected, "expected-version", 0, "mutation CAS: binding generation for revoke, policy version otherwise")
	fs.Var(&o.allowed, "allow", "set-policy only: repeat for each full tool name; omission clears policy")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(help)
			fs.PrintDefaults()
			return o, flag.ErrHelp
		}
		return o, errOptions
	}
	if fs.NArg() != 0 {
		return o, errOptions
	}
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if seen["db"] && o.db == "" || seen["key-file"] && o.keyFile == "" || seen["key-stdin"] && !o.keyStdin {
		return o, errOptions
	}
	if o.db == "" {
		if seen["key-file"] || seen["key-stdin"] || seen["init-db"] {
			return o, errOptions
		}
	} else if (o.keyFile != "") == o.keyStdin {
		return o, errOptions
	}
	if o.operation == "serve" {
		for _, name := range []string{"tenant", "principal", "system", "expected-version", "allow"} {
			if seen[name] {
				return o, errOptions
			}
		}
		host, port, err := net.SplitHostPort(o.listen)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 0 || n > 65535 || net.ParseIP(host) == nil {
			return o, errOptions
		}
		if !o.allowRemoteTest && host != "127.0.0.1" && host != "::1" {
			return o, errOptions
		}
		if (o.tlsCert == "") != (o.tlsKey == "") || seen["tls-cert"] && o.tlsCert == "" || seen["tls-key"] && o.tlsKey == "" {
			return o, errOptions
		}
		if o.allowInsecureHTTPTest && (!o.allowRemoteTest || o.tlsCert != "") {
			return o, errOptions
		}
		if o.allowRemoteTest && o.tlsCert == "" && !o.allowInsecureHTTPTest {
			return o, errOptions
		}
		if o.account && (o.allowRemoteTest || o.tlsCert != "") {
			return o, errOptions
		}
		return o, nil
	}
	if seen["allow-remote-test"] || seen["allow-insecure-http-test"] || seen["tls-cert"] || seen["tls-key"] || seen["listen"] || seen["init-db"] || seen["account"] || o.db == "" || o.tenant == "" || o.principal == "" {
		return o, errOptions
	}
	switch o.operation {
	case "status":
		if seen["expected-version"] || seen["allow"] {
			return o, errOptions
		}
	case "revoke-binding":
		if o.system == "" || o.expected == 0 || seen["allow"] {
			return o, errOptions
		}
	case "disable-principal":
		if o.expected == 0 || seen["system"] || seen["allow"] {
			return o, errOptions
		}
	case "set-policy":
		if o.expected == 0 || seen["system"] {
			return o, errOptions
		}
	default:
		return o, errOptions
	}
	return o, nil
}

func readKey(o options, stdin io.Reader) ([]byte, error) {
	if o.db == "" {
		return nil, nil
	}
	source := stdin
	if o.keyFile != "" {
		info, err := os.Lstat(o.keyFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
			return nil, errors.New("invalid private key file")
		}
		file, err := os.Open(o.keyFile)
		if err != nil {
			return nil, errors.New("cannot read private key file")
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
			return nil, errors.New("invalid private key file")
		}
		source = file
	}
	key, err := io.ReadAll(io.LimitReader(source, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.New("key input must contain exactly 32 raw bytes followed by EOF")
	}
	return key, nil
}

func operate(g *gateway.Gateway, cfg gateway.Config, o options, output io.Writer) error {
	identity := gateway.Identity{Tenant: o.tenant, Principal: o.principal}
	var result any
	var err error
	switch o.operation {
	case "status":
		policy, e := g.Policy(identity)
		if e != nil {
			return e
		}
		bindings := []gateway.BindingInfo{}
		for _, system := range cfg.Systems {
			if o.system != "" && o.system != system.Name {
				continue
			}
			binding, e := g.Binding(identity, system.Name)
			if e != nil {
				return e
			}
			bindings = append(bindings, binding)
		}
		if o.system != "" && len(bindings) == 0 {
			return gateway.ErrDenied
		}
		result = struct {
			Policy   gateway.PolicyInfo
			Bindings []gateway.BindingInfo
		}{policy, bindings}
	case "revoke-binding":
		result, err = g.RevokeBinding(identity, o.system, o.expected)
	case "disable-principal":
		result, err = g.DisablePrincipal(identity, o.expected)
	case "set-policy":
		result, err = g.SetPolicy(identity, o.expected, o.allowed)
	default:
		return errOptions
	}
	if err != nil {
		return err
	}
	if err = json.NewEncoder(output).Encode(result); err != nil {
		return errors.New("cannot write operation result; inspect persisted status before retrying")
	}
	return nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	o, err := parseOptions(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if o.allowRemoteTest {
		info, err := os.Lstat(o.config)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("remote test requires a private regular configuration file")
		}
	}
	file, err := os.Open(o.config)
	if err != nil {
		return errors.New("cannot open configuration")
	}
	if o.allowRemoteTest {
		info, statErr := file.Stat()
		named, nameErr := os.Lstat(o.config)
		if statErr != nil || nameErr != nil || !info.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Mode().Perm()&0077 != 0 {
			file.Close()
			return errors.New("remote test requires a private regular configuration file")
		}
	}
	cfg, err := gateway.LoadConfig(file)
	file.Close()
	if err != nil {
		return err
	}
	if o.account || o.allowRemoteTest {
		preview, err := gateway.New(cfg)
		if err != nil {
			return err
		}
		if o.allowRemoteTest {
			err = preview.ValidateTestEntryAuth()
		} else {
			_, err = preview.AccountHandler("http://127.0.0.1:1")
		}
		preview.Close()
		if err != nil {
			return err
		}
	}
	tlsConfig, err := readServerTLS(o.tlsCert, o.tlsKey)
	if err != nil {
		return err
	}
	key, err := readKey(o, stdin)
	if err != nil {
		return err
	}
	defer clear(key)
	var g *gateway.Gateway
	if o.db != "" {
		g, err = gateway.NewPersistent(cfg, gateway.PersistenceOptions{Path: o.db, Key: key, Initialize: o.initialize})
	} else {
		g, err = gateway.New(cfg)
	}
	if err != nil {
		return err
	}
	defer g.Close()
	if o.operation != "serve" {
		return operate(g, cfg, o, stdout)
	}
	if o.allowRemoteTest {
		if err := g.ValidateTestEntryAuth(); err != nil {
			return err
		}
	}
	// Invalid persistence must not open a socket. Explicit initialization may
	// already have committed if binding fails; retry by reopening, never delete.
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return errors.New("cannot bind configured listener")
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	issues := g.Refresh(discoveryCtx)
	cancel()
	logger := log.New(stderr, "", log.LstdFlags)
	for _, issue := range issues {
		logger.Printf("discovery unavailable: user=%q system=%q", issue.User, issue.System)
	}
	if ctx.Err() != nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", g.Handler())
	if o.account {
		account, err := g.AccountHandler("http://" + listener.Addr().String())
		if err != nil {
			return err
		}
		mux.Handle("/account", account)
		mux.Handle("/account/", account)
	}
	server := &http.Server{TLSConfig: tlsConfig, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			done <- server.ServeTLS(listener, "", "")
		} else {
			done <- server.Serve(listener)
		}
	}()
	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}
	if o.allowRemoteTest {
		logger.Print("REMOTE SYNTHETIC TEST MODE: not a production deployment")
	}
	if o.allowInsecureHTTPTest {
		logger.Print("WARNING: remote plaintext HTTP exposes entry credentials and traffic; isolated synthetic testing only")
	}
	for _, system := range cfg.Systems {
		if system.Network != nil && system.Network.AllowInsecureHTTP {
			logger.Print("WARNING: explicit plaintext downstream policy cannot encrypt credentials or traffic")
			break
		}
	}
	logger.Printf("NONPRODUCTION SYNTHETIC GATEWAY: %s://%s/mcp; %d discovery issue(s); no downstreams started", scheme, listener.Addr(), len(issues))
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("gateway HTTP server stopped")
		}
		return nil
	case <-ctx.Done():
		// Stop admission and cancel detached downstream work before waiting for HTTP.
		closeErr := g.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return errors.New("gateway shutdown incomplete")
		}
		return closeErr
	}
}
func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func readTLSMaterial(path string, private bool, limit int64) ([]byte, error) {
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || named.Size() > limit || private && named.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid TLS material file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read TLS material")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(named, info) || !info.Mode().IsRegular() || private && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid TLS material file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("invalid TLS material")
	}
	return data, nil
}
func readServerTLS(certPath, keyPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	cert, err := readTLSMaterial(certPath, false, 256<<10)
	if err != nil {
		return nil, err
	}
	key, err := readTLSMaterial(keyPath, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("invalid TLS certificate or private key")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
