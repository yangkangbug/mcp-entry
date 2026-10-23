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
	archiveFile, credentialsFile                                      string
	adminTokenFile                                                    string
	clientBinding                                                     bool
	entryFile, entryExpiry, newKeyFile                                string
	allowRemoteTest, allowInsecureHTTPTest                            bool
	tlsCert, tlsKey                                                   string
	config, listen, db, keyFile, operation, tenant, principal, system string
	keyStdin, initialize, account                                     bool
	expected                                                          uint64
	after                                                             uint64
	limit                                                             int
	allowed                                                           toolFlags
}

var errOptions = errors.New("invalid command options; use -help for supported combinations")

// parseOptions 按操作建立参数组合边界；seen 区分未指定与显式传入零值，
// 防止无关选项被静默忽略，让维护命令意外带入服务启动配置。
func parseOptions(args []string, help io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.allowRemoteTest, "allow-remote-test", false, "serve only: explicitly permit remote synthetic MCP testing; strong finite entry auth required")
	fs.BoolVar(&o.allowInsecureHTTPTest, "allow-insecure-http-test", false, "serve only: explicitly permit plaintext remote testing; credentials are not encrypted")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "serve only: PEM server certificate file")
	fs.StringVar(&o.tlsKey, "tls-key", "", "serve only: private PEM server key file")
	fs.StringVar(&o.credentialsFile, "credentials-file", "", "bootstrap only: private JSON file supplementing configured user credentials; no overrides")
	fs.StringVar(&o.config, "config", "configs/demo.json", "synthetic local configuration file")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "serve only: literal IP listen address; loopback unless remote test explicitly enabled")
	fs.StringVar(&o.db, "db", "", "optional local SQLite path; existing file required unless -init-db")
	fs.StringVar(&o.keyFile, "key-file", "", "private regular file containing exactly 32 raw synthetic key bytes")
	fs.BoolVar(&o.keyStdin, "key-stdin", false, "read exactly 32 raw synthetic key bytes followed by EOF from stdin")
	fs.BoolVar(&o.clientBinding, "client-binding", false, "serve only: enable loopback client credential binding without a webpage; strong finite entry credentials required")
	fs.StringVar(&o.adminTokenFile, "admin-token-file", "", "serve only: opt-in loopback admin console with separate private 43-byte synthetic authority")
	fs.BoolVar(&o.account, "account", false, "serve only: enable local own-binding page; requires strong finite entry credentials")
	fs.BoolVar(&o.initialize, "init-db", false, "serve only: explicitly initialize a nonexistent database")
	fs.StringVar(&o.operation, "operation", "serve", "serve, check-config, status, audit, audit-all, archive-audit, migrate, rotate-key, replace-entry, revoke-entry, revoke-binding, disable-principal, or set-policy")
	fs.StringVar(&o.tenant, "tenant", "", "offline only: configured synthetic tenant")
	fs.StringVar(&o.principal, "principal", "", "offline only: configured synthetic principal")
	fs.StringVar(&o.system, "system", "", "revoke-binding requires system; status optionally filters system")
	fs.Uint64Var(&o.expected, "expected-version", 0, "mutation CAS: entry generation for entry operations, binding generation for revoke-binding, audit sequence for archive-audit, policy version otherwise")
	fs.Uint64Var(&o.after, "after-sequence", 0, "audit only: exclusive sequence cursor")
	fs.IntVar(&o.limit, "limit", 100, "audit only: maximum records, 1 through 1000")
	fs.StringVar(&o.entryFile, "entry-file", "", "replace-entry only: private file with exactly 43 canonical base64url token bytes")
	fs.StringVar(&o.entryExpiry, "entry-expires", "", "replace-entry only: finite future RFC3339 expiry")
	fs.StringVar(&o.archiveFile, "archive-file", "", "archive-audit only: nonexistent private export path")
	fs.StringVar(&o.newKeyFile, "new-key-file", "", "rotate-key only: private file with exactly 32 new raw key bytes")
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
	if seen["credentials-file"] && (o.credentialsFile == "" || (o.operation != "check-config" && (o.operation != "serve" || (o.db != "" && !o.initialize)))) {
		return o, errOptions
	}
	if o.operation == "check-config" {
		for name := range seen {
			if name != "operation" && name != "config" && name != "credentials-file" {
				return o, errOptions
			}
		}
		return o, nil
	}
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
	if o.operation != "archive-audit" && seen["archive-file"] {
		return o, errOptions
	}
	if o.operation != "replace-entry" && (seen["entry-file"] || seen["entry-expires"]) {
		return o, errOptions
	}
	if o.operation != "rotate-key" && seen["new-key-file"] {
		return o, errOptions
	}
	if o.operation != "audit" && o.operation != "audit-all" && (seen["after-sequence"] || seen["limit"]) {
		return o, errOptions
	}
	if o.operation == "serve" {
		if seen["admin-token-file"] && o.adminTokenFile == "" {
			return o, errOptions
		}
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
		if (o.account || o.clientBinding || o.adminTokenFile != "") && (o.allowRemoteTest || o.tlsCert != "") {
			return o, errOptions
		}
		return o, nil
	}
	if seen["client-binding"] || seen["admin-token-file"] || seen["allow-remote-test"] || seen["allow-insecure-http-test"] || seen["tls-cert"] || seen["tls-key"] || seen["listen"] || seen["init-db"] || seen["account"] || o.db == "" {
		return o, errOptions
	}
	globalOperation := o.operation == "migrate" || o.operation == "rotate-key" || o.operation == "audit-all" || o.operation == "archive-audit"
	if globalOperation {
		if seen["tenant"] || seen["principal"] || seen["system"] || (seen["expected-version"] && o.operation != "archive-audit") || seen["allow"] {
			return o, errOptions
		}
	} else if o.tenant == "" || o.principal == "" {
		return o, errOptions
	}
	switch o.operation {
	case "archive-audit":
		if o.archiveFile == "" || !seen["expected-version"] {
			return o, errOptions
		}
	case "migrate":
	case "rotate-key":
		if o.newKeyFile == "" {
			return o, errOptions
		}
	case "replace-entry":
		expiry, e := time.Parse(time.RFC3339, o.entryExpiry)
		if o.expected == 0 || o.entryFile == "" || e != nil || !expiry.After(time.Now()) || seen["system"] || seen["allow"] {
			return o, errOptions
		}
	case "revoke-entry":
		if o.expected == 0 || seen["system"] || seen["allow"] {
			return o, errOptions
		}
	case "audit", "audit-all":
		if seen["system"] || seen["expected-version"] || seen["allow"] || o.limit < 1 || o.limit > gateway.MaxAuditReadLimit {
			return o, errOptions
		}
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

// readKey 读取原始 32 字节而非文本编码；文件路径须为私有普通文件，
// 打开后核对同一文件，避免只检查路径却读取被替换的对象。
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
	case "archive-audit":
		result, err = g.ArchiveAudit(o.archiveFile, o.expected)
	case "migrate":
		result = struct{ Version int }{4}
	case "rotate-key":
		var key []byte
		key, err = readKey(options{db: "maintenance", keyFile: o.newKeyFile}, nil)
		if err == nil {
			err = g.RotateKey(key)
			if errors.Is(err, gateway.ErrStorage) {
				err = errors.New("key rotation outcome unknown; retain both keys and authenticate reopen with the new key, then the old key before retrying; if neither succeeds, quarantine the database")
			}
			if err == nil {
				err = g.Close()
				if err == nil {
					var verified *gateway.Gateway
					verified, err = gateway.OpenMaintenance(cfg, gateway.PersistenceOptions{Path: o.db, Key: key})
					if err == nil {
						err = verified.Close()
					}
				}
				if err != nil {
					err = errors.New("key rotation verification failed; retain both keys and inspect state before retrying")
				}
			}
		}
		clear(key)
		result = struct{ Rotated bool }{err == nil}
	case "replace-entry":
		var token string
		token, err = readEntryFile(o.entryFile)
		if err == nil {
			expiry, _ := time.Parse(time.RFC3339, o.entryExpiry)
			result, err = g.ReplaceEntry(identity, o.expected, token, expiry)
		}
	case "revoke-entry":
		result, err = g.RevokeEntry(identity, o.expected)
	case "audit-all":
		result, err = g.AuditAll(o.after, o.limit)
	case "audit":
		var page gateway.AuditPage
		page, err = g.Audit(identity, o.after, o.limit)
		result = struct {
			Status gateway.AuditStatus
			Page   gateway.AuditPage
		}{g.AuditStatus(), page}
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
		entry, e := g.Entry(identity)
		if e != nil {
			return e
		}
		result = struct {
			Policy   gateway.PolicyInfo
			Bindings []gateway.BindingInfo
			Entry    gateway.EntryInfo
		}{policy, bindings, entry}
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
	// 操作可能已持久提交，输出失败不等于变更失败；调用方须检查状态而非重放。
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
	if o.credentialsFile != "" {
		cfg, err = loadCredentials(cfg, o.credentialsFile)
		if err != nil {
			return err
		}
	}
	// 配置预检在读取存储密钥、打开数据库和监听网络之前返回。
	if o.operation == "check-config" {
		return checkConfig(cfg, stdout)
	}
	// 初始化前先检查自助/远程入口凭据要求，避免无效认证配置先创建数据库。
	// 重开既有库则必须在恢复存储权威状态后检查，不能采信配置种子。
	if (o.account || o.clientBinding || o.allowRemoteTest) && (o.db == "" || o.initialize) {
		preview, err := gateway.New(cfg)
		if err != nil {
			return err
		}
		if o.allowRemoteTest {
			err = preview.ValidateTestEntryAuth()
		} else if o.clientBinding {
			_, err = preview.ClientBindingHandler("http://127.0.0.1:1")
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
		opts := gateway.PersistenceOptions{Path: o.db, Key: key, Initialize: o.initialize, Migrate: o.operation == "migrate"}
		if o.operation == "serve" {
			g, err = gateway.NewPersistent(cfg, opts)
		} else {
			g, err = gateway.OpenMaintenance(cfg, opts)
		}
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
	var adminToken string
	if o.adminTokenFile != "" {
		adminToken, err = readEntryFile(o.adminTokenFile)
		if err != nil {
			return errors.New("cannot read private admin authority file")
		}
		if _, err = g.AdminHandler("http://127.0.0.1:1", adminToken); err != nil {
			return err
		}
	}
	// Invalid persistence must not open a socket. Explicit initialization may
	// already have committed if binding fails; retry by reopening, never delete.
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return errors.New("cannot bind configured listener")
	}
	listener = newBoundedListener(listener, maxInboundConnections)
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
	if o.clientBinding {
		binding, err := g.ClientBindingHandler("http://" + listener.Addr().String())
		if err != nil {
			return err
		}
		mux.Handle("/binding/", binding)
	}
	if o.adminTokenFile != "" {
		admin, err := g.AdminHandler("http://"+listener.Addr().String(), adminToken)
		if err != nil {
			return err
		}
		mux.Handle("/admin", admin)
		mux.Handle("/admin/", admin)
	}
	// 在整个 mux 外包一层入口防护，未知路由和管理路由也受同一总预算约束；
	// 已自行包装 GuardHTTP 的路由通过上下文标记避免重复计费。
	server := newGatewayHTTPServer(g.GuardHTTP(mux), tlsConfig)
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
	if o.adminTokenFile != "" {
		logger.Printf("LOCAL ADMIN CONSOLE: http://%s/admin; separate operator authority required", listener.Addr())
	}
	if o.clientBinding {
		logger.Print("LOCAL CLIENT BINDING enabled; use private-file client flow, never MCP tool arguments for credentials")
	}
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

// readEntryFile 只验证私有文件及精确字节长度，不剥除换行；token 的规范编码
// 和用途分离由 ReplaceEntry/AdminHandler 等消费方验证，不能仅凭读取成功授权。
func readEntryFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 43 {
		return "", errors.New("invalid private entry token file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot read entry token file")
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() || actual.Mode().Perm()&0077 != 0 {
		return "", errors.New("invalid private entry token file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 44))
	if err != nil || len(data) != 43 {
		return "", errors.New("entry token file must contain exactly 43 bytes")
	}
	defer clear(data)
	return string(data), nil
}
