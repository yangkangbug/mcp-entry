package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// These are transport budgets, independent of gateway request admission. A
// connection cap is not a stream cap: HTTP/2 has its own per-connection limit.
const (
	maxInboundConnections  = 128
	maxInboundHeaderBytes  = gateway.IngressMaxHeaderBytes
	maxInboundHTTP2Streams = 32
	inboundHeaderTimeout   = 5 * time.Second
	inboundReadTimeout     = gateway.IngressReadTimeout
	// Allow the existing 10-second tool deadline and terminal audit persistence
	// to finish and deliver confirmed results; do not wrap handlers in TimeoutHandler.
	inboundWriteTimeout = 60 * time.Second
	inboundIdleTimeout  = 30 * time.Second
)

func newGatewayHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig,
		MaxHeaderBytes:    maxInboundHeaderBytes,
		ReadHeaderTimeout: inboundHeaderTimeout, ReadTimeout: inboundReadTimeout,
		WriteTimeout: inboundWriteTimeout, IdleTimeout: inboundIdleTimeout,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:      maxInboundHTTP2Streams,
			MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096,
			MaxReadFrameSize:              16 << 10,
			MaxReceiveBufferPerConnection: 1 << 20,
			MaxReceiveBufferPerStream:     64 << 10,
			WriteByteTimeout:              10 * time.Second,
		},
	}
}

// boundedListener never queues accepted sockets waiting for a permit. Excess
// sockets are closed immediately. Wrap the TCP listener before ServeTLS so TLS
// handshakes count too, while net/http still receives its native *tls.Conn.
// Closing the listener stops acceptance; http.Server owns and closes admitted
// connections during Close/Shutdown, releasing their permits in either mode.
type boundedListener struct {
	net.Listener
	slots chan struct{}
}

func newBoundedListener(listener net.Listener, limit int) *boundedListener {
	if limit < 1 {
		panic("connection limit must be positive")
	}
	return &boundedListener{Listener: listener, slots: make(chan struct{}, limit)}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type boundedConn struct {
	net.Conn
	once     sync.Once
	release  func()
	closeErr error
}

func (c *boundedConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.release()
	})
	return c.closeErr
}
