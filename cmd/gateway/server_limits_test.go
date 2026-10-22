package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func loopbackListener(t *testing.T, limit int) *boundedListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := newBoundedListener(l, limit)
	t.Cleanup(func() { b.Close() })
	return b
}

func dialLimited(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", l.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}

func TestBoundedListenerRejectRecoverAndCloseOnce(t *testing.T) {
	l := loopbackListener(t, 1)
	first := dialLimited(t, l)
	admitted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	next := make(chan net.Conn, 1)
	stopped := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			stopped <- err
			return
		}
		next <- c
	}()
	excess := dialLimited(t, l)
	var b [1]byte
	if _, err = excess.Read(b[:]); err == nil {
		t.Fatal("excess connection stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess connection queued rather than closed")
	}
	if len(l.slots) != 1 {
		t.Fatal("excess changed active count")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { admitted.Close() })
	}
	wg.Wait()
	first.Close()
	if len(l.slots) != 0 {
		t.Fatal("permit not released exactly once")
	}
	recovered := dialLimited(t, l)
	select {
	case c := <-next:
		c.Close()
	case err := <-stopped:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("no recovery")
	}
	recovered.Close()
	go func() { _, err := l.Accept(); stopped <- err }()
	l.Close()
	select {
	case err := <-stopped:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accept not unblocked")
	}
}

func serveLimited(t *testing.T, s *http.Server, l *boundedListener) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if s.TLSConfig != nil {
			done <- s.ServeTLS(l, "", "")
		} else {
			done <- s.Serve(l)
		}
	}()
	t.Cleanup(func() {
		s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not exit")
		}
	})
}

func TestInboundHTTPBudgets(t *testing.T) {
	s := newGatewayHTTPServer(http.NotFoundHandler(), nil)
	if s.MaxHeaderBytes != maxInboundHeaderBytes || s.MaxHeaderBytes <= 0 || s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != inboundReadTimeout || s.WriteTimeout != 60*time.Second || s.IdleTimeout != 30*time.Second {
		t.Fatal("missing explicit finite HTTP budgets")
	}
	if s.HTTP2 == nil || s.HTTP2.MaxConcurrentStreams != 32 || s.HTTP2.WriteByteTimeout <= 0 {
		t.Fatal("missing HTTP/2 budgets")
	}
}

func TestInboundRawHeaderAndBodyLimits(t *testing.T) {
	for _, mode := range []string{"large-header", "slow-header", "slow-body"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			readDone := make(chan error, 1)
			closed := make(chan struct{}, 1)
			s := newGatewayHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				_, err := io.Copy(io.Discard, r.Body)
				readDone <- err
				if err != nil {
					http.Error(w, "incomplete body", http.StatusRequestTimeout)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}), nil)
			s.ReadHeaderTimeout = 150 * time.Millisecond
			s.ReadTimeout = 250 * time.Millisecond
			s.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closed <- struct{}{}
				}
			}
			l := loopbackListener(t, 2)
			serveLimited(t, s, l)
			c := dialLimited(t, l)
			switch mode {
			case "large-header":
				io.WriteString(c, "GET / HTTP/1.1\r\nHost: test\r\nX-Large: "+strings.Repeat("x", maxInboundHeaderBytes+8192)+"\r\n\r\n")
				r, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Body.Close()
				if r.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
					t.Fatalf("status %d", r.StatusCode)
				}
			case "slow-header":
				io.WriteString(c, "GET / HTTP/1.1\r\nHost:")
			case "slow-body":
				io.WriteString(c, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 8\r\n\r\na")
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("body handler not entered")
				}
				select {
				case err := <-readDone:
					if err == nil {
						t.Fatal("slow body completed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("body read not bounded")
				}
			}
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("connection not closed")
			}
			if len(l.slots) != 0 {
				t.Fatal("closed socket retained permit")
			}
			if mode != "slow-body" {
				select {
				case <-entered:
					t.Fatal("bad header entered handler")
				default:
				}
			}
		})
	}
}

func TestInboundTLSHTTP2AndShutdown(t *testing.T) {
	cert, key, pool := remoteCertificate(t)
	config, err := readServerTLS(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	l := loopbackListener(t, 2)
	closed := make(chan struct{}, 4)
	s := newGatewayHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), config)
	s.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	serveLimited(t, s, l)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, err := client.Get("https://" + l.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTP/2 lost: %s", resp.Proto)
	}
	// Inspect actual advertised HTTP/2 limits, not just struct fields.
	raw := dialLimited(t, l)
	tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"h2"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("h2 not negotiated")
	}
	io.WriteString(tc, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err = tc.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	} // Empty client SETTINGS.
	var frame [9]byte
	if _, err = io.ReadFull(tc, frame[:]); err != nil {
		t.Fatal(err)
	}
	n := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	if frame[3] != 4 || n > 1024 || n%6 != 0 {
		t.Fatalf("expected bounded SETTINGS, header %x", frame)
	}
	payload := make([]byte, n)
	if _, err = io.ReadFull(tc, payload); err != nil {
		t.Fatal(err)
	}
	settings := map[uint16]uint32{}
	for i := 0; i < n; i += 6 {
		settings[binary.BigEndian.Uint16(payload[i:i+2])] = binary.BigEndian.Uint32(payload[i+2 : i+6])
	}
	if settings[3] != maxInboundHTTP2Streams {
		t.Fatalf("stream limit not advertised: %v", settings)
	}
	// net/http allows its documented framing overhead on top of MaxHeaderBytes.
	if settings[6] < maxInboundHeaderBytes || settings[6] > maxInboundHeaderBytes+4096 {
		t.Fatalf("header list not bounded: %v", settings)
	}
	tc.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS close not observed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 shutdown not observed")
	}
	if len(l.slots) != 0 {
		t.Fatal("TLS shutdown leaked permits")
	}
}

func TestInboundIdleAndForcedShutdown(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "TLS"}[tlsMode], func(t *testing.T) {
			var config *tls.Config
			if tlsMode {
				cert, key, _ := remoteCertificate(t)
				var err error
				config, err = readServerTLS(cert, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			l := loopbackListener(t, 1)
			accepted := make(chan struct{}, 2)
			closed := make(chan struct{}, 2)
			s := newGatewayHTTPServer(http.NotFoundHandler(), config)
			s.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					accepted <- struct{}{}
				}
				if state == http.StateClosed {
					closed <- struct{}{}
				}
			}
			serveLimited(t, s, l)
			// A socket that has not sent even a TLS handshake must consume capacity.
			idle := dialLimited(t, l)
			select {
			case <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("not accepted")
			}
			excess := dialLimited(t, l)
			var b [1]byte
			if _, err := excess.Read(b[:]); err == nil {
				t.Fatal("excess not closed")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("excess queued")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("idle socket not closed")
			}
			if len(l.slots) != 0 {
				t.Fatal("forced close leaked socket slot")
			}
			idle.Close()
		})
	}
}

func TestInboundKeepAliveIdleDeadline(t *testing.T) {
	l := loopbackListener(t, 1)
	closed := make(chan struct{}, 1)
	s := newGatewayHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), nil)
	s.IdleTimeout = 150 * time.Millisecond
	s.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	serveLimited(t, s, l)
	c := dialLimited(t, l)
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.Status)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive not bounded")
	}
	if len(l.slots) != 0 {
		t.Fatal("idle close leaked permit")
	}
}

func TestInboundWriteDeadline(t *testing.T) {
	l := loopbackListener(t, 1)
	writeDone := make(chan error, 1)
	s := newGatewayHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The peer never reads; a finite write deadline must eventually interrupt
		// this bounded stream once the loopback socket buffers fill.
		chunk := make([]byte, 64<<10)
		for range 1024 {
			if _, err := w.Write(chunk); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}), nil)
	s.WriteTimeout = 150 * time.Millisecond
	serveLimited(t, s, l)
	c := dialLimited(t, l)
	if tcp, ok := c.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("all output unexpectedly buffered without timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked write not interrupted")
	}
}
