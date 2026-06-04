package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rhibbitts/credproxy/internal/ca"
	"github.com/rhibbitts/credproxy/internal/resolver"
)

type Proxy struct {
	addr     string
	ca       *ca.Provider
	resolver *resolver.Resolver
	logger   *slog.Logger
	upstream *http.Transport
}

func New(addr string, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger) *Proxy {
	return &Proxy{
		addr:     addr,
		ca:       caProvider,
		resolver: res,
		logger:   logger,
		upstream: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
	}
}

func (p *Proxy) Addr() string {
	return p.addr
}

func (p *Proxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return p.Serve(ln)
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		if err != io.EOF {
			p.logger.Warn("read request", "err", err)
		}
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
		return
	}

	p.handleForward(conn, req)
}

func (p *Proxy) handleConnect(conn net.Conn, req *http.Request) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	if !p.resolver.IsHostAllowed(hostname) {
		p.logger.Info("tunnel", "host", hostname)
		p.tunnelConnect(conn, host)
		return
	}

	p.logger.Info("mitm", "host", hostname)

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.logger.Warn("write connect response", "err", err)
		return
	}

	leafCert, leafKey, err := p.ca.MintLeaf(hostname)
	if err != nil {
		p.logger.Warn("mint leaf cert", "host", hostname, "err", err)
		return
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  leafKey,
		Leaf:       leafCert,
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*tlsCert},
	}

	tlsConn := tls.Server(conn, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Warn("tls handshake", "host", hostname, "err", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	ln := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.forwardRequest(w, r, host, hostname, true) }),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		WriteTimeout:      30 * time.Minute,
	}
	_ = srv.Serve(ln)
}

func (p *Proxy) handleForward(conn net.Conn, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	if !p.resolver.IsHostAllowed(hostname) {
		p.forwardDirect(conn, req, host)
		return
	}

	if err := p.resolver.ResolveRequest(req, hostname); err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(strings.NewReader(err.Error())),
		}
		resp.Write(conn)
		return
	}

	outURL := fmt.Sprintf("http://%s%s", host, req.URL.Path)
	if req.URL.RawQuery != "" {
		outURL += "?" + req.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(context.Background(), req.Method, outURL, req.Body)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	outReq.Host = hostname
	for k, vv := range req.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	resp, err := p.upstream.RoundTrip(outReq)
	if err != nil {
		p.logger.Debug("upstream error", "host", hostname, "err", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}

func (p *Proxy) forwardRequest(w http.ResponseWriter, r *http.Request, target, host string, useTLS bool) {
	p.logger.Info("request", "method", r.Method, "host", host, "path", r.URL.Path)

	if err := p.resolver.ResolveRequest(r, host); err != nil {
		p.logger.Error("resolve failed", "host", host, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	outURL := fmt.Sprintf("%s://%s%s", scheme, target, r.URL.Path)
	if r.URL.RawQuery != "" {
		outURL += "?" + r.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, r.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	outReq.Host = host
	outReq.ContentLength = r.ContentLength
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	resp, err := p.upstream.RoundTrip(outReq)
	if err != nil {
		p.logger.Error("upstream error", "host", host, "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.logger.Info("response", "host", host, "status", resp.StatusCode)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, fmt.Errorf("listener closed")
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (p *Proxy) tunnelConnect(conn net.Conn, host string) {
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.logger.Warn("write tunnel connect response", "err", err)
		return
	}

	dialConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		p.logger.Debug("tunnel dial failed", "host", host, "err", err)
		return
	}
	defer dialConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(dialConn, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, dialConn)
		done <- struct{}{}
	}()
	<-done
}

func (p *Proxy) forwardDirect(conn net.Conn, req *http.Request, host string) {
	outURL := fmt.Sprintf("http://%s%s", host, req.URL.Path)
	if req.URL.RawQuery != "" {
		outURL += "?" + req.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(context.Background(), req.Method, outURL, req.Body)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	outReq.Host = req.Host
	for k, vv := range req.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	resp, err := p.upstream.RoundTrip(outReq)
	if err != nil {
		p.logger.Debug("direct upstream error", "host", host, "err", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}
