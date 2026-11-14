// Package exit opens the outbound side of a routed connection: directly from
// this machine, or through a SOCKS5 or HTTP CONNECT proxy such as a VPN
// client's local port.
package exit

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer opens a TCP connection to host:port.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

const dialTimeout = 15 * time.Second

// New builds the Dialer for spec: "direct", socks5://[user:pass@]host:port
// or http://[user:pass@]host:port. Direct dials resolve names with
// upstreamDNS, never the system resolver, so a machine that uses psxroute as
// its own DNS can't loop back into itself.
func New(spec string, upstreamDNS []string) (Dialer, error) {
	if spec == "" || spec == "direct" {
		return Direct(upstreamDNS), nil
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		return &socks5{addr: u.Host, auth: auth}, nil
	case "http":
		return &httpConnect{proxyAddr: u.Host, user: u.User}, nil
	}
	return nil, fmt.Errorf("exit scheme %q not supported", u.Scheme)
}

// Direct dials from this machine, resolving names through servers.
func Direct(servers []string) Dialer {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			var lastErr error
			for _, s := range servers {
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("no upstream DNS servers")
			}
			return nil, lastErr
		},
	}
	return &net.Dialer{Timeout: dialTimeout, Resolver: r}
}

// socks5 tunnels through a SOCKS5 proxy. Names are sent to the proxy
// unresolved, so the far side does the DNS lookup.
type socks5 struct {
	addr string
	auth *proxy.Auth
}

func (s *socks5) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// A fresh dialer per call lets us keep the TCP connection to the proxy,
	// which the SOCKS library's wrapper hides, for half-closing later.
	fwd := &capture{d: net.Dialer{Timeout: dialTimeout}}
	d, err := proxy.SOCKS5("tcp", s.addr, s.auth, fwd)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks5 dialer has no DialContext")
	}
	c, err := cd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &halfCloser{Conn: c, raw: fwd.conn}, nil
}

type capture struct {
	d    net.Dialer
	conn net.Conn
}

func (c *capture) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

func (c *capture) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.d.DialContext(ctx, network, addr)
	c.conn = conn
	return conn, err
}

// halfCloser adds CloseWrite to a wrapped connection.
type halfCloser struct {
	net.Conn
	raw net.Conn
}

func (h *halfCloser) CloseWrite() error {
	if cw, ok := h.raw.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// httpConnect tunnels through an HTTP proxy with CONNECT.
type httpConnect struct {
	proxyAddr string
	user      *url.Userinfo
}

func (h *httpConnect) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, network, h.proxyAddr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(dialTimeout))
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if h.user != nil {
		pw, _ := h.user.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(h.user.Username() + ":" + pw))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufferedConn keeps bytes the proxy sent right after its CONNECT reply.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite half-closes when the underlying connection supports it.
func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
