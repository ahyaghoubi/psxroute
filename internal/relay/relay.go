// Package relay accepts the console's connections to routed names, reads
// the host name from the TLS ClientHello or HTTP Host header, and forwards
// the untouched bytes through the exit. It refuses names that aren't routed,
// so it can't be used as an open proxy.
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ahyaghoubi/psxroute/internal/exit"
	"github.com/ahyaghoubi/psxroute/internal/rules"
	"github.com/ahyaghoubi/psxroute/internal/sni"
)

// Kind is what a listener expects on its connections.
type Kind int

const (
	TLS  Kind = iota // port 443: read SNI
	HTTP             // port 80: read Host
)

const helloTimeout = 10 * time.Second

// Server relays one listener.
type Server struct {
	Kind   Kind
	Port   int // destination port at the far end
	Rules  *rules.Set
	Exit   exit.Dialer
	Logger *slog.Logger
	// OnOpen and OnConn, when set, are called as each relayed connection
	// starts and ends.
	OnOpen func(host, source string)
	OnConn func(host string, up, down int64, err error)
}

// Serve accepts on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(helloTimeout))
	br := bufio.NewReaderSize(client, sni.BufferSize)
	var host string
	var err error
	if s.Kind == TLS {
		host, err = sni.PeekTLS(br)
	} else {
		host, err = sni.PeekHTTP(br)
	}
	if err != nil {
		s.Logger.Debug("no host name on connection", "client", client.RemoteAddr().String(), "err", err)
		return
	}
	_ = client.SetReadDeadline(time.Time{})
	host = rules.Normalise(host)
	source, ok := s.Rules.Match(host)
	if !ok {
		s.Logger.Warn("refused connection to a name that isn't routed", "host", host, "client", client.RemoteAddr().String())
		return
	}

	if s.OnOpen != nil {
		s.OnOpen(host, source)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := s.Exit.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(s.Port)))
	cancel()
	if err != nil {
		s.Logger.Warn("exit dial failed", "host", host, "err", err)
		if s.OnConn != nil {
			s.OnConn(host, 0, 0, fmt.Errorf("dial: %w", err))
		}
		return
	}
	defer upstream.Close()
	s.Logger.Debug("relaying", "host", host, "port", s.Port, "client", client.RemoteAddr().String())

	// Close both sides when psxroute stops.
	stop := context.AfterFunc(ctx, func() { client.Close(); upstream.Close() })
	defer stop()

	up, down, err := splice(client, br, upstream)
	if s.OnConn != nil {
		s.OnConn(host, up, down, err)
	}
}

// drainGrace is how long the server may stay silent once the console has
// finished sending, before the connection is closed. Servers often keep an
// idle socket open long after the client has gone.
const drainGrace = 15 * time.Second

// splice copies both ways until each side has finished, half-closing as it
// goes. The peeked hello still sits in br and is sent first.
func splice(client net.Conn, br *bufio.Reader, upstream net.Conn) (up, down int64, err error) {
	var wg sync.WaitGroup
	var upErr error
	var clientDone atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		up, upErr = io.Copy(upstream, br)
		closeWrite(upstream)
		clientDone.Store(true)
		// Wake the other direction so it starts counting the grace period.
		_ = upstream.SetReadDeadline(time.Now().Add(drainGrace))
	}()
	down, downErr := copyDown(client, upstream, &clientDone)
	closeWrite(client)
	wg.Wait()
	return up, down, firstReal(upErr, downErr)
}

// copyDown copies server to console. Once the console has finished sending,
// each read gets drainGrace to arrive; a quiet server then ends the copy
// cleanly.
func copyDown(dst, src net.Conn, clientDone *atomic.Bool) (int64, error) {
	buf := make([]byte, 32<<10)
	var n int64
	for {
		if clientDone.Load() {
			_ = src.SetReadDeadline(time.Now().Add(drainGrace))
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			n += int64(nw)
			if werr != nil {
				return n, werr
			}
		}
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() && clientDone.Load() {
				return n, nil
			}
			return n, rerr
		}
	}
}

func firstReal(errs ...error) error {
	for _, e := range errs {
		if e != nil && !errors.Is(e, net.ErrClosed) && !errors.Is(e, io.EOF) {
			return e
		}
	}
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
