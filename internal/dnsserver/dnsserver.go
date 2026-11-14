// Package dnsserver is the console's DNS server. Routed names get this
// machine's address so their connections reach the relay; every other query
// is passed to the upstream servers unchanged.
package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ahyaghoubi/psxroute/internal/rules"
)

// RoutedTTL is the TTL on answers for routed names. It's short so a change
// of rules or of this machine's address takes effect quickly.
const RoutedTTL = 30

const upstreamTimeout = 3 * time.Second

// Server answers DNS over UDP and TCP.
type Server struct {
	Rules     *rules.Set
	Advertise net.IP   // IPv4 given out for routed names
	Upstreams []string // host:port, tried in order
	Logger    *slog.Logger
	// OnLookup, when set, is called for every question received.
	OnLookup func(name, client string, routed bool, source string)

	// Gateway switches routed names to gateway behaviour: A queries get the
	// real answer from upstream, and OnResolved sees its addresses before the
	// reply goes back, so they're routed by the time the console connects.
	Gateway    bool
	OnResolved func(name string, ips []net.IP)
	// OnAnswer, when set, sees the addresses in every answer passed back
	// from upstream, so connections can be labelled with their names.
	OnAnswer func(name string, ips []net.IP)
}

// ServeUDP answers queries on pc until ctx is done.
func (s *Server) ServeUDP(ctx context.Context, pc net.PacketConn) error {
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp := s.Handle(ctx, q, clientIP(addr), "udp")
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

// ServeTCP answers length-prefixed queries on ln until ctx is done.
func (s *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
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
		go s.serveConn(ctx, c)
	}
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	client := clientIP(c.RemoteAddr())
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		msg, err := readTCPMsg(c)
		if err != nil {
			return
		}
		resp := s.Handle(ctx, msg, client, "tcp")
		if resp == nil {
			return
		}
		if err := writeTCPMsg(c, resp); err != nil {
			return
		}
	}
}

// Handle answers one wire-format query. It returns nil when there's nothing
// sensible to reply (an unparseable packet).
func (s *Server) Handle(ctx context.Context, query []byte, client, network string) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return s.reply(hdr, nil, dnsmessage.RCodeFormatError, nil)
	}
	name := rules.Normalise(q.Name.String())
	source, routed := s.Rules.Match(name)
	if s.OnLookup != nil {
		s.OnLookup(name, client, routed, source)
	}
	if routed && q.Class == dnsmessage.ClassINET {
		s.Logger.Debug("routed lookup", "name", name, "type", q.Type, "client", client)
		if !s.Gateway || q.Type != dnsmessage.TypeA {
			return s.answerRouted(hdr, q)
		}
		resp, err := s.forward(ctx, query, network)
		if err != nil {
			s.Logger.Warn("upstream DNS failed", "name", name, "err", err)
			return s.reply(hdr, &q, dnsmessage.RCodeServerFailure, nil)
		}
		if ips := addrsIn(resp); len(ips) > 0 {
			if s.OnResolved != nil {
				s.OnResolved(name, ips)
			}
			if s.OnAnswer != nil {
				s.OnAnswer(name, ips)
			}
		}
		return resp
	}
	resp, err := s.forward(ctx, query, network)
	if err != nil {
		s.Logger.Warn("upstream DNS failed", "name", name, "err", err)
		return s.reply(hdr, &q, dnsmessage.RCodeServerFailure, nil)
	}
	if s.OnAnswer != nil && q.Type == dnsmessage.TypeA {
		if ips := addrsIn(resp); len(ips) > 0 {
			s.OnAnswer(name, ips)
		}
	}
	return resp
}

// addrsIn returns every A record in a reply, including those at the end of
// a CNAME chain.
func addrsIn(resp []byte) []net.IP {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	var out []net.IP
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		if h.Type != dnsmessage.TypeA || h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return out
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return out
		}
		out = append(out, net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3]).To4())
	}
}

// answerRouted gives A queries this machine's address (relay mode) and
// every other type an empty answer, so the console can't reach the real host
// over IPv6 or by an HTTPS record's address hints.
func (s *Server) answerRouted(hdr dnsmessage.Header, q dnsmessage.Question) []byte {
	var answers []dnsmessage.Resource
	if q.Type == dnsmessage.TypeA {
		var a [4]byte
		copy(a[:], s.Advertise.To4())
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: RoutedTTL},
			Body:   &dnsmessage.AResource{A: a},
		})
	}
	return s.reply(hdr, &q, dnsmessage.RCodeSuccess, answers)
}

func (s *Server) reply(qh dnsmessage.Header, q *dnsmessage.Question, rc dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: qh.ID, Response: true, Authoritative: rc == dnsmessage.RCodeSuccess,
			RecursionDesired: qh.RecursionDesired, RecursionAvailable: true, RCode: rc,
		},
		Answers: answers,
	}
	if q != nil {
		msg.Questions = []dnsmessage.Question{*q}
	}
	out, err := msg.Pack()
	if err != nil {
		return nil
	}
	return out
}

// forward sends the query to each upstream in turn and returns the first
// reply. A truncated UDP reply is passed back as-is so the client retries
// over TCP, which is then forwarded over TCP.
func (s *Server) forward(ctx context.Context, query []byte, network string) ([]byte, error) {
	var lastErr error
	for _, up := range s.Upstreams {
		ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
		resp, err := exchange(ctx, network, up, query)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream DNS servers")
	}
	return nil, lastErr
}

func exchange(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	id := binary.BigEndian.Uint16(query)
	if network == "tcp" {
		if err := writeTCPMsg(c, query); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray packets that don't answer this query.
		if n >= 2 && binary.BigEndian.Uint16(buf) == id {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 2); return &b }}

func readTCPMsg(r io.Reader) ([]byte, error) {
	lp := bufPool.Get().(*[]byte)
	defer bufPool.Put(lp)
	if _, err := io.ReadFull(r, *lp); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(*lp)
	if n < 12 {
		return nil, errors.New("short DNS message")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMsg(w io.Writer, msg []byte) error {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

func clientIP(a net.Addr) string {
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}
