package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ahyaghoubi/psxroute/internal/rules"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0xbeef, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m
}

// fakeUpstream answers every A query with 203.0.113.9 over UDP and TCP.
func fakeUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	answer := func(q []byte) []byte {
		var m dnsmessage.Message
		if err := m.Unpack(q); err != nil {
			return nil
		}
		m.Header.Response = true
		m.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}},
		}}
		out, _ := m.Pack()
		return out
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answer(buf[:n]), addr)
		}
	}()
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				_ = writeTCPMsg(c, answer(q))
			}()
		}
	}()
	return pc.LocalAddr().String()
}

func newServer(t *testing.T, upstream string) (*Server, *[]string) {
	set, err := rules.Build(nil, []string{"ea.com"})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	return &Server{
		Rules: set, Advertise: net.IPv4(192, 168, 1, 20).To4(), Upstreams: []string{upstream},
		Logger:   slog.New(slog.DiscardHandler),
		OnLookup: func(name, _ string, routed bool, _ string) { seen = append(seen, name) },
	}, &seen
}

func TestRoutedA(t *testing.T) {
	s, seen := newServer(t, "127.0.0.1:1")
	m := parse(t, s.Handle(context.Background(), query(t, "accounts.ea.com.", dnsmessage.TypeA), "c", "udp"))
	if m.Header.ID != 0xbeef || !m.Header.Response || m.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("bad header %+v", m.Header)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %d", len(m.Answers))
	}
	a := m.Answers[0].Body.(*dnsmessage.AResource).A
	if net.IP(a[:]).String() != "192.168.1.20" {
		t.Fatalf("A = %v", a)
	}
	if m.Answers[0].Header.TTL != RoutedTTL {
		t.Fatalf("TTL = %d", m.Answers[0].Header.TTL)
	}
	if len(*seen) != 1 || (*seen)[0] != "accounts.ea.com" {
		t.Fatalf("lookups = %v", *seen)
	}
}

func TestRoutedAAAAIsEmpty(t *testing.T) {
	s, _ := newServer(t, "127.0.0.1:1")
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeHTTPS} {
		m := parse(t, s.Handle(context.Background(), query(t, "ea.com.", typ), "c", "udp"))
		if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
			t.Fatalf("type %v: rcode %v, %d answers", typ, m.Header.RCode, len(m.Answers))
		}
	}
}

func TestForwardUDPAndTCP(t *testing.T) {
	s, _ := newServer(t, fakeUpstream(t))
	for _, network := range []string{"udp", "tcp"} {
		m := parse(t, s.Handle(context.Background(), query(t, "store.playstation.com.", dnsmessage.TypeA), "c", network))
		if len(m.Answers) != 1 {
			t.Fatalf("%s: answers = %d", network, len(m.Answers))
		}
		if a := m.Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{203, 0, 113, 9} {
			t.Fatalf("%s: A = %v", network, a)
		}
	}
}

func TestUpstreamDownIsServFail(t *testing.T) {
	// A port nothing listens on: UDP read times out or is refused.
	s, _ := newServer(t, "127.0.0.1:9")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := parse(t, s.Handle(ctx, query(t, "example.net.", dnsmessage.TypeA), "c", "udp"))
	if m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode = %v", m.Header.RCode)
	}
}

func TestGarbageIgnored(t *testing.T) {
	s, _ := newServer(t, "127.0.0.1:1")
	if resp := s.Handle(context.Background(), []byte{1, 2, 3}, "c", "udp"); resp != nil {
		t.Fatal("want no reply to garbage")
	}
}

func TestGatewayRoutedAIsRealAndReported(t *testing.T) {
	s, _ := newServer(t, fakeUpstream(t))
	s.Gateway = true
	var got []net.IP
	s.OnResolved = func(name string, ips []net.IP) {
		if name != "accounts.ea.com" {
			t.Errorf("name = %q", name)
		}
		got = ips
	}
	m := parse(t, s.Handle(context.Background(), query(t, "accounts.ea.com.", dnsmessage.TypeA), "c", "udp"))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{203, 0, 113, 9} {
		t.Fatalf("want the upstream answer, got %+v", m.Answers)
	}
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("OnResolved got %v", got)
	}
	// AAAA for routed names stays empty, so traffic can't go around the tunnel.
	m = parse(t, s.Handle(context.Background(), query(t, "accounts.ea.com.", dnsmessage.TypeAAAA), "c", "udp"))
	if len(m.Answers) != 0 {
		t.Fatalf("AAAA answers = %d", len(m.Answers))
	}
}
