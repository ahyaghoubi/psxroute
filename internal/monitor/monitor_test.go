package monitor

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

var (
	lan     = &net.IPNet{IP: net.IPv4(192, 168, 1, 0).To4(), Mask: net.CIDRMask(24, 32)}
	mac     = net.IPv4(192, 168, 1, 10)
	ps5     = [4]byte{192, 168, 1, 50}
	server  = [4]byte{34, 1, 2, 3}
	matchIP = [4]byte{18, 9, 9, 9}
)

func newMon(start time.Time) (*Monitor, *time.Time) {
	m := New(lan, mac)
	now := start
	m.now = func() time.Time { return now }
	return m, &now
}

// tcpExchange plays a TCP connection: a handshake, then every 100 ms the
// console sends a segment and the server acknowledges it rtt later, with
// the home leg (server data → console's ACK) taking home.
func tcpExchange(m *Monitor, start time.Time, n int, rtt, home time.Duration, resend map[int]bool) time.Time {
	const lport, rport = 50000, 443
	out := func(at time.Time, flags uint8, seq uint32, payload int, tsval, tsecr uint32) {
		m.Handle(Packet{At: at, Src: ps5, Dst: server, Proto: protoTCP, SrcPort: lport, DstPort: rport,
			Flags: flags, Seq: seq, Payload: payload, HasTS: true, TSval: tsval, TSecr: tsecr})
	}
	in := func(at time.Time, flags uint8, seq uint32, payload int, tsval, tsecr uint32) {
		m.Handle(Packet{At: at, Src: server, Dst: ps5, Proto: protoTCP, SrcPort: rport, DstPort: lport,
			Flags: flags, Seq: seq, Payload: payload, HasTS: true, TSval: tsval, TSecr: tsecr})
	}
	t := start
	out(t, flagSYN, 1000, 0, 1, 0)
	in(t.Add(rtt), flagSYN|flagACK, 9000, 0, 1, 1)
	out(t.Add(rtt+home), flagACK, 1001, 0, 2, 1)
	seq, sseq := uint32(1001), uint32(9001)
	for i := 0; i < n; i++ {
		t = start.Add(time.Duration(i+1) * 100 * time.Millisecond)
		tsval := uint32(10 + i)
		out(t, flagACK, seq, 100, tsval, 0)
		if resend[i] {
			out(t.Add(time.Millisecond), flagACK, seq, 100, tsval, 0) // sent again
		}
		seq += 100
		in(t.Add(rtt), flagACK, sseq, 50, 5000+uint32(i), tsval)
		out(t.Add(rtt+home), flagACK, seq, 0, tsval+1000, 5000+uint32(i))
		sseq += 50
	}
	return t.Add(rtt + home)
}

func TestTCPPingAndHomeLeg(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	m.SetRunning()
	end := tcpExchange(m, start, 50, 40*time.Millisecond, 3*time.Millisecond, nil)
	*now = end

	v := m.Snapshot("192.168.1.50")
	if !v.Running || v.Console != "192.168.1.50" || v.Active != 1 {
		t.Fatalf("view = %+v", v)
	}
	if !v.HasHome || v.HomeMS != 3 {
		t.Fatalf("home = %v %v", v.HasHome, v.HomeMS)
	}
	if v.Ping == nil || !v.Ping.HasPing || v.Ping.PingMS != 43 || v.Ping.JitterMS != 0 {
		t.Fatalf("ping = %+v", v.Ping)
	}
	if !v.Ping.HasLoss || v.Ping.LossPct != 0 {
		t.Fatalf("loss = %+v", v.Ping)
	}
	if v.Ping.Remote != "34.1.2.3:443" || v.Ping.Proto != "TCP" {
		t.Fatalf("conn = %+v", v.Ping)
	}
	if last := v.PingHist[len(v.PingHist)-1]; last != 43 {
		t.Fatalf("ping history ends %v", last)
	}
}

func TestTCPRetransmissionsCountAsLoss(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	// 2 of 100 segments sent again; data segments = 100 + 2 resent + 100 from the server.
	*now = tcpExchange(m, start, 100, 30*time.Millisecond, 2*time.Millisecond, map[int]bool{10: true, 60: true})
	v := m.Snapshot("")
	if v.Console != "192.168.1.50" {
		t.Fatalf("busiest device = %q", v.Console)
	}
	c := v.Ping
	if c == nil || !c.HasLoss || c.LossPct <= 0 || c.LossPct > 2 {
		t.Fatalf("loss = %+v", c)
	}
	var marks int
	for _, n := range v.LossHist {
		marks += n
	}
	if marks == 0 {
		t.Fatal("loss history has no marks")
	}
}

func TestJitterFromVaryingPing(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	// One exchange per second, alternating 40 ms and 60 ms.
	t0 := start
	for i := 0; i < 10; i++ {
		rtt := 40 * time.Millisecond
		if i%2 == 1 {
			rtt = 60 * time.Millisecond
		}
		at := t0.Add(time.Duration(i) * time.Second)
		m.Handle(Packet{At: at, Src: ps5, Dst: server, Proto: protoTCP, SrcPort: 1, DstPort: 443, Flags: flagACK, Seq: uint32(i * 10), Payload: 10, HasTS: true, TSval: uint32(100 + i)})
		m.Handle(Packet{At: at.Add(rtt), Src: server, Dst: ps5, Proto: protoTCP, SrcPort: 443, DstPort: 1, Flags: flagACK, HasTS: true, TSval: uint32(900 + i), TSecr: uint32(100 + i)})
	}
	*now = t0.Add(10 * time.Second)
	v := m.Snapshot("192.168.1.50")
	if v.Ping == nil || v.Ping.JitterMS != 20 {
		t.Fatalf("ping = %+v", v.Ping)
	}
}

// matchStream sends server packets every 33 ms (30 Hz), each tick as a
// burst of two packets, with optional dropped ticks and delays.
func matchStream(m *Monitor, start time.Time, ticks int, drop map[int]bool, late map[int]time.Duration) time.Time {
	var at time.Time
	for i := 0; i < ticks; i++ {
		at = start.Add(time.Duration(i) * 33 * time.Millisecond)
		if drop[i] {
			continue
		}
		at = at.Add(late[i])
		for j := 0; j < 2; j++ {
			m.Handle(Packet{At: at.Add(time.Duration(j) * 500 * time.Microsecond), Src: matchIP, Dst: ps5, Proto: protoUDP, SrcPort: 3074, DstPort: 3074, Len: 200})
		}
		m.Handle(Packet{At: at.Add(2 * time.Millisecond), Src: ps5, Dst: matchIP, Proto: protoUDP, SrcPort: 3074, DstPort: 3074, Len: 100})
	}
	return at
}

func TestMatchStreamSteady(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	*now = matchStream(m, start, 300, nil, nil)
	v := m.Snapshot("192.168.1.50")
	if v.Match == nil {
		t.Fatalf("no match stream: %+v", v)
	}
	c := v.Match
	if c.Proto != "UDP" || c.Remote != "18.9.9.9:3074" || c.InRate < 55 || c.InRate > 65 {
		t.Fatalf("match = %+v", c)
	}
	if c.JitterMS != 0 || !c.HasLoss || c.LossPct != 0 {
		t.Fatalf("steady stream: jitter %v loss %v (%v)", c.JitterMS, c.LossPct, c.HasLoss)
	}
	if v.Ping != nil {
		t.Fatalf("UDP only, but ping = %+v", v.Ping)
	}
}

func TestSingleMissingPacketCounts(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	// 300 ticks, one tick dropped every 30 from tick 60 on: 8 missing.
	drop := map[int]bool{}
	for i := 60; i < 300; i += 30 {
		drop[i] = true
	}
	*now = matchStream(m, start, 300, drop, nil)
	c := m.Snapshot("192.168.1.50").Match
	// The last 30 s hold ~240 bursts (480 packets, two per tick) and 8 missing ticks.
	if c == nil || c.LossPct < 1 || c.LossPct > 3 {
		t.Fatalf("match = %+v", c)
	}
}

func TestMatchStreamLossAndJitter(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	drop := map[int]bool{}
	for i := 100; i < 300; i += 20 {
		drop[i], drop[i+1] = true, true // ten gaps of two missing ticks
	}
	late := map[int]time.Duration{}
	for i := 50; i < 300; i += 7 {
		late[i] = 10 * time.Millisecond
	}
	*now = matchStream(m, start, 300, drop, late)
	c := m.Snapshot("192.168.1.50").Match
	if c == nil || !c.HasLoss || c.LossPct == 0 {
		t.Fatalf("loss not seen: %+v", c)
	}
	if c.JitterMS == 0 {
		t.Fatalf("jitter not seen: %+v", c)
	}
	if c.MaxGapMS < 90 {
		t.Fatalf("max gap = %v", c.MaxGapMS)
	}
}

func TestIgnoresMacAndLocalTraffic(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	var me [4]byte
	copy(me[:], mac.To4())
	m.Handle(Packet{At: start, Src: me, Dst: server, Proto: protoTCP, SrcPort: 1, DstPort: 443})
	m.Handle(Packet{At: start, Src: ps5, Dst: [4]byte{192, 168, 1, 77}, Proto: protoUDP, SrcPort: 1, DstPort: 2})
	*now = start
	if v := m.Snapshot(""); v.Console != "" || v.Active != 0 {
		t.Fatalf("view = %+v", v)
	}
}

func TestNamesAndVPN(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m, now := newMon(start)
	m.SetName("accounts.ea.com", []net.IP{net.IP(server[:])})
	m.ViaVPN = func(ip net.IP) bool { return ip.Equal(net.IP(server[:])) }
	*now = tcpExchange(m, start, 5, 20*time.Millisecond, time.Millisecond, nil)
	c := m.Snapshot("192.168.1.50").Conns[0]
	if c.Name != "accounts.ea.com" || !c.VPN {
		t.Fatalf("conn = %+v", c)
	}
}

func TestParseEthernetTCPTimestamps(t *testing.T) {
	frame := make([]byte, 14+20+32)
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 20+32+100) // 100 bytes of payload, not captured
	ip[9] = protoTCP
	copy(ip[12:], ps5[:])
	copy(ip[16:], server[:])
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 50000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 12345)
	tcp[12] = 8 << 4 // 32-byte header
	tcp[13] = flagACK
	copy(tcp[20:], []byte{1, 1, 8, 10})
	binary.BigEndian.PutUint32(tcp[24:], 777)
	binary.BigEndian.PutUint32(tcp[28:], 555)

	p, ok := ParseEthernet(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("not parsed")
	}
	if p.Src != ps5 || p.Dst != server || p.SrcPort != 50000 || p.DstPort != 443 || p.Seq != 12345 {
		t.Fatalf("packet = %+v", p)
	}
	if p.Payload != 100 || !p.HasTS || p.TSval != 777 || p.TSecr != 555 {
		t.Fatalf("payload/timestamps = %+v", p)
	}
	frame[12] = 0x86 // IPv6
	if _, ok := ParseEthernet(frame, time.Unix(1, 0)); ok {
		t.Fatal("IPv6 parsed as IPv4")
	}
}
