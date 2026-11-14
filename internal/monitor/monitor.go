// Package monitor watches the console's own connections as this Mac forwards
// them in gateway mode, and works out what matters for online play: ping,
// jitter and packet loss. It is passive: it reads packet headers that are
// already passing through and never sends anything.
//
// What can be measured without sending anything:
//
//   - TCP ping: the time between a packet leaving for the server and the
//     server's reply that acknowledges it, matched by the TCP timestamp
//     option or the connection handshake. That covers the Mac to the server
//     and back; the home network leg (Mac to PS5 and back) is measured the
//     same way in the other direction and added on.
//   - TCP loss: segments sent again (retransmitted) or arriving out of
//     order, as a share of all data segments.
//   - Match traffic (UDP): game servers send at a steady rate, so the
//     variation in the gap between the server's packets is the jitter the
//     PS5 sees, and a gap several times the usual one means packets went
//     missing. UDP has no replies to time, so it has no ping.
package monitor

import (
	"encoding/binary"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	historySecs = 60
	// activeWithin is how recently a connection must have carried traffic to
	// be listed.
	activeWithin = 15 * time.Second
	idleFlow     = 2 * time.Minute
	maxFlows     = 4096
	maxNames     = 8192
	maxPending   = 2048 // unanswered timestamps kept per direction per flow
	// A sample above this is a stalled connection, not a ping.
	maxSampleMS = 5000
	// burstMS: packets closer than this are one burst (one game tick split
	// over several packets), not separate arrivals.
	burstMS = 3.0
	// minMatchRate is the packets per second from a server for its UDP flow
	// to count as match traffic.
	minMatchRate = 10
)

// Ports that are never match traffic.
var notMatchPorts = map[uint16]bool{53: true, 123: true, 1900: true, 5353: true}

type flowKey struct {
	local, remote [4]byte
	lport, rport  uint16
	proto         uint8
}

// second holds one second of a flow's measurements.
type second struct {
	t               int64
	pktsIn, pktsOut int
	data, retrans   int     // TCP data segments, and those sent again or out of order
	rtt, home       float64 // lowest sample this second in ms; 0 for none
	jitSum          float64 // UDP: sum of changes in the server's packet gaps
	jitN            int
	missing         int     // UDP: packets inferred missing from gaps
	maxGap          float64 // UDP: longest gap between the server's packets, ms
}

type tcpDir struct {
	maxEnd uint32
	have   bool
}

type flow struct {
	key   flowKey
	last  time.Time
	secs  [historySecs]second
	synAt time.Time // console's SYN, awaiting the server's SYN-ACK
	ackAt time.Time // server's SYN-ACK, awaiting the console's ACK
	out   tcpDir    // console → server
	in    tcpDir    // server → console
	// Timestamps seen and not yet echoed, by value: tsOut were sent by the
	// console, tsIn by the server.
	tsOut, tsIn map[uint32]time.Time

	lastIn  time.Time // UDP: start of the server's last burst
	lastGap float64
	gaps    [64]float64
	gapN    int
	median  float64
}

func (f *flow) sec(at time.Time) *second {
	t := at.Unix()
	s := &f.secs[t%historySecs]
	if s.t != t {
		*s = second{t: t}
	}
	return s
}

// Monitor is safe for concurrent use.
type Monitor struct {
	lanNet, lanMask uint32
	self            [4]byte
	// ViaVPN, when set, says whether an address goes through the VPN.
	ViaVPN func(ip net.IP) bool

	mu      sync.Mutex
	flows   map[flowKey]*flow
	names   map[[4]byte]string
	running bool
	problem string
	now     func() time.Time
}

// New returns a monitor for consoles on lan. Traffic to or from self (this
// Mac) is ignored: only forwarded traffic is the console's.
func New(lan *net.IPNet, self net.IP) *Monitor {
	m := &Monitor{flows: map[flowKey]*flow{}, names: map[[4]byte]string{}, now: time.Now}
	if v4 := lan.IP.To4(); v4 != nil && len(lan.Mask) == 4 {
		m.lanMask = binary.BigEndian.Uint32(lan.Mask)
		m.lanNet = binary.BigEndian.Uint32(v4) & m.lanMask
	}
	copy(m.self[:], self.To4())
	return m
}

func (m *Monitor) inLAN(a [4]byte) bool {
	return m.lanMask != 0 && binary.BigEndian.Uint32(a[:])&m.lanMask == m.lanNet
}

// SetRunning records that capture has started.
func (m *Monitor) SetRunning() {
	m.mu.Lock()
	m.running, m.problem = true, ""
	m.mu.Unlock()
}

// SetProblem records why capture isn't running.
func (m *Monitor) SetProblem(msg string) {
	m.mu.Lock()
	m.running, m.problem = false, msg
	m.mu.Unlock()
}

// SetName labels addresses with the name the console looked up for them.
func (m *Monitor) SetName(name string, ips []net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		var k [4]byte
		copy(k[:], v4)
		if _, ok := m.names[k]; !ok && len(m.names) >= maxNames {
			for old := range m.names { // drop an arbitrary one
				delete(m.names, old)
				break
			}
		}
		m.names[k] = name
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func lowest(cur *float64, v float64) {
	if v <= 0 || v > maxSampleMS {
		return
	}
	if *cur == 0 || v < *cur {
		*cur = v
	}
}

// seqLT compares TCP sequence numbers with wrap-around.
func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

// Handle takes one captured packet.
func (m *Monitor) Handle(p Packet) {
	if p.Src == m.self || p.Dst == m.self {
		return
	}
	var key flowKey
	var out bool
	switch {
	case m.inLAN(p.Src) && !m.inLAN(p.Dst):
		out = true
		key = flowKey{local: p.Src, remote: p.Dst, lport: p.SrcPort, rport: p.DstPort, proto: p.Proto}
	case m.inLAN(p.Dst) && !m.inLAN(p.Src):
		key = flowKey{local: p.Dst, remote: p.Src, lport: p.DstPort, rport: p.SrcPort, proto: p.Proto}
	default:
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.flows[key]
	if f == nil {
		if len(m.flows) >= maxFlows {
			m.sweep(p.At)
			if len(m.flows) >= maxFlows {
				return
			}
		}
		f = &flow{key: key}
		m.flows[key] = f
	}
	f.last = p.At
	s := f.sec(p.At)
	if out {
		s.pktsOut++
	} else {
		s.pktsIn++
	}
	switch p.Proto {
	case protoTCP:
		f.tcp(p, out, s)
	case protoUDP:
		if !out {
			f.udpIn(p, s)
		}
	}
}

func (f *flow) tcp(p Packet, out bool, s *second) {
	syn, ack := p.Flags&flagSYN != 0, p.Flags&flagACK != 0
	// Handshake: SYN to SYN-ACK is a clean ping sample, SYN-ACK to ACK a
	// clean home network one.
	switch {
	case out && syn && !ack:
		*f = flow{key: f.key, last: f.last, secs: f.secs, synAt: p.At}
	case !out && syn && ack && !f.synAt.IsZero():
		lowest(&s.rtt, ms(p.At.Sub(f.synAt)))
		f.synAt, f.ackAt = time.Time{}, p.At
	case out && !syn && ack && !f.ackAt.IsZero():
		lowest(&s.home, ms(p.At.Sub(f.ackAt)))
		f.ackAt = time.Time{}
	}

	if p.HasTS {
		if f.tsOut == nil {
			f.tsOut, f.tsIn = map[uint32]time.Time{}, map[uint32]time.Time{}
		}
		sent, echoed := f.tsIn, f.tsOut // console's packet echoes the server's
		target := &s.home
		if !out {
			sent, echoed, target = f.tsOut, f.tsIn, &s.rtt
		}
		if p.TSecr != 0 {
			if t, ok := sent[p.TSecr]; ok {
				lowest(target, ms(p.At.Sub(t)))
				delete(sent, p.TSecr)
			}
		}
		if _, ok := echoed[p.TSval]; !ok {
			if len(echoed) >= maxPending {
				prune(echoed, p.At)
			}
			if len(echoed) < maxPending {
				echoed[p.TSval] = p.At
			}
		}
	}

	if p.Payload > 0 && !syn && p.Flags&flagRST == 0 {
		d := &f.in
		if out {
			d = &f.out
		}
		end := p.Seq + uint32(p.Payload)
		keepalive := d.have && p.Payload <= 1 && p.Seq == d.maxEnd-1
		if !keepalive {
			s.data++
			if d.have && seqLT(p.Seq, d.maxEnd) {
				s.retrans++
			}
		}
		if !d.have || seqLT(d.maxEnd, end) {
			d.maxEnd, d.have = end, true
		}
	}
}

// prune drops timestamps that were never echoed.
func prune(pending map[uint32]time.Time, now time.Time) {
	for v, t := range pending {
		if now.Sub(t) > 3*time.Second {
			delete(pending, v)
		}
	}
}

func (f *flow) udpIn(p Packet, s *second) {
	if !f.lastIn.IsZero() {
		gap := ms(p.At.Sub(f.lastIn))
		if gap < burstMS {
			return // part of the same burst
		}
		if gap > s.maxGap {
			s.maxGap = gap
		}
		if f.lastGap > 0 && gap < 1000 && f.lastGap < 1000 {
			s.jitSum += math.Abs(gap - f.lastGap)
			s.jitN++
		}
		f.lastGap = gap
		f.gaps[f.gapN%len(f.gaps)] = gap
		f.gapN++
		if f.gapN >= 32 && f.gapN%16 == 0 {
			f.median = median(f.gaps[:min(f.gapN, len(f.gaps))])
		}
		// A gap much longer than usual means packets that never arrived. A
		// pause of a second or more is the game going quiet, not loss.
		if med := f.median; med > 0 && med < 200 && gap < 1000 && gap > med*1.7 && gap > med+12 {
			s.missing += int(math.Round(gap/med)) - 1
		}
	}
	f.lastIn = p.At
}

func median(v []float64) float64 {
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	return c[len(c)/2]
}

// sweep forgets idle flows. The caller holds m.mu.
func (m *Monitor) sweep(now time.Time) {
	for k, f := range m.flows {
		if now.Sub(f.last) > idleFlow {
			delete(m.flows, k)
		}
	}
}

// Conn is one of the console's connections.
type Conn struct {
	Name   string `json:"name,omitempty"`
	Remote string `json:"remote"`
	Proto  string `json:"proto"`
	VPN    bool   `json:"vpn"`
	// Packets per second over the last 10 seconds.
	InRate  float64 `json:"in_rate"`
	OutRate float64 `json:"out_rate"`

	// TCP: ping includes the home network leg.
	HasPing  bool    `json:"has_ping"`
	PingMS   float64 `json:"ping_ms"`
	JitterMS float64 `json:"jitter_ms"`
	// HasLoss is false until enough packets have been seen to say.
	HasLoss bool    `json:"has_loss"`
	LossPct float64 `json:"loss_pct"`

	// UDP match traffic: longest silence from the server, last 30 seconds.
	MaxGapMS float64 `json:"max_gap_ms,omitempty"`

	ip     net.IP
	remote [4]byte
	key    flowKey
}

// View is what the page shows.
type View struct {
	Running bool   `json:"running"`
	Problem string `json:"problem,omitempty"`
	Console string `json:"console,omitempty"`
	// Active is how many connections carried traffic in the last 15 seconds.
	Active  int     `json:"active"`
	HasHome bool    `json:"has_home"`
	HomeMS  float64 `json:"home_ms"`
	// Ping is the TCP connection the headline ping comes from; Match is the
	// game's UDP traffic, when there is any.
	Ping  *Conn  `json:"ping,omitempty"`
	Match *Conn  `json:"match,omitempty"`
	Conns []Conn `json:"conns"`
	// One value per second, oldest first: ping in ms (-1 none), match jitter
	// in ms (-1 none), and packets lost or sent again.
	PingHist   []float64 `json:"ping_hist"`
	JitterHist []float64 `json:"jitter_hist"`
	LossHist   []int     `json:"loss_hist"`
}

// Snapshot summarises the console's connections. console is its address if
// known; otherwise the busiest device is used.
func (m *Monitor) Snapshot(console string) View {
	now := m.now()
	nowSec := now.Unix()
	m.mu.Lock()
	v := View{Running: m.running, Problem: m.problem, Conns: []Conn{}}
	m.sweep(now)

	local, ok := parse4(console)
	if !ok {
		local, ok = m.busiest(nowSec)
	}
	if !ok {
		m.mu.Unlock()
		return v
	}
	v.Console = net.IP(local[:]).String()

	var homeBySec [historySecs]float64
	var flows []*flow
	for _, f := range m.flows {
		if f.key.local != local || now.Sub(f.last) > activeWithin {
			continue
		}
		flows = append(flows, f)
		for _, s := range f.secs {
			if age := nowSec - s.t; age >= 0 && age < 30 && s.home > 0 {
				lowest(&homeBySec[age], s.home)
			}
		}
	}
	var homes []float64
	for _, h := range homeBySec {
		if h > 0 {
			homes = append(homes, h)
		}
	}
	if len(homes) > 0 {
		v.HasHome, v.HomeMS = true, round1(median(homes))
	}
	for _, f := range flows {
		c := summarise(f, nowSec, v.HomeMS)
		c.Name = m.names[f.key.remote]
		v.Conns = append(v.Conns, c)
	}
	m.mu.Unlock()

	// Outside the lock: ViaVPN takes the gateway's.
	for i := range v.Conns {
		if m.ViaVPN != nil {
			v.Conns[i].VPN = m.ViaVPN(v.Conns[i].ip)
		}
	}
	v.Active = len(v.Conns)
	sort.Slice(v.Conns, func(i, j int) bool {
		a, b := v.Conns[i], v.Conns[j]
		if ra, rb := a.InRate+a.OutRate, b.InRate+b.OutRate; ra != rb {
			return ra > rb
		}
		return a.Remote < b.Remote
	})

	// Match traffic: the busiest UDP stream from a server.
	for i := range v.Conns {
		c := &v.Conns[i]
		if c.Proto == "UDP" && c.InRate >= minMatchRate && !notMatchPorts[c.key.rport] && !notMatchPorts[c.key.lport] {
			mc := *c
			v.Match = &mc
			break
		}
	}
	// Headline ping: a connection to the match server if there is one, then
	// one through the VPN, then the busiest.
	pick := -1
	for i, c := range v.Conns {
		if !c.HasPing {
			continue
		}
		switch {
		case v.Match != nil && c.remote == v.Match.remote:
			pick = i
		case pick < 0:
			pick = i
		case c.VPN && !v.Conns[pick].VPN && (v.Match == nil || v.Conns[pick].remote != v.Match.remote):
			pick = i
		}
		if v.Match != nil && c.remote == v.Match.remote {
			break
		}
	}
	if pick >= 0 {
		pc := v.Conns[pick]
		v.Ping = &pc
	}

	v.PingHist = make([]float64, historySecs)
	v.JitterHist = make([]float64, historySecs)
	v.LossHist = make([]int, historySecs)
	for i := range v.PingHist {
		v.PingHist[i], v.JitterHist[i] = -1, -1
	}
	m.mu.Lock()
	if v.Ping != nil {
		if f := m.flows[v.Ping.key]; f != nil {
			for _, s := range f.secs {
				if age := nowSec - s.t; age >= 0 && age < historySecs {
					i := historySecs - 1 - int(age)
					if s.rtt > 0 {
						v.PingHist[i] = round1(s.rtt + v.HomeMS)
					}
					v.LossHist[i] += s.retrans
				}
			}
		}
	}
	if v.Match != nil {
		if f := m.flows[v.Match.key]; f != nil {
			for _, s := range f.secs {
				if age := nowSec - s.t; age >= 0 && age < historySecs {
					i := historySecs - 1 - int(age)
					if s.jitN > 0 {
						v.JitterHist[i] = round1(s.jitSum / float64(s.jitN))
					}
					v.LossHist[i] += s.missing
				}
			}
		}
	}
	m.mu.Unlock()
	if len(v.Conns) > 20 {
		v.Conns = v.Conns[:20]
	}
	return v
}

// busiest finds the device with the most packets in the last 10 seconds.
// The caller holds m.mu.
func (m *Monitor) busiest(nowSec int64) ([4]byte, bool) {
	count := map[[4]byte]int{}
	for _, f := range m.flows {
		for _, s := range f.secs {
			if age := nowSec - s.t; age >= 0 && age < 10 {
				count[f.key.local] += s.pktsIn + s.pktsOut
			}
		}
	}
	var best [4]byte
	n := 0
	for ip, c := range count {
		if c > n || c == n && string(ip[:]) < string(best[:]) {
			best, n = ip, c
		}
	}
	return best, n > 0
}

// summarise works out one connection's figures. The caller holds m.mu.
func summarise(f *flow, nowSec int64, home float64) Conn {
	ip := net.IP(append([]byte(nil), f.key.remote[:]...))
	c := Conn{
		Remote: net.JoinHostPort(ip.String(), strconv.Itoa(int(f.key.rport))),
		Proto:  "TCP", ip: ip, remote: f.key.remote, key: f.key,
	}
	if f.key.proto == protoUDP {
		c.Proto = "UDP"
	}
	// Seconds of the last 30, oldest first.
	var recent []second
	for age := int64(29); age >= 0; age-- {
		s := f.secs[(nowSec-age)%historySecs]
		if s.t == nowSec-age {
			recent = append(recent, s)
		}
	}
	var in, out, data, retrans, missing, pktsIn30, jitN int
	var rtts []float64
	var jitSum float64
	for _, s := range recent {
		if nowSec-s.t < 10 {
			in += s.pktsIn
			out += s.pktsOut
			jitSum += s.jitSum
			jitN += s.jitN
		}
		data += s.data
		retrans += s.retrans
		missing += s.missing
		pktsIn30 += s.pktsIn
		if s.rtt > 0 {
			rtts = append(rtts, s.rtt)
		}
		if s.maxGap > c.MaxGapMS {
			c.MaxGapMS = round1(s.maxGap)
		}
	}
	c.InRate, c.OutRate = round1(float64(in)/10), round1(float64(out)/10)

	if c.Proto == "TCP" {
		c.MaxGapMS = 0
		if len(rtts) > 0 {
			c.HasPing = true
			c.PingMS = round1(median(rtts) + home)
			if len(rtts) > 1 {
				var d float64
				for i := 1; i < len(rtts); i++ {
					d += math.Abs(rtts[i] - rtts[i-1])
				}
				c.JitterMS = round1(d / float64(len(rtts)-1))
			}
		}
		if data >= 20 {
			c.HasLoss, c.LossPct = true, round1(100*float64(retrans)/float64(data))
		}
		return c
	}
	if jitN > 0 {
		c.JitterMS = round1(jitSum / float64(jitN))
	}
	if pktsIn30 >= 100 {
		c.HasLoss, c.LossPct = true, round1(100*float64(missing)/float64(pktsIn30+missing))
	}
	return c
}

func parse4(s string) ([4]byte, bool) {
	var a [4]byte
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return a, false
	}
	copy(a[:], ip)
	return a, true
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
