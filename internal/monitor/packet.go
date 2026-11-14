package monitor

import (
	"encoding/binary"
	"time"
)

// IP protocol numbers.
const (
	protoTCP = 6
	protoUDP = 17
)

// TCP flags.
const (
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// Packet is the header fields the monitor needs from one IPv4 packet.
type Packet struct {
	At       time.Time
	Src, Dst [4]byte
	Proto    uint8
	SrcPort  uint16
	DstPort  uint16
	Len      int // IP total length

	// TCP only.
	Flags   uint8
	Seq     uint32
	Payload int
	HasTS   bool
	TSval   uint32
	TSecr   uint32
}

// ParseEthernet reads an Ethernet frame (one VLAN tag allowed). It reports
// false for anything that isn't IPv4 TCP or UDP.
func ParseEthernet(b []byte, at time.Time) (Packet, bool) {
	if len(b) < 14 {
		return Packet{}, false
	}
	etype, off := binary.BigEndian.Uint16(b[12:14]), 14
	if etype == 0x8100 && len(b) >= 18 {
		etype, off = binary.BigEndian.Uint16(b[16:18]), 18
	}
	if etype != 0x0800 {
		return Packet{}, false
	}
	return ParseIPv4(b[off:], at)
}

// ParseIPv4 reads an IPv4 packet. b may be truncated after the transport
// header; lengths come from the headers, not len(b).
func ParseIPv4(b []byte, at time.Time) (Packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, false
	}
	p := Packet{At: at, Proto: b[9], Len: int(binary.BigEndian.Uint16(b[2:4]))}
	copy(p.Src[:], b[12:16])
	copy(p.Dst[:], b[16:20])
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return Packet{}, false // a later fragment: no ports
	}
	t := b[ihl:]
	switch p.Proto {
	case protoUDP:
		if len(t) < 8 {
			return Packet{}, false
		}
		p.SrcPort, p.DstPort = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
		return p, true
	case protoTCP:
		if len(t) < 20 {
			return Packet{}, false
		}
		p.SrcPort, p.DstPort = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
		p.Seq = binary.BigEndian.Uint32(t[4:8])
		doff := int(t[12]>>4) * 4
		p.Flags = t[13]
		if doff < 20 {
			return Packet{}, false
		}
		p.Payload = p.Len - ihl - doff
		if p.Payload < 0 {
			p.Payload = 0
		}
		if len(t) >= doff {
			p.TSval, p.TSecr, p.HasTS = timestamps(t[20:doff])
		}
		return p, true
	}
	return Packet{}, false
}

// timestamps finds the TCP timestamp option (RFC 7323).
func timestamps(opts []byte) (val, ecr uint32, ok bool) {
	for i := 0; i < len(opts); {
		switch kind := opts[i]; kind {
		case 0: // end of options
			return 0, 0, false
		case 1: // no-op
			i++
			continue
		}
		if i+1 >= len(opts) {
			return 0, 0, false
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return 0, 0, false
		}
		if opts[i] == 8 && l == 10 {
			return binary.BigEndian.Uint32(opts[i+2 : i+6]), binary.BigEndian.Uint32(opts[i+6 : i+10]), true
		}
		i += l
	}
	return 0, 0, false
}
