//go:build darwin

package monitor

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

func frame(src, dst [4]byte, etype uint16) []byte {
	f := make([]byte, 14+20+8+60)
	binary.BigEndian.PutUint16(f[12:], etype)
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[9] = protoUDP
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	binary.BigEndian.PutUint16(ip[20:], 3074)
	binary.BigEndian.PutUint16(ip[22:], 3074)
	return f
}

// TestFilterProgram runs the kernel filter in Go's BPF VM.
func TestFilterProgram(t *testing.T) {
	prog, err := filterProgram(mac)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := filter(mac); err != nil {
		t.Fatal(err)
	}
	var me [4]byte
	copy(me[:], mac.To4())
	for _, c := range []struct {
		name string
		f    []byte
		want int
	}{
		{"console to server", frame(ps5, server, 0x0800), snapLen},
		{"server to console", frame(server, ps5, 0x0800), snapLen},
		{"from this Mac", frame(me, server, 0x0800), 0},
		{"to this Mac", frame(server, me, 0x0800), 0},
		{"IPv6", frame(ps5, server, 0x86dd), 0},
	} {
		got, err := vm.Run(c.f)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: kept %d bytes, want %d", c.name, got, c.want)
		}
	}
}

// TestReadBatch walks bpf_hdr records as the kernel lays them out.
func TestReadBatch(t *testing.T) {
	m := New(lan, mac)
	var buf []byte
	for i := 0; i < 3; i++ {
		f := frame(server, ps5, 0x0800)[:101] // odd length, so padding is needed
		h := make([]byte, 18)
		binary.NativeEndian.PutUint32(h[0:], uint32(1_000_000+i))
		binary.NativeEndian.PutUint32(h[4:], 500)
		binary.NativeEndian.PutUint32(h[8:], uint32(len(f)))
		binary.NativeEndian.PutUint32(h[12:], 160)
		binary.NativeEndian.PutUint16(h[16:], 18)
		rec := append(h, f...)
		for len(rec)%4 != 0 {
			rec = append(rec, 0)
		}
		buf = append(buf, rec...)
	}
	readBatch(buf, m)
	m.now = func() time.Time { return time.Unix(1_000_002, 0) }
	v := m.Snapshot("192.168.1.50")
	if len(v.Conns) != 1 || v.Conns[0].Proto != "UDP" {
		t.Fatalf("conns = %+v", v.Conns)
	}
	var in int
	for _, s := range m.flows[v.Conns[0].key].secs {
		in += s.pktsIn
	}
	if in != 3 {
		t.Fatalf("packets read = %d, want 3", in)
	}
}
