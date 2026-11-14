//go:build darwin

package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/bpf"
)

// snapLen is how much of each packet is copied: enough for the Ethernet,
// IP and TCP headers with options. Payloads are never read.
const snapLen = 128

const dltEthernet = 1

// Capture reads packet headers on iface and feeds them to m until ctx is
// done. Traffic to or from self (this Mac) is filtered out in the kernel.
// It needs root, which gateway mode already has.
func Capture(ctx context.Context, iface string, self net.IP, m *Monitor) error {
	fd, err := openBPF()
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()

	bufLen, err := syscall.SetBpfBuflen(fd, 1<<20) //nolint:staticcheck // SA1019: no non-deprecated way to set up BPF on macOS; x/net/bpf only assembles programs
	if err != nil {
		return fmt.Errorf("set capture buffer: %w", err)
	}
	if err := syscall.SetBpfInterface(fd, iface); err != nil { //nolint:staticcheck // SA1019: no non-deprecated way to set up BPF on macOS; x/net/bpf only assembles programs
		return fmt.Errorf("capture on %s: %w", iface, err)
	}
	dlt, err := syscall.BpfDatalink(fd) //nolint:staticcheck // SA1019: no non-deprecated way to set up BPF on macOS; x/net/bpf only assembles programs
	if err != nil {
		return fmt.Errorf("capture on %s: %w", iface, err)
	}
	if dlt != dltEthernet {
		return fmt.Errorf("%s isn't an Ethernet or Wi-Fi interface (link type %d)", iface, dlt)
	}
	prog, err := filter(self)
	if err != nil {
		return err
	}
	if err := syscall.SetBpf(fd, prog); err != nil { //nolint:staticcheck // SA1019: no non-deprecated way to set up BPF on macOS; x/net/bpf only assembles programs
		return fmt.Errorf("set capture filter: %w", err)
	}
	// Wake up at least five times a second so ctx is noticed; packets are
	// batched in between, each with its own kernel timestamp.
	if err := syscall.SetBpfTimeout(fd, &syscall.Timeval{Usec: 200000}); err != nil { //nolint:staticcheck // SA1019: no non-deprecated way to set up BPF on macOS; x/net/bpf only assembles programs
		return fmt.Errorf("set capture timeout: %w", err)
	}

	m.SetRunning()
	buf := make([]byte, bufLen)
	for ctx.Err() == nil {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
				continue
			}
			return fmt.Errorf("capture: %w", err)
		}
		readBatch(buf[:n], m)
	}
	return nil
}

// readBatch walks the bpf_hdr records in one read.
func readBatch(b []byte, m *Monitor) {
	for len(b) >= 18 {
		sec := int32(binary.NativeEndian.Uint32(b[0:4]))
		usec := int32(binary.NativeEndian.Uint32(b[4:8]))
		caplen := int(binary.NativeEndian.Uint32(b[8:12]))
		hdrlen := int(binary.NativeEndian.Uint16(b[16:18]))
		if hdrlen < 18 || hdrlen+caplen > len(b) {
			return
		}
		if p, ok := ParseEthernet(b[hdrlen:hdrlen+caplen], time.Unix(int64(sec), int64(usec)*1000)); ok {
			m.Handle(p)
		}
		next := (hdrlen + caplen + 3) &^ 3 // BPF_WORDALIGN: 4 bytes on macOS
		if next > len(b) {
			return
		}
		b = b[next:]
	}
}

// filterProgram keeps IPv4 packets that don't involve self, cut to snapLen.
func filterProgram(self net.IP) ([]bpf.Instruction, error) {
	v4 := self.To4()
	if v4 == nil {
		return nil, fmt.Errorf("this Mac's address %v isn't IPv4", self)
	}
	me := binary.BigEndian.Uint32(v4)
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                         // EtherType
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 5}, // IPv4 or drop
		bpf.LoadAbsolute{Off: 26, Size: 4},                         // source
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: me, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 30, Size: 4}, // destination
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: me, SkipTrue: 1},
		bpf.RetConstant{Val: snapLen},
		bpf.RetConstant{Val: 0},
	}, nil
}

func filter(self net.IP) ([]syscall.BpfInsn, error) {
	prog, err := filterProgram(self)
	if err != nil {
		return nil, err
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, err
	}
	out := make([]syscall.BpfInsn, len(raw))
	for i, r := range raw {
		out[i] = syscall.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return out, nil
}

func openBPF() (int, error) {
	var last error
	for i := 0; i < 256; i++ {
		fd, err := syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
		if err == nil {
			return fd, nil
		}
		last = err
		if errors.Is(err, syscall.EBUSY) {
			continue
		}
		break
	}
	if errors.Is(last, syscall.EACCES) || errors.Is(last, syscall.EPERM) {
		return -1, errors.New("watching the console's connections needs root: run psxroute with sudo")
	}
	return -1, fmt.Errorf("open packet capture: %w", last)
}
