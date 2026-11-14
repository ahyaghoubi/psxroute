// Package sni reads the destination host name from the first bytes of a
// connection without consuming them: the server_name of a TLS ClientHello, or
// the Host header of a plain HTTP request. Nothing is decrypted.
package sni

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// MaxHello caps how much of a ClientHello is buffered. Real ones fit in a
// few kilobytes; post-quantum key shares push some past one TLS record.
const MaxHello = 64 << 10

// BufferSize is the bufio.Reader size the peek functions need.
const BufferSize = MaxHello + 5

var (
	errNotTLS  = errors.New("not a TLS handshake")
	errNoSNI   = errors.New("ClientHello has no server_name")
	errTooBig  = errors.New("ClientHello too large")
	errBadHTTP = errors.New("not an HTTP request")
)

// PeekTLS returns the server_name from the ClientHello at the start of br.
// The bytes stay in br so they can be forwarded unchanged. br must be at
// least BufferSize bytes.
func PeekTLS(br *bufio.Reader) (string, error) {
	var hs []byte // handshake bytes collected across records
	off := 0
	for {
		hdr, err := br.Peek(off + 5)
		if err != nil {
			return "", err
		}
		rec := hdr[off:]
		if rec[0] != 0x16 || rec[1] != 0x03 {
			return "", errNotTLS
		}
		n := int(rec[3])<<8 | int(rec[4])
		if off+5+n > MaxHello {
			return "", errTooBig
		}
		full, err := br.Peek(off + 5 + n)
		if err != nil {
			return "", err
		}
		hs = append(hs, full[off+5:]...)
		off += 5 + n
		if len(hs) >= 4 {
			if hs[0] != 0x01 {
				return "", errNotTLS
			}
			want := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if want > MaxHello {
				return "", errTooBig
			}
			if len(hs) >= want {
				return serverName(hs[4:want])
			}
		}
	}
}

// serverName parses a ClientHello body for the host_name entry of the
// server_name extension (RFC 6066).
func serverName(b []byte) (string, error) {
	p := parser{b: b}
	p.skip(2 + 32)  // legacy_version, random
	p.skip(p.u8())  // session id
	p.skip(p.u16()) // cipher suites
	p.skip(p.u8())  // compression methods
	ext := p.sub(p.u16())
	for p.err == nil && len(ext.b) > 0 {
		typ := ext.u16()
		body := ext.sub(ext.u16())
		if ext.err != nil {
			break
		}
		if typ != 0 {
			continue
		}
		list := body.sub(body.u16())
		for body.err == nil && list.err == nil && len(list.b) > 0 {
			kind := list.u8()
			name := list.bytes(list.u16())
			if list.err == nil && kind == 0 {
				host := string(name)
				if !validHost(host) {
					return "", fmt.Errorf("invalid server_name %q", host)
				}
				return host, nil
			}
		}
		return "", errNoSNI
	}
	if p.err != nil || ext.err != nil {
		return "", errors.New("malformed ClientHello")
	}
	return "", errNoSNI
}

// PeekHTTP returns the Host of the HTTP request at the start of br, leaving
// the bytes in br. br must be at least BufferSize bytes.
func PeekHTTP(br *bufio.Reader) (string, error) {
	const maxHead = 16 << 10
	for n := 1; ; {
		// Wait for at least n bytes, then look at everything that's arrived.
		if _, err := br.Peek(n); err != nil {
			return "", err
		}
		buf, _ := br.Peek(br.Buffered())
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			req, rerr := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf[:i+4])))
			if rerr != nil {
				return "", errBadHTTP
			}
			host := req.Host
			if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
				host = h
			}
			if !validHost(host) {
				return "", fmt.Errorf("invalid Host %q", host)
			}
			return host, nil
		}
		if len(buf) >= maxHead {
			return "", errBadHTTP
		}
		n = len(buf) + 1
	}
}

// validHost accepts DNS names only: no IP literals, ports or odd bytes.
func validHost(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

type parser struct {
	b   []byte
	err error
}

func (p *parser) need(n int) bool {
	if p.err != nil {
		return false
	}
	if n < 0 || len(p.b) < n {
		p.err = errors.New("short")
		return false
	}
	return true
}

func (p *parser) u8() int {
	if !p.need(1) {
		return 0
	}
	v := int(p.b[0])
	p.b = p.b[1:]
	return v
}

func (p *parser) u16() int {
	if !p.need(2) {
		return 0
	}
	v := int(p.b[0])<<8 | int(p.b[1])
	p.b = p.b[2:]
	return v
}

func (p *parser) skip(n int) {
	if p.need(n) {
		p.b = p.b[n:]
	}
}

func (p *parser) bytes(n int) []byte {
	if !p.need(n) {
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}

func (p *parser) sub(n int) *parser {
	b := p.bytes(n)
	return &parser{b: b, err: p.err}
}
