package sni

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHello captures a real ClientHello from crypto/tls for serverName.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan []byte)
	go func() {
		_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64<<10)
		var got []byte
		for {
			n, err := b.Read(buf)
			got = append(got, buf[:n]...)
			// One record is enough for these tests' hellos.
			if err != nil || len(got) >= 5 && len(got) >= 5+(int(got[3])<<8|int(got[4])) {
				break
			}
		}
		b.Close()
		done <- got
	}()
	c := tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = c.Handshake() // fails once the pipe closes; we only want the hello
	a.Close()
	return <-done
}

func TestPeekTLS(t *testing.T) {
	hello := clientHello(t, "accounts.ea.com")
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(hello), strings.NewReader("tail")), BufferSize)
	host, err := PeekTLS(br)
	if err != nil {
		t.Fatal(err)
	}
	if host != "accounts.ea.com" {
		t.Fatalf("host = %q", host)
	}
	// Nothing consumed: the full hello and what follows are still readable.
	rest, _ := io.ReadAll(br)
	if !bytes.Equal(rest, append(append([]byte(nil), hello...), "tail"...)) {
		t.Fatal("PeekTLS consumed bytes")
	}
}

func TestPeekTLSHelloSplitAcrossRecords(t *testing.T) {
	hello := clientHello(t, "prod.demonware.net")
	body := hello[5:]
	cut := len(body) / 2
	var split []byte
	for _, frag := range [][]byte{body[:cut], body[cut:]} {
		split = append(split, 0x16, 0x03, 0x01, byte(len(frag)>>8), byte(len(frag)))
		split = append(split, frag...)
	}
	host, err := PeekTLS(bufio.NewReaderSize(bytes.NewReader(split), BufferSize))
	if err != nil || host != "prod.demonware.net" {
		t.Fatalf("host = %q, err = %v", host, err)
	}
}

func TestPeekTLSRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"http":      []byte("GET / HTTP/1.1\r\n\r\n"),
		"truncated": clientHello(t, "x.ea.com")[:40],
		"no sni":    clientHello(t, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if host, err := PeekTLS(bufio.NewReaderSize(bytes.NewReader(in), BufferSize)); err == nil {
				t.Fatalf("got host %q, want error", host)
			}
		})
	}
}

func TestPeekHTTP(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nHost: Www.CallOfDuty.com:80\r\nUser-Agent: x\r\n\r\nbody"
	br := bufio.NewReaderSize(strings.NewReader(req), BufferSize)
	host, err := PeekHTTP(br)
	if err != nil || host != "Www.CallOfDuty.com" {
		t.Fatalf("host = %q, err = %v", host, err)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != req {
		t.Fatal("PeekHTTP consumed bytes")
	}
}

func TestPeekHTTPSlowClient(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		for _, part := range []string{"GET / HTTP/1.1\r\nHo", "st: ea.com\r\n", "\r\n"} {
			_, _ = a.Write([]byte(part))
			time.Sleep(10 * time.Millisecond)
		}
	}()
	defer a.Close()
	host, err := PeekHTTP(bufio.NewReaderSize(b, BufferSize))
	if err != nil || host != "ea.com" {
		t.Fatalf("host = %q, err = %v", host, err)
	}
}

func TestPeekHTTPRejectsIPHost(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
	if _, err := PeekHTTP(bufio.NewReaderSize(strings.NewReader(req), BufferSize)); err == nil {
		t.Fatal("want error for IP literal")
	}
}
