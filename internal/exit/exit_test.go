package exit

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// echoServer echoes one line back.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// connectProxy is a minimal HTTP CONNECT proxy that sends every tunnel to
// target and records the requested authority.
func connectProxy(t *testing.T, target string, got chan<- *http.Request) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				got <- req
				up, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestHTTPConnect(t *testing.T) {
	got := make(chan *http.Request, 1)
	proxyAddr := connectProxy(t, echoServer(t), got)
	d, err := New("http://user:pw@"+proxyAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), "tcp", "accounts.ea.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c)
	req := <-got
	if req.Method != http.MethodConnect || req.Host != "accounts.ea.com:443" {
		t.Fatalf("proxy got %s %s", req.Method, req.Host)
	}
	if req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwdw==" {
		t.Fatalf("auth = %q", req.Header.Get("Proxy-Authorization"))
	}
}

func TestDirectIPLiteral(t *testing.T) {
	d, err := New("direct", []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), "tcp", echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c)
}

func TestNewRejects(t *testing.T) {
	if _, err := New("ftp://x:1", nil); err == nil {
		t.Fatal("want error")
	}
}
