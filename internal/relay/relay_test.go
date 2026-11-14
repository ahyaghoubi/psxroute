package relay

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// TestSpliceEndsWhenServerLingers: the console sends its request and closes;
// the server answers but never closes. The relay must still finish, after the
// grace period, with the answer delivered.
func TestSpliceEndsWhenServerLingers(t *testing.T) {
	clientSide, relayClient := net.Pipe()
	relayUp, serverSide := tcpPair(t)

	go func() {
		buf := make([]byte, 5)
		_, _ = io.ReadFull(serverSide, buf)
		_, _ = serverSide.Write([]byte("reply"))
		// …and then stays silent without closing.
	}()
	done := make(chan struct{})
	var down int64
	go func() {
		_, down, _ = splice(relayClient, bufio.NewReader(relayClient), relayUp)
		close(done)
	}()
	_, _ = clientSide.Write([]byte("hello"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(clientSide, got); err != nil || string(got) != "reply" {
		t.Fatalf("reply = %q, %v", got, err)
	}
	clientSide.Close()

	select {
	case <-done:
	case <-time.After(drainGrace + 5*time.Second):
		t.Fatal("splice never finished")
	}
	if down != 5 {
		t.Fatalf("down = %d", down)
	}
	serverSide.Close()
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, <-acc
}
