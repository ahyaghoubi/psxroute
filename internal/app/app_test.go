package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ahyaghoubi/psxroute/internal/config"
	"github.com/ahyaghoubi/psxroute/internal/gateway"
)

// toTarget is an exit that sends every connection to one local server and
// records the host:port it was asked for.
type toTarget struct {
	target string
	asked  chan string
}

func (d *toTarget) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.asked <- addr
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func start(t *testing.T, target string) (*App, *toTarget) {
	t.Helper()
	cfg := config.Default()
	cfg.Listen.DNS = "127.0.0.1:0"
	cfg.Listen.HTTPS = "127.0.0.1:0"
	cfg.Listen.HTTP = "127.0.0.1:0"
	cfg.Listen.Dashboard = "127.0.0.1:0"
	cfg.AdvertiseIP = "127.0.0.1"
	cfg.UpstreamDNS = []string{"127.0.0.1:9"}
	cfg.Packs = nil
	cfg.Hosts = []string{"ea.com"}
	if err := cfg.Finalise(); err != nil {
		t.Fatal(err)
	}
	ex := &toTarget{target: target, asked: make(chan string, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := Start(ctx, cfg, Options{Version: "test", Exit: ex})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = a.Wait(ctx) })
	return a, ex
}

func lookupA(t *testing.T, dnsAddr, name string) net.IP {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	q, _ := m.Pack()
	c, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var r dnsmessage.Message
	if err := r.Unpack(buf[:n]); err != nil || len(r.Answers) != 1 {
		t.Fatalf("reply %+v, err %v", r, err)
	}
	a := r.Answers[0].Body.(*dnsmessage.AResource).A
	return net.IP(a[:])
}

// TestHTTPSRoutedEndToEnd plays the console: look the name up, connect to the
// address given, and complete a real TLS request through the relay.
func TestHTTPSRoutedEndToEnd(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Host)
	}))
	defer backend.Close()
	a, ex := start(t, backend.Listener.Addr().String())

	ip := lookupA(t, a.Addrs["dns"], "accounts.ea.com.")
	if ip.String() != "127.0.0.1" {
		t.Fatalf("A = %v", ip)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, a.Addrs["https"]) // "443" on ip
			},
		},
	}
	resp, err := client.Get("https://accounts.ea.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from accounts.ea.com" {
		t.Fatalf("body = %q", body)
	}
	if got := <-ex.asked; got != "accounts.ea.com:443" {
		t.Fatalf("exit asked for %q", got)
	}

	// The dashboard has learnt both the lookup and the connection, with its
	// bytes once the connection closes.
	client.CloseIdleConnections()
	waitFor(t, func() bool {
		for _, h := range a.Tracker.Snapshot() {
			if h.Name == "accounts.ea.com" && h.Routed && h.Lookups == 1 && h.Conns == 1 && h.Active == 0 && h.BytesDown > 0 {
				return true
			}
		}
		return false
	})
	resp, err = http.Get("http://" + a.Addrs["dashboard"] + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Routed []struct {
			Name  string `json:"name"`
			Hosts []struct {
				Name string `json:"name"`
			} `json:"hosts"`
		} `json:"routed"`
	}
	err = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if err != nil || len(st.Routed) != 1 || st.Routed[0].Name != "ea.com" || st.Routed[0].Hosts[0].Name != "accounts.ea.com" {
		t.Fatalf("dashboard state = %+v, %v", st, err)
	}
}

func TestHTTPRoutedEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain "+r.Host)
	}))
	defer backend.Close()
	a, ex := start(t, backend.Listener.Addr().String())

	c, err := net.Dial("tcp", a.Addrs["http"])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: www.ea.com\r\nConnection: close\r\n\r\n")
	out, _ := io.ReadAll(c)
	if !strings.Contains(string(out), "plain www.ea.com") {
		t.Fatalf("response = %q", out)
	}
	if got := <-ex.asked; got != "www.ea.com:80" {
		t.Fatalf("exit asked for %q", got)
	}
}

func TestRelayRefusesUnroutedNames(t *testing.T) {
	a, ex := start(t, "127.0.0.1:1")
	c, err := net.Dial("tcp", a.Addrs["http"])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.net\r\n\r\n")
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("relay answered a name that isn't routed")
	}
	select {
	case got := <-ex.asked:
		t.Fatalf("exit dialled %q", got)
	default:
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// recRunner records commands for gateway-mode tests.
type recRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *recRunner) Run(_ context.Context, _, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if name == "sysctl" && len(args) > 0 && args[0] == "-n" {
		return "0\n", nil
	}
	return "", nil
}

func (r *recRunner) has(line string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == line {
			return true
		}
	}
	return false
}

// upstreamA answers every A query with 198.51.100.7.
func upstreamA(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			m.Header.Response = true
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 7}},
			}}
			out, _ := m.Pack()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestGatewayModeRoutesResolvedAddresses(t *testing.T) {
	prev := gateway.StatePath
	gateway.StatePath = filepath.Join(t.TempDir(), "psxroute.routes")
	t.Cleanup(func() { gateway.StatePath = prev })
	cfg := config.Default()
	cfg.Mode = "gateway"
	cfg.Listen.DNS = "127.0.0.1:0"
	cfg.Listen.HTTPS = "127.0.0.1:0"
	cfg.Listen.HTTP = "127.0.0.1:0"
	cfg.Listen.Dashboard = "127.0.0.1:0"
	cfg.AdvertiseIP = "192.168.1.20"
	cfg.UpstreamDNS = []string{upstreamA(t)}
	cfg.Packs, cfg.Hosts = nil, []string{"ea.com"}
	if err := cfg.Finalise(); err != nil {
		t.Fatal(err)
	}
	_, lan, _ := net.ParseCIDR("192.168.1.20/24")
	lan.IP = net.ParseIP("192.168.1.20")
	_, tun, _ := net.ParseCIDR("10.8.0.2/32")
	run := &recRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := Start(ctx, cfg, Options{
		Version: "test", SkipPreflight: true, GatewayRunner: run,
		GatewayInterfaces: []gateway.Iface{
			{Name: "en0", Up: true, MTU: 1500, Addrs: []*net.IPNet{lan}},
			{Name: "utun4", Up: true, MTU: 1400, Addrs: []*net.IPNet{tun}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Addrs["https"]; ok {
		t.Fatal("gateway mode shouldn't start the relay")
	}

	// The console gets the real address, and it's in the table by the time
	// the reply arrives.
	if ip := lookupA(t, a.Addrs["dns"], "accounts.ea.com."); ip.String() != "198.51.100.7" {
		t.Fatalf("A = %v", ip)
	}
	if !run.has("route -n add -host 198.51.100.7 -interface utun4") {
		t.Fatalf("address not routed; ran %v", run.calls)
	}
	if h := a.Tracker.Snapshot()[0]; h.Name != "accounts.ea.com" || len(h.Addrs) != 1 {
		t.Fatalf("tracker: %+v", h)
	}

	cancel()
	_ = a.Wait(ctx)
	if !run.has("pfctl -a com.apple/psxroute -F all") || !run.has("sysctl -w net.inet.ip.forwarding=0") {
		t.Fatalf("shutdown didn't clean up; ran %v", run.calls)
	}
}

func TestRoutesAddedFromDashboardAreSavedAndReloaded(t *testing.T) {
	path := t.TempDir() + "/routes.txt"
	cfg := config.Default()
	cfg.Listen.DNS, cfg.Listen.HTTPS, cfg.Listen.HTTP, cfg.Listen.Dashboard = "", "", "", "127.0.0.1:0"
	cfg.AdvertiseIP = "127.0.0.1"
	cfg.Packs, cfg.Hosts = nil, nil
	if err := cfg.Finalise(); err != nil {
		t.Fatal(err)
	}
	startDash := func() (*App, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		a, err := Start(ctx, cfg, Options{RoutesPath: path})
		if err != nil {
			t.Fatal(err)
		}
		return a, func() { cancel(); _ = a.Wait(ctx) }
	}
	post := func(a *App, path, body string) int {
		resp, err := http.Post("http://"+a.Addrs["dashboard"]+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	a, stop := startDash()
	if code := post(a, "/api/route", `{"domain":"battlefield.com"}`); code != 200 {
		t.Fatalf("route = %d", code)
	}
	if code := post(a, "/api/route", `{"domain":"not a domain"}`); code != 400 {
		t.Fatalf("bad domain = %d", code)
	}
	if _, ok := a.Rules.Match("cte.battlefield.com"); !ok {
		t.Fatal("route didn't take effect")
	}
	stop()

	a, stop = startDash()
	defer stop()
	if _, ok := a.Rules.Match("cte.battlefield.com"); !ok {
		t.Fatal("saved route wasn't reloaded")
	}
	if code := post(a, "/api/unroute", `{"domain":"battlefield.com"}`); code != 200 {
		t.Fatalf("unroute = %d", code)
	}
	if _, ok := a.Rules.Match("cte.battlefield.com"); ok {
		t.Fatal("unroute didn't take effect")
	}
}
