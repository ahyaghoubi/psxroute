package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records commands and answers sysctl reads, pfctl -E and
// route get.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	stdin  []string
	fail   string // a command prefix that fails
	exists string // a command prefix that fails with route's "File exists"
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, line)
	f.stdin = append(f.stdin, stdin)
	if f.fail != "" && strings.HasPrefix(line, f.fail) {
		return "", errors.New("boom")
	}
	if f.exists != "" && strings.HasPrefix(line, f.exists) {
		return "", errors.New("route: writing to routing socket: File exists")
	}
	switch {
	case line == "sysctl -n net.inet.ip.forwarding":
		return "0\n", nil
	case line == "sysctl -n net.inet.ip.redirect":
		return "1\n", nil
	case line == "pfctl -E":
		return "No ALTQ support in kernel\npf enabled\nToken : 1234567\n", nil
	case line == "route -n get default":
		return "   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n", nil
	}
	return "", nil
}

func (f *fakeRunner) has(line string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == line {
			return true
		}
	}
	return false
}

func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.stdin = nil, nil
}

// useStateDir points StatePath at a temporary file for one test.
func useStateDir(t *testing.T) string {
	t.Helper()
	prev := StatePath
	StatePath = filepath.Join(t.TempDir(), "psxroute.routes")
	t.Cleanup(func() { StatePath = prev })
	return StatePath
}

func settings() Settings {
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	return Settings{
		LANIface: "en0", LANIP: net.ParseIP("192.168.1.20").To4(), LANNet: lan,
		DefaultIface: "en0", DefaultGW: net.ParseIP("192.168.1.1").To4(),
		Tunnel: "utun4", TunnelMTU: 1400,
		CIDRs: []string{"203.0.113.0/24"},
	}
}

func start(t *testing.T, f *fakeRunner, s Settings) *Gateway {
	t.Helper()
	g, err := Start(context.Background(), s, PF(f), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRules(t *testing.T) {
	got := Rules(settings())
	for _, want := range []string{
		"scrub on utun4 inet all max-mss 1360\n",
		"no nat on en0 inet from 192.168.1.20 to any\n",
		"nat on utun4 inet from 192.168.1.0/24 to any -> (utun4)\n",
		"nat on en0 inet from 192.168.1.0/24 to ! 192.168.1.0/24 -> (en0)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rules missing %q\n%s", want, got)
		}
	}
	// route-to panics the macOS 27 kernel on the first forwarded packet.
	if strings.Contains(got, "route-to") {
		t.Fatalf("rules must not use route-to:\n%s", got)
	}
}

// TestRulesParseWithPfctl checks the generated rules against macOS's own pf
// parser. -n parses without loading, and needs no root.
func TestRulesParseWithPfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("pfctl is macOS only")
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("no pfctl")
	}
	s := settings()
	cmd := exec.Command("pfctl", "-n", "-a", Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(Rules(s))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pfctl rejected the rules: %v\n%s\n%s", err, out, Rules(s))
	}
}

func TestStartAddClose(t *testing.T) {
	state := useStateDir(t)
	f := &fakeRunner{}
	g := start(t, f, settings())
	for _, want := range []string{
		"pfctl -a com.apple/psxroute -F all",
		"sysctl -w net.inet.ip.forwarding=1",
		"sysctl -w net.inet.ip.redirect=0",
		"pfctl -a com.apple/psxroute -f -",
		"pfctl -E",
		"route -n add -net 203.0.113.0/24 -interface utun4",
	} {
		if !f.has(want) {
			t.Errorf("Start didn't run %q; ran %v", want, f.calls)
		}
	}
	if tok := g.sys.(*pfSystem).token; tok != "1234567" {
		t.Fatalf("token = %q", tok)
	}

	ips := []net.IP{net.ParseIP("198.51.100.7"), net.ParseIP("198.51.100.7"), net.ParseIP("192.168.1.9"), net.ParseIP("2001:db8::1"), net.ParseIP("224.0.0.251")}
	n, err := g.Add(context.Background(), ips)
	if err != nil || n != 1 {
		t.Fatalf("Add = %d, %v", n, err)
	}
	if !f.has("route -n add -host 198.51.100.7 -interface utun4") {
		t.Fatalf("host route missing: %v", f.calls)
	}
	if n, _ := g.Add(context.Background(), ips[:1]); n != 0 {
		t.Fatal("re-adding a known address should do nothing")
	}
	data, _ := os.ReadFile(state)
	if string(data) != "198.51.100.7\n203.0.113.0/24\n" {
		t.Fatalf("route list = %q", data)
	}

	g.Close()
	g.Close()
	for _, want := range []string{
		"route -n delete -host 198.51.100.7",
		"route -n delete -net 203.0.113.0/24",
		"pfctl -X 1234567",
		"sysctl -w net.inet.ip.forwarding=0",
		"sysctl -w net.inet.ip.redirect=1",
	} {
		if !f.has(want) {
			t.Errorf("Close didn't run %q", want)
		}
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("route list should be gone after Close: %v", err)
	}
	if n, _ := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.8")}); n != 0 {
		t.Fatal("Add after Close should do nothing")
	}
}

func TestExistingRouteIsLeftAlone(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{exists: "route -n add -host 198.51.100.7"}
	g := start(t, f, settings())
	if n, err := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); err != nil || n != 1 {
		t.Fatalf("Add = %d, %v", n, err)
	}
	g.Close()
	if f.has("route -n delete -host 198.51.100.7") {
		t.Fatal("a route psxroute didn't add must not be deleted")
	}
}

func TestStartFailureUndoes(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{fail: "pfctl -a com.apple/psxroute -f"}
	if _, err := Start(context.Background(), settings(), PF(f), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("want error")
	}
	if !f.has("sysctl -w net.inet.ip.forwarding=0") {
		t.Fatalf("forwarding not restored after a failed start: %v", f.calls)
	}
}

func TestAddFailureForgets(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{}
	g := start(t, f, settings())
	defer g.Close()
	f.fail = "route -n add -host"
	if _, err := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); err == nil {
		t.Fatal("want error")
	}
	f.fail = ""
	if n, _ := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); n != 1 {
		t.Fatal("a failed add should be retried next time")
	}
}

func TestRemove(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{}
	g := start(t, f, settings())
	defer g.Close()
	if _, err := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); err != nil {
		t.Fatal(err)
	}
	if err := g.Remove(context.Background(), []string{"198.51.100.7", "198.51.100.99"}); err != nil {
		t.Fatal(err)
	}
	if !f.has("route -n delete -host 198.51.100.7") || f.has("route -n delete -host 198.51.100.99") || g.Len() != 0 {
		t.Fatalf("Remove ran %v, Len %d", f.calls, g.Len())
	}
}

func TestCleanupRemovesListedRoutes(t *testing.T) {
	state := useStateDir(t)
	if err := os.WriteFile(state, []byte("0.0.0.0/1\n198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	if err := Cleanup(context.Background(), PF(f)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"route -n delete -net 0.0.0.0/1", "route -n delete -host 198.51.100.7", "pfctl -a com.apple/psxroute -F all", "sysctl -w net.inet.ip.forwarding=0"} {
		if !f.has(want) {
			t.Errorf("Cleanup didn't run %q; ran %v", want, f.calls)
		}
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("route list should be removed")
	}
}

func ipnet(cidr string) *net.IPNet {
	ip, n, _ := net.ParseCIDR(cidr)
	n.IP = ip
	return n
}

func TestDiscover(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo0", Up: true, Addrs: []*net.IPNet{ipnet("127.0.0.1/8")}},
		{Name: "en0", Up: true, MTU: 1500, Addrs: []*net.IPNet{ipnet("192.168.1.20/24")}},
		{Name: "utun0", Up: true, MTU: 1380, Addrs: []*net.IPNet{ipnet("fe80::1/64")}}, // system utun, IPv6 only
		{Name: "utun4", Up: true, MTU: 1400, Addrs: []*net.IPNet{ipnet("10.8.0.2/32")}},
	}
	s, err := Discover(context.Background(), PF(&fakeRunner{}), ifaces, "192.168.1.20", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if s.LANIface != "en0" || s.LANNet.String() != "192.168.1.0/24" || s.Tunnel != "utun4" || s.TunnelMTU != 1400 {
		t.Fatalf("got %+v", s)
	}
	if s.DefaultIface != "en0" || s.DefaultGW.String() != "192.168.1.1" {
		t.Fatalf("default %s via %v", s.DefaultIface, s.DefaultGW)
	}

	two := append(ifaces, Iface{Name: "utun7", Up: true, Addrs: []*net.IPNet{ipnet("10.9.0.2/32")}})
	if _, err := Discover(context.Background(), PF(&fakeRunner{}), two, "192.168.1.20", "auto"); err == nil || !strings.Contains(err.Error(), "utun4, utun7") {
		t.Fatalf("want ambiguity error, got %v", err)
	}
	if s, err := Discover(context.Background(), PF(&fakeRunner{}), two, "192.168.1.20", "utun7"); err != nil || s.Tunnel != "utun7" {
		t.Fatalf("explicit tunnel: %+v, %v", s, err)
	}
	if _, err := Discover(context.Background(), PF(&fakeRunner{}), ifaces[:2], "192.168.1.20", "auto"); err == nil {
		t.Fatal("want error with no tunnel")
	}
	if _, err := Discover(context.Background(), PF(&fakeRunner{}), ifaces, "192.168.9.9", "auto"); err == nil {
		t.Fatal("want error for an address no interface has")
	}
}

func TestParseDefaultTunnel(t *testing.T) {
	iface, gw := parseDefault("   route to: default\ndestination: default\n  interface: utun4\n      flags: <UP,DONE,STATIC>\n")
	if iface != "utun4" || gw != nil {
		t.Fatalf("got %s %v", iface, gw)
	}
}

func TestSetRouteAll(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{}
	g := start(t, f, settings())
	defer g.Close()
	if _, err := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := g.SetRouteAll(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !g.RouteAll() || !f.has("route -n add -net 0.0.0.0/1 -interface utun4") || !f.has("route -n add -net 128.0.0.0/1 -interface utun4") {
		t.Fatalf("route-all routes not added: %v", f.calls)
	}
	// Addresses learnt while routing everything are kept for switching back.
	if n, _ := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.8")}); n != 1 {
		t.Fatal("Add should still record addresses in route-all")
	}
	if err := g.SetRouteAll(context.Background(), false); err != nil || g.RouteAll() {
		t.Fatalf("switch back: %v", err)
	}
	if !f.has("route -n delete -net 0.0.0.0/1") || f.has("route -n delete -host 198.51.100.7") {
		t.Fatalf("switching back should drop only the halves: %v", f.calls)
	}

	f.reset()
	f.fail = "route -n add -net 128.0.0.0/1"
	if err := g.SetRouteAll(context.Background(), true); err == nil || g.RouteAll() {
		t.Fatal("a failed switch must leave the old setting in place")
	}
	if !f.has("route -n delete -net 0.0.0.0/1") {
		t.Fatalf("the half that was added should be rolled back: %v", f.calls)
	}
}

func TestStartRouteAll(t *testing.T) {
	useStateDir(t)
	f := &fakeRunner{}
	s := settings()
	s.RouteAll = true
	g := start(t, f, s)
	defer g.Close()
	if !f.has("route -n add -net 0.0.0.0/1 -interface utun4") {
		t.Fatalf("route_all at start should add the halves: %v", f.calls)
	}
}
