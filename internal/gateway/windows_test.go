package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeIP is an in-memory Windows routing table.
type fakeIP struct {
	mu         sync.Mutex
	routes     []ipRoute
	forwarding map[int]bool
	fail       bool
}

func key(r ipRoute) string {
	via := "on-link"
	if v := r.NextHop.To4(); v != nil && !v.IsUnspecified() {
		via = v.String()
	}
	return r.Dst.String() + " if " + strconv.Itoa(r.IfIndex) + " via " + via
}

func (f *fakeIP) Routes() ([]ipRoute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ipRoute(nil), f.routes...), nil
}

func (f *fakeIP) AddRoute(r ipRoute) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return false, errors.New("boom")
	}
	for _, x := range f.routes {
		if key(x) == key(r) {
			return false, nil
		}
	}
	f.routes = append(f.routes, r)
	return true, nil
}

func (f *fakeIP) DeleteRoute(r ipRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.routes {
		if key(x) == key(r) {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeIP) Forwarding(i int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.forwarding[i], nil
}

func (f *fakeIP) has(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.routes {
		if key(x) == k {
			return true
		}
	}
	return false
}

func route(cidr string, ifIndex int, via string) ipRoute {
	_, n, _ := net.ParseCIDR(cidr)
	return ipRoute{Dst: n, IfIndex: ifIndex, NextHop: net.ParseIP(via), Metric: 25}
}

func winSettings() Settings {
	s := settings()
	s.LANIface, s.LANIndex = "Ethernet", 7
	s.Tunnel, s.TunnelIndex = "ProtonVPN", 12
	return s
}

func (f *fakeRunner) script(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, "powershell.exe") && strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestWindowsStartAddClose(t *testing.T) {
	state := useStateDir(t)
	ip := &fakeIP{
		forwarding: map[int]bool{7: false, 12: true},
		routes: []ipRoute{
			route("0.0.0.0/0", 7, "192.168.1.1"),
			route("10.8.0.0/24", 12, "0.0.0.0"),
			route("0.0.0.0/1", 12, "10.8.0.1"), // a TAP adapter's gateway
		},
	}
	f := &fakeRunner{}
	g, err := Start(context.Background(), winSettings(), Windows(f, ip), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if !f.has("netsh interface ipv4 set interface interface=7 forwarding=enabled store=active") {
		t.Fatalf("forwarding not switched on for the LAN: %v", f.calls)
	}
	if f.has("netsh interface ipv4 set interface interface=12 forwarding=enabled store=active") {
		t.Fatal("forwarding was already on for the tunnel; it mustn't be touched")
	}
	if !f.script("New-NetNat -Name psxroute -InternalIPInterfaceAddressPrefix 192.168.1.0/24") {
		t.Fatalf("NAT not set up: %v", f.calls)
	}
	if !ip.has("203.0.113.0/24 if 12 via 10.8.0.1") {
		t.Fatalf("fixed range not routed via the tunnel's gateway: %v", ip.routes)
	}

	if n, err := g.Add(context.Background(), []net.IP{net.ParseIP("198.51.100.7")}); err != nil || n != 1 {
		t.Fatalf("Add = %d, %v", n, err)
	}
	if !ip.has("198.51.100.7/32 if 12 via 10.8.0.1") {
		t.Fatalf("host route missing: %v", ip.routes)
	}
	var st winState
	data, _ := os.ReadFile(state)
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 2 || st.Routes[0].Dst != "198.51.100.7" || st.Routes[0].If != 12 || st.Routes[0].Via != "10.8.0.1" || !st.NAT || len(st.Forwarding) != 1 || st.Forwarding[0] != 7 {
		t.Fatalf("state = %s", data)
	}

	g.Close()
	if ip.has("198.51.100.7/32 if 12 via 10.8.0.1") || ip.has("203.0.113.0/24 if 12 via 10.8.0.1") {
		t.Fatalf("routes left after Close: %v", ip.routes)
	}
	if !ip.has("0.0.0.0/1 if 12 via 10.8.0.1") {
		t.Fatal("the VPN's own route must survive")
	}
	if !f.script("Remove-NetNat") || !f.has("netsh interface ipv4 set interface interface=7 forwarding=disabled store=active") {
		t.Fatalf("Close didn't undo NAT and forwarding: %v", f.calls)
	}
	if f.has("netsh interface ipv4 set interface interface=12 forwarding=disabled store=active") {
		t.Fatal("forwarding on the tunnel was on before; it must stay on")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state should be gone after Close: %v", err)
	}
}

func TestWindowsOnLinkTunnel(t *testing.T) {
	useStateDir(t)
	ip := &fakeIP{forwarding: map[int]bool{}, routes: []ipRoute{route("10.2.0.2/32", 12, "0.0.0.0")}}
	g, err := Start(context.Background(), winSettings(), Windows(&fakeRunner{}, ip), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if !ip.has("203.0.113.0/24 if 12 via on-link") {
		t.Fatalf("Wintun-style tunnels take on-link routes: %v", ip.routes)
	}
}

func TestWindowsExistingRouteIsLeftAlone(t *testing.T) {
	useStateDir(t)
	ip := &fakeIP{forwarding: map[int]bool{}, routes: []ipRoute{route("0.0.0.0/1", 12, "0.0.0.0")}}
	s := winSettings()
	s.RouteAll = true
	g, err := Start(context.Background(), s, Windows(&fakeRunner{}, ip), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	if !ip.has("0.0.0.0/1 if 12 via on-link") || ip.has("128.0.0.0/1 if 12 via on-link") {
		t.Fatalf("only psxroute's half should go: %v", ip.routes)
	}
}

func TestWindowsNATFailureUndoes(t *testing.T) {
	state := useStateDir(t)
	ip := &fakeIP{forwarding: map[int]bool{}}
	f := &fakeRunner{fail: "powershell.exe -NoLogo -NoProfile -NonInteractive -Command $ErrorActionPreference"}
	_, err := Start(context.Background(), winSettings(), Windows(f, ip), slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "WinNAT") {
		t.Fatalf("want a WinNAT error, got %v", err)
	}
	for _, idx := range []string{"7", "12"} {
		if !f.has("netsh interface ipv4 set interface interface=" + idx + " forwarding=disabled store=active") {
			t.Errorf("forwarding on %s not switched back off: %v", idx, f.calls)
		}
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state should be gone: %v", err)
	}
}

func TestWindowsCleanup(t *testing.T) {
	state := useStateDir(t)
	data := `{"routes":[{"dst":"198.51.100.7","if":12,"via":"10.8.0.1"},{"dst":"0.0.0.0/1","if":12}],"forwarding":[7],"nat":true}`
	if err := os.WriteFile(state, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ip := &fakeIP{routes: []ipRoute{route("198.51.100.7/32", 12, "10.8.0.1"), route("0.0.0.0/1", 12, ""), route("0.0.0.0/1", 3, "")}}
	f := &fakeRunner{}
	if err := Cleanup(context.Background(), Windows(f, ip)); err != nil {
		t.Fatal(err)
	}
	if len(ip.routes) != 1 || ip.routes[0].IfIndex != 3 {
		t.Fatalf("only the listed routes should go: %v", ip.routes)
	}
	if !f.script("Remove-NetNat") || !f.has("netsh interface ipv4 set interface interface=7 forwarding=disabled store=active") {
		t.Fatalf("Cleanup ran %v", f.calls)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state should be removed")
	}
}

func TestDiscoverWindowsAdapters(t *testing.T) {
	ifaces := []Iface{
		{Name: "Ethernet", Index: 7, Up: true, MTU: 1500, Desc: "Intel(R) Ethernet Connection", Addrs: []*net.IPNet{ipnet("192.168.1.20/24")}},
		{Name: "vEthernet (Default Switch)", Index: 30, Up: true, MTU: 1500, Desc: "Hyper-V Virtual Ethernet Adapter", Addrs: []*net.IPNet{ipnet("172.20.0.1/20")}},
		{Name: "Local Area Connection* 2", Index: 9, Up: false, Desc: "TAP-Windows Adapter V9", Addrs: []*net.IPNet{ipnet("169.254.1.1/16")}},
		{Name: "ProtonVPN", Index: 12, Up: true, MTU: 1420, Desc: "WireGuard Tunnel", Virtual: true, Addrs: []*net.IPNet{ipnet("10.2.0.2/32")}},
	}
	ip := &fakeIP{routes: []ipRoute{route("0.0.0.0/0", 7, "192.168.1.1"), route("0.0.0.0/0", 12, "0.0.0.0")}}
	ip.routes[1].Metric = 5000
	s, err := Discover(context.Background(), Windows(&fakeRunner{}, ip), ifaces, "192.168.1.20", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if s.LANIface != "Ethernet" || s.LANIndex != 7 || s.Tunnel != "ProtonVPN" || s.TunnelIndex != 12 || s.TunnelMTU != 1420 {
		t.Fatalf("got %+v", s)
	}
	if s.DefaultIface != "Ethernet" || s.DefaultGW.String() != "192.168.1.1" {
		t.Fatalf("default %s via %v", s.DefaultIface, s.DefaultGW)
	}
}
