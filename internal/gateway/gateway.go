// Package gateway is psxroute's gateway mode. The console uses this computer
// as its default gateway and the kernel forwards its traffic. Routed
// addresses get host routes through the VPN's tunnel interface; everything
// else follows this computer's default route.
//
// The routing logic is shared; a System does the operating system's part:
// pf and route(8) on macOS (pf.go), the IP Helper API, netsh and WinNAT on
// Windows (windows.go).
//
// Every change is undone by Close. If psxroute is killed before it can clean
// up, `psxroute cleanup` does the same from the list kept at StatePath.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// MaxAddrs caps the routed addresses so a misbehaving rule can't grow the
// routing table forever.
const MaxAddrs = 20000

// StatePath records what psxroute changed, so Cleanup can undo it after a
// crash. On macOS it lives in /var/run, which a reboot clears along with the
// routes. A variable so tests can move it.
var StatePath = defaultStatePath()

func defaultStatePath() string {
	if runtime.GOOS == "windows" {
		dir := os.Getenv("ProgramData")
		if dir == "" {
			dir = `C:\ProgramData`
		}
		return filepath.Join(dir, "psxroute", "gateway.json")
	}
	return "/var/run/psxroute.routes"
}

// allHalves cover every IPv4 address while staying more specific than the
// default route, the way VPN clients take over all traffic.
var allHalves = []string{"0.0.0.0/1", "128.0.0.0/1"}

// Runner runs a command, feeding it stdin, and returns combined output.
type Runner interface {
	Run(ctx context.Context, stdin, name string, args ...string) (string, error)
}

// ExecRunner runs real commands.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// System is the operating system's half of gateway mode. The Gateway
// serialises calls to it.
type System interface {
	// DefaultRoute reports where this computer's own traffic leaves: an
	// interface name and its next hop (nil for a tunnel or if unknown).
	DefaultRoute(ctx context.Context, ifaces []Iface) (string, net.IP)
	// Setup clears anything a crashed run left, then switches forwarding
	// and NAT on for s. After an error, Teardown undoes what was done.
	Setup(ctx context.Context, s Settings) error
	// AddRoute sends dst (an address or a CIDR) through the tunnel. It
	// returns false when the route already existed, so it isn't psxroute's
	// to remove.
	AddRoute(ctx context.Context, dst string) (added bool, err error)
	// DeleteRoute removes a route AddRoute added. One already gone is fine.
	DeleteRoute(ctx context.Context, dst string) error
	// Save records the routes psxroute owns at StatePath for Cleanup.
	Save(owned []string) error
	// Teardown undoes Setup.
	Teardown(ctx context.Context) error
	// Cleanup undoes everything a crashed run left, from StatePath.
	Cleanup(ctx context.Context) error
}

// NewSystem returns this operating system's System.
func NewSystem(run Runner) (System, error) {
	switch runtime.GOOS {
	case "darwin":
		return PF(run), nil
	case "windows":
		return Windows(run, newIPHelper()), nil
	}
	return nil, unsupported()
}

func unsupported() error {
	return fmt.Errorf("gateway mode works on macOS and Windows so far (this is %s); use mode: relay", runtime.GOOS)
}

// Preflight checks the platform and privileges gateway mode needs.
func Preflight() error {
	switch runtime.GOOS {
	case "darwin":
		if os.Geteuid() != 0 {
			return errors.New("gateway mode changes the firewall and routing: run it with sudo")
		}
	case "windows":
		if !isElevated() {
			return errors.New("gateway mode changes routing and NAT: run psxroute from a terminal opened as Administrator")
		}
	default:
		return unsupported()
	}
	return nil
}

// Command is how to start gateway mode on this computer, for messages.
func Command() string {
	if runtime.GOOS == "windows" {
		return "psxroute --mode gateway (in a terminal opened as Administrator)"
	}
	return "sudo psxroute --mode gateway"
}

// Settings describe the network the gateway sits in.
type Settings struct {
	LANIface string     // e.g. en0, or Ethernet on Windows
	LANIndex int        // its interface index
	LANIP    net.IP     // this computer on the LAN
	LANNet   *net.IPNet // the console's subnet

	DefaultIface string // where this computer's default route goes
	DefaultGW    net.IP // its next hop; nil for a tunnel or if unknown

	Tunnel      string // e.g. utun4, or the VPN adapter's name on Windows
	TunnelIndex int
	TunnelMTU   int

	RouteAll bool     // send all console internet traffic through the tunnel
	CIDRs    []string // ranges always routed
}

// Gateway is the running gateway. Its methods are safe for concurrent use.
type Gateway struct {
	s   Settings
	sys System
	log *slog.Logger

	mu     sync.Mutex      // held across system calls so the table and maps agree
	added  map[string]bool // addresses learnt from DNS
	owned  map[string]bool // routes psxroute added and must remove
	closed bool
}

// Start applies s through sys: forwarding and NAT on, fixed routes added. On
// error everything already applied is undone.
func Start(ctx context.Context, s Settings, sys System, log *slog.Logger) (_ *Gateway, err error) {
	g := &Gateway{s: s, sys: sys, log: log, added: map[string]bool{}, owned: map[string]bool{}}
	defer func() {
		if err != nil {
			g.Close()
		}
	}()
	if err := sys.Setup(ctx, s); err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.persist()
	fixed := append([]string(nil), s.CIDRs...)
	if s.RouteAll {
		fixed = append(fixed, allHalves...)
	}
	for _, d := range fixed {
		if err := g.addRoute(ctx, d); err != nil {
			return nil, fmt.Errorf("route %s through %s: %w", d, s.Tunnel, err)
		}
	}
	return g, nil
}

// addRoute sends dst through the tunnel. A route that already exists (the
// VPN's own, say) is left alone and not remembered, so it's never removed.
// The caller holds g.mu and calls persist afterwards.
func (g *Gateway) addRoute(ctx context.Context, dst string) error {
	if g.owned[dst] {
		return nil
	}
	added, err := g.sys.AddRoute(ctx, dst)
	if err != nil {
		return err
	}
	if added {
		g.owned[dst] = true
	}
	return nil
}

// deleteRoute removes a route psxroute added. The caller holds g.mu and
// calls persist afterwards.
func (g *Gateway) deleteRoute(ctx context.Context, dst string) error {
	if !g.owned[dst] {
		return nil
	}
	if err := g.sys.DeleteRoute(ctx, dst); err != nil {
		return err
	}
	delete(g.owned, dst)
	return nil
}

// persist records the owned routes. The caller holds g.mu.
func (g *Gateway) persist() {
	lines := make([]string, 0, len(g.owned))
	for d := range g.owned {
		lines = append(lines, d)
	}
	if err := g.sys.Save(lines); err != nil {
		g.log.Warn("couldn't save route list; `psxroute cleanup` may miss routes after a crash", "path", StatePath, "err", err)
	}
}

// Add routes ips through the tunnel. IPv6, LAN and already-added addresses
// are skipped. It returns how many were new; addresses that failed are
// retried next time.
func (g *Gateway) Add(ctx context.Context, ips []net.IP) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, nil
	}
	defer g.persist()
	n := 0
	var errs []error
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil || g.s.LANNet.Contains(v4) || v4.IsLoopback() || v4.IsUnspecified() || v4.IsMulticast() {
			continue
		}
		k := v4.String()
		if g.added[k] || len(g.added) >= MaxAddrs {
			continue
		}
		if err := g.addRoute(ctx, k); err != nil {
			errs = append(errs, err)
			continue
		}
		g.added[k] = true
		n++
	}
	return n, errors.Join(errs...)
}

// Remove stops routing ips. Fixed CIDRs aren't affected.
func (g *Gateway) Remove(ctx context.Context, ips []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	defer g.persist()
	var errs []error
	for _, ip := range ips {
		if !g.added[ip] {
			continue
		}
		if err := g.deleteRoute(ctx, ip); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(g.added, ip)
	}
	return errors.Join(errs...)
}

// Len is how many addresses Add has routed.
func (g *Gateway) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.added)
}

// ViaTunnel reports whether traffic to ip goes through the tunnel: every
// address when routing everything, otherwise routed addresses and ranges.
func (g *Gateway) ViaTunnel(ip net.IP) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.s.RouteAll {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if g.added[v4.String()] {
		return true
	}
	for _, c := range g.s.CIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(v4) {
			return true
		}
	}
	return false
}

// Settings returns the gateway's current settings.
func (g *Gateway) Settings() Settings {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.s
}

// RouteAll reports whether all console traffic goes through the tunnel.
func (g *Gateway) RouteAll() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.s.RouteAll
}

// SetRouteAll switches between routing everything and routing only routed
// addresses, by adding or removing two routes that cover every address.
// They apply to this computer's own traffic too. Connections already open
// move with the route; the NAT keeps them working only on the new path's
// address, so some may need reopening.
func (g *Gateway) SetRouteAll(ctx context.Context, on bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("gateway is stopping")
	}
	if g.s.RouteAll == on {
		return nil
	}
	defer g.persist()
	if on {
		for i, d := range allHalves {
			if err := g.addRoute(ctx, d); err != nil {
				for _, done := range allHalves[:i] {
					_ = g.deleteRoute(ctx, done)
				}
				return fmt.Errorf("route everything through %s: %w", g.s.Tunnel, err)
			}
		}
	} else {
		var errs []error
		for _, d := range allHalves {
			if err := g.deleteRoute(ctx, d); err != nil {
				errs = append(errs, err)
			}
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("stop routing everything: %w", err)
		}
	}
	g.s.RouteAll = on
	return nil
}

// Close removes the routes, then undoes the system's setup. It is safe to
// call more than once.
func (g *Gateway) Close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	ctx := context.Background()
	for d := range g.owned {
		if err := g.deleteRoute(ctx, d); err != nil {
			g.log.Warn("couldn't remove route; run `psxroute cleanup` as administrator", "dst", d, "err", err)
		}
	}
	g.persist()
	g.mu.Unlock()
	if err := g.sys.Teardown(ctx); err != nil {
		g.log.Warn("couldn't undo every change; run `psxroute cleanup` as administrator", "err", err)
	}
}

// Cleanup undoes what a crashed run left behind.
func Cleanup(ctx context.Context, sys System) error {
	return sys.Cleanup(ctx)
}

// parseDst reads an address or CIDR as an IPv4 network.
func parseDst(dst string) (*net.IPNet, error) {
	if !strings.Contains(dst, "/") {
		dst += "/32"
	}
	_, n, err := net.ParseCIDR(dst)
	if err != nil || n.IP.To4() == nil {
		return nil, fmt.Errorf("%q isn't an IPv4 address or range", dst)
	}
	return n, nil
}
