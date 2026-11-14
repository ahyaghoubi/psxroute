// Package gateway is psxroute's gateway mode on macOS. The console uses this
// Mac as its default gateway and the kernel forwards its traffic. Routed
// addresses get host routes through the VPN's tunnel interface; everything
// else follows this Mac's default route. pf only NATs.
//
// pf's route-to isn't used: on macOS 27 it panics the kernel ("Bounds safety
// trap") on the first forwarded packet. Ordinary routes plus forwarding is
// the path Internet Sharing uses, and is far better exercised.
//
// Every change is undone by Close. If psxroute is killed before it can clean
// up, `psxroute cleanup` does the same: the routes it added are listed in
// StatePath, which lives in /var/run so it goes when the routes do, at reboot.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Anchor sits under Apple's com.apple/* anchors, which the stock
// /etc/pf.conf already evaluates for nat, rdr, scrub and filter rules.
const Anchor = "com.apple/psxroute"

// MaxAddrs caps the routed addresses so a misbehaving rule can't grow the
// routing table forever.
const MaxAddrs = 20000

// StatePath lists the routes psxroute added, one destination per line, so
// Cleanup can remove them after a crash. A variable so tests can move it.
var StatePath = "/var/run/psxroute.routes"

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

// Settings describe the network the gateway sits in.
type Settings struct {
	LANIface string     // e.g. en0
	LANIP    net.IP     // this Mac on the LAN
	LANNet   *net.IPNet // the console's subnet

	DefaultIface string // where this Mac's default route goes, e.g. en0 or utun4
	DefaultGW    net.IP // its next hop; nil for a tunnel or if unknown

	Tunnel    string // e.g. utun4
	TunnelMTU int

	RouteAll bool     // send all console internet traffic through the tunnel
	CIDRs    []string // ranges always routed
}

// Preflight checks the platform and privileges gateway mode needs.
func Preflight() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("gateway mode is only supported on macOS so far (this is %s); use mode: relay", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("gateway mode changes the firewall and routing: run it with sudo")
	}
	return nil
}

// Rules renders the pf anchor for s. It only clamps MSS and NATs: the
// routing table decides which interface a packet leaves by.
func Rules(s Settings) string {
	lan := s.LANNet.String()
	tun := s.Tunnel
	var b strings.Builder
	fmt.Fprintf(&b, "# psxroute gateway rules: removed when psxroute stops, or by `psxroute cleanup`\n")
	if s.TunnelMTU > 0 {
		// Tunnels have a smaller MTU than Ethernet; clamp TCP so the console's
		// full-size segments don't get dropped.
		fmt.Fprintf(&b, "scrub on %s inet all max-mss %d\n", tun, s.TunnelMTU-40)
	}
	// This Mac's own traffic keeps its address.
	fmt.Fprintf(&b, "no nat on %s inet from %s to any\n", s.LANIface, s.LANIP)
	fmt.Fprintf(&b, "nat on %s inet from %s to any -> (%s)\n", tun, lan, tun)
	fmt.Fprintf(&b, "nat on %s inet from %s to ! %s -> (%s)\n", s.LANIface, lan, lan, s.LANIface)
	return b.String()
}

// routeArgs builds route(8) arguments for an address or a CIDR.
func routeArgs(verb, dst string) []string {
	if strings.Contains(dst, "/") && !strings.HasSuffix(dst, "/32") {
		return []string{"-n", verb, "-net", dst}
	}
	return []string{"-n", verb, "-host", strings.TrimSuffix(dst, "/32")}
}

// Gateway is the running gateway. Its methods are safe for concurrent use.
type Gateway struct {
	s   Settings
	run Runner
	log *slog.Logger

	mu      sync.Mutex        // held across route commands so the table and maps agree
	added   map[string]bool   // addresses learnt from DNS
	owned   map[string]bool   // routes psxroute added and must remove
	token   string            // pf enable reference
	restore map[string]string // sysctl name → value before we changed it
	closed  bool
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// Start applies s: forwarding on, ICMP redirects off, NAT rules loaded, pf
// enabled, fixed routes added. On error everything already applied is undone.
func Start(ctx context.Context, s Settings, run Runner, log *slog.Logger) (_ *Gateway, err error) {
	g := &Gateway{s: s, run: run, log: log, added: map[string]bool{}, owned: map[string]bool{}, restore: map[string]string{}}
	defer func() {
		if err != nil {
			g.Close()
		}
	}()
	// Clear anything a crashed run left behind.
	if err := cleanupRoutes(ctx, run); err != nil {
		log.Warn("couldn't remove routes left by an earlier run", "err", err)
	}
	_, _ = run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all")

	for name, want := range map[string]string{
		"net.inet.ip.forwarding": "1",
		// Redirects would tell the console to bypass this Mac for addresses
		// that aren't routed; that skips the NAT and breaks connections.
		"net.inet.ip.redirect": "0",
	} {
		prev, err := run.Run(ctx, "", "sysctl", "-n", name)
		if err != nil {
			return nil, err
		}
		g.restore[name] = strings.TrimSpace(prev)
		if _, err := run.Run(ctx, "", "sysctl", "-w", name+"="+want); err != nil {
			return nil, err
		}
	}
	if _, err := run.Run(ctx, Rules(s), "pfctl", "-a", Anchor, "-f", "-"); err != nil {
		return nil, fmt.Errorf("load pf rules: %w", err)
	}
	out, err := run.Run(ctx, "", "pfctl", "-E")
	if err != nil {
		return nil, fmt.Errorf("enable pf: %w", err)
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		g.token = m[1]
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
	_, err := g.run.Run(ctx, "", "route", append(routeArgs("add", dst), "-interface", g.s.Tunnel)...)
	if err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	g.owned[dst] = true
	return nil
}

// deleteRoute removes a route psxroute added. The caller holds g.mu and
// calls persist afterwards.
func (g *Gateway) deleteRoute(ctx context.Context, dst string) error {
	if !g.owned[dst] {
		return nil
	}
	if _, err := g.run.Run(ctx, "", "route", routeArgs("delete", dst)...); err != nil && !strings.Contains(err.Error(), "not in table") {
		return err
	}
	delete(g.owned, dst)
	return nil
}

// persist writes the owned routes to StatePath. The caller holds g.mu.
func (g *Gateway) persist() {
	if len(g.owned) == 0 {
		if err := os.Remove(StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			g.log.Warn("couldn't remove route list", "path", StatePath, "err", err)
		}
		return
	}
	lines := make([]string, 0, len(g.owned))
	for d := range g.owned {
		lines = append(lines, d)
	}
	sort.Strings(lines)
	if err := os.WriteFile(StatePath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
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
// They apply to this Mac's own traffic too. Connections already open move
// with the route; the NAT keeps them working only on the new path's address,
// so some may need reopening.
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

// Close removes the routes and rules, releases pf and restores the sysctls.
// It is safe to call more than once.
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
			g.log.Warn("couldn't remove route; run `sudo psxroute cleanup`", "dst", d, "err", err)
		}
	}
	g.persist()
	g.mu.Unlock()
	if _, err := g.run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all"); err != nil {
		g.log.Warn("couldn't remove pf rules; run `sudo psxroute cleanup`", "err", err)
	}
	if g.token != "" {
		_, _ = g.run.Run(ctx, "", "pfctl", "-X", g.token)
	}
	for name, v := range g.restore {
		if v == "" {
			continue
		}
		if _, err := g.run.Run(ctx, "", "sysctl", "-w", name+"="+v); err != nil {
			g.log.Warn("couldn't restore sysctl", "name", name, "err", err)
		}
	}
}

// cleanupRoutes removes the routes listed in StatePath, then the list.
func cleanupRoutes(ctx context.Context, run Runner) error {
	data, err := os.ReadFile(StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range strings.Fields(string(data)) {
		if _, err := run.Run(ctx, "", "route", routeArgs("delete", d)...); err != nil && !strings.Contains(err.Error(), "not in table") {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return os.Remove(StatePath)
}

// Cleanup removes psxroute's routes and rules and puts forwarding and
// redirects back to macOS defaults, for after a crash.
func Cleanup(ctx context.Context, run Runner) error {
	var errs []error
	if err := cleanupRoutes(ctx, run); err != nil {
		errs = append(errs, err)
	}
	if _, err := run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all"); err != nil {
		errs = append(errs, err)
	}
	for _, kv := range []string{"net.inet.ip.forwarding=0", "net.inet.ip.redirect=1"} {
		if _, err := run.Run(ctx, "", "sysctl", "-w", kv); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
