package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Anchor sits under Apple's com.apple/* anchors, which the stock
// /etc/pf.conf already evaluates for nat, rdr, scrub and filter rules.
const Anchor = "com.apple/psxroute"

// pfSystem is gateway mode on macOS: route(8) adds the routes, sysctl turns
// forwarding on, and pf only NATs.
//
// pf's route-to isn't used: on macOS 27 it panics the kernel ("Bounds safety
// trap") on the first forwarded packet. Ordinary routes plus forwarding is
// the path Internet Sharing uses, and is far better exercised.
type pfSystem struct {
	run     Runner
	tunnel  string
	token   string            // pf enable reference
	restore map[string]string // sysctl name → value before we changed it
}

// PF returns the macOS System, running its commands with run.
func PF(run Runner) System {
	return &pfSystem{run: run, restore: map[string]string{}}
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

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

func (p *pfSystem) DefaultRoute(ctx context.Context, _ []Iface) (string, net.IP) {
	out, err := p.run.Run(ctx, "", "route", "-n", "get", "default")
	if err != nil {
		return "", nil
	}
	return parseDefault(out)
}

var (
	gatewayRe = regexp.MustCompile(`gateway:\s+(\d+\.\d+\.\d+\.\d+)`)
	ifaceRe   = regexp.MustCompile(`interface:\s+(\S+)`)
)

// parseDefault reads "interface: en0" and "gateway: 192.168.1.1" from
// `route get` output. A tunnel's default route usually has no IPv4 gateway.
func parseDefault(out string) (string, net.IP) {
	var iface string
	var gw net.IP
	if m := ifaceRe.FindStringSubmatch(out); m != nil {
		iface = m[1]
	}
	if m := gatewayRe.FindStringSubmatch(out); m != nil {
		gw = net.ParseIP(m[1]).To4()
	}
	return iface, gw
}

// Setup turns forwarding on, ICMP redirects off, loads the NAT rules and
// enables pf.
func (p *pfSystem) Setup(ctx context.Context, s Settings) error {
	p.tunnel = s.Tunnel
	// Clear anything a crashed run left behind.
	_ = p.cleanupRoutes(ctx)
	_, _ = p.run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all")

	for name, want := range map[string]string{
		"net.inet.ip.forwarding": "1",
		// Redirects would tell the console to bypass this Mac for addresses
		// that aren't routed; that skips the NAT and breaks connections.
		"net.inet.ip.redirect": "0",
	} {
		prev, err := p.run.Run(ctx, "", "sysctl", "-n", name)
		if err != nil {
			return err
		}
		p.restore[name] = strings.TrimSpace(prev)
		if _, err := p.run.Run(ctx, "", "sysctl", "-w", name+"="+want); err != nil {
			return err
		}
	}
	if _, err := p.run.Run(ctx, Rules(s), "pfctl", "-a", Anchor, "-f", "-"); err != nil {
		return fmt.Errorf("load pf rules: %w", err)
	}
	out, err := p.run.Run(ctx, "", "pfctl", "-E")
	if err != nil {
		return fmt.Errorf("enable pf: %w", err)
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		p.token = m[1]
	}
	return nil
}

func (p *pfSystem) AddRoute(ctx context.Context, dst string) (bool, error) {
	_, err := p.run.Run(ctx, "", "route", append(routeArgs("add", dst), "-interface", p.tunnel)...)
	if err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *pfSystem) DeleteRoute(ctx context.Context, dst string) error {
	if _, err := p.run.Run(ctx, "", "route", routeArgs("delete", dst)...); err != nil && !strings.Contains(err.Error(), "not in table") {
		return err
	}
	return nil
}

// Save writes one destination per line.
func (p *pfSystem) Save(owned []string) error {
	if len(owned) == 0 {
		if err := os.Remove(StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	lines := append([]string(nil), owned...)
	sort.Strings(lines)
	return os.WriteFile(StatePath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// Teardown removes the rules, releases pf and restores the sysctls.
func (p *pfSystem) Teardown(ctx context.Context) error {
	var errs []error
	if _, err := p.run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all"); err != nil {
		errs = append(errs, fmt.Errorf("remove pf rules: %w", err))
	}
	if p.token != "" {
		_, _ = p.run.Run(ctx, "", "pfctl", "-X", p.token)
		p.token = ""
	}
	for name, v := range p.restore {
		if v == "" {
			continue
		}
		if _, err := p.run.Run(ctx, "", "sysctl", "-w", name+"="+v); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", name, err))
		}
	}
	p.restore = map[string]string{}
	return errors.Join(errs...)
}

// cleanupRoutes removes the routes listed in StatePath, then the list.
func (p *pfSystem) cleanupRoutes(ctx context.Context) error {
	data, err := os.ReadFile(StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range strings.Fields(string(data)) {
		if err := p.DeleteRoute(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return os.Remove(StatePath)
}

// Cleanup removes psxroute's routes and rules and puts forwarding and
// redirects back to macOS defaults.
func (p *pfSystem) Cleanup(ctx context.Context) error {
	var errs []error
	if err := p.cleanupRoutes(ctx); err != nil {
		errs = append(errs, err)
	}
	if _, err := p.run.Run(ctx, "", "pfctl", "-a", Anchor, "-F", "all"); err != nil {
		errs = append(errs, err)
	}
	for _, kv := range []string{"net.inet.ip.forwarding=0", "net.inet.ip.redirect=1"} {
		if _, err := p.run.Run(ctx, "", "sysctl", "-w", kv); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
