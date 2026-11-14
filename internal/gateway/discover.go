package gateway

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// tunnelPrefixes are interface names VPN clients use on macOS.
var tunnelPrefixes = []string{"utun", "ipsec", "ppp", "tun", "wg"}

// Iface is the part of net.Interface discovery needs, so tests can fake it.
type Iface struct {
	Name  string
	Up    bool
	MTU   int
	Addrs []*net.IPNet
}

// Interfaces lists the machine's interfaces.
func Interfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		it := Iface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, MTU: i.MTU}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				it.Addrs = append(it.Addrs, n)
			}
		}
		out = append(out, it)
	}
	return out, nil
}

// Discover fills in Settings for a LAN address and a tunnel name ("auto" or
// "" picks the only VPN interface with an IPv4 address).
func Discover(ctx context.Context, run Runner, ifaces []Iface, lanIP, tunnel string) (Settings, error) {
	var s Settings
	ip := net.ParseIP(lanIP).To4()
	if ip == nil {
		return s, fmt.Errorf("LAN address %q isn't IPv4", lanIP)
	}
	for _, i := range ifaces {
		for _, n := range i.Addrs {
			if n.IP.To4() != nil && n.IP.Equal(ip) {
				s.LANIface, s.LANIP = i.Name, ip
				s.LANNet = &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask}
			}
		}
	}
	if s.LANIface == "" {
		return s, fmt.Errorf("no interface has the address %s; set advertise_ip to this Mac's LAN address", lanIP)
	}

	var candidates []Iface
	for _, i := range ifaces {
		if !i.Up || !hasIPv4(i) || i.Name == s.LANIface {
			continue
		}
		if tunnel != "" && tunnel != "auto" {
			if i.Name == tunnel {
				candidates = append(candidates, i)
			}
			continue
		}
		for _, p := range tunnelPrefixes {
			if strings.HasPrefix(i.Name, p) {
				candidates = append(candidates, i)
				break
			}
		}
	}
	switch {
	case len(candidates) == 0 && tunnel != "" && tunnel != "auto":
		return s, fmt.Errorf("tunnel interface %s isn't up with an IPv4 address; is the VPN connected?", tunnel)
	case len(candidates) == 0:
		return s, fmt.Errorf("no VPN tunnel interface found; connect the VPN first, or set gateway.tunnel")
	case len(candidates) > 1:
		names := make([]string, len(candidates))
		for i, c := range candidates {
			names[i] = c.Name
		}
		sort.Strings(names)
		return s, fmt.Errorf("several tunnel interfaces are up (%s); set gateway.tunnel to the VPN's", strings.Join(names, ", "))
	}
	s.Tunnel, s.TunnelMTU = candidates[0].Name, candidates[0].MTU

	// Traffic that isn't routed follows this Mac's default route.
	if out, err := run.Run(ctx, "", "route", "-n", "get", "default"); err == nil {
		s.DefaultIface, s.DefaultGW = parseDefault(out)
	}
	return s, nil
}

func hasIPv4(i Iface) bool {
	for _, n := range i.Addrs {
		if n.IP.To4() != nil {
			return true
		}
	}
	return false
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
