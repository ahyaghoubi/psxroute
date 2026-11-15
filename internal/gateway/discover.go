package gateway

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// tunnelPrefixes are interface names VPN clients use on macOS.
var tunnelPrefixes = []string{"utun", "ipsec", "ppp", "tun", "wg"}

// tunnelWords appear in the descriptions of Windows VPN adapters: Wintun
// (WireGuard and most v2ray-style clients), TAP-Windows (OpenVPN) and the
// vendors' own drivers.
var tunnelWords = []string{"wintun", "wireguard", "tap-windows", "openvpn", "vpn", "tunnel"}

// Iface is the part of an interface discovery needs, so tests can fake it.
type Iface struct {
	Name  string
	Index int
	Up    bool
	MTU   int
	Addrs []*net.IPNet
	// Windows only: the adapter's description, and whether its type is a
	// tunnel, PPP or proprietary virtual link.
	Desc    string
	Virtual bool
}

// IsTunnel reports whether i looks like a VPN's interface.
func IsTunnel(i Iface) bool {
	if i.Virtual {
		return true
	}
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(i.Name, p) {
			return true
		}
	}
	d := strings.ToLower(i.Desc)
	for _, w := range tunnelWords {
		if strings.Contains(d, w) {
			return true
		}
	}
	return false
}

// Discover fills in Settings for a LAN address and a tunnel name ("auto" or
// "" picks the only VPN interface with an IPv4 address).
func Discover(ctx context.Context, sys System, ifaces []Iface, lanIP, tunnel string) (Settings, error) {
	var s Settings
	ip := net.ParseIP(lanIP).To4()
	if ip == nil {
		return s, fmt.Errorf("LAN address %q isn't IPv4", lanIP)
	}
	for _, i := range ifaces {
		for _, n := range i.Addrs {
			if n.IP.To4() != nil && n.IP.Equal(ip) {
				s.LANIface, s.LANIndex, s.LANIP = i.Name, i.Index, ip
				s.LANNet = &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask}
			}
		}
	}
	if s.LANIface == "" {
		return s, fmt.Errorf("no interface has the address %s; set advertise_ip to this computer's LAN address", lanIP)
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
		if IsTunnel(i) {
			candidates = append(candidates, i)
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
	s.Tunnel, s.TunnelIndex, s.TunnelMTU = candidates[0].Name, candidates[0].Index, candidates[0].MTU

	// Traffic that isn't routed follows this computer's default route.
	s.DefaultIface, s.DefaultGW = sys.DefaultRoute(ctx, ifaces)
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
