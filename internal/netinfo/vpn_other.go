//go:build !windows

package netinfo

// vpnAdapters is empty here: VPN tunnels are point-to-point interfaces,
// which IPv4Addrs already skips.
func vpnAdapters() map[string]bool { return nil }
