//go:build windows

package netinfo

import "github.com/ahyaghoubi/psxroute/internal/gateway"

// vpnAdapters names the VPN adapters to skip. Windows doesn't mark Wintun or
// TAP adapters as point-to-point, so they're told apart by type and
// description.
func vpnAdapters() map[string]bool {
	ifaces, err := gateway.Interfaces()
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, i := range ifaces {
		if gateway.IsTunnel(i) {
			out[i.Name] = true
		}
	}
	return out
}
