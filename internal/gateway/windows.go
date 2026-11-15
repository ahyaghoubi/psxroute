package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// NATName is the WinNAT instance psxroute creates on Windows.
const NATName = "psxroute"

// ipRoute is one IPv4 route in Windows' table. A nil or unspecified NextHop
// means on-link, which is how tunnels such as Wintun take routes.
type ipRoute struct {
	Dst     *net.IPNet
	IfIndex int
	NextHop net.IP
	Metric  uint32
}

// ipHelper is the part of Windows' IP Helper API gateway mode uses, so the
// logic can be tested on any OS. Errors are already mapped: AddRoute reports
// an existing route as false, nil and DeleteRoute a missing one as nil.
type ipHelper interface {
	Routes() ([]ipRoute, error)
	AddRoute(r ipRoute) (added bool, err error)
	DeleteRoute(r ipRoute) error
	Forwarding(ifIndex int) (bool, error)
}

// winSystem is gateway mode on Windows. Routes go in through the IP Helper
// API, which keeps them in the active store only, so a reboot removes them.
// Forwarding is switched on for the LAN and tunnel interfaces with netsh,
// also in the active store. WinNAT translates the console's addresses to the
// tunnel's.
//
// Traffic that isn't routed comes in and goes back out the LAN interface to
// the router, which isn't NATed: the router knows the console and sends the
// replies straight to it.
type winSystem struct {
	run   Runner
	ip    ipHelper
	s     Settings
	via   net.IP // the tunnel's next hop; nil for on-link
	state winState
}

// winState is what StatePath holds on Windows.
type winState struct {
	Routes []winRoute `json:"routes,omitempty"`
	// Forwarding lists the interfaces psxroute switched forwarding on for.
	Forwarding []int `json:"forwarding,omitempty"`
	NAT        bool  `json:"nat,omitempty"`
}

type winRoute struct {
	Dst string `json:"dst"`
	If  int    `json:"if"`
	Via string `json:"via,omitempty"`
}

func (st winState) empty() bool {
	return len(st.Routes) == 0 && len(st.Forwarding) == 0 && !st.NAT
}

// Windows returns the Windows System, running netsh and PowerShell with run
// and changing routes through ip.
func Windows(run Runner, ip ipHelper) System {
	return &winSystem{run: run, ip: ip}
}

func (w *winSystem) DefaultRoute(_ context.Context, ifaces []Iface) (string, net.IP) {
	routes, err := w.ip.Routes()
	if err != nil {
		return "", nil
	}
	best := -1
	for i, r := range routes {
		if ones, _ := r.Dst.Mask.Size(); ones != 0 {
			continue
		}
		if best < 0 || r.Metric < routes[best].Metric {
			best = i
		}
	}
	if best < 0 {
		return "", nil
	}
	r := routes[best]
	name := strconv.Itoa(r.IfIndex)
	for _, i := range ifaces {
		if i.Index == r.IfIndex {
			name = i.Name
		}
	}
	var gw net.IP
	if v4 := r.NextHop.To4(); v4 != nil && !v4.IsUnspecified() {
		gw = v4
	}
	return name, gw
}

// tunnelNextHop finds the gateway the VPN routes its own traffic through on
// the tunnel. Wintun and other point-to-point tunnels have none and take
// on-link routes; a TAP adapter has one, as an Ethernet link would.
func tunnelNextHop(routes []ipRoute, ifIndex int) net.IP {
	sort.SliceStable(routes, func(i, j int) bool {
		a, _ := routes[i].Dst.Mask.Size()
		b, _ := routes[j].Dst.Mask.Size()
		return a < b
	})
	for _, r := range routes {
		if r.IfIndex != ifIndex {
			continue
		}
		if v4 := r.NextHop.To4(); v4 != nil && !v4.IsUnspecified() {
			return v4
		}
	}
	return nil
}

func (w *winSystem) Setup(ctx context.Context, s Settings) error {
	w.s = s
	if s.LANIndex == 0 || s.TunnelIndex == 0 {
		return errors.New("the LAN and tunnel interface indexes are unknown")
	}
	// Clear anything a crashed run left behind.
	_ = w.cleanup(ctx, false)

	for _, idx := range []int{s.LANIndex, s.TunnelIndex} {
		on, err := w.ip.Forwarding(idx)
		if err != nil {
			return fmt.Errorf("read forwarding on interface %d: %w", idx, err)
		}
		if on {
			continue
		}
		// Recorded first, so a crash halfway still gets it switched back.
		w.state.Forwarding = append(w.state.Forwarding, idx)
		_ = w.write()
		if err := w.setForwarding(ctx, idx, true); err != nil {
			return fmt.Errorf("switch on forwarding: %w", err)
		}
	}

	w.state.NAT = true
	_ = w.write()
	script := fmt.Sprintf("$ErrorActionPreference = 'Stop'\n"+
		"Get-NetNat -Name %s -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false\n"+
		"New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s | Out-Null\n",
		NATName, NATName, s.LANNet.String())
	if _, err := w.powershell(ctx, script); err != nil {
		return fmt.Errorf("set up Windows NAT (WinNAT) for %s: %w\n"+
			"Gateway mode on Windows uses WinNAT (New-NetNat), part of Windows' Hyper-V and container networking, "+
			"which may need one of those features switched on. Windows allows only one WinNAT, so one set up by "+
			"Docker or another tool also stops it: run Get-NetNat to see", s.LANNet, err)
	}

	if routes, err := w.ip.Routes(); err == nil {
		w.via = tunnelNextHop(routes, s.TunnelIndex)
	}
	return nil
}

func (w *winSystem) route(dst string) (ipRoute, error) {
	n, err := parseDst(dst)
	if err != nil {
		return ipRoute{}, err
	}
	return ipRoute{Dst: n, IfIndex: w.s.TunnelIndex, NextHop: w.via}, nil
}

func (w *winSystem) AddRoute(_ context.Context, dst string) (bool, error) {
	r, err := w.route(dst)
	if err != nil {
		return false, err
	}
	added, err := w.ip.AddRoute(r)
	if err != nil {
		return false, fmt.Errorf("add route %s: %w", dst, err)
	}
	return added, nil
}

func (w *winSystem) DeleteRoute(_ context.Context, dst string) error {
	r, err := w.route(dst)
	if err != nil {
		return err
	}
	if err := w.ip.DeleteRoute(r); err != nil {
		return fmt.Errorf("delete route %s: %w", dst, err)
	}
	return nil
}

func (w *winSystem) Save(owned []string) error {
	sorted := append([]string(nil), owned...)
	sort.Strings(sorted)
	w.state.Routes = w.state.Routes[:0]
	for _, d := range sorted {
		r := winRoute{Dst: d, If: w.s.TunnelIndex}
		if w.via != nil {
			r.Via = w.via.String()
		}
		w.state.Routes = append(w.state.Routes, r)
	}
	return w.write()
}

// write saves w.state to StatePath, or removes it when there's nothing to
// undo.
func (w *winSystem) write() error {
	if w.state.empty() {
		if err := os.Remove(StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(w.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(StatePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(StatePath, append(data, '\n'), 0o600)
}

// Teardown removes the NAT and switches forwarding back off where psxroute
// switched it on.
func (w *winSystem) Teardown(ctx context.Context) error {
	var errs []error
	if w.state.NAT {
		if err := w.removeNAT(ctx); err != nil {
			errs = append(errs, err)
		} else {
			w.state.NAT = false
		}
	}
	var left []int
	for _, idx := range w.state.Forwarding {
		if err := w.setForwarding(ctx, idx, false); err != nil {
			errs = append(errs, fmt.Errorf("switch off forwarding: %w", err))
			left = append(left, idx)
		}
	}
	w.state.Forwarding = left
	if err := w.write(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Cleanup undoes what StatePath lists, and removes psxroute's NAT whether or
// not it's listed.
func (w *winSystem) Cleanup(ctx context.Context) error {
	return w.cleanup(ctx, true)
}

func (w *winSystem) cleanup(ctx context.Context, alwaysNAT bool) error {
	var st winState
	data, err := os.ReadFile(StatePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("read %s: %w", StatePath, err)
		}
	}
	var errs []error
	for _, r := range st.Routes {
		n, err := parseDst(r.Dst)
		if err != nil {
			continue
		}
		if err := w.ip.DeleteRoute(ipRoute{Dst: n, IfIndex: r.If, NextHop: net.ParseIP(r.Via)}); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", r.Dst, err))
		}
	}
	if st.NAT || alwaysNAT {
		if err := w.removeNAT(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	for _, idx := range st.Forwarding {
		if err := w.setForwarding(ctx, idx, false); err != nil {
			errs = append(errs, fmt.Errorf("switch off forwarding: %w", err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.Remove(StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (w *winSystem) setForwarding(ctx context.Context, ifIndex int, on bool) error {
	v := "disabled"
	if on {
		v = "enabled"
	}
	_, err := w.run.Run(ctx, "", "netsh", "interface", "ipv4", "set", "interface",
		"interface="+strconv.Itoa(ifIndex), "forwarding="+v, "store=active")
	return err
}

func (w *winSystem) removeNAT(ctx context.Context) error {
	_, err := w.powershell(ctx, fmt.Sprintf(
		"Get-NetNat -Name %s -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false", NATName))
	if err != nil {
		return fmt.Errorf("remove Windows NAT %s: %w", NATName, err)
	}
	return nil
}

func (w *winSystem) powershell(ctx context.Context, script string) (string, error) {
	return w.run.Run(ctx, "", "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
}
