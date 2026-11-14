// Package app wires psxroute's listeners together. It lives outside main so
// tests can start the whole thing on loopback ports.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ahyaghoubi/psxroute/internal/config"
	"github.com/ahyaghoubi/psxroute/internal/dashboard"
	"github.com/ahyaghoubi/psxroute/internal/dnsserver"
	"github.com/ahyaghoubi/psxroute/internal/exit"
	"github.com/ahyaghoubi/psxroute/internal/gateway"
	"github.com/ahyaghoubi/psxroute/internal/learn"
	"github.com/ahyaghoubi/psxroute/internal/monitor"
	"github.com/ahyaghoubi/psxroute/internal/netinfo"
	"github.com/ahyaghoubi/psxroute/internal/relay"
	"github.com/ahyaghoubi/psxroute/internal/rules"
)

// Options are the parts tests may replace.
type Options struct {
	Version string
	Logger  *slog.Logger
	// Exit overrides the dialer built from cfg.Exit.
	Exit exit.Dialer
	// HTTPSPort and HTTPPort are the far-end ports; 0 means 443 and 80.
	HTTPSPort, HTTPPort int

	// RoutesPath is where domains added from the dashboard are saved, and
	// loaded from at start. Empty means they last until psxroute stops.
	RoutesPath string

	// Gateway mode: tests swap in a fake command runner and interface list,
	// and skip the macOS and root checks.
	GatewayRunner     gateway.Runner
	GatewayInterfaces []gateway.Iface
	SkipPreflight     bool
}

// App is a running psxroute.
type App struct {
	Advertise string
	// Addrs are the bound listener addresses, by name: dns, https, http,
	// dashboard. A listener switched off in the config is missing.
	Addrs   map[string]string
	Rules   *rules.Set
	Tracker *learn.Tracker
	// Gateway is set in gateway mode.
	Gateway *gateway.Gateway
	// Monitor watches the console's connections; gateway mode only.
	Monitor *monitor.Monitor

	wg   sync.WaitGroup
	errs chan error
	log  *slog.Logger
	ctx  context.Context
}

// Start binds every listener and serves until ctx is done.
func Start(ctx context.Context, cfg *config.Config, opt Options) (*App, error) {
	log := opt.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	set, err := rules.Build(cfg.Packs, cfg.Hosts)
	if err != nil {
		return nil, err
	}
	if set.Len() == 0 {
		log.Warn("no domains are routed: every lookup is passed straight to upstream DNS")
	}
	advertise := cfg.AdvertiseIP
	if advertise == "" {
		advertise = netinfo.PrimaryIPv4()
		if advertise == "" {
			return nil, errors.New("couldn't find this machine's LAN address; set advertise_ip in the config")
		}
	}
	dialer := opt.Exit
	if dialer == nil {
		dialer, err = exit.New(cfg.Exit, cfg.UpstreamDNS)
		if err != nil {
			return nil, err
		}
	}
	httpsPort, httpPort := opt.HTTPSPort, opt.HTTPPort
	if httpsPort == 0 {
		httpsPort = 443
	}
	if httpPort == 0 {
		httpPort = 80
	}

	a := &App{Advertise: advertise, Addrs: map[string]string{}, Rules: set, Tracker: learn.New(), errs: make(chan error, 8), log: log, ctx: ctx}
	rt := &routes{set: set, path: opt.RoutesPath, track: a.Tracker, log: log, ctx: ctx}
	if err := rt.loadAdded(); err != nil {
		log.Warn("couldn't read saved routes", "path", opt.RoutesPath, "err", err)
	}
	ok := false
	var closers []func()
	defer func() {
		if !ok {
			for _, c := range closers {
				c()
			}
		}
	}()

	if cfg.Mode == "gateway" {
		if !opt.SkipPreflight {
			if err := gateway.Preflight(); err != nil {
				return nil, err
			}
		}
		run := opt.GatewayRunner
		if run == nil {
			run = gateway.ExecRunner{}
		}
		ifaces := opt.GatewayInterfaces
		if ifaces == nil {
			if ifaces, err = gateway.Interfaces(); err != nil {
				return nil, err
			}
		}
		gs, err := gateway.Discover(ctx, run, ifaces, advertise, cfg.Gateway.Tunnel)
		if err != nil {
			return nil, err
		}
		gs.RouteAll, gs.CIDRs = cfg.Gateway.RouteAll, cfg.Gateway.CIDRs
		gw, err := gateway.Start(ctx, gs, run, log)
		if err != nil {
			return nil, err
		}
		closers = append(closers, gw.Close)
		a.Gateway = gw
		rt.gw = gw
		a.Monitor = monitor.New(gs.LANNet, gs.LANIP)
		a.Monitor.ViaVPN = gw.ViaTunnel
		if gs.DefaultIface == gs.Tunnel && !gs.RouteAll {
			log.Warn("this Mac's default route is the VPN, so all console traffic goes through it; use a split tunnel to send only routed names")
		}
	}

	dns := &dnsserver.Server{
		Rules: set, Advertise: net.ParseIP(advertise).To4(), Upstreams: cfg.UpstreamDNS,
		Logger: log, OnLookup: a.Tracker.Lookup,
	}
	if gw := a.Gateway; gw != nil {
		dns.Gateway = true
		dns.OnResolved = func(name string, ips []net.IP) {
			n, err := gw.Add(ctx, ips)
			if err != nil {
				log.Warn("couldn't route addresses", "name", name, "err", err)
				return
			}
			strs := make([]string, len(ips))
			for i, ip := range ips {
				strs[i] = ip.String()
			}
			a.Tracker.Resolved(name, strs)
			if n > 0 {
				log.Debug("routing addresses", "name", name, "new", n, "total", gw.Len())
			}
		}
	}
	if mon := a.Monitor; mon != nil {
		dns.OnAnswer = mon.SetName
	}
	if cfg.Listen.DNS != "" {
		pc, err := net.ListenPacket("udp", cfg.Listen.DNS)
		if err != nil {
			return nil, listenErr("DNS (UDP)", cfg.Listen.DNS, err)
		}
		closers = append(closers, func() { pc.Close() })
		// Use the port UDP actually got, so ":0" in tests binds TCP alike.
		tcpAddr := cfg.Listen.DNS
		if host, _, err := net.SplitHostPort(cfg.Listen.DNS); err == nil {
			tcpAddr = net.JoinHostPort(host, portOf(pc.LocalAddr()))
		}
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return nil, listenErr("DNS (TCP)", tcpAddr, err)
		}
		closers = append(closers, func() { ln.Close() })
		a.Addrs["dns"] = pc.LocalAddr().String()
		a.goServe("dns udp", func() error { return dns.ServeUDP(ctx, pc) })
		a.goServe("dns tcp", func() error { return dns.ServeTCP(ctx, ln) })
	}

	for _, l := range []struct {
		name, addr string
		kind       relay.Kind
		port       int
	}{
		{"https", cfg.Listen.HTTPS, relay.TLS, httpsPort},
		{"http", cfg.Listen.HTTP, relay.HTTP, httpPort},
	} {
		// Gateway mode routes packets, so the relay isn't needed.
		if l.addr == "" || a.Gateway != nil {
			continue
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			return nil, listenErr(l.name, l.addr, err)
		}
		closers = append(closers, func() { ln.Close() })
		a.Addrs[l.name] = ln.Addr().String()
		srv := &relay.Server{Kind: l.kind, Port: l.port, Rules: set, Exit: dialer, Logger: log, OnOpen: a.Tracker.Open, OnConn: a.Tracker.Conn}
		a.goServe(l.name, func() error { return srv.Serve(ctx, ln) })
	}

	if mon := a.Monitor; mon != nil && !opt.SkipPreflight {
		gs := a.Gateway.Settings()
		a.goServe("monitor", func() error {
			// A capture problem is shown on the dashboard; it never stops psxroute.
			if err := monitor.Capture(ctx, gs.LANIface, gs.LANIP, mon); err != nil {
				log.Warn("connection monitor stopped", "err", err)
				mon.SetProblem(err.Error())
			}
			return nil
		})
	}

	if cfg.Listen.Dashboard != "" {
		ln, err := net.Listen("tcp", cfg.Listen.Dashboard)
		if err != nil {
			return nil, listenErr("dashboard", cfg.Listen.Dashboard, err)
		}
		closers = append(closers, func() { ln.Close() })
		a.Addrs["dashboard"] = ln.Addr().String()
		srv := &http.Server{
			Handler:           dashboard.New(a.dashboardInfo(cfg, opt.Version), rt, a.Tracker),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
		a.goServe("dashboard", func() error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
	}
	ok = true
	return a, nil
}

func (a *App) dashboardInfo(cfg *config.Config, version string) dashboard.Info {
	info := dashboard.Info{Version: version, Mode: cfg.Mode, ConsoleIP: a.Advertise, Exit: cfg.Exit}
	if a.Monitor != nil {
		info.Monitor = a.Monitor
	}
	if gw := a.Gateway; gw != nil {
		gs := gw.Settings()
		info.Tunnel, info.CIDRs = gs.Tunnel, gs.CIDRs
		info.RouteAll = gw.RouteAll
		info.SetRouteAll = func(on bool) error {
			if err := gw.SetRouteAll(context.Background(), on); err != nil {
				return err
			}
			a.log.Info("everything through the VPN", "on", on)
			return nil
		}
		info.SubnetMask = net.IP(gs.LANNet.Mask).String()
		info.LANNet = gs.LANNet.String()
		info.RoutedAddrs = gw.Len
	}
	return info
}

func (a *App) goServe(name string, fn func() error) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := fn(); err != nil {
			a.errs <- fmt.Errorf("%s: %w", name, err)
		}
	}()
}

// Wait blocks until every listener has stopped, returning the first error a
// listener failed with, or nil after a clean shutdown.
// In gateway mode it then removes the firewall rules and restores the
// system settings it changed.
func (a *App) Wait(ctx context.Context) error {
	if a.Gateway != nil {
		defer a.Gateway.Close()
	}
	select {
	case err := <-a.errs:
		return err
	case <-ctx.Done():
	}
	a.wg.Wait()
	return nil
}

func portOf(addr net.Addr) string {
	_, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "0"
	}
	if _, err := strconv.Atoi(p); err != nil {
		return "0"
	}
	return p
}

func listenErr(what, addr string, err error) error {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("%s: %s is already in use by another program", what, addr)
	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf("%s: no permission to listen on %s (ports below 1024 need extra rights on Linux: see README)", what, addr)
	}
	return fmt.Errorf("%s: listen on %s: %w", what, addr, err)
}
