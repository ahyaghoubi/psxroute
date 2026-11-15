// Command psxroute sends chosen games' online traffic out through another
// route, such as a VPN, by being the console's DNS server.
//
// Usage:
//
//	psxroute [--config FILE] [--mode relay|gateway] [--exit URL] [--advertise IP] [--log-level LEVEL]
//	psxroute packs
//	psxroute cleanup
//	psxroute version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ahyaghoubi/psxroute/internal/app"
	"github.com/ahyaghoubi/psxroute/internal/config"
	"github.com/ahyaghoubi/psxroute/internal/gateway"
	"github.com/ahyaghoubi/psxroute/internal/netinfo"
	"github.com/ahyaghoubi/psxroute/internal/rules"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "psxroute:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintln(out, version)
			return nil
		case "packs":
			return listPacks(out)
		case "cleanup":
			// Undo gateway mode after a crash or kill -9.
			if err := gateway.Preflight(); err != nil {
				return err
			}
			sys, err := gateway.NewSystem(gateway.ExecRunner{})
			if err != nil {
				return err
			}
			if err := gateway.Cleanup(ctx, sys); err != nil {
				return err
			}
			fmt.Fprintln(out, "Removed psxroute's routes, firewall and NAT rules and switched IP forwarding off.")
			return nil
		}
	}

	fs := flag.NewFlagSet("psxroute", flag.ContinueOnError)
	fs.SetOutput(out)
	cfgPath := fs.String("config", "", "settings file (default "+config.DefaultPath()+")")
	mode := fs.String("mode", "", "relay (default) or gateway (macOS with sudo, or Windows as Administrator)")
	exitURL := fs.String("exit", "", "where routed traffic leaves: direct, socks5://host:port or http://host:port")
	advertise := fs.String("advertise", "", "this machine's LAN IPv4 address, if the automatic one is wrong")
	logLevel := fs.String("log-level", "", "debug, info, warn or error")
	fs.Usage = func() {
		fmt.Fprintln(out, "Usage: psxroute [flags]\n       psxroute packs\n       psxroute cleanup   (undo gateway mode after a crash)\n       psxroute version\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q (run psxroute -h for help)", fs.Arg(0))
	}

	path, explicit := *cfgPath, *cfgPath != ""
	if !explicit {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path, explicit)
	if err != nil {
		return err
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *exitURL != "" {
		cfg.Exit = *exitURL
	}
	if *advertise != "" {
		cfg.AdvertiseIP = *advertise
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}
	if err := cfg.Finalise(); err != nil {
		return err
	}
	logger := newLogger(cfg.Log.Level)

	routesPath := ""
	if path != "" {
		routesPath = filepath.Join(filepath.Dir(path), "routes.txt")
	}
	a, err := app.Start(ctx, cfg, app.Options{Version: version, Logger: logger, RoutesPath: routesPath})
	if err != nil {
		return err
	}
	printBanner(out, a, cfg)
	err = a.Wait(ctx)
	fmt.Fprintln(out, "\nStopped.")
	return err
}

func listPacks(out io.Writer) error {
	packs, err := rules.Packs()
	if err != nil {
		return err
	}
	for _, p := range packs {
		fmt.Fprintf(out, "%-12s %s\n", p.Name, p.Description)
		for _, h := range p.Hosts {
			fmt.Fprintf(out, "             %s\n", h)
		}
	}
	return nil
}

func printBanner(out io.Writer, a *app.App, cfg *config.Config) {
	fmt.Fprintf(out, "psxroute %s, %s mode\n\n", version, cfg.Mode)
	if gw := a.Gateway; gw != nil {
		gs := gw.Settings()
		free := "an unused address on " + gs.LANNet.String()
		fmt.Fprintf(out, "  On the console: Advanced Settings › IP Address Settings: Manual\n")
		fmt.Fprintf(out, "    IP Address %s, Subnet Mask %s,\n", free, net.IP(gs.LANNet.Mask).String())
		fmt.Fprintf(out, "    Default Gateway, Primary DNS and Secondary DNS:  %s\n", a.Advertise)
		fmt.Fprintf(out, "  Tunnel:                                          %s", gs.Tunnel)
		if gs.RouteAll {
			fmt.Fprint(out, " (all console traffic)")
		}
		fmt.Fprintln(out)
		if gs.DefaultIface != "" && !gs.RouteAll {
			via := gs.DefaultIface
			if gs.DefaultGW != nil {
				via += " via " + gs.DefaultGW.String()
			}
			fmt.Fprintf(out, "  Everything else leaves by:                       %s\n", via)
		}
	} else {
		fmt.Fprintf(out, "  On the console, set Primary and Secondary DNS to:  %s\n", a.Advertise)
	}
	if d, ok := a.Addrs["dashboard"]; ok {
		_, port, _ := net.SplitHostPort(d)
		fmt.Fprintf(out, "  Dashboard:                                       http://%s:%s/\n", a.Advertise, port)
	}
	if a.Gateway == nil {
		fmt.Fprintf(out, "  Exit:                                            %s\n", cfg.Exit)
	}
	fmt.Fprintf(out, "  Routing %d domains", a.Rules.Len())
	if len(cfg.Packs) > 0 {
		fmt.Fprintf(out, " (packs: %v)", cfg.Packs)
	}
	fmt.Fprintln(out)
	if addrs, _ := netinfo.IPv4Addrs(); len(addrs) > 1 && cfg.AdvertiseIP == "" {
		fmt.Fprintf(out, "\n  This machine has several addresses: %v\n  If the console can't reach %s, run with --advertise <the one on the console's network>.\n", addrs, a.Advertise)
	}
	if a.Gateway == nil && cfg.Exit == "direct" {
		fmt.Fprintln(out, "\n  Exit is direct: routed traffic leaves through this machine's own connection.\n  That only helps if this machine is on a full-tunnel VPN.")
	}
	if a.Gateway != nil {
		fmt.Fprintln(out, "\nPress Ctrl+C to stop: the routes and firewall rules are removed and forwarding restored.\nSet the console back to Automatic afterwards, or it loses internet.")
		return
	}
	fmt.Fprintln(out, "\nPress Ctrl+C to stop.")
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
