// Package config loads psxroute's settings from a YAML file over built-in
// defaults.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the whole settings file.
type Config struct {
	// Mode is "relay" (DNS plus SNI relay, any OS) or "gateway" (this Mac is
	// the console's gateway and routes traffic through a VPN tunnel; macOS,
	// needs sudo).
	Mode string `yaml:"mode"`

	// Gateway configures gateway mode.
	Gateway struct {
		// Tunnel is the VPN's interface, e.g. utun4. "auto" picks the only one.
		Tunnel string `yaml:"tunnel"`
		// RouteAll sends all the console's internet traffic through the
		// tunnel, not just routed names and CIDRs.
		RouteAll bool `yaml:"route_all"`
		// CIDRs are address ranges always routed, for servers a game reaches
		// by IP rather than by name.
		CIDRs []string `yaml:"cidrs"`
	} `yaml:"gateway"`

	Listen struct {
		// DNS is where the console sends its DNS queries (UDP and TCP).
		DNS string `yaml:"dns"`
		// HTTPS and HTTP receive the connections for routed host names.
		HTTPS string `yaml:"https"`
		HTTP  string `yaml:"http"`
		// Dashboard shows what the console looked up and where it went.
		Dashboard string `yaml:"dashboard"`
	} `yaml:"listen"`

	// AdvertiseIP is the address given to the console for routed names. Empty
	// means this machine's LAN address, found automatically.
	AdvertiseIP string `yaml:"advertise_ip"`

	// UpstreamDNS answers every name that isn't routed, and resolves routed
	// names when Exit is "direct". Plain DNS servers, host:port.
	UpstreamDNS []string `yaml:"upstream_dns"`

	// Exit is where routed connections leave: "direct" (this machine's own
	// route, e.g. a full-tunnel VPN), socks5://host:port or http://host:port.
	Exit string `yaml:"exit"`

	// Packs are the built-in host lists to route, by name.
	Packs []string `yaml:"packs"`
	// Hosts are extra domain names to route. A name also covers its
	// subdomains: "ea.com" routes "accounts.ea.com".
	Hosts []string `yaml:"hosts"`

	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`
}

// Default returns the zero-config settings.
func Default() *Config {
	c := &Config{}
	c.Mode = "relay"
	c.Gateway.Tunnel = "auto"
	c.Listen.DNS = "0.0.0.0:53"
	c.Listen.HTTPS = "0.0.0.0:443"
	c.Listen.HTTP = "0.0.0.0:80"
	c.Listen.Dashboard = "0.0.0.0:8053"
	c.UpstreamDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
	c.Exit = "direct"
	c.Packs = []string{"ea", "activision"}
	c.Log.Level = "info"
	return c
}

// DefaultPath is ~/.config/psxroute/config.yaml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "psxroute", "config.yaml")
}

// Load reads path over the defaults. A missing file is only an error when
// the path was given explicitly.
func Load(path string, explicit bool) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}

// Finalise normalises and checks the settings after flags are applied.
func (c *Config) Finalise() error {
	switch c.Mode = strings.ToLower(strings.TrimSpace(c.Mode)); c.Mode {
	case "":
		c.Mode = "relay"
	case "relay", "gateway":
	default:
		return fmt.Errorf("mode %q: want relay or gateway", c.Mode)
	}
	if c.Gateway.Tunnel == "" {
		c.Gateway.Tunnel = "auto"
	}
	for i, s := range c.Gateway.CIDRs {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil || n.IP.To4() == nil {
			return fmt.Errorf("gateway.cidrs: %q is not an IPv4 address or range", c.Gateway.CIDRs[i])
		}
		c.Gateway.CIDRs[i] = n.String()
	}
	for name, addr := range map[string]string{
		"listen.dns": c.Listen.DNS, "listen.https": c.Listen.HTTPS,
		"listen.http": c.Listen.HTTP, "listen.dashboard": c.Listen.Dashboard,
	} {
		if addr == "" {
			continue // empty switches that listener off
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s %q: want host:port", name, addr)
		}
	}
	if c.AdvertiseIP != "" {
		ip := net.ParseIP(c.AdvertiseIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("advertise_ip %q is not an IPv4 address", c.AdvertiseIP)
		}
	}
	if len(c.UpstreamDNS) == 0 {
		return errors.New("upstream_dns: at least one DNS server is needed")
	}
	for i, s := range c.UpstreamDNS {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		c.UpstreamDNS[i] = s
	}
	c.Exit = strings.TrimSpace(c.Exit)
	if c.Exit == "" {
		c.Exit = "direct"
	}
	if c.Exit != "direct" {
		u, err := url.Parse(c.Exit)
		if err != nil || u.Host == "" {
			return fmt.Errorf("exit %q: want direct, socks5://host:port or http://host:port", c.Exit)
		}
		switch u.Scheme {
		case "socks5", "socks5h", "http":
		default:
			return fmt.Errorf("exit: scheme %q not supported (use socks5 or http)", u.Scheme)
		}
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
		c.Log.Level = strings.ToLower(c.Log.Level)
	case "":
		c.Log.Level = "info"
	default:
		return fmt.Errorf("log.level %q: want debug, info, warn or error", c.Log.Level)
	}
	return nil
}
