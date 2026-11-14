package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsFinalise(t *testing.T) {
	c := Default()
	if err := c.Finalise(); err != nil {
		t.Fatal(err)
	}
	if c.Exit != "direct" || c.Listen.DNS != "0.0.0.0:53" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "exit: socks5://127.0.0.1:10808\nupstream_dns: [9.9.9.9]\nhosts: [example.org]\npacks: []\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Finalise(); err != nil {
		t.Fatal(err)
	}
	if c.Exit != "socks5://127.0.0.1:10808" || c.UpstreamDNS[0] != "9.9.9.9:53" || len(c.Packs) != 0 || c.Hosts[0] != "example.org" {
		t.Fatalf("got %+v", c)
	}
}

func TestLoadMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.yaml")
	if _, err := Load(missing, false); err != nil {
		t.Fatalf("implicit missing file should load defaults: %v", err)
	}
	if _, err := Load(missing, true); err == nil {
		t.Fatal("explicit missing file should fail")
	}
}

func TestFinaliseRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"bad exit scheme": func(c *Config) { c.Exit = "ftp://x:1" },
		"bad exit":        func(c *Config) { c.Exit = "socks5://" },
		"ipv6 advertise":  func(c *Config) { c.AdvertiseIP = "::1" },
		"bad listen":      func(c *Config) { c.Listen.DNS = "53" },
		"no upstream":     func(c *Config) { c.UpstreamDNS = nil },
		"bad log level":   func(c *Config) { c.Log.Level = "loud" },
		"bad mode":        func(c *Config) { c.Mode = "tunnel" },
		"bad cidr":        func(c *Config) { c.Gateway.CIDRs = []string{"10.0.0.0/33"} },
		"ipv6 cidr":       func(c *Config) { c.Gateway.CIDRs = []string{"2001:db8::/32"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Finalise(); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestGatewayCIDRsNormalised(t *testing.T) {
	c := Default()
	c.Mode = "Gateway"
	c.Gateway.CIDRs = []string{"203.0.113.7", "198.51.100.9/24"}
	if err := c.Finalise(); err != nil {
		t.Fatal(err)
	}
	if c.Mode != "gateway" || c.Gateway.CIDRs[0] != "203.0.113.7/32" || c.Gateway.CIDRs[1] != "198.51.100.0/24" {
		t.Fatalf("got %q %v", c.Mode, c.Gateway.CIDRs)
	}
}
