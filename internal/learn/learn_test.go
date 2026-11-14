package learn

import (
	"errors"
	"testing"
	"time"
)

func TestTracker(t *testing.T) {
	tr := New()
	clock := time.Unix(1000, 0)
	tr.now = func() time.Time { return clock }

	tr.Lookup("accounts.ea.com", "192.168.1.5", true, "ea")
	tr.Lookup("accounts.ea.com", "192.168.1.5", true, "ea")
	clock = clock.Add(time.Second)
	tr.Lookup("store.playstation.com", "192.168.1.5", false, "")
	tr.Open("accounts.ea.com", "ea")
	tr.Open("accounts.ea.com", "ea")
	tr.Conn("accounts.ea.com", 100, 2000, nil)
	tr.Conn("accounts.ea.com", 0, 0, errors.New("dial: refused"))

	got := tr.Snapshot()
	if len(got) != 2 || got[0].Name != "accounts.ea.com" {
		t.Fatalf("order: %+v", got)
	}
	h := got[0]
	if h.Lookups != 2 || h.Conns != 2 || h.Active != 0 || h.Failures != 1 || h.BytesDown != 2000 || len(h.Clients) != 1 || h.LastError != "dial: refused" {
		t.Fatalf("host: %+v", h)
	}
	clock = clock.Add(time.Second)
	tr.Open("cached.ea.com", "ea")
	if h := tr.Snapshot()[0]; h.Name != "cached.ea.com" || !h.Routed || h.Source != "ea" {
		t.Fatalf("relayed without lookup: %+v", h)
	}
	tr.Clear()
	if len(tr.Snapshot()) != 0 {
		t.Fatal("Clear left hosts")
	}
}

func TestEviction(t *testing.T) {
	tr := New()
	clock := time.Unix(0, 0)
	tr.now = func() time.Time { clock = clock.Add(time.Millisecond); return clock }
	for i := 0; i <= MaxHosts; i++ {
		tr.Lookup(string(rune('a'+i%26))+time.Duration(i).String(), "c", false, "")
	}
	if n := len(tr.Snapshot()); n != MaxHosts {
		t.Fatalf("kept %d hosts, want %d", n, MaxHosts)
	}
}
