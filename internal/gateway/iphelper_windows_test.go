//go:build windows

package gateway

import (
	"net"
	"testing"
)

// TestIPHelperOnWindows uses the real API. Adding a route needs an elevated
// process, which GitHub's Windows runners are.
func TestIPHelperOnWindows(t *testing.T) {
	ifaces, err := Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Fatalf("Interfaces = %v, %v", ifaces, err)
	}
	h := newIPHelper()
	routes, err := h.Routes()
	if err != nil || len(routes) == 0 {
		t.Fatalf("Routes = %d, %v", len(routes), err)
	}
	if !isElevated() {
		t.Skip("not elevated: can't add routes")
	}

	// An up adapter with IPv4, to hang a test route on.
	var idx int
	for _, i := range ifaces {
		if i.Up && hasIPv4(i) {
			idx = i.Index
			break
		}
	}
	if idx == 0 {
		t.Skip("no up adapter with IPv4")
	}
	if _, err := h.Forwarding(idx); err != nil {
		t.Fatalf("Forwarding(%d): %v", idx, err)
	}

	_, dst, _ := net.ParseCIDR("198.51.100.77/32") // TEST-NET-2
	r := ipRoute{Dst: dst, IfIndex: idx}
	_ = h.DeleteRoute(r)
	if added, err := h.AddRoute(r); err != nil || !added {
		t.Fatalf("AddRoute = %v, %v", added, err)
	}
	t.Cleanup(func() { _ = h.DeleteRoute(r) })
	if added, err := h.AddRoute(r); err != nil || added {
		t.Fatalf("adding it again = %v, %v; want false, nil", added, err)
	}
	found := false
	routes, _ = h.Routes()
	for _, x := range routes {
		if x.Dst.String() == dst.String() && x.IfIndex == idx {
			found = true
		}
	}
	if !found {
		t.Fatal("added route isn't in the table")
	}
	if err := h.DeleteRoute(r); err != nil {
		t.Fatal(err)
	}
	if err := h.DeleteRoute(r); err != nil {
		t.Fatalf("deleting a missing route should be fine: %v", err)
	}
}
