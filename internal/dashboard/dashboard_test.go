package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ahyaghoubi/psxroute/internal/learn"
	"github.com/ahyaghoubi/psxroute/internal/rules"
)

type setRoutes struct{ *rules.Set }

func (r setRoutes) Add(d string) error {
	_, err := r.Set.Add(d, rules.SourceAdded)
	return err
}

func (r setRoutes) Remove(d string) error {
	if !r.Set.Remove(d, rules.SourceAdded) {
		return errors.New("not added")
	}
	return nil
}

func newHandler(t *testing.T, exit string) (*Handler, *learn.Tracker, setRoutes) {
	t.Helper()
	set, err := rules.Build([]string{"ea"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := learn.New()
	rt := setRoutes{set}
	h := New(Info{Version: "test", Mode: "relay", ConsoleIP: "192.168.1.20", Exit: exit}, rt, tr)
	return h, tr, rt
}

func getState(t *testing.T, h http.Handler) State {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if rec.Code != 200 {
		t.Fatalf("state = %d", rec.Code)
	}
	var st State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStateGroupsAndConsole(t *testing.T) {
	h, tr, _ := newHandler(t, "socks5://user:secret@127.0.0.1:10808")
	tr.Lookup("accounts.ea.com", "192.168.1.50", true, "ea")
	tr.Lookup("gateway.ea.com", "192.168.1.50", true, "ea")
	tr.Open("accounts.ea.com", "ea")
	tr.Lookup("cdn1.battlefield.com", "192.168.1.50", false, "")
	tr.Lookup("cdn2.battlefield.com", "192.168.1.50", false, "")
	tr.Lookup("np.playstation.net", "192.168.1.20", false, "") // this machine itself

	st := getState(t, h)
	if !st.Console.Connected || st.Console.IP != "192.168.1.50" {
		t.Fatalf("console = %+v", st.Console)
	}
	if len(st.Routed) != 1 || st.Routed[0].Name != "ea.com" || len(st.Routed[0].Hosts) != 2 || st.Routed[0].Open != 1 || st.Routed[0].SourceLabel != "EA games" {
		t.Fatalf("routed = %+v", st.Routed)
	}
	if st.Routed[0].Removable {
		t.Fatal("pack domains shouldn't be removable from the page")
	}
	var bf *Group
	for i := range st.Other {
		if st.Other[i].Name == "battlefield.com" {
			bf = &st.Other[i]
		}
	}
	if bf == nil || len(bf.Hosts) != 2 || bf.RouteDomain != "battlefield.com" {
		t.Fatalf("other = %+v", st.Other)
	}
	if strings.Contains(st.ExitLabel, "secret") || !strings.Contains(st.ExitLabel, "127.0.0.1:10808") {
		t.Fatalf("exit label %q", st.ExitLabel)
	}
	if st.Totals.Open != 1 || st.Totals.RoutedSites != 1 {
		t.Fatalf("totals = %+v", st.Totals)
	}
}

func TestConsoleGoesQuiet(t *testing.T) {
	h, tr, _ := newHandler(t, "direct")
	tr.Lookup("x.example.com", "192.168.1.50", false, "")
	h.now = func() time.Time { return time.Now().Add(ConnectedWithin + time.Second) }
	if c := getState(t, h).Console; !c.Seen || c.Connected {
		t.Fatalf("console = %+v", c)
	}
}

func TestRouteAndUnrouteAPI(t *testing.T) {
	h, tr, rt := newHandler(t, "direct")
	tr.Lookup("cdn1.battlefield.com", "192.168.1.50", false, "")

	post := func(path, ctype, body string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// A plain form post (what a hostile page could send) is refused.
	if code := post("/api/route", "application/x-www-form-urlencoded", "domain=battlefield.com"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post = %d", code)
	}
	if code := post("/api/route", "application/json", `{"domain":"battlefield.com"}`); code != 200 {
		t.Fatalf("route = %d", code)
	}
	st := getState(t, h)
	if len(st.Routed) != 1 || st.Routed[0].Name != "battlefield.com" || !st.Routed[0].Removable {
		t.Fatalf("after route: %+v", st.Routed)
	}
	if code := post("/api/unroute", "application/json", `{"domain":"ea.com"}`); code != 400 {
		t.Fatalf("removing a pack domain = %d", code)
	}
	if code := post("/api/unroute", "application/json", `{"domain":"battlefield.com"}`); code != 200 {
		t.Fatalf("unroute = %d", code)
	}
	if _, ok := rt.Match("cdn1.battlefield.com"); ok {
		t.Fatal("still routed")
	}
}

func TestFriendlyErrors(t *testing.T) {
	h, _, _ := newHandler(t, "socks5://127.0.0.1:10808")
	for raw, want := range map[string]string{
		"dial: dial tcp 127.0.0.1:10808: connect: connection refused": "VPN app's proxy",
		"dial: i/o timeout":              "Timed out",
		"read: connection reset by peer": "cut part-way",
	} {
		if got := h.friendlyError(raw, 1, 1); !strings.Contains(got, want) {
			t.Errorf("friendlyError(%q) = %q, want it to mention %q", raw, got, want)
		}
	}
	if got := h.friendlyError("dial: i/o timeout", 1, 4); !strings.HasPrefix(got, "1 of 4 connections failed") {
		t.Errorf("partial failure = %q", got)
	}
}

func TestPageServed(t *testing.T) {
	h, _, _ := newHandler(t, "direct")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/api/state") {
		t.Fatalf("page = %d", rec.Code)
	}
}

func TestMonitorNeedsGatewayMode(t *testing.T) {
	h, _, _ := newHandler(t, "direct")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/monitor", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("monitor = %d %s", rec.Code, rec.Body)
	}
}
