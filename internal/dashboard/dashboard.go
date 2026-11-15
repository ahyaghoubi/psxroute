// Package dashboard is psxroute's web page: setup steps for the console, what
// is going through the VPN, everything else the console looked up, and a
// one-click way to route more.
package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ahyaghoubi/psxroute/internal/learn"
	"github.com/ahyaghoubi/psxroute/internal/monitor"
	"github.com/ahyaghoubi/psxroute/internal/rules"
)

//go:embed web/index.html
var webFS embed.FS

// ConnectedWithin is how recent the console's last lookup must be for it to
// show as connected.
const ConnectedWithin = 2 * time.Minute

// Info is the fixed setup the page shows.
type Info struct {
	Version   string
	Mode      string // relay or gateway
	ConsoleIP string // this machine's LAN address: the console's DNS (and gateway)
	Exit      string // exit URL, or "direct"
	// GatewayCommand is how to start gateway mode on this computer.
	GatewayCommand string

	// Gateway mode only.
	Tunnel string
	// RouteAll and SetRouteAll read and flip "everything through the VPN".
	RouteAll    func() bool
	SetRouteAll func(on bool) error
	SubnetMask  string
	LANNet      string
	CIDRs       []string
	RoutedAddrs func() int

	// Monitor, when set, feeds the connection monitor (gateway mode).
	Monitor Monitor
}

// Monitor summarises the console's connections.
type Monitor interface {
	Snapshot(console string) monitor.View
}

// Routes is the live rule set.
type Routes interface {
	Domains() []rules.Domain
	MatchDomain(host string) (domain, source string, ok bool)
	Add(domain string) error
	Remove(domain string) error
}

// Handler serves the page and its API.
type Handler struct {
	info   Info
	routes Routes
	track  *learn.Tracker
	now    func() time.Time
}

// New returns the dashboard handler.
func New(info Info, routes Routes, track *learn.Tracker) *Handler {
	return &Handler{info: info, routes: routes, track: track, now: time.Now}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		page, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	case r.URL.Path == "/api/state" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, h.state())
	case r.URL.Path == "/api/monitor" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, h.monitorState())
	case r.URL.Path == "/api/route" && r.Method == http.MethodPost:
		h.change(w, r, h.routes.Add)
	case r.URL.Path == "/api/unroute" && r.Method == http.MethodPost:
		h.change(w, r, h.routes.Remove)
	case r.URL.Path == "/api/route-all" && r.Method == http.MethodPost:
		h.routeAll(w, r)
	case r.URL.Path == "/api/clear" && r.Method == http.MethodPost:
		if !isJSON(r) {
			writeJSON(w, http.StatusUnsupportedMediaType, apiError{"send JSON"})
			return
		}
		h.track.Clear()
		writeJSON(w, http.StatusOK, struct{}{})
	case r.URL.Path == "/hosts.json" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, h.track.Snapshot())
	case r.URL.Path == "/hosts.txt" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, host := range h.track.Snapshot() {
			mark := "  "
			if _, _, ok := h.routes.MatchDomain(host.Name); ok {
				mark = "R "
			}
			fmt.Fprintf(w, "%s%s\n", mark, host.Name)
		}
	default:
		http.NotFound(w, r)
	}
}

type apiError struct {
	Error string `json:"error"`
}

// change handles route and unroute. Requiring a JSON body means a page on
// another site can't trigger it with a plain form post.
func (h *Handler) change(w http.ResponseWriter, r *http.Request, fn func(string) error) {
	if !isJSON(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, apiError{"send JSON"})
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{"couldn't read the request"})
		return
	}
	if err := fn(strings.TrimSpace(body.Domain)); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (h *Handler) gatewayCommand() string {
	if h.info.GatewayCommand != "" {
		return h.info.GatewayCommand
	}
	return "sudo psxroute --mode gateway"
}

func (h *Handler) routeAll(w http.ResponseWriter, r *http.Request) {
	if !isJSON(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, apiError{"send JSON"})
		return
	}
	if h.info.SetRouteAll == nil {
		writeJSON(w, http.StatusConflict, apiError{"Sending everything through the VPN needs gateway mode. Restart psxroute with: " + h.gatewayCommand()})
		return
	}
	var body struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{"couldn't read the request"})
		return
	}
	if err := h.info.SetRouteAll(body.On); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// State is everything the page shows, recomputed on each poll.
type State struct {
	Version    string `json:"version"`
	Mode       string `json:"mode"`
	ConsoleIP  string `json:"console_ip"`
	ExitLabel  string `json:"exit_label"`
	SubnetMask string `json:"subnet_mask,omitempty"`
	LANNet     string `json:"lan_net,omitempty"`
	RouteAll   bool   `json:"route_all"`
	// CanRouteAll is false in relay mode, where the switch is unavailable.
	CanRouteAll bool     `json:"can_route_all"`
	CIDRs       []string `json:"cidrs,omitempty"`
	// GatewayCommand is how to start gateway mode, for hints in relay mode.
	GatewayCommand string `json:"gateway_command"`

	Console Console `json:"console"`
	Totals  Totals  `json:"totals"`
	Routed  []Group `json:"routed"`
	Other   []Group `json:"other"`
	Domains []Rule  `json:"domains"`
}

// Console is what's known about the PS5.
type Console struct {
	Seen      bool   `json:"seen"`
	Connected bool   `json:"connected"`
	IP        string `json:"ip,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// Totals are the headline numbers.
type Totals struct {
	RoutedSites int    `json:"routed_sites"`
	Open        int    `json:"open"`
	Data        string `json:"data"`
	Addresses   int    `json:"addresses"`
}

// Group is one site (ea.com) and the names under it.
type Group struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"` // a friendly name for known sites
	Routed      bool   `json:"routed"`
	Source      string `json:"source,omitempty"`
	SourceLabel string `json:"source_label,omitempty"`
	// RouteDomain is the domain the Route or Stop routing button acts on.
	RouteDomain string `json:"route_domain"`
	Removable   bool   `json:"removable,omitempty"`
	Hosts       []Name `json:"hosts"`
	Lookups     int    `json:"lookups"`
	Conns       int    `json:"conns"`
	Open        int    `json:"open"`
	Data        string `json:"data"`
	LastSeen    string `json:"last_seen"`
	Problem     string `json:"problem,omitempty"`

	lastSeen time.Time
	bytes    int64
}

// Name is one host name in a group.
type Name struct {
	Name     string   `json:"name"`
	Lookups  int      `json:"lookups"`
	Conns    int      `json:"conns"`
	Open     int      `json:"open"`
	Data     string   `json:"data"`
	LastSeen string   `json:"last_seen"`
	Problem  string   `json:"problem,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
}

// Rule is one routed domain in the rules list.
type Rule struct {
	Domain      string `json:"domain"`
	SourceLabel string `json:"source_label"`
	Removable   bool   `json:"removable"`
}

func (h *Handler) state() State {
	now := h.now()
	st := State{
		Version: h.info.Version, Mode: h.info.Mode, ConsoleIP: h.info.ConsoleIP,
		SubnetMask: h.info.SubnetMask, LANNet: h.info.LANNet,
		CIDRs: h.info.CIDRs, CanRouteAll: h.info.SetRouteAll != nil,
		GatewayCommand: h.gatewayCommand(),
	}
	if h.info.RouteAll != nil {
		st.RouteAll = h.info.RouteAll()
	}
	st.ExitLabel = h.exitLabel()
	st.Console = h.console(now)

	groups := map[string]*Group{}
	var routedBytes int64
	for _, host := range h.track.Snapshot() {
		domain, source, routed := h.routes.MatchDomain(host.Name)
		site := rules.Group(host.Name)
		key := site
		if routed {
			// Keep routed and unrouted names of one site apart.
			key = "r:" + domain
		}
		g := groups[key]
		if g == nil {
			g = &Group{Name: site, RouteDomain: site}
			if routed {
				g.Routed = true
				g.Name, g.RouteDomain = domain, domain
				g.Source, g.SourceLabel = source, sourceLabel(source)
				g.Removable = source == rules.SourceAdded
			}
			g.Label = friendlySite(rules.Group(g.Name))
			groups[key] = g
		}
		problem := h.friendlyError(host.LastError, host.Failures, host.Conns)
		bytes := host.BytesUp + host.BytesDown
		g.Hosts = append(g.Hosts, Name{
			Name: host.Name, Lookups: host.Lookups, Conns: host.Conns, Open: host.Active,
			Data: humanBytes(bytes), LastSeen: ago(now, host.LastSeen), Problem: problem, Addrs: host.Addrs,
		})
		g.Lookups += host.Lookups
		g.Conns += host.Conns
		g.Open += host.Active
		g.bytes += bytes
		if host.LastSeen.After(g.lastSeen) {
			g.lastSeen = host.LastSeen
		}
		if problem != "" && g.Problem == "" {
			g.Problem = problem
		}
		if routed {
			routedBytes += bytes
			st.Totals.Open += host.Active
		}
	}
	st.Routed, st.Other = []Group{}, []Group{}
	for _, g := range groups {
		g.Data = humanBytes(g.bytes)
		g.LastSeen = ago(now, g.lastSeen)
		if g.Routed {
			st.Routed = append(st.Routed, *g)
		} else {
			st.Other = append(st.Other, *g)
		}
	}
	sortGroups(st.Routed)
	sortGroups(st.Other)
	st.Totals.RoutedSites = len(st.Routed)
	st.Totals.Data = humanBytes(routedBytes)
	if h.info.RoutedAddrs != nil {
		st.Totals.Addresses = h.info.RoutedAddrs()
	}
	st.Domains = []Rule{}
	for _, d := range h.routes.Domains() {
		st.Domains = append(st.Domains, Rule{Domain: d.Name, SourceLabel: sourceLabel(d.Source), Removable: d.Source == rules.SourceAdded})
	}
	return st
}

// MonitorState is the connection monitor's card, polled every second apart
// from State so the rest of the page isn't redrawn.
type MonitorState struct {
	// Available is false in relay mode, where the console's packets don't
	// pass through this machine.
	Available bool `json:"available"`
	monitor.View
}

func (h *Handler) monitorState() MonitorState {
	if h.info.Monitor == nil {
		return MonitorState{View: monitor.View{Conns: []monitor.Conn{}}}
	}
	return MonitorState{Available: true, View: h.info.Monitor.Snapshot(h.console(h.now()).IP)}
}

func sortGroups(gs []Group) {
	sort.Slice(gs, func(i, j int) bool {
		if (gs[i].Open > 0) != (gs[j].Open > 0) {
			return gs[i].Open > 0
		}
		if !gs[i].lastSeen.Equal(gs[j].lastSeen) {
			return gs[i].lastSeen.After(gs[j].lastSeen)
		}
		return gs[i].Name < gs[j].Name
	})
	for i := range gs {
		hs := gs[i].Hosts
		sort.Slice(hs, func(a, b int) bool { return hs[a].Name < hs[b].Name })
	}
}

// console finds the most recent DNS client that isn't this machine.
func (h *Handler) console(now time.Time) Console {
	var c Console
	var at time.Time
	for ip, seen := range h.track.Clients() {
		if ip == h.info.ConsoleIP {
			continue
		}
		if p := net.ParseIP(ip); p == nil || p.IsLoopback() {
			continue
		}
		if seen.After(at) {
			c.IP, at = ip, seen
		}
	}
	if c.IP == "" {
		return Console{}
	}
	c.Seen = true
	c.Connected = now.Sub(at) < ConnectedWithin
	c.LastSeen = ago(now, at)
	return c
}

func (h *Handler) exitLabel() string {
	if h.info.Mode == "gateway" {
		if h.info.RouteAll != nil && h.info.RouteAll() {
			return "VPN tunnel " + h.info.Tunnel + ", all traffic"
		}
		return "VPN tunnel " + h.info.Tunnel
	}
	if h.info.Exit == "direct" || h.info.Exit == "" {
		return "This computer's connection"
	}
	if i := strings.Index(h.info.Exit, "://"); i >= 0 {
		scheme := strings.ToUpper(strings.TrimSuffix(h.info.Exit[:i], "h"))
		host := h.info.Exit[i+3:]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:] // never show credentials
		}
		return "VPN app, " + scheme + " " + host
	}
	return h.info.Exit
}

func sourceLabel(src string) string {
	switch src {
	case "":
		return ""
	case rules.SourceAdded:
		return "Added by you"
	case rules.SourceConfig:
		return "From your config"
	case "ea":
		return "EA games"
	case "activision":
		return "Activision games"
	}
	return strings.ToUpper(src[:1]) + src[1:] + " games"
}

// friendlySite names well-known sites so people recognise them.
func friendlySite(site string) string {
	switch site {
	case "playstation.net", "playstation.com", "sonyentertainmentnetwork.com", "sony.com", "scea.com":
		return "PlayStation Network"
	case "ea.com", "origin.com", "easports.com":
		return "EA"
	case "activision.com", "callofduty.com", "demonware.net":
		return "Activision / Call of Duty"
	case "akamaihd.net", "akamaized.net", "akamai.net", "cloudfront.net", "fastly.net", "cloudflare.net":
		return "Content delivery network"
	case "amazonaws.com":
		return "Amazon Web Services"
	case "googleapis.com", "google.com", "gstatic.com":
		return "Google"
	}
	return ""
}

// friendlyError turns a relay error into something a player can act on.
func (h *Handler) friendlyError(raw string, failures, conns int) string {
	if raw == "" || failures == 0 {
		return ""
	}
	e := strings.ToLower(raw)
	via := "the VPN app"
	if h.info.Exit == "direct" || h.info.Exit == "" {
		via = "this computer's connection"
	}
	var msg string
	switch {
	case strings.Contains(e, "connection refused") && strings.HasPrefix(e, "dial") && via == "the VPN app":
		msg = "Can't reach the VPN app's proxy. Is the VPN app running with its local proxy switched on?"
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		msg = "Timed out reaching the game's server through " + via + "."
	case strings.Contains(e, "no such host") || strings.Contains(e, "server misbehaving"):
		msg = "The server's name couldn't be looked up. Check the upstream DNS servers."
	case strings.Contains(e, "connection reset"), strings.Contains(e, "broken pipe"):
		msg = "The connection was cut part-way through."
	case strings.Contains(e, "network is unreachable"), strings.Contains(e, "no route"):
		msg = "No route to the internet through " + via + "."
	default:
		msg = "Couldn't connect: " + raw
	}
	if conns > failures {
		msg = fmt.Sprintf("%d of %d connections failed. %s", failures, conns, msg)
	}
	return msg
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d sec ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	default:
		return t.Format("02/01 15:04")
	}
}
