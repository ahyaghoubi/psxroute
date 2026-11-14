// Package learn records which host names the console looked up and what
// happened to the connections psxroute relayed, so you can see what a game
// talks to and decide what to route.
package learn

import (
	"sort"
	"sync"
	"time"
)

// MaxHosts caps how many names are remembered; the least recently seen are
// dropped first.
const MaxHosts = 5000

// Host is everything known about one name.
type Host struct {
	Name     string    `json:"name"`
	Routed   bool      `json:"routed"`
	Source   string    `json:"source,omitempty"` // pack or "config" when routed
	Lookups  int       `json:"lookups"`
	LastSeen time.Time `json:"last_seen"`
	Clients  []string  `json:"clients"`
	Addrs    []string  `json:"addrs,omitempty"` // gateway mode: addresses routed for this name

	Conns     int    `json:"conns"`
	Active    int    `json:"active"`
	Failures  int    `json:"failures"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	LastError string `json:"last_error,omitempty"`
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu      sync.Mutex
	hosts   map[string]*Host
	clients map[string]time.Time // DNS client → last query
	now     func() time.Time
}

// New returns an empty Tracker.
func New() *Tracker {
	return &Tracker{hosts: map[string]*Host{}, clients: map[string]time.Time{}, now: time.Now}
}

func (t *Tracker) get(name string) *Host {
	h, ok := t.hosts[name]
	if !ok {
		if len(t.hosts) >= MaxHosts {
			t.evictOldest()
		}
		h = &Host{Name: name}
		t.hosts[name] = h
	}
	h.LastSeen = t.now()
	return h
}

func (t *Tracker) evictOldest() {
	var oldest string
	var at time.Time
	for n, h := range t.hosts {
		if oldest == "" || h.LastSeen.Before(at) {
			oldest, at = n, h.LastSeen
		}
	}
	delete(t.hosts, oldest)
}

// Lookup records a DNS query.
func (t *Tracker) Lookup(name, client string, routed bool, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.get(name)
	if len(t.clients) < 256 {
		t.clients[client] = h.LastSeen
	} else if _, ok := t.clients[client]; ok {
		t.clients[client] = h.LastSeen
	}
	h.Lookups++
	h.Routed = routed
	h.Source = source
	for _, c := range h.Clients {
		if c == client {
			return
		}
	}
	if len(h.Clients) < 16 {
		h.Clients = append(h.Clients, client)
	}
}

// Resolved records addresses gateway mode routed for a name.
func (t *Tracker) Resolved(name string, ips []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.get(name)
	for _, ip := range ips {
		known := false
		for _, a := range h.Addrs {
			if a == ip {
				known = true
				break
			}
		}
		if !known && len(h.Addrs) < 32 {
			h.Addrs = append(h.Addrs, ip)
		}
	}
}

// Open records a relayed connection starting. Only routed names are
// relayed, so it also marks the name routed, even if the console never
// looked it up through psxroute (a cached answer, for example).
func (t *Tracker) Open(name, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.get(name)
	h.Routed, h.Source = true, source
	h.Conns++
	h.Active++
}

// Conn records a relayed connection that Open started finishing.
func (t *Tracker) Conn(name string, up, down int64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.get(name)
	if h.Active > 0 {
		h.Active--
	}
	h.BytesUp += up
	h.BytesDown += down
	if err != nil {
		h.Failures++
		h.LastError = err.Error()
	}
}

// Snapshot returns copies of every host, most recently seen first.
func (t *Tracker) Snapshot() []Host {
	t.mu.Lock()
	out := make([]Host, 0, len(t.hosts))
	for _, h := range t.hosts {
		c := *h
		c.Clients = append([]string(nil), h.Clients...)
		c.Addrs = append([]string(nil), h.Addrs...)
		out = append(out, c)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Clients returns every DNS client seen and when it last asked something.
func (t *Tracker) Clients() map[string]time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]time.Time, len(t.clients))
	for c, at := range t.clients {
		out[c] = at
	}
	return out
}

// Clear forgets the names seen. Clients are kept, so the console still
// shows as connected.
func (t *Tracker) Clear() {
	t.mu.Lock()
	t.hosts = map[string]*Host{}
	t.mu.Unlock()
}
