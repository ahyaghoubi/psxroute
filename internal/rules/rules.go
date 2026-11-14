// Package rules decides which host names psxroute routes. A rule is a domain
// name that also covers its subdomains.
package rules

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed packs/*.yaml
var packFS embed.FS

// Pack is a named list of domains, usually one publisher's.
type Pack struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Hosts       []string `yaml:"hosts"`
}

// Packs returns the built-in packs, sorted by name.
func Packs() ([]Pack, error) {
	entries, err := packFS.ReadDir("packs")
	if err != nil {
		return nil, err
	}
	var out []Pack
	for _, e := range entries {
		data, err := packFS.ReadFile("packs/" + e.Name())
		if err != nil {
			return nil, err
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("pack %s: %w", e.Name(), err)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Sources other than pack names.
const (
	SourceConfig = "config" // hosts: in the config file
	SourceAdded  = "added"  // added from the dashboard
)

// Set matches host names against domains. It is safe for concurrent use,
// and a nil Set matches nothing.
type Set struct {
	mu sync.RWMutex
	// domains maps a normalised domain to the source it came from: a pack
	// name, SourceConfig or SourceAdded.
	domains map[string]string
}

// Build makes a Set from the named built-in packs plus extra domains.
func Build(packNames, extra []string) (*Set, error) {
	all, err := Packs()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]Pack, len(all))
	for _, p := range all {
		byName[p.Name] = p
	}
	s := &Set{domains: map[string]string{}}
	for _, name := range packNames {
		p, ok := byName[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("unknown pack %q (built-in packs: %s)", name, strings.Join(names(all), ", "))
		}
		for _, h := range p.Hosts {
			s.add(h, p.Name)
		}
	}
	for _, h := range extra {
		s.add(h, SourceConfig)
	}
	return s, nil
}

func names(ps []Pack) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func (s *Set) add(domain, source string) {
	d := Normalise(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
	if d == "" {
		return
	}
	if _, ok := s.domains[d]; !ok {
		s.domains[d] = source
	}
}

// Normalise lowercases a host name and drops a trailing dot.
func Normalise(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// Add routes domain (and its subdomains) from now on. It reports false when
// the domain was already routed.
func (s *Set) Add(domain, source string) (bool, error) {
	d := Normalise(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
	if err := ValidDomain(d); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.domains == nil {
		s.domains = map[string]string{}
	}
	if _, ok := s.domains[d]; ok {
		return false, nil
	}
	s.domains[d] = source
	return true, nil
}

// Remove stops routing domain if it came from source. It reports whether
// anything was removed.
func (s *Set) Remove(domain, source string) bool {
	d := Normalise(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.domains[d] != source {
		return false
	}
	delete(s.domains, d)
	return true
}

// Domain is one routed domain and where it came from.
type Domain struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Domains lists every routed domain, sorted by name.
func (s *Set) Domains() []Domain {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	out := make([]Domain, 0, len(s.domains))
	for d, src := range s.domains {
		out = append(out, Domain{Name: d, Source: src})
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ValidDomain accepts a DNS name with at least two labels.
func ValidDomain(d string) error {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return fmt.Errorf("%q isn't a domain name like example.com", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q isn't a domain name like example.com", d)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("%q isn't a domain name like example.com", d)
			}
		}
	}
	return nil
}

// twoLevel are common second-level registries, so "x.co.uk" groups under
// "x.co.uk" rather than "co.uk".
var twoLevel = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "com.au": true, "net.au": true,
	"co.jp": true, "ne.jp": true, "com.br": true, "com.cn": true, "com.tr": true,
	"co.kr": true, "com.mx": true, "co.in": true, "co.ir": true, "ac.ir": true,
}

// Group returns the site a host name belongs to, for display and as the
// suggested domain to route: "eaassets-a.akamaihd.net" → "akamaihd.net".
func Group(host string) string {
	h := Normalise(host)
	labels := strings.Split(h, ".")
	if len(labels) <= 2 {
		return h
	}
	last2 := strings.Join(labels[len(labels)-2:], ".")
	if twoLevel[last2] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return last2
}

// Match reports whether host is routed and which source routed it. It
// matches the domain itself and any subdomain, on label boundaries only:
// "ea.com" matches "x.ea.com" but not "tea.com".
func (s *Set) Match(host string) (source string, ok bool) {
	_, source, ok = s.MatchDomain(host)
	return source, ok
}

// MatchDomain is Match that also returns the routed domain that matched.
func (s *Set) MatchDomain(host string) (domain, source string, ok bool) {
	if s == nil {
		return "", "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.domains) == 0 {
		return "", "", false
	}
	h := Normalise(host)
	for h != "" {
		if src, ok := s.domains[h]; ok {
			return h, src, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return "", "", false
}

// Len is the number of distinct domains in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domains)
}
