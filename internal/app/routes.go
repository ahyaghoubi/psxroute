package app

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ahyaghoubi/psxroute/internal/gateway"
	"github.com/ahyaghoubi/psxroute/internal/learn"
	"github.com/ahyaghoubi/psxroute/internal/rules"
)

// routes is the dashboard's view of the rules: it adds and removes domains
// at runtime, remembers the added ones in a file, and keeps gateway mode's
// address table in step.
type routes struct {
	set   *rules.Set
	path  string // where added domains are saved; "" means not saved
	gw    *gateway.Gateway
	track *learn.Tracker
	log   *slog.Logger
	ctx   context.Context

	mu sync.Mutex // serialises saves
}

// loadAdded reads saved domains into the set. A missing file is fine.
func (r *routes) loadAdded() error {
	if r.path == "" {
		return nil
	}
	f, err := os.Open(r.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := r.set.Add(line, rules.SourceAdded); err != nil {
			r.log.Warn("skipping saved route", "domain", line, "err", err)
		}
	}
	return sc.Err()
}

func (r *routes) Domains() []rules.Domain { return r.set.Domains() }

func (r *routes) MatchDomain(host string) (string, string, bool) { return r.set.MatchDomain(host) }

func (r *routes) Add(domain string) error {
	ok, err := r.set.Add(domain, rules.SourceAdded)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	r.log.Info("routing domain", "domain", domain)
	return r.save()
}

func (r *routes) Remove(domain string) error {
	d := rules.Normalise(domain)
	if !r.set.Remove(d, rules.SourceAdded) {
		return fmt.Errorf("%s wasn't added from the dashboard, so it can't be removed here", d)
	}
	r.log.Info("stopped routing domain", "domain", d)
	if r.gw != nil {
		// Take back the addresses of names that are no longer routed.
		var ips []string
		for _, h := range r.track.Snapshot() {
			if _, still := r.set.Match(h.Name); !still {
				ips = append(ips, h.Addrs...)
			}
		}
		if err := r.gw.Remove(r.ctx, ips); err != nil {
			r.log.Warn("couldn't stop routing addresses", "err", err)
		}
	}
	return r.save()
}

func (r *routes) save() error {
	if r.path == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	b.WriteString("# Domains routed from the psxroute dashboard, one per line.\n")
	for _, d := range r.set.Domains() {
		if d.Source == rules.SourceAdded {
			b.WriteString(d.Name + "\n")
		}
	}
	dir := filepath.Dir(r.path)
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		chownToSudoUser(dir)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	chownToSudoUser(tmp)
	return os.Rename(tmp, r.path)
}

// chownToSudoUser gives a file back to the person who ran sudo, so gateway
// mode doesn't leave root-owned files in their config folder.
func chownToSudoUser(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || os.Geteuid() != 0 {
		return
	}
	_ = os.Chown(path, uid, gid)
}
