# Architecture

One binary, no state on disk. Relay mode is described first; gateway mode
reuses the DNS server and dashboard and replaces the relay with pf rules.

```
                 ┌───────────────────────── psxroute ─────────────────────────┐
 console ──53──► │ dnsserver ── routed? ──yes──► A = advertise_ip, AAAA = empty │
                 │     │                                                       │
                 │     └─no──► upstream_dns (UDP, TCP for truncated replies)  │
                 │                                                             │
 console ─443──► │ relay (TLS)  ── sni.PeekTLS ──┐                             │
 console ──80──► │ relay (HTTP) ── sni.PeekHTTP ─┴─ routed? ─yes─► exit ──────►│──► game servers
                 │                                     └─no─► drop             │
 browser ─8053─► │ dashboard ◄── learn.Tracker ◄── lookups and connections     │
                 └─────────────────────────────────────────────────────────────┘
```

## Packages

| Package | Job |
| --- | --- |
| `internal/config` | YAML over defaults, `Finalise` validates. |
| `internal/rules` | Embedded packs plus `hosts:`; suffix match on label boundaries. |
| `internal/dnsserver` | Parses only the question; routed names answered locally, the rest forwarded byte for byte. |
| `internal/sni` | Peeks the ClientHello `server_name` (across TLS records) or the HTTP `Host` without consuming bytes. |
| `internal/relay` | Accept, peek, check the rules, dial the exit, splice with half-close. |
| `internal/exit` | `direct` (own resolver on `upstream_dns`), SOCKS5 (`golang.org/x/net/proxy`), HTTP CONNECT. |
| `internal/learn` | In-memory record of names, lookups, connections, bytes and errors. Capped at 5,000 names. |
| `internal/dashboard` | One embedded page (vanilla JS) polling `/api/state` every 2 s; `POST /api/route`, `/api/unroute`, `/api/route-all`, `/api/clear` (JSON only, so other sites can't trigger them with a form); `hosts.txt` and `hosts.json` exports. |
| `internal/gateway` | Gateway mode: finds the LAN and tunnel, renders and loads the pf anchor, adds addresses to its table, undoes everything on close. |
| `internal/app` | Wires the listeners; tests start it on loopback ports. |

## Design rules

- **Never decrypt.** Bytes after the peek are forwarded unchanged. No
  certificates, no MITM.
- **Not an open proxy.** The relay drops any name the rules don't route.
- **Routed names get only A records.** AAAA and HTTPS/SVCB queries for them
  get an empty answer, so the console can't reach the real server around the
  relay.
- **No loops.** Direct exits resolve with `upstream_dns`, never the system
  resolver.
- **Short TTL (30 s)** on routed answers, so rule changes take effect
  quickly.

## Gateway mode (macOS)

```
 console ──(gateway = Mac)──► en0 ── kernel forwarding, routing table
                                     │
                                     ├─ host route via utunN (routed) ─► NAT on utunN ─► VPN
                                     └─ the Mac's default route ──────► NAT on en0  ─► ISP
 console ──DNS──► dnsserver: routed A query → real answer → host routes added → reply
```

- **No pf `route-to`**: it panics the macOS 27 kernel on the first forwarded
  packet (see [ADR 0003](decisions/0003-routes-not-route-to.md)). pf only
  clamps MSS and NATs.
- **The anchor sits under `com.apple/*`**, which the stock `/etc/pf.conf`
  already evaluates, so the system ruleset is never touched.
- **Routes are added before the DNS reply goes back**, so the console's
  first packet to a routed name already takes the tunnel. `route_all` adds
  `0.0.0.0/1` and `128.0.0.0/1` through the tunnel.
- **Traffic that isn't routed follows the Mac's default route**: the router
  with a split tunnel VPN, the tunnel with a full one.
- **`pfctl -E` / `-X token`** enables pf by reference, so psxroute doesn't
  switch pf off under another program that needs it.
- **TCP MSS is clamped** to the tunnel's MTU minus 40.
- **ICMP redirects are switched off** while running, so the console isn't
  told to bypass the Mac.
- **Undo** removes the routes psxroute added (never ones that were already
  there), flushes the anchor, releases the pf reference and restores the
  sysctls it changed. The added routes are listed in
  `/var/run/psxroute.routes`, so `psxroute cleanup` can do the same after a
  crash.
- The generated rules are checked against macOS's own parser in the tests
  (`pfctl -n`, no root needed).
