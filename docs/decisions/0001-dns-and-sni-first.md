# ADR 0001: DNS and SNI relay first, full gateway later

- Status: Accepted
- Date: 13/11/2026
- Deciders: project owner

## Context

Online features in some games (EA SPORTS FC, Battlefield, Call of Duty)
return 403 from regions their publishers block. psxdownloadhelper can't help:
games ignore the console's proxy setting, so their traffic never reaches it.

There are two ways to change the route a console's game traffic takes:

1. **DNS plus SNI relay.** Be the console's DNS server, answer chosen names
   with this machine's address, and forward their TCP connections by host
   name. Works on any OS without root (except low ports on Linux), needs no
   VPN on the console, and leaves downloads direct.
2. **Full gateway.** Be the console's default gateway and route chosen IP
   ranges through a tunnel (WireGuard or TUN). Covers UDP and IP-addressed
   traffic, but needs root, platform-specific routing and NAT code, and
   usually gives Strict NAT.

Region blocks are usually enforced by HTTPS services reached by name, which
option 1 covers.

## Decision

Build option 1 first, with a learning dashboard that shows every name the
console looks up, so host lists come from observation rather than guesswork.
Build option 2 only if real tests show games that option 1 can't fix.

## Dependencies

- `gopkg.in/yaml.v3`: config, same as psxdownloadhelper.
- `golang.org/x/net`: `dns/dnsmessage` for DNS wire format and `proxy` for
  SOCKS5. Go-team maintained, BSD-3-Clause.

Anything else needs its own ADR.

## Consequences

- One binary; four listeners (DNS, 443, 80, dashboard).
- UDP gameplay and IP-addressed servers aren't covered until option 2.
- The built-in packs are unverified starting points until checked on a
  console.
