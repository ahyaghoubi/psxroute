# ADR 0002: Gateway mode on macOS through the VPN's own tunnel

- Status: Accepted; routing superseded by [ADR 0003](0003-routes-not-route-to.md)
- Date: 13/11/2026
- Deciders: project owner
- Builds on: [ADR 0001](0001-dns-and-sni-first.md)

## Context

Relay mode carries TCP to routed names only. Games that also check UDP
traffic, or reach servers by IP, need the console's packets routed, not
relayed. The owner asked for this mode before any console testing.

## Decision

- **Use the VPN's existing tunnel interface** (`utun…`) rather than building a
  tunnel into psxroute. Every VPN client on macOS already creates one;
  embedding WireGuard would add a userspace network stack and its
  dependencies, and tie users to one protocol.
- **Route with pf**, in an anchor under `com.apple/*`: `route-to` sends the
  console's packets for routed destinations to the tunnel and the rest to the
  router, so it works whether the VPN is full or split tunnel. Both are NATed.
- **Fill the routed table from DNS.** A routed name's A records are added
  before the answer is returned. Fixed `cidrs` and `route_all` cover servers
  reached by IP.
- **macOS first**: it's the owner's machine, and pf ships with it. Linux
  (nftables) and Windows follow if needed.
- **Leave no trace**: undo on exit, `psxroute cleanup` after a crash, and
  nothing persists across a reboot.

No new dependencies: pfctl, sysctl, ifconfig and route are called as
commands.

## Consequences

- Needs `sudo`, and the console needs a manual IP and gateway.
- Consoles usually report Strict NAT behind the tunnel.
- IPv4 only; routed names get no AAAA answer.
- Can't be tested end to end in CI. Rule text is checked with `pfctl -n`
  on macOS runners; behaviour needs a real Mac, VPN and console.
