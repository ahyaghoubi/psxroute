# ADR 0003: Gateway mode routes with the routing table, not pf route-to

- Status: Accepted
- Date: 14/11/2026
- Deciders: project owner
- Supersedes: the "Route with pf" part of [ADR 0002](0002-gateway-mode-on-macos.md)

## Context

With ADR 0002's rules loaded, macOS 27.2.1 (Mac17,9) kernel panicked the
moment the console sent its first packet through the Mac: `Bounds safety
trap` in `kernel_task`, with only Apple kernel frames in the backtrace. It
happened twice in a row, five minutes apart, with identical registers. Both
`pass in … route-to` rules were candidates: one into the VPN's `utun`, one
back out of `en0` to the router. pf's `route-to` is a rarely used path on
macOS, and a user space rule shouldn't be able to panic the kernel, so this
is an Apple bug (reported through Feedback Assistant). We still have to stop
triggering it.

## Decision

- **No `route-to`.** pf only clamps MSS and NATs (`nat on utunN`,
  `nat on en0`). The kernel forwards with `net.inet.ip.forwarding=1` and
  picks the interface from the routing table, the same path Internet Sharing
  uses.
- **Routed addresses become host routes** through the tunnel
  (`route add -host X -interface utunN`), added before the DNS answer is
  returned, as the table entries were. Fixed `cidrs` become network routes.
- **`route_all` adds `0.0.0.0/1` and `128.0.0.0/1`** through the tunnel, the
  way VPN clients take over all traffic without replacing the default route.
- **Only routes psxroute added are removed.** A route that already exists
  (`File exists`) is left alone. The ones it added are listed in
  `/var/run/psxroute.routes` so `psxroute cleanup` can remove them after a
  crash; `/var/run` empties at reboot, as the routes do.

## Consequences

- Everything not routed follows the Mac's own default route. With a full
  tunnel VPN that's the tunnel, so the console's other traffic goes through
  it too; psxroute warns at start. Use a split tunnel to keep the rest direct.
  ADR 0002's "works whether full or split tunnel" no longer holds.
- Routes apply to the Mac's own traffic too: the Mac reaches routed
  addresses through the VPN. Harmless here.
- `route_all` also moves the Mac's own traffic onto the tunnel. VPN clients
  built on Network Extension bind their own sockets to the physical
  interface, so this doesn't loop; a client that doesn't, with no host route
  to its server, could lose its connection while `route_all` is on.
- One `route` command per new address instead of one `pfctl` call per DNS
  answer. Answers carry a handful of addresses, so this stays well under the
  DNS timeout.
