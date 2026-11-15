# ADR 0004: Gateway mode on Windows with the IP Helper API and WinNAT

- Status: Accepted, not yet tried on real hardware
- Date: 15/11/2026
- Deciders: project owner
- Builds on: [ADR 0002](0002-gateway-mode-on-macos.md),
  [ADR 0003](0003-routes-not-route-to.md)

## Context

Relay mode already runs on Windows. Gateway mode, which games that check UDP
or reach servers by IP need, was macOS only. The owner asked for Windows
support. ADR 0003's design (host routes through the VPN's own tunnel,
forwarding on, NAT only) carries over; Windows needs its own way to add
routes, forward and NAT.

## Decision

- **Split the gateway into shared logic and a `System` per OS.** The macOS
  System is the existing pf code, unchanged in behaviour.
- **Routes through the IP Helper API** (`CreateIpForwardEntry2`,
  `DeleteIpForwardEntry2`, via `golang.org/x/sys/windows`). A route is added
  for every new address in a DNS answer, before the answer goes back, so
  spawning `route.exe` or `netsh` each time would add latency. The API also
  returns error codes, where the commands' messages are localised.
- **Forwarding with `netsh interface ipv4 set interface … store=active`**, on
  the LAN and tunnel interfaces, only where it was off. Active store means a
  reboot puts it back.
- **NAT with WinNAT** (`New-NetNat`), its internal prefix set to the LAN.
  Internet Connection Sharing was ruled out: it readdresses the shared
  adapter to 192.168.137.1. A user-space NAT (WinDivert) would need a
  third-party kernel driver.
- **Find the tunnel by adapter type and description**, since Windows adapter
  names are free text: PPP, tunnel and proprietary virtual types (Wintun),
  and descriptions naming Wintun, WireGuard, TAP-Windows, OpenVPN, "VPN" or
  "tunnel". `gateway.tunnel` takes the adapter's name when that isn't enough.
- **State as JSON in `%ProgramData%\psxroute\gateway.json`**: routes with
  their interface and next hop, the interfaces whose forwarding was switched
  on, and whether the NAT exists, so `psxroute cleanup` can undo a crashed
  run.

Adds `golang.org/x/sys` as a direct dependency; it was already indirect
through `golang.org/x/net`.

## Consequences

- Needs an Administrator terminal and WinNAT. Windows editions or setups
  without WinNAT, or with another program's WinNAT, can't use gateway mode;
  psxroute stops with an explanation and changes nothing.
- No TCP MSS clamping, unlike pf. Path MTU Discovery has to work through
  the tunnel; real use will show whether it does.
- The connection monitor stays macOS only: Windows has no BPF, and capture
  would need Npcap or raw sockets.
- Untested end to end. Unit tests cover the logic with a fake IP Helper and
  runner; a Windows-only test adds and removes a real route on CI's elevated
  runner. WinNAT's behaviour with a physical LAN as its internal network is
  the main unknown.
