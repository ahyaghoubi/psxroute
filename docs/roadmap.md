# Roadmap

## Now: validate on a real console

Nothing has been tested against a PS5 yet. Until it has, "works" means
"works against loopback tests and a real HTTPS site".

- [ ] PS5 accepts psxroute as DNS; PSN sign-in and Store still work.
- [ ] EA SPORTS FC: record the names looked up when the 403 appears; does
      routing them fix it?
- [ ] Battlefield: same.
- [ ] Call of Duty: same; check whether `demonware.net` is involved.
- [ ] Gateway mode on a real Mac with a real VPN: rules load, the console
      gets online, routed addresses leave by the tunnel (check with the
      VPN's exit IP), Ctrl+C restores everything.
- [ ] For any game still failing in relay mode, try gateway mode, then
      `route_all`, to see whether UDP or IP-addressed traffic is the blocker.
- [ ] Turn what's learnt into verified packs and remove "unverified" from
      their comments.

## Next, if needed

- **Gateway mode on Linux** (nftables or iptables with ipset), then Windows.
- **Built-in WireGuard** for gateway mode, so no separate VPN app is needed.
- **Remember what was learnt** across restarts.

## Not planned

- Decrypting or modifying game traffic.
- Being a general-purpose VPN or proxy for other devices.
