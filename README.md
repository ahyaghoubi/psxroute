# psxroute

Send chosen games' online traffic out through another route, such as a VPN,
without putting the whole console on it.

`psxroute` runs on a PC on your home network and becomes the console's DNS
server. When a game looks up one of the routed domains (EA's or
Activision's, say), psxroute answers with the PC's own address. The game then
connects to the PC, and psxroute forwards the still-encrypted connection
through your chosen exit. Everything else (PSN, the Store, game downloads)
goes direct, at full speed.

```
 console ──DNS──► psxroute ──► upstream DNS              (everything not routed)
    │                │
    │   routed name? └─ answer: "this PC"
    │
    └──HTTPS/HTTP──► psxroute ──exit──► game's servers   (routed names only)
                       reads the host name, never decrypts
```

It's built for 403 errors that come from a game's online services refusing
your IP's region. It has two modes:

| | Relay mode (default) | Gateway mode |
| --- | --- | --- |
| Console setting | DNS only | Gateway and DNS |
| Carries | HTTPS and HTTP to routed names | All traffic to routed names' addresses, UDP included, plus fixed ranges, or everything |
| Exit | VPN client's SOCKS5/HTTP port, or the PC's own route | The VPN's tunnel interface (`utun…`) |
| Runs on | macOS, Windows, Linux, no admin rights | macOS, with `sudo` |
| NAT type on the console | Unchanged | Usually Strict |

Start with relay mode. Use gateway mode when a game still fails with its names
routed.

Sister project of [psxdownloadhelper](https://github.com/ahyaghoubi/psxdownloadhelper).

---

## Quick start

1. **Pick an exit.** Run your VPN client on the PC and do one of these:
   - turn on its local proxy (v2rayN, Nekoray, Clash and similar offer a
     SOCKS5 or HTTP port) and run with `--exit socks5://127.0.0.1:10808`, or
   - put the PC on a full-tunnel VPN and keep the default `--exit direct`.
2. **Run psxroute**: `psxroute --exit socks5://127.0.0.1:10808`. It prints the
   address to give the console.
3. **On the PS5:** Settings › Network › Settings › Set Up Internet
   Connection › your network › Advanced Settings › DNS Settings: Manual.
   Set **Primary and Secondary DNS** to the PC's address.
4. **Play the game.** Open the dashboard at `http://<PC address>:8053/`, on
   the PC or your phone.

## The dashboard

- **Set up your PS5:** the exact menu steps, with every value ready to copy.
  It folds away once the console connects.
- **Status:** whether the PS5 is connected, how many services are going
  through the VPN, open connections and data used.
- **Connection monitor** (gateway mode): ping, jitter and packet loss on
  the PS5's own connections, a one-minute graph, and every connection with
  whether it goes through the VPN. It only reads the headers of packets the
  Mac is already forwarding and never sends anything itself.
  - *Ping* comes from TCP connections: the time between the PS5's packet
    passing the Mac and the server's reply, plus the home network leg.
  - *Match traffic* is UDP, which has no replies to time, so it shows jitter
    (how unevenly the server's packets arrive) and loss estimated from gaps
    in its steady stream.
  - Relay mode can't show it: the PS5's traffic doesn't pass through the PC.
- **What goes through your VPN:** *Game services only* (recommended) or
  *Everything*. Everything needs gateway mode, and is the quickest way to test
  whether a full VPN fixes a game. It lasts until psxroute restarts; set
  `gateway.route_all` to make it the default.
- **Everything else:** every other site the PS5 looked up, grouped by site,
  with a **Route** button. Routes you add take effect straight away (restart
  the game so it looks the name up again) and are saved in `routes.txt` next
  to the config file.
- **Routing rules:** everything that's routed, with a box to add a domain
  by hand and **Remove** for the ones you added.
- Problems are shown in plain words, for example "Can't reach the VPN app's
  proxy. Is the VPN app running with its local proxy switched on?"

Set the console's DNS back to Automatic when the PC is off, or it loses
internet.

---

## Gateway mode (macOS)

The Mac becomes the console's router. Routed addresses get routes through
the VPN's tunnel; everything else follows the Mac's own default route, and pf
NATs both. A routed name's addresses are added the moment the console looks
it up, before the answer reaches it.

Use a **split tunnel** VPN on the Mac. With a full tunnel the Mac's default
route is the VPN, so all the console's traffic goes through it anyway.

1. **Connect your VPN** in a mode that creates a tunnel interface (WireGuard,
   OpenVPN, IKEv2, or a v2ray-style client's TUN mode). Split tunnel or full
   tunnel both work.
2. **Run it:** `sudo psxroute --mode gateway`. It finds the tunnel
   (`gateway.tunnel: utun4` if there's more than one) and prints the console
   settings.
3. **On the PS5:** Settings › Network › Settings › Set Up Internet
   Connection › your network › Advanced Settings:
   - **IP Address Settings:** Manual. Use an unused address on your network,
     the subnet mask shown, and the Mac's address as **Default Gateway**.
   - **DNS Settings:** Manual, Primary and Secondary set to the Mac's
     address.
4. **Stop with Ctrl+C.** The routes and rules are removed and IP forwarding
   is put back.
   Set the console back to Automatic.

Options:

```yaml
mode: gateway
gateway:
  tunnel: auto          # or utun4
  route_all: false      # true: every console connection goes through the tunnel
  cidrs:                # ranges always routed (servers reached by IP)
    - 203.0.113.0/24
```

`route_all: true`, or **Everything** on the dashboard, is the quick way to
answer "would a full VPN fix this game?".

`route_all` routes the Mac's own traffic through the tunnel too, while it's
on.

If psxroute is killed before it can clean up (a crash, `kill -9`, a power
cut), run `sudo psxroute cleanup`. A restart also clears it: macOS doesn't
keep the routes or rules.

---

## Find out what's blocked first

Before relying on psxroute for a game, check which layer refuses you:

1. **Run psxroute** with the default packs and play. If the 403 goes away,
   you're done.
2. **Still a 403?** Watch the dashboard while you reproduce it. Names that
   aren't green aren't routed: add the likely ones (the publisher's domains)
   to `hosts:` in the config and try again.
3. **Still a 403 with the names routed?** The game also checks traffic relay
   mode can't carry (UDP, or servers addressed by IP). Switch to gateway mode
   with the same names. Still failing? Try `route_all: true`: if that works,
   the game reaches servers by IP, so watch the dashboard's addresses and add
   their ranges to `gateway.cidrs`.
4. **Nothing works?** It's an account or region check, not the network.

---

## Configuration

`~/.config/psxroute/config.yaml` (or `--config FILE`). Every key is optional:

```yaml
mode: relay                        # relay | gateway (see above)
exit: socks5://127.0.0.1:10808     # direct | socks5://[user:pass@]host:port | http://[user:pass@]host:port
packs: [ea, activision]            # built-in domain lists: run `psxroute packs`
hosts:                             # extra domains; each covers its subdomains
  - example-publisher.com
upstream_dns: [1.1.1.1, 8.8.8.8]   # answers everything that isn't routed
advertise_ip: ""                   # this PC's LAN address; empty = automatic
listen:
  dns: 0.0.0.0:53
  https: 0.0.0.0:443
  http: 0.0.0.0:80
  dashboard: 0.0.0.0:8053
log:
  level: info                      # debug shows every routed lookup and connection
```

Flags override the file: `--mode`, `--exit`, `--advertise`, `--log-level`,
`--config`.

- **SOCKS5 exits resolve names at the far end**, so a poisoned local DNS
  doesn't matter for routed names.
- **Direct exits resolve routed names with `upstream_dns`**, never with the
  PC's own resolver, so they can't loop back into psxroute.
- **The relay only forwards routed names.** Anything else that connects is
  dropped, so psxroute isn't an open proxy on your network.

---

## Good to know

- **Ports 53, 80 and 443.** macOS and Windows let a normal user listen on
  them. On Linux, run
  `sudo setcap cap_net_bind_service=+ep ./psxroute` once. If another program
  already uses a port (a local DNS server, a web server), psxroute says
  which.
- **Several network adapters?** If the printed address isn't the one on the
  console's network, pass `--advertise 192.168.1.20`.
- **Routed names get no IPv6 answer**, so the console can't bypass the relay
  over IPv6.
- **The PC must stay on and awake** while you play.
- **Publishers' terms** can prohibit VPNs or region workarounds, and
  anti-cheat systems may flag VPN addresses. A private VPS address is lower
  risk than a shared commercial one, but not risk-free.

## What it can't do

- **Relay mode carries TCP only.** UDP gameplay traffic (matches, voice)
  needs gateway mode.
- **Servers reached by IP address** never touch DNS. In gateway mode, list
  their ranges in `gateway.cidrs` or use `route_all`.
- **Gateway mode is macOS only** for now. Linux and Windows are on the
  [roadmap](docs/roadmap.md).
- **IPv6 isn't routed.** Routed names get no IPv6 answer, so the console uses
  IPv4 for them.
- **Certificate pinning isn't a problem**: psxroute never decrypts, so the
  game still talks TLS to the real server.

---

## Development

Needs Go (the version in `go.mod`). Run `make` to list commands:

```bash
make run ARGS="--exit socks5://127.0.0.1:10808"
make test     # unit tests plus end-to-end tests on loopback
make check    # formatting, vet and tests, as CI runs them
make dist     # binaries for every OS/arch in ./dist
```

Design notes: [docs/architecture.md](docs/architecture.md). Decisions:
[docs/decisions/](docs/decisions/).

## Licence

MIT. See [LICENSE](LICENSE).
