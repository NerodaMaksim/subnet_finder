# Subnet Scanner

A small macOS desktop app that scans your local subnets for active devices and
resolves their hostnames. Go backend, embedded web UI, native window.

![status](https://img.shields.io/badge/platform-macOS-blue)

## What it does

Pick one or more of the IPv4 subnets your machine is attached to, hit scan, and
get a live table of everything that answers:

| IP | Hostname | Method | Open ports |
|---|---|---|---|
| 192.168.1.42 | workshop-pi.local | both | 22, 80 |

Hosts are detected by ICMP ping and by TCP connects to a set of common ports
(22, 80, 443, 445, 3389, 8080, 548, 5900), run concurrently. Results stream to
the UI over Server-Sent Events as they are found.

## Hostname resolution

Most scanners do a single reverse-DNS `PTR` lookup, which on a home network
just reads the router's DHCP lease table. That fails in two common cases:

- **Two devices with the same hostname.** The router registers the first lease
  and refuses the second, so only one of them ever gets a name.
- **A VPN is connected.** The tunnel installs its own resolver as the system
  default, so `PTR` queries for LAN addresses go to a DNS server that has never
  heard of your LAN, and every hostname comes back empty.

This app queries three sources concurrently and keeps the best answer:

| Source | Method | Why it helps |
|---|---|---|
| `mdns` | Reverse `PTR` sent straight to the multicast group `224.0.0.251:5353` | The device answers for *itself*. No DNS server involved, so it survives a VPN, and Bonjour's automatic rename keeps duplicate hostnames distinct. |
| `dns` | Unicast `PTR` to the resolver **scoped to the target's interface** | Asks the network's own DNS server rather than whatever the system default happens to be, so a VPN can't hijack it. |
| `netbios` | Node-status query to UDP 137 | Catches Windows machines that publish neither mDNS nor a DHCP hostname. |

mDNS wins ties because the answer comes from the device itself. Both UDP
queries retransmit within their budget, since a single dropped multicast packet
would otherwise silently lose a name. Lookups run off the probe path in their
own worker pool, so a slow resolver never holds up the scan: hosts appear the
moment they answer, and names fill in as they arrive. Results are cached for 5
minutes (1 minute for misses, so a host that was merely quiet gets re-asked).

Hover a hostname in the UI to see which source produced it.

## Build

Requires Go and Xcode command line tools (the native window uses cgo).

```sh
make build      # build the binary into bin/
make app        # build a Subnet Scanner.app into ~/Applications
make install    # build the app and add a `subnet_scaner` launcher to ~/.local/bin
make uninstall
```

## Caveats

- macOS only. The per-interface resolver table is read from `scutil --dns`;
  other platforms fall back to `/etc/resolv.conf`.
- IPv4 only.
- A device that runs no mDNS responder and answers no NetBIOS query can only be
  named by the router's lease table. If two such devices share a hostname, one
  of them will still show no name — install `avahi-daemon` on Linux hosts to
  fix this properly.
- Scanning a subnet larger than a `/22` will take a while; the UI warns you.
