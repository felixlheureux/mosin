# mosin

System-wide ad blocker for Linux. Intercepts DNS queries via a TUN device and blocks ads, trackers, and malware at the network level. Prevents DNS-over-HTTPS (DoH) bypass.

## Features

- **DNS Sinkhole** — intercepts UDP/53 queries, returns NXDOMAIN for blocked domains
- **IP Blocking** — drops packets to blocked IPs/CIDRs via radix tree lookup
- **DoH Prevention** — blocks known DoH resolver IPs and detects DoH via TLS SNI extraction
- **Fast Fail** — blocked connections get TCP RST (instant fail, no timeout)
- **Standard Blocklist Formats** — supports hosts-file and domains-only formats

## Quick Start

```bash
# Build
cargo build

# Download blocklists
mkdir -p lists
curl -o lists/blocklist.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
curl -o lists/doh_ips.txt https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt
curl -o lists/doh_domains.txt https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt

# Run (requires root for TUN device)
sudo ./target/debug/mosin start --blocklist lists/blocklist.txt --block-doh --verbose
```

## Usage

```text
mosin start [OPTIONS]

Options:
  -b, --blocklist <FILE>       Domain blocklist (hosts-file or domains-only), repeatable
  -I, --ip-blocklist <FILE>    IP/CIDR blocklist, repeatable
      --block-doh              Block known DoH providers
      --doh-ips <FILE>         DoH IP list [default: lists/doh_ips.txt]
      --doh-domains <FILE>     DoH domain list [default: lists/doh_domains.txt]
  -v, --verbose                Verbose logging
  -q, --quiet                  Errors only
```

### Examples

```bash
# Multiple blocklists
sudo ./target/debug/mosin start \
  -b lists/blocklist.txt \
  -b lists/another_list.txt \
  -I lists/blocked_ips.txt \
  --block-doh \
  --verbose

# Minimal (just DNS blocking, no DoH)
sudo ./target/debug/mosin start -b lists/blocklist.txt
```

## Blocklists

### Domain Blocklists

| List         | Domains | Format       | URL                                                                          |
| ------------ | ------- | ------------ | ---------------------------------------------------------------------------- |
| Steven Black | ~79k    | hosts-file   | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`           |
| OISD Big     | ~200k   | domains-only | `https://big.oisd.nl/`                                                       |
| Hagezi Pro   | ~170k   | hosts-file   | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt` |

### DoH Blocklists

| List                         | URL                                                                                 |
| ---------------------------- | ----------------------------------------------------------------------------------- |
| DoH IPs (updated hourly)     | `https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt`    |
| DoH Domains (updated hourly) | `https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt` |

## Supported Formats

**Hosts-file** (e.g. Steven Black, Hagezi):

```text
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
```

**Domains-only** (e.g. OISD):

```text
ads.example.com
tracker.example.com
```

**IP/CIDR** (for `--ip-blocklist`):

```text
1.2.3.4
10.0.0.0/8
```

Comments (`#`, `!`) and blank lines are ignored in all formats.

## Testing

```bash
cargo test
```

## Architecture

```text
TUN Device (mosin0)
  │
  ├─ UDP/53 → Parse DNS → Domain in blocklist? → NXDOMAIN response
  │
  ├─ TCP/443 → Dst IP is DoH resolver? → TCP RST
  │           → Parse TLS ClientHello SNI → DoH hostname? → TCP RST
  │
  ├─ TCP (any) → Dst IP in blocklist? → TCP RST
  │
  └─ UDP (any) → Dst IP in blocklist? → Drop
```

## License

MIT
