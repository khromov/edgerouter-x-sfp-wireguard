# EdgeRouter X SFP: WireGuard

Sets up WireGuard remote access on an EdgeRouter X SFP running **EdgeOS 3**,
which has WireGuard built in, and manages devices from a Mac. Adding a device
shows a QR code for the WireGuard app.

Tested on an EdgeRouter X SFP with EdgeOS v3.0.1 (WireGuard module
1.0.20220627) and an Android phone on mobile data.

```
phone (anywhere) ──UDP 51831──► router wg0 10.51.83.1 ──► internet / home LAN
                                      └─ DNS: the router's dnsmasq
```

- **Port:** UDP 51831.
- **Tunnel network:** `10.51.83.0/24`. The router is `.1`; devices get `.2`,
  `.3` and so on.
- **Full tunnel:** devices send all traffic home (`AllowedIPs = 0.0.0.0/0, ::/0`).
  IPv6 goes into the tunnel and is dropped there, so it can't leak around the
  VPN on networks that have IPv6.
- **DNS:** devices use the router (`10.51.83.1`). If the router forwards DNS
  over HTTPS, devices get that too.
- **Keys:** device keys are generated on the Mac. A device's private key never
  reaches the router. The router's own key is generated on the router and
  stays there.

## Requirements

- EdgeOS 3 on the router, SSH enabled, an admin user (default `ubnt`).
- On the Mac: `brew install wireguard-tools qrencode`.
- A public IPv4 address on the WAN (not carrier-grade NAT), ideally with a
  dynamic DNS hostname that follows it.

## Usage

```sh
./install.sh --check        # report only: support, versions vs upstream, known CVEs
./install.sh                # set up wg0, firewall rule, NAT, DNS (safe to re-run)

./device.sh add phone       # add a device: shows its QR code and config
./device.sh show phone      # show them again later (no router login)
./device.sh list            # devices with their last handshake and traffic
./device.sh remove phone    # revoke a device and delete its saved config
./device.sh debug           # watch the router while a device connects

./install.sh --uninstall    # remove wg0 and everything install.sh added
```

Every command asks for the router address (default `192.168.10.1`; type
`user@address` if your admin user isn't `ubnt`) and the SSH password. Output is
also saved under `logs/`, except QR codes and configs, which only go to the
terminal.

`install.sh` asks once for the public hostname or IP that devices connect to.
It suggests the router's dynamic DNS hostname or WAN address, checks that the
name resolves to the WAN address, and saves it in `local.conf`.

## What it changes on the router

- `interfaces wireguard wg0`: address `10.51.83.1/24`, listen-port `51831`,
  private key in `/config/auth/wg0.key` (readable by root and admins only).
- A rule in the WAN's local firewall (e.g. `WAN_LOCAL`) accepting UDP 51831,
  described `erx-wg: WireGuard UDP 51831`.
- A masquerade rule for `10.51.83.0/24` out of the WAN, only if no existing
  masquerade rule already covers it.
- `service dns forwarding listen-on wg0`, so devices can use the router's DNS.
- One `peer` per device: its public key, `allowed-ips 10.51.83.N/32` and its
  name as `description`.

What it added is recorded in `/config/erx-wg/state` and removed by
`--uninstall`. `/config/config.boot` is backed up to `/config/erx-wg/` before
every change. Everything lives in the EdgeOS config and `/config`, and
WireGuard is part of EdgeOS 3, so firmware upgrades keep it.

## Troubleshooting

If a device never gets a handshake (`./device.sh list` shows `never` and the
app shows 0 B received), run `./device.sh debug`. While you connect the
device, it captures traffic on port 51831 on all of the router's interfaces
and shows the firewall counters before and after:

- **No packets at all:** they don't reach the router. The usual cause is an
  old **port-forward or destination NAT rule for the same port**. It rewrites
  the packets before the router's own firewall sees them, so the firewall rule
  counter stays at 0. `--check` and `debug` flag such rules. Otherwise suspect
  the mobile network, the ISP, or the endpoint pointing elsewhere.
- **148-byte UDP packets in, nothing back:** the router ignores them. Usually
  the keys don't match; remove and re-add the device.
- **Only TCP arrives, never UDP** (from opening `http://<endpoint>:51831` on
  the device): something along the way blocks UDP to this port.

Testing from your own Wi-Fi checks the keys and config. Testing from mobile
data checks the path from the internet.

## Versions and security

`./install.sh --check` reports the router's WireGuard kernel module and `wg`
tool versions and compares them with the latest upstream releases. It then
lists every NVD CVE for the Linux kernel WireGuard driver and wireguard-tools.

The ER-X runs kernel 4.14, older than 5.6 where WireGuard joined the kernel,
so its WireGuard comes from a backport (`wireguard-linux-compat`), which has
had no upstream release since v1.0.20220627. A kernel CVE can only be fixed on
the router if the fix predates the module or Ubiquiti backported it. Bugs
introduced in newer kernels don't apply. The list is a starting point for
review, not a verdict.

## Files and secrets

| Path | What | Committed |
|---|---|---|
| `clients/<name>.conf` | Device configs **with private keys** (mode 600) | no |
| `local.conf` | Your endpoint hostname | no |
| `logs/` | Run logs (router details, no private keys) | no |
| `install.sh`, `device.sh`, `lib/` | Mac side | yes |
| `router/erx-wg.sh` | Router side, uploaded to `/tmp/erx-wg` on each run | yes |

## License

MIT, see [LICENSE](LICENSE).
