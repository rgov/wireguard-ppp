> [!CAUTION]
> This is a vibe-coded experiment written in a memory unsafe programming language. It would be a poor decision to use it in a security-sensitive context.
>
> Prefer using mainline kernel WireGuard support (Linux 5.6+), the [out-of-tree module][wireguard-linux-compat] (Linux 3.10 – 5.5), or the official userspace implementation, [wireguard-go][].


# Point-to-Point Protocol (PPP) Adapter for WireGuard

This project implements a userspace [WireGuard][] endpoint for Linux systems with Point-to-Point Protocol (PPP) support.

Briefly, [`pppd`][pppd] creates the host's PPP interface and attaches it to `wg-ppp`. This project provides the glue between [lwIP][], which speaks PPP, and Daniel Hope's [wireguard-lwip][], which handles the WireGuard handshake, encryption, etc.


## Usage

The host needs `pppd`, kernel PPP support (`CONFIG_PPP` and `CONFIG_PPP_ASYNC`), and Unix98 PTYs (`CONFIG_UNIX98_PTYS`).


```sh
git submodule update --init --recursive
make
```

Create a WireGuard configuration file. Only one peer, literal IPv4 addresses, and `/32` tunnel addresses are supported.

```ini
[Interface]
PrivateKey = <host private key>
Address = 10.8.0.1/32

[Peer]
PublicKey = <peer public key>
AllowedIPs = 10.8.0.2/32
Endpoint = 192.0.2.1:51820
```

Run `wg-ppp wireguard.conf` as `pppd`'s PTY command:

```sh
pppd nodetach local noauth nodefaultroute \
    noaccomp nopcomp nomagic noccp novj asyncmap 0 mtu 1400 mru 1400 \
    10.8.0.1:10.8.0.2 \
    pty 'exec build/wg-ppp wireguard.conf'
```

---

This is an independent project, unaffiliated with the WireGuard project. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.


[pppd]: https://ppp.samba.org/
[lwIP]: https://www.nongnu.org/lwip/
[WireGuard]: https://www.wireguard.com/
[wireguard-go]: https://git.zx2c4.com/wireguard-go/about/
[wireguard-linux-compat]: https://git.zx2c4.com/wireguard-linux-compat/about/
[wireguard-lwip]: https://github.com/smartalock/wireguard-lwip
