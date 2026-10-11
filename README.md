# krouter

**Version:** 6.4.124  
**Author:** Kage  
**License:** [Apache License 2.0](LICENSE)

A small home router stack: DHCP, DNS policy, study-mode scheduling, firewall / port forwarding, and a single admin web UI.

## History

This is not a green-field toy. From about **2004**, Kage kept expanding firewall and **iptables-based routing** work — used at home and in many other setups.  
A shape closer to today’s **home router** (LAN/WAN, NAT, policy) grew around **2006**.  
Those lines of practice kept being upgraded for years until they became the packaged **krouter** you see here.

**Real home production use** (not just lab experiments) started around **July 2025**: this box became the main router, the previous router was switched to **AP mode**, and several AP-mode routers were placed around the house. That setup is still in daily use.

## Why this exists

Commercial home routers often feel short-lived, complicated, and packed with features that are hard to use day to day — while still supporting only a modest number of devices. Many “security” options exist on paper, but the controls people actually need (especially with students at home) are awkward or incomplete.

`krouter` was built for that gap: keep the network simple, put the useful policies where they belong, and keep improving them. After years of real home use and hardening, it became stable enough to package and share.

If there are students in the house, the internet can become a daily fight. During agreed study hours, what they need for school stays open while distractions stay blocked. Outside those hours the policy tightens, and an adult can still grant extra time or a short temporary “free” window when needed.

## What you get

- **DHCP** with reservations and an auto-assign IP pool
- **DNS** with per-mode block lists (default / study / schedule-off BLOCK)
- **Modes:** `default`, `all_allow`, `study` (+ temporary allow for study devices)
- **Firewall / port forward** (optional; code default ON, configure per host)
- **One admin UI** (English), one control script: `krouterctl`

Host NIC names and other site-specific values live in **Settings DB**, not in the source defaults. Published source carries the author name and intent — not private contact details or host NIC names.

## Quick start

```bash
cd tree
sudo ./krouterctl start
./krouterctl status
./krouterctl ui
```

- UI: `http://<LAN_IP>:15000/` (default login: `admin` / `admin` — change it)
- Stop: `sudo ./krouterctl stop`
- Emergency rollback to a previous systemd stack (if you had one): `sudo ./krouterctl fallback`

SAFE / UI-only (no live DHCP/DNS/iptables):

```bash
sudo KROUTER_SAFE_MODE=1 ./krouterctl start
```

## Layout

| Path | Role |
|------|------|
| `tree/` | Runtime code (`admin_app`, `dhcp_app`, `dns_app`, `router.sh`, `krouterctl`) |
| `tree/data/` | Local DBs & generated conf (gitignored — host-specific) |
| `VERSION` | Package version (shown in the admin UI) |
| `LICENSE` / `NOTICE` | Apache 2.0 |

## License

Licensed under the **Apache License, Version 2.0**.

As the copyright holder, you (Kage) may publish the project and also ship commercial products based on it.  
Apache 2.0 also lets others use, modify, and redistribute (including commercially), provided they keep the license notices. See `LICENSE` and `NOTICE`.

Review firewall and study policies before exposing anything to the public internet.
