<div align="center">

# WG-PROXY-PANEL

**A single-file web panel for monitoring and managing WireGuard and a Squid proxy.**<br>
Pure Python standard library — no pip packages, no build step, four languages.

[![verify](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/actions/workflows/verify.yml/badge.svg)](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/actions/workflows/verify.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)
![Languages](https://img.shields.io/badge/UI-EN%20%C2%B7%20FA%20%C2%B7%20RU%20%C2%B7%20ZH-orange.svg)

**English** · [فارسی](README.fa.md) · [Русский](README.ru.md) · [中文](README.zh-CN.md)

</div>

---

The whole application is one file, `wg_panel.py`, that uses **nothing but the
Python standard library**. Run it as a systemd service (or in the provided
Docker container) and you get a web panel for the WireGuard interfaces on that
machine: live per-client traffic, adding and disabling clients, QR codes and
share links, speed limits and data quotas, rich charts, backups, an audit log,
an advanced Telegram bot, and Prometheus metrics.

It was built for a server with no Docker and no pip, so deploying the panel
means copying one file.

## Contents

- [Features](#features)
- [Languages](#languages)
- [Requirements](#requirements)
- [Quick start with Docker](#quick-start-with-docker)
- [Install with systemd](#install-with-systemd)
- [Configuration](#configuration)
- [Prometheus](#prometheus)
- [Security](#security)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Contributing](#contributing)
- [Support the project](#support-the-project)
- [License](#license)

## Features

### Speed limits and data quotas for every WireGuard client

- **Speed limit per client**, in Mbit/s, enforced in the Linux kernel with
  `tc htb` — download is shaped on the WireGuard interface, upload through an
  `ifb` device. It is opt-in: until you limit someone, the panel does not
  touch `tc` at all, and clients without a limit are not affected.
- **Monthly data quota**, a **lifetime data cap** and an **expiry date** for
  each client.
- When a client reaches a limit, the panel acts on its own: it **disables**
  the client (the default) or **deletes** it, writes the event to the audit
  log and sends a Telegram alert. Accounts that are about to expire (3 days
  ahead by default) are reported too.
- Squid proxy users get the same treatment: quota, speed limit and expiry.

### Professional charts

- A canvas chart engine written from scratch — no chart library: line and bar
  charts on a real time axis, **zoom**, **logarithmic scale**, gaps shown
  where data is missing, hover values, series you can switch on and off, and
  a full-screen view
- Time ranges: **live, 1 hour, 24 hours, 7 days, 30 days and 6 months**
- Traffic charts for every client, every interface and every egress tunnel
- A **heat map of weekday × hour** that shows when each client uses the
  connection
- Live gauges for CPU, memory and disk; latency and routing charts for WARP
- A usage chart on every share page, so the client can see their own usage

### Advanced Telegram bot

The bot runs inside the panel process, so it needs no extra service. It is a
complete second way to manage the server — no SSH, no browser:

- **18 commands** and a button menu: create, show, rename, enable/disable and
  delete WireGuard clients and proxy users; set **quotas** and **speed
  limits**; send the **config file** and the **QR code**
- **Charts as images** — the bot draws the PNG itself (pure Python, no image
  library) for client traffic (24 hours / 7 days / 30 days / 6 months), proxy
  traffic and speed tests, with totals, averages and peaks in the caption
- Online users, search, reports sorted by expiry and by usage, backup status,
  speed test, and a daily or weekly summary
- **12 kinds of alerts**: egress tunnel down/up, quota reached, accounts about
  to expire, high CPU/RAM/disk, swap use, repeated failed logins, failed
  backup upload, speed drop, panel restart, and more
- **Approve panel logins** with one tap in Telegram (optional)
- Roles for bot users (`owner`, `admin`, `viewer`), and a separate language
  for every chat

### More features

**Clients**

- Online/offline state from the handshake age, live RX/TX per client sampled
  every 2 seconds
- Add a client (key pair generated, a free address picked from the pool) and
  remove one
- Enable or disable a client on the live interface **and** in the config file,
  so the change survives a restart
- Ready-to-use client config with copy, download and QR code
- **Share links** — a standalone page with the QR code, a download button and
  a usage chart, for sending a config to someone. Links are valid for 1 minute
  to 24 hours, can be single-use, and can be revoked. The page picks its
  language from the recipient's browser.

**Server**

- Status of egress tunnels: endpoint, live throughput, systemd unit state
- WireGuard and AmneziaWG interfaces
- Squid proxy user management
- Cloudflare WARP status, and an optional SNI-splitting daemon that routes
  connections by destination hostname
- Read-only leak audits (routing; DNS and IPv6 from the Telegram bot)
- Backup and restore; every config file is backed up automatically before it
  is written, and writes are atomic
- An audit log of every action, with who, what and the result
- A TV / kiosk view that rotates through status pages, including a 3D network
  scene

**Access**

- Multiple users; built-in `admin` and `viewer` roles plus custom roles built
  from a catalog of fine-grained permissions
- Optional TOTP two-factor authentication, and optional approval of every
  panel login from Telegram
- Signed session cookies, login rate limiting, optional IP allowlist
- Prometheus metrics at `/metrics`, protected by a bearer token

## Languages

The panel, the audit log, API errors, the Telegram bot and the Telegram alerts
are all available in **English, Persian, Russian and Chinese**. The
translations live inside `wg_panel.py` itself (about two thousand keys), so the
panel still deploys as a single file.

| Where | How the language is chosen |
|---|---|
| Panel, login page, share page | `?lang=` → `wgl` cookie → browser `Accept-Language` → Persian |
| Telegram bot | Per chat — each user chooses with `/lang` |
| Telegram alerts | The bot owner's language |

Persian pages are right-to-left, the others left-to-right; the stylesheet uses
logical CSS properties, so the layout mirrors itself. Persian digits are used
only in Persian. Identifiers — client names, keys, endpoints, IP addresses —
stay in Latin script in every language, so they can be searched and copied.

The embedded Vazirmatn font covers Persian and Latin; Russian and Chinese use
the system font. Nothing is loaded from a CDN, so the panel also works on
servers without internet access.

## Requirements

- Ubuntu 22.04 or 24.04 (x86_64 or arm64) with root access
- Python 3.10 or newer from the distribution — no pip packages, no virtualenv
- `wireguard-tools`

> [!NOTE]
> The panel manages WireGuard interfaces; it does not design your network
> topology. The Docker install creates one interface for you. With systemd,
> the panel manages the interfaces that already exist on the server.

## Quick start with Docker

The panel and WireGuard run in one container. The first start creates
`config.json`, the server keys and a self-signed TLS certificate; later starts
only update the panel code and never touch your data.

```bash
git clone https://github.com/alibakhtiari-ux/WG-PROXY-PANEL.git
cd WG-PROXY-PANEL/docker
sudo bash host-setup.sh
(umask 077 && cp .env.example .env)
```

Open `.env` and set at least `WG_SERVER_HOST` — the public IP address or
domain that clients will connect to. Then:

```bash
docker compose up -d --build
```

The panel starts at `https://SERVER:8787` with a self-signed certificate
(accept the browser warning once). The username is `admin`.

> [!WARNING]
> **The first password you type becomes the admin password.** Sign in right
> after installing, before anyone else can reach port 8787.

For servers without internet access, an offline bundle can be built on a
connected machine and carried over. From the repository root:

```bash
cd docker/airgap && bash build-offline-bundle.sh --arch amd64
```

Details: [docker/README.md](docker/README.md) ·
[docker/airgap/README.md](docker/airgap/README.md)

## Install with systemd

The panel does **not** create its own configuration: it reads `config.json`
from the same directory as `wg_panel.py` and will not start without it.
Install the file and the unit:

```bash
sudo install -D -m600 -o root -g root wg_panel.py /opt/wg-panel/wg_panel.py
sudo install -m644 wg-panel.service /etc/systemd/system/
```

Then create `/opt/wg-panel/config.json` (owner root, mode `600`). A minimal
example — with empty `salt` and `hash`, the first login sets the password;
without `tls_cert`/`tls_key` the panel serves plain HTTP:

```json
{
  "port": 8787,
  "users": [{"username": "admin", "salt": "", "hash": "", "role": "admin"}],
  "server_host": "vpn.example.com",
  "client_dns": "1.1.1.1, 8.8.8.8",
  "client_mtu": 1420
}
```

```bash
sudo systemctl enable --now wg-panel
```

Optional units for backups, log rotation, OOM protection and a fail2ban jail
are in [deploy/](deploy/).

## Configuration

All settings are in `/opt/wg-panel/config.json`. Most of them can also be
changed from the panel. The most important keys:

| Key | Purpose |
|---|---|
| `port` | Listening port (default `8787`) |
| `tls_cert` · `tls_key` | Paths to the TLS certificate and key; plain HTTP if absent |
| `users` | Panel accounts (PBKDF2 password hashes) and their roles |
| `roles` | Custom roles and their permissions |
| `server_host` · `server_endpoint` | The address written into generated client configs |
| `client_dns` · `client_mtu` · `client_allowed` | Defaults for generated client configs |
| `allow_ips` | Optional IP allowlist (`127.0.0.1` is always allowed) |
| `metrics_token` | Bearer token for `/metrics` |
| `bot` | Telegram bot token and authorized users |
| `alerts` | Telegram alerts and their thresholds |

## Prometheus

```yaml
scrape_configs:
  - job_name: wg-panel
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: <metrics_token from config.json>
    static_configs:
      - targets: ['your-server:8787']
```

With a self-signed certificate, add `tls_config: {insecure_skip_verify: true}`
or give Prometheus the certificate.

## Security

- The service runs as root, because it changes network interfaces and
  firewall rules. Its files are owned by root with mode `600`.
- Private keys of clients created **by the panel** are stored in
  `/opt/wg-panel/clients/` (root only), so the config and QR can be shown
  again later.
- **Share links contain the client's private key.** They are short-lived,
  can be single-use and revoked, and are served with
  `Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex` — still, treat
  every link as a secret.
- Login is limited to 5 attempts per minute per IP, and repeated failures can
  trigger a Telegram alert. A fail2ban filter and jail are in `deploy/`.
- The Telegram bot is a full management path: anyone on its authorized-user
  list can change the server without SSH or a panel login.
- Put the panel behind `allow_ips` or a firewall. With Docker, note that `ufw`
  does not filter ports published by Docker — see
  [docker/README.md](docker/README.md).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

`wg_panel.py` has more than 30,000 lines, including the whole web interface
(HTML, CSS and JavaScript) inside Python strings. Run the tests with:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile wg_panel.py
```

The tests check, among other things, that every translation key exists in all
four languages with matching placeholders, that translated text never becomes
data (metric labels, stored audit rows, comparison keys), that nothing private
enters the Docker build context, and that test fixtures use RFC 5737
documentation addresses. Some tests are skipped in this repository because
they check deployment tooling that is not published here.

> [!IMPORTANT]
> Python cannot see errors inside the JavaScript strings — `py_compile`
> passes on broken JavaScript, and the result is a blank page in the browser.
> After changing the interface, open the panel and check the browser console.

## Repository layout

| Path | Contents |
|---|---|
| `wg_panel.py` | The entire application |
| `wg-panel.service` | systemd unit |
| `docker/` | Docker Compose install and the offline bundle builder |
| `deploy/` | Optional systemd units, fail2ban jail, backup scripts, SNI splitter |
| `tests/` | Test suite |
| `fonts/` | Vazirmatn font subset |
| `qr.js` · `three.*.min.js.gz` | Bundled QR code and three.js libraries |

## Contributing

Bug reports and pull requests are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Please keep the project's two rules:
**standard library only** and **one file**.

## Support the project

If this panel is useful to you, you can support its development with a donation:

**USDT** — USDT · TRON (TRC20)

```text
TV4R2i7yQxzEVSzZEXwBJqfhDavifaGwMt
```

**USDT or USDC** — USDT / USDC · BNB Smart Chain (BEP20)

```text
0x5631398273a7283d543A62336eD090101FF3D449
```

**BTC** — Bitcoin (BTC)

```text
bc1qjnmmqs5c57shld3ka90vcle4scxhszevehj4y3
```

> [!WARNING]
> Send each coin **only on the network shown next to it**. Coins sent on a
> different network cannot be recovered.

## License

[MIT](LICENSE) © 2026 Ali Bakhtiari

Bundled third-party components keep their own licenses:

- [three.js](https://threejs.org) — MIT ([three.LICENSE.txt](three.LICENSE.txt))
- [Vazirmatn](https://github.com/rastikerdar/vazirmatn) — SIL Open Font License 1.1
