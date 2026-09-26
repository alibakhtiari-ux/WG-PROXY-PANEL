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

<p align="center">
  <img src="docs/screenshots/overview.png" width="900"
       alt="The WG-PROXY-PANEL dashboard: server gauges and the WireGuard client table with live traffic, quotas and speed limits">
</p>
<p align="center"><sub>Every screenshot in this README shows synthetic demo data — see <a href="#screenshots">Screenshots</a>.</sub></p>

## Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [The chart engine](#chart-engine)
- [Languages](#languages)
- [Requirements](#requirements)
- [Quick start with Docker](#quick-start-with-docker)
- [Install with systemd](#install-with-systemd)
- [Upgrading](#upgrading)
- [Configuration](#configuration)
- [Prometheus](#prometheus)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Contributing](#contributing)
- [Support the project](#support-the-project)
- [License](#license)

## Screenshots

<table>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/client-chart.png"><img src="docs/screenshots/client-chart.png" alt="30-day traffic chart of one client, with totals, average, peak, p95 and a month-end forecast"></a>
      <p align="center"><b>Per-client traffic chart</b><br><sub>30 days of daily usage with average, peak, p95, change against the previous range and a month-end forecast</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/heatmap.png"><img src="docs/screenshots/heatmap.png" alt="Heat map of a client's usage by weekday and hour"></a>
      <p align="center"><b>Weekday × hour heat map</b><br><sub>When a client uses the connection, and its busiest hour</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/rtl-fa.png"><img src="docs/screenshots/rtl-fa.png" alt="The panel in Persian, laid out right to left"></a>
      <p align="center"><b>Persian, right to left</b><br><sub>The same panel in Persian — one of four interface languages</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/light.png"><img src="docs/screenshots/light.png" alt="The panel in the light theme"></a>
      <p align="center"><b>Light theme</b><br><sub>Dark and light themes, switched from the toolbar</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/config-qr.png"><img src="docs/screenshots/config-qr.png" alt="A client's WireGuard config with its QR code"></a>
      <p align="center"><b>Client config and QR code</b><br><sub>Copy it, download the <code>.conf</code> file, or scan the QR code</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/telegram-chart.png"><img src="docs/screenshots/telegram-chart.png" alt="A traffic chart drawn as a PNG image by the Telegram bot"></a>
      <p align="center"><b>Chart from the Telegram bot</b><br><sub>The bot draws the PNG itself, in pure Python</sub></p>
    </td>
  </tr>
</table>

<p align="center">
  <a href="docs/screenshots/share-mobile.png"><img src="docs/screenshots/share-mobile.png" width="260" alt="The share page on a phone: config, QR code, download button and a usage chart"></a><br>
  <b>Share page on a phone</b><br><sub>What the recipient of a share link sees: config, QR code, download button and their own usage</sub>
</p>

> [!NOTE]
> The screenshots were taken from a real running panel filled with **synthetic
> data**: made-up client names, generated keys, the example domain
> `vpn.example.com`, and IP addresses from the RFC 5737 documentation ranges.
> No real server, user or key appears in them. `python3 demo/screenshots.py`
> regenerates all of them.

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

How it works, and everything it can do: [The chart engine](#chart-engine).

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

<a id="chart-engine"></a>

## The chart engine

Every chart in the panel comes from a small drawing engine written from
scratch for this project: plain Canvas 2D in about two thousand lines of
JavaScript inside `wg_panel.py`. It uses no chart library and no CDN, so it
works on a server with no internet access, and it knows the data it draws.
It knows what a quota is, when a client was disabled, and how many bytes a
tunnel moved in the last ten seconds.

### What it draws

| Chart | Where | What it shows |
|---|---|---|
| Traffic | Every client, interface and egress tunnel | Received and sent traffic plus a dashed total line; lines for Live and 1 hour, bars from 24 hours up |
| Heat map | Any traffic chart, 7 or 30 days | Average use for each weekday × hour, and the busiest hour |
| Per-client split | Every WireGuard interface | How the interface's traffic divides between its clients: the top 7, with the rest grouped as "Others" |
| Compare | Any set of charts you pick | Several clients, tunnels or interfaces as lines on one shared axis |
| Usage overview | The WireGuard clients section | Stacked usage of all clients of an interface over time |
| Server gauges | CPU, RAM, disk, panel CPU and panel RAM | The history behind each gauge |
| Speed test | The speed test section | Download and upload in Mbit/s, with ping on a second axis |
| WARP | The WARP section | Response time direct vs. through WARP, and the share of traffic routed to AI services |
| Route quality | Service reachability | Call quality (MOS) and round-trip time for each measured route |
| Share page | The page behind a share link | The recipient's own last 30 days, with their daily budget if they have a quota |

### Where the numbers come from

| Range | One point is | Kept |
|---|---|---|
| Live | a 2-second sample | the last 3 minutes, in memory |
| 1 hour | a 10-second average | the last hour, in memory (starts again after a restart) |
| 24 hours | one hour | about 21 days, in SQLite |
| 7 days · 30 days · 6 months | one day | about 400 days, in SQLite; the 6-month view can group days into weeks |

Proxy users are measured from Squid's access log and start at the 24-hour
view. The heat map is built from the hourly rows, so it can look back about
21 days.

### The figures above each chart

- **In, Out, Total**: the current rate on Live and 1 hour; the total for the
  range on the longer views.
- **Average** and **Peak**, and **p95**: the value that 95% of the hours or
  days in the range stay under. A single spike therefore does not dominate it.
- **vs previous range**: the change against the equally long period just
  before it. ▲ amber is more, ▼ green is less.
- **Month-end forecast**, for clients with a monthly quota. It takes this
  month's use so far, spreads it over the whole month, and warns
  "~N days until the quota runs out" when the pace is too high.
- **Recorded since**: the first day with data, so a short history is not
  mistaken for low use.

On the chart itself, a gold dot marks the peak, and clients with a quota get
a dashed line at their daily share of it.

### Working with a chart

- **Hover** shows every series at that moment. With several charts open,
  they all follow the same point in time.
- **Zoom**: drag across the chart to select a time span, or use the mouse
  wheel. On a phone, pinch with two fingers. Once zoomed in, drag to move
  along the time axis. Double-click or **↺ Whole range** zooms back out.
  The vertical scale fits whatever is visible.
- **Click a legend item** to hide or show that series.
- **log** switches to a logarithmic scale, so a quiet client and a heavy one
  can be read on the same chart.
- **🚩** marks changes from the audit log on the time axis: red when a
  client is disabled or a tunnel goes down, green when something comes back,
  blue for other changes. On a tunnel's chart, the time it was down is also
  shaded red. Hover near a flag to see what happened, who did it and why.
  The WARP interface's chart also shows WARP's own events, such as a switch
  to the standby key.
- **⛶ Enlarge** opens the chart full screen, and **＋ Compare** adds it to
  the comparison.
- **🔗** copies a link to exactly this view: the chart, the range, the zoom,
  and log, heat-map or per-client mode.
- **PNG** saves the chart at full screen resolution with its title. **CSV**
  saves the raw rows in UTF-8, ready for a spreadsheet.

Each open chart's range, scale and hidden series are remembered in the
browser.

### Honest by design

- From the 1-hour view up, the time axis is real time: a missing hour is
  left empty, and a line breaks where data is missing instead of drawing
  across the gap.
- In the 1-hour view, a silent client is a real zero line, not a gap: the
  panel records the silence too.
- The axes use round steps (1, 2, 2.5 or 5 × 10ⁿ) and scale bytes in powers
  of 1024. Rates are bytes per second; speed tests are in Mbit/s.
- Charts are drawn at the screen's real pixel density, so they stay sharp on
  high-resolution screens, and are redrawn when the window changes size.
- Updates arrive every 2 seconds but pause while you hover, so the chart does
  not move under the cursor.

### Colours and languages

The charts take their colours from the page theme, so they follow the dark
and light themes. The **🎨** button switches to a colour-blind-safe palette
(Okabe–Ito), which also draws the sent line dashed so the series differ in
shape as well as colour. In Persian the charts use Persian digits, and the
speed test, route and WARP charts give dates in the Solar Hijri calendar.

### Charts in Telegram

The Telegram bot cannot run a browser, so the panel also draws charts on the
server, in pure Python. It fills a pixel buffer, draws lines and bars into
it, writes the labels with a built-in bitmap font, and packs the result into
a PNG with `zlib`. The PNG is 900 × 400, bars or lines. These images go into
the client and proxy graphs in the bot and into the periodic report.

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

Download the panel and its unit from the [latest release](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/releases/latest) and
check them against the published checksums (a clone of the repository works
too):

```bash
base=https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/releases/latest/download
curl -fLO "$base/wg_panel.py" -O "$base/wg-panel.service" -O "$base/qr.js" \
     -O "$base/three.module.min.js.gz" -O "$base/three.core.min.js.gz" -O "$base/SHA256SUMS"
sha256sum -c SHA256SUMS
```

The panel does **not** create its own configuration: it reads `config.json`
from the same directory as `wg_panel.py` and will not start without it.
Install the file and the unit:

```bash
sudo install -D -m600 -o root -g root wg_panel.py /opt/wg-panel/wg_panel.py
sudo install -m644 -t /opt/wg-panel qr.js three.module.min.js.gz three.core.min.js.gz
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

## Upgrading

The panel is one file, so upgrading means replacing that file. The settings in
`config.json` and the data in `traffic.db` are kept; older configurations are
brought up to date automatically when the panel starts.

**With systemd:** download the new release as above, including the
`sha256sum -c` check, then:

```bash
sudo install -m600 -o root -g root wg_panel.py /opt/wg-panel/wg_panel.py
sudo systemctl restart wg-panel
```

To see which build a server runs, compare
`sha256sum /opt/wg-panel/wg_panel.py | cut -c1-12` with the build id in the
release notes. Changes between versions are listed in
[CHANGELOG.md](CHANGELOG.md).

**With Docker:** bring the new code onto the server (`git pull`), then, in
`docker/`:

```bash
docker compose up -d --build
```

> [!TIP]
> Take a backup before upgrading — the **Backup / restore** button in the
> panel, or a copy of `/opt/wg-panel/` (`docker/data/` with Docker).

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
| `metrics_token` | Bearer token for `/metrics` and `/api/health` |
| `trusted_proxies` | IPs/CIDRs of a reverse proxy in front of the panel; only then is the client IP read from `X-Forwarded-For` |
| `session_idle_min` | Sign out a session after this many idle minutes (`0`/absent = only the 12-hour absolute limit) |
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

`GET /api/health` (same Bearer token, or a signed-in user with `sys.view`)
reports the heartbeat of every background thread and answers `503` when one
has stopped — suitable for an external uptime check or a Docker healthcheck.

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

## Troubleshooting

<details>
<summary><b>I forgot the admin password, or lost the two-factor device</b></summary>

<br>

Stop the panel and open `config.json` (`/opt/wg-panel/config.json`, or
`docker/data/panel/config.json` with Docker). Find the account in `users` and
set its `salt` and `hash` to empty strings — to switch off two-factor
authentication for it as well, also set `totp` to `""`. Start the panel again:
the next password you type for that account on the login page becomes its new
password, so do this while no one else can reach the panel.

</details>

<details>
<summary><b>The service does not start</b></summary>

<br>

Read the log with `journalctl -u wg-panel -n 50`. The most common cause is a
missing or invalid `config.json`: the panel never creates this file itself
(see [Install with systemd](#install-with-systemd)), and it must be valid JSON.

</details>

<details>
<summary><b>A share link says it is invalid or expired</b></summary>

<br>

Share links stop working when they expire, after their first use if they are
single-use, or when they are revoked. The page deliberately does not say which
of these happened. Create a new link from the client's row.

</details>

<details>
<summary><b>The page is blank after I changed the code</b></summary>

<br>

This almost always means a JavaScript error inside the Python strings — see
the note under [Development](#development) and check the browser console.

</details>

## Development

`wg_panel.py` has more than 30,000 lines, including the whole web interface
(HTML, CSS and JavaScript) inside Python strings. Run the tests with:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile wg_panel.py
python3 tests/check_js.py      # JavaScript syntax, needs Node.js
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
> `tests/check_js.py` (also run by CI) catches syntax errors; after changing
> the interface, still open the panel and check the browser console.

**Demo mode.** `python3 demo/run.py` starts the panel at
`http://127.0.0.1:8787` (user `admin`, password `demo`) with made-up clients,
six months of traffic history and fake system tools. It needs no WireGuard and
no root, and it writes nothing outside a temporary folder. `python3
demo/screenshots.py` rebuilds every image in `docs/screenshots/`; it needs
Node.js and Playwright, and compresses the images if Pillow is installed.

## Repository layout

| Path | Contents |
|---|---|
| `wg_panel.py` | The entire application |
| `wg-panel.service` | systemd unit |
| `docker/` | Docker Compose install and the offline bundle builder |
| `deploy/` | Optional systemd units, fail2ban jail, backup scripts, SNI splitter |
| `tests/` | Test suite |
| `docs/screenshots/` | The screenshots used in the READMEs |
| `demo/` | Demo mode and the screenshot generator |
| `CHANGELOG.md` | Changes in each version |
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
