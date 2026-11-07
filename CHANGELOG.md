# Changelog

All notable changes to WG-PROXY-PANEL are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Each release on GitHub attaches `wg_panel.pyz` (the panel), `wg_panel.py` (its launcher),
`wg-panel.service`, the bundled `qr.js` and three.js files, and a `SHA256SUMS` file. From
1.4.0 it also attaches `wg_nqmo.pyz` (the WG-NQMO engine) with `deploy/wg-nqmo.service`,
checked by their own list, `SHA256SUMS.nqmo`.
The release notes also give the **build id**: the first 12 characters of the SHA-256 of
`wg_panel.pyz`, the same value a Docker install prints as its version, and the engine's
build id, the same measure of `wg_nqmo.pyz`.

## [Unreleased]

## [1.5.0] — 2026-11-07

### Added

- WG-NQMO in the Telegram bot: `/quality` and a menu button show the engine mode, the
  age of its data, coverage, global diagnoses and the clients worst first; tapping a
  client (or `/quality <name>`) shows its quality, round trip, upstream loss, MTU status,
  open diagnoses and recommendations, with the panel's own wording in all four
  languages. Read-only and gated by `nqmo.view`; prefixes, ASNs and raw evidence never
  reach the bot. The command and the button exist only while the engine is turned on.

- Excel export in the Telegram bot: `/excel` and a menu button build one `.xlsx` file
  for the last 1, 3, 7 or 30 days or a typed range (Gregorian or Solar Hijri). Three
  kinds: all WireGuard clients, the whole server (only the sheets the user's role may
  see), or one WireGuard or proxy user, reached by name search or from that user's
  page in the bot. The user workbook has a dashboard, daily and hourly traffic with
  charts, the user's path as native Excel shapes with its evidence, connection
  quality, share links, proxy sources and destinations, and the admin actions on that
  user. The server workbook gains proxy-user, daily proxy traffic and connection
  quality sheets. Passwords and share tokens never reach the file.

### Fixed

- `/quality` listed only the first 20 clients in name order, so a client could be
  missing from the list while the engine had data for it. The list is now paged and
  puts clients with measurements first. In observation-only mode a client's page says
  why there is no grade instead of showing a dash.
- Releases 1.4.0 and 1.4.1: `SHA256SUMS` also listed the two engine files, which the
  install steps in the README do not download, so `sha256sum -c SHA256SUMS` stopped with
  "No such file". Both releases now carry a `SHA256SUMS` for the panel files only and a
  separate `SHA256SUMS.nqmo` for `wg_nqmo.pyz` and `wg-nqmo.service`; no other file
  changed. Those two releases had been made by hand. The release workflow now builds
  and attaches the engine itself and writes both lists, and the release notes give the
  engine's build id.

## [1.4.1] — 2026-11-07

### Fixed

- Telegram bot: rotating a client's key is now refused in a group chat, both when the
  bot would ask and when the confirmation arrives. The new config, which holds the private
  key, is only ever sent in a private chat, so a rotation started in a group cut the client
  off without ever delivering their new config. Every path that sends a config, a key, a
  proxy link or a password is now covered by one test, in group, supergroup and channel
  chats.

### Changed

- README, in all four languages: the screenshot gallery is grouped by topic (Map & report,
  Connection quality, traffic charts, everyday use, clients and phones), shows the
  egress map, the user trace, the timeline and the Excel sheets, and adds two WG-NQMO
  screenshots. The Telegram bot section is rewritten to match the bot: it no longer
  claims a rename the bot does not have, says that proxy users get a link and a QR code,
  and lists the leak audit, the ECMP guard, the WARP pages, speed test charts, the
  periodic chart report, bot user management and `/botwatch`.
- The demo (`demo/run.py`) writes a WG-NQMO engine state in the engine's own format, so
  the demo panel shows the Connection quality section with diagnoses and recommendations.

## [1.4.0] — 2026-11-07

### Added

- The WG-NQMO engine itself. The `nqmo/` package is built into a second single file,
  `wg_nqmo.pyz`, by `tools/build_nqmo_pyz.py` (reproducible; its build id is the first 12
  characters of `sha256(wg_nqmo.pyz)`, printed by `--id`). It runs as its own systemd
  service, `deploy/wg-nqmo.service`, under the unprivileged user `wg-nqmo` with no
  capability at all. The optional drop-in `deploy/wg-nqmo-capture.conf` grants only
  `CAP_NET_RAW`, for reading WireGuard headers, and `deploy/wg-nqmo-resources.conf` raises
  the CPU and memory caps for busy servers. Two configurations ship with it: observation
  only without capture, `deploy/wg-nqmo.config.json`, and observation only with capture,
  `deploy/wg-nqmo.capture.config.json`. `wg_nqmo.pyz --check` is its self-test, like the
  panel's; it needs neither root nor Linux.
- Observation only is the default mode and active probes are off: the engine sends
  nothing, changes nothing and raises no alert until the mode is moved up from the panel,
  one step at a time. The capture filters are compiled for WireGuard port 53953; another
  port needs `tools/gen_nqmo_bpf.py` run again.
- `deploy/wg-nqmo-review.sh` with its service and timer: an optional hourly archive of the
  engine's state file and a one-line summary with no names, keys or addresses.
- The engine's tests (`tests/test_nqmo.py`, `tests/test_nqmo_diag.py`,
  `tests/test_nqmo_panel.py`), the generator of its capture filters
  (`tools/gen_nqmo_bpf.py`) and its design documents (`docs/nqmo/`).
- README, all four languages: *Installing the engine* under *Connection quality
  (WG-NQMO)*: install, the observation-only default, header capture, the resource quota
  and where the metrics come from. The opening no longer says the engine is unpublished.
- CI builds and self-tests `wg_nqmo.pyz` as well, and checks that the build is
  reproducible.
- **Map & report**, a new section of the panel drawn with the SvgStudio engine
  (`wgpanel/web/svgstudio.js`) from models built on the server (`wgpanel/viz.py`): a live
  map of every egress path (users, ingress, route decision, mother and nested tunnels,
  ECMP, the SNI splitter, the AI egress pool, a WARP chain, the kill switch, the uplink),
  a step-by-step *Why is this user disconnected?* trace that ends in a verdict, and a 6, 24
  or 72-hour timeline of tunnel traffic, outages, tunnel-guard repairs and WARP, WG-NQMO and
  admin events. Every part opens a drawer with its evidence. The map is also a TV slide.
  New routes: `/api/viz/egress` and `/api/viz/timeline` (`tun.view`), `/api/viz/trace`
  (`wg.view`).
- An Excel report, `/api/report.xlsx` (`wg.view`), written with the standard library
  (`wgpanel/xlsx.py`, `wgpanel/report.py`): up to ten sheets for 7, 30 or 90 days, each
  shown only to roles allowed to see it, with the egress map drawn as native Excel shapes.
  Client endpoints are masked unless *Mask user IPs* is unticked, and every download is
  written to the audit log.
- A faster interface: a section bar with live counts, search and commands
  (<kbd>Ctrl</kbd>/<kbd>⌘</kbd> + <kbd>K</kbd>), an event center for the last 24 hours, status
  filters and quota and expiry badges on the client table, one dialog for every
  confirmation (irreversible actions need the name typed in), *Undo* after enabling or
  disabling a client, cards on phones, and loading, empty and error states.
- `svg-pan-zoom` 3.6.1 (BSD 2-Clause) is vendored in `wgpanel/web/vendor/` for zooming and
  panning the diagrams; nothing is loaded from a CDN.

### Changed

- README: the opening of all four languages now introduces WG-NQMO, says what it answers,
  and states that the engine is not published yet and that the panel works fully without it.
- README: the *Connection quality (WG-NQMO)* section moved up from near the end of the
  file to right after the feature descriptions, and was rewritten in all four languages.
  It now opens with what the engine is for, explains the modes, every diagnosis, quality
  level and MTU status, adds a turn-on check and a troubleshooting guide, and folds the
  reference material. The Persian section also renders right to left on GitHub.
- README (Persian): the whole document now renders right to left on GitHub, including
  tables, lists, headings and collapsible sections, and code stays readable inside
  Persian sentences.
- README, all four languages: a new *Map & report* section (the three views, every verdict
  and traffic signature, the Excel sheets, permissions and API), an *Interface* group under
  the features, and new screenshots taken from the demo with synthetic data: the egress
  map in English and Persian, a user trace, the timeline, the event center, search and
  commands, the panel on a phone, and two sheets of the Excel report as Microsoft Excel
  shows them. Stale facts about `wgpanel/app.py` (its size, and the interface and
  translations living inside it) were corrected.
- The demo (`demo/run.py`) now has a full egress topology, a client whose carrier NAT has
  expired, tunnel-guard events and system gauges, so every screenshot shows realistic and
  consistent data. `demo/screenshots.py --reports DIR` also saves the demo's Excel
  workbooks.

### Fixed

- The event center showed actions without a target, such as downloading a backup or a
  report, as "Download backup — *". The `*` is no longer shown.
- On the egress map, the details of the *Users* box listed the number of clients under
  *Total traffic*; the row is now labelled *Users*.
- WG-NQMO commands on Linux: when the engine closed the connection without replying (the
  panel is not running as root), the panel reported `UNREACHABLE`, which points at a
  stopped engine. Linux delivers that close as a reset rather than an end of stream, and
  the panel treated every socket error the same way. It now reports `NO_REPLY`, as the
  README describes, and keeps `UNREACHABLE` for a socket it could not connect to.

## [1.3.0] — 2026-11-01

### Added

- Hooks for WG-NQMO, a separate link-quality engine that is **not part of this repository**.
  They are off unless `config.json` has `"nqmo": {"enabled": true}`. While off, the panel
  reads and writes nothing for the engine, `/api/stats` and `/metrics` answer exactly as
  before, and the `/api/nqmo/*` routes answer `disabled`. The page makes no WG-NQMO
  request and shows no WG-NQMO section; its permission group and alert kind are hidden, and
  saving a role or the alert settings keeps their stored values.
  The README section *Connection quality (WG-NQMO)*, in all four languages, describes the
  files, permissions, alerts, API routes and Prometheus series the hooks use once switched on.

### Changed

- The panel source is now the `wgpanel/` package, released as `wg_panel.pyz` plus the
  launcher `wg_panel.py`. Install both side by side; `wg_panel.py --check` replaces
  `py_compile`. The systemd unit is unchanged, and `config.json`, `traffic.db` and
  `clients/` stay where they are. When upgrading, install `wg_panel.pyz` first, then
  `wg_panel.py`.
- The build id is the first 12 characters of `sha256(wg_panel.pyz)`; builds are
  reproducible (`python3 tools/build_pyz.py --id` on the source prints the same value).
- The interface HTML/CSS/JavaScript, the two fonts and the translation catalog now live as
  ordinary files in `wgpanel/web/` and `wgpanel/i18n/catalog.json` instead of inside
  `wgpanel/app.py`. Nothing that is served changed. A duplicate catalog key now fails at
  start-up and in `wg_panel.pyz --check`.

### Fixed

- Speed test on several interfaces: the Ookla server refused the second and later tests of a
  back-to-back run with `Cannot read`, so only the first interface got a result. The panel
  now waits 30 seconds between interfaces and retries a `Cannot read` once after 60 seconds;
  both waits stop at once when the run is cancelled.

### Removed

- The “flagged clients going offline” alert toggle. It never sent anything; existing settings
  keep loading.

## [1.2.3] — 2026-10-03

### Fixed

- Adding a client while its interface is up: if the live `wg set` failed, the panel
  still marked the configuration as applied, so the file watcher never retried and the
  kernel stayed out of step with the file until the next change. The panel now applies
  the peer in one `wg set` (address, preshared key and keepalive together) and leaves a
  failed apply for the watcher to retry. Changing a client's AllowedIPs goes through the
  same path.
- Deleting a client while its interface is up: if removing the peer from the live
  interface failed, the deleted client could stay connected until the next restart,
  because the watcher was told everything was applied. A failed removal is now retried.

## [1.2.2] — 2026-09-26

### Changed

- A broken user record in `config.json` (bad username, salt, role, expiry
  date or `allow_ips`, or a duplicate) no longer stops the panel. The record
  is logged, cannot sign in, and is written back unchanged when the panel
  saves the configuration; quota and expiry enforcement, the bot and alerts
  keep running. Structural errors (port, TLS, network lists) still stop it.
- `/api/health` returns `ok: false` together with `503`; it returned
  `ok: true` for an unhealthy panel.
- Restoring a WireGuard config that has `[Peer]` blocks without a `#!!!`
  label onto an interface that is up is refused (the live apply only knows
  labelled blocks and would have dropped every current client). On an
  interface that is down, the file is still written.

### Fixed

- A TOTP code could be replayed at login within its 90-second window: the
  replay check rejected it, but the rejection branch let the login through.
- The daily database prune never deleted old service IPs (`svc_resolved`) or
  route-chart history (`mtr_run`); both tables grew without limit.
- Behind a trusted proxy, a malformed or all-trusted `X-Forwarded-For` was
  resolved to the proxy's own address — `127.0.0.1` for a proxy on the same
  host, which skips the IP allowlist and Telegram login approval. A proxy that
  sets only `X-Real-IP` let a forged `X-Forwarded-For` through, and only the
  first `X-Forwarded-For` header line was read. Such requests now get a
  non-privileged placeholder address, a forwarded loopback address is never
  the client, and `X-Real-IP` must agree with `X-Forwarded-For`.
- `X-Forwarded-Proto: https` from a trusted proxy is now honoured: behind a
  TLS-terminating proxy, share links started with `http://` and the session
  cookie was not marked `Secure`.
- The Telegram bot's WireGuard and proxy creation wizards worked in groups:
  a WireGuard client was created whose config was then withheld, and the
  proxy password appeared in the group. Group messages from a user with a
  private wizard open were also taken as wizard input.
- Removing `PersistentKeepalive` or emptying `AllowedIPs` in a config never
  reached the running interface. When enabling, disabling or changing the
  PSK of a client failed to apply live, the change was recorded as applied,
  so the file watcher never retried it.
- The bot and alert-monitor threads were reported as dead in `/api/health`
  during a long Telegram outage, because one cycle of retries over several
  tunnels took longer than their heartbeat limit.
- Long Telegram messages split inside `<pre>` (WireGuard configs, the leak
  audit, the tunnel list) were rejected by Telegram with "can't parse
  entities". Every part is now valid HTML on its own.
- TOTP recovery codes stayed in the page after their window was closed, a
  code typed without its dash was rejected, and their copy button said
  "Copy link".
- Seventeen more inline button handlers and the chart controls placed data
  in single-quoted JavaScript with only HTML escaping; they now use the same
  JSON escaping as the service card.
- The restore preview ignored `PersistentKeepalive` changes that the restore
  then applied.
- `alert-edges.json` kept an entry for every deleted tunnel, proxy user and
  domain; entries not checked for seven days are pruned.
- A negative `Content-Length` made a request thread wait until the client
  closed the connection.
- The login rate limiter's cleanup left open reservations behind; the next
  failure from that address was then not counted.
- `/api/totp/setup`, `/api/totp/disable`, `/api/password` and the password
  confirmation of both restore paths checked the password without a rate
  limit; they now share the per-account login budget.

## [1.2.1] — 2026-09-26

### Changed

- The Telegram bot's command menu is shown in each bot user's language (the
  one chosen with `/lang`); chats of users who are not authorized see the
  owner's language. The descriptions used to be Persian in every language.
- The periodic picture report (`report`) is written in the owner's language,
  like the other alerts; it used to be Persian only.
- `deploy/wg-panel-verify-backup.sh` checks the full-host backup chain only
  when it is in use (`FULL_PREFIX` set in `/etc/wg-panel-s4.env`, or the
  chain has uploaded at least once). An install that backs up only the panel
  no longer fails every week with "no backup on MEGA".
- README, in all four languages, checked against the code: new sections on
  setting up the Telegram bot, the Squid proxy, backups, TLS and reverse
  proxies, outbound connections, limitations and uninstalling; the optional
  programs and ports to open; more configuration keys with their defaults
  and the permission catalog. The upgrade step now installs
  `wg-panel.service` and the bundled files too.

### Fixed

- Per-client **upload** limits were never applied under the shipped systemd
  unit: `ProtectKernelModules=yes` stopped the panel from loading the `ifb`
  module, and the limit failed with only a line in `actions.log`. The unit
  now loads `ifb` before the panel starts, and the Docker installers
  (`host-setup.sh`, the offline `install.sh`) load it on the host.
  **Existing systemd installs must install the new `wg-panel.service`**
  (see Upgrading in the README).
- Saving the bot users from the panel erased each user's `/lang` choice,
  because the form does not carry it. For the owner this also switched the
  alerts back to Persian. The language is now kept.
- The systemd install step in the READMEs did not download
  `three.LICENSE.txt`, so `sha256sum -c SHA256SUMS` failed on a correct
  download.

## [1.2.0] — 2026-09-26

### Added

- `trusted_proxies` in `config.json`: when the panel runs behind a reverse
  proxy listed there, the client IP is taken from `X-Forwarded-For` (allowlist,
  rate limit, Telegram login approval and the audit log then see the real
  address). Headers from any other peer are ignored.
- Password hashes record their PBKDF2 iteration count and are upgraded from
  200 000 to 600 000 iterations on the next successful login, without
  invalidating anybody's password.
- `config.json` is validated at start-up; a broken user record, salt, port,
  TLS pair or network list stops the panel with a clear message instead of a
  500 later.
- TOTP recovery codes: enabling two-factor login hands out eight one-time
  codes (only their hashes are stored); a code works once in place of the app
  code, is written to the audit log and raises an alert.
- `session_idle_min`: optional idle timeout for panel sessions.
- `GET /api/health`: heartbeat of every background thread (Bearer token or
  `sys.view`), `503` when one has stopped; `panel_thread_alive` and
  `wg_panel_uptime_seconds` in `/metrics`.
- Prometheus: per-client quota, total cap, speed limit, expiry timestamp,
  lifetime usage and auto-disable reason; host CPU/RAM/disk; last probe result
  and latency of each restricted service; `wg_panel_build_info`. Label values
  are escaped, and the `*_bytes_total` counters are omitted for a client that
  is absent from the live snapshot instead of reporting a false reset.
- Restore preview: the restore dialog first shows which clients the archive
  would add, remove or change, per interface, before anything is written
  (`X-Dry-Run: 1` on `/api/restore`). Archives are validated first: a
  WireGuard config must have `[Interface]` and `PrivateKey`, and `traffic.db`
  must pass `PRAGMA integrity_check`.
- Share page: a "Copy config" button, the link's validity and the account's
  expiry date, `noindex`, and a download name that WireGuard clients accept
  (15 characters or fewer).
- Telegram bot: configs, preshared keys and proxy passwords are only sent in a
  private chat with the bot; the bot stays silent in groups where the sender
  is not authorised. Long messages are split at the 4096-character limit.

### Changed

- Client IP allocation follows the interface's real prefix (`/22` is no longer
  treated as `/24`), reserves every server address and walks the whole subnet;
  IPv6 endpoints are written as `[host]:port`.
- Changing a client's AllowedIPs refuses an address or range that already
  belongs to another client of the same interface.
- Config writes are fsynced before the rename; a bulk add takes one backup for
  the whole batch instead of one per client.
- The state of edge alerts is kept on disk, so a restart no longer forgets that
  a tunnel was already down; the expensive WARP checks (DNS leak audit, ECH
  lookup, split series) run every few minutes instead of every 30 seconds; the
  daily digest is marked as sent only after it was built.
- Telegram API calls remember the last route that worked, honour
  `retry_after` on 429 and stop retrying on 403/409.
- The WARP endpoint ranking pings the pool in parallel with one packet each.
- Config parsing is cached by file mtime, so the 2-second poll and the
  Prometheus scrape no longer re-read and re-parse every config; the audit
  search escapes `%` and `_`; the WAL is checkpointed after the daily prune.
- The Telegram digest, the "time ago" strings, the start-up alert and the
  audit details of adding/editing a client or a panel user are now translated
  (they were Persian in every language).
- The services card warns about a missing `traceroute` (the tool it actually
  uses) rather than `mtr`; the shaper loads the `ifb` module explicitly and
  logs when upload limits cannot be enforced.

### Fixed

- Re-enabling a WireGuard client did not restore its preshared key and
  keepalive on the running interface, so a client that had been disabled
  (by hand, or automatically after reaching its quota) could not connect again
  until the interface was restarted. Disabling removes the peer from the
  kernel completely; enabling now applies the preshared key, keepalive and
  AllowedIPs from the file in one step. Key rotation applies them the same
  way.
- Removing a client's preshared key while the interface was up silently did
  nothing in the kernel: the config and the client's file lost the key, the
  kernel still required it, and the panel reported success. The kernel now
  gets the removal, and a failed live change is reported as an error.
- Restoring a backup only rewrote the config files; the running interface was
  never updated, so clients removed by the restore stayed connected and
  clients brought back could not connect, and the config watcher never caught
  up. The restore now applies the differences live and holds the config lock
  while writing.
- The CPU, RAM and disk alerts were never sent: the monitor read the metrics
  from the wrong level of the snapshot and always saw nothing.
- The WARP status API leaked the per-user SNI tables and the IP-to-user map to
  every user with the `tun.view` permission (including the built-in `viewer`
  role); the redaction only looked at the top level of the payload.
- A custom service's label was placed unescaped into an inline `onclick`
  handler, so a user with `svc.edit` could store a label that runs JavaScript
  in every administrator's browser. Handler arguments are now JSON-escaped
  before HTML-escaping, and labels are limited to letters, digits, spaces,
  dots, dashes and parentheses.
- `wg-panel.service` made `/etc/squid` read-only (`ProtectSystem=full`), so the
  panel could not write the Squid password file or `squid.conf`; the error
  went only to `actions.log`. The unit now lists `/etc/squid` in
  `ReadWritePaths` (ignored when Squid is not installed).
- Releases and the systemd install steps shipped only `wg_panel.py`; without
  `qr.js` and the three.js files next to it, QR codes, the share page and the
  TV 3D view failed. The release now attaches those files and the install
  steps copy them.
- A request body that was valid JSON but not an object (for example `[]`),
  and several wrongly typed fields (role permissions, bot users, ECMP groups,
  alert event toggles, the proxy log line count), crashed the request thread
  and closed the connection without a reply. They are now answered with
  `400`, and any other unexpected error in a request is answered with a JSON
  `500` and written to `actions.log` instead of dropping the connection.
- A quota, total cap or speed limit of `inf` or `nan` was accepted; `inf`
  then broke `/api/stats` for every open tab (invalid JSON), and `nan`
  silently disabled the limit. Non-finite numbers are rejected, and the API
  never emits `NaN`/`Infinity`.
- Share links always started with `https://`, so on a panel served over plain
  HTTP they did not work. The link now uses the scheme the panel runs on.
- The login rate limit (5 per minute per IP, 10 per 5 minutes per account)
  counted an attempt only after the password check, so parallel requests
  could all pass. The slot is now reserved when the request is admitted and
  released on success.
- Enrolling a new TOTP secret while one was already active needed no
  password, so a stolen session cookie could replace the second factor. It
  now requires the current password, the pending secret expires after 10
  minutes, and confirming a new secret signs the other sessions out.
- Speed-limit classes in `tc` were numbered by the last byte of the client's
  IP, so with a client subnet larger than /24 two clients could share one
  class (the second `tc class add` failed and both got one rate). Classes are
  now numbered sequentially; IPv6-only peers are skipped instead of producing
  an invalid class.
- The Squid and traffic-shaper reconcile loops could run concurrently (from
  the UI and the background thread) and the Squid password file, `squid.conf`
  and the WARP targets file were written through a fixed temporary name, so
  two writers could publish a truncated file. Reconciles are serialised and
  temporary files are unique.
- A WARP target overlapping one of the endpoints the guard rotates through
  (for example `188.114.96.0/24`) was accepted, which routes the WARP tunnel's
  own packets into the tunnel after a rotation. The whole endpoint pool and
  the live endpoint are now protected.
- The Telegram bot accepted an expiry date typed with Persian digits and
  stored it as-is, so the account never expired; Persian digits in Telegram
  user IDs were accepted too and never matched. Both are normalised.
- The "expiring soon" alert only covered proxy users, repeated every six
  hours and again after every restart. It now covers WireGuard clients too,
  is sent once per day, and remembers the day across restarts.
- The alert toggles for tunnel up/down and swap usage had no effect; edge
  alerts now honour their event category.
- The active tab in the users/roles editor was invisible in the light theme
  and the permission chips had no borders (two undefined CSS variables); the
  IP allowlist box and the restore password field had a dark background with
  light-theme text.

## [1.1.0] — 2026-09-26

### Fixed

- The embedded Vazirmatn font was blocked by the page's Content-Security-Policy,
  so every page fell back to a system font.
- The WARP section never finished loading: its status request failed on the
  server with a `NameError`. Changing WARP presets, targets and the QUIC
  setting failed the same way. A WARP request from a user who is removed or
  disabled while it runs now gets a 401 answer instead of a dropped
  connection.
- Some invalid requests crashed on the server instead of returning an error,
  for example an invalid bot ID when saving the Telegram bot settings.
- When applying a changed config or generating keys failed, the error showed
  a raw key such as `api.err.apply.edited` instead of the message.
- Chart event markers (🚩) showed raw action codes and raw JSON in their
  tooltip, were always blue, and the red band for a tunnel's downtime was
  never drawn.
- The Telegram bot's charts lost letters in titles, legends and user names
  ("DOWN" showed as "D W"), and speed-test charts labelled the Y axis in bytes
  ("95 B") instead of bit/s.
- In English, Russian and Chinese, many labels still appeared in Persian:
  - names of the built-in services
  - backup rows, restore components and MEGA S4 errors
  - the reason in auto-disable audit rows
  - permissions in the role editor
  - alert event names
  - WARP event names, in the panel and in the Telegram bot
  - error and success messages from the panel, the Telegram bot and the
    audit log, such as the "sending…" message of the report test and the
    confirmation after enabling or disabling a client
- The Telegram bot's new-proxy-user wizard showed a raw key such as
  `bot.proto.https` instead of the service type.
- The share page's usage chart was scaled to the daily quota share, so with a
  large quota the bars were only a few pixels tall. The chart now scales to
  the usage. The quota line is drawn only when it fits; otherwise the daily
  share is written under the chart.
- The chart windows (⛶ Enlarge, Client usage overview, Compare) were only
  560 px wide, and their legend and buttons fell below the fold. They are now
  wide, and everything fits on one screen.

### Changed

- The first slide of the TV / kiosk view fills the screen: six large tiles
  whose text scales with the screen, with a level bar for CPU, RAM and disk.

### Added

- `demo/`: runs the panel with synthetic data and no real server, as a normal
  user on Linux or macOS, without touching anything outside its own folder.
  `python3 demo/screenshots.py` regenerates every screenshot in the READMEs,
  and `docs/social-preview.png` for the repository's social preview.
- `tests/check_js.py`: a JavaScript syntax check for the scripts inside
  `wg_panel.py`. CI now runs it.
- A release workflow: pushing a `vX.Y.Z` tag runs the tests and publishes a
  GitHub release with the files and their checksums.
- README: screenshots, upgrading, troubleshooting, and a section on the chart
  engine, in all four languages.

## [1.0.0] — 2026-09-26

First public release.

[Unreleased]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/81faf06...v1.1.0
[1.0.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/commit/81faf06
