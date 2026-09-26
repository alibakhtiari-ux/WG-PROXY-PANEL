# Changelog

All notable changes to WG-PROXY-PANEL are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Each release on GitHub attaches `wg_panel.py`, `wg-panel.service`, the bundled
`qr.js` and three.js files, and a `SHA256SUMS` file. The release notes also give the **build id**: the first 12
characters of the SHA-256 of `wg_panel.py`, the same value a Docker install
prints as its version.

## [Unreleased]

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

[Unreleased]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/compare/81faf06...v1.1.0
[1.0.0]: https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/commit/81faf06
