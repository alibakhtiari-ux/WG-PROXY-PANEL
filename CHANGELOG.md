# Changelog

All notable changes to WG-PROXY-PANEL are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Each release on GitHub attaches `wg_panel.py`, `wg-panel.service` and a
`SHA256SUMS` file. The release notes also give the **build id**: the first 12
characters of the SHA-256 of `wg_panel.py`, the same value a Docker install
prints as its version.

## [Unreleased]

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
