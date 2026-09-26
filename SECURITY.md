# Security Policy

## Reporting a vulnerability

Please report security issues privately to **abghub@pm.me** rather than opening
a public issue. Include enough detail to reproduce: the version identifier
(first 12 characters of `sha256(wg_panel.py)`), the install path you used, and
the request or sequence that triggers the problem.

You will get an acknowledgement. There is no bug bounty — this is a
single-maintainer project.

## Scope

wg-panel manages WireGuard peers, generates client configurations and stores
private keys on the server. Reports about the following are in scope:

- authentication, the session cookie, and the Telegram second factor
- the RBAC permission gate and the bot's authorization model
- share links — unauthenticated by design, single-use and time-limited, so a
  way to enumerate, replay or extend one is a real finding
- anything that discloses a private key, a stored credential or another user's
  configuration
- the installers and the container bootstrap, which run as root

## Not in scope

These are deployment choices or documented design decisions, not defects:

- **Exposure of the panel port to the internet.** The panel binds to a port you
  control and supports an IP allowlist; putting it on a public interface without
  one is your decision.
- **The self-signed certificate on first run.** Intentional, so the panel is
  reachable before any certificate exists. Replace it.
- **`script-src 'unsafe-inline'` in the CSP.** Forced by the single-file design:
  the HTML, CSS and JavaScript live inside `wg_panel.py` as strings, and there is
  no build step to hash or nonce them.
- **The service running as root.** It edits `/etc/wireguard`, brings interfaces
  up and down, and writes firewall rules.

## Supported versions

There is one version: the current `main`. The single-file design means there are
no release branches to backport to.
