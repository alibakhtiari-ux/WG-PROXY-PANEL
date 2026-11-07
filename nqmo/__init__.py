"""WG-NQMO — passive network-quality observer for the wg-panel server.

Read-only by construction: the only process launcher is nqmo.runner (an argv
allowlist of show/get commands), packet sockets are receive-only taps, and the
engine never holds CAP_NET_ADMIN. Design: docs/nqmo/01..07.
"""

VERSION = "0.1.0"
SCHEMA_VERSION = 2          # nqmo.db PRAGMA user_version
STATE_SCHEMA = 1            # state.json "schema"
