#!/usr/bin/env python3
"""Print the release notes for a tag, taken from CHANGELOG.md.

    python3 .github/release_notes.py v1.1.0 > notes.md

Fails when CHANGELOG.md has no "## [1.1.0]" section, so a version cannot be
released without being described. The notes end with the build id — the first
12 characters of the SHA-256 of wg_panel.py, the value a Docker install prints
as its version.
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def section(changelog, version):
    """The body under "## [version]", up to the next "## [" heading."""
    m = re.search(r"^## \[%s\][^\n]*\n(.*?)(?=^## \[|\Z)" % re.escape(version),
                  changelog, re.S | re.M)
    if not m:
        return None
    body = m.group(1)
    # link references at the end of the file are not part of any section
    body = re.sub(r"^\[[^\]]+\]: \S+\s*$", "", body, flags=re.M)
    return body.strip()


def build_id(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:12]


def main(argv):
    if len(argv) != 2 or not re.fullmatch(r"v\d+\.\d+\.\d+", argv[1]):
        print("usage: release_notes.py vX.Y.Z", file=sys.stderr)
        return 2
    version = argv[1][1:]
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        body = section(f.read(), version)
    if not body:
        print("CHANGELOG.md has no section for [%s]" % version,
              file=sys.stderr)
        return 1
    print(body)
    print()
    print("---")
    print()
    print("Build id: `%s` (first 12 characters of the SHA-256 of "
          "`wg_panel.py`; a Docker install prints the same value as its "
          "version). Verify the download with `sha256sum -c SHA256SUMS`."
          % build_id(os.path.join(ROOT, "wg_panel.py")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
