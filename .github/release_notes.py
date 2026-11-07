#!/usr/bin/env python3
"""Print the release notes for a tag, taken from CHANGELOG.md.

    python3 .github/release_notes.py v1.1.0 > notes.md

Fails when CHANGELOG.md has no "## [1.1.0]" section, so a version cannot be
released without being described. The notes end with the build id — the first
12 characters of the SHA-256 of wg_panel.pyz, the value a Docker install prints
as its version — and, when the tree has the WG-NQMO engine, the engine's build
id, the same measure of wg_nqmo.pyz.
"""
import hashlib
import importlib.util
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


def panel_build_id():
    """Build id of wg_panel.pyz, built in memory from wgpanel/.

    Always from the source, never from an existing dist/wg_panel.pyz: a stale
    local dist/ would print an old id. The build is deterministic, so CI's
    freshly built release asset has exactly this id."""
    spec = importlib.util.spec_from_file_location(
        "build_pyz", os.path.join(ROOT, "tools", "build_pyz.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_id(mod.build_bytes(os.path.join(ROOT, "wgpanel")))


def engine_build_id():
    """Build id of wg_nqmo.pyz, built in memory from nqmo/ like the panel's;
    None when the tree has no engine."""
    if not os.path.isfile(os.path.join(ROOT, "nqmo", "__main__.py")):
        return None
    spec = importlib.util.spec_from_file_location(
        "build_nqmo_pyz", os.path.join(ROOT, "tools", "build_nqmo_pyz.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = mod.build_bytes(os.path.join(ROOT, "nqmo"), allow_untracked=True)
    return hashlib.sha256(data).hexdigest()[:12]


def main(argv, changelog=None):
    if len(argv) != 2 or not re.fullmatch(r"v\d+\.\d+\.\d+", argv[1]):
        print("usage: release_notes.py vX.Y.Z", file=sys.stderr)
        return 2
    version = argv[1][1:]
    path = changelog or os.path.join(ROOT, "CHANGELOG.md")
    with open(path, encoding="utf-8") as f:
        body = section(f.read(), version)
    # Private tree only: there CHANGELOG.md is the ops archive and the public
    # changelog lives in publish/. The public tree has no publish/ directory.
    alt = os.path.join(ROOT, "publish", "CHANGELOG.public.md")
    if not body and not changelog and os.path.exists(alt):
        with open(alt, encoding="utf-8") as f:
            body = section(f.read(), version)
    if not body:
        print("CHANGELOG.md has no section for [%s]" % version,
              file=sys.stderr)
        return 1
    print(body)
    print()
    print("---")
    print()
    engine = engine_build_id()
    line = ("Build id: `%s` (first 12 characters of the SHA-256 of "
            "`wg_panel.pyz`; a Docker install prints the same value as its "
            "version)." % panel_build_id())
    if engine:
        line += (" Engine build id: `%s` (the same measure of `wg_nqmo.pyz`)."
                 " Verify the panel download with `sha256sum -c SHA256SUMS`,"
                 " and the engine files (`wg_nqmo.pyz`, `wg-nqmo.service`) with"
                 " `sha256sum -c SHA256SUMS.nqmo`." % engine)
    else:
        line += " Verify the download with `sha256sum -c SHA256SUMS`."
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
