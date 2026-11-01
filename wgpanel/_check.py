"""`python3 wg_panel.pyz --check` — offline self-test of a build.

Compiles every .py member and checks required members exist. It never imports
wgpanel.app: no traffic.db, no threads, no config read. Safe to run on a live
server next to a running panel. Exit 0 and one line starting CHECK_OK on success.
"""
import json
import os
import sys
import zipfile

REQUIRED = ("wgpanel/__init__.py", "wgpanel/__main__.py",
            "wgpanel/_check.py", "wgpanel/app.py",
            "wgpanel/i18n/catalog.json",
            "wgpanel/web/page.html", "wgpanel/web/share.html",
            "wgpanel/web/tv3d.mjs",
            "wgpanel/web/fonts/vazirmatn-400.woff2",
            "wgpanel/web/fonts/vazirmatn-700.woff2")
CATALOG = "wgpanel/i18n/catalog.json"
LANG_COUNT = 4  # fa, en, ru, zh — همان LANGS در app.py (app.py در --check import نمی‌شود)


def _catalog_errors(raw):
    """کلیدِ تکراری یا ردیفِ بدشکل در catalog.json را گزارش می‌دهد (بدونِ import ِ app)."""
    errs = []

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                errs.append("catalog: duplicate key %r" % k)
            out[k] = v
        return out
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError) as e:
        return ["catalog: not valid JSON: %s" % e]
    if not isinstance(data, dict):
        return ["catalog: top level is not an object"]
    for k, v in data.items():
        if (not isinstance(v, list) or len(v) != LANG_COUNT
                or not all(isinstance(x, str) for x in v)):
            errs.append("catalog: malformed row %r" % k)
    return errs


def _members():
    archive = getattr(globals().get("__loader__"), "archive", None)
    if archive:  # running from wg_panel.pyz (zipimporter)
        with zipfile.ZipFile(archive) as z:
            return archive, {n: z.read(n) for n in z.namelist()}
    pkg = os.path.dirname(os.path.abspath(__file__))
    base = os.path.dirname(pkg)
    out = {}
    for dirpath, dirnames, filenames in os.walk(pkg):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            with open(full, "rb") as f:
                out[os.path.relpath(full, base).replace(os.sep, "/")] = f.read()
    return pkg, out


def main():
    where, files = _members()
    errors = ["missing member: " + r for r in REQUIRED if r not in files]
    n = 0
    for name in sorted(files):
        if name.endswith(".py"):
            try:
                compile(files[name], name, "exec")
                n += 1
            except (SyntaxError, ValueError) as e:
                errors.append("does not compile: %s: %s" % (name, e))
    if CATALOG in files:
        errors.extend(_catalog_errors(files[CATALOG]))
    if errors:
        print("CHECK_FAIL %s" % where, file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    print("CHECK_OK %d python files (%s)" % (n, where))
    return 0
