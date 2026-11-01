#!/usr/bin/env python3
"""Build wg_panel.pyz from the wgpanel/ package — deterministically.

Same source ⇒ byte-identical archive on any machine and any CPython ≥ 3.9
(verified 3.9 / 3.11 / 3.14): stored (uncompressed) members, fixed 1980-01-01
timestamps, sorted names, fixed mode. That is what lets sha256(wg_panel.pyz)[:12]
be the build id everywhere: VERSION, drift-check, the ansible role, the docker
tag, release notes.

  python3 tools/build_pyz.py              # → dist/wg_panel.pyz ; prints "<path> <id>"
  python3 tools/build_pyz.py --out PATH   # write PATH instead
  python3 tools/build_pyz.py --src DIR    # package dir (default: <repo>/wgpanel)
  python3 tools/build_pyz.py --id         # print only the 12-hex build id; writes nothing

Untracked files under the package (editor backups, *.orig, *.rej) would silently land in
the archive and change the id, while make-public only publishes git-tracked files. So
inside a git checkout the build refuses them, unless --allow-untracked is passed.
Outside git (docker build, a release tarball) the check is skipped.
"""
import argparse
import hashlib
import io
import os
import stat
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHEBANG = b"#!/usr/bin/env python3\n"
EPOCH = (1980, 1, 1, 0, 0, 0)
ROOT_MAIN = (b"import runpy\n"
             b"runpy.run_module(\"wgpanel\", run_name=\"__main__\", alter_sys=True)\n")


def _info(name):
    zi = zipfile.ZipInfo(name, date_time=EPOCH)
    zi.compress_type = zipfile.ZIP_STORED
    zi.create_system = 3
    zi.external_attr = (stat.S_IFREG | 0o644) << 16
    return zi


def members(src):
    """[(archive_name, absolute_path)], sorted; skips caches and dotfiles."""
    out = []
    parent = os.path.dirname(os.path.abspath(src))
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames
                             if d != "__pycache__" and not d.startswith("."))
        for fn in filenames:
            if fn.startswith(".") or fn.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, fn)
            out.append((os.path.relpath(full, parent).replace(os.sep, "/"), full))
    out.sort()
    return out


def untracked(src):
    """Paths under src that git does not track; [] when src is not in a git checkout."""
    try:
        r = subprocess.run(["git", "-C", src, "ls-files", "--others",
                            "--exclude-standard", "--", "."],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:          # not a git checkout
        return []
    return [p for p in r.stdout.splitlines()
            if p and "__pycache__" not in p and not p.endswith((".pyc", ".pyo"))]


def build_bytes(src):
    src = os.path.abspath(src)
    if os.path.basename(src) != "wgpanel" or not os.path.isfile(
            os.path.join(src, "__main__.py")):
        raise SystemExit("build_pyz: %s is not the wgpanel package" % src)
    buf = io.BytesIO()
    buf.write(SHEBANG)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(_info("__main__.py"), ROOT_MAIN)
        for name, full in members(src):
            with open(full, "rb") as f:
                z.writestr(_info(name), f.read())
    return buf.getvalue()


def build_id(data):
    return hashlib.sha256(data).hexdigest()[:12]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", default=os.path.join(ROOT, "wgpanel"))
    ap.add_argument("--out", default=os.path.join(ROOT, "dist", "wg_panel.pyz"))
    ap.add_argument("--id", action="store_true", help="print the build id only")
    ap.add_argument("--allow-untracked", action="store_true",
                    help="build even if git reports untracked files under --src")
    a = ap.parse_args(argv)
    if not a.allow_untracked:
        stray = untracked(a.src)
        if stray:
            raise SystemExit("build_pyz: untracked files under %s would change the build id:\n  %s\n"
                             "git add them, delete them, or pass --allow-untracked"
                             % (a.src, "\n  ".join(stray)))
    data = build_bytes(a.src)
    if a.id:
        print(build_id(data))
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    tmp = a.out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, a.out)
    print("%s %s" % (a.out, build_id(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
