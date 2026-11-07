#!/usr/bin/env python3
"""Build wg_nqmo.pyz from the nqmo/ package — deterministically.

Same rules as tools/build_pyz.py (stored members, fixed timestamps, sorted
names, refuses untracked files inside a git checkout) and the same build-id
convention: sha256(wg_nqmo.pyz)[:12].

  python3 tools/build_nqmo_pyz.py              # → dist/wg_nqmo.pyz ; prints "<path> <id>"
  python3 tools/build_nqmo_pyz.py --out PATH
  python3 tools/build_nqmo_pyz.py --id         # print only the build id
  python3 tools/build_nqmo_pyz.py --allow-untracked
"""
import argparse
import hashlib
import io
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_pyz  # noqa: E402  (shared deterministic-zip helpers)

ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "nqmo")
ROOT_MAIN = (b"import runpy\n"
             b"runpy.run_module(\"nqmo\", run_name=\"__main__\", alter_sys=True)\n")


def build_bytes(src=SRC, allow_untracked=False):
    src = os.path.abspath(src)
    if os.path.basename(src) != "nqmo" or not os.path.isfile(os.path.join(src, "__main__.py")):
        raise SystemExit("build_nqmo_pyz: %s is not the nqmo package" % src)
    if not allow_untracked:
        extra = build_pyz.untracked(src)
        if extra:
            raise SystemExit("build_nqmo_pyz: untracked files in package: %s "
                             "(commit them or pass --allow-untracked)" % ", ".join(extra))
    buf = io.BytesIO()
    buf.write(build_pyz.SHEBANG)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(build_pyz._info("__main__.py"), ROOT_MAIN)
        for name, full in build_pyz.members(src):
            with open(full, "rb") as f:
                z.writestr(build_pyz._info(name), f.read())
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "dist", "wg_nqmo.pyz"))
    ap.add_argument("--id", action="store_true")
    ap.add_argument("--allow-untracked", action="store_true")
    a = ap.parse_args()
    data = build_bytes(allow_untracked=a.allow_untracked)
    bid = hashlib.sha256(data).hexdigest()[:12]
    if a.id:
        print(bid)
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(data)
    os.chmod(a.out, 0o644)
    print(a.out, bid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
