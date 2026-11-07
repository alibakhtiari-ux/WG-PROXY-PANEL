# Contributing

Thank you for helping. Bug reports, translations and pull requests are all
welcome — in English, Persian, Russian or Chinese.

## The two rules

1. **Standard library only.** The panel (`wgpanel/`) must run with nothing but the
   Python standard library. The servers it runs on often have no pip and
   sometimes no internet at all. A patch that adds a dependency cannot be
   merged, however good it is. The same applies in the browser: no CDN, no
   external font, no bundler — `three.js`, the QR generator and the Vazirmatn
   font are bundled in the repository for this reason.
2. **One deployable file.** The panel is the `wgpanel/` package, and
   `tools/build_pyz.py` bundles it into `wg_panel.pyz` deterministically (same
   source, same bytes). Nothing the panel needs at runtime may live outside
   `wgpanel/`, except the static assets it serves from `BASE_DIR`. The build
   tool and `--check` must stay standard-library only.

The minimum Python version is **3.10** (Ubuntu 22.04's system Python). CI
tests 3.10 and 3.12.

## Finding your way around

The panel code is `wgpanel/app.py` (about 17,000 lines of Python). Do not read
it end to end — use `grep`; the `# ------` separator comments work as a table
of contents. The web interface and the translations are ordinary files:
`wgpanel/web/page.html` (the panel: HTML, CSS and JavaScript),
`wgpanel/web/share.html` (the share page), `wgpanel/web/tv3d.mjs` (the 3-D TV
scene), `wgpanel/web/fonts/` (the two Vazirmatn fonts, inlined at render time)
and `wgpanel/i18n/catalog.json` (the translations). All of them are bundled
into `wg_panel.pyz` automatically. (`wg_panel.py` in the repository root is only the 20-line launcher.)

## Testing

Users need no build step; contributors build the archive. Before opening a pull request, run:

```bash
python3 -m unittest discover -s tests
python3 tools/build_pyz.py && python3 dist/wg_panel.pyz --check
python3 tools/build_nqmo_pyz.py && python3 -I dist/wg_nqmo.pyz --check
```

That is necessary but **not sufficient**. Python cannot see inside the
JavaScript files: `py_compile` and the archive self-test pass on broken JavaScript, and the user
gets a **blank page** in the browser. If you changed anything in the web
interface, also check the JavaScript syntax (needs Node.js):

```bash
python3 tests/check_js.py
```

It prints `0 failed` when every script parses; CI runs the same check. Then
open the panel, use the part you changed, and check the browser console.

In your pull request, say which of these checks you ran and what they
reported.

## Trying a change without a server

`python3 demo/run.py` starts the panel at `http://127.0.0.1:8787` (user
`admin`, password `demo`) with made-up clients, an egress tunnel, six months of
traffic history, gauges, speed tests and audit events. It loads a copy of
the panel from a temporary folder and redirects every `/etc`, `/var` and
`/opt` path into it. It also puts fake versions of `wg`, `ip`, `systemctl`
and every other program the panel calls in front of the real ones, and
listens only on localhost. It needs no WireGuard and no root.
`--reset` throws the data away and seeds it again.

If you add a call to a new system program, add it to `TOOLS` in
`demo/run.py`: `tests/test_demo.py` fails otherwise, because the demo would
run the real program.

If a change alters how the interface looks, regenerate the screenshots:

```bash
python3 demo/screenshots.py
```

This needs Node.js and Playwright (`npm install playwright`); if Pillow is
installed, the images are compressed.

## Releasing

1. Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a new
   `## [X.Y.Z] — date` section, and add its link at the bottom.
2. Merge that to `main`, then tag it:

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

The release workflow runs the tests again and publishes a GitHub release with
`wg_panel.pyz`, its launcher `wg_panel.py`, `wg-panel.service`, the bundled
`qr.js`, three.js files and `three.LICENSE.txt`, and `SHA256SUMS`. The notes are that
version's CHANGELOG section plus the build id. A tag without a CHANGELOG
section fails and publishes nothing.

## Conventions

- **Translations.** Every user-facing string lives in
  `wgpanel/i18n/catalog.json`: one line per key, whose value is the list
  `[fa, en, ru, zh]` (the order of `LANGS`). To add a key, add one line in
  that form; a duplicate key or a row that is not four strings fails at import
  and in `python3 dist/wg_panel.pyz --check`, and a key missing in any
  language fails a test. If you cannot translate into a language, use English there and say so
  in the pull request.
- **Translated text is never data.** Store and compare stable codes, not
  translated strings — in the database, in metric labels and in audit rows.
- **Right-to-left.** Persian pages are right-to-left, the others
  left-to-right. Use logical CSS properties (`margin-inline-start`,
  `text-align: start`, …) instead of `left`/`right`. A `<select>` that can
  show Persian needs `direction` and `text-align` on both the element and its
  `option`s.
- **Digits and identifiers.** Quantities are shown in Persian digits only in
  Persian. Identifiers — client names, keys, endpoints, IP addresses — stay in
  Latin script in every language. Elements that must stay Latin get
  `class="mono"` or `data-ltr`.
- **Colors.** No hard-coded colors: use the CSS variables in `:root`, which
  both the dark and the light theme define.
- **Test data.** Use RFC 5737 documentation addresses (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`, never real hosts.
- **Language of code comments.** Existing comments and commit messages are
  mostly in Persian. English is equally welcome.

## When you fix a bug, guard the whole family

A fix should come with a test that catches **the whole family of that bug,
not just the one case**. If a formatter broke one language, test every
language; if one write path was not atomic, look for the same pattern
everywhere it could appear.

Then make sure the test really works: run it against the code *before* your
fix and confirm that it fails. A test that also passes on the broken code does
not protect anything.

## Reporting security issues

Please do not open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md).
