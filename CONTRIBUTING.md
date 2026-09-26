# Contributing

Thank you for helping. Bug reports, translations and pull requests are all
welcome — in English, Persian, Russian or Chinese.

## The two rules

1. **Standard library only.** `wg_panel.py` must run with nothing but the
   Python standard library. The servers it runs on often have no pip and
   sometimes no internet at all. A patch that adds a dependency cannot be
   merged, however good it is. The same applies in the browser: no CDN, no
   external font, no bundler — `three.js`, the QR generator and the Vazirmatn
   font are bundled in the repository for this reason.
2. **One file.** The whole application stays in `wg_panel.py`, including the
   web interface and all four translations.

The minimum Python version is **3.10** (Ubuntu 22.04's system Python). CI
tests 3.10 and 3.12.

## Finding your way around

`wg_panel.py` is over 30,000 lines, and several thousand of them are the
HTML, CSS and JavaScript of the panel, stored in raw Python strings
(`PAGE_HTML`, `SHARE_HTML`, `TV3D_JS`). Do not read it end to end — use
`grep`; the `# ------` separator comments work as a table of contents.

## Testing

There is no build step. Before opening a pull request, run:

```bash
python3 -m unittest discover -s tests
python3 -m py_compile wg_panel.py
```

That is necessary but **not sufficient**. Python cannot see inside the
JavaScript strings: `py_compile` passes on broken JavaScript, and the user
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
`wg_panel.py` from a temporary folder and redirects every `/etc`, `/var` and
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
`wg_panel.py`, `wg-panel.service`, the bundled `qr.js`, three.js files and
`three.LICENSE.txt`, and `SHA256SUMS`. The notes are that
version's CHANGELOG section plus the build id. A tag without a CHANGELOG
section fails and publishes nothing.

## Conventions

- **Translations.** Every user-facing string lives in the `I18N` catalog in
  `wg_panel.py`, as one 4-tuple per key in the order
  `LANGS = ("fa", "en", "ru", "zh")`. A key missing in any language fails a
  test. If you cannot translate into a language, use English there and say so
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
