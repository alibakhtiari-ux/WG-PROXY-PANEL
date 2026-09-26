# Contributing

## The constraint that shapes everything

`wg_panel.py` is a **single file** and uses **only the Python standard
library**. The target servers have no pip and no Docker; air-gapped installs
have no network at all. A patch that adds a dependency cannot be merged,
however good it is. The same rule covers the browser: no CDN, no external
font, no bundler. `three.js`, the QR generator and the Vazirmatn subset are
vendored into the repository for exactly this reason.

Python 3.10 or newer (that is the floor the installers check, chosen so Ubuntu
22.04's system Python works).

The file is over 30,000 lines and about 7,100 of them are the HTML, CSS and
JavaScript of the panel, held as raw Python strings. **Do not read it end to
end.** Use `grep` to find the region you need — the `# ------` separator
comments are its table of contents.

## Building and testing

There is no build step. To run the tests:

```bash
python3 -m unittest discover -s tests
```

That is necessary and **not sufficient**, for one specific reason:

> Python cannot see inside those raw strings. `py_compile` stays green on
> JavaScript with a syntax error, and the failure reaches the user as a **blank
> page** in the browser. The test suite alone will not catch it.

The maintainer's gate is a ten-step battery that also extracts and syntax-checks
every inline script, sweeps `bash -n` over every shell script, and verifies the
install bundles agree. That tooling lives in the maintainer's working tree and
is not part of this repository, so if you are reading this on the public branch
you cannot run it. What you can and should do before proposing a change:

```bash
python3 -m unittest discover -s tests
python3 -m py_compile wg_panel.py
```

and, if you touched anything inside `PAGE_HTML`, `TV3D_JS` or the share-page
template, extract the script and check it yourself:

```bash
python3 - <<'PY' > /tmp/panel.js
import re
src = open('wg_panel.py', encoding='utf-8').read()
print('\n'.join(m.group(1) for m in
      re.finditer(r'<script[^>]*>(.*?)</script>', src, re.S)))
PY
node --check /tmp/panel.js
```

Say in your patch description which of these you ran. "It looks right" is not a
verification; this project's convention is to report the number.

## Conventions

- **The interface is right-to-left.** Any container that may hold Persian text
  needs `direction: rtl` or `unicode-bidi: plaintext`. A `<select>` needs the
  rule on both the element and its `option`s, and new ones need
  `class="rtlsel"` — macOS renders the native dropdown left-aligned otherwise.
- **Quantities render in Persian digits, identifiers stay Latin.** A
  `TreeWalker` converts digits in rendered text; device names, keys, endpoints
  and IPs are excluded so they stay searchable and copyable. New elements that
  must stay Latin get `class="mono"` or `data-ltr`.
- **No hard-coded colors.** Everything is a CSS variable in `:root`, and both
  themes supply values. A dark-theme literal is unreadable in the light theme.
- **User-facing strings live in the `I18N` catalog**, in Persian, English,
  Russian and Chinese — one 4-tuple per key, ordered
  `LANGS = ("fa", "en", "ru", "zh")`. A missing entry fails a test.
- **Code comments and commit messages are in Persian**, matching the rest of the
  repository. Documentation aimed at users is English. If you are more
  comfortable in English throughout, write it in English and say so — a correct
  patch in the wrong language is a much smaller problem than no patch.

## When you fix a bug, guard the family

This is the convention the project cares about most: a fix ships with a test
that catches **the whole family of that bug, not the instance**. If a
timestamp formatter mishandled one locale, the test asserts the behaviour for
every locale in the catalog; if one write path was not atomic, the test looks
for the same shape everywhere it could recur.

Then check the test actually has teeth — run it against the code *before* your
fix and confirm it fails. A guard that passes on the broken version is not a
guard, and this repository has shipped that mistake more than once (twice by
matching a comment that described the trap rather than the code that contained
it; strip comment lines before any textual assertion).

## Notes for maintainers of this deployment

These do not apply to the public repository, only to the working tree that
carries the ansible role and the three install bundles:

- After changing `wg_panel.py`, run `ansible/sync-files.sh`, or the bundle
  synchronization test goes red. Five copies of the file must agree.
- The version identifier is the first 12 characters of `sha256(wg_panel.py)`,
  so any change to the file — including a comment — moves it.
