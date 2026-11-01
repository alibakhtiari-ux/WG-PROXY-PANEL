## What this changes

<!-- A short description, and the issue it fixes if there is one (Fixes #…). -->

## Checklist

- [ ] Only the Python standard library is used, and everything the panel needs at runtime stays inside `wgpanel/`
- [ ] `python3 -m unittest discover -s tests` passes
- [ ] `python3 tools/build_pyz.py && python3 dist/wg_panel.pyz --check` passes
- [ ] If the web interface changed: the JavaScript check from CONTRIBUTING.md passes and the browser console shows no errors
- [ ] New user-facing text is in the `I18N` catalog in all four languages
- [ ] A bug fix comes with a test that fails without the fix
- [ ] No real IP addresses, keys, tokens or hostnames in code, tests or screenshots

## Checks I ran

<!-- Paste the result lines, for example "Ran 715 tests … OK". -->
