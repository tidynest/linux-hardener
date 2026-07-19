# README status badges

The README status badges are **vendored**: rendered once to local SVGs under
`docs/assets/badges/` and served from this repository. Because GitHub serves
them from the repo itself (the same way it serves `docs/assets/logo.svg`), they
never depend on `shields.io` being reachable and cannot break.

Only the CI badge stays remote: it uses GitHub's native
`actions/workflows/ci.yml/badge.svg` because it reports live build status, which
a frozen SVG could not.

## Regenerating

`generate.js` uses shields.io's own renderer (`badge-maker`) offline, so the
output matches the flat-square look exactly, including the white simple-icons
glyphs embedded from `rust.svg`, `linux.svg` and `archlinux.svg` in this folder.

```sh
cd scripts/badges
npm install      # fetches badge-maker (dev only, never committed)
node generate.js # rewrites docs/assets/badges/*.svg
```

## When to run it

Three badges carry values that change; bump their `message` in `generate.js`
before regenerating:

| Badge      | Changes on              |
|------------|-------------------------|
| `version`  | every release           |
| `aur`      | every AUR package update |
| `tests`    | when the test count moves |

`license`, `rust` and `platform` are constant and normally never need a rebuild.
The teal palette (`#134e4a` label, `#0f766e` body, `#0d9488` tests) lives at the
top of `generate.js`.
