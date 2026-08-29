'use strict'
// Regenerates the README status badges as local SVGs under docs/assets/badges/.
// Vendored on purpose: badges served from this repo (like the logo) never depend
// on shields.io being reachable, so they cannot break. Uses shields.io's own
// renderer (badge-maker) offline, so the output matches the flat-square look
// exactly. Run after bumping the value constants below on release:
//   cd scripts/badges && npm install && node generate.js
const fs = require('fs')
const path = require('path')
const makeBadge = require('badge-maker/lib/make-badge') // internal entry: exposes `logo`

const OUT = path.join(__dirname, '..', '..', 'docs', 'assets', 'badges')

const TEAL = '#0f766e'       // message (right) background
const TEAL_TESTS = '#0d9488' // slightly lighter, tests only
const LABEL = '#134e4a'      // label (left) background

// simple-icons glyph -> force white fill -> data URI embedded by badge-maker
const logoURI = name => {
  const svg = fs.readFileSync(path.join(__dirname, `${name}.svg`), 'utf8')
    .replace('<svg ', '<svg fill="#ffffff" ') // path inherits the white fill
  return 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64')
}

// Bump `message` on release for version / aur / tests; the rest are constant.
const BADGES = [
  { file: 'version',  label: 'version',  message: '1.7.0',      color: TEAL },
  { file: 'license',  label: 'license',  message: 'Apache-2.0', color: TEAL },
  { file: 'rust',     label: 'rust',     message: '1.88+',      color: TEAL,       logo: 'rust' },
  { file: 'aur',      label: 'AUR',      message: '1.6.0',      color: TEAL,       logo: 'archlinux' },
  { file: 'platform', label: 'platform', message: 'Linux',      color: TEAL,       logo: 'linux' },
  { file: 'tests',    label: 'tests',    message: '2314+',      color: TEAL_TESTS },
]

fs.mkdirSync(OUT, { recursive: true })
for (const b of BADGES) {
  const svg = makeBadge({
    style: 'flat-square',
    label: b.label,
    message: b.message,
    color: b.color,
    labelColor: LABEL,
    ...(b.logo ? { logo: logoURI(b.logo) } : {}),
  })
  fs.writeFileSync(path.join(OUT, `${b.file}.svg`), svg)
  console.log(`docs/assets/badges/${b.file}.svg  ${svg.match(/width="(\d+)"/)[1]}px`)
}
