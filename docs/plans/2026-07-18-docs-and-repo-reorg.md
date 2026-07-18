# Documentation and Repository Reorganisation Plan

**Last Updated**: 2026-07-18
**Status**: Phases 1 to 4 executed 2026-07-18 (branches `chore/docs-reorg-phase1`, `chore/scripts-consolidate`, `chore/scripts-regroup`, `chore/docs-phase2-content`, `chore/packaging-layout`), with one maintainer override: `ROADMAP.md` and `NEXT.md` moved to `docs/` rather than staying at root. Still open: the `linux-hardener` vs `linux-system-hardener` naming decision (breaking for installed unit and action ids; needs its own scoped change), the fonts-in-src relocation, and runtime verification of the consolidated container and polkit scripts (needs sudo and live sessions).

This plan is the deliverable of a full audit of every markdown doc and of the
non-code file structure. It proposes a staged reorganisation of `docs/` and the
repository layout. Execute one phase at a time, on its own branch, reviewing the
diff before merging. The "Already done" section at the end lists the small
fix-now items that were applied in the same session that produced this plan.

## Guiding decisions

1. **Single source per topic.** Where the same content lives in several files
   (install, CLI usage, release process, roadmap), one file is authoritative and
   the others link to it. This is the biggest source of drift today.
2. **Archive, do not delete.** Completed plans, resolved audits, and superseded
   design docs move to an `archive/` area rather than being removed, preserving
   the record.
3. **GitHub-convention files stay at root.** `README.md`, `CHANGELOG.md`,
   `CONTRIBUTING.md`, `SECURITY.md` remain where tooling and contributors expect
   them. `ROADMAP.md` and `NEXT.md` also stay at root by preference.
4. **Moves are link-breaking.** Every move needs a follow-up pass to fix
   references in `README.md`, `docs/FILE_MAP.md`, the `scripts/validate_*.py`
   validators (several hard-code doc paths), and cross-doc links. Phase 4 covers
   this and must run before any moved state is pushed.
5. **British spelling and no em/en dashes** apply to everything written here and
   to any doc touched during execution (the dash rule is now enforced by
   `scripts/validate_naming.py`).

## Phase 1: docs/ directory restructure

Target layout:

```
docs/
  README.md                 (NEW: index / table of contents)
  guide/                    end-user task docs
  reference/                stable reference material
  architecture/             system internals
  contributing/             developer workflow and standards
  design/                   living design docs
  plans/  plans/archive/    planning (keep as-is)
  security/  security/archive/   audit records
```

Move list (from -> to). Paths that do not move are omitted.

**End-user guide**
- `docs/INSTALL.md` -> `docs/guide/installation.md` (canonical install source)
- `docs/SSH_REMOTE_SCANNING.md` -> `docs/guide/ssh-remote-scanning.md`
- `docs/de-compatibility.md` -> `docs/guide/desktop-environment-compatibility.md`
  (also fixes the lowercase-name inconsistency with its siblings)

**Reference**
- `docs/commands/cli.md` -> `docs/reference/cli.md`
- `docs/NAMING_CONVENTIONS.md` -> `docs/reference/naming-conventions.md`
- `docs/FILE_MAP.md` -> `docs/reference/file-map.md`
- `docs/DATA_FLOW.md` -> `docs/reference/data-flow.md`
- `docs/DISTRIBUTION_VALIDATION.md` -> `docs/reference/distribution-validation.md`

**Architecture**
- `docs/architecture/ARCHITECTURE.md` -> `docs/architecture/architecture.md`
  (lowercase for consistency; optional)

**Contributing (developer workflow)**
- `docs/commands/building.md` -> `docs/contributing/building.md`
- `docs/commands/testing.md` -> `docs/contributing/testing.md`
- `docs/commands/documentation.md` -> `docs/contributing/documentation.md`
- Merge `docs/commands/releasing.md` + `docs/RELEASING.md` ->
  `docs/contributing/releasing.md` (single source; the thin command wrapper
  already only points back at RELEASING.md)

**Design (living)**
- `docs/THEME_DESIGN_GUIDE.md` -> `docs/design/theming.md`

**Plans (archive the finished ones)**
- `docs/plans/2026-06-19-compliance-coverage-phase2.md` -> `docs/plans/archive/`
  (self-declared IMPLEMENTED, currently misfiled at the plans root)
- `docs/plans/remaining-work.md` -> `docs/plans/archive/` (self-declared
  Superseded 2026-06-19)
- `docs/GUI_CLI_PARITY_PLAN.md` -> `docs/plans/archive/2026-02-24-gui-cli-parity.md`
  (Complete plan living outside plans/)
- `docs/CONFIG_DESIGN.md` -> `docs/plans/archive/` (2025-12 draft, superseded by
  the shipped config system and `data-flow.md`; see the new configuration
  reference in Phase 2)

**Security records**
- `docs/security-audit/` -> `docs/security/`
- The 2026-02-25 internal audit set (`SECURITY_AUDIT_REPORT.md`,
  `REMEDIATION_TRACKER.md`, `THREAT_MODEL.md`, and the five `domain/*.md`) ->
  `docs/security/archive/2026-02-25-internal-audit/` (all 53 findings resolved)
- `docs/security-audit/EXTERNAL_AUDIT_SCOPE.md` ->
  `docs/security/external-audit-scope.md` (the only forward-looking file, stays
  live)

## Phase 2: content consolidation and gap-filling

Single-source consolidations (remove the duplicate, leave a pointer):
- **Install**: README keeps a short quickstart and links to the guide.
  (README build/dev blocks and an AUR->guide pointer were already trimmed; see
  "Already done".) Fold `packaging/docker/README.md` usage into the install
  guide's Docker section and keep only a short build-context stub beside the
  Dockerfile.
- **CLI usage**: README §Usage links to `reference/cli.md` instead of restating
  the command surface.
- **Release process**: one `contributing/releasing.md`; the `scripts/README.md`
  release section links to it.
- **Roadmap**: README §Roadmap links to `ROADMAP.md` rather than re-listing the
  same version milestones.

New docs to fill gaps:
- `docs/README.md`: an index mapping guide / reference / architecture /
  contributing, so discovery does not depend on the 1700-line root README.
- `docs/guide/getting-started.md`: an end-user task guide (scan, review, apply,
  rollback), extracted from the README usage and configuration sections.
- `docs/guide/troubleshooting.md`: consolidate the troubleshooting content
  currently split across the install guide and the desktop-environment doc.
- `docs/reference/configuration.md`: a real config reference (supersedes
  `CONFIG_DESIGN.md`), since config is currently documented only inside the
  README.
- `docs/contributing/plugin-authoring.md`: a "how to write a plugin" guide, which
  the plugin-based architecture currently lacks.

## Phase 3: non-documentation cleanup

**Root clutter (packaging inputs currently at root):**
- `data/` -> `packaging/assets/` (holds the `.policy`, `.desktop`, the
  `hardener.1` manpage, and `config.toml.example`)
- `systemd/` -> `packaging/systemd/` (`linux-hardener.service` and `.timer`)
- These moves touch install paths in `PKGBUILD`, the rpm spec, debian rules,
  the systemd install command, and the docs that reference `data/...`; treat as
  a coordinated packaging change, verified against a package build.

**scripts/ grouping** (31 files, flat). Proposed subdirectories: (executed 2026-07-18)
- `scripts/containers/` : the five `create-*-container.sh` plus
  `boot-ssh-test-container.sh`
- `scripts/test/` : the cross-distro, package, and root/full suites
- `scripts/test/gui/` : the GUI and Tauri runners and inner scripts
- `scripts/test/polkit/` : the six `test-polkit-*.sh` plus the matrix driver
- `scripts/validate/` : the seven `validate_*.py` plus `update_all_docs.py`
- `scripts/release/`, `scripts/dev/` : `release.sh`, `tauri-dev.sh`
- Also move `gui-tests/tauri-functional-test.sh` and
  `gui-tests/tauri-ux-test.sh` under `scripts/test/gui/` so all shell test
  scripts share one home.

**De-duplication candidates in scripts/ (investigate, do not blindly merge):**
- Five near-identical `create-*-container.sh` could collapse to one
  `create-container.sh <distro>`. (executed 2026-07-18)
- Six per-desktop `test-polkit-*.sh` could become one parametrised script driven
  by the existing matrix runner. (executed 2026-07-18 as `test-polkit.sh
  <desktop>`; the matrix driver and agent detector stay separate)
- The serial/parallel pairs (`run-gui-tests` / `-parallel`, `run-cross-distro`
  / `-parallel`) duplicate setup and could become a `--parallel` flag.
  (executed 2026-07-18)
- `gui-test-inner.sh` and `tauri-gui-test-inner.sh` likely share a large body
  worth factoring. Confirm the web-UI GUI runner is not legacy now that the
  product is Tauri-first.

**Tracked-but-review:**
- `crates/hardener-core/.gitignore` contains only `/target`, redundant with the
  root ignore; delete it.
- `crates/hardener-compliance/src/fonts/NotoSans-*.ttf` are vendored binaries
  inside `src/`; consider `assets/fonts/` and confirm the OFL licence is noted.
- `src-tauri/gen/schemas/*.json` and `src-tauri/permissions/autogenerated/*.toml`
  are Tauri-generated but committed (Tauri convention). Mark them
  `linguist-generated` in `.gitattributes` so they stop cluttering diffs.

**Naming stems (review, some are intentional):**
- The product appears as `linux-system-hardener` (packaging, repo),
  `linux-hardener` (systemd unit, desktop entry, manpage), `hardener` (binary),
  and two reverse-DNS ids: polkit `com.tidynest.linux-hardener` and Tauri
  bundle `com.ericjingryd.linux-hardener`. The two reverse-DNS ids are
  deliberately different namespaces (documented in the desktop-environment doc)
  and must not be "unified". The `linux-hardener` vs `linux-system-hardener`
  split is worth a conscious decision, but changing installed unit or action ids
  is a breaking change for existing installs; scope carefully.
- Shell scripts use hyphens, Python scripts use underscores. This split is clean
  along language lines; if kept, state it explicitly in
  `reference/naming-conventions.md`.
- Doc filenames mix `SCREAMING_SNAKE.md` and `kebab-case.md`. The Phase 1 moves
  standardise most of these to lowercase-hyphen; apply the same rule to any
  remaining outliers.

## Phase 4: link and tooling fixes (run with each move, before pushing)

- Update every intra-repo link to a moved doc: `README.md`, `docs/FILE_MAP.md`
  (now `reference/file-map.md`), cross-doc links, and the new `docs/README.md`
  index.
- Update hard-coded doc paths in `scripts/validate_*.py`
  (`validate_cli_docs.py`, `validate_compliance_docs.py`, `validate_file_map.py`,
  `validate_last_updated.py`, `validate_tauri_docs.py`) and in
  `scripts/update_all_docs.py`; `validate_last_updated.py` in particular globs
  `docs/*.md` and will need to recurse into the new subdirectories.
- Re-run the full validator suite after each phase and fix what moves broke.

## Risks and sequencing

- Do Phase 1 (pure moves) and Phase 4 (link fixes) together as one reviewable
  change; a half-moved tree with dangling links is worse than either state.
- Phase 2 (content rewrites) is the highest-effort and most subjective; do it
  after the structure settles.
- Phase 3 packaging moves (`data/`, `systemd/`) must be validated against an
  actual package build (`PKGBUILD`, rpm, deb) because they change install paths.
- Keep each phase on its own branch; the naming validator and the doc validators
  are the guard rails for "did a move break a reference".

## Already done (this session, on `chore/docs-sweep`)

These were low-risk fix-now items applied while auditing; they are not part of
the phased proposal above and need no further approval:
- `SECURITY.md` supported-versions table corrected (1.1.x -> 1.2.x latest).
- `Last Updated` markers added to `INSTALL.md`, `DISTRIBUTION_VALIDATION.md`,
  `de-compatibility.md`, and `HANDOFF.md`; `HANDOFF.md` moved to `.gitignore`
  (kept on disk as a local dev note).
- README install/build/dev blocks trimmed to a quickstart plus pointers to
  `docs/INSTALL.md`, `docs/commands/building.md`, and `scripts/README.md`
  (partial single-sourcing; the guide-directory move in Phase 1 completes it).
- README CLI examples added for `checkpoint delete`, `history trends`,
  `history regressions`, and the global `--quiet` flag.

## Future consideration: architecture visualisation

The README architecture diagram was restructured into layered subgraphs with the
`common`/`types` edges thinned into a caption, which is a clear improvement, but
the two binaries (`hardener-cli` and `linux-hardener-desktop`) each fan out to
six domain crates, so the Binaries-to-Domain band still reads as a bundle of
crossing edges. Mermaid's default routing has limited control here. Worth
evaluating, not urgent:
- Mermaid's `flowchart-elk` renderer for better edge routing (confirm GitHub and
  GitLab both render it before committing).
- A hand-authored SVG diagram (full control over layout and edge routing, at the
  cost of manual upkeep when the crate graph changes).
- Splitting into two smaller diagrams (a high-level layer view, plus a detailed
  per-crate dependency view) rather than one graph carrying every edge.
- A generated dependency graph (for example `cargo depgraph`) checked in as an
  image, regenerated on release.

## Open questions for the maintainer

1. Root planning docs: keep `ROADMAP.md` and `NEXT.md` at root (current plan), or
   move them under `docs/`? `HANDOFF.md` is now gitignored.
2. `linux-hardener` vs `linux-system-hardener` naming: unify the user-visible
   name, or accept the split as install-compatibility baggage?
3. Aggressiveness of scripts/ de-duplication in Phase 3: consolidate the
   container and polkit script families now, or leave them and only regroup into
   subdirectories?
4. Is the web-UI (non-Tauri) GUI test path still needed, or can those runners be
   retired?
