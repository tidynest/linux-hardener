# Session Handoff — 2026-06-19

> **Read this first.** Point-in-time handoff for the next development session and
> assistant. Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md).
> Project is **v1.0.5**.

---

## TL;DR

A long compliance bug was found, proven, and fully fixed across phases 1–3
(honest status → multi-framework mappings → derive catalogues + Option B), and
SSH crypto hardening was added. **All work has been merged into `main` locally
and is NOT pushed to any remote.** With the compliance reconciliation now
complete, the next session's agreed top priority is **Multi-host SSH**, followed
by everything else listed under "Remaining work".

> **Update 2026-06-20:** the "Derive + Option B" task below is **DONE** (see
> CHANGELOG *Unreleased* → "Plugin-declared compliance coverage" / "Accurate
> Pass". Coverage is now per-control via `hardener_plugins::compliance_coverage()`
> injected into `ReportGenerator`; non-CIS catalogues are derived from coverage
> and the hand-written `stig/nist/pci/hipaa/gdpr.rs` are deleted; CIS + ISO 27001
> stay curated. Builds + tests + clippy + fmt clean; verified end-to-end with
> `hardener report --framework STIG`. **Next priority is now Multi-host SSH.**

The headline finding: compliance reporting initially assessed CIS only. Every
plugin tagged its findings with CIS control IDs, and the report generator
defaulted any unmapped control to `Pass` — so for STIG / NIST / PCI-DSS / HIPAA /
GDPR the controls reported as passing without the engine having evaluated them.
This had been the behaviour since the first compliance commit (`6596a55`,
2025-11-26) — a coverage limitation in how partial mappings were reported, not a
regression.

---

## What shipped this session (now on `main`, local only)

1. **Honest status fix** — controls the engine doesn't assess now report
   `ManualReview`, never a false `Pass`. `frameworks::AUTOMATED_FRAMEWORKS` (CIS
   only) is the single source of truth for "what is automatically assessed".
2. **Multi-framework mappings** — all 8 plugins now tag findings with **STIG,
   NIST 800-53, PCI-DSS, HIPAA, GDPR and ISO 27001:2022** control IDs alongside
   CIS. So every framework now genuinely fails on insecure systems.
3. **ISO/IEC 27001:2022** — implemented `frameworks/iso27001.rs` (93 Annex A
   controls, 4 themes) and wired it in (was an empty stub).
4. **Generator augmentation** — surfaces finding-referenced controls that aren't
   in a framework's curated catalogue, so mappings using upstream (SSG) id
   schemes still produce real failures (see "Known wrinkles" → catalogue ids).
5. **SSH crypto hardening** — `KexAlgorithms` / `Ciphers` / `MACs` incl.
   post-quantum kex. Auto-detects host support (`ssh -Q kex|cipher|mac`) and
   writes only the strong-allow-list ∩ supported set (no lockout, no downgrade);
   validates with `sshd -t` before any write/restart. Removed obsolete
   `Protocol 2`.
6. **Docs** — CHANGELOG, NEXT, ROADMAP, README, DATA_FLOW, SECURITY,
   DISTRIBUTION_VALIDATION all updated; phase-2 design proposal added.

**Verification at handoff:** `hardener-plugins`, `hardener-compliance`,
`hardener-cli` all build + test + clippy + fmt clean (55 compliance tests, 35
CLI tests, full plugin suite). See "How to verify" below.

---

## Decisions made by the user (apply these next session)

| Topic | Decision |
|-------|----------|
| Catalogue reconciliation | **Derive catalogues from plugin coverage** (one source of truth — not hand-rewrite). |
| Option B (`Pass` for checked-passing) | **Yes, implement it** — pairs with the derive work (same plumbing). |
| Integration of this session's work | **Merge to main, no push** (done). |
| Next priority | **Multi-host SSH**, then all remaining work. |

---

## Start here next session: Derive + Option B (do these together)

These two share one mechanism, so build them as a unit. Design notes:
[docs/plans/2026-06-19-compliance-coverage-phase2.md](docs/plans/2026-06-19-compliance-coverage-phase2.md).

Goal: each non-CIS framework's catalogue should *be* the set of controls the
plugins actually map to (not a separate hand-written list), and a control the
engine checked-and-passed should show `Pass` rather than `ManualReview`.

Suggested approach:
1. Expose plugin coverage — add a way to enumerate every `(framework, control_id,
   title, section)` the plugins can emit (e.g. a `compliance_coverage()` on the
   `HardeningPlugin` trait, or a free function per plugin aggregated in
   `hardener-plugins`). `hardener-compliance` must not depend on
   `hardener-plugins`, so inject the coverage set from the caller (CLI / Tauri /
   scheduler all build the plugin registry) OR confirm the dep direction allows a
   direct call.
2. Derive non-CIS catalogues from that coverage set (replaces the hand-written
   `stig.rs` / `nist.rs` / `pci.rs` / `hipaa.rs` / `gdpr.rs` catalogues — those
   can then be deleted). CIS keeps its curated catalogue.
3. Generator: a control is `Pass`/`Fail` if it is in the coverage set (assessed),
   else `ManualReview`. This makes the catalogue and findings share one id scheme
   (clean reports) **and** gives Option B for free (checked-passing → `Pass`).
4. Keep the safe-failure invariant (below) and update
   `crates/hardener-compliance/tests/assessment_honesty.rs`.

---

## Remaining work (full list — nothing is lost)

In priority order per the user:

1. **Catalogue reconciliation (derive) + Option B** — see above. Do first.
2. **Multi-host SSH** — manage many machines from one place: host list/profiles,
   parallel scanning, per-host history/trends, regression alerts. Single-host
   remote SSH already works (`crates/hardener-core/src/executor/ssh.rs`,
   `crates/hardener-cli/src/ssh_config.rs`, `docs/SSH_REMOTE_SCANNING.md`). This
   is a large feature (data model + UI + orchestration), not a one-pass job.
   Design sketch exists under `docs/superpowers/plans/` (gitignored).
3. **RHEL 10 / per-version profiles** — current STIG/CIS mappings are RHEL-8/SSG
   flavoured and applied generically to the whole Red Hat family. RHEL 10 STIG
   V1R1 (2026-06-02) and CIS RHEL 10 v1.0.1 now exist with different ids.
   Deciding to select benchmark ids per OS version is an architecture choice.
4. **Distro re-validation** — re-run the cross-distro sweep on current releases:
   Debian 13, Fedora 44, RHEL 10, openSUSE Leap 16 (Leap 15 is EOL since Apr
   2026). Needs `systemd-nspawn` containers + root — a human runs this, not the
   agent, on the host.
5. **More frameworks** — SOC 2 and/or FedRAMP (and NIST SP 800-171 alongside
   800-53), following the existing framework pattern.
6. **HIPAA/GDPR mapping accuracy review** — those mappings are interpretive
   (GDPR Art.32 / the project's `TM-*` scheme; HIPAA §164). Worth a review pass.
7. **Routine** — bump `tauri` 2.11.2 → 2.11.3 (no CVE); add an `#[ignore]`
   root integration test for the SSH `apply()` path (still flock-bound).

---

## Architecture the next assistant needs

**Compliance data flow:** scanner → `Finding`s (only failures produce findings).
Each `Finding` carries `finding_compliance: Vec<ComplianceMapping>` tagging the
controls it violates. `ReportGenerator` (`crates/hardener-compliance/src/
generator.rs`) walks each framework's `get_controls()` catalogue and marks each
control `Fail` (a finding maps to it) / `Pass` (no finding **and** framework is
in `AUTOMATED_FRAMEWORKS`) / `ManualReview` (otherwise), plus it appends any
finding-referenced control absent from the catalogue as a `Fail`.

**Key files:**
- `crates/hardener-compliance/src/frameworks/mod.rs` — `AUTOMATED_FRAMEWORKS`,
  `is_automated()`, `get_controls()` dispatch.
- `crates/hardener-compliance/src/generator.rs` — the Pass/Fail/ManualReview
  logic + the non-catalogue augmentation.
- `crates/hardener-compliance/src/frameworks/iso27001.rs` — new 93-control
  catalogue (pattern to follow for SOC 2 / FedRAMP).
- `crates/hardener-plugins/src/*/mod.rs` — each plugin's
  `get_*_compliance_mappings()` is where framework ids are attached to findings.
- `crates/hardener-plugins/src/ssh/mod.rs` — `select_algorithms()` (anti-lockout
  intersection), `supported_algorithms()` (`ssh -Q`), `validate_sshd_config()`
  (`sshd -t`).

---

## Invariants & gotchas (do not break)

- **Safe-failure invariant:** a wrong/imperfect compliance mapping must only ever
  cause a false *failure*, never a false *pass*. Preserve this — it is what makes
  the mappings safe to extend. Prefer omitting a mapping over guessing.
- **Source mappings, don't invent:** control ids come from ComplianceAsCode/SSG
  (`github.com/ComplianceAsCode/content`, the rule `references:` blocks) and the
  project catalogues. Cite the SSG rule id in a `// SSG:` comment.
- **Tauri desktop bin won't build** until the WASM frontend is built
  (`trunk build` → `crates/hardener-ui/dist`). This is pre-existing and unrelated
  to compliance/plugins/CLI, which all build fine. Don't chase it as a regression.
- **`SshHardeningPlugin::apply` is not cleanly unit-testable** — it takes a real
  `std::fs` flock on the real `/etc/ssh/sshd_config`; its only full test is
  `#[ignore]` (root). Test pure helpers with `MockExecutor` instead.
- **British-spelling linter** flags official NIST/ISO control titles
  (e.g. "Authorize Access to Security Functions"). These are kept in the official
  (American) spelling on purpose — fidelity to the standard beats house style.
  The ~90 pre-existing naming warnings are not from this work; the pre-commit
  gate passes with 0 errors.
- **Project conventions:** no AI attribution anywhere (commits/code/comments);
  run `cargo fmt` before commits; use Rust let-chains, never nested `if`;
  British spelling in prose; never run Playwright/GUI tests on the host (nspawn
  containers only).

---

## How to verify

```bash
cargo build  -p hardener-plugins -p hardener-compliance -p hardener-cli
cargo test   -p hardener-plugins -p hardener-compliance -p hardener-cli
cargo clippy -p hardener-plugins -p hardener-compliance --all-targets
cargo fmt --check
```
All should be clean. (A full `cargo build --workspace` fails only on the Tauri
desktop bin for the frontend-dist reason above.)

---

## Git state at handoff

- This session's work (12 commits) was fast-forward **merged into `main` locally**.
- **Nothing is pushed** — `main` is ahead of all remotes; pushing is the user's call.
- The work was developed on worktree branch `worktree-fix+compliance-framework-mapping`
  (now equal to `main`); that worktree can be removed when convenient.
