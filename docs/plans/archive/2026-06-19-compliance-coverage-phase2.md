# Compliance Coverage: Phase 2 Design Proposal

> **Status:** IMPLEMENTED (2026-06-20). Option B adopted as recommended; coverage
> is plugin-declared via `coverage()` per plugin, aggregated by
> `hardener_plugins::compliance_coverage()` and injected into `ReportGenerator`.
> Non-CIS catalogues are derived from coverage (hand-written `stig/nist/pci/hipaa/
> gdpr.rs` deleted); CIS + ISO 27001 stay curated. Checked-passing controls now
> report `Pass` for every framework.
> **Date:** 2026-06-19 · **Author:** maintainer
> **Superseded API:** the phase-1 `frameworks::AUTOMATED_FRAMEWORKS`/`is_automated`
> flag is removed in favour of per-control coverage.

## 1. Problem

Compliance control pass/fail is derived from scan findings, and every plugin
tags its findings with **CIS Benchmark** control IDs only. Phase 1 stopped the
false-`Pass` problem by reporting controls of unassessed frameworks as
`ManualReview`. Phase 2 gives findings **real multi-framework mappings** so
STIG, NIST 800-53, PCI-DSS, HIPAA and GDPR genuinely pass/fail.

The blocker is that phase-1 coverage is tracked at **framework granularity**
(`AUTOMATED_FRAMEWORKS = [CIS]`). The moment a framework is partially mapped,
framework-level granularity is wrong: unmapped controls of that framework would
revert to a false `Pass`. Phase 2 must move to **per-control coverage**.

## 2. Coverage model: DECISION NEEDED

How does the generator know a control was actually assessed (→ `Pass`/`Fail`)
versus not (→ `ManualReview`)? A clean scan emits no findings, so "no finding"
alone cannot mean "assessed and passing".

| Option | Mechanism | Verdict |
|--------|-----------|---------|
| **A. Derive from findings** | Assessed = frameworks/controls present in this scan's findings | ❌ A clean system has no findings → everything looks unassessed. Breaks `Pass`. |
| **B. Plugin-declared coverage** | Each plugin declares the `(framework, control_id)` set it assesses; generator marks those `Pass`/`Fail`, the rest `ManualReview` | ✅ **Recommended.** Correct for clean systems; partial coverage is honest; coverage grows as mappings are added. |
| **C. Stay framework-level** | Only add a framework to `AUTOMATED_FRAMEWORKS` once *fully* covered | ❌ All-or-nothing; blocks incremental per-control rollout. |

**Recommendation: Option B.** It is the only model that stays honest under
partial coverage, which is the realistic rollout path.

## 3. Mechanism (if Option B is chosen)

- **No signature change to mappings:** each plugin's `get_*_compliance_mappings(key)`
  already returns `Vec<ComplianceMapping>`; phase 2 simply returns *more than one*
  framework per check.
- **Coverage set:** the union of every `(framework, control_id)` any plugin can
  emit = the assessed-coverage set. Two ways to expose it to the generator
  (which lives in `hardener-compliance`, and must not depend on `hardener-plugins`):
  1. Add `fn compliance_coverage(&self) -> Vec<ComplianceMapping>` to the
     `HardeningPlugin` trait (default `vec![]`); aggregate in `hardener-plugins`;
     the CLI/Tauri/scheduler (which build the registry) pass the set into
     `ReportGenerator`. **Preferred**: single source of truth, no duplication.
  2. A static table in `hardener-compliance`. Rejected: duplicates plugin knowledge.
- **Generator change:** `ManualReview` only when the control's `(framework, id)`
  is **not** in the coverage set; otherwise `Pass`/`Fail` as today. Replaces the
  framework-level `is_automated()` check.

## 4. Crosswalk data: sourcing strategy (do NOT hand-invent)

Wrong mappings re-introduce false compliance, so mappings must come from
authoritative sources and be reviewed, not guessed.

- **Primary: [ComplianceAsCode/SSG](https://github.com/ComplianceAsCode/content)**
  maps each concrete rule (e.g. `sshd_disable_root_login`) to CIS Benchmark,
  DISA STIG/SRG, NIST 800-53, PCI-DSS simultaneously. This matches our model
  (findings keyed by concrete check), so it is the right source for STIG/NIST/PCI.
- **Control-level:** [CIS Controls v8.1 → NIST SP 800-53 Rev 5](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mapping-to-nist-sp-800-53-rev-5)
  and the NIST OLIR program (standardised crosswalk format). Note: these map CIS
  *Controls* (Safeguards), not CIS *Benchmark* line items: secondary reference only.
- **HIPAA / GDPR:** no line-item technical crosswalk exists; mappings are
  interpretive (e.g. HIPAA §164.312 ↔ access/audit controls). Mark **low
  confidence**, keep coarse, and require explicit review.
- **Rule:** every new mapping cites its SSG rule id / source in a comment.

## 5. Incremental rollout (reviewable portions)

1. Implement Option B mechanism (trait method + generator + tests): no mappings yet; behaviour unchanged.
2. Per plugin, add sourced mappings (start with SSH, then kernel, then the rest): one PR-sized portion each, reviewed against SSG.
3. Add each newly-covered `(framework, control_id)` to coverage automatically via the trait method (no `AUTOMATED_FRAMEWORKS` edit needed).
4. Once a framework is meaningfully covered, surface it in the report wizard / docs.
5. ISO/IEC 27001:2022 catalogue (`iso27001.rs`, 93 Annex A controls) lands here, mapped via SSG's ISO references where available.

## 6. Risks

- **Mapping accuracy is paramount**: a wrong mapping is worse than `ManualReview`. Review every mapping against SSG; prefer omission over a guess.
- **SSG rule ↔ our check alignment**: our checks must correspond to the SSG rule whose mappings we borrow; verify per check.
- **Catalogue vs coverage drift**: a framework's catalogue (`get_controls`) and its assessed set must be reconciled; controls in the catalogue but never assessed stay `ManualReview` (correct).

## 7. Decision requested

1. Approve **Option B** (per-control, plugin-declared coverage)?
2. Approve **ComplianceAsCode/SSG** as the primary mapping source?
3. Start order for §5 step 2 (proposed: SSH → kernel → firewall → PAM → services → audit → permissions → MAC)?

Sources: [CIS Controls v8.1 → NIST 800-53 r5](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mapping-to-nist-sp-800-53-rev-5), [CIS Controls v8 → NIST CSF 2.0](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-mapping-to-nist-csf-2-0), [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content).
