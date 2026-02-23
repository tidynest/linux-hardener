# hardener-compliance — Crate Audit

**Files:** 17 | **Lines:** 3,120 | **Fixes:** 5 | **Design Flags:** 3

## Purpose

Compliance framework mapping and report generation. Takes scan findings from `hardener-core::Finding` and produces reports in 5 output formats (text, JSON, CSV, HTML, PDF) against 6 compliance frameworks (CIS, STIG, NIST, PCI-DSS, HIPAA, GDPR).

## Architecture

```
ReportConfig (scenario + formats)
        │
        ▼
ReportGenerator ──→ frameworks::get_controls(framework)
        │                     │
        │          ┌──────────┴──────────┐
        │          │ cis │ stig │ nist │ pci │ hipaa │ gdpr │
        │          └──────────┬──────────┘
        │                     │
        │    match findings ←─┘
        │    by (framework, control_id)
        ▼
Vec<ComplianceReport>
        │
        ▼
ReportFormatter trait dispatch
        │
  ┌─────┼─────┬─────┬─────┐
  │     │     │     │     │
 Text  JSON  CSV  HTML   PDF
```

## Module Map

| Module | Lines | Role |
|--------|-------|------|
| `output/pdf.rs` | 707 | PDF generation via krilla library |
| `output/html.rs` | 283 | Styled HTML with embedded CSS |
| `frameworks/cis.rs` | 279 | 34 CIS Benchmark controls |
| `config.rs` | 221 | Scenarios, output formats, report config |
| `frameworks/pci.rs` | 177 | 22 PCI-DSS v4.0 controls |
| `output/csv.rs` | 172 | CSV with field escaping |
| `output/text.rs` | 171 | Plaintext for terminal |
| `report.rs` | 167 | Re-exports types from hardener-types |
| `generator.rs` | 163 | Orchestrator: findings → controls → reports |
| `frameworks/stig.rs` | 156 | 20 DISA STIG controls |
| `output/json.rs` | 153 | JSON with pretty-print option |
| `frameworks/nist.rs` | 151 | 20 NIST 800-53 controls |
| `frameworks/hipaa.rs` | 118 | 14 HIPAA Security Rule controls |
| `frameworks/gdpr.rs` | 105 | 12 GDPR Art.32 controls |
| `lib.rs` | 37 | Crate root, re-exports |
| `output/mod.rs` | 34 | ReportFormatter trait + feature-gated PDF |
| `frameworks/mod.rs` | 26 | Framework dispatch |

## Fixes Applied

| # | File | Fix | Severity |
|---|------|-----|----------|
| 1 | pdf.rs:625 | `truncate_string` byte-based → char-based (UTF-8 panic) | BUG |
| 2 | pdf.rs:163 | Sort comparator `String::new()` allocation → `""` literal | PERF |
| 3 | html.rs:83 | Section name `<h2>` now escaped via `html_escape()` | XSS |
| 4 | html.rs:100 | `control_id` in table now escaped via `html_escape()` | XSS |
| 5 | pci.rs:55 | `"notused"` → `"not used"` typo | TYPO |

## Design Flags (Deferred)

| # | File | Flag |
|---|------|------|
| D1 | pdf.rs:101 | Binary PDF returned as String via Latin-1 char map (trait constraint) |
| D2 | csv.rs:26-106 | `format()` and `format_all()` duplicate ~30 lines of row generation |
| D3 | html.rs:82 | Sections sorted alphabetically (BTreeMap) vs pdf.rs numeric sort |

## Control Coverage

| Framework | Controls | Reference |
|-----------|----------|-----------|
| CIS | 34 | CIS Benchmark v2.0 |
| STIG | 20 | DISA RHEL 8/9 STIG |
| NIST | 20 | NIST 800-53 Rev 5 |
| PCI-DSS | 22 | PCI-DSS v4.0 |
| HIPAA | 14 | 45 CFR 164 |
| GDPR | 12 | Article 32 |
| **Total** | **122** | |
