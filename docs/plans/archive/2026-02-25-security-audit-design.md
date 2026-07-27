# Security Audit Design: 2026-02-25

## Goal

Comprehensive internal security audit combining threat modelling with targeted code review. Produces a formal report suitable as foundation for third-party review (v1.0.0 prerequisite).

## Approach

**Threat model first, then targeted code review** of highest-risk areas. Document everything first, fix after: full picture before any code changes.

## Deliverables

```
docs/security-audit/
├── THREAT_MODEL.md              # Attack surface map, trust boundaries, risk ratings
├── SECURITY_AUDIT_REPORT.md     # Master findings report (all agents merged)
├── REMEDIATION_TRACKER.md       # Finding → fix → verification tracking table
└── domain/
    ├── command-execution.md      # Agent 2 raw findings
    ├── filesystem-state.md       # Agent 3 raw findings
    ├── crypto-integrity.md       # Agent 4 raw findings
    ├── network-input.md          # Agent 5 raw findings
    └── frontend-boundary.md      # Agent 6 raw findings
```

## Finding Format

Each finding uses:
- **ID**: `SA-XXX` (sequential)
- **Severity**: Critical / High / Medium / Low / Informational
- **CWE**: Mapped CWE ID where applicable
- **Location**: `crate/src/file.rs:line`
- **Description**: What the issue is
- **Attack Scenario**: How it could be exploited
- **Remediation**: Specific fix recommendation
- **Status**: Open / Fixed / Verified

## Agent Decomposition (6 parallel Opus 4.6 agents)

### Agent 1: Threat Model
**Mission**: Map trust boundaries, privilege transitions, attack surfaces, data flows.
**Reads**: Architecture docs, DATA_FLOW.md, SECURITY.md, CONFIG_DESIGN.md, key entry points.
**Outputs**: `THREAT_MODEL.md`

### Agent 2: Command Execution & Privilege
**Mission**: Find command injection, argument injection, privilege escalation, TOCTOU.
**Files**: CLI apply/rollback, Tauri pkexec, all 8 plugin apply() methods, local executor, package managers.

### Agent 3: File System & State
**Mission**: Find path traversal, symlink attacks, TOCTOU races, atomic write failures, SQLite injection.
**Files**: file_utils.rs, checkpoint manager, db.rs, scan_manager.rs, plugins lib.rs, local executor.

### Agent 4: Crypto & Integrity
**Mission**: Find weaknesses in key management, signature verification, hash chain, randomness.
**Files**: signing.rs, hash_chain.rs, audit.rs, json_store.rs.

### Agent 5: Network & Input Parsing
**Mission**: Find SSRF, notification injection, XSS, CSV injection, config parsing exploits, SSH gaps.
**Files**: SSH executor, config.rs, config_loader.rs, email/webhook notifiers, HTML/CSV output, ssh_config.rs.

### Agent 6: Frontend Trust Boundary
**Mission**: Find IPC validation gaps, CSP bypasses, capability over-granting, deserialisation issues.
**Files**: tauri_bindings.rs, AppState, Tauri commands, tauri.conf.json, capabilities.

## Workflow

1. Launch all 6 agents in parallel
2. Merge findings into master report, deduplicate, assign final severities
3. Review findings together
4. Fix phase (user adds code in portions)
5. Re-verification pass updates remediation tracker

**Last Updated**: 2026-07-27
