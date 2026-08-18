# Documentation index

**Last Updated**: 2026-08-07

Map of everything under `docs/`. Root-level files (`README.md`,
`CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`) follow GitHub convention
and stay at the repository root.

## Guide (end users)

| Doc | Read it when you want to |
|-----|--------------------------|
| [guide/getting-started.md](guide/getting-started.md) | Scan, review findings, dry-run, apply, roll back, and produce a first compliance report |
| [guide/installation.md](guide/installation.md) | Install from AUR, RPM, deb, static binary, Docker, or source |
| [guide/upgrading.md](guide/upgrading.md) | Check whether a defect a release fixed is still on a host you already hardened, and repair it |
| [guide/troubleshooting.md](guide/troubleshooting.md) | Fix a problem: GUI launch, polkit auth errors, timer, partial scans |
| [guide/ssh-remote-scanning.md](guide/ssh-remote-scanning.md) | Scan, apply, and report against remote hosts over SSH |
| [guide/desktop-environment-compatibility.md](guide/desktop-environment-compatibility.md) | Set up a polkit agent per desktop environment or window manager |

## Reference

| Doc | Read it when you want to |
|-----|--------------------------|
| [reference/cli.md](reference/cli.md) | Look up any `hardener` command, subcommand, or flag |
| [reference/configuration.md](reference/configuration.md) | Look up any `config.toml` or `hosts.toml` key, default, and effect |
| [reference/naming-conventions.md](reference/naming-conventions.md) | Follow the project's naming standards |
| [reference/file-map.md](reference/file-map.md) | Find which source file implements what |
| [reference/data-flow.md](reference/data-flow.md) | Trace how data moves through the system, and its sources of truth |
| [reference/distribution-validation.md](reference/distribution-validation.md) | See which distro versions were validated end-to-end |
| [reference/evidence-ledger.md](reference/evidence-ledger.md) | Check what evidence backs a capability, and the ceiling on what that evidence proves |
| [reference/what-is-not-proven.md](reference/what-is-not-proven.md) | Find out what the test suite does **not** establish, before relying on it |
| [reference/coverage-baseline.md](reference/coverage-baseline.md) | Read the dated line-coverage measurement and what was deleted as dead |

## Architecture

| Doc | Read it when you want to |
|-----|--------------------------|
| [architecture/architecture.md](architecture/architecture.md) | Understand the crate layout, plugin engine, and desktop stack |

## Contributing (developers)

| Doc | Read it when you want to |
|-----|--------------------------|
| [contributing/building.md](contributing/building.md) | Build the CLI, desktop app, or WASM frontend |
| [contributing/testing.md](contributing/testing.md) | Run the test suites, including the container-based ones |
| [contributing/plugin-authoring.md](contributing/plugin-authoring.md) | Write a new hardening plugin |
| [contributing/documentation.md](contributing/documentation.md) | Validate and update the documentation |
| [contributing/releasing.md](contributing/releasing.md) | Cut a release |

## Design

| Doc | Read it when you want to |
|-----|--------------------------|
| [design/theming.md](design/theming.md) | Work on GUI themes and the styling system |

## Security

| Doc | Read it when you want to |
|-----|--------------------------|
| [security/external-audit-scope.md](security/external-audit-scope.md) | Scope a third-party security audit |
| `security/archive/2026-02-25-internal-audit/` | Review the resolved 2026 internal audit record |

## Planning and history

| Location | Contents |
|----------|----------|
| [ROADMAP.md](ROADMAP.md) | Milestones, completed and planned |
| [NEXT.md](NEXT.md) | Session handoff and current state |
| [Issue tracker](https://github.com/tidynest/linux-hardener/issues) | Open work, one issue per item; the authoritative list |
| [CHANGELOG.md](../CHANGELOG.md) | What each release changed, and what is merged but unreleased |
| `plans/` | Active plans; `plans/archive/` holds completed or superseded ones |
| `archive/` | Historical one-off docs |
| `assets/` | Logo and badge artwork |
