# hardener-scheduler::systemd
**File:** `crates/hardener-scheduler/src/systemd.rs` | **Lines:** 276

## Purpose
Generates systemd `.service` and `.timer` unit files for scheduled scanning. Includes `cron_to_calendar()` converter for 5-field cron expressions. Service unit has security hardening directives (NoNewPrivileges, ProtectSystem, PrivateTemp).

## Dependencies
- Imports from: `std::path`
- Used by: CLI `systemd install` command

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SystemdGenerator` | struct | Builder for service/timer unit content |
| `cron_to_calendar()` | fn | Converts 5-field cron to systemd OnCalendar format |
| `service_name()` | fn | Returns "linux-hardener.service" |
| `timer_name()` | fn | Returns "linux-hardener.timer" |
| `system_unit_path()` | fn | Returns "/etc/systemd/system" |
| `user_unit_path()` | fn | Returns "/etc/systemd/user" |

## Flags
- **TYPO** (line 34): Fixed — doc said "path to the given schedule" instead of "path to the hardener binary".
- **ANTIPATTERN** (lines 153, 160, 167, 174): Fixed — `parse().is_ok()` + `parse().unwrap()` parsed twice; replaced with nested `match` on `parse()` result.
