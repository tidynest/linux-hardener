#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`systemd`](super).
//!
//! Split out of `systemd.rs`. This file sits in the `systemd/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::systemd` and every import carried
//! across unchanged, private items included.

use super::*;

#[test]
fn generate_service_basic() {
    let generator = SystemdGenerator::new(PathBuf::from("/usr/bin/hardener"), "daily");
    let service = generator.generate_service();

    assert!(service.contains("[Unit]"));
    assert!(service.contains("[Service]"));
    assert!(service.contains("Type=oneshot"));
    assert!(service.contains("/usr/bin/hardener daemon run-once"));
    assert!(service.contains("NoNewPrivileges=true"));
}

#[test]
fn generate_service_with_config() {
    let generator = SystemdGenerator::new(PathBuf::from("/usr/bin/hardener"), "daily")
        .with_config(PathBuf::from("/etc/hardener/config.toml"));
    let service = generator.generate_service();

    assert!(service.contains("--config /etc/hardener/config.toml"));
}

#[test]
fn generate_timer_basic() {
    let generator = SystemdGenerator::new(PathBuf::from("/usr/bin/hardener"), "*-*-* 02:00:00");
    let timer = generator.generate_timer();

    assert!(timer.contains("[Timer]"));
    assert!(timer.contains("OnCalendar=*-*-* 02:00:00"));
    assert!(timer.contains("Persistent=true"));
    assert!(timer.contains("RandomizedDelaySec=300"));
}

#[test]
fn cron_daily_at_2am() {
    let result = cron_to_calendar("0 2 * * *");
    assert_eq!(result, Some("*-*-* 02:00:00".to_string()));
}

#[test]
fn cron_weekly_sunday_midnight() {
    let result = cron_to_calendar("0 0 * * 0");
    assert_eq!(result, Some("Sun *-*-* 00:00:00".to_string()));
}

#[test]
fn cron_monthly_first_day() {
    let result = cron_to_calendar("0 3 1 * *");
    assert_eq!(result, Some("*-*-01 03:00:00".to_string()));
}

#[test]
fn cron_specific_date() {
    let result = cron_to_calendar("30 14 15 6 *");
    assert_eq!(result, Some("*-06-15 14:30:00".to_string()));
}

#[test]
fn cron_invalid_format_returns_none() {
    assert_eq!(cron_to_calendar("invalid"), None);
    assert_eq!(cron_to_calendar("* * *"), None);
    assert_eq!(cron_to_calendar(""), None);
}

#[test]
fn static_names_are_correct() {
    assert_eq!(service_name(), "linux-hardener.service");
    assert_eq!(timer_name(), "linux-hardener.timer");
}
