//! Unit tests for [`crate::remote`].
//!
//! Split out of `remote.rs`. This file sits in the `remote/` directory beside
//! it, so `super` still resolves to `crate::remote` and every import carried
//! across unchanged, private items included.

use super::*;

#[test]
fn from_target_parses_user_host_port() {
    let p = RemoteHostProfile::from_target("admin@web-01:2222", 22, None, true);
    assert_eq!(p.user.as_deref(), Some("admin"));
    assert_eq!(p.hostname, "web-01");
    assert_eq!(p.port, 2222, ":port suffix overrides the default");
    assert_eq!(p.name, "web-01", "name is the bare hostname");
}

#[test]
fn from_target_applies_caller_defaults() {
    let p = RemoteHostProfile::from_target("web-01", 2200, Some("/k".into()), false);
    assert_eq!(p.user, None, "no user part means current user");
    assert_eq!(p.port, 2200, "caller default port applies without :suffix");
    assert_eq!(p.key_file.as_deref(), Some("/k"));
    assert!(!p.host_key_checking);
}

#[test]
fn target_formats_with_and_without_user() {
    let with_user = RemoteHostProfile::from_target("admin@web-01:2222", 22, None, true);
    assert_eq!(with_user.target(), "admin@web-01:2222");
    let bare = RemoteHostProfile::from_target("web-01", 22, None, true);
    assert_eq!(bare.target(), "web-01:22", "defaults are made explicit");
}

#[test]
fn fleet_progress_round_trips_json() {
    let p = FleetProgress {
        host: "root@10.0.0.5:22".to_string(),
        done: 2,
        total: 5,
        failed: true,
    };
    let back: FleetProgress = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back.host, p.host);
    assert_eq!((back.done, back.total, back.failed), (2, 5, true));
}

#[test]
fn is_valid_hostname_accepts_plain_hosts_and_ips() {
    assert!(RemoteHostProfile::is_valid_hostname("web-01"));
    assert!(RemoteHostProfile::is_valid_hostname("10.242.117.2"));
    assert!(RemoteHostProfile::is_valid_hostname("example.com"));
}

#[test]
fn is_valid_hostname_accepts_ipv6_literals() {
    // IPv6 hostnames carry colons (and brackets when the user wrote them);
    // a valid target must never be rejected.
    assert!(RemoteHostProfile::is_valid_hostname("fe80::1"));
    assert!(RemoteHostProfile::is_valid_hostname("[::1]:22"));
}

#[test]
fn is_valid_hostname_rejects_empty_dash_and_stray_punctuation() {
    assert!(!RemoteHostProfile::is_valid_hostname(""), "empty");
    assert!(
        !RemoteHostProfile::is_valid_hostname("-oProxyCommand=x"),
        "leading dash reads as an ssh option"
    );
    // The live typo: `root@10.242.117.2, scan:22` parses to this hostname.
    assert!(
        !RemoteHostProfile::is_valid_hostname("10.242.117.2, scan"),
        "comma and space must be rejected"
    );
    assert!(!RemoteHostProfile::is_valid_hostname("a b"), "space");
    assert!(
        !RemoteHostProfile::is_valid_hostname("a$b"),
        "shell metachar"
    );
}

#[test]
fn from_target_leaves_ipv6_and_bad_ports_alone() {
    let v6 = RemoteHostProfile::from_target("root@fe80::1", 22, None, true);
    assert_eq!(v6.hostname, "fe80::1", "unbracketed IPv6 keeps its colons");
    assert_eq!(v6.port, 22, "IPv6 target keeps the default port");
    let bad = RemoteHostProfile::from_target("host:notaport", 22, None, true);
    assert_eq!(
        bad.hostname, "host:notaport",
        "unparsable port is not split"
    );
    assert_eq!(bad.port, 22);
}
