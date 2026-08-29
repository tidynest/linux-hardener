//! Fuzzes `vendor_path_for`, the function that maps an `/etc` path to its
//! `/usr/etc` counterpart on layering distributions.
//!
//! The mapping is small but load-bearing: a wrong answer reports a vendor
//! file where there is none (or misses one that is in force), and the input
//! arrives from configuration and remote hosts rather than from this
//! codebase. The asserted property is the whole contract, no more: a `Some`
//! answer is exactly `/usr/etc/` joined to what followed `/etc/`, and only
//! non-`/etc` paths and the directory itself answer `None`. Passthrough of
//! odd input (double slashes, trailing slashes) is the function's documented
//! behaviour, not a violation, so it is deliberately not asserted against.

#![no_main]

use hardener_common::vendor_config::vendor_path_for;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|path: &str| {
    match vendor_path_for(path) {
        Some(mapped) => {
            let rest = path.strip_prefix("/etc/").expect("Some implies /etc/ prefix");
            assert!(!rest.is_empty(), "the directory itself maps to None");
            assert_eq!(mapped, format!("/usr/etc/{rest}"));
        }
        None => {
            assert!(
                !path.starts_with("/etc/") || path == "/etc/",
                "None only for non-/etc paths and the directory itself"
            );
        }
    }
});
