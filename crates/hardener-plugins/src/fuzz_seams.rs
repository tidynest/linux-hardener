//! The one consumer outside this crate that needs the configuration parsers
//! by path: the fuzz targets under `fuzz/`.
//!
//! Everything re-exported here parses bytes that arrive from remote hosts
//! over the SSH executor, which is input the operator does not control, and
//! each of those parsers used to be reachable only through a live scan or
//! apply. cargo-fuzz builds the whole graph with `--cfg fuzzing`, and only
//! such a build compiles this module (see the declaration in `lib.rs`), so
//! the door does not exist for any other consumer: the crate's public
//! surface is exactly what it was, and the targets reach module-private
//! code without any of it becoming API.

/// The sshd_config `Include` resolution core: directive-line parsing, the
/// glob matcher, pattern classification, and the first-wins order
/// `ResolvedConfig` answers from.
pub mod ssh_include {
    pub use crate::ssh::include::{
        EffectiveValue, ResolvedConfig, absolute_pattern, glob_matches, include_patterns,
        pattern_is_supported,
    };
}

/// The PAM stack and conffile parsing halves: module-presence lines, inline
/// `arg=value` overrides, and the exact-match conffile writer.
pub mod pam_parsing {
    pub use crate::pam::parsing::{
        apply_exact_directive, inline_arg_in_content, stack_loads_module,
    };
}

/// The nftables boot-file include append, pure over the content it is given.
pub mod nftables_include {
    pub use crate::firewall::nftables::with_include_line;
}
