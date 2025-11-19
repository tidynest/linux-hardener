//! Kernel hardening plugin for sysctl parameter management.
//!
//! This plugin scans, applies, and manages kernel security parameters via sysctl.
//! It focuses on critical security settings including:
//! - Address Space Layout Randomisation (ASLR)
//! - Kernel pointer restrictions
//! - dmesg access restriction
//! - Core dump restrictions
//!
//! The plugin reads current values, compares against secure baselines,
//! and can apply hardening configurations with automatic rollback support.

use hardener_common::{
    error::Result,
    types::{
        FindingCategory,
        PluginId,
        Severity,
    }
};
use hardener_core::{
    context::Context,
    plugin::{
        ApplyResult,
        Finding,
        HardeningPlugin,
        PluginMetadata,
        ScanResult,
    }
};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    time::Instant,
};

