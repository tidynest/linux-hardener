use hardener_common::types::PluginId;
use hardener_core::context::AuditOperation;
use hardener_core::{Context, PluginAuditEntry, SystemInfo};

#[test]
fn test_system_info_detection() {
    let info = SystemInfo::detect().unwrap();

    assert!(!info.system_distribution.is_empty());
    assert!(!info.system_distribution_version.is_empty());
    assert!(!info.system_kernel_version.is_empty());
    assert!(!info.system_hostname.is_empty());
    assert!(!info.system_architecture.is_empty());
}

#[test]
fn test_audit_entry_creation() {
    let entry = PluginAuditEntry::new("test_plugin", AuditOperation::Scan, "Scanning system", true);

    assert_eq!(entry.entry_plugin_id, PluginId::from("test_plugin"));
    assert_eq!(entry.entry_description, "Scanning system");
    assert!(entry.entry_success);
    assert!(entry.entry_error.is_none());
    assert!(entry.entry_timestamp > 0);
}

#[test]
fn test_audit_entry_with_error() {
    let entry = PluginAuditEntry::with_error(
        "test_plugin",
        AuditOperation::Apply,
        "Failed to apply changes",
        "Permission denied",
    );

    assert_eq!(entry.entry_plugin_id, PluginId::from("test_plugin"));
    assert!(!entry.entry_success);
    assert_eq!(entry.entry_error, Some("Permission denied".to_string()));
}

#[test]
fn test_context_logs_audit() {
    let ctx = Context::new();
    let entry = PluginAuditEntry::new("test_plugin", AuditOperation::Scan, "Test operation", true);

    let result = ctx.log_audit(entry);
    assert!(result.is_ok());
}
