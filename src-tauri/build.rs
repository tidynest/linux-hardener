/// Every `#[tauri::command]` registered in `main.rs`. Listing them here makes
/// tauri-build autogenerate `allow-*`/`deny-*` permissions per command, so the
/// capability file (`capabilities/default.json`) must grant each one explicitly
/// (SAM-039). Keep in sync with the `generate_handler!` block in `src/main.rs`.
const COMMANDS: &[&str] = &[
    "connect_remote",
    "create_checkpoint",
    "delete_checkpoint",
    "delete_remote_host",
    "disconnect_remote",
    "export_compliance_report",
    "generate_compliance_report",
    "get_checkpoint_detail",
    "get_checkpoints",
    "get_host_history",
    "get_latest_scan",
    "get_scan_history",
    "get_scan_session",
    "get_scheduler_config",
    "list_plugins",
    "list_remote_hosts",
    "pick_config_file",
    "run_apply",
    "run_apply_dry_run",
    "run_fleet_apply",
    "run_fleet_rollback",
    "run_fleet_scan",
    "run_remote_scan",
    "run_rollback",
    "run_scan",
    "save_remote_host",
    "save_scheduler_config",
    "test_notification",
    "validate_config",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
