mod commands;
mod validation;

use commands::{
    RemoteState, connect_remote, create_checkpoint, delete_checkpoint, delete_remote_host,
    disconnect_remote, export_compliance_report, generate_compliance_report, get_checkpoint_detail,
    get_checkpoints, get_latest_scan, get_scan_history, get_scan_session, get_scheduler_config,
    list_plugins, list_remote_hosts, pick_config_file, run_apply, run_apply_dry_run,
    run_remote_scan, run_rollback, run_scan, save_remote_host, save_scheduler_config,
    test_notification, validate_config,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Initialize tracing for debug output
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(RemoteState {
            active_connection: std::sync::Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            connect_remote,
            create_checkpoint,
            delete_checkpoint,
            delete_remote_host,
            disconnect_remote,
            export_compliance_report,
            generate_compliance_report,
            get_checkpoint_detail,
            get_checkpoints,
            get_latest_scan,
            get_scan_history,
            get_scan_session,
            get_scheduler_config,
            list_plugins,
            list_remote_hosts,
            pick_config_file,
            run_apply,
            run_apply_dry_run,
            run_remote_scan,
            run_rollback,
            run_scan,
            save_remote_host,
            save_scheduler_config,
            test_notification,
            validate_config,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run tauri application");
}
