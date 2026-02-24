mod commands;

use commands::{
    create_checkpoint, delete_checkpoint, export_compliance_report, generate_compliance_report,
    get_checkpoints, get_latest_scan, run_apply, run_apply_dry_run, run_rollback, run_scan,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Initialize tracing for debug output
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            create_checkpoint,
            delete_checkpoint,
            export_compliance_report,
            generate_compliance_report,
            get_checkpoints,
            get_latest_scan,
            run_apply,
            run_apply_dry_run,
            run_rollback,
            run_scan,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run tauri application");
}
