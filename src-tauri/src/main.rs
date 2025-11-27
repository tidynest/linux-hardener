mod commands;

use commands::{generate_compliance_report, get_checkpoints, run_apply, run_rollback, run_scan};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate_compliance_report,
            get_checkpoints,
            run_apply,
            run_rollback,
            run_scan,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run tauri application");
}
