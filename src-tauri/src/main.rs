mod commands;

use commands::{get_checkpoints, run_apply, run_rollback, run_scan};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_checkpoints,
            run_apply,
            run_rollback,
            run_scan,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run tauri application");
}
