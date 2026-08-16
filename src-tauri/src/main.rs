//! The Tauri desktop shell: the only bridge between the WASM frontend and the
//! hardening engine.
//!
//! Every capability the GUI has is a command registered here and listed in
//! [`commands`]. **Adding one means three edits, not one**: the handler in
//! `commands.rs`, the name in `build.rs`'s COMMANDS list, and an entry in
//! `capabilities/default.json`. Miss the third and the command exists but is
//! refused at runtime by its own ACL, which is what the per-command ACLs in
//! `acl_tests` exist to catch.
//!
//! Privileged work is not done in this process. It shells out to the `hardener`
//! CLI through pkexec, so the desktop app itself never runs as root, and
//! [`validation`] is the boundary that decides what may be passed across.

#[cfg(test)]
mod acl_tests;
mod commands;
mod validation;

use commands::{
    RemoteState, add_policy_exception, connect_remote, create_checkpoint, delete_checkpoint,
    delete_remote_host, disconnect_remote, export_compliance_report, generate_compliance_report,
    get_checkpoint_detail, get_checkpoints, get_host_history, get_latest_scan, get_scan_history,
    get_scan_session, get_scheduler_config, list_plugins, list_remote_hosts, pick_config_file,
    remove_policy_exception, run_apply, run_apply_dry_run, run_deep_scan, run_fleet_apply,
    run_fleet_rollback, run_fleet_scan, run_remote_scan, run_rollback, run_scan, save_remote_host,
    save_scheduler_config, test_notification, validate_config,
};
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Prevent WebKitGTK compositing crash on Wayland (Hyprland, Sway, etc.)
    // SAFETY: Called before any threads are spawned (start of main).
    unsafe { std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1") };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // On tiling Wayland compositors the client-side title bar and its
            // min/max/close controls are redundant: the compositor owns window
            // placement and lifecycle. Drop the decorations there and keep them
            // for floating desktops (GNOME, KDE) that depend on them.
            if !want_decorations()
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.set_decorations(false);
            }
            Ok(())
        })
        .manage(RemoteState {
            active_connection: tokio::sync::Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            add_policy_exception,
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
            get_host_history,
            get_scan_history,
            get_scan_session,
            get_scheduler_config,
            list_plugins,
            list_remote_hosts,
            pick_config_file,
            remove_policy_exception,
            run_apply,
            run_apply_dry_run,
            run_deep_scan,
            run_fleet_apply,
            run_fleet_rollback,
            run_fleet_scan,
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

/// Whether the main window should keep its client-side title bar and controls.
///
/// An explicit `HARDENER_DECORATIONS` value wins on any compositor ("0" hides
/// the frame, anything else shows it); otherwise the frame is dropped on known
/// tiling Wayland compositors and kept everywhere else.
fn want_decorations() -> bool {
    match std::env::var("HARDENER_DECORATIONS") {
        Ok(value) => value != "0",
        Err(_) => !is_tiling_wayland(),
    }
}

/// Best-effort detection of a tiling Wayland compositor from its session
/// environment. Recognises the common wlroots-family compositors by their
/// signature variables or their `XDG_CURRENT_DESKTOP` identifier.
fn is_tiling_wayland() -> bool {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
        || std::env::var_os("SWAYSOCK").is_some()
    {
        return true;
    }

    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|desktop| desktop_is_tiling(&desktop))
}

/// Whether an `XDG_CURRENT_DESKTOP` identifier, possibly a colon-separated
/// list, names a known tiling Wayland compositor. Case-insensitive.
fn desktop_is_tiling(xdg: &str) -> bool {
    const TILING: [&str; 6] = ["hyprland", "sway", "river", "niri", "wayfire", "labwc"];
    xdg.to_ascii_lowercase()
        .split(':')
        .any(|part| TILING.contains(&part))
}

#[cfg(test)]
mod decoration_tests;
