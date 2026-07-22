//! Configure section for the Hardening page.
//!
//! Selection state: protection-level segmented control, per-area plugin
//! rows with inline help, an "Advanced (optional)" config-file disclosure,
//! and a live "what will change" summary beside the Preview action. Apply
//! and preview handling (the dry-run, the review panel, confirm/cancel)
//! stay wired to the same `AppState` signals as before; this component only
//! re-skins the selection UI in front of them.

use crate::components::{Card, ConfigFileCard, HeadingLevel, IconCheck, IconInfo};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_apply, invoke_apply_dry_run};
use crate::utils::{annotate_preview, is_auth_cancelled};
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Plugin definition: ID, display name, and the plain-English one-liner
/// shown when its `(i)` help affordance is opened.
struct PluginDef {
    id: &'static str,
    name: &'static str,
    summary: &'static str,
}

const PLUGINS: &[PluginDef] = &[
    PluginDef {
        id: "kernel",
        name: "Kernel Hardening",
        summary: "tightens kernel memory and sysctl protections",
    },
    PluginDef {
        id: "ssh",
        name: "SSH Hardening",
        summary: "enforces stricter SSH authentication and crypto",
    },
    PluginDef {
        id: "firewall",
        name: "Firewall",
        summary: "sets a default-deny inbound policy",
    },
    PluginDef {
        id: "pam",
        name: "PAM Authentication",
        summary: "strengthens password quality and lockout policy",
    },
    PluginDef {
        id: "service",
        name: "Service Minimisation",
        summary: "disables unnecessary background services",
    },
    PluginDef {
        id: "audit",
        name: "Audit Rules",
        summary: "records security-relevant events with auditd rules",
    },
    PluginDef {
        id: "permissions",
        name: "File Permissions",
        summary: "corrects permissions on sensitive system files",
    },
    PluginDef {
        id: "mac",
        name: "MAC System",
        summary: "enables mandatory access control (AppArmor or SELinux)",
    },
];

/// The four segments of the protection-level control, in display order.
const PROFILES: &[(&str, &str)] = &[
    ("baseline", "Baseline"),
    ("secure", "Secure"),
    ("high", "High"),
    ("custom", "Custom"),
];

/// Configure section with the selection state and apply controls.
#[component]
pub fn ConfigureSection() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Profile presets
    let selected_profile = RwSignal::new("secure".to_string());

    // Individual plugin states - stored for access across closures
    let plugin_states: Vec<(String, RwSignal<bool>)> = PLUGINS
        .iter()
        .map(|p| {
            let enabled = matches!(p.id, "kernel" | "ssh" | "firewall" | "pam" | "service");
            (p.id.to_string(), RwSignal::new(enabled))
        })
        .collect();
    let plugin_states = StoredValue::new(plugin_states);

    // Update plugins based on profile selection
    let update_profile = std::sync::Arc::new(move |profile: &str| {
        selected_profile.set(profile.to_string());

        let enabled_plugins: Vec<&str> = match profile {
            "baseline" => vec!["ssh", "firewall"],
            "secure" => vec!["kernel", "ssh", "firewall", "pam", "service"],
            "high" => PLUGINS.iter().map(|p| p.id).collect(),
            _ => vec![],
        };

        plugin_states.with_value(|states| {
            for (id, signal) in states {
                signal.set(enabled_plugins.contains(&id.as_str()));
            }
        });
    });

    // Get enabled plugin IDs for apply
    let get_enabled_plugins = move || {
        plugin_states.with_value(|states| {
            states
                .iter()
                .filter(|(_, signal)| signal.get())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        })
    };

    // Live count of enabled areas - drives the "N areas selected" summary
    // and the Preview action's disabled state. Real, not fabricated: this
    // counts what is actually selected, unlike a settings count, which the
    // frontend cannot know until the dry-run returns.
    let enabled_count =
        move || plugin_states.with_value(|states| states.iter().filter(|(_, s)| s.get()).count());

    // Display names of the enabled areas, in PLUGINS order - feeds the calm
    // checking view's skeleton rows. Derived from get_enabled_plugins(): a
    // real reflection of the current selection, not fabricated per-item
    // progress (there is none to report; see on_preview below).
    let checking_areas = move || {
        get_enabled_plugins()
            .into_iter()
            .filter_map(|id| PLUGINS.iter().find(|p| p.id == id).map(|p| p.name))
            .collect::<Vec<_>>()
    };

    // Which plugin row's `(i)` help is open, if any - only one at a time.
    let help_open = RwSignal::<Option<usize>>::new(None);

    // Set true only by Cancel while a dry-run is in flight (see
    // on_cancel_checking below); reset at the start of every fresh
    // on_preview run. Presentation-only client-side state.
    let checking_cancelled = RwSignal::new(false);

    // Preview handler - runs dry-run and shows preview panel
    let on_preview = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        checking_cancelled.set(false);
        app_state.is_previewing.set(true);
        app_state.show_preview.set(false);

        leptos::task::spawn_local(async move {
            match invoke_apply_dry_run(plugins, app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    // ponytail: the dry-run future in flight cannot be
                    // truly aborted from here; a Cancel click just discards
                    // its result instead of racing to stop it, which is the
                    // honest option available client-side.
                    if !checking_cancelled.get_untracked() {
                        app_state.preview_results.set(results);
                        app_state.show_preview.set(true);
                    }
                }
                Err(e) => {
                    // Mirror the Ok arm: a cancelled run's outcome is
                    // discarded silently, whether it resolves or fails.
                    if !checking_cancelled.get_untracked() {
                        web_sys::console::error_1(&format!("Preview failed: {}", e).into());
                        app_state
                            .error_message
                            .set(Some(format!("Preview failed: {}", e)));
                    }
                }
            }
            app_state.is_previewing.set(false);
        });
    };

    // Cancel while checking - returns to the selection state without
    // waiting for the in-flight dry-run; see the ponytail note above.
    let on_cancel_checking = move |_| {
        app_state.is_previewing.set(false);
        checking_cancelled.set(true);
    };

    // Cancel preview - hides preview panel
    let on_cancel_preview = move |_| {
        app_state.show_preview.set(false);
        app_state.preview_results.set(Vec::new());
    };

    // Confirm and apply - runs actual apply after preview
    let on_confirm_apply = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        app_state.is_applying.set(true);
        app_state.show_preview.set(false);

        leptos::task::spawn_local(async move {
            match invoke_apply(plugins, app_state.config_path.get_untracked()).await {
                Ok(results) => {
                    app_state.apply_results.update(|r| r.extend(results));
                    app_state.preview_results.set(Vec::new());
                }
                Err(e) if is_auth_cancelled(&e) => {
                    web_sys::console::info_1(&"Apply cancelled by user.".into());
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Apply failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Apply failed: {}", e)));
                }
            }
            app_state.is_applying.set(false);
        });
    };

    // WAI-ARIA radiogroup keyboard handling for the segmented control:
    // arrow keys move focus AND selection (mirrors `TabBar`'s pattern).
    // Native buttons already handle Space/Enter as a click, so only
    // directional movement needs a handler here.
    let on_segment_keydown = {
        let update_profile = update_profile.clone();
        move |ev: web_sys::KeyboardEvent| {
            let count = PROFILES.len();
            let current = PROFILES
                .iter()
                .position(|(id, _)| *id == selected_profile.get_untracked())
                .unwrap_or(0);
            let next = match ev.key().as_str() {
                "ArrowRight" | "ArrowDown" => Some((current + 1) % count),
                "ArrowLeft" | "ArrowUp" => Some(current.checked_sub(1).unwrap_or(count - 1)),
                "Home" => Some(0),
                "End" => Some(count - 1),
                _ => None,
            };

            if let Some(idx) = next {
                ev.prevent_default();
                let (id, _) = PROFILES[idx];
                if id == "custom" {
                    selected_profile.set("custom".to_string());
                } else {
                    update_profile(id);
                }

                // Focus by known element ID: avoids a race with the
                // aria-checked re-render, same as TabBar.
                if let Some(el) = web_sys::window()
                    .and_then(|w| w.document())
                    .and_then(|d| d.get_element_by_id(&format!("segment-{}", id)))
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = el.focus();
                }
            }
        }
    };

    view! {
        <div class="configure-section">
            <div class="configure-layout">
                <div class="configure-main" class:is-disabled=move || app_state.is_previewing.get()>
                    <div
                        class="segmented-control"
                        role="radiogroup"
                        aria-label="Protection level"
                        on:keydown=on_segment_keydown
                    >
                        {PROFILES.iter().map(|(id, label)| {
                            let id = *id;
                            let label = *label;
                            let update = update_profile.clone();
                            let is_active = move || selected_profile.get() == id;

                            view! {
                                <button
                                    type="button"
                                    id=format!("segment-{}", id)
                                    role="radio"
                                    aria-checked=move || is_active().to_string()
                                    tabindex=move || if is_active() { "0" } else { "-1" }
                                    disabled=move || app_state.is_previewing.get()
                                    class="segment-btn"
                                    class:is-active=is_active
                                    on:click=move |_| {
                                        if id == "custom" {
                                            selected_profile.set("custom".to_string());
                                        } else {
                                            update(id);
                                        }
                                    }
                                >
                                    {label}
                                </button>
                            }
                        }).collect::<Vec<_>>()}
                    </div>

                    <p id="plugin-profile-hint" class="sr-only" aria-live="polite">
                        {move || format!("Active profile: {}", selected_profile.get())}
                    </p>
                    <div
                        class="plugin-rows"
                        role="group"
                        aria-label="Plugin areas"
                        aria-describedby="plugin-profile-hint"
                    >
                        {plugin_states.with_value(|states| {
                            states.iter().enumerate().map(|(i, (_, signal))| {
                                let plugin = &PLUGINS[i];
                                let name = plugin.name;
                                let summary = plugin.summary;
                                let signal = *signal;
                                let is_help_open = move || help_open.get() == Some(i);
                                let toggle = move || {
                                    // A dry-run in flight has already captured the
                                    // selection it is checking; a mid-check toggle
                                    // would silently desync the two, so no-op it.
                                    // (Mouse clicks are also blocked by the
                                    // .configure-main.is-disabled CSS below; this
                                    // covers the keyboard Space path pointer-events
                                    // cannot reach.)
                                    if app_state.is_previewing.get_untracked() {
                                        return;
                                    }
                                    signal.update(|v| *v = !*v);
                                    selected_profile.set("custom".to_string());
                                };

                                view! {
                                    <div
                                        class="plugin-row"
                                        role="checkbox"
                                        aria-checked=move || signal.get().to_string()
                                        aria-label=name
                                        tabindex="0"
                                        on:click=move |_| toggle()
                                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                                            if ev.key() == " " {
                                                ev.prevent_default();
                                                toggle();
                                            }
                                        }
                                    >
                                        <span class="plugin-row-indicator" aria-hidden="true">
                                            <Show
                                                when=move || signal.get()
                                                fallback=|| view! { <span class="plugin-row-indicator-empty"></span> }
                                            >
                                                <IconCheck class="plugin-row-check-icon".to_string() />
                                            </Show>
                                        </span>
                                        <span class="plugin-row-name">{name}</span>
                                        <button
                                            type="button"
                                            class="plugin-row-help"
                                            aria-label=format!("About {}", name)
                                            aria-expanded=move || is_help_open().to_string()
                                            on:click=move |ev: web_sys::MouseEvent| {
                                                ev.stop_propagation();
                                                help_open.update(|cur| *cur = if *cur == Some(i) { None } else { Some(i) });
                                            }
                                            on:keydown=move |ev: web_sys::KeyboardEvent| {
                                                ev.stop_propagation();
                                            }
                                        >
                                            <IconInfo class="plugin-row-help-icon".to_string() />
                                        </button>
                                        <Show when=is_help_open>
                                            <p class="plugin-row-detail">{summary}</p>
                                        </Show>
                                    </div>
                                }
                            }).collect::<Vec<_>>()
                        })}
                    </div>

                    <details class="advanced-disclosure">
                        <summary class="advanced-disclosure-summary">"Advanced (optional)"</summary>
                        <div class="advanced-disclosure-body">
                            <p class="advanced-disclosure-hint">
                                "Load your own .toml to override the profile. Most people leave this blank."
                            </p>
                            <ConfigFileCard />
                        </div>
                    </details>
                </div>

                <div class="configure-aside">
                    // The calm checking (dry-run) loading state. There is no
                    // per-plugin progress event for the local dry-run (a single
                    // invoke_apply_dry_run call resolves all at once), so this
                    // deliberately makes no "N of M done" claim: the skeleton
                    // rows are a cosmetic top-down reveal, not a completion
                    // counter. Only the area count and the area names
                    // themselves are real (the current selection).
                    <Show
                        when=move || !app_state.is_previewing.get()
                        fallback=move || {
                            let areas = checking_areas();
                            let count = areas.len();
                            view! {
                                <div class="checking-view" aria-live="polite">
                                    <p class="checking-reassurance">"Nothing is changed yet"</p>
                                    <p class="checking-heading">
                                        {format!("Checking {} area{}", count, if count == 1 { "" } else { "s" })}
                                    </p>
                                    <ul class="checking-skeleton-list">
                                        {areas.into_iter().enumerate().map(|(i, name)| {
                                            view! {
                                                <li
                                                    class="checking-skeleton-row"
                                                    style=format!("animation-delay: {}ms", i * 70)
                                                >
                                                    <span class="checking-skeleton-indicator" aria-hidden="true"></span>
                                                    <span class="checking-skeleton-name">{name}</span>
                                                </li>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </ul>
                                    <button
                                        type="button"
                                        class="btn btn-secondary checking-cancel"
                                        on:click=on_cancel_checking
                                    >
                                        "Cancel"
                                    </button>
                                </div>
                            }
                        }
                    >
                        <div class="apply-summary" aria-live="polite">
                            {move || {
                                let n = enabled_count();
                                if n == 0 {
                                    view! {
                                        <p class="apply-summary-text apply-summary-empty">"Select at least one area"</p>
                                    }.into_any()
                                } else {
                                    view! {
                                        <p class="apply-summary-text">
                                            {format!("{} area{} selected", n, if n == 1 { "" } else { "s" })}
                                        </p>
                                    }.into_any()
                                }
                            }}
                            <p class="apply-summary-reassurance">
                                "A checkpoint is saved before anything changes, so you can undo it all."
                            </p>
                        </div>

                        <button
                            class="btn btn-primary btn-large"
                            on:click=on_preview
                            disabled=move || app_state.is_applying.get() || enabled_count() == 0
                        >
                            "Preview Changes"
                        </button>
                    </Show>
                </div>
            </div>

            // Preview panel - shown after dry-run completes
            <Show when=move || app_state.show_preview.get()>
                <Card title="Preview Changes" title_level=HeadingLevel::H2 class="preview-panel">
                    <p class="preview-warning">
                        "Review the changes below before applying. A checkpoint will be created for rollback."
                    </p>

                    <div class="preview-changes">
                        {move || {
                            let results = app_state.preview_results.get();
                            if results.is_empty() {
                                view! { <p class="empty-state">"No changes to preview."</p> }.into_any()
                            } else {
                                // Cross-check each estimate against the latest persisted
                                // scan: a plugin the last deep scan verified fully
                                // compliant is shown as "0 changes" rather than listing
                                // conditional estimates the real apply would skip. This
                                // is display-only; the privileged apply re-checks
                                // everything and remains authoritative.
                                let scan_results = app_state.scan_results.get();
                                let decisions = annotate_preview(&results, &scan_results);
                                decisions.into_iter().map(|decision| {
                                    let plugin_id = decision.plugin_id;
                                    let compliant = decision.verified_compliant;
                                    let changes = decision.estimated_changes;
                                    let change_count = changes.len();

                                    view! {
                                        <div class="preview-plugin">
                                            <h4 class="preview-plugin-name">
                                                {plugin_id}
                                                <span class="preview-change-count">
                                                    {format!("({} change{})", change_count, if change_count == 1 { "" } else { "s" })}
                                                </span>
                                            </h4>
                                            {if compliant {
                                                view! {
                                                    <p class="preview-compliant-note">
                                                        "Verified compliant by last deep scan"
                                                    </p>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <ul class="preview-change-list">
                                                        {changes.iter().map(|change| {
                                                            view! { <li>{change.clone()}</li> }
                                                        }).collect::<Vec<_>>()}
                                                    </ul>
                                                }.into_any()
                                            }}
                                        </div>
                                    }
                                }).collect::<Vec<_>>().into_any()
                            }
                        }}
                    </div>

                    <div class="preview-actions">
                        <button
                            class="btn btn-secondary"
                            on:click=on_cancel_preview
                        >
                            "Cancel"
                        </button>
                        <button
                            class="btn btn-primary"
                            on:click=on_confirm_apply
                            disabled=move || app_state.is_applying.get()
                            aria-live="polite"
                        >
                            {move || if app_state.is_applying.get() {
                                "Applying..."
                            } else {
                                "Confirm & Apply"
                            }}
                        </button>
                    </div>
                </Card>
            </Show>
        </div>
    }
}
