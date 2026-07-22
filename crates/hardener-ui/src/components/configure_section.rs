//! Configure section for the Hardening page.
//!
//! Selection state: protection-level segmented control, per-area plugin
//! rows with inline help, an "Advanced (optional)" config-file disclosure,
//! and a live "what will change" summary beside the Preview action. Apply
//! and preview handling (the dry-run, the review panel, confirm/cancel)
//! stay wired to the same `AppState` signals as before; this component only
//! re-skins the selection UI in front of them.

use crate::components::{Card, ConfigFileCard, HeadingLevel, IconCheck, IconInfo, IconMinus};
use crate::state::AppState;
use crate::tauri_bindings::{invoke_apply, invoke_apply_dry_run};
use crate::utils::{PreviewDecision, annotate_preview, is_auth_cancelled};
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

/// Maps a dry-run decision's plugin id to its `PLUGINS` display name.
///
/// The backend echoes back the FULL registry id (e.g. `"kernel-hardening"`),
/// not the short id this file sends it (`"kernel"`) - `src-tauri`'s own
/// `validate_plugin_ids` documents and relies on the same short-id-is-a-
/// prefix-of-the-full-id relationship, so matching via `starts_with` here is
/// the existing convention, not a new one. Falls back to a plain label only
/// if the backend ever reports a plugin this build does not know about.
fn plugin_display_name(plugin_id: &str) -> &'static str {
    PLUGINS
        .iter()
        .find(|p| plugin_id.starts_with(p.id))
        .map(|p| p.name)
        .unwrap_or("Unknown area")
}

/// Lockout risk class for a plugin id, if any.
///
/// SSH and the firewall are the only two areas that can affect how the user
/// logs in or reaches the machine at all - the sole two lockout classes for
/// now (brief Step 4). The label is neutral text, never a status colour.
fn lockout_class(plugin_id: &str) -> Option<&'static str> {
    if plugin_id.starts_with("ssh") {
        Some("login")
    } else if plugin_id.starts_with("firewall") {
        Some("network")
    } else {
        None
    }
}

/// Honest confirm count: the sum of each decision's estimated change count.
///
/// A `verified_compliant` decision already has `estimated_changes` emptied
/// by `annotate_preview`, so it naturally contributes 0. This must never be
/// swapped for `decisions.len()`, which would count a compliant/skipped area
/// as if it were a pending change.
fn total_estimated_changes(decisions: &[PreviewDecision]) -> usize {
    decisions.iter().map(|d| d.estimated_changes.len()).sum()
}

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

    // Review step (2a.3) - presentation-only client-side state, reset
    // whenever a fresh review is entered or left (see on_preview and
    // on_cancel_preview below) so neither can leak into an unrelated
    // selection.
    //
    // The single lockout acknowledgement tick (Step 4): gates Apply only
    // when the current decisions include an ssh/firewall (login/network)
    // area.
    let lockout_ack = RwSignal::new(false);
    // Seeds the admin drawer (Step 5); 2a.4 fills the panel this opens.
    let drawer_open = RwSignal::new(false);

    // Preview handler - runs dry-run and shows preview panel
    let on_preview = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        checking_cancelled.set(false);
        lockout_ack.set(false);
        drawer_open.set(false);
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

    // Cancel preview - hides the review step. Also reused for [Edit] (Step
    // 1), which returns to selection the same way. Clears the lockout tick
    // and closes the admin drawer stub so neither survives into the next
    // review pass.
    let on_cancel_preview = move |_| {
        app_state.show_preview.set(false);
        app_state.preview_results.set(Vec::new());
        lockout_ack.set(false);
        drawer_open.set(false);
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

    // Cross-checks the dry-run estimate against the latest persisted scan:
    // a plugin the last deep scan verified fully compliant is shown as
    // "Already compliant, skipped" rather than listing conditional
    // estimates the real apply would skip. Display-only; the privileged
    // apply re-checks everything and remains authoritative. Reused across
    // the review step's groups list, its honest confirm count, and the
    // lockout gate below, so this stays one call site rather than three.
    let get_decisions = move || {
        let results = app_state.preview_results.get();
        let scan_results = app_state.scan_results.get();
        annotate_preview(&results, &scan_results)
    };

    // Whether the current decisions include an ssh/firewall (login/network)
    // area - Step 4's single extra confirmation tick is shown only then.
    let has_lockout = move || {
        get_decisions()
            .iter()
            .any(|d| lockout_class(&d.plugin_id).is_some())
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
            // Step 1 - once the review has a result to show, it takes full
            // attention: the selection UI (segmented control, plugin rows,
            // the old "N areas selected" aside) steps aside rather than
            // sitting duplicated above the review's own compact summary
            // header. [Edit] (below) is the only way back to this.
            <Show when=move || !app_state.show_preview.get()>
            <div class="configure-layout">
                <div class="configure-main" class:is-disabled=move || app_state.is_previewing.get()>
                    <div
                        class="segmented-control"
                        role="radiogroup"
                        aria-label="Protection level"
                        on:keydown=on_segment_keydown.clone()
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
            </Show>

            // Review step - shown after a successful dry-run. Flow:
            // choose (2a.1) -> checking (2a.2) -> review (here) -> applying
            // -> done/partial.
            <Show when=move || app_state.show_preview.get()>
                <Card title_level=HeadingLevel::H2 class="review-panel">
                    // Step 1 - the selection collapses to a summary header;
                    // [Edit] returns to it via the same handler as Cancel.
                    <div class="review-header">
                        <p class="review-summary">
                            {move || {
                                let n = enabled_count();
                                let profile_label = PROFILES
                                    .iter()
                                    .find(|(id, _)| *id == selected_profile.get())
                                    .map(|(_, label)| *label)
                                    .unwrap_or("Custom");
                                format!(
                                    "{} profile . {} area{}",
                                    profile_label,
                                    n,
                                    if n == 1 { "" } else { "s" }
                                )
                            }}
                        </p>
                        <button type="button" class="btn btn-secondary btn-small" on:click=on_cancel_preview>
                            "Edit"
                        </button>
                    </div>

                    // Step 2 - changes grouped by area. A native
                    // <details>/<summary> per group with changes (the lazy
                    // correct choice for "expandable"); a verified_compliant
                    // group is dimmed and shown, never hidden.
                    <div class="review-groups">
                        {move || {
                            let decisions = get_decisions();
                            if decisions.is_empty() {
                                view! { <p class="empty-state">"No changes to preview."</p> }.into_any()
                            } else {
                                decisions.into_iter().map(|decision| {
                                    let name = plugin_display_name(&decision.plugin_id);
                                    let pill = lockout_class(&decision.plugin_id);
                                    let count = decision.estimated_changes.len();

                                    if decision.verified_compliant {
                                        view! {
                                            <div class="review-group review-group-compliant">
                                                <IconMinus class="review-group-minus-icon".to_string() />
                                                <span class="review-group-name">{name}</span>
                                                <span class="review-group-note">"Already compliant, skipped"</span>
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <details class="review-group review-group-details">
                                                <summary class="review-group-summary">
                                                    <IconCheck class="review-group-check-icon".to_string() />
                                                    <span class="review-group-name">{name}</span>
                                                    {pill.map(|p| view! { <span class="lockout-pill">{p}</span> })}
                                                    <span class="review-group-count">
                                                        {format!("{} change{}", count, if count == 1 { "" } else { "s" })}
                                                    </span>
                                                </summary>
                                                <ul class="review-group-changes">
                                                    {decision.estimated_changes.iter().map(|change| {
                                                        view! { <li>{change.clone()}</li> }
                                                    }).collect::<Vec<_>>()}
                                                </ul>
                                            </details>
                                        }.into_any()
                                    }
                                }).collect::<Vec<_>>().into_any()
                            }
                        }}
                    </div>

                    // Step 5 seed - trigger + signal only; 2a.4 fills the
                    // drawer body.
                    <button
                        type="button"
                        class="btn btn-secondary review-detail-trigger"
                        on:click=move |_| drawer_open.set(true)
                    >
                        "View full detail"
                    </button>

                    // Step 3 - the count-named confirm, in a calm accent box
                    // (never red/warning) beside the checkpoint/password
                    // reassurance. Step 4 - the single lockout tick lives in
                    // the same box, shown only when the selection includes
                    // an ssh/firewall area.
                    <div class="review-confirm-box">
                        <p class="review-confirm-reassurance">
                            "A checkpoint is saved first, and you will be asked for your password. You can undo everything from History."
                        </p>

                        <Show when=has_lockout>
                            <label class="review-lockout-tick">
                                <input
                                    type="checkbox"
                                    prop:checked=move || lockout_ack.get()
                                    on:change=move |ev| {
                                        lockout_ack.set(crate::components::form_helpers::checkbox_checked(&ev));
                                    }
                                />
                                <span>"I understand this can affect how I log in or reach this machine"</span>
                            </label>
                        </Show>

                        <div class="review-confirm-actions">
                            <button
                                class="btn btn-secondary"
                                on:click=on_cancel_preview
                            >
                                "Cancel"
                            </button>
                            <button
                                class="btn btn-primary"
                                on:click=on_confirm_apply
                                disabled=move || {
                                    let total = total_estimated_changes(&get_decisions());
                                    app_state.is_applying.get()
                                        || total == 0
                                        || (has_lockout() && !lockout_ack.get())
                                }
                                aria-live="polite"
                            >
                                {move || {
                                    if app_state.is_applying.get() {
                                        "Applying...".to_string()
                                    } else {
                                        let total = total_estimated_changes(&get_decisions());
                                        if total == 0 {
                                            "Nothing to Apply".to_string()
                                        } else {
                                            format!("Apply {} Change{}", total, if total == 1 { "" } else { "s" })
                                        }
                                    }
                                }}
                            </button>
                        </div>

                        <Show when=move || has_lockout() && !lockout_ack.get()>
                            <p class="review-lockout-hint">"Tick the box above to enable Apply."</p>
                        </Show>
                    </div>
                </Card>

                // Admin drawer stub - 2a.4 fills this drawer with the
                // grid-aligned config diff. The backdrop dims the rest of
                // the page (same pattern as the existing .modal-backdrop)
                // rather than leaving the review's own Cancel/Apply row
                // silently unreachable underneath an opaque fixed panel;
                // clicking it, like Close, dismisses the stub.
                <Show when=move || drawer_open.get()>
                    <div class="review-drawer-backdrop" on:click=move |_| drawer_open.set(false)></div>
                    <aside class="review-drawer" aria-label="Full detail">
                        <div class="review-drawer-header">
                            <h3>"Full detail"</h3>
                            <button
                                type="button"
                                class="btn btn-secondary btn-small"
                                on:click=move |_| drawer_open.set(false)
                            >
                                "Close"
                            </button>
                        </div>
                        <p class="review-drawer-placeholder">
                            "The full change detail view is on its way."
                        </p>
                    </aside>
                </Show>
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_estimated_changes_excludes_compliant_groups() {
        // The task brief's hand example: 2 plugins, one with 3 estimated
        // changes, one verified_compliant (changes emptied). Honest N is 3,
        // never `decisions.len()` (which would read 2).
        let decisions = vec![
            PreviewDecision {
                plugin_id: "ssh-hardening".to_string(),
                verified_compliant: false,
                estimated_changes: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
            PreviewDecision {
                plugin_id: "permissions-hardening".to_string(),
                verified_compliant: true,
                estimated_changes: vec![],
            },
        ];
        assert_eq!(total_estimated_changes(&decisions), 3);
    }

    #[test]
    fn total_estimated_changes_is_zero_when_everything_compliant() {
        let decisions = vec![PreviewDecision {
            plugin_id: "kernel-hardening".to_string(),
            verified_compliant: true,
            estimated_changes: vec![],
        }];
        assert_eq!(total_estimated_changes(&decisions), 0);
    }

    #[test]
    fn plugin_display_name_maps_the_full_backend_id_via_prefix() {
        // Backend echoes the FULL registry id, not the short id this file
        // sends it - see plugin_display_name's own doc comment.
        assert_eq!(plugin_display_name("kernel-hardening"), "Kernel Hardening");
        assert_eq!(plugin_display_name("ssh-hardening"), "SSH Hardening");
        assert_eq!(
            plugin_display_name("service-minimisation"),
            "Service Minimisation"
        );
        assert_eq!(plugin_display_name("mac-hardening"), "MAC System");
        assert_eq!(plugin_display_name("unknown-plugin"), "Unknown area");
    }

    #[test]
    fn lockout_class_flags_only_ssh_and_firewall() {
        assert_eq!(lockout_class("ssh-hardening"), Some("login"));
        assert_eq!(lockout_class("firewall-hardening"), Some("network"));
        assert_eq!(lockout_class("kernel-hardening"), None);
        assert_eq!(lockout_class("pam-hardening"), None);
    }
}
