//! Configure section for the Hardening page.
//!
//! Selection state: protection-level segmented control, per-area plugin
//! rows with inline help, an "Advanced (optional)" config-file disclosure,
//! and a live "what will change" summary beside the Preview action. Apply
//! and preview handling (the dry-run, the review panel, confirm/cancel)
//! stay wired to the same `AppState` signals as before; this component only
//! re-skins the selection UI in front of them.

use crate::components::{
    Card, ConfigFileCard, HeadingLevel, IconCheck, IconInfo, IconMinus, IconWrench, IconX,
    SegmentedControl, calculate_all_scores,
};
use crate::pages::hardening_page::HardeningSection;
use crate::state::AppState;
use crate::tauri_bindings::{
    invoke_apply, invoke_apply_dry_run, invoke_generate_report, invoke_scan,
};
use crate::types::ApplyResult;
use crate::utils::{
    ApplyOutcome, PreviewDecision, annotate_preview, applied_settings_and_areas,
    apply_change_summary, apply_fully_successful, classify_apply_result, is_auth_cancelled,
    is_manual_action, nothing_to_apply_line, partial_summary_sentence, score_delta_label,
};
use leptos::prelude::*;
use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

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

/// Maps a plugin id to its `PLUGINS` display name.
///
/// The backend echoes back the FULL registry id (e.g. `"kernel-hardening"`),
/// not the short id this file sends it (`"kernel"`), so the lookup asks
/// `plugin_id_named_by`: the same question the CLI's `--plugin` filter and the
/// desktop's two scan paths ask, and now the same code. This screen used to ask
/// it with a bare `starts_with`, without the hyphen that makes a short id a
/// whole segment, so a future plugin whose id began with another's short id
/// would have been labelled as that other one. Falls back to a plain label only
/// if the backend ever reports a plugin this build does not know about.
///
/// `pub(crate)` for `schedule_section` and `fleet_apply_page`, which both
/// listed the same eight areas and rendered their raw ids as labels, so the
/// Scheduler said `mac-hardening` and Fleet Apply said `audit-hardening` where
/// this screen says "MAC System" and "Audit Rules". One table of names, three
/// screens.
///
/// Fleet Apply reaches its plugins as `PluginMetadata`, which carries a
/// `plugin_name` of its own, and that is NOT used: the registry calls them
/// "Audit Rules Hardening" and "MAC System Hardening", so rendering it would
/// have replaced a third naming scheme with a fourth rather than removing one.
pub(crate) fn plugin_display_name(plugin_id: &str) -> &'static str {
    PLUGINS
        .iter()
        .find(|p| hardener_types::plugin_id_named_by(plugin_id, p.id))
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

/// The partial view's (Task 2a.7) real second-line text for a `Failed` row:
/// the first genuine failure (non-skipped, non-checkpoint, failed, and NOT
/// a manual action - the same definition `classify_apply_result` uses),
/// preferring its `change_error` and falling back to `change_description`
/// if the error text is empty. Mirroring the classifier's own "genuine
/// failure" filter keeps the row's revealed text pinned to whichever
/// change actually put it in the Failed bucket.
fn failure_detail(result: &ApplyResult) -> String {
    result
        .apply_changes
        .iter()
        .find(|c| {
            !c.is_skipped() && !c.is_checkpoint() && !c.change_success && !is_manual_action(c)
        })
        .map(|c| {
            c.change_error
                .clone()
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| c.change_description.clone())
        })
        .unwrap_or_default()
}

/// The partial view's (Task 2a.7) real second-line instruction for a
/// `ManualStep` row: the first manual-action change's `change_description`,
/// never `change_error`, which only ever holds the marker literal, not
/// human-readable guidance.
fn manual_step_detail(result: &ApplyResult) -> String {
    result
        .apply_changes
        .iter()
        .find(|c| is_manual_action(c))
        .map(|c| c.change_description.clone())
        .unwrap_or_default()
}

/// The partial view's (Task 2a.7) status text for a `Skipped` row:
/// "Skipped: {reason}" using the first skip entry's own description as the
/// human reason, falling back to a bare "Skipped" when that description is
/// empty (or there is no skip entry at all, e.g. an area with zero
/// attempted changes).
fn skipped_status_text(result: &ApplyResult) -> String {
    result
        .apply_changes
        .iter()
        .find(|c| c.is_skipped())
        .map(|c| c.change_description.clone())
        .filter(|d| !d.is_empty())
        .map(|reason| format!("Skipped: {reason}"))
        .unwrap_or_else(|| "Skipped".to_string())
}

/// Number of steps in the score count-up animation, and the delay between
/// them - together the animated duration, matched to `SCORE_REVEAL_MIN_MS`
/// so the number finishes counting roughly when the reveal beat ends.
const SCORE_COUNT_UP_STEPS: u32 = 16;
const SCORE_COUNT_UP_STEP: Duration = Duration::from_millis(50);

/// Minimum time the score-reveal strip spends showing "Scanning..." (Step
/// 3), even when the scan+report+score round trip resolves faster - long
/// enough for the beat to read as deliberate rather than a flicker.
const SCORE_REVEAL_MIN_MS: f64 = 800.0;

/// How long the one-time success-tint flash (Step 3) stays on before the
/// CSS transition fades it back out.
const SCORE_FLASH_MS: u64 = 600;

/// Client-side signals driving the one-time security-score reveal beat
/// shown after a fully successful apply (Step 3). Bundled as one `Copy`
/// struct - mirroring `HardeningSection`'s newtype pattern below - so the
/// DONE view here and Task 2a.7's PARTIAL view can each construct their own
/// instance and drive it through the same [`run_score_reveal`], rather than
/// duplicating the reveal mechanics.
#[derive(Clone, Copy)]
struct ScoreReveal {
    /// True only while the "Scanning..." beat is in flight.
    revealing: RwSignal<bool>,
    /// `Some(score)` once a reveal has completed; `None` before the first
    /// scan this session (score honesty: no number until a real scan).
    revealed: RwSignal<Option<i32>>,
    /// The count-up value actually rendered; animates from the previous
    /// score (or 0) up to `revealed`'s value, and also drives the sweeping
    /// bar's width so the two stay in lockstep.
    displayed: RwSignal<i32>,
    /// `score_delta_label`'s output for the current reveal ("Up N points",
    /// "No change", "Down N points", or empty with no prior score).
    delta_text: RwSignal<String>,
    /// Toggled true then back false shortly after a reveal completes, to
    /// drive the one-time success-tint CSS flash.
    flash: RwSignal<bool>,
}

impl ScoreReveal {
    fn new() -> Self {
        Self {
            revealing: RwSignal::new(false),
            revealed: RwSignal::new(None),
            displayed: RwSignal::new(0),
            delta_text: RwSignal::new(String::new()),
            flash: RwSignal::new(false),
        }
    }

    /// Resets every signal to its pre-scan initial state.
    ///
    /// Score honesty ("no number until a real scan") must hold not only
    /// before the first-ever scan but at the start of every subsequent
    /// apply cycle - without this, a reveal completed after one apply (e.g.
    /// 88/100) would still be sitting in these signals the next time the
    /// done view mounts, showing a stale score before the new state has
    /// been scanned at all. Called from `on_confirm_apply` (so a fresh
    /// cycle never inherits the previous one's reveal) and from `on_done`
    /// (tidiness on the way back to the selection view).
    fn reset(&self) {
        self.revealing.set(false);
        self.revealed.set(None);
        self.displayed.set(0);
        self.delta_text.set(String::new());
        self.flash.set(false);
    }
}

/// Whether the user's OS/browser preference asks for reduced motion.
///
/// `web-sys`'s `MediaQueryList` binding is not among this crate's enabled
/// features (and Cargo.toml is out of scope for this task - see the task
/// brief), so this reaches `window.matchMedia` through `js_sys::Reflect`
/// instead of the typed `Window::match_media` method. Defaults to `false`
/// (full motion) if `window` or the call is unavailable for any reason,
/// same fail-open posture as every other best-effort browser feature check
/// in this crate.
fn prefers_reduced_motion() -> bool {
    (|| -> Option<bool> {
        let window = web_sys::window()?;
        let window: &JsValue = window.as_ref();
        let match_media = js_sys::Reflect::get(window, &JsValue::from_str("matchMedia")).ok()?;
        let match_media = match_media.dyn_ref::<js_sys::Function>()?;
        let query = match_media
            .call1(
                window,
                &JsValue::from_str("(prefers-reduced-motion: reduce)"),
            )
            .ok()?;
        js_sys::Reflect::get(&query, &JsValue::from_str("matches"))
            .ok()?
            .as_bool()
    })()
    .unwrap_or(false)
}

/// Animates `displayed` counting from `from` to `to` over
/// `SCORE_COUNT_UP_STEPS * SCORE_COUNT_UP_STEP` (Step 3's count-up), via
/// `leptos::prelude::set_interval_with_handle` - the codebase's established
/// timer primitive (re-exported from `leptos_dom::helpers`, itself the
/// `web_sys::Window::set_timeout`/`set_interval` pattern used in
/// `clipboard.rs`/`sidebar.rs`/`lib.rs`), so no new dependency is needed.
/// The interval clears itself on its final tick - no leaked timer. Seeds
/// `displayed` to `from` synchronously, before the interval's first tick,
/// so the strip never renders the signal's untouched prior value (a bare
/// "0/100" flash) for the one frame between mount and that first tick.
fn animate_score_count_up(displayed: RwSignal<i32>, from: i32, to: i32) {
    displayed.set(from);

    let step = Rc::new(Cell::new(0_u32));
    let handle: Rc<Cell<Option<IntervalHandle>>> = Rc::new(Cell::new(None));
    let handle_for_tick = handle.clone();

    let Ok(interval_handle) = set_interval_with_handle(
        move || {
            let n = step.get() + 1;
            step.set(n);
            let progress = (f64::from(n) / f64::from(SCORE_COUNT_UP_STEPS)).min(1.0);
            displayed.set(from + ((to - from) as f64 * progress).round() as i32);
            if n >= SCORE_COUNT_UP_STEPS
                && let Some(h) = handle_for_tick.take()
            {
                h.clear();
            }
        },
        SCORE_COUNT_UP_STEP,
    ) else {
        // set_interval itself failed (no window) - settle immediately
        // rather than leaving the number stuck at `from`.
        displayed.set(to);
        return;
    };
    handle.set(Some(interval_handle));
}

/// Sets `flash` true, then back to false after `SCORE_FLASH_MS` - the
/// one-time success-tint flash (Step 3). Mirrors `clipboard.rs`'s
/// set-then-reset status pattern.
fn flash_once(flash: RwSignal<bool>) {
    flash.set(true);
    set_timeout(
        move || flash.set(false),
        Duration::from_millis(SCORE_FLASH_MS),
    );
}

/// Runs the score-reveal beat (Step 3): captures the previous score (if
/// any), runs a fresh scan+report+score cycle following `quick_actions.rs`'s
/// `on_run_scan` pattern exactly, enforces `SCORE_REVEAL_MIN_MS` as a floor
/// on the "Scanning..." beat, then reveals - animating the count-up (or
/// jumping straight to the final value under reduced motion) and firing the
/// one-time flash. An explicit user action only (a button click); never
/// wired to an effect that could re-fire on a passive re-render. Re-running
/// while already revealing is a no-op, so a double-click cannot start two
/// overlapping scans.
///
/// Free function, not inlined into the component, and takes its signals as
/// plain parameters (not a prop) precisely so 2a.7's partial/mixed view can
/// call it with its own [`ScoreReveal`] instance.
fn run_score_reveal(app_state: AppState, reveal: ScoreReveal) {
    if reveal.revealing.get_untracked() {
        return;
    }
    reveal.revealing.set(true);
    reveal.delta_text.set(String::new());

    let previous = {
        let reports = app_state.compliance_reports.get_untracked();
        if reports.is_empty() {
            None
        } else {
            Some(calculate_all_scores(&reports).0)
        }
    };

    let start_ms = js_sys::Date::now();

    leptos::task::spawn_local(async move {
        let mut new_score = previous.unwrap_or(0);
        // Fix 3: only a real, freshly-computed score may be revealed - a
        // failed scan or report generation must not fall back to showing
        // `previous` again as if it had just been measured.
        let mut succeeded = true;

        match invoke_scan(vec![], app_state.config_path.get_untracked()).await {
            Ok(results) => {
                app_state.scan_results.set(results);

                let frameworks = hardener_types::ComplianceFramework::ALL
                    .iter()
                    .map(|f| f.id().to_string())
                    .collect();
                match invoke_generate_report(frameworks).await {
                    Ok(reports) => {
                        new_score = calculate_all_scores(&reports).0;
                        app_state.compliance_reports.set(reports);
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("Compliance generation failed: {}", e).into(),
                        );
                        succeeded = false;
                    }
                }
            }
            Err(e) => {
                web_sys::console::error_1(&format!("Scan failed: {}", e).into());
                app_state
                    .error_message
                    .set(Some(format!("Scan failed: {}", e)));
                succeeded = false;
            }
        }

        let elapsed_ms = js_sys::Date::now() - start_ms;
        let remaining_ms = (SCORE_REVEAL_MIN_MS - elapsed_ms).max(0.0) as u64;

        set_timeout(
            move || {
                reveal.revealing.set(false);

                // Error path: let the strip fall back to its
                // "Run Security Scan" action rather than reveal a number
                // that was never actually measured this cycle. Whatever
                // error_message the failure above set (currently only the
                // invoke_scan arm does) still surfaces via the existing
                // error banner independently of this signal.
                if !succeeded {
                    reveal.revealed.set(None);
                    return;
                }

                reveal.revealed.set(Some(new_score));
                reveal
                    .delta_text
                    .set(score_delta_label(previous, new_score));

                if prefers_reduced_motion() {
                    reveal.displayed.set(new_score);
                } else {
                    animate_score_count_up(reveal.displayed, previous.unwrap_or(0), new_score);
                }
                flash_once(reveal.flash);
            },
            Duration::from_millis(remaining_ms),
        );
    });
}

/// The strip Task 2a.6's done view and 2a.7's partial view both render
/// verbatim beneath their own status-specific content: the three shared
/// actions (View in History / Done / Run Security Scan) and the
/// score-reveal beat itself (Step 3 - no number shown until a real scan
/// runs, then a count-up reveal via [`run_score_reveal`]). Factored into
/// one place, per the 2a.7 brief, rather than each `Show` branch below
/// carrying its own copy of this markup.
///
/// Takes `app_state`/`score_reveal`/`hardening_section` directly rather
/// than pre-built closures, so it can construct all three action handlers
/// itself - each depends on nothing else from either caller's scope. A
/// bare `<div>` would break the `.done-panel`/`.partial-panel` flex gap
/// this strip's pieces (`.done-actions`, `.score-reveal`, the `sr-only`
/// live region) rely on from their parent, so the wrapper is `display:
/// contents` in CSS - present in the DOM for this function's single
/// `impl IntoView` return, invisible to layout.
fn score_strip(
    app_state: AppState,
    score_reveal: ScoreReveal,
    hardening_section: Option<HardeningSection>,
) -> impl IntoView {
    let on_view_history = move |_| {
        if let Some(section) = hardening_section {
            section.0.set(1);
        }
    };
    let on_done = move |_| {
        app_state.apply_results.set(Vec::new());
        score_reveal.reset();
    };
    let on_run_security_scan = move |_| {
        run_score_reveal(app_state, score_reveal);
    };

    view! {
        <div class="score-strip">
            <div class="done-actions">
                <button type="button" class="btn btn-secondary" on:click=on_view_history>
                    "View in History"
                </button>
                <button type="button" class="btn btn-secondary" on:click=on_done>
                    "Done"
                </button>
                <button
                    type="button"
                    class="btn btn-primary"
                    on:click=on_run_security_scan
                    disabled=move || score_reveal.revealing.get()
                >
                    "Run Security Scan"
                </button>
            </div>

            // Step 3 - the score-reveal strip. Score honesty: before the
            // first scan this renders nothing (the button above is the
            // only affordance); while scanning it shows the "Scanning..."
            // beat; once revealed it settles into the number (a NOTCH above
            // body text, never a hero size), the delta copy, and the
            // sweeping bar. The dedicated sr-only live region below carries
            // the announcement on its own, once per reveal, independent of
            // this markup.
            <div class="score-reveal">
                {move || {
                    if score_reveal.revealing.get() {
                        view! { <p class="score-reveal-status">"Scanning..."</p> }.into_any()
                    } else if score_reveal.revealed.get().is_some() {
                        let delta = score_reveal.delta_text.get();
                        view! {
                            <div class="score-reveal-content">
                                <div
                                    class="score-reveal-result"
                                    class:score-reveal-flash=move || score_reveal.flash.get()
                                >
                                    <span class="score-reveal-value">{move || score_reveal.displayed.get()}</span>
                                    <span class="score-reveal-max">"/100"</span>
                                    {(!delta.is_empty()).then(|| view! {
                                        <span class="score-reveal-delta">{delta.clone()}</span>
                                    })}
                                </div>
                                <div class="score-reveal-bar" aria-hidden="true">
                                    <div
                                        class="score-reveal-bar-fill"
                                        style=move || format!(
                                            "width: {}%",
                                            score_reveal.displayed.get().clamp(0, 100)
                                        )
                                    ></div>
                                </div>
                            </div>
                        }.into_any()
                    } else {
                        view! { <div></div> }.into_any()
                    }
                }}
            </div>
            <p class="sr-only" aria-live="polite">
                {move || {
                    score_reveal.revealed.get().map(|score| {
                        let delta = score_reveal.delta_text.get();
                        if delta.is_empty() {
                            format!("Security score {score}.")
                        } else {
                            format!("Security score {score}, {}.", delta.to_lowercase())
                        }
                    }).unwrap_or_default()
                }}
            </p>
        </div>
    }
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

    // Display names of the enabled areas, in PLUGINS order - feeds both the
    // calm checking view's skeleton rows and the applying view's active
    // rows below. Derived from get_enabled_plugins(): a real reflection of
    // the current selection, not fabricated per-item progress (there is
    // none to report for either view; see on_preview and on_confirm_apply).
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

    // Preview handler - runs dry-run and shows preview panel
    let on_preview = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        checking_cancelled.set(false);
        lockout_ack.set(false);
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
                Err(e) if is_auth_cancelled(&e) => {
                    // The preview's polkit prompt was dismissed. Mirror
                    // on_confirm_apply's arm for the same outcome: a
                    // cancelled prompt is a choice, not a failure, so the
                    // wizard returns to the selection view without an
                    // error banner.
                    if !checking_cancelled.get_untracked() {
                        web_sys::console::info_1(&"Preview cancelled by user.".into());
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
    // so it does not survive into the next review pass.
    let on_cancel_preview = move |_| {
        app_state.show_preview.set(false);
        app_state.preview_results.set(Vec::new());
        lockout_ack.set(false);
    };

    // Done view (Step 3) - the score-reveal signals, bundled so
    // `run_score_reveal` can be handed one value. Declared here, ahead of
    // `on_confirm_apply` below, so that closure can reset it too.
    let score_reveal = ScoreReveal::new();

    // Confirm and apply - runs actual apply after preview
    let on_confirm_apply = move |_| {
        let plugins = get_enabled_plugins();
        if plugins.is_empty() {
            return;
        }

        // Fix: a completed reveal from a PRIOR apply cycle (e.g. 88/100)
        // must not survive into this one - without this, the done view for
        // this new apply would show that stale number before any new scan
        // has run. Score honesty applies per cycle, not just once ever.
        score_reveal.reset();

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

    // Step 3/4's reassurance and lockout tick describe what an apply will do.
    // With nothing to apply, none of it happens: no checkpoint, no password
    // prompt, no lockout risk. Gate both on there being real work, leaving
    // Cancel and the disabled "Nothing to Apply" button as the way out.
    let total_changes = Signal::derive(move || total_estimated_changes(&get_decisions()));
    let has_changes = Signal::derive(move || total_changes.get() != 0);

    // How many areas produced no estimate because something stopped them,
    // rather than because they were clean. The rows below already refuse to
    // call such an area compliant; the summary needs the same fact or it
    // contradicts them, which it did for every selection with zero changes.
    let areas_with_issues = Signal::derive(move || {
        get_decisions()
            .iter()
            .filter(|d| !d.issues.is_empty())
            .count()
    });

    // Done view (Step 4) - the Hardening page's tab-section signal, read
    // via `use_context` (not `expect_context`) so this component still
    // works if it is ever mounted outside `HardeningPage`; "View in
    // History" (built inside `score_strip`, shared by the done and partial
    // views) no-ops gracefully when absent.
    let hardening_section = use_context::<HardeningSection>();

    // Partial view (Task 2a.7): which rows' "View details"/"How?" toggle
    // has been opened, keyed by the row's full backend plugin id -
    // independent per row, client-side only. Reveals text already present
    // in `apply_results`; never fetches anything new (brief Step 3).
    let expanded_rows: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    let toggle_expanded = move |plugin_id: String| {
        expanded_rows.update(|set| {
            if !set.remove(&plugin_id) {
                set.insert(plugin_id);
            }
        });
    };

    // Retry (Task 2a.7): re-applies just the one plugin behind a Failed
    // row, mirroring `on_confirm_apply`'s success/cancelled/error handling
    // above. On success REPLACES that plugin's entry in `apply_results` in
    // place (matched on `apply_plugin_id`) - including when the retried
    // result is itself still failed - rather than appending a second entry
    // for the same area. `Some(plugin_id)` while a retry is in flight
    // disables that row's own Retry button; other rows are unaffected.
    let retrying_plugin: RwSignal<Option<String>> = RwSignal::new(None);
    let on_retry = move |plugin_id: String| {
        if retrying_plugin.get_untracked().is_some() {
            return;
        }
        retrying_plugin.set(Some(plugin_id.clone()));

        leptos::task::spawn_local(async move {
            match invoke_apply(
                vec![plugin_id.clone()],
                app_state.config_path.get_untracked(),
            )
            .await
            {
                Ok(results) => {
                    if let Some(new_result) = results.into_iter().next() {
                        app_state.apply_results.update(|all| {
                            match all
                                .iter_mut()
                                .find(|r| r.apply_plugin_id.as_str() == plugin_id)
                            {
                                Some(existing) => *existing = new_result,
                                None => all.push(new_result),
                            }
                        });
                    }
                }
                Err(e) if is_auth_cancelled(&e) => {
                    web_sys::console::info_1(&"Retry cancelled by user.".into());
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Retry failed: {}", e).into());
                    app_state
                        .error_message
                        .set(Some(format!("Retry failed: {}", e)));
                }
            }
            retrying_plugin.set(None);
        });
    };

    view! {
        <div class="configure-section">
            // Step 1 - once the review has a result to show, it takes full
            // attention: the selection UI (segmented control, plugin rows,
            // the old "N areas selected" aside) steps aside rather than
            // sitting duplicated above the review's own compact summary
            // header. [Edit] (below) is the only way back to this. Also
            // steps aside for the whole real apply (`!is_applying`):
            // on_confirm_apply sets show_preview false in the same tick it
            // sets is_applying true, so without this second guard this
            // selection UI - not the review card, which is already gated on
            // show_preview alone - would be what reappeared underneath the
            // applying view below. And steps aside once there is a result to
            // show (`apply_results` non-empty): the done view below (Step 2)
            // - or 2a.7's partial view - is what replaces it then, until
            // "Done" clears apply_results again.
            <Show when=move || {
                !app_state.show_preview.get()
                    && !app_state.is_applying.get()
                    && app_state.apply_results.get().is_empty()
            }>
            <div class="configure-layout">
                <div class="configure-main" class:is-disabled=move || app_state.is_previewing.get()>
                    <SegmentedControl
                        aria_label="Protection level"
                        segments=PROFILES
                        selected=selected_profile
                        on_select=Callback::new({
                            let update_profile = update_profile.clone();
                            move |id: String| {
                                if id == "custom" {
                                    selected_profile.set("custom".to_string());
                                } else {
                                    update_profile(&id);
                                }
                            }
                        })
                        disabled=app_state.is_previewing
                    />

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
                    //
                    // The preview elevates through the same pkexec channel as
                    // the apply it previews, so the polkit prompt can appear
                    // while this view is up; the reassurance says so, because
                    // a password dialog with no warning reads as a change
                    // starting rather than a read.
                    <Show
                        when=move || !app_state.is_previewing.get()
                        fallback=move || {
                            let areas = checking_areas();
                            let count = areas.len();
                            view! {
                                <div class="checking-view" aria-live="polite">
                                    <p class="checking-reassurance">"Nothing is changed yet. You may be asked for your password, which is used to read the settings the same way Apply will read them."</p>
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
                                    // The names, not only the count: this column
                                    // is the live "what will change" summary, and
                                    // a count alone left it empty below the
                                    // button. The names are the same selection
                                    // the checking view lists a moment later.
                                    view! {
                                        <p class="apply-summary-text">
                                            {format!("{} area{} selected", n, if n == 1 { "" } else { "s" })}
                                        </p>
                                        <p class="apply-summary-areas">{checking_areas().join(", ")}</p>
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
                                    // An issue means the estimate is not a
                                    // clean bill of health: the plugin may
                                    // have produced no changes because it
                                    // could not read anything. Never let such
                                    // a group claim "Already compliant".
                                    let issues = decision.issues.clone();

                                    if decision.verified_compliant && issues.is_empty() {
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
                                                <summary>
                                                    <IconCheck class="review-group-check-icon".to_string() />
                                                    <span class="review-group-name">{name}</span>
                                                    {pill.map(|p| view! { <span class="lockout-pill">{p}</span> })}
                                                    <span class="review-group-count">
                                                        {format!("{} change{}", count, if count == 1 { "" } else { "s" })}
                                                    </span>
                                                </summary>
                                                <ul class="review-group-issues">
                                                    {issues.iter().map(|issue| {
                                                        let label = issue.validation_issue_severity.to_string();
                                                        let key = issue.validation_issue_config_key.clone();
                                                        view! {
                                                            <li class="review-group-issue">
                                                                <span class="review-group-issue-severity">{label}</span>
                                                                <span>{issue.validation_issue_message.clone()}</span>
                                                                {key.map(|k| view! {
                                                                    <span class="review-group-issue-key">{k}</span>
                                                                })}
                                                            </li>
                                                        }
                                                    }).collect::<Vec<_>>()}
                                                </ul>
                                                <ul class="review-group-changes">
                                                    {decision.estimated_changes.iter().map(|change| {
                                                        view! { <li>{change.clone()}</li> }
                                                    }).collect::<Vec<_>>()}
                                                </ul>
                                                // A setting left alone because
                                                // a policy exception documents
                                                // it. Rendered below the
                                                // pending changes, in its own
                                                // list, so it can neither be
                                                // mistaken for one nor vanish.
                                                <ul class="review-group-exceptions">
                                                    {decision.exceptions.iter().map(|exception| {
                                                        view! { <li>{exception.clone()}</li> }
                                                    }).collect::<Vec<_>>()}
                                                </ul>
                                            </details>
                                        }.into_any()
                                    }
                                }).collect::<Vec<_>>().into_any()
                            }
                        }}
                    </div>

                    // Step 3 - the count-named confirm, in a calm accent box
                    // (never red/warning) beside the checkpoint/password
                    // reassurance. Step 4 - the single lockout tick lives in
                    // the same box, shown only when the selection includes
                    // an ssh/firewall area.
                    <div class="review-confirm-box">
                        // With nothing staged the box would otherwise draw an
                        // empty accent frame around the two buttons: the
                        // reassurance was gated on has_changes but the box was
                        // not. Say why there is nothing to confirm instead.
                        <Show
                            when=move || has_changes.get()
                            fallback=move || view! {
                                <p class="review-confirm-reassurance">
                                    {move || nothing_to_apply_line(areas_with_issues.get())}
                                </p>
                            }
                        >
                            <p class="review-confirm-reassurance">
                                "A checkpoint is saved first, and you will be asked for your password. You can undo everything from History."
                            </p>
                        </Show>

                        <Show when=move || has_lockout() && has_changes.get()>
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
                                    app_state.is_applying.get()
                                        || total_changes.get() == 0
                                        || (has_lockout() && !lockout_ack.get())
                                }
                                aria-live="polite"
                            >
                                // No "Applying..." branch here: on_confirm_apply sets
                                // show_preview false in the same tick it sets is_applying
                                // true, so this button (inside the show_preview Show) is
                                // never visible while is_applying is true - the dedicated
                                // applying view below is what the user sees instead. The
                                // disabled check above stays as a defensive guard.
                                {move || {
                                    let total = total_changes.get();
                                    if total == 0 {
                                        "Nothing to Apply".to_string()
                                    } else {
                                        format!("Apply {} Change{}", total, if total == 1 { "" } else { "s" })
                                    }
                                }}
                            </button>
                        </div>

                        <Show when=move || has_lockout() && !lockout_ack.get() && has_changes.get()>
                            <p class="review-lockout-hint">"Tick the box above to enable Apply."</p>
                        </Show>
                    </div>
                </Card>
            </Show>

            // Applying step - the real apply is running. Flow: choose
            // (2a.1) -> checking (2a.2) -> review (2a.3) -> applying (here)
            // -> done/partial (2a.6/2a.7). on_confirm_apply above sets
            // is_applying true and show_preview false in the same tick, so
            // both the selection UI (gated on !show_preview && !is_applying)
            // and the review card (gated on show_preview) are already
            // hidden here - this is the only one of the three visible while
            // an apply is in flight.
            //
            // Same no-progress-stream reality as the checking view: local
            // apply is one invoke_apply call with no per-plugin signal, so
            // this makes no "area X done" claim either - every row keeps
            // one active, indeterminate indicator for the whole apply,
            // never a green tick (that is the real applied status, only
            // knowable once apply_results is read in the done/partial
            // view). This is also the flow's one destructive "changing
            // now" moment, so unlike the calm checking view: a checkpoint
            // reassurance sits up top, the "keep this window open" note is
            // muted (never amber - amber is reserved for the Manual step
            // status), and there is no Cancel (apply has no safe mid-write
            // abort to offer).
            <Show when=move || app_state.is_applying.get()>
                <Card title="Applying Changes" title_level=HeadingLevel::H2 class="applying-panel">
                    <p class="applying-reassurance">
                        "A checkpoint was saved first, so you can undo everything from History."
                    </p>
                    <ul class="checking-skeleton-list" aria-live="polite">
                        {move || {
                            checking_areas().into_iter().enumerate().map(|(i, name)| {
                                view! {
                                    <li
                                        class="checking-skeleton-row"
                                        style=format!("animation-delay: {}ms", i * 70)
                                    >
                                        <span class="applying-area-indicator" aria-hidden="true"></span>
                                        <span class="checking-skeleton-name">{name}</span>
                                    </li>
                                }
                            }).collect::<Vec<_>>()
                        }}
                    </ul>
                    <p class="applying-keep-open">"Keep this window open until this finishes."</p>
                </Card>
            </Show>

            // Done view (Step 2) - the SUCCESS state, shown once the apply
            // has finished and every result came back clean. 2a.7 adds the
            // sibling PARTIAL/mixed branch directly below this one, gated on
            // `!apply_fully_successful(&results) && !results.is_empty()` (the
            // two conditions are mutually exclusive over the same
            // apply_results signal, so nothing here needs to change for that
            // slice to land - this is the seam the brief calls for).
            <Show when=move || {
                !app_state.is_applying.get() && apply_fully_successful(&app_state.apply_results.get())
            }>
                <Card title_level=HeadingLevel::H2 class="done-panel">
                    <div class="done-heading">
                        <IconCheck class="done-heading-icon".to_string() />
                        <h2 class="done-heading-title">"System Hardened"</h2>
                    </div>
                    <p class="done-summary-line">
                        {move || {
                            let (settings, areas) = applied_settings_and_areas(&app_state.apply_results.get());
                            format!(
                                "{} setting{} applied across {} area{}",
                                settings,
                                if settings == 1 { "" } else { "s" },
                                areas,
                                if areas == 1 { "" } else { "s" },
                            )
                        }}
                    </p>

                    <ul class="done-area-list">
                        {move || {
                            app_state.apply_results.get().into_iter().map(|result| {
                                let name = plugin_display_name(result.apply_plugin_id.as_str());
                                if result.applied_change_count() == 0 {
                                    view! {
                                        <li class="done-area-row done-area-compliant">
                                            <IconMinus class="done-area-minus-icon".to_string() />
                                            <span class="done-area-name">{name}</span>
                                            <span class="done-area-note">"Already compliant, skipped"</span>
                                        </li>
                                    }.into_any()
                                } else {
                                    let summary = apply_change_summary(&result);
                                    view! {
                                        <li class="done-area-row">
                                            <IconCheck class="done-area-check-icon".to_string() />
                                            <span class="done-area-name">{name}</span>
                                            <span class="done-area-summary">{summary}</span>
                                        </li>
                                    }.into_any()
                                }
                            }).collect::<Vec<_>>()
                        }}
                    </ul>

                    <p class="done-checkpoint-reassurance">
                        "A checkpoint was saved. You can undo everything from History."
                    </p>

                    {score_strip(app_state, score_reveal, hardening_section)}
                </Card>
            </Show>

            // Partial/mixed view (Task 2a.7) - the honest sad path: shown
            // once the apply has finished with at least one failed change
            // anywhere, or with nothing genuinely applied and nothing
            // failed either (an all-skipped/all-compliant result - see
            // `apply_fully_successful`'s own doc comment on why an empty or
            // all-skip outcome is deliberately not a "success"). Mutually
            // exclusive with the done view immediately above: both read the
            // same `apply_results`/`is_applying` signals, and this Show's
            // third condition is exactly `apply_fully_successful`'s
            // complement, so the two can never both be visible at once -
            // the seam 2a.6 left, now filled in.
            //
            // Layout is the ACCEPTED one from the brief: a small header
            // (a 28px neutral/amber-tinted circle beside a single summary
            // sentence, no separate bold title line), then a clean
            // single-column list with hairline row separators. The two
            // REJECTED variants - a left-status-column layout, and a headed
            // two-up grid - do not appear here.
            <Show when=move || {
                !app_state.is_applying.get()
                    && !app_state.apply_results.get().is_empty()
                    && !apply_fully_successful(&app_state.apply_results.get())
            }>
                <Card title_level=HeadingLevel::H2 class="partial-panel">
                    <div class="partial-heading">
                        <span class="partial-heading-icon" aria-hidden="true">
                            <IconInfo class="partial-heading-icon-glyph".to_string() />
                        </span>
                        <p class="partial-heading-text">
                            {move || partial_summary_sentence(&app_state.apply_results.get())}
                        </p>
                    </div>

                    <ul class="partial-area-list">
                        {move || {
                            app_state.apply_results.get().into_iter().map(|result| {
                                let plugin_id = result.apply_plugin_id.as_str().to_string();
                                let name = plugin_display_name(&plugin_id);
                                let outcome = classify_apply_result(&result);

                                match outcome {
                                    ApplyOutcome::Applied => view! {
                                        <li class="partial-row">
                                            <div class="partial-row-main">
                                                <IconCheck class="partial-row-icon partial-row-icon-applied".to_string() />
                                                <span class="partial-row-name">{name}</span>
                                                <span class="partial-row-status">
                                                    {format!("{} applied", result.applied_change_count())}
                                                </span>
                                            </div>
                                        </li>
                                    }.into_any(),

                                    ApplyOutcome::Skipped => view! {
                                        <li class="partial-row">
                                            <div class="partial-row-main">
                                                <IconMinus class="partial-row-icon partial-row-icon-skipped".to_string() />
                                                <span class="partial-row-name">{name}</span>
                                                <span class="partial-row-status">{skipped_status_text(&result)}</span>
                                            </div>
                                        </li>
                                    }.into_any(),

                                    ApplyOutcome::Failed => {
                                        let detail = failure_detail(&result);
                                        let pid_for_show = plugin_id.clone();
                                        let pid_for_aria = plugin_id.clone();
                                        let pid_for_toggle = plugin_id.clone();
                                        let pid_for_disabled = plugin_id.clone();
                                        let pid_for_label = plugin_id.clone();
                                        let pid_for_retry = plugin_id.clone();
                                        view! {
                                            <li class="partial-row">
                                                <div class="partial-row-main">
                                                    <IconX class="partial-row-icon partial-row-icon-failed".to_string() />
                                                    <span class="partial-row-name">{name}</span>
                                                    <span class="partial-row-badge partial-row-badge-failed">"Failed"</span>
                                                    <button
                                                        type="button"
                                                        class="btn btn-secondary btn-small"
                                                        disabled=move || retrying_plugin.get().as_deref() == Some(pid_for_disabled.as_str())
                                                        on:click=move |_| on_retry(pid_for_retry.clone())
                                                    >
                                                        {move || if retrying_plugin.get().as_deref() == Some(pid_for_label.as_str()) {
                                                            "Retrying..."
                                                        } else {
                                                            "Retry"
                                                        }}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="partial-row-toggle"
                                                        aria-expanded=move || expanded_rows.get().contains(&pid_for_aria).to_string()
                                                        on:click=move |_| toggle_expanded(pid_for_toggle.clone())
                                                    >
                                                        "View details"
                                                    </button>
                                                </div>
                                                <Show when=move || expanded_rows.get().contains(&pid_for_show)>
                                                    <p class="partial-row-detail">{detail.clone()}</p>
                                                </Show>
                                            </li>
                                        }.into_any()
                                    }

                                    ApplyOutcome::ManualStep => {
                                        let detail = manual_step_detail(&result);
                                        let pid_for_show = plugin_id.clone();
                                        let pid_for_aria = plugin_id.clone();
                                        let pid_for_toggle = plugin_id.clone();
                                        view! {
                                            <li class="partial-row">
                                                <div class="partial-row-main">
                                                    <IconWrench class="partial-row-icon partial-row-icon-manual".to_string() />
                                                    <span class="partial-row-name">{name}</span>
                                                    <span class="partial-row-badge partial-row-badge-manual">"Manual step"</span>
                                                    <button
                                                        type="button"
                                                        class="partial-row-toggle"
                                                        aria-expanded=move || expanded_rows.get().contains(&pid_for_aria).to_string()
                                                        on:click=move |_| toggle_expanded(pid_for_toggle.clone())
                                                    >
                                                        "How?"
                                                    </button>
                                                </div>
                                                <Show when=move || expanded_rows.get().contains(&pid_for_show)>
                                                    <p class="partial-row-detail partial-row-detail-mono">{detail.clone()}</p>
                                                </Show>
                                            </li>
                                        }.into_any()
                                    }
                                }
                            }).collect::<Vec<_>>()
                        }}
                    </ul>

                    <p class="done-checkpoint-reassurance">
                        "Only the applied changes can be rolled back."
                    </p>

                    {score_strip(app_state, score_reveal, hardening_section)}
                </Card>
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests;
