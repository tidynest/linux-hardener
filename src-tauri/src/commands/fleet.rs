//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// Number of hosts scanned concurrently in a fleet scan.
pub(crate) const FLEET_CONCURRENCY: usize = 8;

/// Scans many hosts concurrently, isolating per-host failure and preserving
/// input order. `scan_one` produces one host's resolved compliance profile and
/// scan results (or an error that becomes a `Failed` row). Each row carries the
/// profile it was scanned under in `FleetHostScan::profile`: it drives posture
/// scoring, travels to the UI as the scheme that scored the row, and is
/// `Generic` for failed hosts. `on_progress` fires once per completed host, in
/// completion order, with (host row, completed count, total): the UI's live
/// progress hook. Generic so the orchestration is unit-testable without real
/// SSH or a Tauri app handle.
///
/// ponytail: a spawned task that *panics* (rather than returning `Err`) keeps
/// its pre-filled `Failed` slot, so the result always has exactly one row per
/// input host in input order, never a silently dropped host (panicked tasks
/// emit no progress event; the scan still ends because the invoke resolves).
pub(crate) async fn scan_fleet<F, Fut>(
    host_names: Vec<String>,
    scan_one: F,
    mut on_progress: impl FnMut(&FleetHostScan, usize, usize),
) -> Vec<FleetHostScan>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(ComplianceProfile, Vec<ScanResult>), String>>
        + Send
        + 'static,
{
    let total = host_names.len();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(FLEET_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();

    // One placeholder row per host, overwritten as tasks complete. A panicked
    // task leaves its placeholder, preserving the one-row-per-host contract.
    let mut ordered: Vec<FleetHostScan> = host_names
        .iter()
        .map(|name| FleetHostScan {
            host_name: name.clone(),
            status: FleetHostStatus::Failed("scan task panicked".to_string()),
            tallies: SeverityTallies::default(),
            scan_results: Vec::new(),
            compliance: Vec::new(),
            profile: ComplianceProfile::Generic,
        })
        .collect();

    for (index, name) in host_names.into_iter().enumerate() {
        let permits = semaphore.clone();
        let task = scan_one(name.clone());
        set.spawn(async move {
            let _permit = permits.acquire_owned().await;
            let (profile, status, scan_results) = match task.await {
                Ok((profile, results)) => (profile, FleetHostStatus::Ok, results),
                Err(e) => (
                    ComplianceProfile::Generic,
                    FleetHostStatus::Failed(e),
                    Vec::new(),
                ),
            };
            (
                index,
                FleetHostScan {
                    host_name: name,
                    tallies: SeverityTallies::from_results(&scan_results),
                    status,
                    scan_results,
                    compliance: Vec::new(),
                    profile,
                },
            )
        });
    }

    let mut completed = 0;
    while let Some(joined) = set.join_next().await {
        if let Ok((index, scan)) = joined {
            completed += 1;
            on_progress(&scan, completed, total);
            ordered[index] = scan;
        }
    }
    ordered
}

/// Scans a remote host using the active SSH connection.
///
/// Uses the `SshExecutor` from `RemoteState` instead of the local executor.
/// Results are returned in-memory only (not persisted to scan history).
#[tauri::command]
pub async fn run_remote_scan(
    plugin_ids: Option<Vec<String>>,
    state: tauri::State<'_, RemoteState>,
) -> Result<Vec<ScanResult>, String> {
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }

    // Clone the Arc<SshExecutor> out of the mutex before any async work.
    let executor = {
        let connection = state.active_connection.lock().await;
        match connection.as_ref() {
            Some(conn) => conn.executor.clone(),
            None => return Err("No active remote connection".to_string()),
        }
    };

    scan_with_executor(executor, plugin_ids.as_deref()).await
}

/// Frameworks the fleet view scores against.
/// ISO 27001 is deliberately omitted; add it here to include it.
pub(crate) const FLEET_FRAMEWORKS: [ComplianceFramework; 9] = [
    ComplianceFramework::CIS,
    ComplianceFramework::STIG,
    ComplianceFramework::NIST,
    ComplianceFramework::PCIDSS,
    ComplianceFramework::HIPAA,
    ComplianceFramework::GDPR,
    ComplianceFramework::SOC2,
    ComplianceFramework::NIST800171,
    ComplianceFramework::FedRAMP,
];

/// Builds the report generator used for fleet compliance scoring (all
/// `FLEET_FRAMEWORKS` in one pass) under one host's resolved profile and
/// identity. Built per host: profiles differ across a mixed fleet, so callers
/// fetch coverage once and clone it per host (cheap at fleet scale).
///
/// `exclusions` is this controller's `[compliance]` section: one file
/// describing a fleet. `ScopeExclusion` carries a `hosts` list precisely
/// because an exclusion is a claim about particular systems, so the set is
/// handed over whole and `host` decides which of its entries reach this
/// report. An untargeted declaration is a claim about the estate and applies
/// everywhere; a targeted one reaches only the hosts it names.
pub(crate) fn fleet_report_generator(
    profile: ComplianceProfile,
    inventory: hardener_types::PluginInventory,
    exclusions: ComplianceConfig,
    host: &RemoteHostProfile,
) -> ReportGenerator {
    let config = ReportConfig {
        scenario: Scenario::Custom(FLEET_FRAMEWORKS.to_vec()),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile,
    };
    ReportGenerator::new(config, inventory, exclusions).for_host(
        host.target(),
        host.hostname.clone(),
        host.name.clone(),
    )
}

/// Derives slim per-framework posture for one host's findings and the checks
/// its scan could not evaluate (which must not auto-pass). In-memory; no SSH.
pub(crate) fn posture_for_findings(
    generator: &ReportGenerator,
    results: &[ScanResult],
) -> Vec<FleetFrameworkPosture> {
    generator
        .generate(results, &[])
        .into_iter()
        .map(|r| FleetFrameworkPosture {
            framework: r.report_framework,
            // Built before `summary` is moved out, and from the same report, so
            // the rows and the counts describe one generation rather than two.
            controls: r.report_controls.iter().map(ControlOutcome::from).collect(),
            summary: r.report_summary,
        })
        .collect()
}

/// Parses and validates one ad-hoc `user@host[:port]` target. Rejects an empty
/// hostname, a leading `-` (which ssh would otherwise read as an option), and
/// stray punctuation (space/comma) via `RemoteHostProfile::is_valid_hostname` -
/// the same predicate the desktop client uses, so both guards stay mirrored.
pub(crate) fn adhoc_profile(target: &str) -> Result<RemoteHostProfile, String> {
    validate_ipc_string(target, "adhoc_target")?;
    let profile = RemoteHostProfile::from_target(target.trim(), 22, None, true);
    if !RemoteHostProfile::is_valid_hostname(&profile.hostname) {
        return Err(format!(
            "Invalid ad-hoc target '{target}': invalid hostname"
        ));
    }
    Ok(profile)
}

/// How long a remote connection may take to establish, for every host the
/// desktop reaches: one saved profile or eight fleet hosts at once.
pub(crate) const REMOTE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the core SSH config for one host profile. The single place the
/// desktop turns a profile into a connection, shared by `connect_remote` and
/// the fleet scan: `host_key_checking` decides `Strict` against `Accept`, and
/// no caller can drift on which way round that goes.
pub(crate) fn ssh_config_for(profile: &RemoteHostProfile) -> hardener_core::SshConfig {
    hardener_core::SshConfig {
        host: profile.hostname.clone(),
        port: profile.port,
        user: profile.user.clone(),
        identity_file: profile.key_file.clone(),
        known_hosts: if profile.host_key_checking {
            hardener_core::KnownHosts::Strict
        } else {
            hardener_core::KnownHosts::Accept
        },
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
    }
}

/// Resolves a fleet scan's targets into one profile per row, keyed the way the
/// rows are named: inventory hosts by their profile name, ad-hoc ones by the
/// full `user@host[:port]` string as typed, which is also the history key.
///
/// An inventory host keeps precedence over an ad-hoc target that happens to
/// spell its name, because the saved profile carries the real hostname, port,
/// user and key file that parsing a bare name cannot recover. An unparseable
/// ad-hoc target fails the whole scan rather than being dropped: a silently
/// skipped host reads as a host with nothing to report.
pub(crate) fn fleet_targets(
    hosts: Vec<RemoteHostProfile>,
    adhoc: &[String],
) -> Result<std::collections::HashMap<String, RemoteHostProfile>, String> {
    let mut profiles: std::collections::HashMap<String, RemoteHostProfile> =
        hosts.into_iter().map(|h| (h.name.clone(), h)).collect();
    for target in adhoc {
        let profile = adhoc_profile(target)?;
        profiles.entry(target.clone()).or_insert(profile);
    }
    Ok(profiles)
}

/// The rows a fleet scan produces: in order, and one per host rather than one
/// per mention of a host.
///
/// [`fleet_targets`] has already decided that an inventory host and an ad-hoc
/// target spelling its name are the same host, and
/// `fleet_targets_lets_an_inventory_host_win_a_name_collision` pins that
/// decision. The names reaching [`scan_fleet`] used to carry a different one:
/// the two lists were chained, so a host named in both appeared twice, was
/// connected to twice, scanned twice over two SSH sessions, counted twice in
/// the progress total, and rendered as two rows a reader had no way to tell
/// apart. `scan_fleet` builds one row per entry and calls that "the
/// one-row-per-host contract", which holds only when the entries are hosts.
///
/// Inventory names come first, so the spelling that survives is the one whose
/// profile `fleet_targets` kept, and the row is named the way its profile is
/// keyed.
///
/// **Two hosts are the same host by two different measures**, and matching the
/// strings is only the first. An operator who ticks `web-01` and then types
/// that host's endpoint has selected one machine twice under names sharing no
/// character, so the second measure is the canonical `target()` of the profile
/// each name resolves to. `resolve_hosts` in the CLI reached this first and
/// says at its own definition why the name cannot serve as the identity;
/// until 2026-08-28 the desktop asked only the string question, and the same
/// selection scanned as two rows here and applied as one outcome through
/// `run_fleet_apply`, which shells out to that code.
///
/// **Only ad-hoc targets are compared by endpoint**, which is `resolve_hosts`'
/// rule as well. Two inventory entries for one machine are two selections the
/// operator made deliberately and stay two rows; a run that writes refuses
/// them further down, in the CLI's `colliding_host_key`, because the harm
/// there is two checkpoints under one key rather than a duplicated row.
///
/// A name resolving to no profile keeps its row. It becomes a Failed row in
/// [`scan_fleet`] saying the profile was not found, and dropping it here would
/// turn a visible failure into a host that silently reports nothing.
pub(crate) fn fleet_row_names(
    host_names: Vec<String>,
    adhoc: Vec<String>,
    profiles: &std::collections::HashMap<String, RemoteHostProfile>,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut names: Vec<String> = Vec::with_capacity(host_names.len() + adhoc.len());
    for name in host_names {
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }

    let mut endpoints: std::collections::HashSet<String> = names
        .iter()
        .filter_map(|name| profiles.get(name))
        .map(|profile| profile.target())
        .collect();
    for target in adhoc {
        if !seen.insert(target.clone()) {
            continue;
        }
        let endpoint = profiles.get(&target).map(|profile| profile.target());
        if let Some(endpoint) = endpoint
            && !endpoints.insert(endpoint)
        {
            continue;
        }
        names.push(target);
    }
    names
}

/// Derives each scanned host's compliance posture from the findings already in
/// hand: in memory, with no second trip over SSH. A host that failed keeps an
/// empty posture, because a score derived from no findings is a claim about a
/// host nobody assessed rather than a clean bill of health.
///
/// Flattening goes through `flatten_scan_results`, the same path the local
/// compliance tab uses, and not a hand-written pass over `scan_results`. A
/// fleet scan does not always come back with every plugin: the caller may have
/// filtered to a subset with `plugin_ids`, and `scan_with_executor` skips one
/// whose registry lookup does not return it. Those plugins report nothing, and
/// nothing is exactly what a control needs to look clean, so every registered
/// plugin missing from a row contributes an unassessed entry and its controls
/// report ManualReview. Flattened by hand this said nothing, and a row scanned
/// with one plugin reported the same 38 passing CIS controls as a row scanned
/// with all eight.
///
/// **A plugin whose scan errored is not one of those cases**, though this said
/// it was until 2026-08-28. `scan_with_executor` records the failure through
/// `recorded_scan` and pushes it, so it is present with `scan_success` false,
/// and `scan_evidence::flatten` gives it a `ScanIncomplete` entry carrying its
/// error rather than the `NotCovered` it gives an absent one. The same wrong
/// sentence was corrected in the fleet test's doc on 2026-08-27 and left
/// standing here, which is what a second copy does.
///
/// `coverage` and `exclusions` are passed in rather than read here, so the
/// caller does the one disk read and this stays a pure function of its inputs.
/// Each host is scored under its own resolved `ComplianceProfile` and its own
/// identity: the identity decides which host-targeted exclusions apply, so a
/// row scored under the wrong one silently gains or loses its operator's
/// declarations. A row exists because `profiles` produced the profile it was
/// scanned with, so the lookup resolves; the fallback keeps the arm gated by
/// the display name rather than leaving it ungated.
pub(crate) fn attach_compliance(
    results: &mut [FleetHostScan],
    profiles: &std::collections::HashMap<String, RemoteHostProfile>,
    inventory: hardener_types::PluginInventory,
    exclusions: ComplianceConfig,
) {
    for host in results
        .iter_mut()
        .filter(|h| matches!(h.status, FleetHostStatus::Ok))
    {
        let identity = profiles
            .get(&host.host_name)
            .cloned()
            .unwrap_or_else(|| RemoteHostProfile::from_target(&host.host_name, 22, None, true));
        let generator = fleet_report_generator(
            host.profile,
            inventory.clone(),
            exclusions.clone(),
            &identity,
        );
        host.compliance = posture_for_findings(&generator, &host.scan_results);
    }
}

/// Scans several hosts concurrently and returns each host's severity posture:
/// saved inventory hosts by name plus ad-hoc `user@host[:port]` targets.
/// Read-only: opens a short-lived SSH connection per host, scans, and drops it.
/// Per-host failure is isolated: a failed host is a `Failed` row whilst the
/// others still complete.
#[tauri::command]
pub async fn run_fleet_scan(
    host_names: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugin_ids: Option<Vec<String>>,
    app: tauri::AppHandle,
) -> Result<Vec<FleetHostScan>, String> {
    if let Some(ref ids) = plugin_ids {
        validate_plugin_ids(ids)?;
    }
    for name in &host_names {
        validate_ipc_string(name, "host_name")?;
    }
    let adhoc = adhoc.unwrap_or_default();

    // One profile lookup, built once and shared, because the scan closure takes
    // ownership of what it captures and the compliance pass below needs the
    // same identities to resolve host-targeted exclusions.
    let config = load_hosts_config()?;
    let profiles = fleet_targets(config.hosts, &adhoc)?;

    let plugin_ids = std::sync::Arc::new(plugin_ids);
    let profiles = std::sync::Arc::new(profiles);
    let scan_profiles = profiles.clone();

    // Ad-hoc rows keep the full target string as their display name. A host
    // named in both lists gets one row, matching the single key `fleet_targets`
    // gave it, and so does one reached under an inventory name and its own
    // endpoint, which the profiles are needed to see.
    let all_names = fleet_row_names(host_names, adhoc, &profiles);

    // Best-effort live progress: a dead listener must never fail the scan.
    let on_progress = move |scan: &FleetHostScan, done: usize, total: usize| {
        use tauri::Emitter;
        let _ = app.emit(
            FLEET_PROGRESS_EVENT,
            FleetProgress {
                host: scan.host_name.clone(),
                done,
                total,
                failed: matches!(scan.status, FleetHostStatus::Failed(_)),
            },
        );
    };

    let mut results = scan_fleet(
        all_names,
        move |name| {
            let profile = scan_profiles.get(&name).cloned();
            let plugin_ids = plugin_ids.clone();
            async move {
                let profile =
                    profile.ok_or_else(|| format!("Host profile '{}' not found", name))?;

                let ssh_config = ssh_config_for(&profile);

                let executor = std::sync::Arc::new(
                    hardener_core::SshExecutor::connect(ssh_config)
                        .await
                        .map_err(safe_err)?,
                );

                let results = scan_with_executor(executor.clone(), plugin_ids.as_deref()).await?;
                // The connection is still open: resolve the host's own
                // compliance profile from its /etc/os-release while it is.
                Ok((detect_host_profile(executor.as_ref()).await, results))
            }
        },
        on_progress,
    )
    .await;

    attach_compliance(
        &mut results,
        &profiles,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );

    Ok(results)
}

// ---------------------------------------------------------------------------
// Scheduler configuration
// ---------------------------------------------------------------------------

/// Runs a fleet apply via the audited CLI. `execute = false` is a dry-run
/// (preview); `true` mutates. JSON is read regardless of exit code: tiered
/// exit codes carry per-host results.
#[tauri::command]
pub async fn run_fleet_apply(
    hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<ApplyOutcome>, String> {
    run_fleet_mutation("apply", hosts, adhoc.unwrap_or_default(), plugins, execute).await
}

/// Runs a fleet rollback via the audited CLI. `execute = false` previews.
#[tauri::command]
pub async fn run_fleet_rollback(
    hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<RollbackOutcome>, String> {
    run_fleet_mutation(
        "rollback",
        hosts,
        adhoc.unwrap_or_default(),
        plugins,
        execute,
    )
    .await
}

/// Spawns `hardener batch <verb>` and parses its outcome JSON. Shared by apply
/// and rollback. No pkexec: remote hosts authenticate over SSH via the saved
/// inventory profiles (or the ad-hoc targets) the CLI reads, so the local
/// `PrivilegedOpGuard` (which serialises local pkexec mutations) deliberately
/// does not apply here.
pub(crate) async fn run_fleet_mutation<T: serde::de::DeserializeOwned>(
    verb: &str,
    hosts: Vec<String>,
    adhoc: Vec<String>,
    plugins: Vec<String>,
    execute: bool,
) -> Result<Vec<T>, String> {
    if hosts.is_empty() && adhoc.is_empty() {
        return Err("No hosts selected".to_string());
    }
    for h in &hosts {
        validate_ipc_string(h, "host_name")?;
    }
    for t in &adhoc {
        adhoc_profile(t)?;
    }
    validate_plugin_ids(&plugins)?;
    let binary = get_hardener_binary_path()?;
    let args = build_batch_args(verb, &hosts, &adhoc, &plugins, execute);
    let output = Command::new(&binary)
        .args(&args)
        .output()
        .await
        .map_err(|e| safe_err(format!("Failed to run fleet {verb}: {e}")))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| safe_err(format!("Invalid UTF-8 in CLI output: {e}")))?;
    // Exit code is intentionally NOT checked: tiered codes accompany valid JSON.
    parse_outcomes(&stdout).map_err(|e| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        sanitise_error(&format!("{e}; stderr: {stderr}"))
    })
}

/// Builds the `hardener batch <verb> …` argument vector. `verb` is "apply" or
/// "rollback". Inventory hosts route to `--host`, ad-hoc targets to `--ssh`;
/// all are repeated flags (robust to commas in names). Empty `plugins` ⇒ no
/// `--plugin` (CLI default = all). `--format json` is always set; `--execute`
/// only when `execute`.
pub(crate) fn build_batch_args(
    verb: &str,
    hosts: &[String],
    adhoc: &[String],
    plugins: &[String],
    execute: bool,
) -> Vec<String> {
    let mut args = vec!["batch".to_string(), verb.to_string()];
    for h in hosts {
        args.push("--host".to_string());
        args.push(h.clone());
    }
    for t in adhoc {
        args.push("--ssh".to_string());
        args.push(t.clone());
    }
    for p in plugins {
        args.push("--plugin".to_string());
        args.push(p.clone());
    }
    if execute {
        args.push("--execute".to_string());
    }
    args.push("--format".to_string());
    args.push("json".to_string());
    args
}

/// Parses the JSON outcome array from CLI stdout.
///
/// Exit-code agnostic by design, which is why this is not `accept_json_output`:
/// `batch apply/rollback` exit non-zero on per-host failures yet still print the
/// array, so the array is the source of truth. That is the one difference, and
/// it is why the two cannot merge.
///
/// The leading-bytes skip is tolerance, not a step over anything `batch`
/// writes: it prints the rendered payload to stdout and every message it has to
/// stderr. The comment here used to name "leading info lines" as the reason,
/// which stopped being true when `output::info` moved to stderr. Left in place
/// rather than tightened because the fleet path cannot be exercised outside a
/// container, and a stricter parser is not worth an untested change to the one
/// verb that reaches every host at once.
pub(crate) fn parse_outcomes<T: serde::de::DeserializeOwned>(
    stdout: &str,
) -> Result<Vec<T>, String> {
    let start = stdout.find('[').ok_or("No JSON array in CLI output")?;
    serde_json::from_str(&stdout[start..]).map_err(|e| format!("Failed to parse CLI output: {e}"))
}
