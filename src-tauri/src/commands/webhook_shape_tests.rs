#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading.

//! What the desktop writes has to be what the scheduler reads.
//!
//! Both crates are dependencies of this one, and this is the only place the two
//! shapes of `[scheduler.notifications.webhooks]` meet. They had drifted apart
//! entirely: the desktop wrote a flat `url`/`format` pair, the scheduler expects
//! `endpoints`, nothing rejects an unknown key, and so a webhook configured in
//! the GUI saved successfully and reached the daemon as an empty list.

use super::*;

/// Parses a rendered section the way the scheduler itself does.
fn scheduler_section_of(rendered: &str) -> hardener_scheduler::SchedulerConfig {
    #[derive(serde::Deserialize)]
    struct ConfigFile {
        #[serde(default)]
        scheduler: hardener_scheduler::SchedulerConfig,
    }
    let parsed: ConfigFile = toml::from_str(rendered)
        .unwrap_or_else(|e| panic!("the desktop's own output must parse: {e}\n---\n{rendered}"));
    parsed.scheduler
}

/// A file carrying every `[scheduler]` key the desktop form does not model.
const FULL_SECTION: &str = "\
[scheduler]
enabled = false
schedule = \"0 0 5 * * *\"
plugins = []
min_severity = \"low\"

[scheduler.storage]
database_path = \"/srv/hardener/scheduler.db\"
retention_count = 400

[scheduler.notifications]
notify_min_severity = \"high\"
notify_mode = \"regression\"

[scheduler.notifications.email]
enabled = true
smtp_host = \"smtp.example.invalid\"
smtp_port = 465
smtp_username = \"hardener\"
recipients = [\"ops@example.invalid\"]
from_address = \"scanner@example.invalid\"
";

/// Every key the form does not model survives a save.
///
/// The save rewrote the whole `[scheduler]` section from a UI type that models
/// a subset, so `smtp_host` became an empty string and `EmailNotifier::new`
/// then returned `None` while the channel still read as enabled.
/// `[scheduler.storage]` and `notify_mode` went the same way, and the form has
/// no field for any of them.
#[test]
fn a_save_keeps_the_keys_the_form_does_not_model() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/hook", "slack"),
        FULL_SECTION,
    )
    .expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    assert_eq!(
        scheduler.notifications.email.smtp_host, "smtp.example.invalid",
        "the SMTP host must survive: {rendered}"
    );
    assert_eq!(scheduler.notifications.email.smtp_port, 465);
    assert_eq!(
        scheduler.storage.database_path,
        std::path::PathBuf::from("/srv/hardener/scheduler.db"),
        "the storage path must survive: {rendered}"
    );
    assert_eq!(
        scheduler.notifications.notify_mode,
        hardener_scheduler::config::NotifyMode::Regression
    );
}

/// The form still owns what it does model.
///
/// The control on the test above: preserving unknown keys must not turn into
/// preserving everything, or the page would stop saving at all.
#[test]
fn a_save_still_overwrites_what_the_form_owns() {
    // Values that are neither the file's nor `SchedulerConfig::default()`'s.
    // The obvious fixture, the form's usual `0 0 2 * * *` and `medium`, is
    // exactly what the defaults are, so asserting it would hold just as well
    // for a merge that dropped both keys entirely. That vacuity was removed
    // from `a_webhook_with_no_url_writes_no_endpoint` one commit earlier and
    // walked straight back in here.
    let mut form = ui_config_with_webhook("https://example.invalid/hook", "slack");
    form.schedule = "0 30 4 * * *".to_string();
    form.min_severity = "critical".to_string();

    let rendered = render_scheduler_section(&form, FULL_SECTION).expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    // The fixture file says false / "0 0 5 * * *" / "low"; the form disagrees
    // with each, and so do the defaults.
    assert!(scheduler.enabled, "the form's enable flag wins: {rendered}");
    assert_eq!(scheduler.schedule, "0 30 4 * * *");
    assert_eq!(scheduler.min_severity, "critical");
    assert_eq!(
        scheduler.notifications.webhooks.endpoints[0].url,
        "https://example.invalid/hook"
    );
}

/// Clearing the URL in the form removes the endpoint from the file.
///
/// The other half of ownership: a merge that only ever adds would make the
/// webhook impossible to delete from the desktop that created it.
#[test]
fn clearing_the_url_removes_an_endpoint_the_file_already_had() {
    let with_endpoint = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/hook", "slack"),
        FULL_SECTION,
    )
    .expect("the section renders");
    assert_eq!(
        scheduler_section_of(&with_endpoint)
            .notifications
            .webhooks
            .endpoints
            .len(),
        1,
        "precondition: the file now has an endpoint"
    );

    let cleared = render_scheduler_section(&ui_config_with_webhook("", "slack"), &with_endpoint)
        .expect("the section renders");
    let scheduler = scheduler_section_of(&cleared);
    assert!(
        scheduler.notifications.webhooks.endpoints.is_empty(),
        "clearing the URL must remove the endpoint: {cleared}"
    );
    // The control: clearing the webhook did not also wipe the unmodelled keys.
    assert_eq!(
        scheduler.notifications.email.smtp_host,
        "smtp.example.invalid"
    );
}

/// A webhook deleted in the GUI stays deleted.
///
/// The merge keeps what the form does not emit, and `WebhookWire` deliberately
/// never writes the legacy flat `url`/`format` pair. Those two effects combined
/// meant the dead keys now survived every save, and the read path prefers them
/// whenever the endpoint list is empty: clearing the URL wrote `endpoints = []`,
/// the next load showed the old URL again as though nothing had happened, and
/// the save after that promoted it back to a live endpoint. The daemon then
/// posts scan findings to the endpoint the operator deleted.
#[test]
fn a_webhook_deleted_in_the_form_does_not_come_back_from_the_legacy_keys() {
    let legacy = "\
[scheduler]
enabled = true

[scheduler.notifications.webhooks]
enabled = true
url = \"https://old.invalid/hook\"
format = \"slack\"
";

    let cleared = render_scheduler_section(&ui_config_with_webhook("", "slack"), legacy)
        .expect("the section renders");

    assert!(
        !cleared.contains("old.invalid"),
        "the deleted URL must not survive anywhere in the file: {cleared}"
    );
    // Read it back the way the desktop does: the form must come up empty.
    #[derive(serde::Deserialize)]
    struct Wrapper {
        scheduler: hardener_types::scheduler::SchedulerUiConfig,
    }
    let reloaded: Wrapper = toml::from_str(&cleared).expect("the desktop re-reads its own output");
    assert!(
        reloaded.scheduler.notifications.webhooks.url.is_empty(),
        "the form must not show a URL that was deleted: {cleared}"
    );
}

fn ui_config_with_webhook(url: &str, format: &str) -> hardener_types::scheduler::SchedulerUiConfig {
    let mut config = hardener_types::scheduler::SchedulerUiConfig {
        enabled: true,
        schedule: "0 0 2 * * *".to_string(),
        min_severity: "medium".to_string(),
        ..Default::default()
    };
    config.notifications.webhooks.enabled = true;
    config.notifications.webhooks.url = url.to_string();
    config.notifications.webhooks.format = format.to_string();
    config
}

#[test]
fn a_webhook_saved_in_the_desktop_reaches_the_scheduler() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/hook", "slack"),
        "",
    )
    .expect("the section renders");

    let scheduler = scheduler_section_of(&rendered);
    let endpoints = &scheduler.notifications.webhooks.endpoints;

    assert_eq!(
        endpoints.len(),
        1,
        "the saved webhook must arrive as one endpoint: {rendered}"
    );
    assert_eq!(
        endpoints[0].url, "https://example.invalid/hook",
        "the URL must survive the round trip: {rendered}"
    );
}

#[test]
fn the_saved_format_is_the_one_the_operator_chose() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/h", "discord"),
        "",
    )
    .expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    assert_eq!(
        scheduler.notifications.webhooks.endpoints[0].format,
        hardener_scheduler::config::WebhookFormat::Discord
    );
    // The control against a renderer that hardcodes one format and would pass
    // the assertion above for any input.
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/h", "slack"),
        "",
    )
    .expect("the section renders");
    assert_eq!(
        scheduler_section_of(&rendered)
            .notifications
            .webhooks
            .endpoints[0]
            .format,
        hardener_scheduler::config::WebhookFormat::Slack
    );
}

/// A form that never chose a format must not write a file the daemon refuses.
///
/// `WebhookUiConfig::default()` leaves `format` empty and the scheduler page
/// sets the form straight from it, so a fresh form saved unchanged carries an
/// empty format through. Written flat it was inert; written inside an endpoint
/// `""` is not one of the enum's variants and the file stops parsing. The panic
/// in `scheduler_section_of` is what catches that here.
#[test]
fn an_unchosen_format_still_produces_a_file_the_daemon_can_read() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/hook", ""),
        "",
    )
    .expect("the section renders");

    let scheduler = scheduler_section_of(&rendered);
    assert_eq!(
        scheduler.notifications.webhooks.endpoints[0].format,
        hardener_scheduler::config::WebhookFormat::Generic
    );
    assert!(
        scheduler.notifications.webhooks.enabled,
        "the enable flag is unaffected by the format fallback"
    );
}

/// An array of tables must come out as a usable header.
///
/// The header was previously rewritten textually after serialisation, and an
/// array of tables opens with two brackets, so replacing only the first
/// produced `[scheduler.[notifications.webhooks.endpoints]]` and left the file
/// unparseable. The serialiser now names the tables itself, which is why this
/// asserts on the rendered text rather than on a string helper.
#[test]
fn an_array_of_tables_header_is_rendered_whole() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/h", "slack"),
        "",
    )
    .expect("the section renders");

    assert!(
        rendered.contains("[[scheduler.notifications.webhooks.endpoints]]"),
        "the endpoint list needs a usable array-of-tables header: {rendered}"
    );
    // The control: a plain sub-table is nested under the same prefix, so the
    // assertion above is not satisfied by some unrelated stray bracket.
    assert!(
        rendered.contains("[scheduler.notifications.email]"),
        "a plain sub-table is nested too: {rendered}"
    );
}

/// The endpoint carries the name both the CHANGELOG and the reference promise.
///
/// Nothing asserted it, so mutating the constant to an empty string left every
/// test in the workspace green while the daemon's log lines lost the only thing
/// identifying where the endpoint came from.
#[test]
fn the_endpoint_is_named_for_the_desktop_that_wrote_it() {
    let rendered = render_scheduler_section(
        &ui_config_with_webhook("https://example.invalid/h", "slack"),
        "",
    )
    .expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    assert_eq!(
        scheduler.notifications.webhooks.endpoints[0].name,
        "desktop"
    );
    // The control: the name is not simply whatever the URL was.
    assert_ne!(
        scheduler.notifications.webhooks.endpoints[0].name,
        scheduler.notifications.webhooks.endpoints[0].url
    );
}

#[test]
fn a_webhook_with_no_url_writes_no_endpoint() {
    let rendered = render_scheduler_section(&ui_config_with_webhook("", "slack"), "")
        .expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    assert!(
        scheduler.notifications.webhooks.endpoints.is_empty(),
        "an endpoint with no URL is not a webhook: {rendered}"
    );
    // The control that the section was rendered at all rather than coming back
    // empty, which would satisfy the assertion above for the wrong reason.
    // `enabled` and not `schedule`: `SchedulerConfig` defaults its schedule to
    // the same `0 0 2 * * *` this fixture sets, so asserting that passed for an
    // empty render too and the control proved nothing. `enabled` is the one
    // fixture value that differs from the default.
    assert!(
        scheduler.enabled,
        "the section must have been rendered, not defaulted: {rendered}"
    );
}
