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
    let rendered = render_scheduler_section(&ui_config_with_webhook(
        "https://example.invalid/hook",
        "slack",
    ))
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
    let rendered = render_scheduler_section(&ui_config_with_webhook(
        "https://example.invalid/h",
        "discord",
    ))
    .expect("the section renders");
    let scheduler = scheduler_section_of(&rendered);

    assert_eq!(
        scheduler.notifications.webhooks.endpoints[0].format,
        hardener_scheduler::config::WebhookFormat::Discord
    );
    // The control against a renderer that hardcodes one format and would pass
    // the assertion above for any input.
    let rendered = render_scheduler_section(&ui_config_with_webhook(
        "https://example.invalid/h",
        "slack",
    ))
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
    let rendered =
        render_scheduler_section(&ui_config_with_webhook("https://example.invalid/hook", ""))
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

/// An array of tables opens with two brackets.
///
/// The header rewriter replaced only the first, producing
/// `[scheduler.[notifications.webhooks.endpoints]]`, which is not a header and
/// leaves the file unparseable. Nothing met it while the desktop rendered no
/// list at all.
#[test]
fn an_array_of_tables_header_is_moved_whole() {
    assert_eq!(
        prefix_table_header("[[notifications.webhooks.endpoints]]"),
        "[[scheduler.notifications.webhooks.endpoints]]"
    );
    // The control: a plain table header still moves, and a line that is not a
    // header at all is returned untouched.
    assert_eq!(
        prefix_table_header("[notifications.email]"),
        "[scheduler.notifications.email]"
    );
    assert_eq!(
        prefix_table_header("  smtp_port = 587"),
        "  smtp_port = 587",
        "a line that is not a header keeps even its leading whitespace"
    );
}

/// The endpoint carries the name both the CHANGELOG and the reference promise.
///
/// Nothing asserted it, so mutating the constant to an empty string left every
/// test in the workspace green while the daemon's log lines lost the only thing
/// identifying where the endpoint came from.
#[test]
fn the_endpoint_is_named_for_the_desktop_that_wrote_it() {
    let rendered = render_scheduler_section(&ui_config_with_webhook(
        "https://example.invalid/h",
        "slack",
    ))
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
    let rendered = render_scheduler_section(&ui_config_with_webhook("", "slack"))
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
