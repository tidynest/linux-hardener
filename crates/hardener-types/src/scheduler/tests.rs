#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`scheduler`](super).
//!
//! Split out of `scheduler.rs`. This file sits in the `scheduler/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves and private items stay reachable.

use super::*;

/// The desktop's single webhook has to land in the list the scheduler reads.
///
/// `WebhookUiConfig` used to serialise its own flat shape, so the desktop wrote
/// `url` and `format` into a table whose backend struct has neither field and
/// expects `endpoints`. Nothing rejected the unknown keys, so the save
/// succeeded, the endpoint list stayed empty, and no notification was ever
/// dispatched.
#[test]
fn a_webhook_is_written_as_the_endpoint_list_the_scheduler_reads() {
    let config = WebhookUiConfig {
        enabled: true,
        url: "https://example.invalid/hook".to_string(),
        format: "slack".to_string(),
    };

    let rendered = toml::to_string(&config).expect("the webhook config serialises");

    assert!(
        rendered.contains("[[endpoints]]"),
        "the endpoint must be a list entry: {rendered}"
    );
    assert!(
        rendered.contains("url = \"https://example.invalid/hook\""),
        "the URL must survive: {rendered}"
    );
    // The control against writing the list *and* keeping the flat pair, which
    // would satisfy both assertions above while leaving the old dead keys in
    // the file for the next reader to be confused by. Judged on the text
    // *before* the list, since the endpoint has a `url` line of its own and a
    // whole-string search would match that instead.
    let above_the_list = rendered
        .split("[[endpoints]]")
        .next()
        .expect("split always yields a first part");
    assert!(
        !above_the_list.contains("url ="),
        "the flat url key must not be written beside the list: {rendered}"
    );
}

#[test]
fn a_webhook_reads_back_from_the_endpoint_list() {
    let on_disk = "\
enabled = true

[[endpoints]]
name = \"desktop\"
url = \"https://example.invalid/hook\"
format = \"discord\"
";

    let config: WebhookUiConfig = toml::from_str(on_disk).expect("the endpoint list parses");
    assert_eq!(config.url, "https://example.invalid/hook");
    assert_eq!(config.format, "discord");
    // The control: a shape carrying no endpoint at all must come back empty
    // rather than inventing one, or the form would show a URL nobody set.
    let empty: WebhookUiConfig = toml::from_str("enabled = false").expect("an empty table parses");
    assert!(empty.url.is_empty());
}

/// A config the shipped desktop already wrote still populates the form.
///
/// The flat pair is what every existing installation has on disk. Dropping it
/// on read would show the operator an empty URL field and quietly discard their
/// setting the moment they pressed Save.
#[test]
fn the_flat_shape_the_desktop_used_to_write_is_still_read() {
    let legacy = "\
enabled = true
url = \"https://example.invalid/legacy\"
format = \"slack\"
";

    let config: WebhookUiConfig = toml::from_str(legacy).expect("the legacy shape parses");
    assert!(config.enabled);
    assert_eq!(config.url, "https://example.invalid/legacy");
    assert_eq!(config.format, "slack");
}

/// When a file carries both shapes, the list wins.
///
/// Neither read test above presents both at once, so the precedence the
/// conversion documents was unasserted: inverting it left both of them green.
/// The list is the right winner because it is the only half the daemon reads,
/// so it is the one describing what the host is actually doing.
#[test]
fn the_endpoint_list_wins_over_the_flat_pair() {
    let both = "\
enabled = true
url = \"https://example.invalid/flat\"
format = \"slack\"

[[endpoints]]
name = \"desktop\"
url = \"https://example.invalid/list\"
format = \"discord\"
";

    let config: WebhookUiConfig = toml::from_str(both).expect("a file with both shapes parses");
    assert_eq!(config.url, "https://example.invalid/list");
    assert_eq!(config.format, "discord");
}

/// An unset format must not become a config file the daemon cannot parse.
///
/// `WebhookUiConfig::default()` leaves `format` empty and the scheduler page
/// sets the form straight from it with no fallback, so a fresh form saved
/// unchanged carries an empty format through. As a flat key that was inert, the
/// backend never read it; inside an endpoint `""` is not one of the enum's
/// three variants and the whole file stops parsing. The guard is what makes the
/// endpoint list safe, not a repair of something that had been biting.
#[test]
fn an_unset_format_is_written_as_the_default_the_backend_knows() {
    let config = WebhookUiConfig {
        enabled: true,
        url: "https://example.invalid/hook".to_string(),
        format: String::new(),
    };

    let rendered = toml::to_string(&config).expect("the webhook config serialises");
    assert!(
        rendered.contains("format = \"generic\""),
        "an empty format becomes the documented default: {rendered}"
    );
    // The control: a format that was set is not overwritten by the fallback.
    let named = WebhookUiConfig {
        format: "discord".to_string(),
        ..config
    };
    let rendered = toml::to_string(&named).expect("the webhook config serialises");
    assert!(
        rendered.contains("format = \"discord\""),
        "a chosen format survives: {rendered}"
    );
}

/// A webhook with no URL writes no endpoint.
///
/// An endpoint carrying an empty URL is not a webhook, and the dispatcher would
/// try to post to it. `enabled` still round-trips on its own.
#[test]
fn no_url_means_no_endpoint() {
    let config = WebhookUiConfig {
        enabled: true,
        url: String::new(),
        format: "slack".to_string(),
    };

    let rendered = toml::to_string(&config).expect("the webhook config serialises");
    assert!(
        !rendered.contains("[[endpoints]]"),
        "an endpoint with no URL is not written: {rendered}"
    );
    assert!(
        rendered.contains("enabled = true"),
        "the enable flag still round-trips: {rendered}"
    );
}
