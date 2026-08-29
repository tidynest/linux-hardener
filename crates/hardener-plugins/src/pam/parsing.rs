//! The pure parsing halves of the PAM plugin's stack and conffile readers.
//!
//! One module, `pub(crate)`, so the crate's fuzz-seam can re-export these to
//! the targets under `fuzz/`: everything here consumes bytes that arrive from
//! remote hosts over the SSH executor, which is input the operator does not
//! control, and each of these used to sit inline inside an async reader
//! where only a live host could reach it. The readers stay in `mod.rs` and
//! call in; the parsing answers, and the properties the fuzz targets assert,
//! live here.

use hardener_common::file_utils::{
    ConfigFormat, Duplicates, parse_config_value, set_config_directive,
};
use hardener_core::{Change, ChangeType};

/// Whether a stack file's content loads `module` on any live line.
///
/// A commented line loads nothing, however much of the module name it
/// carries: `mod tests` blocks and operator notes quote module names often.
pub fn stack_loads_module(content: &str, module: &str) -> bool {
    content
        .lines()
        .map(str::trim)
        .any(|line| !line.starts_with('#') && line.contains(module))
}

/// The `arg=value` set inline on `module`'s stack line, if this content holds
/// one: the first live line naming the module wins, and only a whole token
/// `arg=` prefix matches, so `even_deny_root` never matches `deny`.
pub fn inline_arg_in_content<'a>(content: &'a str, module: &str, arg: &str) -> Option<&'a str> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains(module) {
            continue;
        }
        if let Some(value) = line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(arg).and_then(|r| r.strip_prefix('=')))
        {
            return Some(value);
        }
    }
    None
}

/// State-aware exact-match apply for a config held in memory: mutates `content`
/// and records a real change when the file's current value differs from the
/// target, when the file defines the key more than once, or when the line
/// holding an already-correct value needs its separator repaired in place;
/// anything else records a Skipped no-op instead. The third case means the
/// count this produces is not always a count of hardening successes, since a
/// cosmetic repair reports the same as a load-bearing one. `format` is the
/// syntax the file accepts, which is the caller's to know: writing a
/// directive in a syntax its file does not parse leaves the insecure value in
/// force.
pub fn apply_exact_directive(
    content: &mut String,
    changed: &mut bool,
    changes: &mut Vec<Change>,
    name: &str,
    target: &str,
    format: ConfigFormat,
    file_label: &str,
) {
    let current = parse_config_value(content, name, ConfigFormat::Auto, true);
    let updated = set_config_directive(content, name, target, format, true, Duplicates::Remove);
    // A correct value alone is not enough to leave the file alone: these files
    // take one definition per key, and an earlier release appended a second
    // one in a syntax they do not parse. Skipping on the value would leave that
    // repair undone on every run, so the file never converges. With the value
    // already correct the writer can still rewrite a line where it stands,
    // repair the syntax of that line, or drop a duplicate, and only comparing
    // the lines themselves tells "nothing to do" apart from all three: a
    // repaired line leaves the count of lines exactly as it was, which is how a
    // file whose only definition is the appended one stayed broken and green.
    // Blank lines are excluded. The reason they had to be is gone: the writer
    // dropped the file's terminator, so a compliant file came back one byte
    // short, read as a change, and was rewritten on every run. The writer
    // terminates its output now and that hazard is closed. The filter stays
    // because the comparison it serves is about directive lines rather than
    // layout, and a run that only moved a blank line still has nothing to say.
    fn lines_with_text(text: &str) -> Vec<&str> {
        text.lines().filter(|l| !l.trim().is_empty()).collect()
    }
    if current.as_deref() == Some(target) && lines_with_text(&updated) == lines_with_text(content) {
        changes.push(Change {
            change_type: ChangeType::Skipped,
            change_description: format!("{} already set to {} in {}", name, target, file_label),
            change_success: true,
            change_error: None,
        });
        return;
    }

    *content = updated;
    *changed = true;
    changes.push(Change {
        change_type: ChangeType::ConfigFile,
        change_description: format!("Set {} = {} in {}", name, target, file_label),
        change_success: true,
        change_error: None,
    });
}
