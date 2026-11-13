//! Resolving `Include` directives in sshd_config.
//!
//! sshd uses the first value it obtains for a keyword, and distributions ship
//! an `sshd_config` whose second line is
//! `Include /etc/ssh/sshd_config.d/*.conf`. Everything this tool writes lands
//! below that line, so a drop-in setting the same keyword always wins. Reading
//! only the main file therefore reports the value this tool wrote while sshd
//! enforces the drop-in's: a false pass, and `sshd -t` does not object to it.
//!
//! This module reconstructs the order sshd reads in, so a caller can ask what
//! the daemon will actually use and which file supplies it.
//!
//! One boundary is deliberately not modelled: an `Include` that sits *inside* a
//! `Match` block is conditional, and the files it names are treated here as
//! global. Every shipped layout puts the Include at the top of the file, above
//! any `Match`, so this does not arise in practice; a configuration that does
//! it would need checking by hand with `sshd -T`.

use hardener_common::error::{HardeningError, Result};
use hardener_common::file_utils::{global_scope, split_directive};
use hardener_core::context::Context;
use std::path::{Path, PathBuf};

/// sshd stops following nested includes at this depth. The real limit is 16;
/// anything approaching it is a loop rather than a configuration.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Relative include paths are resolved against this directory, per
/// sshd_config(5): "Files without absolute paths are assumed to be in
/// /etc/ssh".
const SSH_CONFIG_DIR: &str = "/etc/ssh";

/// The names sshd accepts for one option, the current name first.
///
/// `servconf.c` maps every name in a group to the same option, and sshd keeps
/// the first value it reads under any of them. Rocky 10 ships only
/// `ChallengeResponseAuthentication no`, so a lookup by the current name reads
/// that host as unset, and one lookup per name cannot order two hits inside
/// one file. Measured with `sshd -G` on OpenSSH 10.6p1, 2026-11-10: All three
/// names set `kbdinteractiveauthentication`, and the earlier line wins
/// whichever name it uses.
const KEYWORD_SPELLINGS: &[&[&str]] = &[&[
    "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication",
    "SkeyAuthentication",
]];

/// Every name sshd reads `keyword` under: Its group in
/// [`KEYWORD_SPELLINGS`], or the keyword alone where it has no other name.
fn spellings<'a>(keyword: &'a &'a str) -> &'a [&'a str] {
    KEYWORD_SPELLINGS
        .iter()
        .copied()
        .find(|group| group.iter().any(|name| name.eq_ignore_ascii_case(keyword)))
        .unwrap_or(std::slice::from_ref(keyword))
}

/// Where one directive's effective value comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveValue {
    /// The value sshd will use.
    pub value: String,
    /// The file supplying it.
    pub source: String,
    /// The keyword as that file spells it, which is not always the name the
    /// caller asked for: See [`KEYWORD_SPELLINGS`]. A caller editing the line
    /// in place has to address it by this name, because a second line under
    /// the current name would sit below it and lose.
    pub keyword: String,
}

/// sshd_config as sshd processes it: the main file with each `Include`
/// replaced, in place, by the files it names.
pub struct ResolvedConfig {
    /// `(path, content)` in sshd's processing order. The main file
    /// contributes several entries once it is split at its Include lines.
    segments: Vec<(String, String)>,
}

impl ResolvedConfig {
    /// The effective global value for a directive, and the file it comes from.
    ///
    /// Only the global scope of each segment is consulted: a value inside a
    /// `Match` block applies to particular connections, not to the host.
    pub fn effective(&self, directive_name: &str) -> Option<EffectiveValue> {
        self.first_value(directive_name, |_| true)
    }

    /// The effective global value a directive would have if one file were not
    /// there.
    ///
    /// Apply needs this to decide where a directive belongs. Once this tool has
    /// written its own fragment, that fragment supplies the value, so asking
    /// only "does anything other than us win" answers "no" on a host where a
    /// vendor fragment is still waiting underneath it. The question that
    /// decides whether the main file is a usable target is what would win
    /// without the fragment, which is this.
    pub fn effective_without(
        &self,
        directive_name: &str,
        ignored_path: &str,
    ) -> Option<EffectiveValue> {
        self.first_value(directive_name, |path| path != ignored_path)
    }

    /// Every argument of the directive's effective global line, for a keyword
    /// whose value is a list.
    ///
    /// [`Self::effective`] keeps the first argument, which is the whole value
    /// of a switch or a number and only the first of the lists in
    /// `AuthenticationMethods publickey,password publickey,keyboard-interactive`.
    /// sshd lets an argument be quoted and lets a comment end the line, so
    /// the quotes are dropped and the arguments stop at a `#`.
    pub fn effective_arguments(&self, directive_name: &str) -> Option<Vec<&str>> {
        self.first_line(directive_name, |_| true)
            .map(|(_, _, arguments)| {
                arguments
                    .split_whitespace()
                    .take_while(|argument| !argument.starts_with('#'))
                    .map(|argument| argument.trim_matches('"'))
                    .collect()
            })
    }

    /// The first segment satisfying `considered` that supplies the directive.
    fn first_value(
        &self,
        directive_name: &str,
        considered: impl Fn(&str) -> bool,
    ) -> Option<EffectiveValue> {
        self.first_line(directive_name, considered)
            .and_then(|(source, keyword, arguments)| {
                arguments
                    .split_whitespace()
                    .next()
                    .map(|value| EffectiveValue {
                        value: value.to_string(),
                        source: source.to_string(),
                        keyword: keyword.to_string(),
                    })
            })
    }

    /// The first global line, in sshd's reading order, that sets the directive
    /// under any name sshd accepts for it: The file, the keyword as written
    /// and the text after it.
    ///
    /// A commented line needs no skip of its own. Its key begins with `#`, so
    /// it equals no keyword.
    fn first_line(
        &self,
        directive_name: &str,
        considered: impl Fn(&str) -> bool,
    ) -> Option<(&str, &str, &str)> {
        let names = spellings(&directive_name);
        self.segments
            .iter()
            .filter(|(path, _)| considered(path))
            .find_map(|(path, content)| {
                global_scope(content).lines().find_map(|line| {
                    let (keyword, arguments) = split_directive(line.trim());
                    (!arguments.is_empty()
                        && names.iter().any(|name| name.eq_ignore_ascii_case(keyword)))
                    .then_some((path.as_str(), keyword, arguments))
                })
            })
    }

    /// Fuzz-only construction from raw segments, so the resolution order can
    /// be held to first-wins without an executor: the targets under `fuzz/`
    /// build configurations directly and ask `effective` what sshd would
    /// read.
    #[cfg(fuzzing)]
    pub fn from_segments(segments: Vec<(String, String)>) -> Self {
        Self { segments }
    }
}

/// The `Include` patterns on a line, or `None` when it is not a live
/// `Include`.
///
/// A commented line includes nothing. Multiple pathnames on one line are
/// permitted and are processed left to right.
pub fn include_patterns(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let keyword = parts.next()?;
    if !keyword.eq_ignore_ascii_case("Include") {
        return None;
    }
    let patterns: Vec<String> = parts.map(str::to_string).collect();
    (!patterns.is_empty()).then_some(patterns)
}

/// Whether a filename matches a glob(7) pattern containing `*` and `?`.
///
/// Backtracking matcher rather than a dependency: sshd's own patterns are
/// simple, and a partial implementation that silently mismatched would
/// reintroduce the very false pass this module exists to remove. Character
/// classes are deliberately unsupported and are reported by
/// [`pattern_is_supported`] instead of being guessed at.
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), name.chars().collect());
    let (mut p, mut n) = (0usize, 0usize);
    // Position to resume from when a `*` needs to consume one more character.
    let (mut star, mut resume) = (None, 0usize);

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = n;
            p += 1;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            resume += 1;
            n = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Whether this module can expand a pattern faithfully.
///
/// A glob(7) character class would need real parsing, and treating an
/// unexpandable pattern as "matches nothing" would hide exactly the drop-in
/// the caller is asking about, so such a pattern is refused instead.
pub fn pattern_is_supported(pattern: &str) -> bool {
    !pattern.contains('[') && !pattern.contains(']')
}

/// Whether a relative include can be resolved for the file containing it.
///
/// sshd_config(5) resolves relative includes against sshd's compiled
/// sysconfdir. That is `/etc/ssh` where the including file is the
/// administrator's, and something this tool cannot read out of the binary
/// where the file came from the vendor layer under `/usr/etc`. Every shipped
/// layout uses absolute includes, so refusing costs nothing, whereas guessing
/// would silently mis-locate a fragment, which is the false pass this module
/// exists to prevent.
fn relative_base(including_path: &str) -> Option<&'static str> {
    including_path
        .starts_with("/etc/")
        .then_some(SSH_CONFIG_DIR)
}

/// Absolute form of an include pattern, per sshd_config(5).
///
/// `None` where the pattern is relative and its base cannot be determined.
pub fn absolute_pattern(pattern: &str, including_path: &str) -> Option<PathBuf> {
    let path = Path::new(pattern);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    relative_base(including_path).map(|base| Path::new(base).join(path))
}

/// The files a pattern names, in the lexical order sshd processes them.
///
/// A pattern that names a single existing file needs no directory listing. A
/// pattern whose directory cannot be listed is an error rather than an empty
/// result: "no drop-ins" and "could not look" must not be the same answer.
async fn expand_pattern(
    ctx: &Context,
    pattern: &str,
    including_path: &str,
) -> Result<Vec<PathBuf>> {
    if !pattern_is_supported(pattern) {
        return Err(HardeningError::Plugin(format!(
            "Include pattern {pattern} uses a character class, which this tool cannot expand; \
             check it by hand with `sshd -T`"
        )));
    }

    let Some(absolute) = absolute_pattern(pattern, including_path) else {
        return Err(HardeningError::Plugin(format!(
            "The relative Include pattern {pattern} in {including_path} resolves against sshd's \
             compiled sysconfdir, which this tool cannot read for a file outside /etc; \
             check it by hand with `sshd -T`"
        )));
    };
    let has_wildcard = pattern.contains('*') || pattern.contains('?');
    if !has_wildcard {
        // A literal include of a file that does not exist is not an error to
        // sshd, so it is not one here either.
        return match ctx.executor().path_exists(&absolute).await {
            Ok(true) => Ok(vec![absolute]),
            Ok(false) => Ok(Vec::new()),
            Err(e) => Err(HardeningError::Plugin(format!(
                "Cannot determine whether the included file {} exists: {e}",
                absolute.display()
            ))),
        };
    }

    let (directory, file_pattern) = match (absolute.parent(), absolute.file_name()) {
        (Some(directory), Some(name)) => {
            (directory.to_path_buf(), name.to_string_lossy().to_string())
        }
        _ => {
            return Err(HardeningError::Plugin(format!(
                "Include pattern {pattern} has no directory to search"
            )));
        }
    };

    let entries = ctx.executor().read_dir(&directory).await.map_err(|e| {
        HardeningError::Plugin(format!(
            "Cannot list {} to expand the Include pattern {pattern}: {e}",
            directory.display()
        ))
    })?;

    let mut matched: Vec<PathBuf> = entries
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .is_some_and(|name| glob_matches(&file_pattern, &name.to_string_lossy()))
        })
        .collect();
    // glob(7) expansion is processed in lexical order.
    matched.sort();
    Ok(matched)
}

/// Reads sshd_config and every file it includes, in sshd's processing order.
///
/// Fails rather than returning a partial view: a caller uses this to decide
/// whether a host is compliant, and a silently incomplete answer is the defect
/// this replaces.
pub(super) async fn resolve(
    ctx: &Context,
    main_path: &str,
    main_content: &str,
) -> Result<ResolvedConfig> {
    let mut segments = Vec::new();
    expand_into(
        ctx,
        main_path,
        main_content,
        &mut segments,
        MAX_INCLUDE_DEPTH,
    )
    .await?;
    Ok(ResolvedConfig { segments })
}

/// Appends this file and, in place, everything it includes.
///
/// Boxed because the recursion is through an async fn.
fn expand_into<'a>(
    ctx: &'a Context,
    path: &'a str,
    content: &'a str,
    segments: &'a mut Vec<(String, String)>,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if depth == 0 {
            return Err(HardeningError::Plugin(format!(
                "Include nesting exceeded {MAX_INCLUDE_DEPTH} levels at {path}; \
                 this is a loop rather than a configuration"
            )));
        }

        // An Include takes effect where it sits, not before the file and not
        // after it. The shipped layout puts it on line 2, above every
        // directive this tool writes, so a model that placed the whole file
        // ahead of its includes would still read the main file's value first
        // and report exactly the compliance sshd does not have. The file is
        // therefore split at each Include: the lines above it, then the files
        // it names, then the lines below.
        let mut pending = String::new();
        let flush = |pending: &mut String, segments: &mut Vec<(String, String)>| {
            if !pending.is_empty() {
                segments.push((path.to_string(), std::mem::take(pending)));
            }
        };

        for line in content.lines() {
            let Some(patterns) = include_patterns(line) else {
                pending.push_str(line);
                pending.push('\n');
                continue;
            };
            flush(&mut pending, segments);
            for pattern in patterns {
                for included in expand_pattern(ctx, &pattern, path).await? {
                    let included_path = included.display().to_string();
                    let included_content =
                        ctx.executor().read_file(&included).await.map_err(|e| {
                            HardeningError::Plugin(format!(
                                "Cannot read the included file {included_path}: {e}"
                            ))
                        })?;
                    expand_into(ctx, &included_path, &included_content, segments, depth - 1)
                        .await?;
                }
            }
        }
        flush(&mut pending, segments);
        Ok(())
    })
}

#[cfg(test)]
mod tests;
