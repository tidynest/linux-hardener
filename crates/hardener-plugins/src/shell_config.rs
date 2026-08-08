//! Reading a shell-sourced configuration file, the format ufw's own init
//! scripts and defaults files use.

/// The last value `key` is assigned in a shell-sourced configuration file.
///
/// `/etc/default/ufw` and `/etc/ufw/ufw.conf` are both `.`-sourced by
/// `ufw-init-functions`, so the last assignment wins and a commented-out line
/// is not an assignment at all.
pub(crate) fn shell_value(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().trim_matches(['"', '\'']).to_string())
        })
        .next_back()
}

#[cfg(test)]
mod tests;
