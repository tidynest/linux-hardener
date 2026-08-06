//! Systemd unit file generation for scheduled scanning.
//!
//! Generates `.service` and `.timer` unit files for running
//! scheduled scans via systemd instead of the built-in daemon.

use std::path::{Path, PathBuf};

/// Unit file names.
const SERVICE_NAME: &str = "linux-hardener.service";
const TIMER_NAME: &str = "linux-hardener.timer";

/// Renders one path as a single `ExecStart` word.
///
/// `ExecStart` is not a shell line and it is not handed to the process as
/// written. systemd expands `%` specifiers over the whole value and then splits
/// it on whitespace, so a path was interpolated raw into a setting that reads
/// neither of those characters literally. Measured on a live unit: a config
/// path containing one space arrived as two arguments, which clap refuses with
/// `unrecognized subcommand`, and `%h` arrived as the home directory.
///
/// Quoting answers the split, `%%` answers the specifier, and the two C escapes
/// answer what quoting would otherwise swallow. Applied to the binary path as
/// well as the config path, because `--binary` takes an operator's path and
/// `current_exe()` can return one just as awkward.
fn exec_word(path: &Path) -> String {
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

/// Generates systemd unit files for scheduled scanning.
pub struct SystemdGenerator {
    /// Path to the hardener binary.
    binary_path: PathBuf,
    /// Path to the configuration file (optional).
    config_path: Option<PathBuf>,
    /// Systemd calendar expression for the timer.
    calendar: String,
    /// Description for the units.
    description: String,
    /// Whether generating for user-mode (`systemctl --user`).
    user_mode: bool,
}

impl SystemdGenerator {
    /// Generates a new generator with the given schedule.
    ///
    /// # Arguments
    /// * `binary_path` - Absolute path to the hardener binary
    /// * `calendar` - Systemd OnCalendar expression (e.g., "daily", "*-*-* 02:00:00")
    pub fn new(binary_path: PathBuf, calendar: impl Into<String>) -> Self {
        Self {
            binary_path,
            config_path: None,
            calendar: calendar.into(),
            description: "Linux Hardener scheduled security scan".to_string(),
            user_mode: false,
        }
    }

    /// Sets an optional configuration file path.
    pub fn with_config(mut self, config_path: PathBuf) -> Self {
        self.config_path = Some(config_path);
        self
    }

    /// Sets a custom description for the units.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Enables user-mode generation (omits privileged security directives).
    pub fn with_user_mode(mut self, user: bool) -> Self {
        self.user_mode = user;
        self
    }

    /// Generates the `.service` unit file content.
    pub fn generate_service(&self) -> String {
        let binary = exec_word(&self.binary_path);
        let exec_start = match &self.config_path {
            Some(cfg) => format!("{binary} --config {} daemon run-once", exec_word(cfg)),
            None => format!("{binary} daemon run-once"),
        };

        // User services cannot use privileged sandboxing directives
        let security = if self.user_mode {
            "NoNewPrivileges=true".to_string()
        } else {
            "# Security hardening\n\
             NoNewPrivileges=true\n\
             ProtectSystem=strict\n\
             ProtectHome=read-only\n\
             PrivateTemp=true\n\
             ReadWritePaths=/var/lib/linux-hardener"
                .to_string()
        };

        let wanted_by = if self.user_mode {
            "default.target"
        } else {
            "multi-user.target"
        };

        format!(
            "[Unit]\n\
             Description={description}\n\
             Documentation=https://github.com/tidynest/linux-hardener\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart={exec_start}\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             {security}\n\
             \n\
             [Install]\n\
             WantedBy={wanted_by}\n",
            description = self.description,
            exec_start = exec_start,
            security = security,
            wanted_by = wanted_by,
        )
    }

    /// Generates the `.timer` unit file content.
    pub fn generate_timer(&self) -> String {
        format!(
            r#"[Unit]
Description={description} (timer)
Documentation=https://github.com/tidynest/linux-hardener

[Timer]
OnCalendar={calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"#,
            description = self.description,
            calendar = self.calendar,
        )
    }
}

/// Converts a cron expression to systemd OnCalendar format.
///
/// Supports common patterns; complex expressions may need manual conversion.
/// Returns `None` if the expression cannot be converted.
///
/// # Examples
/// ```
/// use hardener_scheduler::systemd::cron_to_calendar;
///
/// assert_eq!(cron_to_calendar("0 2 * * *"), Some("*-*-* 02:00:00".to_string()));
/// ```
pub fn cron_to_calendar(cron: &str) -> Option<String> {
    let parts: Vec<&str> = cron.split_whitespace().collect();

    // Standard 5-field cron: minute hour day month weekday
    if parts.len() != 5 {
        return None;
    }

    let (minute, hour, day, month, weekday) = (parts[0], parts[1], parts[2], parts[3], parts[4]);

    // Handle special weekday values
    let weekday_prefix = match weekday {
        "*" => String::new(),
        "0" | "7" => "Sun ".to_string(),
        "1" => "Mon ".to_string(),
        "2" => "Tue ".to_string(),
        "3" => "Wed ".to_string(),
        "4" => "Thu ".to_string(),
        "5" => "Fri ".to_string(),
        "6" => "Sat ".to_string(),
        _ => return None, // Complex weekday patterns not supported
    };

    // Convert month field
    let month_part = match month {
        "*" => "*".to_string(),
        m => match m.parse::<u8>() {
            Ok(n) => format!("{n:02}"),
            _ => return None,
        },
    };

    // Convert day field
    let day_part = match day {
        "*" => "*".to_string(),
        d => match d.parse::<u8>() {
            Ok(n) => format!("{n:02}"),
            _ => return None,
        },
    };

    // Convert hour field
    let hour_part = match hour {
        "*" => "*".to_string(),
        h => match h.parse::<u8>() {
            Ok(n) => format!("{n:02}"),
            _ => return None,
        },
    };

    // Convert minute field
    let minute_part = match minute {
        "*" => "*".to_string(),
        m => match m.parse::<u8>() {
            Ok(n) => format!("{n:02}"),
            _ => return None,
        },
    };

    Some(format!(
        "{}*-{}-{} {}:{}:00",
        weekday_prefix, month_part, day_part, hour_part, minute_part
    ))
}

/// Returns the service unit filename.
pub fn service_name() -> &'static str {
    SERVICE_NAME
}

/// Returns the timer unit filename.
pub fn timer_name() -> &'static str {
    TIMER_NAME
}

#[cfg(test)]
mod tests;
