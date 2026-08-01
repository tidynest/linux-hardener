//! Resolving configuration that a distribution layers across two directories.
//!
//! openSUSE (Leap 15.6+, Tumbleweed, MicroOS) ships vendor configuration under
//! `/usr/etc` and reserves `/etc` for administrator overrides. Fedora is moving
//! the same way. The override is whole-file, not per directive: the first file
//! found wins entirely, which was verified on a live container by writing a
//! one-directive `/etc/login.defs` and watching the directives it omitted fall
//! to shadow's unset sentinel rather than to the vendor's values.

use crate::executor::SystemExecutor;

/// Which directory supplied a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigLayer {
    /// `/etc`, the administrator's.
    Admin,
    /// `/usr/etc`, the distribution's.
    Vendor,
}

/// The outcome of reading a layered configuration file.
#[derive(Clone, Debug)]
pub enum LayeredRead {
    /// A file was read. `path` names which one, `layer` says whose it is.
    Found {
        path: String,
        layer: ConfigLayer,
        content: String,
    },
    /// Absence confirmed at both layers.
    Absent,
    /// A layer could not be read, or its existence could not be determined.
    Unreadable {
        path: String,
        reason: String,
        permission_denied: bool,
    },
}

/// The `/usr/etc` counterpart of an `/etc` path, when there is one.
///
/// A path naming the directory itself rather than a file below it has no
/// counterpart: `/usr/etc` exists as a directory on every host that layers at
/// all, so mapping `/etc/` to it would report a vendor file where there is only
/// a directory.
pub fn vendor_path_for(admin_path: &str) -> Option<String> {
    let rest = admin_path.strip_prefix("/etc/")?;
    (!rest.is_empty()).then(|| format!("/usr/etc/{rest}"))
}

/// Reads whichever file is actually in force for `admin_path`.
///
/// `/etc` is tried first and `/usr/etc` only on confirmed absence. Anything
/// else at the admin layer is `Unreadable`: an admin file that exists but
/// cannot be read is still the file the system obeys, so answering with the
/// vendor copy's contents would report a configuration that is not in force.
/// That is the false pass this module exists to remove, and it is the mistake a
/// plausible implementation makes.
pub async fn read_layered(executor: &dyn SystemExecutor, admin_path: &str) -> LayeredRead {
    match read_one(executor, admin_path).await {
        Layer::Content(content) => LayeredRead::Found {
            path: admin_path.to_string(),
            layer: ConfigLayer::Admin,
            content,
        },
        Layer::Unreadable {
            reason,
            permission_denied,
        } => LayeredRead::Unreadable {
            path: admin_path.to_string(),
            reason,
            permission_denied,
        },
        Layer::Absent => match vendor_path_for(admin_path) {
            None => LayeredRead::Absent,
            Some(vendor) => match read_one(executor, &vendor).await {
                Layer::Content(content) => LayeredRead::Found {
                    path: vendor,
                    layer: ConfigLayer::Vendor,
                    content,
                },
                Layer::Absent => LayeredRead::Absent,
                Layer::Unreadable {
                    reason,
                    permission_denied,
                } => LayeredRead::Unreadable {
                    path: vendor,
                    reason,
                    permission_denied,
                },
            },
        },
    }
}

/// One layer's outcome, before it is attributed to a layer.
enum Layer {
    Content(String),
    Absent,
    Unreadable {
        reason: String,
        permission_denied: bool,
    },
}

/// Reads one path, distinguishing confirmed absence from every other failure.
///
/// Mirrors the three-outcome contract documented on
/// [`SystemExecutor::file_metadata`]: an error means existence could not be
/// determined, and must never be treated as absence.
async fn read_one(executor: &dyn SystemExecutor, path: &str) -> Layer {
    let as_path = std::path::Path::new(path);
    match executor.read_file(as_path).await {
        Ok(content) => Layer::Content(content),
        Err(e) => match executor.path_exists(as_path).await {
            Ok(false) => Layer::Absent,
            _ => Layer::Unreadable {
                reason: e.to_string(),
                permission_denied: crate::error::is_permission_denied(&e),
            },
        },
    }
}

#[cfg(test)]
mod tests;
