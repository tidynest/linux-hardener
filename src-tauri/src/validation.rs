const MAX_IPC_STRING_LEN: usize = 4096;

/// Rejects control characters (except space) and strings exceeding MAX_IPC_STRING_LEN bytes.
pub fn validate_ipc_string(s: &str, field_name: &str) -> Result<(), String> {
    if s.len() > MAX_IPC_STRING_LEN {
        return Err(format!(
            "{field_name} exceeds maximum length ({} > {MAX_IPC_STRING_LEN})",
            s.len()
        ));
    }
    if let Some(pos) = s.bytes().position(|b| b < b' ' && b != b'\t') {
        return Err(format!(
            "{field_name} contains invalid control character at byte {pos}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_string_accepts_normal_text() {
        assert!(validate_ipc_string("Hello World 123", "test").is_ok());
    }

    #[test]
    fn ipc_string_accepts_empty() {
        assert!(validate_ipc_string("", "test").is_ok());
    }

    #[test]
    fn ipc_string_accepts_tab() {
        assert!(validate_ipc_string("line\ttab", "test").is_ok());
    }

    #[test]
    fn ipc_string_rejects_null_byte() {
        assert!(validate_ipc_string("hello\x00world", "test").is_err());
    }

    #[test]
    fn ipc_string_rejects_newline() {
        assert!(validate_ipc_string("line\nbreak", "test").is_err());
    }

    #[test]
    fn ipc_string_rejects_oversize() {
        let big = "a".repeat(MAX_IPC_STRING_LEN + 1);
        assert!(validate_ipc_string(&big, "test").is_err());
    }

    #[test]
    fn ipc_string_accepts_max_size() {
        let exact = "a".repeat(MAX_IPC_STRING_LEN);
        assert!(validate_ipc_string(&exact, "test").is_ok());
    }
}
