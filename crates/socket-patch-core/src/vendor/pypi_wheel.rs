//! Metadata for downloaded Python distributions.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelArtifact {
    pub file_name: String,
    /// Plain sha256 hex of the wheel bytes (what pip `--hash=` and uv lock
    /// `hash = "sha256:..."` verify).
    pub sha256_hex: String,
    pub size: u64,
}

pub(crate) fn escape_wheel_version(s: &str) -> String {
    escape_wheel_chars(s, true)
}

fn escape_wheel_chars(s: &str, keep_version_separators: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_run = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric()
            || ch == '.'
            || (keep_version_separators && (ch == '+' || ch == '!'))
        {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}
