//! Hit logging — runs ONLY on the veto path (never on the fast path).
//! Local file, redacted preview: the full secret is never duplicated here.

use std::fs::OpenOptions;
use std::io::Write;

/// Append one hit line. Best-effort: any error is swallowed — logging must
/// never break (or leak via) the exec flow.
pub fn append_hit(exe: &str, pattern: &str, arg_index: usize, preview: &str) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let dir = std::path::Path::new(&home).join(".local/share/argv-guard");
    let path = dir.join("hits.log");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(
            f,
            "{ts} exe={exe} pattern={pattern} arg={arg_index} preview={preview}"
        );
    }
}

/// Redacted preview: first 6 bytes of the match region + "…".
/// The full secret goes nowhere — not even to our own log.
pub fn preview(arg: &[u8], match_pos: usize, needle_len: usize) -> String {
    let start = match_pos;
    let mut end = (start + needle_len + 6).min(arg.len());
    // trim to token charset so we don't echo surrounding context
    while end > start + needle_len && !arg[end - 1].is_ascii_alphanumeric() {
        end -= 1;
    }
    let mut out = String::from_utf8_lossy(&arg[start..end.max(start)]).into_owned();
    out.push('…');
    out
}
