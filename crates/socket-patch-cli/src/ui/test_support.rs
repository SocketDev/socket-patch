//! A tiny terminal emulator for asserting on what a user would *see*.
//!
//! Test-only and dependency-free: the lib includes it under `cfg(test)`,
//! and the integration tests include this same file by path from
//! `tests/common/pty_io.rs`, so there is exactly one emulator.

/// Render raw bytes as screen lines: `\n` starts a line, `\r` returns
/// to column 0 (later text overwrites), `ESC[2K` erases the line,
/// `ESC[K` erases to its end, SGR and other CSI sequences are
/// dropped. Trailing spaces are trimmed and a final empty line is
/// omitted.
pub fn render(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<Vec<char>> = vec![Vec::new()];
    let mut col = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let line = lines.last_mut().expect("never empty");
        match c {
            '\n' => {
                lines.push(Vec::new());
                col = 0;
            }
            '\r' => col = 0,
            '\x1b' if chars.peek() == Some(&'[') => {
                chars.next();
                let mut params = String::new();
                let mut fin = '\0';
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        fin = c;
                        break;
                    }
                    params.push(c);
                }
                match (fin, params.as_str()) {
                    ('K', "2") => line.clear(),
                    ('K', "" | "0") => line.truncate(col),
                    _ => {}
                }
            }
            c => {
                if col < line.len() {
                    line[col] = c;
                } else {
                    line.resize(col, ' ');
                    line.push(c);
                }
                col += 1;
            }
        }
    }
    let mut out: Vec<String> = lines
        .into_iter()
        .map(|l| l.into_iter().collect::<String>().trim_end().to_string())
        .collect();
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}
