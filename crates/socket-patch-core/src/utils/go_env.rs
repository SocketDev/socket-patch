//! Go configuration lookup the way the `go` command resolves it (#344).
//!
//! go reads each setting from the process environment first, then from the
//! per-user Go environment file that `go env -w` writes, then falls back to
//! its built-in default. The Go docs tell users to configure `GOPRIVATE`,
//! `GOPROXY` and `GOMODCACHE` with `go env -w`, so consulting only the
//! environment silently ignores those settings: a private module path is
//! requested from `proxy.golang.org`, a corporate mirror is bypassed, and a
//! relocated module cache is not found.
//!
//! The file is `$GOENV` when set (`GOENV=off` disables it), else
//! `os.UserConfigDir()/go/env`: `$XDG_CONFIG_HOME/go/env` (or
//! `~/.config/go/env`) on Linux and other Unix, `~/Library/Application
//! Support/go/env` on macOS, `%AppData%\go\env` on Windows.
//!
//! Out of scope: `$GOROOT/go.env` (Go 1.21+), the toolchain's own lowest
//! layer. Upstream Go ships it with the same values as the built-in
//! defaults, and locating it would mean running `go`.

use std::path::PathBuf;

/// The effective value of Go setting `key`: a non-empty environment variable
/// wins, else the Go environment file's non-empty value, else `None` (the
/// caller applies go's default). An empty environment variable falls
/// through to the file, as go's own `cfg.Getenv` does.
pub(crate) fn go_env(key: &str) -> Option<String> {
    go_env_with(key, |k| std::env::var(k).ok())
}

/// [`go_env`] over an injected environment lookup.
pub(crate) fn go_env_with(key: &str, env: impl Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(v) = env(key).filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let file = go_env_file(&env)?;
    let text = crate::utils::fs::read_regular_to_string_sync(&file).ok()?;
    lookup_in_env_file(&text, key).filter(|v| !v.is_empty())
}

/// The Go environment file go would read, or `None` when `GOENV=off` or no
/// user config directory resolves.
fn go_env_file(env: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    match env("GOENV").filter(|v| !v.is_empty()) {
        Some(v) if v == "off" => None,
        Some(v) => Some(PathBuf::from(v)),
        None => Some(user_config_dir(env)?.join("go").join("env")),
    }
}

/// Go's `os.UserConfigDir`.
fn user_config_dir(env: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let absolute = |v: Option<String>| {
        v.filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if cfg!(windows) {
        return absolute(env("AppData").or_else(|| env("APPDATA")));
    }
    let home = || absolute(env("HOME"));
    if cfg!(target_os = "macos") {
        return Some(home()?.join("Library").join("Application Support"));
    }
    match env("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        // go refuses a relative XDG_CONFIG_HOME rather than falling back.
        Some(xdg) => absolute(Some(xdg)),
        None => Some(home()?.join(".config")),
    }
}

/// `key`'s value in a Go environment file (`cmd/go/internal/cfg`
/// `readEnvFile`): one `KEY=VALUE` per line, the value taken verbatim after
/// the first `=`; a line not starting with an uppercase letter (blank, a
/// `#` comment) or without `=` is skipped. A later line for the same key
/// wins.
fn lookup_in_env_file(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| line.starts_with(|c: char| c.is_ascii_uppercase()))
        .filter_map(|line| line.split_once('='))
        .rfind(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn parses_go_env_w_output() {
        let text = "# comment\nGOPROXY=http://127.0.0.1:18702\r\nGOPRIVATE=example.com,*.corp\n\
                    lower=x\nNOEQUALS\nGOFLAGS=-mod=mod -tags=a=b\nGOPROXY=https://mirror\n";
        assert_eq!(
            lookup_in_env_file(text, "GOPROXY").as_deref(),
            Some("https://mirror")
        );
        assert_eq!(
            lookup_in_env_file(text, "GOPRIVATE").as_deref(),
            Some("example.com,*.corp")
        );
        assert_eq!(
            lookup_in_env_file(text, "GOFLAGS").as_deref(),
            Some("-mod=mod -tags=a=b")
        );
        assert_eq!(lookup_in_env_file(text, "lower"), None);
        assert_eq!(lookup_in_env_file(text, "NOEQUALS"), None);
        assert_eq!(lookup_in_env_file(text, "GONOPROXY"), None);
    }

    /// env (non-empty) → `$GOENV` file → `None`; an empty env var falls
    /// through to the file and `GOENV=off` disables it.
    #[test]
    fn env_then_goenv_file_then_default() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("env");
        std::fs::write(&file, "GOPRIVATE=example.com\nGOMODCACHE=/cache\n").unwrap();
        let goenv = file.to_str().unwrap();

        let env = env_of(&[("GOENV", goenv)]);
        assert_eq!(
            go_env_with("GOPRIVATE", &env).as_deref(),
            Some("example.com")
        );
        assert_eq!(go_env_with("GOPROXY", &env), None);

        let env = env_of(&[("GOENV", goenv), ("GOPRIVATE", "env.example")]);
        assert_eq!(
            go_env_with("GOPRIVATE", &env).as_deref(),
            Some("env.example")
        );
        let env = env_of(&[("GOENV", goenv), ("GOPRIVATE", "")]);
        assert_eq!(
            go_env_with("GOPRIVATE", &env).as_deref(),
            Some("example.com")
        );

        let env = env_of(&[("GOENV", "off"), ("HOME", "/nonexistent")]);
        assert_eq!(go_env_with("GOPRIVATE", &env), None);
        let env = env_of(&[("GOENV", dir.path().join("missing").to_str().unwrap())]);
        assert_eq!(go_env_with("GOPRIVATE", &env), None);
    }

    /// Without `GOENV` the file is `os.UserConfigDir()/go/env`.
    #[test]
    fn default_file_is_under_the_user_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let config = if cfg!(windows) {
            base.join("roaming")
        } else if cfg!(target_os = "macos") {
            base.join("Library").join("Application Support")
        } else {
            base.join("xdg")
        };
        std::fs::create_dir_all(config.join("go")).unwrap();
        std::fs::write(config.join("go").join("env"), "GOPROXY=https://mirror\n").unwrap();
        let env = env_of(&[
            ("HOME", base.to_str().unwrap()),
            ("XDG_CONFIG_HOME", base.join("xdg").to_str().unwrap()),
            ("AppData", base.join("roaming").to_str().unwrap()),
        ]);
        assert_eq!(
            go_env_with("GOPROXY", &env).as_deref(),
            Some("https://mirror")
        );
        // A relative XDG_CONFIG_HOME / HOME resolves nothing.
        let env = env_of(&[
            ("HOME", "rel"),
            ("XDG_CONFIG_HOME", "rel"),
            ("AppData", "rel"),
        ]);
        assert_eq!(go_env_with("GOPROXY", &env), None);
    }
}
