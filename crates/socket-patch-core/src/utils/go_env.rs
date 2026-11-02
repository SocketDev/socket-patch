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

use std::path::{Path, PathBuf};

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

/// go's GOPATH list (`cfg.BuildContext.GOPATH`): the setting split on the
/// OS list separator, empty entries kept, or go's default `$HOME/go` when
/// it is unset or empty. `go_env` resolves a setting as [`go_env`] does.
pub(crate) fn gopath_entries(
    go_env: &dyn Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    match go_env("GOPATH").filter(|v| !v.is_empty()) {
        Some(gopath) => std::env::split_paths(&gopath).collect(),
        None => home.map(|h| h.join("go")).into_iter().collect(),
    }
}

/// go's module cache (`cfg.GOMODCACHE`): GOMODCACHE, else `pkg/mod` under
/// the FIRST [`gopath_entries`] entry, the one place both the crawler and
/// the installed-tool audit read it from (#1834). `None` wherever go has
/// no usable module cache, never a path under the working directory:
/// * an empty first entry (`GOPATH=:/a`): go reads only that entry, so it
///   reports "module cache not found";
/// * a relative or `~`-prefixed GOPATH entry anywhere in the list: go
///   refuses to run at all, even with GOMODCACHE set;
/// * a relative cache path, which go refuses too.
pub(crate) fn gomodcache(
    go_env: &dyn Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let gopath = gopath_entries(go_env, home);
    let refused = |p: &PathBuf| {
        !p.as_os_str().is_empty() && (!p.is_absolute() || p.to_string_lossy().starts_with('~'))
    };
    if gopath.iter().any(refused) {
        return None;
    }
    let cache = match go_env("GOMODCACHE").filter(|v| !v.is_empty()) {
        Some(cache) => PathBuf::from(cache),
        None => gopath.into_iter().next()?.join("pkg").join("mod"),
    };
    cache.is_absolute().then_some(cache)
}

/// What a `GOFLAGS` setting makes go do about `-modfile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoflagsModfile {
    /// go reads the module's own go.mod: no `-modfile`, or an empty one.
    Default,
    /// go reads this file instead (the last `-modfile` wins).
    File(String),
    /// go refuses the setting, so no go command runs: why.
    Refused(String),
}

/// `-modfile` in a `GOFLAGS` setting, read as go reads it
/// (`cmd/go/internal/base.InitGOFLAGS`): fields split by
/// [`split_goflags`], each `-flag` or `--flag` (anything else makes go
/// fail: "non-flag"), the last `-modfile` winning, and a bare `-modfile`
/// refused for want of a value.
pub(crate) fn goflags_modfile(goflags: &str) -> GoflagsModfile {
    let Some(fields) = split_goflags(goflags) else {
        return GoflagsModfile::Refused("GOFLAGS has an unterminated quote".into());
    };
    // `Some(None)`: a bare `-modfile`.
    let mut modfile: Option<Option<&str>> = None;
    for field in &fields {
        let name = field
            .strip_prefix("--")
            .or_else(|| field.strip_prefix('-'))
            .filter(|n| !n.is_empty() && !n.starts_with(['-', '=']));
        let Some(name) = name else {
            return GoflagsModfile::Refused(format!("GOFLAGS has the non-flag \"{field}\""));
        };
        match name.split_once('=') {
            Some(("modfile", value)) => modfile = Some(Some(value)),
            None if name == "modfile" => modfile = Some(None),
            _ => {}
        }
    }
    match modfile {
        None | Some(Some("")) => GoflagsModfile::Default,
        Some(None) => GoflagsModfile::Refused("GOFLAGS sets -modfile without a value".into()),
        Some(Some(value)) => GoflagsModfile::File(value.to_string()),
    }
}

/// Go's `cmd/internal/quoted.Split`: whitespace-separated fields, a field
/// that opens with `'` or `"` running to the same quote (the next field
/// starts right after it). `None` when a quote is unterminated.
fn split_goflags(s: &str) -> Option<Vec<String>> {
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r');
    let mut fields = Vec::new();
    let mut rest = s.trim_start_matches(is_space);
    while !rest.is_empty() {
        let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"');
        let (field, after) = match quote {
            Some(q) => {
                let end = rest[1..].find(q)? + 1;
                (&rest[1..end], &rest[end + 1..])
            }
            None => {
                let end = rest.find(is_space).unwrap_or(rest.len());
                (&rest[..end], &rest[end..])
            }
        };
        fields.push(field.to_string());
        rest = after.trim_start_matches(is_space);
    }
    Some(fields)
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

    /// One GOPATH / GOMODCACHE rule for every caller, checked against go
    /// 1.24's `go env GOMODCACHE` and `go mod download` (#1834).
    #[cfg(unix)]
    #[test]
    fn gomodcache_follows_go() {
        let home = Some(Path::new("/home/u"));
        let cache = |pairs: &[(&str, &str)]| gomodcache(&env_of(pairs), home);
        let p = |s: &str| Some(PathBuf::from(s));
        // GOMODCACHE set: it wins.
        assert_eq!(cache(&[("GOMODCACHE", "/c"), ("GOPATH", "/a")]), p("/c"));
        // Multi-entry GOPATH: only the first entry counts.
        assert_eq!(cache(&[("GOPATH", "/a:/b")]), p("/a/pkg/mod"));
        // No GOPATH: go's default `$HOME/go`.
        assert_eq!(cache(&[]), p("/home/u/go/pkg/mod"));
        assert_eq!(gomodcache(&env_of(&[]), None), None);
        // An empty first entry: go has no module cache, not the next entry
        // and not the home default.
        assert_eq!(cache(&[("GOPATH", ":")]), None);
        assert_eq!(cache(&[("GOPATH", ":/b")]), None);
        // Empty settings count as unset.
        assert_eq!(
            cache(&[("GOMODCACHE", ""), ("GOPATH", "")]),
            p("/home/u/go/pkg/mod")
        );
        // Empty entries elsewhere in the list are ignored.
        assert_eq!(cache(&[("GOPATH", "/a::/b")]), p("/a/pkg/mod"));
        // go refuses relative paths: a relative cache, and a relative or
        // `~` GOPATH entry anywhere, even beside GOMODCACHE.
        assert_eq!(cache(&[("GOMODCACHE", "rel")]), None);
        assert_eq!(cache(&[("GOPATH", "rel:/b")]), None);
        assert_eq!(cache(&[("GOPATH", "/a:rel")]), None);
        assert_eq!(cache(&[("GOPATH", "/a:~/x")]), None);
        assert_eq!(cache(&[("GOMODCACHE", "/c"), ("GOPATH", "/a:rel")]), None);
        assert_eq!(gomodcache(&env_of(&[]), Some(Path::new("rel"))), None);

        let entries = |pairs: &[(&str, &str)]| gopath_entries(&env_of(pairs), home);
        assert_eq!(
            entries(&[("GOPATH", "/a::/b")]),
            ["/a", "", "/b"].map(PathBuf::from)
        );
        assert_eq!(entries(&[]), [PathBuf::from("/home/u/go")]);
    }

    /// `-modfile` read from GOFLAGS as go reads it (#1799).
    #[test]
    fn goflags_modfile_reads_the_last_modfile() {
        use GoflagsModfile::*;
        let file = |f: &str| File(f.to_string());
        let refused = |s: &str| matches!(goflags_modfile(s), Refused(_));
        assert_eq!(goflags_modfile(""), Default);
        assert_eq!(goflags_modfile("-mod=mod -tags=a=b"), Default);
        assert_eq!(goflags_modfile("-modfiles=a.mod"), Default);
        assert_eq!(goflags_modfile("-modfile=alt.mod"), file("alt.mod"));
        assert_eq!(
            goflags_modfile("  --modfile=alt.mod\t-mod=mod "),
            file("alt.mod")
        );
        assert_eq!(
            goflags_modfile("-modfile=a.mod -modfile=b.mod"),
            file("b.mod")
        );
        assert_eq!(goflags_modfile("-modfile=a.mod -modfile="), Default);
        assert_eq!(goflags_modfile("'-modfile=a b.mod'"), file("a b.mod"));
        assert_eq!(goflags_modfile("\"-mod=mod\"-modfile=a.mod"), file("a.mod"));
        // go rejects these settings outright.
        for s in [
            "-modfile",
            "-modfile=a.mod -modfile",
            "'-modfile=a.mod",
            "modfile=a.mod",
            "---modfile=a.mod",
            "-mod=mod -",
            "--",
            "-=x",
        ] {
            assert!(refused(s), "{s}");
        }
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
