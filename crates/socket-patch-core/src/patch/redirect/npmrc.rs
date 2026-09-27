//! The hosted npm flow's project `.npmrc` `allow-remote=all` auto-config —
//! the npm twin of the pnpm `trustLockfile` auto-config.
//!
//! npm >= 12 defaults `allow-remote=none` and refuses (EALLOWREMOTE) every
//! lockfile entry whose `resolved` tarball URL is not served by the
//! configured registry — exactly what a hosted redirect writes. The hosted
//! flow therefore ensures `allow-remote=all` in the project `.npmrc`
//! (creating the file, or appending one line) and records the edit in the
//! redirect ledger under [`NPMRC_ALLOW_REMOTE_EDIT_KIND`], so every unwind
//! path (rollback / remove replay, the per-purl npm revert behind scoped
//! rollback and the vendored takeover, the vendored-supersedes-hosted
//! reconcile) removes exactly what was added once no redirected npm lock
//! entry needs it any more.
//!
//! The `.npmrc` grammar here is npm's as MEASURED against npm 12.1.0
//! (`npm config get allow-remote` plus a real EALLOWREMOTE/ENOTFOUND install
//! probe), not a guess: the key must be spelled exactly `allow-remote` —
//! `allow_remote` and `ALLOW-REMOTE` are NOT honored in a `.npmrc` file (npm
//! only normalizes `npm_config_*` environment variables); leading/trailing
//! whitespace and a UTF-8 BOM around the key are ignored; `;` / `#` start a
//! comment line; values may be quoted and carry an inline `;`/`#` comment;
//! the LAST top-level assignment wins; assignments under an ini `[section]`
//! header are not top-level config; CRLF line endings are accepted. The
//! value is compared case-SENSITIVELY: npm's gate (`pacote` `canUse`)
//! admits every remote tarball only for the exact string `all` (`All`
//! behaves like `root`).
//!
//! Tokenization follows npm's bundled `ini` parser exactly (the unit tests
//! pin a differential corpus against it): lines split on any run of `\r` /
//! `\n` (a bare `\r` ends a line), keys and values go through ini's
//! `unsafe()` decode, and a section header is `^\[[^\]]*\]\s*$` on the
//! UNTRIMMED line (an indented or BOM-prefixed `[sec]` is a top-level key).
//!
//! An explicit non-`all` value is respected wherever npm would read it: the
//! project file, an `npm_config_allow_remote` env var (beats every file),
//! and — when the project file is silent — the user / global / builtin
//! config files ([`resolve_outer_allow_remote`]).

use std::collections::HashSet;

use super::FileEdit;

/// Repo-relative path of the project `.npmrc` the auto-config edits.
pub const NPMRC_REL: &str = ".npmrc";

/// `FileEdit.kind` recorded when the hosted flow ensures `allow-remote=all`
/// in the project `.npmrc`. `action: "created"` — the file itself was
/// created (an unwind deletes it while it still holds exactly
/// [`NPMRC_CREATED`]); `action: "added"` — the single
/// [`NPMRC_ALLOW_REMOTE_LINE`] line was spliced into an existing file (an
/// unwind removes exactly that line). `key` is `"allow-remote"`, `new` the
/// VALUE `"all"`. Additive ledger vocabulary: older ledgers load unchanged.
pub const NPMRC_ALLOW_REMOTE_EDIT_KIND: &str = "redirect_npmrc_allow_remote";

/// The line the auto-config writes (and the only line an unwind removes).
pub const NPMRC_ALLOW_REMOTE_LINE: &str = "allow-remote=all";

/// The exact `.npmrc` the auto-config CREATES when none existed.
pub const NPMRC_CREATED: &str = "allow-remote=all\n";

/// The ledger kinds that record a package-lock.json / npm-shrinkwrap.json
/// hosted splice — the entries that NEED `allow-remote=all` on npm >= 12.
/// While any of them remains in the ledger the `.npmrc` edit stays.
pub const NPM_LOCK_EDIT_KINDS: [&str; 2] = ["redirect_npm_lock_entry", "redirect_npm_lock_dep"];

const BOM: char = '\u{feff}';

/// ECMAScript whitespace — what npm's `ini` means by `\s` and by
/// `String.prototype.trim` (WhiteSpace + LineTerminator). Rust's
/// `char::is_whitespace` differs only by U+0085 (NEL: not JS whitespace)
/// and U+FEFF (the BOM: JS whitespace).
fn is_js_ws(c: char) -> bool {
    c == BOM || (c.is_whitespace() && c != '\u{85}')
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

/// npm `ini`'s line tokenization: `str.split(/[\r\n]+/)` — a bare `\r`
/// ends a line just like `\n` (empty pieces are skipped by the parser).
fn ini_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split(['\r', '\n']).filter(|l| !l.is_empty())
}

/// A `\r` that is not the first half of a `\r\n` pair: npm ends a line
/// there, but the line-splice writer below works on `\n`-terminated lines
/// (with an optional CRLF `\r`), so such a file is never rewritten.
fn has_lone_cr(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\r' && bytes.get(i + 1) != Some(&b'\n'))
}

/// npm `ini`'s section header — `^\[([^\]]*)\]\s*$` matched against the
/// UNTRIMMED line: an indented `  [sec]` or a BOM-prefixed `\u{feff}[sec]`
/// is NOT a header to npm (it parses as a top-level key), so it must not
/// end the top-level scope here either.
fn is_section_header(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    rest.find(']')
        .is_some_and(|i| rest[i + 1..].chars().all(is_js_ws))
}

/// Does this `\n`-split line (maybe carrying a CRLF `\r` — or, in a file
/// with lone `\r`s, several npm lines) hold a real section header? `line0`
/// is true for the file's first line, which carries the BOM `bom` the
/// callers strip off before splitting (npm does NOT strip it, so a
/// `\u{feff}[sec]` first line is no header).
fn holds_section_header(bom: &str, line: &str, line0: bool) -> bool {
    let owned;
    let line = if line0 && !bom.is_empty() {
        owned = format!("{bom}{line}");
        owned.as_str()
    } else {
        line
    };
    line.split('\r').any(is_section_header)
}

/// Index of the first `\n`-split line that opens an ini section (every
/// line before it is npm top-level config), or `lines.len()`.
fn top_level_end(bom: &str, lines: &[&str]) -> usize {
    lines
        .iter()
        .enumerate()
        .position(|(i, l)| holds_section_header(bom, l, i == 0))
        .unwrap_or(lines.len())
}

/// npm `ini`'s `unsafe()` value/key decode: JS-trimmed; a `"…"` value is
/// `JSON.parse`d (kept verbatim when that fails); a `'…'` value loses its
/// quotes and is then `JSON.parse`d the same way; an unquoted value is cut
/// at its first unescaped `;` / `#` (`\;` / `\#` are literal) and trimmed.
fn ini_unsafe(raw: &str) -> String {
    let v = js_trim(raw);
    let quoted =
        (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''));
    if quoted {
        let candidate = if v.starts_with('\'') {
            if v.len() >= 2 {
                &v[1..v.len() - 1]
            } else {
                ""
            }
        } else {
            v
        };
        return match serde_json::from_str::<serde_json::Value>(candidate) {
            Ok(serde_json::Value::String(s)) => s,
            Ok(other) => other.to_string(),
            Err(_) => candidate.to_string(),
        };
    }
    let mut out = String::new();
    let mut esc = false;
    for c in v.chars() {
        if esc {
            if !matches!(c, '\\' | ';' | '#') {
                out.push('\\');
            }
            out.push(c);
            esc = false;
        } else if c == ';' || c == '#' {
            break;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    if esc {
        out.push('\\');
    }
    js_trim(&out).to_string()
}

/// The value an npm config FILE sets for `key` at top level, parsed the
/// way npm's `ini` does (see the module doc): `None` when it sets none.
/// The LAST assignment wins; a `key[]` array assignment makes the value an
/// array (reported as `[a, b]` — never the plain string a caller compares
/// against, so it reads as an explicit non-default value).
pub fn npmrc_top_level_value(npmrc: &str, key: &str) -> Option<String> {
    enum Val {
        Scalar(String),
        Array(Vec<String>),
    }
    let array_key = format!("{key}[]");
    let mut value: Option<Val> = None;
    for line in ini_lines(npmrc) {
        let lead = line.trim_start_matches(is_js_ws);
        if lead.is_empty() || lead.starts_with(';') || lead.starts_with('#') {
            continue;
        }
        if is_section_header(line) {
            // Every later key belongs to a section, never to top level.
            break;
        }
        // `^([^=]+)(=(.*))?$`: at least one key character before the first
        // `=`; `.` never matches U+2028/U+2029, so such a value fails the
        // whole match and npm skips the line.
        let (raw_key, raw_value) = match line.split_once('=') {
            Some(("", _)) => continue,
            Some((k, v)) => (k, Some(v)),
            None => (line, None),
        };
        if raw_value.is_some_and(|v| v.contains(['\u{2028}', '\u{2029}'])) {
            continue;
        }
        let k = ini_unsafe(raw_key);
        let is_array = k == array_key;
        if k != key && !is_array {
            continue;
        }
        let v = raw_value.map_or_else(|| "true".to_string(), ini_unsafe);
        value = Some(match (value.take(), is_array) {
            (Some(Val::Array(mut items)), _) => {
                items.push(v);
                Val::Array(items)
            }
            (Some(Val::Scalar(prev)), true) => Val::Array(vec![prev, v]),
            (None, true) => Val::Array(vec![v]),
            (_, false) => Val::Scalar(v),
        });
    }
    value.map(|v| match v {
        Val::Scalar(s) => s,
        Val::Array(items) => format!("[{}]", items.join(", ")),
    })
}

/// The `allow-remote` value a project `.npmrc` sets at top level (the LAST
/// assignment wins, like npm's ini parser), or `None` when it sets none.
/// See the module doc for the measured grammar.
pub fn npmrc_allow_remote(npmrc: &str) -> Option<String> {
    npmrc_top_level_value(npmrc, "allow-remote")
}

/// The planned project `.npmrc` edit.
#[derive(Debug, PartialEq)]
pub enum NpmrcPlan {
    /// No `.npmrc`: create it holding exactly [`NPMRC_CREATED`].
    Create(String),
    /// `.npmrc` exists without a top-level `allow-remote` assignment: the
    /// full new text, with exactly one [`NPMRC_ALLOW_REMOTE_LINE`] line
    /// spliced in (after the last non-empty top-level line — before any
    /// `[section]` header — in the file's own line ending); every other byte
    /// (BOM, CRLF, trailing-newline shape) preserved.
    Append(String),
    /// Already resolves to `allow-remote=all` — nothing to write.
    AlreadyAll,
    /// The user explicitly set `allow-remote=<value>` (not `all`). Their
    /// call is respected — flipping an explicit security setting behind the
    /// user's back is worse than a failing install with a clear warning
    /// (the pnpm `trustLockfile: false` precedent).
    UserSet(String),
    /// An `npm_config_allow_remote` environment variable (`var`, any
    /// spelling npm normalizes to the key) sets a non-`all` value. The
    /// environment layer beats every `.npmrc`, so a project write could not
    /// take effect here — and an explicit setting is respected anyway.
    EnvSet { var: String, value: String },
    /// No project assignment, but a lower npm config layer — user
    /// (`~/.npmrc`), global (`$PREFIX/etc/npmrc`) or builtin — explicitly
    /// sets a non-`all` value. A committed project `allow-remote=all` would
    /// silently override that machine/org policy for every checkout, so it
    /// is respected like a project value.
    OuterSet {
        layer: &'static str,
        path: std::path::PathBuf,
        value: String,
    },
    /// The existing file cannot be spliced safely (e.g. bare-`\r` line
    /// endings npm splits on but the line writer does not): left alone,
    /// the reason is surfaced with the manual remedy.
    Unsupported(String),
}

/// The npm config layers OUTSIDE the project `.npmrc` that can set
/// `allow-remote` (see [`resolve_outer_allow_remote`]).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct OuterAllowRemote {
    /// `(variable, value)` of an `npm_config_allow_remote` env var (beats
    /// every `.npmrc`).
    pub env: Option<(String, String)>,
    /// The highest-precedence explicit value among the user, global and
    /// builtin config files (all below the project `.npmrc`).
    pub file: Option<OuterFileValue>,
}

/// One explicit `allow-remote` assignment in a non-project npm config file.
#[derive(Debug, Clone, PartialEq)]
pub struct OuterFileValue {
    /// `"user"`, `"global"` or `"builtin"`.
    pub layer: &'static str,
    pub path: std::path::PathBuf,
    pub value: String,
}

/// The process facts npm itself uses to locate its config layers
/// (`@npmcli/config`): environment, home directory, and the node binary
/// (npm derives the default global prefix from `process.execPath`, and its
/// own install root — the builtin config's home — sits beside it).
#[derive(Debug, Default, Clone)]
pub struct NpmConfigEnv {
    pub vars: Vec<(String, String)>,
    pub home: Option<std::path::PathBuf>,
    /// The resolved (symlink-free) node executable, when found on PATH.
    pub node_exe: Option<std::path::PathBuf>,
    /// Resolve like npm on Windows: env names case-insensitive, the default
    /// prefix is `node.exe`'s own directory, `~\` expands.
    pub windows: bool,
}

impl NpmConfigEnv {
    /// Snapshot this process's environment.
    pub fn from_process() -> Self {
        let vars: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let windows = cfg!(windows);
        let node_exe = crate::utils::process::resolve_tool("node")
            .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
            .map(|p| strip_verbatim(p, windows));
        Self::from_parts(vars, node_exe, windows)
    }

    /// Build from injected facts, deriving `home` the way npm does:
    /// `env.HOME || os.homedir()` — `os.homedir()` being `USERPROFILE` on
    /// Windows (on Unix it re-reads `HOME`, so the fallback is inert there).
    pub fn from_parts(
        vars: Vec<(String, String)>,
        node_exe: Option<std::path::PathBuf>,
        windows: bool,
    ) -> Self {
        let mut env = Self {
            vars,
            home: None,
            node_exe,
            windows,
        };
        env.home = env
            .var("HOME")
            .or_else(|| env.var("USERPROFILE"))
            .map(std::path::PathBuf::from);
        env
    }

    /// A variable as npm's `process.env[name]` reads it: exact case on
    /// Unix, case-insensitive on Windows. `Some("")` when set but empty.
    fn var_raw(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| {
                if self.windows {
                    k.eq_ignore_ascii_case(name)
                } else {
                    k == name
                }
            })
            .map(|(_, v)| v.as_str())
    }

    /// [`Self::var_raw`] with empty read as unset (npm tests `PREFIX` /
    /// `DESTDIR` / `HOME` for truthiness).
    fn var(&self, name: &str) -> Option<&str> {
        self.var_raw(name).filter(|v| !v.is_empty())
    }

    /// `@npmcli/config`'s `env-replace`, applied to every config value:
    /// `${NAME}` becomes the variable (left verbatim when unset), `${NAME?}`
    /// becomes it or empty; an odd run of backslashes before `$` escapes
    /// the expression (half the run, rounded down, is kept), an even run
    /// is halved. E.g. the Windows installer's builtin `prefix=${APPDATA}\npm`.
    fn env_replace(&self, value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = String::with_capacity(value.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'\\' && bytes[i] != b'$' {
                let next = value[i..].find(['\\', '$']).map_or(value.len(), |n| i + n);
                out.push_str(&value[i..next]);
                i = next;
                continue;
            }
            // A backslash run (possibly empty) then `${name}` / `${name?}`,
            // `name` free of `$ { } ?`. A failed match emits the whole run:
            // no position inside it may start a match (npm's lookbehind).
            let run_end = i + value[i..].len() - value[i..].trim_start_matches('\\').len();
            let expr = value[run_end..].strip_prefix("${").and_then(|rest| {
                let close = rest.find('}')?;
                let inner = &rest[..close];
                let (name, optional) = match inner.strip_suffix('?') {
                    Some(name) => (name, true),
                    None => (inner, false),
                };
                (!name.is_empty() && !name.contains(['$', '{', '}', '?'])).then_some((
                    name,
                    optional,
                    run_end + 2 + close + 1,
                ))
            });
            let Some((name, optional, end)) = expr else {
                let stop = if run_end > i { run_end } else { i + 1 };
                out.push_str(&value[i..stop]);
                i = stop;
                continue;
            };
            let esc = run_end - i;
            if esc % 2 == 1 {
                out.push_str(&value[i + esc.div_ceil(2)..end]);
            } else {
                out.push_str(&value[i..i + esc / 2]);
                match self.var_raw(name) {
                    Some(v) => out.push_str(v),
                    None if optional => {}
                    None => out.push_str(&value[run_end..end]),
                }
            }
            i = end;
        }
        out
    }

    /// A `path`-typed config value as npm's `parseField` reads it: trimmed,
    /// env-replaced, then a leading `~/` (also `~\` on Windows) expands
    /// against [`Self::home`].
    fn config_path(&self, value: &str) -> std::path::PathBuf {
        let value = self.env_replace(value.trim_matches(is_js_ws));
        let rest = value
            .strip_prefix("~/")
            .or_else(|| value.strip_prefix("~\\").filter(|_| self.windows));
        match (rest, &self.home) {
            (Some(rest), Some(home)) => home.join(rest),
            _ => std::path::PathBuf::from(value),
        }
    }

    /// An `npm_config_*` variable, matched the way npm's `loadEnv` does:
    /// prefix case-insensitive, then non-leading `_` → `-` and lowercased.
    /// Empty values are ignored (npm skips them). When several spellings
    /// are set a non-`all` one wins (process env order is unspecified, so
    /// the conservative reading is reported).
    fn npm_config(&self, key: &str) -> Option<(String, String)> {
        let mut found: Option<(String, String)> = None;
        for (k, v) in &self.vars {
            let Some(rest) = k
                .get(..11)
                .filter(|p| p.eq_ignore_ascii_case("npm_config_"))
                .map(|_| &k[11..])
            else {
                continue;
            };
            if v.is_empty() {
                continue;
            }
            let mut norm = String::with_capacity(rest.len());
            for (i, c) in rest.chars().enumerate() {
                norm.push(if c == '_' && i > 0 {
                    '-'
                } else {
                    c.to_ascii_lowercase()
                });
            }
            if norm == key && found.as_ref().is_none_or(|(_, prev)| prev == "all") {
                found = Some((k.clone(), v.clone()));
            }
        }
        found
    }
}

/// Drop Windows' verbatim `\\?\` prefix `canonicalize` adds to a drive
/// path, so config paths read (and are reported) as npm prints them.
fn strip_verbatim(path: std::path::PathBuf, windows: bool) -> std::path::PathBuf {
    if !windows {
        return path;
    }
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.into(),
        _ => path,
    }
}

/// Resolve the `allow-remote` assignments npm would see OUTSIDE the project
/// `.npmrc`, following `@npmcli/config`'s layer order (default < builtin <
/// global < user < project < env < cli) and file-location rules:
/// builtin = `npmrc` in npm's own install root, beside the node binary
/// (`<dir>/lib/node_modules/npm` on Unix, `<dir>/node_modules/npm` on
/// Windows — `PREFIX` / `DESTDIR` never move it); user =
/// `npm_config_userconfig` (else builtin `userconfig`, else `~/.npmrc`);
/// global = `npm_config_globalconfig` (else user/builtin `globalconfig`,
/// else `<prefix>/etc/npmrc`, the prefix from `npm_config_prefix`,
/// user/builtin `prefix`, `PREFIX`, or the node binary's install root —
/// `dirname(dirname(node))`, `dirname(node)` on Windows, `DESTDIR`-rooted
/// on Unix). Path values are env-replaced and `~`-expanded like npm's
/// `parseField`; on Windows env names match case-insensitively. Best-effort:
/// `read` returning `None` (absent / unreadable) reads as "sets nothing",
/// like npm.
pub fn resolve_outer_allow_remote(
    env: &NpmConfigEnv,
    read: impl Fn(&std::path::Path) -> Option<String>,
) -> OuterAllowRemote {
    use std::path::{Path, PathBuf};
    let home = env.home.as_deref();
    // The directory holding node (Windows) / its `bin` parent (Unix).
    let node_root: Option<PathBuf> = env.node_exe.as_deref().and_then(|node| {
        let bin = node.parent()?;
        Some(if env.windows { bin } else { bin.parent()? }.to_path_buf())
    });
    let default_prefix: Option<PathBuf> = env.var("PREFIX").map(PathBuf::from).or_else(|| {
        let root = node_root.clone()?;
        Some(match env.var("DESTDIR").filter(|_| !env.windows) {
            Some(dest) => Path::new(dest).join(root.strip_prefix("/").unwrap_or(&root)),
            None => root,
        })
    });
    let builtin_path = node_root.map(|root| {
        if env.windows {
            root.join("node_modules").join("npm").join("npmrc")
        } else {
            root.join("lib")
                .join("node_modules")
                .join("npm")
                .join("npmrc")
        }
    });
    let builtin_text = builtin_path.as_deref().and_then(&read);
    let env_path = |key: &str| env.npm_config(key).map(|(_, v)| env.config_path(&v));
    let file_value = |text: &Option<String>, key: &str| {
        text.as_deref()
            .and_then(|t| npmrc_top_level_value(t, key))
            .map(|v| env.config_path(&v))
    };
    let user_path = env_path("userconfig")
        .or_else(|| file_value(&builtin_text, "userconfig"))
        .or_else(|| home.map(|h| h.join(".npmrc")));
    let user_text = user_path.as_deref().and_then(&read);
    let global_path = env_path("globalconfig")
        .or_else(|| file_value(&user_text, "globalconfig"))
        .or_else(|| file_value(&builtin_text, "globalconfig"))
        .or_else(|| {
            env_path("prefix")
                .or_else(|| file_value(&user_text, "prefix"))
                .or_else(|| file_value(&builtin_text, "prefix"))
                .or_else(|| default_prefix.clone())
                .map(|prefix| prefix.join("etc").join("npmrc"))
        });
    let global_text = global_path.as_deref().and_then(&read);
    let file = [
        ("user", user_path, user_text),
        ("global", global_path, global_text),
        ("builtin", builtin_path, builtin_text),
    ]
    .into_iter()
    .find_map(|(layer, path, text)| {
        let value = npmrc_allow_remote(text.as_deref()?)?;
        Some(OuterFileValue {
            layer,
            path: path?,
            value,
        })
    });
    OuterAllowRemote {
        env: env.npm_config("allow-remote"),
        file,
    }
}

/// Decide how to ensure `allow-remote=all` in the project `.npmrc`,
/// considering only the project file (no outer npm config layers). Line
/// splices only: untouched lines stay byte-identical, so an unwind can
/// remove exactly what was added.
pub fn plan_npmrc_allow_remote(existing: Option<&str>) -> NpmrcPlan {
    plan_npmrc_allow_remote_with(existing, &OuterAllowRemote::default())
}

/// [`plan_npmrc_allow_remote`] with the npm config layers outside the
/// project file: an env `npm_config_allow_remote` that is not `all`
/// ([`NpmrcPlan::EnvSet`]) beats everything; then the project value; then
/// an explicit non-`all` user / global / builtin value
/// ([`NpmrcPlan::OuterSet`]). Every explicit value is respected, never
/// overridden by a write.
pub fn plan_npmrc_allow_remote_with(existing: Option<&str>, outer: &OuterAllowRemote) -> NpmrcPlan {
    if let Some((var, value)) = &outer.env {
        if value != "all" {
            return NpmrcPlan::EnvSet {
                var: var.clone(),
                value: value.clone(),
            };
        }
    }
    match existing.and_then(npmrc_allow_remote) {
        Some(v) if v == "all" => return NpmrcPlan::AlreadyAll,
        Some(v) => return NpmrcPlan::UserSet(v),
        None => {}
    }
    if let Some(file) = &outer.file {
        if file.value != "all" {
            return NpmrcPlan::OuterSet {
                layer: file.layer,
                path: file.path.clone(),
                value: file.value.clone(),
            };
        }
    }
    let Some(text) = existing else {
        return NpmrcPlan::Create(NPMRC_CREATED.to_string());
    };
    if has_lone_cr(text) {
        return NpmrcPlan::Unsupported(
            "uses bare carriage-return (CR-only) line endings, which socket-patch does not \
             rewrite"
                .into(),
        );
    }
    let (bom, body) = match text.strip_prefix(BOM) {
        Some(rest) => (&text[..BOM.len_utf8()], rest),
        None => ("", text),
    };
    let crlf = body.contains("\r\n");
    let line = if crlf {
        format!("{NPMRC_ALLOW_REMOTE_LINE}\r")
    } else {
        NPMRC_ALLOW_REMOTE_LINE.to_string()
    };
    let mut lines: Vec<&str> = body.split('\n').collect();
    let end = top_level_end(bom, &lines);
    let anchor = lines[..end]
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    lines.insert(anchor, &line);
    NpmrcPlan::Append(format!("{bom}{}", lines.join("\n")))
}

/// What unwinding one recorded `.npmrc` edit does to the live file.
#[derive(Debug, PartialEq)]
pub enum NpmrcUnwind {
    /// The file is gone, or no longer carries the line — already clean.
    Unchanged,
    /// Delete the file (a `created` edit whose file still holds exactly
    /// [`NPMRC_CREATED`]).
    Delete,
    /// Write this content (the one line removed). `modified_created` is
    /// set when a `created` file had grown other content: it is kept and
    /// only the line goes, which callers surface as
    /// `redirect_npmrc_allow_remote_modified`.
    Write {
        content: String,
        modified_created: bool,
    },
}

/// Is `line` (one `\n`-split element, maybe carrying a CRLF `\r` or the
/// file's BOM) exactly the line the auto-config writes?
fn is_our_line(line: &str) -> bool {
    line.trim_start_matches(BOM).trim_end_matches('\r') == NPMRC_ALLOW_REMOTE_LINE
}

/// Unwind one recorded `.npmrc` edit (`action` `created` / `added`) against
/// the live `content` (`None` = file absent). Exact inverse of
/// [`plan_npmrc_allow_remote`]'s splice: the one matching line is removed
/// with its line terminator, every other byte kept. Only TOP-LEVEL lines
/// (before the first real ini `[section]` header — the scope the plan
/// writes into and npm reads the key from) count: a copy under a section
/// is inert user text, never ours. `Err` when the line appears more than
/// once at top level (ambiguous — refuse rather than guess which copy the
/// redirect owns).
pub fn unwind_npmrc_allow_remote(
    action: &str,
    content: Option<&str>,
) -> Result<NpmrcUnwind, String> {
    let Some(content) = content else {
        return Ok(NpmrcUnwind::Unchanged);
    };
    if action == "created" && content == NPMRC_CREATED {
        return Ok(NpmrcUnwind::Delete);
    }
    let (bom, body) = match content.strip_prefix(BOM) {
        Some(rest) => (&content[..BOM.len_utf8()], rest),
        None => ("", content),
    };
    let mut lines: Vec<&str> = body.split('\n').collect();
    let end = top_level_end(bom, &lines);
    let hits: Vec<usize> = lines[..end]
        .iter()
        .enumerate()
        .filter(|(_, l)| is_our_line(l))
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [] => Ok(NpmrcUnwind::Unchanged),
        [i] => {
            lines.remove(*i);
            let rest = lines.join("\n");
            // A created file reduced to nothing but its BOM/whitespace is the
            // redirect's own file: delete it rather than leave a husk.
            if action == "created" && rest.trim().is_empty() {
                return Ok(NpmrcUnwind::Delete);
            }
            Ok(NpmrcUnwind::Write {
                content: format!("{bom}{rest}"),
                modified_created: action == "created",
            })
        }
        _ => Err(format!(
            "{NPMRC_REL}: the `{NPMRC_ALLOW_REMOTE_LINE}` line appears more than once — \
             ambiguous, refusing to guess which copy the hosted redirect added; remove the \
             duplicate, then re-run"
        )),
    }
}

/// The advisory for a redirect-created `.npmrc` that was modified since.
pub fn npmrc_modified_warning() -> (String, String) {
    (
        "redirect_npmrc_allow_remote_modified".to_string(),
        format!(
            "{NPMRC_REL} was created by the hosted redirect but has been modified since — kept \
             the file and removed only the `{NPMRC_ALLOW_REMOTE_LINE}` line"
        ),
    )
}

/// The unwind of every recorded `.npmrc` edit once no redirected npm lock
/// entry needs `allow-remote=all` any more.
#[derive(Debug, Default)]
pub struct NpmrcUnwindPlan {
    /// Ledger indices of the `.npmrc` edits to drop.
    pub indices: Vec<usize>,
    /// `None` — the file needs no change; `Some(None)` — delete it;
    /// `Some(Some(text))` — write `text`.
    pub staged: Option<Option<String>>,
    /// Advisory (code, detail) pairs.
    pub warnings: Vec<(String, String)>,
}

/// Is an unwind of the recorded `.npmrc` edit(s) due once `dropping` (the
/// ledger indices the caller is about to remove) is gone? True iff a
/// [`NPMRC_ALLOW_REMOTE_EDIT_KIND`] edit survives while no
/// [`NPM_LOCK_EDIT_KINDS`] edit does. Callers check this BEFORE reading the
/// live `.npmrc`, so a file that merely has an odd shape never refuses an
/// unrelated revert while the setting is still needed.
pub fn npmrc_unwind_due(edits: &[FileEdit], dropping: &HashSet<usize>) -> bool {
    let live = |kinds: &[&str]| {
        edits
            .iter()
            .enumerate()
            .any(|(i, e)| !dropping.contains(&i) && kinds.contains(&e.kind.as_str()))
    };
    live(&[NPMRC_ALLOW_REMOTE_EDIT_KIND]) && !live(&NPM_LOCK_EDIT_KINDS)
}

/// "Last one out turns off the lights" for the `.npmrc` auto-config: when
/// no [`NPM_LOCK_EDIT_KINDS`] edit survives outside `dropping` (the indices
/// the caller is about to remove), plan the unwind of every recorded
/// [`NPMRC_ALLOW_REMOTE_EDIT_KIND`] edit, newest first, against `current`
/// (the live `.npmrc`). `Ok(None)` when an npm lock edit still needs the
/// setting, or there is no `.npmrc` edit to unwind. `Err` on an ambiguous
/// file or a tampered ledger path (callers fail closed).
pub fn plan_unneeded_npmrc_unwind(
    edits: &[FileEdit],
    dropping: &HashSet<usize>,
    current: Option<String>,
) -> Result<Option<NpmrcUnwindPlan>, String> {
    let still_needed = edits
        .iter()
        .enumerate()
        .any(|(i, e)| !dropping.contains(&i) && NPM_LOCK_EDIT_KINDS.contains(&e.kind.as_str()));
    if still_needed {
        return Ok(None);
    }
    let indices: Vec<usize> = edits
        .iter()
        .enumerate()
        .filter(|(i, e)| !dropping.contains(i) && e.kind == NPMRC_ALLOW_REMOTE_EDIT_KIND)
        .map(|(i, _)| i)
        .collect();
    if indices.is_empty() {
        return Ok(None);
    }
    let mut plan = NpmrcUnwindPlan {
        indices: indices.clone(),
        ..NpmrcUnwindPlan::default()
    };
    let mut content = current;
    for &i in indices.iter().rev() {
        let edit = &edits[i];
        if edit.path != NPMRC_REL {
            return Err(format!(
                "the redirect ledger records a {} edit for `{}` (expected `{NPMRC_REL}`); \
                 refusing to touch it",
                edit.kind, edit.path
            ));
        }
        match unwind_npmrc_allow_remote(&edit.action, content.as_deref())? {
            NpmrcUnwind::Unchanged => {}
            NpmrcUnwind::Delete => {
                content = None;
                plan.staged = Some(None);
            }
            NpmrcUnwind::Write {
                content: next,
                modified_created,
            } => {
                if modified_created {
                    plan.warnings.push(npmrc_modified_warning());
                }
                content = Some(next.clone());
                plan.staged = Some(Some(next));
            }
        }
    }
    Ok(Some(plan))
}

/// Read the live project `.npmrc` for an unwind: `Ok(None)` when absent.
/// Refuses (`Err`) a symlink or any non-regular file HERE, at plan time —
/// [`flush_npmrc`] would refuse it too, but only after the caller's other
/// staged files (the reverted lock) had already been written, leaving the
/// lock unwound while the ledger still records the redirect. FIFO-safe
/// (non-blocking open + fstat), so a planted FIFO refuses fast instead of
/// wedging the run.
pub fn read_project_npmrc(project_root: &std::path::Path) -> Result<Option<String>, String> {
    let path = project_root.join(NPMRC_REL);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("inspect {NPMRC_REL}: {e}")),
        Ok(meta) if !meta.is_file() => {
            return Err(format!(
                "{NPMRC_REL} is not a regular file (a symlink, directory or special file); \
                 socket-patch never writes through one — replace it with a regular file, \
                 then re-run"
            ))
        }
        Ok(_) => {}
    }
    match crate::utils::fs::read_regular_to_string_sync(&path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {NPMRC_REL}: {e}")),
    }
}

/// Write (or delete) a planned `.npmrc` unwind through the reverts' shared
/// staged flush: it refuses a non-regular file (a symlink or FIFO planted at
/// the path) instead of writing through it, and writes atomically keeping
/// the file's mode.
pub async fn flush_npmrc(
    project_root: &std::path::Path,
    staged: &Option<String>,
) -> Result<(), String> {
    let one = super::staged::Staged::from([(NPMRC_REL.to_string(), staged.clone())]);
    super::staged::flush_staged(project_root, &one, &super::staged::StagedBytes::new()).await
}

/// What [`unwind_unneeded_npmrc`] did.
#[derive(Debug, Default, PartialEq)]
pub struct NpmrcStandaloneUnwind {
    /// The `.npmrc` itself was (or, on a dry run, would be) rewritten or
    /// deleted.
    pub file_changed: bool,
    /// At least one recorded `.npmrc` edit was dropped from the ledger.
    pub edits_dropped: bool,
    /// Advisory (code, detail) pairs (e.g.
    /// `redirect_npmrc_allow_remote_modified`).
    pub warnings: Vec<(String, String)>,
}

/// Standalone "last one out" pass over a ledger the caller has just pruned
/// WITHOUT an on-disk revert (the vendored-supersedes-hosted reconcile):
/// when no npm lock edit remains, unwind the recorded `.npmrc` edits on
/// disk (unless `dry_run`) and drop them from `state`. Returns what changed
/// plus the advisory warnings (the caller surfaces them); the caller
/// persists `state`. The ledger is only consulted — and the file only
/// read — when it records a `.npmrc` edit at all.
pub async fn unwind_unneeded_npmrc(
    project_root: &std::path::Path,
    state: &mut super::RedirectState,
    dry_run: bool,
) -> Result<NpmrcStandaloneUnwind, String> {
    if !npmrc_unwind_due(&state.edits, &HashSet::new()) {
        // Nothing recorded, or still needed: no read, no refusal over the
        // file's shape.
        return Ok(NpmrcStandaloneUnwind::default());
    }
    let current = read_project_npmrc(project_root)?;
    let Some(plan) = plan_unneeded_npmrc_unwind(&state.edits, &HashSet::new(), current)? else {
        return Ok(NpmrcStandaloneUnwind::default());
    };
    if !dry_run {
        if let Some(staged) = &plan.staged {
            flush_npmrc(project_root, staged).await?;
        }
    }
    let drop: HashSet<usize> = plan.indices.iter().copied().collect();
    let mut idx = 0usize;
    state.edits.retain(|_| {
        let keep = !drop.contains(&idx);
        idx += 1;
        keep
    });
    Ok(NpmrcStandaloneUnwind {
        file_changed: plan.staged.is_some(),
        edits_dropped: !plan.indices.is_empty(),
        warnings: plan.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(kind: &str, action: &str) -> FileEdit {
        FileEdit {
            path: if kind == NPMRC_ALLOW_REMOTE_EDIT_KIND {
                NPMRC_REL.into()
            } else {
                "package-lock.json".into()
            },
            kind: kind.into(),
            action: action.into(),
            key: Some(if kind == NPMRC_ALLOW_REMOTE_EDIT_KIND {
                "allow-remote".into()
            } else {
                "node_modules/left-pad".into()
            }),
            original: None,
            new: Some(serde_json::json!("all")),
        }
    }

    /// The measured npm 12.1.0 grammar (see the module doc): exact key
    /// spelling only, BOM / whitespace / CRLF / quotes / inline comments
    /// tolerated, comment lines and `[section]` bodies ignored, LAST
    /// top-level assignment wins, value case-sensitive.
    #[test]
    fn npmrc_allow_remote_reads_the_effective_assignment() {
        assert_eq!(npmrc_allow_remote(""), None);
        assert_eq!(npmrc_allow_remote("registry=https://r.example/\n"), None);
        assert_eq!(
            npmrc_allow_remote("allow-remote=all\n").as_deref(),
            Some("all")
        );
        assert_eq!(
            npmrc_allow_remote("  allow-remote = \"all\"\r\n").as_deref(),
            Some("all")
        );
        assert_eq!(
            npmrc_allow_remote("allow-remote='root'\n").as_deref(),
            Some("root")
        );
        assert_eq!(
            npmrc_allow_remote("allow-remote=all ; why\n").as_deref(),
            Some("all")
        );
        assert_eq!(
            npmrc_allow_remote("\u{feff}allow-remote=all\n").as_deref(),
            Some("all")
        );
        // npm does NOT normalize `.npmrc` keys: these are ignored by npm 12.
        assert_eq!(npmrc_allow_remote("allow_remote=all\n"), None);
        assert_eq!(npmrc_allow_remote("ALLOW-REMOTE=all\n"), None);
        // Comment lines never count.
        assert_eq!(
            npmrc_allow_remote("; allow-remote=all\n# allow-remote=all\n"),
            None
        );
        // LAST top-level assignment wins, either direction.
        assert_eq!(
            npmrc_allow_remote("allow-remote=none\nallow-remote=all\n").as_deref(),
            Some("all")
        );
        assert_eq!(
            npmrc_allow_remote("allow-remote=all\nallow-remote=none\n").as_deref(),
            Some("none")
        );
        // Section bodies are not top-level config.
        assert_eq!(npmrc_allow_remote("[sec]\nallow-remote=all\n"), None);
        assert_eq!(
            npmrc_allow_remote("allow-remote=root\n[sec]\nallow-remote=all\n").as_deref(),
            Some("root")
        );
        // Case-sensitive value: `All` is not `all` to npm's gate.
        assert_eq!(
            npmrc_allow_remote("allow-remote=All\n").as_deref(),
            Some("All")
        );
    }

    /// Differential corpus: every expectation is what npm's bundled `ini`
    /// (`ini.parse(text)['allow-remote']`) returned for the same text —
    /// identically under npm 11.19 (ini 6.0.0) and npm 12.1.0 (ini 7.0.0). Pins the review findings: a bare
    /// `\r` ends a line (`/[\r\n]+/`), and a section header is matched on
    /// the UNTRIMMED line (an indented or BOM-prefixed `[sec]` is a plain
    /// top-level key, so the scope does not end there).
    #[test]
    fn npmrc_allow_remote_matches_npm_ini_differentially() {
        let cases: &[(&str, Option<&str>)] = &[
            ("registry=x\rallow-remote=none\r", Some("none")),
            ("  [sec]\nallow-remote=none\n", Some("none")),
            ("\u{feff}[sec]\nallow-remote=none\n", Some("none")),
            ("[sec]\nallow-remote=all\n", None),
            ("[a]b=c\nallow-remote=none\n", Some("none")),
            ("[sec] \t\nallow-remote=none\n", None),
            ("\"allow-remote\"=none\n", Some("none")),
            ("allow-remote=\"none\"\n", Some("none")),
            ("allow-remote='\"root\"'\n", Some("root")),
            ("allow-remote=al;l\n", Some("al")),
            ("allow-remote=al\\;l\n", Some("al;l")),
            ("allow-remote\n", Some("true")),
            ("=allow-remote=none\n", None),
            (
                "allow-remote[]=none\nallow-remote=all\n",
                Some("[none, all]"),
            ),
            ("allow-remote=none\u{2028}\n", None),
            ("allow-remote = all # c\n", Some("all")),
            ("\u{a0}allow-remote=none\n", Some("none")),
            ("\u{85}allow-remote=none\n", None),
            (
                "allow-remote=all\r\n[x]\r\nallow-remote=none\r\n",
                Some("all"),
            ),
            ("allow-remote=\"\n", Some("\"")),
            ("allow-remote='\n", Some("")),
        ];
        for (text, want) in cases {
            assert_eq!(npmrc_allow_remote(text).as_deref(), *want, "{text:?}");
        }
    }

    /// Finding: a CR-only `.npmrc` with an explicit `allow-remote=none` was
    /// read as one `registry` line, planned an Append, and the appended
    /// `allow-remote=all` silently flipped the user's `none`. Now it is
    /// respected; a CR-only file WITHOUT the key is never spliced.
    #[test]
    fn plan_never_flips_or_splices_a_cr_only_npmrc() {
        assert_eq!(
            plan_npmrc_allow_remote(Some("registry=x\rallow-remote=none\r")),
            NpmrcPlan::UserSet("none".into())
        );
        assert!(matches!(
            plan_npmrc_allow_remote(Some("registry=x\r[sec]\rfund=false\r")),
            NpmrcPlan::Unsupported(_)
        ));
        // Mixed: one lone CR anywhere is enough to stand down.
        assert!(matches!(
            plan_npmrc_allow_remote(Some("a=1\r\nb=2\rc=3\r\n")),
            NpmrcPlan::Unsupported(_)
        ));
    }

    /// Finding: an indented / BOM-prefixed `[sec]` was treated as a header,
    /// so the plan wrote `allow-remote=all` above it while npm kept reading
    /// the user's `none` below it (EALLOWREMOTE, yet the warning claimed
    /// the write fixed it). npm reads those lines as top-level keys.
    #[test]
    fn plan_respects_values_under_non_headers() {
        for text in [
            "  [sec]\nallow-remote=none\n",
            "\u{feff}[sec]\nallow-remote=none\n",
            "[a]b=c\nallow-remote=none\n",
        ] {
            assert_eq!(
                plan_npmrc_allow_remote(Some(text)),
                NpmrcPlan::UserSet("none".into()),
                "{text:?}"
            );
        }
        // A real header after a BOM-less first line still bounds the scope,
        // and a BOM-prefixed first-line "header" does not.
        let NpmrcPlan::Append(text) = plan_npmrc_allow_remote(Some("\u{feff}[x]\n[sec]\ny=1\n"))
        else {
            panic!("append expected");
        };
        assert_eq!(text, "\u{feff}[x]\nallow-remote=all\n[sec]\ny=1\n");
    }

    /// Finding: `[sec]\nallow-remote=all\n` (inert under a section) planned
    /// a top-level append, and the unwind then counted BOTH copies and
    /// refused as ambiguous — blocking rollback, remove, the vendored
    /// takeover and the reconcile over a state our own writer created. The
    /// unwind now only counts top-level lines, like the plan.
    #[test]
    fn unwind_ignores_section_scoped_copies() {
        let before = "[sec]\nallow-remote=all\n";
        let NpmrcPlan::Append(text) = plan_npmrc_allow_remote(Some(before)) else {
            panic!("append expected");
        };
        assert_eq!(text, "allow-remote=all\n[sec]\nallow-remote=all\n");
        assert_eq!(
            unwind_npmrc_allow_remote("added", Some(&text)).unwrap(),
            NpmrcUnwind::Write {
                content: before.into(),
                modified_created: false
            }
        );
        // Only a section copy left: nothing of ours to remove.
        assert_eq!(
            unwind_npmrc_allow_remote("added", Some(before)).unwrap(),
            NpmrcUnwind::Unchanged
        );
        // The ledger-level plan agrees (the per-purl revert / reconcile path).
        let edits = vec![edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "added")];
        let plan = plan_unneeded_npmrc_unwind(&edits, &HashSet::new(), Some(text))
            .unwrap()
            .expect("unwind planned");
        assert_eq!(plan.staged, Some(Some(before.into())));
        // Two TOP-LEVEL copies are still genuinely ambiguous.
        assert!(unwind_npmrc_allow_remote(
            "added",
            Some("allow-remote=all\nallow-remote=all\n[sec]\nallow-remote=all\n")
        )
        .is_err());
    }

    fn cfg_env(vars: &[(&str, &str)]) -> NpmConfigEnv {
        NpmConfigEnv {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            home: Some("/home/u".into()),
            node_exe: Some("/opt/node/bin/node".into()),
            windows: false,
        }
    }

    /// Finding: only the project `.npmrc` was consulted, so a machine / org
    /// `allow-remote=none` in `~/.npmrc` or `$PREFIX/etc/npmrc` was
    /// silently overridden by a committed project `allow-remote=all`, and
    /// an env `npm_config_allow_remote=none` (which beats the project file)
    /// was ignored while the warning promised `npm ci` needs no flags.
    #[test]
    fn outer_layers_are_located_like_npm_and_respected() {
        use std::collections::HashMap;
        use std::path::{Path, PathBuf};
        let files: HashMap<PathBuf, &str> = HashMap::from([
            (PathBuf::from("/home/u/.npmrc"), "allow-remote=none\n"),
            (PathBuf::from("/opt/node/etc/npmrc"), "allow-remote=root\n"),
            (
                PathBuf::from("/opt/node/lib/node_modules/npm/npmrc"),
                "allow-remote=all\n",
            ),
            (
                PathBuf::from("/alt/user.npmrc"),
                "fund=false\nprefix=/pfx\n",
            ),
            (PathBuf::from("/pfx/etc/npmrc"), "allow-remote=none\n"),
        ]);
        let read = |p: &Path| files.get(p).map(|s| s.to_string());

        // user beats global beats builtin.
        let outer = resolve_outer_allow_remote(&cfg_env(&[]), read);
        assert_eq!(outer.env, None);
        let file = outer.file.clone().expect("user value");
        assert_eq!((file.layer, file.value.as_str()), ("user", "none"));
        assert_eq!(file.path, PathBuf::from("/home/u/.npmrc"));
        assert_eq!(
            plan_npmrc_allow_remote_with(None, &outer),
            NpmrcPlan::OuterSet {
                layer: "user",
                path: "/home/u/.npmrc".into(),
                value: "none".into()
            }
        );
        // A project value outranks every file layer.
        assert_eq!(
            plan_npmrc_allow_remote_with(Some("allow-remote=all\n"), &outer),
            NpmrcPlan::AlreadyAll
        );

        // npm_config_userconfig relocates the user file; its `prefix`
        // relocates the global file.
        let outer = resolve_outer_allow_remote(
            &cfg_env(&[("NPM_CONFIG_USERCONFIG", "/alt/user.npmrc")]),
            read,
        );
        let file = outer.file.expect("global value");
        assert_eq!((file.layer, file.value.as_str()), ("global", "none"));
        assert_eq!(file.path, PathBuf::from("/pfx/etc/npmrc"));

        // Default global prefix from the node binary; builtin beside npm.
        let outer =
            resolve_outer_allow_remote(&cfg_env(&[("npm_config_userconfig", "/nowhere")]), read);
        let file = outer.file.expect("global value");
        assert_eq!((file.layer, file.value.as_str()), ("global", "root"));
        let outer = resolve_outer_allow_remote(
            &cfg_env(&[
                ("npm_config_userconfig", "/nowhere"),
                ("npm_config_globalconfig", "/nowhere"),
            ]),
            read,
        );
        let file = outer.file.clone().expect("builtin value");
        assert_eq!((file.layer, file.value.as_str()), ("builtin", "all"));
        // An outer `all` never blocks the write.
        assert_eq!(
            plan_npmrc_allow_remote_with(None, &outer),
            NpmrcPlan::Create(NPMRC_CREATED.into())
        );

        // env: any spelling npm normalizes to the key; beats everything.
        for var in [
            "npm_config_allow_remote",
            "NPM_CONFIG_ALLOW_REMOTE",
            "npm_config_allow-remote",
        ] {
            let outer = resolve_outer_allow_remote(&cfg_env(&[(var, "none")]), |_| None);
            assert_eq!(outer.env, Some((var.to_string(), "none".to_string())));
            assert_eq!(
                plan_npmrc_allow_remote_with(Some("allow-remote=all\n"), &outer),
                NpmrcPlan::EnvSet {
                    var: var.into(),
                    value: "none".into()
                },
                "{var}"
            );
        }
        // Empty env values are ignored by npm; `all` never blocks.
        let outer = resolve_outer_allow_remote(
            &cfg_env(&[("npm_config_allow_remote", ""), ("npm_config_x", "none")]),
            |_| None,
        );
        assert_eq!(outer, OuterAllowRemote::default());
        let outer =
            resolve_outer_allow_remote(&cfg_env(&[("npm_config_allow_remote", "all")]), |_| None);
        assert_eq!(
            plan_npmrc_allow_remote_with(None, &outer),
            NpmrcPlan::Create(NPMRC_CREATED.into())
        );
        // PREFIX (exact case) overrides the node-derived default prefix.
        let outer = resolve_outer_allow_remote(
            &cfg_env(&[("npm_config_userconfig", "/nowhere"), ("PREFIX", "/pfx")]),
            read,
        );
        assert_eq!(
            outer.file.expect("global").path,
            PathBuf::from("/pfx/etc/npmrc")
        );
        // ...but never the builtin config: npm's own install root is where
        // npm lives (beside node), not the global prefix.
        let outer = resolve_outer_allow_remote(
            &cfg_env(&[
                ("npm_config_userconfig", "/nowhere"),
                ("npm_config_globalconfig", "/nowhere"),
                ("PREFIX", "/pfx"),
                ("DESTDIR", "/dest"),
            ]),
            read,
        );
        let file = outer.file.expect("builtin value");
        assert_eq!(file.layer, "builtin");
        assert_eq!(
            file.path,
            PathBuf::from("/opt/node/lib/node_modules/npm/npmrc")
        );
    }

    /// `@npmcli/config`'s env-replace, differentially pinned against npm
    /// 12.1.0's `lib/env-replace.js` (outputs captured from node).
    #[test]
    fn env_replace_matches_npm() {
        let env = NpmConfigEnv::from_parts(
            vec![("A".into(), "x".into()), ("E".into(), String::new())],
            None,
            false,
        );
        for (input, want) in [
            ("${A}", "x"),
            ("${B}", "${B}"),
            ("${B?}", ""),
            ("${A?}", "x"),
            ("${E}", ""),
            ("${E?}", ""),
            ("\\${A}", "${A}"),
            ("\\\\${A}", "\\x"),
            ("\\\\\\${A}", "\\${A}"),
            ("\\\\\\\\${A}", "\\\\x"),
            ("a$b${", "a$b${"),
            ("${A}${A}", "xx"),
            ("$${A}", "$x"),
            ("\\x${A}", "\\xx"),
            ("${}", "${}"),
            ("${a{b}", "${a{b}"),
            ("${a?b}", "${a?b}"),
            ("${a??}", "${a??}"),
            ("pre\\\\\\${B?}post", "pre\\${B?}post"),
            ("${A}\\npm", "x\\npm"),
            ("\\\\${B?}", "\\"),
            ("é${A}ü", "éxü"),
        ] {
            assert_eq!(env.env_replace(input), want, "{input:?}");
        }
    }

    /// Windows resolution, simulated on any host (forward-slash drive paths
    /// parse on both): env names are case-insensitive (`process.env`), home
    /// falls back to `USERPROFILE` (`os.homedir()`), the default prefix is
    /// `node.exe`'s own directory (no `bin`), builtin is
    /// `<dir>/node_modules/npm/npmrc`, `DESTDIR` is ignored, `~\` expands,
    /// and the installer's builtin `prefix=${APPDATA}\npm` is env-replaced.
    /// The same inputs with `windows: false` resolve the Unix way.
    #[test]
    fn outer_layers_are_located_like_npm_on_windows() {
        use std::collections::HashMap;
        use std::path::{Path, PathBuf};
        let win = |vars: &[(&str, &str)]| {
            NpmConfigEnv::from_parts(
                vars.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                Some("C:/nodejs/node.exe".into()),
                true,
            )
        };
        let appdata_global = PathBuf::from(r"C:/Users/u/AppData/Roaming\npm")
            .join("etc")
            .join("npmrc");
        let files: HashMap<PathBuf, &str> = HashMap::from([
            (PathBuf::from("C:/Users/u/.npmrc"), "allow-remote=none\n"),
            (PathBuf::from("C:/Users/u/alt.npmrc"), "allow-remote=root\n"),
            (
                PathBuf::from("C:/nodejs/node_modules/npm/npmrc"),
                "prefix=${APPDATA}\\npm\n",
            ),
            (appdata_global.clone(), "allow-remote=none\n"),
            (PathBuf::from("C:/nodejs/etc/npmrc"), "allow-remote=root\n"),
            (PathBuf::from("C:/pfx/etc/npmrc"), "allow-remote=none\n"),
        ]);
        let read = |p: &Path| files.get(p).map(|s| s.to_string());

        // Home from USERPROFILE (any case); HOME (any case) wins over it.
        let env = win(&[("UserProfile", "C:/Users/u")]);
        assert_eq!(env.home, Some(PathBuf::from("C:/Users/u")));
        assert_eq!(
            win(&[("USERPROFILE", "C:/Users/u"), ("Home", "D:/h")]).home,
            Some(PathBuf::from("D:/h"))
        );
        let file = resolve_outer_allow_remote(&env, read).file.expect("user");
        assert_eq!(file.layer, "user");
        assert_eq!(file.path, PathBuf::from("C:/Users/u/.npmrc"));

        // `~\` expands on Windows.
        let file = resolve_outer_allow_remote(
            &win(&[
                ("USERPROFILE", "C:/Users/u"),
                ("npm_config_userconfig", r"~\alt.npmrc"),
            ]),
            read,
        )
        .file
        .expect("relocated user");
        assert_eq!(file.path, PathBuf::from("C:/Users/u/alt.npmrc"));

        // The builtin `prefix=${APPDATA}\npm` (APPDATA matched in any case)
        // moves the global file under %APPDATA%\npm.
        let file = resolve_outer_allow_remote(
            &win(&[
                ("npm_config_userconfig", "C:/nowhere"),
                ("AppData", "C:/Users/u/AppData/Roaming"),
            ]),
            read,
        )
        .file
        .expect("global");
        assert_eq!((file.layer, file.path), ("global", appdata_global.clone()));

        // With no builtin prefix: `dirname(node.exe)`, not its parent, and
        // DESTDIR is Unix-only.
        let no_builtin = |p: &Path| {
            (!p.ends_with("node_modules/npm/npmrc"))
                .then(|| read(p))
                .flatten()
        };
        let file = resolve_outer_allow_remote(
            &win(&[("npm_config_userconfig", "C:/nowhere"), ("DESTDIR", "C:/d")]),
            no_builtin,
        )
        .file
        .expect("global");
        assert_eq!(file.path, PathBuf::from("C:/nodejs/etc/npmrc"));

        // PREFIX is matched case-insensitively on Windows, exactly on Unix.
        let vars = [
            ("npm_config_userconfig", "C:/nowhere"),
            ("Prefix", "C:/pfx"),
        ];
        let file = resolve_outer_allow_remote(&win(&vars), no_builtin)
            .file
            .expect("global");
        assert_eq!(file.path, PathBuf::from("C:/pfx/etc/npmrc"));
        let mut unix = win(&vars);
        unix.windows = false;
        let outer = resolve_outer_allow_remote(&unix, |p| {
            assert_ne!(p, Path::new("C:/pfx/etc/npmrc"), "`Prefix` is not PREFIX");
            None
        });
        assert_eq!(outer.file, None);

        // The Unix reading of the same facts: `~\` is literal, env names
        // are exact-case (`AppData` does not satisfy `${APPDATA}`), the
        // builtin lives under `lib/`.
        let unix = NpmConfigEnv::from_parts(
            vec![
                ("HOME".into(), "/home/u".into()),
                ("npm_config_userconfig".into(), r"~\alt.npmrc".into()),
                ("AppData".into(), "/appdata".into()),
            ],
            Some("/opt/node/bin/node".into()),
            false,
        );
        let seen = std::cell::RefCell::new(Vec::new());
        resolve_outer_allow_remote(&unix, |p| {
            seen.borrow_mut().push(p.to_path_buf());
            (p == Path::new("/opt/node/lib/node_modules/npm/npmrc"))
                .then(|| "prefix=${APPDATA}/npm\n".to_string())
        });
        assert_eq!(
            seen.into_inner(),
            vec![
                PathBuf::from("/opt/node/lib/node_modules/npm/npmrc"),
                PathBuf::from(r"~\alt.npmrc"),
                PathBuf::from("${APPDATA}/npm/etc/npmrc"),
            ]
        );
    }

    #[test]
    fn strip_verbatim_only_touches_windows_drive_paths() {
        use std::path::PathBuf;
        let v = PathBuf::from(r"\\?\C:\Program Files\nodejs\node.exe");
        assert_eq!(
            strip_verbatim(v.clone(), true),
            PathBuf::from(r"C:\Program Files\nodejs\node.exe")
        );
        assert_eq!(strip_verbatim(v.clone(), false), v);
        let unc = PathBuf::from(r"\\?\UNC\srv\share\node.exe");
        assert_eq!(strip_verbatim(unc.clone(), true), unc);
    }

    #[test]
    fn unwind_due_only_when_no_npm_lock_edit_survives() {
        let edits = vec![
            edit("redirect_npm_lock_entry", "rewritten"),
            edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "created"),
        ];
        assert!(!npmrc_unwind_due(&edits, &HashSet::new()));
        assert!(npmrc_unwind_due(&edits, &HashSet::from([0])));
        assert!(!npmrc_unwind_due(&edits, &HashSet::from([0, 1])));
        assert!(!npmrc_unwind_due(&edits[..1], &HashSet::new()));
    }

    /// Finding: the per-purl revert learned a symlinked `.npmrc` was
    /// unwritable only at flush time, after the reverted lock had landed.
    /// The read used while PLANNING now refuses it.
    #[cfg(unix)]
    #[test]
    fn read_project_npmrc_refuses_a_symlink_at_plan_time() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_project_npmrc(dir.path()), Ok(None));
        std::fs::write(dir.path().join("shared.npmrc"), "allow-remote=all\n").unwrap();
        std::os::unix::fs::symlink("shared.npmrc", dir.path().join(".npmrc")).unwrap();
        let err = read_project_npmrc(dir.path()).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        std::fs::remove_file(dir.path().join(".npmrc")).unwrap();
        std::fs::create_dir(dir.path().join(".npmrc")).unwrap();
        assert!(read_project_npmrc(dir.path()).is_err());
    }

    #[test]
    fn plan_creates_when_absent() {
        assert_eq!(
            plan_npmrc_allow_remote(None),
            NpmrcPlan::Create("allow-remote=all\n".into())
        );
    }

    #[test]
    fn plan_appends_preserving_bytes_and_round_trips() {
        let cases = [
            (
                "registry=https://r.example/\n",
                "registry=https://r.example/\nallow-remote=all\n",
            ),
            ("a=1", "a=1\nallow-remote=all"),
            ("a=1\n\n", "a=1\nallow-remote=all\n\n"),
            ("a=1\r\nb=2\r\n", "a=1\r\nb=2\r\nallow-remote=all\r\n"),
            ("\u{feff}a=1\n", "\u{feff}a=1\nallow-remote=all\n"),
            ("", "allow-remote=all\n"),
            ("\u{feff}", "\u{feff}allow-remote=all\n"),
            ("\n", "allow-remote=all\n\n"),
            ("; team config\n", "; team config\nallow-remote=all\n"),
            // An `allow_remote` spelling npm ignores stays byte-identical.
            ("allow_remote=all\n", "allow_remote=all\nallow-remote=all\n"),
            // Never inside an ini section: before the first header.
            ("a=1\n[sec]\nx=1\n", "a=1\nallow-remote=all\n[sec]\nx=1\n"),
            ("[sec]\nx=1\n", "allow-remote=all\n[sec]\nx=1\n"),
        ];
        for (before, after) in cases {
            let NpmrcPlan::Append(text) = plan_npmrc_allow_remote(Some(before)) else {
                panic!("{before:?} must plan an append");
            };
            assert_eq!(text, after, "append into {before:?}");
            assert_eq!(
                npmrc_allow_remote(&text).as_deref(),
                Some("all"),
                "{text:?}"
            );
            // Exact inverse: the unwind restores the user's bytes.
            assert_eq!(
                unwind_npmrc_allow_remote("added", Some(&text)).unwrap(),
                NpmrcUnwind::Write {
                    content: before.to_string(),
                    modified_created: false
                },
                "unwind of {text:?}"
            );
        }
    }

    #[test]
    fn plan_respects_existing_values() {
        for text in [
            "allow-remote=all\n",
            "allow-remote = \"all\"\r\n",
            "allow-remote=none\nallow-remote=all\n",
        ] {
            assert_eq!(
                plan_npmrc_allow_remote(Some(text)),
                NpmrcPlan::AlreadyAll,
                "{text:?}"
            );
        }
        for (text, value) in [
            ("allow-remote=none\n", "none"),
            ("allow-remote=root\n", "root"),
            ("allow-remote=all\nallow-remote=root\n", "root"),
            ("allow-remote=All\n", "All"),
        ] {
            assert_eq!(
                plan_npmrc_allow_remote(Some(text)),
                NpmrcPlan::UserSet(value.into()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn unwind_created_file() {
        assert_eq!(
            unwind_npmrc_allow_remote("created", Some(NPMRC_CREATED)).unwrap(),
            NpmrcUnwind::Delete
        );
        assert_eq!(
            unwind_npmrc_allow_remote("created", None).unwrap(),
            NpmrcUnwind::Unchanged
        );
        // Grown since: keep the file, drop only our line, say so.
        assert_eq!(
            unwind_npmrc_allow_remote("created", Some("allow-remote=all\nfund=false\n")).unwrap(),
            NpmrcUnwind::Write {
                content: "fund=false\n".into(),
                modified_created: true
            }
        );
        // The user already removed our line: nothing to do.
        assert_eq!(
            unwind_npmrc_allow_remote("added", Some("fund=false\n")).unwrap(),
            NpmrcUnwind::Unchanged
        );
        // A commented-out copy is not our line.
        assert_eq!(
            unwind_npmrc_allow_remote("added", Some("; allow-remote=all\n")).unwrap(),
            NpmrcUnwind::Unchanged
        );
        // Ambiguous duplicates refuse.
        assert!(
            unwind_npmrc_allow_remote("added", Some("allow-remote=all\nallow-remote=all\n"))
                .is_err()
        );
    }

    #[test]
    fn last_one_out_keeps_the_setting_while_npm_lock_edits_remain() {
        let edits = vec![
            edit("redirect_npm_lock_entry", "rewritten"),
            edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "created"),
        ];
        // The lock edit survives: the setting is still needed.
        assert!(
            plan_unneeded_npmrc_unwind(&edits, &HashSet::new(), Some(NPMRC_CREATED.into()))
                .unwrap()
                .is_none()
        );
        // The lock edit is being dropped: unwind (delete the created file).
        let plan =
            plan_unneeded_npmrc_unwind(&edits, &HashSet::from([0]), Some(NPMRC_CREATED.into()))
                .unwrap()
                .expect("unwind planned");
        assert_eq!(plan.indices, vec![1]);
        assert_eq!(plan.staged, Some(None));
        // A pnpm-only ledger with a stray `.npmrc` edit also unwinds.
        let edits = vec![
            edit("redirect_pnpm_resolution", "rewritten"),
            edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "added"),
        ];
        let plan = plan_unneeded_npmrc_unwind(
            &edits,
            &HashSet::new(),
            Some("a=1\nallow-remote=all\n".into()),
        )
        .unwrap()
        .expect("unwind planned");
        assert_eq!(plan.staged, Some(Some("a=1\n".into())));
        // A tampered ledger path refuses.
        let mut bad = edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "added");
        bad.path = "../.npmrc".into();
        assert!(plan_unneeded_npmrc_unwind(&[bad], &HashSet::new(), None).is_err());
    }

    #[tokio::test]
    async fn standalone_unwind_removes_only_our_line_and_drops_the_edit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "fund=false\r\nallow-remote=all\r\n",
        )
        .unwrap();
        let mut state = super::super::RedirectState::new();
        state
            .edits
            .push(edit(NPMRC_ALLOW_REMOTE_EDIT_KIND, "added"));
        // Dry run: nothing written, edit still dropped from the (throwaway) state.
        let mut probe = state.clone();
        unwind_unneeded_npmrc(dir.path(), &mut probe, true)
            .await
            .unwrap();
        assert!(probe.edits.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "fund=false\r\nallow-remote=all\r\n"
        );
        let out = unwind_unneeded_npmrc(dir.path(), &mut state, false)
            .await
            .unwrap();
        assert!(out.warnings.is_empty());
        assert!(out.file_changed && out.edits_dropped, "{out:?}");
        assert!(state.edits.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".npmrc")).unwrap(),
            "fund=false\r\n"
        );
    }
}
