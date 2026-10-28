//! yarn 1's `yarn-offline-mirror` setting, resolved the way yarn 1.22
//! resolves it (`NpmRegistry.getPossibleConfigLocations`,
//! `BaseRegistry.mergeEnv` and `Config.getOfflineMirrorPath` in
//! `yarn@1.22.22`), for the hosted yarn classic rewriter's refusal (#364).
//!
//! Yarn 1 keeps two config registries, npm's (`.npmrc` files,
//! `npm_config_*` and `YARN_*` env) and its own (`.yarnrc` files, `YARN_*`
//! env). In each, an env variable beats every file, and among the files
//! the FIRST one that sets the key wins, in this order: the project's,
//! the user's (`userconfig`, else `~/.<rc>`, `/usr/local/share/.<rc>` for
//! root), `<prefix>/etc/<rc>`, `~/.<rc>` again when root, then every
//! ancestor directory up to (not including) the filesystem root. The
//! mirror is the npm value overridden by the yarn value, and `false` in
//! either one turns it off.
//!
//! [`configured_yarn_global_folders`] reads yarn 1's `global-folder`
//! from the same layers, for self-update's install-channel detection
//! (#1629).
//!
//! Every text is read BOM-stripped: yarn honours a `.yarnrc` / `.npmrc`
//! saved as "UTF-8 with signature" (#1078).

use std::path::{Path, PathBuf};

use super::npmrc::NpmConfigEnv;
use crate::formats::text::strip_bom;

const KEY: &str = "yarn-offline-mirror";

/// One `yarn-offline-mirror` assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorValue {
    /// `false`: no mirror, whatever any other layer says.
    Disabled,
    /// A mirror directory (empty: set, but no mirror).
    Path(String),
}

/// A [`MirrorValue`] and the layer that set it (for the refusal's detail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSetting {
    pub value: MirrorValue,
    /// The file path, or the env variable name.
    pub origin: String,
}

/// The layers of one yarn config registry outside the project's own rc.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OuterRegistryMirror {
    /// An env variable (beats the project file).
    pub env: Option<MirrorSetting>,
    /// The first non-project rc file that sets the key (below the project
    /// file).
    pub file: Option<MirrorSetting>,
}

/// The `yarn-offline-mirror` layers yarn 1 reads OUTSIDE the project's
/// `.yarnrc` / `.npmrc` (see [`resolve_outer_yarn_mirror`]). The default
/// sets nothing: only the project files count (the in-memory flow, which
/// has no host).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OuterYarnMirror {
    pub npm: OuterRegistryMirror,
    pub yarn: OuterRegistryMirror,
    /// The mirror yarn 1 uses when it runs in a workspace member directory
    /// (`cd packages/a && yarn install`, `yarn --cwd packages/a install`),
    /// whose own `.yarnrc` / `.npmrc` the root's layers never read (#1115).
    /// See [`resolve_member_yarn_mirror`].
    pub member: Option<MirrorSetting>,
}

/// The mirror yarn 1 uses for a project, if any: per registry the env
/// layer, then the project file, then the outer files; then npm's value
/// overridden by yarn's, `false` in either one meaning none, and an empty
/// value meaning none.
pub fn effective_mirror(
    yarnrc: Option<&str>,
    npmrc: Option<&str>,
    outer: &OuterYarnMirror,
) -> Option<MirrorSetting> {
    let layered = |outer: &OuterRegistryMirror, project: Option<MirrorValue>, rel: &str| {
        outer
            .env
            .clone()
            .or_else(|| {
                project.map(|value| MirrorSetting {
                    value,
                    origin: rel.to_string(),
                })
            })
            .or_else(|| outer.file.clone())
    };
    let npm = layered(
        &outer.npm,
        npmrc.and_then(npmrc_value),
        super::npmrc::NPMRC_REL,
    );
    let yarn = layered(
        &outer.yarn,
        yarnrc.and_then(yarnrc_value),
        super::YARNRC_REL,
    );
    let mut mirror = None;
    for setting in [npm, yarn].into_iter().flatten() {
        match setting.value {
            MirrorValue::Disabled => return None,
            MirrorValue::Path(_) => mirror = Some(setting),
        }
    }
    mirror.filter(|s| matches!(&s.value, MirrorValue::Path(p) if !p.is_empty()))
}

fn mirror_value(raw: &str) -> MirrorValue {
    match unquote_rc_value(raw) {
        "false" => MirrorValue::Disabled,
        value => MirrorValue::Path(value.to_string()),
    }
}

/// Strip one pair of matching quotes, as yarn's `.yarnrc` parser and npm's
/// ini parser both do.
fn unquote_rc_value(raw: &str) -> &str {
    let raw = raw.trim();
    for q in ['"', '\''] {
        if raw.len() >= 2 && raw.starts_with(q) && raw.ends_with(q) {
            return &raw[1..raw.len() - 1];
        }
    }
    raw
}

/// The last `yarn-offline-mirror` value in a `.yarnrc` (`key value` or
/// `key: value` lines, key optionally quoted, `#` comments); later lines
/// override earlier ones.
pub fn yarnrc_value(text: &str) -> Option<MirrorValue> {
    yarnrc_setting(text, KEY).map(mirror_value)
}

/// The last raw `key` value in a `.yarnrc` (see [`yarnrc_value`]).
fn yarnrc_setting<'a>(text: &'a str, key_name: &str) -> Option<&'a str> {
    let mut found = None;
    for line in strip_bom(text).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = match line.strip_prefix('"') {
            Some(quoted) => match quoted.split_once('"') {
                Some((key, rest)) => (key, rest),
                None => continue,
            },
            // yarn's `.yarnrc` parser also ends an unquoted key at `:`, so
            // `key: value` and `key:value` set the key like `key value`.
            None => match line.split_once(|c: char| c.is_whitespace() || c == ':') {
                Some((key, rest)) => (key, rest),
                None => (line, ""),
            },
        };
        if key == key_name {
            let rest = rest.trim_start();
            found = Some(rest.strip_prefix(':').unwrap_or(rest));
        }
    }
    found
}

/// The last top-level `yarn-offline-mirror` value in an `.npmrc` (ini
/// `key = value` lines, `#`/`;` comments, `[section]` headers end the
/// top level).
pub fn npmrc_value(text: &str) -> Option<MirrorValue> {
    npmrc_setting(text, KEY).map(mirror_value)
}

/// The last raw top-level `key` value in an `.npmrc` (see
/// [`npmrc_value`]).
fn npmrc_setting<'a>(text: &'a str, key_name: &str) -> Option<&'a str> {
    let mut found = None;
    for line in strip_bom(text).lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if unquote_rc_value(key) == key_name {
            found = Some(value);
        }
    }
    found
}

/// A config key set through env variables with one of `prefixes`, matched
/// like yarn's `mergeEnv`: the whole name lowercased, the prefix stripped,
/// `__` read as a key path separator and a `_` after another character as
/// `-`. Later prefixes override earlier ones (yarn merges `YARN_*` before
/// `npm_config_*`). Process env order is unspecified, so when several
/// spellings of one prefix are set the most conservative reading wins: a
/// mirror over none.
fn env_value(env: &NpmConfigEnv, prefixes: &[&str], key: &str) -> Option<(String, String)> {
    let mut found = None;
    for prefix in prefixes {
        let mut best: Option<(String, String)> = None;
        for (name, value) in &env.vars {
            let lower = name.to_ascii_lowercase();
            let Some(rest) = lower.strip_prefix(prefix) else {
                continue;
            };
            let rest = rest.replace("__", ".");
            let normalized: String = rest
                .char_indices()
                .map(|(i, c)| if c == '_' && i > 0 { '-' } else { c })
                .collect();
            if normalized != key {
                continue;
            }
            let rank = |v: &str| match v {
                "" | "false" => 0,
                _ => 1,
            };
            if best
                .as_ref()
                .is_none_or(|(_, prev)| rank(value) > rank(prev))
            {
                best = Some((name.clone(), value.clone()));
            }
        }
        if best.is_some() {
            found = best;
        }
    }
    found
}

/// Resolve the `yarn-offline-mirror` layers yarn 1 reads outside the
/// project's own `.yarnrc` / `.npmrc` (see the module docs), for a yarn
/// run in `project`. `root_user` is whether yarn runs as uid 0 (its user
/// rc then lives in `/usr/local/share`, unless `FAKEROOTKEY` is set or on
/// Windows). `read` returning `None` (absent / unreadable) reads as "sets
/// nothing", like yarn.
pub fn resolve_outer_yarn_mirror(
    env: &NpmConfigEnv,
    root_user: bool,
    project: &Path,
    read: impl Fn(&Path) -> Option<String>,
) -> OuterYarnMirror {
    let layout = RcLayout::new(env, root_user);
    let files = |rc: &str, userconfig| layout.files(project, rc, userconfig);
    let first_file = |paths: Vec<PathBuf>, parse: fn(&str) -> Option<MirrorValue>| {
        paths.into_iter().find_map(|path| {
            let value = parse(&read(&path)?)?;
            Some(MirrorSetting {
                value,
                origin: path.display().to_string(),
            })
        })
    };
    let env_setting = |prefixes: &[&str]| {
        env_value(env, prefixes, KEY).map(|(name, value)| MirrorSetting {
            value: match value.as_str() {
                "false" => MirrorValue::Disabled,
                _ => MirrorValue::Path(value),
            },
            origin: name,
        })
    };
    // npm's registry also merges `YARN_*` first (`BaseRegistry.init`),
    // then `npm_config_*` over it.
    let npm_prefixes = ["yarn_", "npm_config_"];
    OuterYarnMirror {
        npm: OuterRegistryMirror {
            env: env_setting(&npm_prefixes),
            file: first_file(
                files("npmrc", env_value(env, &npm_prefixes, "userconfig")),
                npmrc_value,
            ),
        },
        yarn: OuterRegistryMirror {
            env: env_setting(&["yarn_"]),
            file: first_file(
                files("yarnrc", env_value(env, &["yarn_"], "userconfig")),
                yarnrc_value,
            ),
        },
        member: None,
    }
}

/// Where yarn 1 looks for rc files outside the project (see the module
/// docs).
struct RcLayout {
    /// `~`, from `HOME` (`USERPROFILE` on Windows).
    home: Option<PathBuf>,
    /// yarn's `userHome`: `/usr/local/share` for root, else `home`.
    user_home: Option<PathBuf>,
    /// yarn's `getGlobalPrefix`.
    prefix: Option<PathBuf>,
}

impl RcLayout {
    /// `root_user` is whether yarn runs as uid 0 (its user rc then lives
    /// in `/usr/local/share`, unless `FAKEROOTKEY` is set or on Windows).
    fn new(env: &NpmConfigEnv, root_user: bool) -> Self {
        let home = env.home.clone();
        let user_home = if root_user && !env.windows && env.var("FAKEROOTKEY").is_none() {
            Some(PathBuf::from("/usr/local/share"))
        } else {
            home.clone()
        };
        // yarn's `getGlobalPrefix`: `PREFIX`, else node's directory (Windows)
        // or its install root (Unix, `DESTDIR`-rooted).
        let prefix: Option<PathBuf> = env.var("PREFIX").map(PathBuf::from).or_else(|| {
            let bin = env.node_exe.as_deref()?.parent()?;
            if env.windows {
                return Some(bin.to_path_buf());
            }
            let root = bin.parent()?;
            Some(match env.var("DESTDIR") {
                Some(dest) => Path::new(dest).join(root.strip_prefix("/").unwrap_or(root)),
                None => root.to_path_buf(),
            })
        });
        RcLayout {
            home,
            user_home,
            prefix,
        }
    }

    /// The `<rc>` files yarn run in `project` reads after the project's
    /// own, in its order; `userconfig` is the env override of the user
    /// file.
    fn files(
        &self,
        project: &Path,
        rc: &str,
        userconfig: Option<(String, String)>,
    ) -> Vec<PathBuf> {
        let local = format!(".{rc}");
        let mut out = Vec::new();
        match userconfig {
            Some((_, path)) if !path.is_empty() => out.push(project.join(path)),
            _ => out.extend(self.user_home.as_ref().map(|h| h.join(&local))),
        }
        out.extend(self.prefix.as_ref().map(|p| p.join("etc").join(rc)));
        if let (Some(home), Some(user_home)) = (&self.home, &self.user_home) {
            if home != user_home {
                out.push(home.join(&local));
            }
        }
        out.extend(
            project
                .ancestors()
                .skip(1)
                .filter(|dir| dir.parent().is_some())
                .map(|dir| dir.join(&local)),
        );
        out
    }

    /// yarn's `resolveWithHome`: a leading `~/` (also `~\` on Windows)
    /// is `userHome`, anything else resolves against `cwd`.
    fn resolve_with_home(&self, value: &str, cwd: &Path, windows: bool) -> Option<PathBuf> {
        let tilde = value
            .strip_prefix("~/")
            .or_else(|| value.strip_prefix("~\\").filter(|_| windows));
        match tilde {
            Some(rest) => self.user_home.as_ref().map(|h| h.join(rest)),
            None => Some(cwd.join(value)),
        }
    }
}

const GLOBAL_FOLDER_KEY: &str = "global-folder";

/// Every folder yarn 1 run in `cwd` is configured to use as its global
/// folder (`yarn global dir`) by a `global-folder` setting: the `YARN_*`
/// and `npm_config_*` env layers, the `.yarnrc` files (also as a
/// `--global-folder` default flag) and the `.npmrc` files (the project's
/// in `cwd`, then the outer ones). Yarn uses the first of them by its
/// precedence, but a folder any layer names was set up as a yarn global
/// folder, so all of them count.
///
/// Values read as in `yarn@1.22.22`: a `.yarnrc` value is one token of
/// yarn's rc grammar ([`yarnrc_token`]) resolved against the folder of
/// its file (`RELATIVE_KEYS`); an `.npmrc` value has its `${NAME}`
/// references expanded ([`yarn_env_replace`]); env and `.npmrc` values
/// then go through `resolveWithHome` (`~/` is yarn's `userHome`, else the
/// cwd). Empty values set nothing.
pub fn configured_yarn_global_folders(
    env: &NpmConfigEnv,
    root_user: bool,
    cwd: &Path,
    read: impl Fn(&Path) -> Option<String>,
) -> Vec<PathBuf> {
    let layout = RcLayout::new(env, root_user);
    let mut out = Vec::new();
    let mut push = |value: Option<String>, resolve: &dyn Fn(&str) -> Option<PathBuf>| {
        if let Some(path) = value.filter(|v| !v.is_empty()).and_then(|v| resolve(&v)) {
            out.push(path);
        }
    };
    let with_home = |value: &str| layout.resolve_with_home(value, cwd, env.windows);
    for prefix in ["yarn_", "npm_config_"] {
        push(
            env_value(env, &[prefix], GLOBAL_FOLDER_KEY).map(|(_, value)| value),
            &with_home,
        );
    }
    let rc_files = |rc: &str, prefixes: &[&str]| {
        let mut files = vec![cwd.join(format!(".{rc}"))];
        files.extend(layout.files(cwd, rc, env_value(env, prefixes, "userconfig")));
        files
    };
    for path in rc_files("yarnrc", &["yarn_"]) {
        let Some(text) = read(&path) else { continue };
        let Some(dir) = path.parent() else { continue };
        for key in [GLOBAL_FOLDER_KEY, "--global-folder"] {
            push(
                yarnrc_setting(&text, key).and_then(yarnrc_token),
                &|value| Some(dir.join(value)),
            );
        }
    }
    for path in rc_files("npmrc", &["yarn_", "npm_config_"]) {
        let Some(text) = read(&path) else { continue };
        push(
            npmrc_setting(&text, GLOBAL_FOLDER_KEY)
                .map(ini_value)
                .and_then(|value| yarn_env_replace(env, &value)),
            &with_home,
        );
    }
    out
}

/// The value token that starts `rest` (what follows a key in a `.yarnrc`
/// line), read like yarn's lockfile tokenizer: a double-quoted string is
/// JSON (escapes decoded), a bare word starts with a letter, `/`, `.` or
/// `-` and ends at a space, `:` or `,` (so a trailing `# comment` is not
/// part of it), and a run of digits is a number. A single-quoted string
/// is what yarn's YAML fallback reads in a `"key": '…'` line. Anything
/// else (`~/x`) is a token yarn can't read: `None`.
fn yarnrc_token(rest: &str) -> Option<String> {
    let rest = rest.trim_start_matches([' ', '\t']);
    if let Some(quoted) = rest.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = quoted.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\'' if chars.peek() == Some(&'\'') => {
                    chars.next();
                    out.push('\'');
                }
                '\'' => return Some(out),
                c => out.push(c),
            }
        }
        return None;
    }
    if rest.starts_with('"') {
        let bytes = rest.as_bytes();
        let mut end = rest.len();
        for i in 1..bytes.len() {
            let escaped = bytes[i - 1] == b'\\' && (i < 2 || bytes[i - 2] != b'\\');
            if bytes[i] == b'"' && !escaped {
                end = i + 1;
                break;
            }
        }
        return serde_json::from_str(&rest[..end]).ok();
    }
    let first = rest.chars().next()?;
    let word = if first.is_ascii_digit() {
        rest.split(|c: char| !c.is_ascii_digit()).next()
    } else if first.is_ascii_alphabetic() || matches!(first, '/' | '.' | '-') {
        rest.split([':', ' ', ',', '\r', '\n']).next()
    } else {
        None
    };
    word.map(str::to_string)
}

/// An `.npmrc` value as the `ini` parser yarn 1 bundles decodes it: a
/// quoted value loses its quotes (a double-quoted one is JSON), and an
/// unquoted one ends at an unescaped `;` or `#` (an inline comment),
/// with `\\`, `\;` and `\#` read as the escaped character.
fn ini_value(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        if let Ok(value) = serde_json::from_str::<String>(raw) {
            return value;
        }
    }
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return raw[1..raw.len() - 1].to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut escaped = false;
    for c in raw.chars() {
        if escaped {
            if !matches!(c, '\\' | ';' | '#') {
                out.push('\\');
            }
            out.push(c);
            escaped = false;
        } else if matches!(c, ';' | '#') {
            break;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    if escaped {
        out.push('\\');
    }
    out.trim().to_string()
}

/// yarn 1's `envReplace` over an `.npmrc` value: `${NAME}` becomes the
/// variable (`HOME` is the user's home), and an odd run of backslashes
/// before it keeps the whole expression verbatim, while an even run is
/// replaced with it. An unset variable makes yarn fail to load its
/// config: `None`.
fn yarn_env_replace(env: &NpmConfigEnv, value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let Some(len) = rest[start + 2..].find('}') else {
            break;
        };
        let name = &rest[start + 2..start + 2 + len];
        let before = &rest[..start];
        let slashes = before.len() - before.trim_end_matches('\\').len();
        let expr_end = start + 2 + len + 1;
        if name.is_empty() || slashes % 2 == 1 {
            out.push_str(&rest[..expr_end]);
        } else {
            out.push_str(&before[..before.len() - slashes]);
            let home = env.home.as_ref().and_then(|h| h.to_str());
            out.push_str(match name {
                "HOME" => home?,
                _ => env.var_raw(name)?,
            });
        }
        rest = &rest[expr_end..];
    }
    out.push_str(rest);
    Some(out)
}

/// [`configured_yarn_global_folders`] for this process, run in its cwd,
/// reading regular files only.
pub fn configured_yarn_global_folders_for_process() -> Vec<PathBuf> {
    let Ok(cwd) = std::env::current_dir() else {
        return Vec::new();
    };
    configured_yarn_global_folders(
        &NpmConfigEnv::from_process(),
        process_is_root_user(),
        &cwd,
        |path| crate::utils::fs::read_regular_to_string_sync(path).ok(),
    )
}

/// The global folder yarn 1.0.x uses by default, which it can't report:
/// `yarn global dir` only exists from yarn 1.1.0 (#437). This is yarn
/// 1.0.2's `GLOBAL_MODULE_DIRECTORY`, `<CONFIG_DIRECTORY>/global`, where
/// the config directory is `%LOCALAPPDATA%\Yarn\config` on Windows (when
/// `LOCALAPPDATA` is set) and `<userHome>/.config/yarn` otherwise.
pub fn yarn_1_0_default_global_folder(env: &NpmConfigEnv, root_user: bool) -> Option<PathBuf> {
    if env.windows {
        if let Some(local) = env.var("LOCALAPPDATA") {
            return Some(Path::new(local).join("Yarn").join("config").join("global"));
        }
    }
    let user_home = RcLayout::new(env, root_user).user_home?;
    Some(user_home.join(".config").join("yarn").join("global"))
}

/// [`yarn_1_0_default_global_folder`] for this process.
pub fn yarn_1_0_default_global_folder_for_process() -> Option<PathBuf> {
    yarn_1_0_default_global_folder(&NpmConfigEnv::from_process(), process_is_root_user())
}

/// Whether this process runs as uid 0 (yarn's `getuid() === 0`).
pub fn process_is_root_user() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The mirror yarn 1 uses when it runs in one of the workspace `members`
/// of `root` (absolute member directories), if any (#1115). Yarn 1 builds
/// its config from the directory it runs in, so a member run reads the
/// member's `.yarnrc` / `.npmrc` as the project files and the root's only
/// as an ancestor's; the lock is still the root's. The first member (in
/// the given order) whose effective mirror is set wins, its origin spelled
/// as the full path of the file that set it.
pub fn resolve_member_yarn_mirror(
    env: &NpmConfigEnv,
    root_user: bool,
    members: &[PathBuf],
    read: impl Fn(&Path) -> Option<String>,
) -> Option<MirrorSetting> {
    members.iter().find_map(|member| {
        let outer = resolve_outer_yarn_mirror(env, root_user, member, &read);
        let yarnrc = read(&member.join(super::YARNRC_REL));
        let npmrc = read(&member.join(super::npmrc::NPMRC_REL));
        let mut setting = effective_mirror(yarnrc.as_deref(), npmrc.as_deref(), &outer)?;
        let origin =
            if setting.origin == super::YARNRC_REL || setting.origin == super::npmrc::NPMRC_REL {
                member.join(&setting.origin).display().to_string()
            } else {
                setting.origin
            };
        setting.origin = format!(
            "{origin}, as read by yarn run in the workspace member {}",
            member.display()
        );
        Some(setting)
    })
}

/// The workspace members yarn 1 installs for a classic `yarn.lock` at
/// `root`: the directories below it that hold a `package.json` and match
/// the root `package.json`'s `workspaces` in yarn classic's reading,
/// sorted. Empty when the root has no classic `yarn.lock` or declares no
/// workspaces. The search follows directory links like yarn's globber,
/// never enters `node_modules` or `.git`, stops at the deepest pattern's
/// depth ([`MEMBER_SEARCH_DEPTH`] for `**`, which also bounds a link
/// cycle), and gives up after [`MEMBER_SEARCH_DIR_BUDGET`] directories,
/// keeping the members found so far.
pub fn yarn_classic_workspace_members(root: &Path) -> Vec<PathBuf> {
    use crate::utils::fs::read_regular_to_string_sync;
    use crate::utils::workspace_globs::{workspaces_include_as, WorkspacesDialect};

    let classic = read_regular_to_string_sync(&root.join("yarn.lock"))
        .is_ok_and(|lock| !super::is_berry_lock(&lock));
    if !classic {
        return Vec::new();
    }
    let Some(patterns) = read_regular_to_string_sync(&root.join("package.json"))
        .ok()
        .and_then(|text| crate::hosted::governing_root::workspace_patterns(&text))
        .filter(|patterns| !patterns.is_empty())
    else {
        return Vec::new();
    };
    let depth = patterns
        .iter()
        .map(|p| {
            if p.contains("**") {
                MEMBER_SEARCH_DEPTH
            } else {
                p.trim_start_matches('!')
                    .split('/')
                    .filter(|c| !c.is_empty() && *c != ".")
                    .count()
            }
        })
        .max()
        .unwrap_or(0);
    let mut members = Vec::new();
    let mut budget = MEMBER_SEARCH_DIR_BUDGET;
    let mut stack = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((dir, rel)) = stack.pop() {
        if !rel.is_empty()
            && dir.join("package.json").is_file()
            && workspaces_include_as(&patterns, &rel, WorkspacesDialect::YARN_CLASSIC)
        {
            members.push(dir.clone());
        }
        if rel.len() >= depth {
            continue;
        }
        let Some(left) = budget.checked_sub(1) else {
            break;
        };
        budget = left;
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if name == "node_modules" || name == ".git" || !path.is_dir() {
                continue;
            }
            let mut child = rel.clone();
            child.push(name);
            stack.push((path, child));
        }
    }
    members.sort();
    members
}

/// How deep [`yarn_classic_workspace_members`] searches for a `**`
/// pattern's members.
pub const MEMBER_SEARCH_DEPTH: usize = 32;

/// How many directories [`yarn_classic_workspace_members`] lists before it
/// stops searching.
pub const MEMBER_SEARCH_DIR_BUDGET: usize = 20_000;

/// [`resolve_outer_yarn_mirror`] for this process, reading regular files
/// only, with [`OuterYarnMirror::member`] from the project's yarn classic
/// workspace members. A relative `project` is taken against the process
/// cwd, as yarn run there would (its ancestors must be walkable).
pub fn resolve_outer_yarn_mirror_for_process(project: &Path) -> OuterYarnMirror {
    let project = std::path::absolute(project).unwrap_or_else(|_| project.to_path_buf());
    let env = NpmConfigEnv::from_process();
    let root_user = process_is_root_user();
    let read = |path: &Path| crate::utils::fs::read_regular_to_string_sync(path).ok();
    let mut outer = resolve_outer_yarn_mirror(&env, root_user, &project, read);
    outer.member = resolve_member_yarn_mirror(
        &env,
        root_user,
        &yarn_classic_workspace_members(&project),
        read,
    );
    outer
}

#[cfg(test)]
#[path = "yarnrc_tests.rs"]
mod tests;
