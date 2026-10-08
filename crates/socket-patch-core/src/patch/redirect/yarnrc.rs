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
        if key == KEY {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix(':').unwrap_or(rest);
            found = Some(mirror_value(rest));
        }
    }
    found
}

/// The last top-level `yarn-offline-mirror` value in an `.npmrc` (ini
/// `key = value` lines, `#`/`;` comments, `[section]` headers end the
/// top level).
pub fn npmrc_value(text: &str) -> Option<MirrorValue> {
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
        if unquote_rc_value(key) == KEY {
            found = Some(mirror_value(value));
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
    let files = |rc: &str, userconfig: Option<(String, String)>| -> Vec<PathBuf> {
        let local = format!(".{rc}");
        let mut out = Vec::new();
        match userconfig {
            Some((_, path)) if !path.is_empty() => out.push(project.join(path)),
            _ => out.extend(user_home.as_ref().map(|h| h.join(&local))),
        }
        out.extend(prefix.as_ref().map(|p| p.join("etc").join(rc)));
        if let (Some(home), Some(user_home)) = (&home, &user_home) {
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
    };
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
    }
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

/// [`resolve_outer_yarn_mirror`] for this process, reading regular files
/// only. A relative `project` is taken against the process cwd, as yarn
/// run there would (its ancestors must be walkable).
pub fn resolve_outer_yarn_mirror_for_process(project: &Path) -> OuterYarnMirror {
    let project = std::path::absolute(project).unwrap_or_else(|_| project.to_path_buf());
    resolve_outer_yarn_mirror(
        &NpmConfigEnv::from_process(),
        process_is_root_user(),
        &project,
        |path| crate::utils::fs::read_regular_to_string_sync(path).ok(),
    )
}

#[cfg(test)]
#[path = "yarnrc_tests.rs"]
mod tests;
