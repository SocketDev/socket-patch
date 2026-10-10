//! npm-family upstream restores: package-lock.json / npm-shrinkwrap.json,
//! yarn.lock (classic and berry), pnpm-lock.yaml, bun.lock — plus the
//! npm-family side settings a hosted run writes (`.npmrc`
//! `allow-remote=all`, pnpm-workspace.yaml `trustLockfile: true`).
//!
//! Every restorer rewrites ONLY entries whose resolution is a hosted URL
//! naming one of the in-scope patch uuids; every other byte of the file is
//! the file's own. The upstream values come from the npm registry's
//! version document (`dist.tarball`, `dist.integrity`, `dist.shasum`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::client::NpmDist;
use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::vendor::lock_inventory::{npm_lock_entries, NpmLockEntry};

/// Resolve the dist of every `(uuid, name, version)` wanted from the
/// default registry, concurrently. A failed lookup refuses its pin.
pub(super) async fn fetch_dists(
    wanted: &BTreeSet<(String, String, String)>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), NpmDist> {
    fetch_dists_on(wanted, |_| None::<String>, ctx, result)
        .await
        .into_iter()
        .map(|(key, found)| (key, found.dist))
        .collect()
}

/// A version's `dist`, and whether it is the document of the registry the
/// project resolves the package against (rather than the default one).
pub(super) struct ProjectDist {
    pub dist: NpmDist,
    pub from_project: bool,
}

/// Whether `base` is registry.npmjs.org or its registry.yarnpkg.com alias
/// (either scheme).
fn is_npmjs_registry(base: &str) -> bool {
    let base = base.trim().trim_end_matches('/');
    let host = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    matches!(host, "registry.npmjs.org" | "registry.yarnpkg.com")
}

/// The registry base a project names, unless it is the default registry
/// (npmjs, its registry.yarnpkg.com alias, or `SOCKET_NPM_REGISTRY`), whose
/// document [`fetch_dists`] already reads.
pub(super) fn non_default_registry(base: &str) -> Option<String> {
    use crate::vendor::registry_fetch::npm_registry_base;
    let base = base.trim().trim_end_matches('/');
    (!base.is_empty() && !is_npmjs_registry(base) && base != npm_registry_base())
        .then(|| base.to_string())
}

/// A registry a project resolves a package against, with the
/// `Authorization` header value its settings configure for it (a private
/// registry's token or basic credentials). Never `Debug`: it holds a secret.
#[derive(Clone)]
pub(super) struct ProjectRegistry {
    pub base: String,
    pub authorization: Option<String>,
}

impl From<String> for ProjectRegistry {
    fn from(base: String) -> Self {
        ProjectRegistry {
            base,
            authorization: None,
        }
    }
}

/// [`fetch_dists`], reading each version document from the registry the
/// project resolves `name` against (`registry(name)`; `None` means the
/// default registry), since a mirror's `dist.tarball` need not be the
/// default registry's (#521, #908), with the credentials the project
/// configures for it (#992). A registry with credentials is read even when
/// it is the default one (a private package on npmjs). When the project's
/// registry can't be read, the default registry's document is used, as
/// before, and `upstream_registry_fallback` says so.
pub(super) async fn fetch_dists_on<R: Into<ProjectRegistry>>(
    wanted: &BTreeSet<(String, String, String)>,
    registry: impl Fn(&str) -> Option<R>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), ProjectDist> {
    let lookups = wanted.iter().map(|(uuid, name, version)| {
        let project = registry(name)
            .map(Into::into)
            .and_then(|r: ProjectRegistry| {
                let base = non_default_registry(&r.base).or_else(|| {
                    r.authorization
                        .is_some()
                        .then(|| r.base.trim().trim_end_matches('/').to_string())
                })?;
                Some(ProjectRegistry {
                    base,
                    authorization: r.authorization,
                })
            });
        async move {
            let mut fell_back = None;
            let found = match project {
                Some(ProjectRegistry {
                    base,
                    authorization,
                }) => match ctx
                    .client
                    .npm_dist_authorized(&base, authorization.as_deref(), name, version)
                    .await
                {
                    Ok(dist) => Ok(ProjectDist {
                        dist,
                        from_project: true,
                    }),
                    Err(why) => {
                        fell_back = Some((base, why));
                        ctx.client
                            .npm_dist(name, version)
                            .await
                            .map(|dist| ProjectDist {
                                dist,
                                from_project: false,
                            })
                    }
                },
                None => ctx
                    .client
                    .npm_dist(name, version)
                    .await
                    .map(|dist| ProjectDist {
                        dist,
                        from_project: false,
                    }),
            };
            (
                uuid.clone(),
                name.clone(),
                version.clone(),
                found,
                fell_back,
            )
        }
    });
    let mut out = BTreeMap::new();
    for (uuid, name, version, found, fell_back) in futures_util::future::join_all(lookups).await {
        match found {
            Ok(found) => {
                if let Some((base, why)) = fell_back {
                    // The detail is printed and persisted in `--json`
                    // output (CI logs): never the URL's credentials.
                    let clean = crate::vex::product::strip_url_userinfo(&base);
                    let why = why.replace(base.trim_end_matches('/'), &clean);
                    let base = clean;
                    result.warnings.push((
                        "upstream_registry_fallback",
                        format!(
                            "{name}@{version}: the project's registry {base} could not be read \
                             ({why}), so the entry was restored from the default registry's \
                             version document; check its tarball URL against {base}"
                        ),
                    ));
                }
                out.insert((name, version), found);
            }
            Err(why) => result.refuse(&uuid, format!("{name}@{version}: {why}")),
        }
    }
    out
}

// ── package-lock.json / npm-shrinkwrap.json ─────────────────────────────────

/// One hosted entry of an npm lock: its JSON pointer, and what it stands for.
struct NpmHit {
    pointer: String,
    uuid: String,
    name: String,
    version: String,
}

/// Every hosted entry of an npm lock: the installed `packages` entries
/// (never the root or a workspace member) and every node of the legacy
/// `dependencies` tree, an alias node restoring its target's registry dist
/// (#432).
fn npm_lock_hits(lock: &Value, ctx: &Ctx<'_>) -> Vec<NpmHit> {
    npm_lock_entries(lock)
        .into_iter()
        .filter(NpmLockEntry::is_dependency)
        .filter_map(|entry| {
            let uuid = entry.node.resolved.and_then(|u| ctx.hosted_uuid(u))?;
            let version = entry.node.version?;
            Some(NpmHit {
                pointer: entry.pointer,
                uuid,
                name: entry.node.name.to_string(),
                version: version.to_string(),
            })
        })
        .collect()
}

pub(crate) async fn restore_npm_locks(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        // npm reads past a leading UTF-8 BOM; so do we.
        let Ok(mut lock) = crate::vendor::common::parse_json_text(&text) else {
            refuse_all_in(&pins, rel, &mut result, format!("{rel} is not valid JSON"));
            continue;
        };
        let hits: Vec<NpmHit> = npm_lock_hits(&lock, ctx)
            .into_iter()
            .filter(|h| pins.contains_key(h.uuid.as_str()))
            .collect();
        let wanted: BTreeSet<(String, String, String)> = hits
            .iter()
            .map(|h| (h.uuid.clone(), h.name.clone(), h.version.clone()))
            .collect();
        let dists = fetch_dists(&wanted, ctx, &mut result).await;
        let mut changed = false;
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            let Some(dist) = dists.get(&(hit.name.clone(), hit.version.clone())) else {
                continue;
            };
            let Some(integrity) = dist.integrity.as_deref() else {
                result.refuse(
                    &hit.uuid,
                    format!(
                        "the registry records no integrity for {}@{}",
                        hit.name, hit.version
                    ),
                );
                continue;
            };
            let Some(entry) = lock
                .pointer_mut(&hit.pointer)
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            entry.insert("resolved".into(), Value::String(dist.tarball.clone()));
            entry.insert("integrity".into(), Value::String(integrity.to_string()));
            result.handled.insert(hit.uuid.clone());
            changed = true;
        }
        if changed {
            // The lock's own BOM, indent and line endings (#324).
            view.write(rel, super::super::serialize_json_like(&lock, &text));
        }
    }
    result
}

// ── yarn.lock ────────────────────────────────────────────────────────────────

/// yarn v1's default registry host, used for a classic lock's `resolved`
/// unless `SOCKET_NPM_REGISTRY` names another.
const YARN_CLASSIC_REGISTRY: &str = "https://registry.yarnpkg.com";

fn yarn_classic_tarball(dist: &NpmDist) -> String {
    if std::env::var("SOCKET_NPM_REGISTRY").is_ok_and(|v| !v.trim().is_empty()) {
        return dist.tarball.clone();
    }
    match dist
        .tarball
        .strip_prefix(crate::vendor::registry_fetch::DEFAULT_NPM_REGISTRY)
    {
        Some(rest) => format!("{YARN_CLASSIC_REGISTRY}{rest}"),
        None => dist.tarball.clone(),
    }
}

pub(crate) async fn restore_yarn_locks(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(raw) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        if crate::formats::yarn::is_berry_lock(&raw) {
            restore_berry(view, rel, &raw, &pins, ctx, &mut result).await;
        } else {
            restore_classic(view, rel, &raw, &pins, ctx, &mut result).await;
        }
    }
    result
}

async fn restore_classic(
    view: &mut View<'_>,
    rel: &str,
    raw: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    use crate::formats::yarn::blocks::{
        block_eol, classic_field, classic_line_endings_supported, repin_classic_block,
        replace_block, scan_blocks,
    };
    use crate::formats::yarn::patterns::{classic_key_real_name, split_key_patterns};
    use crate::formats::yarn::source::{classic_copy_source, CopySource};

    // The same byte splice as the hosted rewriter (see
    // [`classic_line_endings_supported`]).
    if !classic_line_endings_supported(raw) {
        refuse_all_in(
            pins,
            rel,
            result,
            format!("{rel} holds bare carriage returns"),
        );
        return;
    }
    let blocks = scan_blocks(raw);

    // (block index, uuid, name, version) per hosted block.
    let mut hits: Vec<(usize, String, String, String)> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let Some((resolved, uuid)) =
            classic_field(&block.lines, "resolved").and_then(|r| Some((r, ctx.hosted_uuid(r)?)))
        else {
            continue;
        };
        if !pins.contains_key(uuid.as_str()) {
            continue;
        }
        let patterns = split_key_patterns(&block.key);
        // yarn 1 fetches a git pattern with git, from `resolved` (#363): a
        // registry tarball there fails every install just as the hosted one
        // does, and the block's own git source was never recorded.
        match classic_copy_source(&patterns, Some(resolved)) {
            CopySource::Git => {
                result.refuse(
                    &uuid,
                    format!(
                        "the {rel} entry wiring it installs from git; a registry tarball there \
                         would still be fetched with git"
                    ),
                );
                continue;
            }
            // A pin an older release wrote on a `file:` tarball, URL or
            // hosted-git copy (B16): its own `resolved` was never recorded,
            // and the registry tarball is not what that copy installed.
            CopySource::RemoteTarball => {
                result.refuse(
                    &uuid,
                    format!(
                        "the {rel} entry wiring it is keyed by a non-registry source (a file: \
                         tarball, URL or hosted-git dependency) whose original `resolved` was \
                         not recorded — restore {rel} from version control"
                    ),
                );
                continue;
            }
            _ => {}
        }
        let name = classic_key_real_name(&patterns);
        let version = classic_field(&block.lines, "version");
        match (name, version) {
            (Some(name), Some(version)) => {
                hits.push((i, uuid, name.to_string(), version.to_string()))
            }
            _ => result.refuse(
                &uuid,
                format!("a {rel} entry wiring it names no single package and version"),
            ),
        }
    }
    let wanted = hits
        .iter()
        .map(|(_, u, n, v)| (u.clone(), n.clone(), v.clone()))
        .collect();
    let dists = fetch_dists(&wanted, ctx, result).await;
    // (block index, restored lines), spliced last-to-first below so every
    // earlier block's byte span stays valid.
    let mut splices: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, uuid, name, version) in hits {
        if result.refused.contains_key(&uuid) {
            continue;
        }
        let Some(dist) = dists.get(&(name.clone(), version.clone())) else {
            continue;
        };
        let Some(integrity) = dist.integrity.as_deref() else {
            result.refuse(
                &uuid,
                format!("the registry records no integrity for {name}@{version}"),
            );
            continue;
        };
        let frag = dist
            .shasum
            .as_deref()
            .map(|s| format!("#{s}"))
            .unwrap_or_default();
        let resolved = format!("{}{frag}", yarn_classic_tarball(dist));
        splices.push((
            i,
            repin_classic_block(&blocks[i].lines, &resolved, integrity),
        ));
        result.handled.insert(uuid);
    }
    if splices.is_empty() {
        return;
    }
    let mut text = raw.to_string();
    for (i, lines) in splices.iter().rev() {
        let block = &blocks[*i];
        text = replace_block(&text, block, lines, block_eol(raw, block));
    }
    view.write(rel, text);
}

/// Whether a package manager derives `tarball` for `name@version` itself,
/// and so leaves it out of the lock: it is the conventional URL under the
/// registry the version document came from, or under the project's
/// configured registry (`project_registry`; npmjs when unset), which is
/// the one the package manager compares against.
fn registry_derives_tarball(
    project_registry: Option<&str>,
    name: &str,
    version: &str,
    tarball: &str,
) -> bool {
    use crate::vendor::registry_fetch::{
        npm_registry_base, npm_tarball_is_conventional, DEFAULT_NPM_REGISTRY,
    };
    [
        npm_registry_base().as_str(),
        project_registry.unwrap_or(DEFAULT_NPM_REGISTRY),
    ]
    .iter()
    .any(|base| npm_tarball_is_conventional(base, name, version, tarball))
}

/// The `npm:` locator yarn berry writes for `name@version` resolved from the
/// registry: bare when yarn derives `tarball` itself, else bound to it with
/// `::__archiveUrl=<encodeURIComponent>`.
fn berry_registry_locator(
    project_registry: Option<&str>,
    name: &str,
    version: &str,
    tarball: &str,
) -> String {
    if registry_derives_tarball(project_registry, name, version, tarball) {
        format!("{name}@npm:{version}")
    } else {
        format!(
            "{name}@npm:{version}::__archiveUrl={}",
            crate::utils::uri::encode_uri_component(tarball)
        )
    }
}

use crate::formats::pnpm::workspace::yaml_top_level_value;
use crate::formats::text::strip_bom;

/// The registry yarn berry resolves `name` against (`Ok(None)`: yarn's
/// default registry), read the way yarn merges its settings (#1017):
///
/// - a scoped `@scope/name` takes `npmScopes.<scope>.npmRegistryServer`
///   from the highest-precedence rc file that sets it;
/// - otherwise (and for a scope without its own server) the
///   `YARN_NPM_REGISTRY_SERVER` environment variable, then the
///   highest-precedence rc file's top-level `npmRegistryServer`.
///
/// `rcs` are the `.yarnrc.yml` texts yarn reads, highest precedence first
/// ([`BerryRegistrySettings::read`]): the lock directory's, each parent
/// directory's up to the filesystem root, then the home directory's. A
/// value's `${VAR}` / `${VAR:-default}` / `${VAR-default}` references are
/// expanded through `var` as yarn expands them. `Err` names why the
/// registry cannot be known: a reference to an unset variable with no
/// default (yarn refuses to run), or an `npmScopes` this reader cannot
/// follow (a flow mapping).
fn berry_lookup_registry(
    rcs: &[String],
    env_registry: Option<&str>,
    name: &str,
    var: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    if let Some((scope, _)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        let keys = [scope.to_string(), format!("@{scope}")];
        for rc in rcs {
            for key in &keys {
                if let Some(value) =
                    yaml_path_value(rc, &["npmScopes", key.as_str(), "npmRegistryServer"])?
                {
                    return yarn_expand_env(&value, var).map(Some);
                }
            }
        }
    }
    if let Some(env) = env_registry.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(Some(env.to_string()));
    }
    for rc in rcs {
        if let Some(value) = yaml_path_value(rc, &["npmRegistryServer"])? {
            return yarn_expand_env(&value, var).map(Some);
        }
    }
    Ok(None)
}

/// The scalar at `path` in a YAML settings file of block mappings (the
/// last occurrence of each key wins, quotes removed). `Ok(None)` when a
/// key on the path is absent or null; `Err` when a mapping on the path is
/// written in flow style, which this reader does not follow.
fn yaml_path_value(text: &str, path: &[&str]) -> Result<Option<String>, String> {
    // `top_level_key` skips the first line's BOM (one, as yarn's parser).
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect();
    yaml_path_in(&lines, path)
}

fn yaml_path_in(lines: &[String], path: &[&str]) -> Result<Option<String>, String> {
    use crate::formats::pnpm::workspace::top_level_key;
    let Some((key, rest)) = path.split_first() else {
        return Ok(None);
    };
    let Some((at, value)) = lines.iter().enumerate().rev().find_map(|(i, line)| {
        top_level_key(line)
            .filter(|(k, _)| k == key)
            .map(|(_, value)| (i, value.to_string()))
    }) else {
        return Ok(None);
    };
    if matches!(value.as_str(), "~" | "null") {
        return Ok(None);
    }
    if rest.is_empty() {
        let value = value.trim_matches(['"', '\'']).to_string();
        return Ok((!value.is_empty()).then_some(value));
    }
    if !value.is_empty() {
        return Err(format!(
            "`{}` is not written as a block mapping",
            path.first().copied().unwrap_or_default()
        ));
    }
    let end = lines[at + 1..]
        .iter()
        .position(|l| !l.is_empty() && !l.starts_with([' ', '\t', '#']))
        .map_or(lines.len(), |p| at + 1 + p);
    let children = &lines[at + 1..end];
    let Some(indent) = children.iter().find_map(|line| {
        let content = line.trim_start_matches(' ');
        (!content.trim().is_empty() && !content.starts_with('#'))
            .then(|| line.len() - content.len())
    }) else {
        return Ok(None);
    };
    let dedented: Vec<String> = children
        .iter()
        .map(|line| match line.get(indent..) {
            Some(rest) if line[..indent].trim().is_empty() => rest.to_string(),
            _ => String::new(),
        })
        .collect();
    yaml_path_in(&dedented, rest)
}

/// A `.yarnrc.yml` registry value with its environment references read as
/// yarn reads them: `${NAME}`, `${NAME-fallback}` (the fallback when `NAME`
/// is unset) and `${NAME:-fallback}` (also when it is empty). A reference
/// to an unset variable with no fallback is the error yarn stops on.
///
/// A reference to a variable that IS set is never expanded: the rc file
/// (possibly a checked-in, lower-trust one) would choose which of this
/// process's variables — a token, say — lands in a URL the restore
/// requests and may print. That is `Err` too, so the restore falls back to
/// the default registry with `upstream_registry_fallback`, as for the Bun
/// and pnpm settings, which never expand an arbitrary variable either.
fn yarn_expand_env(value: &str, var: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let body = &rest[at + 2..];
        let name_len = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        let name = &body[..name_len];
        let mut tail = &body[name_len..];
        let colon = tail.starts_with(':');
        if colon {
            tail = &tail[1..];
        }
        let fallback = match tail.strip_prefix('-') {
            Some(after) => match after.find('}') {
                Some(close) => {
                    tail = &after[close..];
                    Some(&after[..close])
                }
                None => None,
            },
            None => None,
        };
        let Some(after) = tail.strip_prefix('}').filter(|_| !name.is_empty()) else {
            // Not a reference yarn recognizes: kept literally.
            out.push_str("${");
            rest = body;
            continue;
        };
        let set = var(name);
        let expanded = match (set, fallback) {
            (Some(v), _) if !v.is_empty() => {
                return Err(format!(
                    "it references the environment variable {name}, which socket-patch does \
                     not expand into a registry URL"
                ))
            }
            (Some(v), _) if !colon => v,
            (_, Some(fallback)) => fallback.to_string(),
            (_, None) => return Err(format!("the environment variable {name} is not set")),
        };
        out.push_str(&expanded);
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

/// The yarn berry settings that decide which registry a package resolves
/// against: the `.yarnrc.yml` texts yarn reads for a lock, highest
/// precedence first, and `YARN_NPM_REGISTRY_SERVER`.
struct BerryRegistrySettings {
    rcs: Vec<String>,
    env_registry: Option<String>,
}

impl BerryRegistrySettings {
    /// Yarn reads the rc file (`YARN_RC_FILENAME`, default `.yarnrc.yml`)
    /// of the project directory and of every parent directory up to the
    /// filesystem root (a closer one wins), then the home directory's,
    /// below them all.
    async fn read(view: &View<'_>, dir_prefix: &str) -> Self {
        let rc_name = std::env::var("YARN_RC_FILENAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| ".yarnrc.yml".to_string());
        let root = view.root().join(dir_prefix);
        let root = tokio::fs::canonicalize(&root).await.unwrap_or(root);
        let mut read: Vec<std::path::PathBuf> =
            root.ancestors().map(|d| d.join(&rc_name)).collect();
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .filter(|h| !h.is_empty())
            .map(std::path::PathBuf::from);
        if let Some(home) = home {
            let home = tokio::fs::canonicalize(&home).await.unwrap_or(home);
            let rc = home.join(&rc_name);
            if !read.contains(&rc) {
                read.push(rc);
            }
        }
        let mut rcs = Vec::new();
        for path in read {
            if let Ok(text) = crate::utils::fs::read_regular_to_string(&path).await {
                rcs.push(text);
            }
        }
        BerryRegistrySettings {
            rcs,
            env_registry: std::env::var("YARN_NPM_REGISTRY_SERVER").ok(),
        }
    }

    fn registry(&self, name: &str) -> Result<Option<String>, String> {
        berry_lookup_registry(
            &self.rcs,
            self.env_registry.as_deref(),
            name,
            &|key: &str| std::env::var(key).ok(),
        )
    }
}

async fn restore_berry(
    view: &mut View<'_>,
    rel: &str,
    raw: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    use crate::formats::yarn::blocks::{berry_field, with_body_field};
    use crate::formats::yarn::patterns::{
        resolution_selector_target, split_berry_key_patterns, split_pattern,
    };
    use crate::formats::yarn::stanzas::{stanza_key, stanza_lines, BerryStanzas};

    let dir_prefix = match rel.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/"),
        None => String::new(),
    };
    let yarnrc_rel = format!("{dir_prefix}.yarnrc.yml");
    let yarnrc = view.read(&yarnrc_rel).await.ok().flatten();
    // The root manifest: a hosted pin keyed by its tarball URL keeps the
    // descriptors it replaced only as `resolutions` selectors routed there.
    // Read before the gates: a mixed one is refused like a mixed lock.
    let pkg_rel = format!("{dir_prefix}package.json");
    let pkg_text = view.read(&pkg_rel).await.ok().flatten();
    if let Err(w) =
        super::super::preflight_yarn_berry_hosted(raw, pkg_text.as_deref(), yarnrc.as_deref())
    {
        refuse_all_in(pins, rel, result, w.detail);
        return;
    }
    // The preflight refused a mixed lock, so the stanza view round-trips.
    let mut doc = BerryStanzas::parse(raw);
    let mut blocks = std::mem::take(&mut doc.stanzas);

    let mut pkg: Option<serde_json::Value> = pkg_text
        .as_deref()
        .and_then(|t| serde_json::from_str(strip_bom(t)).ok())
        .filter(serde_json::Value::is_object);
    let mut pkg_changed = false;

    // `(block index, uuid, name, version, restored key or None to keep it,
    // selectors to drop)`.
    struct Hit {
        idx: usize,
        uuid: String,
        name: String,
        version: String,
        key: Option<String>,
        selectors: Vec<String>,
        /// A tarball-URL pin, whose `bin:` the pin took from the served
        /// tarball's own manifest (#718), not the registry's.
        url_pin: bool,
    }
    let mut hits: Vec<Hit> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let lines = stanza_lines(block);
        let Some(resolution) = berry_field(&lines, "resolution").map(str::to_string) else {
            continue;
        };
        // The hosted pin is the tarball-URL locator `name@<url>`; locks
        // pinned by releases up to 5.0 spell it as an `npm:` locator's
        // percent-encoded `::__archiveUrl=` binding (#404).
        let Some((_, reference)) = split_pattern(&resolution) else {
            continue;
        };
        let url_pin = reference.starts_with("https://") || reference.starts_with("http://");
        let archive = if url_pin {
            reference
        } else if let Some((_, binding)) = reference.split_once("::__archiveUrl=") {
            binding.split('&').next().unwrap_or(binding)
        } else {
            continue;
        };
        let Some(uuid) = ctx.hosted_uuid(archive) else {
            continue;
        };
        if !pins.contains_key(uuid.as_str()) {
            continue;
        }
        let key = stanza_key(block).unwrap_or("");
        let patterns = split_berry_key_patterns(key);
        let names: BTreeSet<String> = patterns
            .iter()
            .filter_map(|p| split_pattern(p).map(|(n, _)| n.to_string()))
            .collect();
        let version = berry_field(&lines, "version").map(str::to_string);
        let (Some(name), Some(version), 1) = (names.iter().next(), version, names.len()) else {
            result.refuse(
                &uuid,
                format!("a {rel} entry wiring it names no single package and version"),
            );
            continue;
        };
        // An entry keyed by the tarball descriptor itself takes back the
        // descriptors its `resolutions` selectors route to that URL.
        let keyed_by_url = matches!(
            patterns.as_slice(),
            [only] if split_pattern(only).is_some_and(|(_, r)| r == reference)
        );
        let (restored_key, selectors) = if keyed_by_url {
            let selectors: Vec<String> = pkg
                .as_ref()
                .and_then(|p| p.get("resolutions"))
                .and_then(serde_json::Value::as_object)
                .map(|table| {
                    table
                        .iter()
                        .filter(|(sel, value)| {
                            resolution_selector_target(sel) == Some(name.as_str())
                                && value.as_str() == Some(reference)
                        })
                        .map(|(sel, _)| sel.clone())
                        .collect()
                })
                .unwrap_or_default();
            let mut descriptors: Vec<String> = selectors
                .iter()
                .filter(|sel| {
                    split_pattern(sel).is_some_and(|(n, r)| n == name && r.starts_with("npm:"))
                })
                .cloned()
                .collect();
            if descriptors.is_empty() {
                result.refuse(
                    &uuid,
                    format!(
                        "{pkg_rel} has no resolutions entry routing a {name} descriptor to the \
                         hosted tarball, so the {rel} entry's original key cannot be rebuilt — \
                         restore {rel} and {pkg_rel} from version control (or delete the entry \
                         and run `yarn install`)"
                    ),
                );
                continue;
            }
            descriptors.sort();
            descriptors.dedup();
            (Some(format!("\"{}\"", descriptors.join(", "))), selectors)
        } else {
            (None, Vec::new())
        };
        hits.push(Hit {
            idx: i,
            uuid,
            name: name.clone(),
            version,
            key: restored_key,
            selectors,
            url_pin,
        });
    }
    // The registry's `dist.tarball` decides the restored locator: yarn binds
    // a tarball URL off the conventional path as `::__archiveUrl=` (#817).
    let wanted = hits
        .iter()
        .map(|h| (h.uuid.clone(), h.name.clone(), h.version.clone()))
        .collect();
    // The registry yarn resolves each package against, read from every
    // settings source yarn merges (#1017); one it cannot be known for is
    // restored from the default registry's document, with a warning.
    let settings = BerryRegistrySettings::read(view, &dir_prefix).await;
    let mut registries: BTreeMap<String, Option<String>> = BTreeMap::new();
    for hit in &hits {
        if registries.contains_key(&hit.name) {
            continue;
        }
        let registry = settings.registry(&hit.name).unwrap_or_else(|why| {
            result.warnings.push((
                "upstream_registry_fallback",
                format!(
                    "{}@{}: the registry yarn resolves it against could not be determined \
                     ({why}), so the entry was restored from the default registry's version \
                     document; check its tarball URL against the project's registry",
                    hit.name, hit.version
                ),
            ));
            None
        });
        registries.insert(hit.name.clone(), registry);
    }
    let registry = |name: &str| registries.get(name).cloned().flatten();
    let dists = fetch_dists_on(&wanted, registry, ctx, result).await;
    let mut changed = false;
    let mut moved: Vec<String> = Vec::new();
    for Hit {
        idx,
        uuid,
        name,
        version,
        key,
        selectors,
        url_pin,
    } in hits
    {
        if result.refused.contains_key(&uuid) {
            continue;
        }
        let checksum = match ctx
            .client
            .npm_berry_checksum(
                &uuid,
                &name,
                &version,
                ctx.origins
                    .first()
                    .map(String::as_str)
                    .unwrap_or("https://patch.socket.dev"),
            )
            .await
        {
            Ok(c) => crate::vendor::yarn_berry_lock::checksum_in_lock_spelling(&doc.lf, &c),
            Err(why) => {
                result.refuse(&uuid, format!("{name}@{version}: {why}"));
                continue;
            }
        };
        let Some(dist) = dists.get(&(name.clone(), version.clone())).map(|d| &d.dist) else {
            continue;
        };
        let locator = berry_registry_locator(
            registries.get(&name).and_then(Option::as_deref),
            &name,
            &version,
            &dist.tarball,
        );
        let resolution = format!("  resolution: \"{locator}\"");
        let mut lines = stanza_lines(&blocks[idx]);
        if let Some(pinned) = with_body_field(&lines, "resolution", &resolution) {
            lines = pinned;
        }
        if let Some(pinned) =
            with_body_field(&lines, "checksum", &format!("  checksum: {checksum}"))
        {
            lines = pinned;
        }
        if let Some(key) = key {
            lines[0] = format!("{key}:");
            moved.push(key);
        }
        // The tarball-URL pin wrote the served tarball's `bin:` (#718);
        // yarn writes the version document's for the `npm:` entry (#1131).
        // Only `bin` comes from the version document here: the manifest
        // declares `node-gyp` so `render_pinned_entry` keeps the entry's
        // dependencies as they are, and the re-add below decides the
        // implicit one (#737).
        if url_pin {
            use crate::formats::yarn::berry_entry::{render_pinned_entry, Pin};
            lines = render_pinned_entry(
                &lines[1..],
                &Pin {
                    key_line: &lines[0],
                    resolution: &locator,
                    checksum: None,
                    manifest: Some(&serde_json::json!({
                        "bin": &dist.bin,
                        "dependencies": { "node-gyp": "" },
                    })),
                },
            );
        }
        // The npm resolver's implicit `node-gyp` dependency, which the pin
        // dropped (#737), comes back while the lock still holds the entry
        // it resolves to; without it only `yarn install` can re-resolve
        // that subtree.
        if dist.node_gyp && !crate::formats::yarn::berry_entry::has_implicit_node_gyp(&lines) {
            let resolvable = blocks.iter().any(|b| {
                stanza_key(b).is_some_and(|k| {
                    split_berry_key_patterns(k)
                        .iter()
                        .any(|p| p == "node-gyp@npm:latest")
                })
            });
            if resolvable {
                lines = crate::formats::yarn::berry_entry::with_implicit_node_gyp(&lines);
            } else {
                result.warnings.push((
                    "yarn_berry_node_gyp_unresolved",
                    format!(
                        "{name}@{version}: yarn gives the restored registry entry an \
                         implicit `node-gyp` dependency that {rel} no longer resolves; run \
                         `yarn install` once to add it back (until then a hardened or \
                         `--refresh-lockfile` install reports the lockfile as modified)"
                    ),
                ));
            }
        }
        blocks[idx] = lines.join("\n");
        if !selectors.is_empty() {
            if let Some(table) = pkg
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
                .and_then(|obj| obj.get_mut("resolutions"))
                .and_then(serde_json::Value::as_object_mut)
            {
                for selector in &selectors {
                    table.shift_remove(selector);
                }
                pkg_changed = true;
            }
        }
        result.handled.insert(uuid);
        changed = true;
    }
    if !changed {
        return;
    }
    if pkg_changed {
        if let (Some(text), Some(value)) = (pkg_text.as_deref(), pkg.as_mut()) {
            if let Some(obj) = value.as_object_mut() {
                if obj
                    .get("resolutions")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
                {
                    obj.shift_remove("resolutions");
                }
            }
            match crate::vendor::common::JsonLayout::of(text)
                .render(value)
                .map(String::from_utf8)
            {
                Ok(Ok(rendered)) => view.write(&pkg_rel, rendered),
                _ => {
                    for uuid in pins.keys() {
                        result.refuse(uuid, format!("{pkg_rel} could not be re-serialized"));
                    }
                    return;
                }
            }
        }
    }
    doc.stanzas = blocks;
    view.write(rel, doc.render(&moved));
}

/// Retire the leftover hosted `resolutions` selectors of a yarn berry root
/// `package.json` (#1203): `yarn remove` / `yarn up` deleted the lock entry
/// a hosted pin keyed by its tarball URL but left its selector, which now
/// routes nothing. Each in-scope pin's selectors are re-checked against
/// the sibling `yarn.lock` as the view holds it (the berry restore may
/// have run first) and dropped with a `hosted_resolution_orphaned`
/// warning; the lock itself is not touched. A pin with no such selector
/// left is not handled here, so it is refused like any unrestorable pin.
pub(crate) async fn retire_stale_selectors(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::vendor::lock_inventory::yarn::{berry_entries, berry_selector_routes_nothing};

    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let dir_prefix = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => String::new(),
        };
        let lock_rel = format!("{dir_prefix}yarn.lock");
        let lock = match view.read(&lock_rel).await {
            Ok(Some(lock)) if crate::formats::yarn::is_berry_lock(strip_bom(&lock)) => {
                berry_entries(strip_bom(&lock))
            }
            _ => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} routes a hosted patch but {lock_rel} is not a yarn berry lock"),
                );
                continue;
            }
        };
        let Some(mut pkg) = serde_json::from_str::<Value>(strip_bom(&text))
            .ok()
            .filter(Value::is_object)
        else {
            refuse_all_in(
                &pins,
                rel,
                &mut result,
                format!("{rel} is not a JSON object"),
            );
            continue;
        };
        let Some(table) = pkg.get_mut("resolutions").and_then(Value::as_object_mut) else {
            continue;
        };
        let stale: Vec<(String, String, String)> = table
            .iter()
            .filter_map(|(selector, value)| {
                let url = value.as_str()?;
                let uuid = ctx.hosted_uuid(url)?;
                (pins.contains_key(uuid.as_str())
                    && berry_selector_routes_nothing(&lock, selector, url))
                .then(|| (selector.clone(), url.to_string(), uuid))
            })
            .collect();
        if stale.is_empty() {
            continue;
        }
        for (selector, _, _) in &stale {
            table.shift_remove(selector);
        }
        if table.is_empty() {
            if let Some(obj) = pkg.as_object_mut() {
                obj.shift_remove("resolutions");
            }
        }
        match crate::vendor::common::JsonLayout::of(&text)
            .render(&pkg)
            .map(String::from_utf8)
        {
            Ok(Ok(rendered)) => view.write(rel, rendered),
            _ => {
                refuse_all_in(
                    &pins,
                    rel,
                    &mut result,
                    format!("{rel} could not be re-serialized"),
                );
                continue;
            }
        }
        // The detail names the selector, never its URL (which carries the
        // grant token).
        for (selector, _url, uuid) in stale {
            result.warnings.push((
                "hosted_resolution_orphaned",
                format!(
                    "{rel}: removed the hosted `resolutions` entry `{selector}`; no \
                     {lock_rel} entry installs it any more (the package was removed or moved \
                     to another version), so it was leftover wiring"
                ),
            ));
            result.handled.insert(uuid);
        }
    }
    result
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────

/// What decides whether pnpm records a resolution's `tarball:` in the lock
/// at `rel`, read from its sibling settings files.
struct PnpmTarballPolicy {
    /// pnpm's `lockfileIncludeTarballUrl` was in effect when it wrote the
    /// lock, so every resolution carries its tarball
    /// (see [`pnpm_include_tarball`]).
    always: bool,
    /// `always` rests on the tier-3 guess that another pnpm major would
    /// read the other way (see [`PnpmIncludeTarball::guess`]).
    guess: Option<PnpmTarballGuess>,
    /// The lock is a Rush lock (`rush.json` at the Rush root): its pnpm is
    /// rush.json's `pnpmVersion`, not a sibling package.json pin.
    rush: bool,
    /// The sibling pnpm-workspace.yaml and `.npmrc`, and the pnpm major
    /// that reads them ([`pnpm_settings_major`]), which name the registry
    /// pnpm resolves a package against (see [`pnpm_lookup_registry`]).
    workspace: Option<String>,
    npmrc: Option<String>,
    major: Option<u32>,
    /// The `dir/` prefix those settings were read from
    /// ([`pnpm_settings_prefix`]), for the guess warning.
    settings_prefix: String,
}

impl PnpmTarballPolicy {
    fn registry(&self, name: &str) -> Option<String> {
        pnpm_lookup_registry(
            self.workspace.as_deref(),
            self.npmrc.as_deref(),
            self.major,
            name,
        )
    }
}

/// The pnpm major whose settings reading applies to the lock `text`: the
/// installed / pinned `pm_major`, else 8 for a pre-9 lock or a shrinkwrap
/// (only pnpm <= 8 writes those), else 11 for a lock carrying pnpm 11+'s
/// env lockfile document ahead of the project lock (only pnpm >= 11
/// writes one, so its `.npmrc` pnpm settings are ignored).
fn pnpm_settings_major(text: &str, pm_major: Option<u32>) -> Option<u32> {
    use crate::formats::pnpm::grammar::{is_pnpm_lock_text, main_document};
    use crate::formats::pnpm::lock_version_major;

    let legacy_lock = lock_version_major(text).is_some_and(|major| major < 9)
        || text
            .lines()
            .any(|line| line.starts_with("shrinkwrapVersion:"));
    let main = main_document(text);
    let env_document = is_pnpm_lock_text(&text[..text.len() - main.len()]);
    pm_major
        .or(legacy_lock.then_some(8))
        .or(env_document.then_some(11))
}

/// The value of `key` in the top-level block mapping `section` of the YAML
/// `text` (its direct children only, the last one winning, quotes
/// removed); `None` when absent, empty or flow-styled.
fn yaml_block_value(text: &str, section: &str, key: &str) -> Option<String> {
    use crate::formats::pnpm::workspace::{block_section_bounds, top_level_key};

    let lines: Vec<String> = crate::formats::text::strip_bom(text)
        .lines()
        .map(str::to_string)
        .collect();
    let (start, end) = block_section_bounds(&lines, section)?;
    let children = &lines[start + 1..end];
    let indent = children.iter().find_map(|line| {
        let rest = line.trim_start_matches(' ');
        (!rest.trim().is_empty() && !rest.starts_with('#')).then(|| line.len() - rest.len())
    })?;
    children
        .iter()
        .filter_map(|line| {
            line.get(indent..)
                .filter(|_| line[..indent].trim().is_empty())
        })
        .filter_map(top_level_key)
        .rfind(|(k, _)| k == key)
        .map(|(_, value)| value.trim_matches(['"', '\'']).to_string())
        .filter(|value| !value.is_empty())
}

/// The registry pnpm resolves `name` against (`None`: the default
/// registry). pnpm both reads the version document from it and derives
/// conventional tarball URLs under it (#919). Which settings file names it
/// follows the pnpm `major` ([`pnpm_settings_major`]):
///
/// - pnpm <= 9: the lock's sibling `.npmrc`, `@scope:registry` for a
///   scoped name when set, else `registry`;
/// - pnpm 10: pnpm-workspace.yaml's `registries` map when present (it
///   replaces `.npmrc`'s registries wholesale: the scope's key, else
///   `default`), else `.npmrc`; a workspace `registry:` is ignored;
/// - pnpm 11+ (and an unknown major, since a workspace `registry:` only
///   takes effect there): the two merged, the workspace file winning per
///   key: `registries."@scope"`, `.npmrc` `@scope:registry`, then
///   `registry:`, `registries.default`, `.npmrc` `registry`.
///
/// (Measured with pnpm 9.15, 10.34 and 11.27.) A value still holding a
/// `${VAR}` reference is read as unset: the restore does not expand the
/// user's environment, and must not fetch it as a URL.
fn pnpm_lookup_registry(
    workspace: Option<&str>,
    npmrc: Option<&str>,
    major: Option<u32>,
    name: &str,
) -> Option<String> {
    use super::super::npmrc::npmrc_top_level_value;
    use crate::formats::pnpm::workspace::top_level_key;

    let workspace = workspace.filter(|_| major.is_none_or(|major| major > 9));
    let scope = name
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map(|(scope, _)| format!("@{scope}"));
    let rc = |key: &str| {
        npmrc
            .and_then(|text| npmrc_top_level_value(text, key))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let registries =
        |key: &str| workspace.and_then(|text| yaml_block_value(text, "registries", key));
    let from_npmrc = || {
        scope
            .as_ref()
            .and_then(|scope| rc(&format!("{scope}:registry")))
            .or_else(|| rc("registry"))
    };
    let value = if major == Some(10) {
        let has_registries = workspace.is_some_and(|text| {
            crate::formats::text::strip_bom(text)
                .lines()
                .filter_map(top_level_key)
                .any(|(key, _)| key == "registries")
        });
        if has_registries {
            scope
                .as_deref()
                .and_then(registries)
                .or_else(|| registries("default"))
        } else {
            from_npmrc()
        }
    } else {
        scope
            .as_ref()
            .and_then(|scope| registries(scope).or_else(|| rc(&format!("{scope}:registry"))))
            .or_else(|| workspace.and_then(|text| yaml_top_level_value(text, "registry")))
            .or_else(|| registries("default"))
            .or_else(|| rc("registry"))
    };
    value.filter(|value| !value.contains("${"))
}

/// What [`pnpm_include_tarball`] concluded about the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PnpmIncludeTarball {
    /// pnpm wrote the lock under `lockfileIncludeTarballUrl`.
    on: bool,
    /// `on` came from the tier-3 fallback (no lock evidence, no known pnpm
    /// major) and pnpm 9 or pnpm >= 11, which also write a 9.0 lock, would
    /// read the two settings files the other way.
    guess: Option<PnpmTarballGuess>,
}

/// The settings a tier-3 guess read (`None`: unset; anything but `true`
/// reads as off): pnpm 10 follows the workspace file, else `.npmrc`; pnpm 9
/// reads only `.npmrc`, pnpm >= 11 only the workspace file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PnpmTarballGuess {
    workspace: Option<bool>,
    npmrc: Option<bool>,
}

impl PnpmTarballGuess {
    /// pnpm 10's reading, which the restore follows.
    fn on(self) -> bool {
        self.workspace.or(self.npmrc).unwrap_or(false)
    }

    /// pnpm 9's reading (`.npmrc` only).
    fn pnpm9(self) -> bool {
        self.npmrc.unwrap_or(false)
    }

    /// pnpm >= 11's reading (pnpm-workspace.yaml only).
    fn pnpm11(self) -> bool {
        self.workspace.unwrap_or(false)
    }
}

/// Whether pnpm wrote the lock `text` under `lockfileIncludeTarballUrl`
/// (#902). The setting lives in pnpm-workspace.yaml or `.npmrc`, but which
/// of those pnpm reads depends on its major: pnpm <= 9 ignores workspace
/// settings, pnpm 11+ ignores pnpm settings in `.npmrc`, and pnpm 10 reads
/// both (the workspace file wins). Strongest signal first:
///
/// 1. the lock's own unpinned registry resolutions ([`pnpm_lock_tarball_evidence`]);
/// 2. the settings file the installed pnpm major (`pm_major`, or a pre-9
///    lock / shrinkwrap, which only pnpm <= 8 writes) reads;
/// 3. with neither, pnpm 10's reading (workspace file, else `.npmrc`).
///    That covers a lock with no sibling install record (a fresh clone, a
///    Rush lock whose node_modules lives in common/temp) and only pinned
///    entries; a global `~/.npmrc` or `npm_config_*` setting is only
///    visible through tier 1. A 9.0 lock may come from pnpm 9, 10 or 11+,
///    so when pnpm 9's reading (`.npmrc` only) or pnpm 11+'s (the
///    workspace file only) differs from pnpm 10's, the result says so
///    ([`PnpmIncludeTarball::guess`]) so the restore can warn.
fn pnpm_include_tarball(
    text: &str,
    workspace: Option<&str>,
    npmrc: Option<&str>,
    pm_major: Option<u32>,
    is_hosted: impl Fn(&str) -> bool,
) -> PnpmIncludeTarball {
    use super::super::npmrc::npmrc_top_level_value;

    let major = pnpm_settings_major(text, pm_major);
    let registry = |name: &str| pnpm_lookup_registry(workspace, npmrc, major, name);
    if let Some(on) = pnpm_lock_tarball_evidence(text, registry, is_hosted) {
        return PnpmIncludeTarball { on, guess: None };
    }
    // js-yaml reads `True` / `TRUE` as true too; `.npmrc` (ini + nopt)
    // only a lowercase `true`.
    let from_workspace = || {
        workspace
            .and_then(|text| yaml_top_level_value(text, "lockfileIncludeTarballUrl"))
            .map(|value| value.trim().eq_ignore_ascii_case("true"))
    };
    let from_npmrc = || {
        npmrc
            .and_then(|text| npmrc_top_level_value(text, "lockfile-include-tarball-url"))
            .map(|value| value.trim() == "true")
    };
    let value = match major {
        Some(major) if major <= 9 => from_npmrc(),
        Some(major) if major >= 11 => from_workspace(),
        Some(_) => from_workspace().or_else(from_npmrc),
        // Tier 3: pnpm 10's reading, flagged when another major differs.
        None => {
            let guess = PnpmTarballGuess {
                workspace: from_workspace(),
                npmrc: from_npmrc(),
            };
            let on = guess.on();
            let differs = guess.pnpm9() != on || guess.pnpm11() != on;
            return PnpmIncludeTarball {
                on,
                guess: differs.then_some(guess),
            };
        }
    };
    PnpmIncludeTarball {
        on: value.unwrap_or(false),
        guess: None,
    }
}

/// What the lock's unpinned registry resolutions (integrity, a registry
/// key, no `type` / `directory` / `commit` / `repo`, a non-hosted and
/// non-`file:` tarball if any) say about `lockfileIncludeTarballUrl`.
/// With it on, pnpm records `tarball:` on every one of them, so a single
/// bare one proves it off, whatever else the lock holds (a conventional
/// URL can still appear with it off, under a second registry). With no
/// bare one, a tarball pnpm could have derived proves it on. `None`: no
/// such resolution (an unconventional URL is recorded either way). Only
/// the main document counts: pnpm 11+'s env lockfile document records its
/// resolutions bare whatever the setting.
fn pnpm_lock_tarball_evidence(
    text: &str,
    registry: impl Fn(&str) -> Option<String>,
    is_hosted: impl Fn(&str) -> bool,
) -> Option<bool> {
    use crate::formats::pnpm::{classify_pnpm_key, grammar::main_document, pnpm_packages, PnpmKey};

    let mut derived = false;
    for package in pnpm_packages(main_document(text)) {
        let PnpmKey::Registry { name, version } = classify_pnpm_key(package.key) else {
            continue;
        };
        let Some(resolution) = package.resolution.as_ref() else {
            continue;
        };
        if resolution.integrity().is_none()
            || resolution
                .fields
                .iter()
                .any(|(k, _)| matches!(*k, "type" | "directory" | "commit" | "repo"))
        {
            continue;
        }
        match resolution.tarball() {
            None => return Some(false),
            Some(tarball) if tarball.starts_with("file:") || is_hosted(tarball) => {}
            Some(tarball) => {
                derived |=
                    registry_derives_tarball(registry(name).as_deref(), name, version, tarball);
            }
        }
    }
    derived.then_some(true)
}

/// The major of a `pnpm@<version>` package-manager spec (`.modules.yaml`'s
/// `packageManager`, package.json's corepack pin, `+sha…` suffix allowed).
fn pnpm_spec_major(spec: &str) -> Option<u32> {
    let version = spec
        .trim()
        .trim_matches(['"', '\''])
        .strip_prefix("pnpm@")?;
    let major = version.split(['.', '+', '-']).next()?;
    major.parse().ok()
}

/// The pnpm major an install record names: `node_modules/.modules.yaml`'s
/// `packageManager` (JSON on pnpm 10+, a top-level YAML scalar before).
fn modules_yaml_pnpm_major(text: &str) -> Option<u32> {
    let text = crate::formats::text::strip_bom(text);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return value
            .get("packageManager")
            .and_then(|v| v.as_str())
            .and_then(pnpm_spec_major);
    }
    yaml_top_level_value(text, "packageManager")
        .as_deref()
        .and_then(pnpm_spec_major)
}

/// The pnpm major package.json's corepack `packageManager` pins.
fn package_json_pnpm_major(text: &str) -> Option<u32> {
    serde_json::from_str::<serde_json::Value>(crate::formats::text::strip_bom(text))
        .ok()?
        .get("packageManager")?
        .as_str()
        .and_then(pnpm_spec_major)
}

/// The Rush root (`""` or a `dir/` prefix) of a Rush lock path: the common
/// lock `common/config/rush/pnpm-lock.yaml` or a subspace's
/// `common/config/subspaces/<name>/pnpm-lock.yaml`. Whether it is one is
/// settled by a `rush.json` at that root.
fn rush_lock_root(rel: &str) -> Option<&str> {
    use crate::constants::npm_family::{RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};

    let root = match rel.strip_suffix(RUSH_COMMON_LOCK_REL) {
        Some(root) => root,
        None => {
            let (dir, name) = rel.strip_suffix("/pnpm-lock.yaml")?.rsplit_once('/')?;
            if name.is_empty() {
                return None;
            }
            dir.strip_suffix(RUSH_SUBSPACES_DIR)?
        }
    };
    (root.is_empty() || root.ends_with('/')).then_some(root)
}

/// The pnpm major rush.json's `pnpmVersion` names (rush.json is JSONC).
fn rush_json_pnpm_major(text: &str) -> Option<u32> {
    let text = crate::vendor::bun_lock_text::strip_jsonc(crate::formats::text::strip_bom(text));
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()?
        .get("pnpmVersion")?
        .as_str()?
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// The text of `name` next to the lock (`dir_prefix`); `None` when absent
/// or unreadable.
async fn read_sibling(view: &mut View<'_>, dir_prefix: &str, name: &str) -> Option<String> {
    view.read(&format!("{dir_prefix}{name}"))
        .await
        .ok()
        .flatten()
}

/// The directory (as a `dir/` prefix, `""` for the project root) whose
/// pnpm-workspace.yaml, `.npmrc` and `package.json` pnpm reads for the lock
/// `rel`: the lock's own directory, except for a workspace member lock
/// (`sharedWorkspaceLockfile: false`). pnpm reads a member's settings only
/// from its workspace root: the nearest ancestor with a
/// pnpm-workspace.yaml whose `packages:` lists the member's directory
/// ([`lists_as_member`]), when the member has no such file of its own.
/// That root may sit above the project root (a rollback run from the
/// member itself, its lock `pnpm-lock.yaml`): it is then found on disk
/// ([`governing_workspace_file`]) and returned as an absolute directory
/// prefix. A Rush lock (see [`rush_lock_root`], settled by its
/// `rush.json`) keeps its own directory.
///
/// [`lists_as_member`]: crate::utils::pnpm_workspace::lists_as_member
/// [`governing_workspace_file`]: crate::utils::pnpm_workspace::governing_workspace_file
async fn pnpm_settings_prefix(view: &mut View<'_>, rel: &str) -> String {
    let (dir, own) = match rel.rsplit_once('/') {
        Some((dir, _)) => (dir, format!("{dir}/")),
        None => ("", String::new()),
    };
    if let Some(root) = rush_lock_root(rel) {
        if read_sibling(view, root, "rush.json").await.is_some() {
            return own;
        }
    }
    if read_sibling(view, &own, "pnpm-workspace.yaml")
        .await
        .is_some()
    {
        return own;
    }
    let parts: Vec<&str> = if dir.is_empty() {
        Vec::new()
    } else {
        dir.split('/').collect()
    };
    for depth in (0..parts.len()).rev() {
        let prefix: String = parts[..depth].iter().map(|p| format!("{p}/")).collect();
        let Some(yaml) = read_sibling(view, &prefix, "pnpm-workspace.yaml").await else {
            continue;
        };
        let member: Vec<String> = parts[depth..].iter().map(|p| p.to_string()).collect();
        // pnpm stops at the nearest workspace file.
        return if crate::utils::pnpm_workspace::lists_as_member(&yaml, &member) {
            prefix
        } else {
            own
        };
    }
    // No workspace file inside the project: pnpm keeps looking above it.
    let member = view.root().join(dir);
    match crate::utils::pnpm_workspace::governing_workspace_file(&member)
        .as_deref()
        .and_then(std::path::Path::parent)
    {
        Some(root) => format!("{}{}", root.display(), std::path::MAIN_SEPARATOR),
        None => own,
    }
}

/// The `upstream_pnpm_tarball_setting_guessed` detail (#902): nothing
/// showed which pnpm wrote the lock `rel`, so the restore read
/// `lockfileIncludeTarballUrl` as pnpm 10 does (`guess`) for the derivable
/// `entries`, and pnpm 9 or pnpm >= 11 would read it the other way. `rush`:
/// a Rush lock, whose pnpm is rush.json's `pnpmVersion`. Worded for a dry
/// run and every caller (rollback, remove, a vendor takeover or eject).
fn pnpm_tarball_guess_warning(
    rel: &str,
    dir_prefix: &str,
    guess: PnpmTarballGuess,
    rush: bool,
    entries: &[&str],
) -> String {
    let workspace = format!("{dir_prefix}pnpm-workspace.yaml");
    let npmrc = format!("{dir_prefix}.npmrc");
    let ws_value = |value: Option<bool>| match value {
        Some(value) => format!("`lockfileIncludeTarballUrl: {value}`"),
        None => "`lockfileIncludeTarballUrl` unset".to_string(),
    };
    let rc_value = |value: Option<bool>| match value {
        Some(value) => format!("`lockfile-include-tarball-url={value}`"),
        None => "`lockfile-include-tarball-url` unset".to_string(),
    };
    let on = guess.on();
    let followed = if guess.workspace.is_some() {
        format!("{} in {workspace}", ws_value(guess.workspace))
    } else {
        format!("{} in {npmrc}", rc_value(guess.npmrc))
    };
    let effect = |on: bool| if on { "keep it" } else { "leave it out" };
    let mut differ = Vec::new();
    if guess.pnpm9() != on {
        differ.push(format!(
            "pnpm 9 reads only {npmrc} ({}) and would {}",
            rc_value(guess.npmrc),
            effect(guess.pnpm9())
        ));
    }
    if guess.pnpm11() != on {
        differ.push(format!(
            "pnpm >= 11 reads only {workspace} ({}) and would {}",
            ws_value(guess.workspace),
            effect(guess.pnpm11())
        ));
    }
    let (unknown, pin) = if rush {
        let root = rush_lock_root(rel).unwrap_or_default();
        (
            format!("no {root}rush.json `pnpmVersion`"),
            format!(
                "set {root}rush.json `pnpmVersion` to the pnpm Rush installs with, so the \
                 restore reads the setting as that pnpm does"
            ),
        )
    } else {
        (
            format!(
                "no {dir_prefix}node_modules/.modules.yaml install record, no \
                 {dir_prefix}package.json `packageManager` pin"
            ),
            format!(
                "pin it in {dir_prefix}package.json `packageManager` (or reinstall so \
                 {dir_prefix}node_modules/.modules.yaml records it), or give \
                 `lockfile-include-tarball-url` in {npmrc} and `lockfileIncludeTarballUrl` \
                 in {workspace} the same value, so every pnpm reads the setting alike"
            ),
        )
    };
    format!(
        "{rel}: nothing shows which pnpm wrote this lock (no unpinned registry entry that \
         shows the setting, {unknown}), so the restore reads `lockfileIncludeTarballUrl` \
         as pnpm 10 does, from {followed}, and restores {} {} `tarball:`; {}. If the \
         project uses that pnpm, those entries' `tarball:` lines differ from what it writes: \
         {pin}. A rollback or remove can then be redone by restoring {rel} from version \
         control and re-running it",
        entries.join(", "),
        if on { "with" } else { "without" },
        differ.join("; ")
    )
}

async fn pnpm_tarball_policy(
    view: &mut View<'_>,
    rel: &str,
    text: &str,
    ctx: &Ctx<'_>,
) -> PnpmTarballPolicy {
    let dir_prefix = pnpm_settings_prefix(view, rel).await;
    let lock_prefix = match rel.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/"),
        None => String::new(),
    };
    let workspace = read_sibling(view, &dir_prefix, "pnpm-workspace.yaml").await;
    let npmrc = read_sibling(view, &dir_prefix, ".npmrc").await;
    // A Rush lock: Rush installs with rush.json's `pnpmVersion` in
    // common/temp, so neither an install record nor a package.json sits
    // beside the lock.
    let rush_json = match rush_lock_root(rel) {
        Some(root) => read_sibling(view, root, "rush.json").await,
        None => None,
    };
    let rush = rush_json.is_some();
    let pm_major = if let Some(rush_json) = rush_json.as_deref() {
        rush_json_pnpm_major(rush_json)
    } else {
        // What installed the project (the workspace root's install
        // record, else the member's own), else what it pins.
        let mut installed = None;
        for prefix in [&dir_prefix, &lock_prefix] {
            installed = read_sibling(view, prefix, "node_modules/.modules.yaml")
                .await
                .as_deref()
                .and_then(modules_yaml_pnpm_major);
            if installed.is_some() || dir_prefix == lock_prefix {
                break;
            }
        }
        match installed {
            Some(major) => Some(major),
            None => read_sibling(view, &dir_prefix, "package.json")
                .await
                .as_deref()
                .and_then(package_json_pnpm_major),
        }
    };
    let include = pnpm_include_tarball(
        text,
        workspace.as_deref(),
        npmrc.as_deref(),
        pm_major,
        |url| ctx.hosted_uuid(url).is_some(),
    );
    PnpmTarballPolicy {
        always: include.on,
        guess: include.guess,
        rush,
        workspace,
        npmrc,
        major: pnpm_settings_major(text, pm_major),
        settings_prefix: dir_prefix,
    }
}

pub(crate) async fn restore_pnpm_locks(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::formats::pnpm::grammar as pnpm;

    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        // (resolution range, uuid, name, version, rebuilt-without-integrity)
        let mut hits: Vec<(std::ops::Range<usize>, String, String, String)> = Vec::new();
        for entry in pnpm::entries(&text) {
            let Some(resolution) = pnpm::resolution(&entry) else {
                continue;
            };
            let Some(uuid) = resolution.tarball().and_then(|t| ctx.hosted_uuid(t)) else {
                continue;
            };
            let Some(pin) = pins.get(uuid.as_str()) else {
                continue;
            };
            let Some((name, version)) = pin.name_version() else {
                result.refuse(&uuid, format!("{} is not an npm purl", pin.purl));
                continue;
            };
            if pnpm::suffix(entry.key, &name, &version).is_none() {
                result.refuse(
                    &uuid,
                    format!(
                        "the {rel} entry `{}` wiring it is not {name}@{version}",
                        entry.key
                    ),
                );
                continue;
            }
            hits.push((resolution.range.clone(), uuid, name, version));
        }
        let wanted = hits
            .iter()
            .map(|(_, u, n, v)| (u.clone(), n.clone(), v.clone()))
            .collect();
        let policy = pnpm_tarball_policy(view, rel, &text, ctx).await;
        let dists = fetch_dists_on(&wanted, |name| policy.registry(name), ctx, &mut result).await;
        let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
        // (uuid, name@version whose `tarball:` only the guessed setting decided)
        let mut handled: Vec<(String, Option<String>)> = Vec::new();
        for entry in pnpm::entries(&text) {
            let Some(resolution) = pnpm::resolution(&entry) else {
                continue;
            };
            let Some((_, uuid, name, version)) = hits.iter().find(|(r, ..)| *r == resolution.range)
            else {
                continue;
            };
            if result.refused.contains_key(uuid) {
                continue;
            }
            let Some(dist) = dists.get(&(name.clone(), version.clone())).map(|d| &d.dist) else {
                continue;
            };
            let Some(integrity) = dist.integrity.as_deref() else {
                result.refuse(
                    uuid,
                    format!("the registry records no integrity for {name}@{version}"),
                );
                continue;
            };
            // pnpm records `tarball:` under lockfileIncludeTarballUrl and for
            // a URL it cannot derive from the registry (#557).
            let derived = registry_derives_tarball(
                policy.registry(name).as_deref(),
                name,
                version,
                &dist.tarball,
            );
            let restored = if policy.always || !derived {
                resolution.rewrite(integrity, &dist.tarball)
            } else {
                resolution.restore(integrity)
            };
            // A URL pnpm records anyway is no guess.
            let guessed = (policy.guess.is_some() && derived).then(|| format!("{name}@{version}"));
            splices.push((resolution.range.clone(), restored));
            handled.push((uuid.clone(), guessed));
        }
        // A refusal recorded after a splice was planned (a second instance
        // of the same pin) drops that pin's splices too.
        let kept: Vec<_> = splices
            .into_iter()
            .zip(&handled)
            .filter(|(_, (u, _))| !result.refused.contains_key(u))
            .collect();
        let mut guessed: Vec<&str> = kept.iter().filter_map(|(_, (_, g))| g.as_deref()).collect();
        guessed.sort_unstable();
        guessed.dedup();
        let splices: Vec<_> = kept.into_iter().map(|(s, _)| s).collect();
        if splices.is_empty() {
            continue;
        }
        if let Some(guess) = policy.guess.filter(|_| !guessed.is_empty()) {
            result.warnings.push((
                "upstream_pnpm_tarball_setting_guessed",
                pnpm_tarball_guess_warning(
                    rel,
                    &policy.settings_prefix,
                    guess,
                    policy.rush,
                    &guessed,
                ),
            ));
        }
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        let mut sorted = splices;
        sorted.sort_by_key(|(r, _)| r.start);
        for (range, replacement) in sorted {
            out.push_str(&text[cursor..range.start]);
            out.push_str(&replacement);
            cursor = range.end;
        }
        out.push_str(&text[cursor..]);
        for (uuid, _) in handled {
            if !result.refused.contains_key(&uuid) {
                result.handled.insert(uuid);
            }
        }
        view.write(rel, out);
    }
    result
}

// ── bun.lock ─────────────────────────────────────────────────────────────────

/// The registry Bun resolves `name` against, from the settings beside the
/// lock (#992): a scoped package's `.npmrc` `@scope:registry`, else its
/// `bunfig.toml` `[install.scopes]` entry; otherwise `env_registry`
/// (`BUN_CONFIG_REGISTRY` / `NPM_CONFIG_REGISTRY`), the `.npmrc`
/// `registry`, then `bunfig.toml` `[install] registry` — Bun ≤ 1.3's
/// order. [`bun_lookup_layered`] is the general form, with the user's own
/// files and Bun ≥ 1.4's order.
#[cfg(test)]
fn bun_lookup_registry(
    npmrc: Option<&str>,
    bunfig: Option<&str>,
    env_registry: Option<&str>,
    var: &dyn Fn(&str) -> Option<String>,
    name: &str,
) -> Option<ProjectRegistry> {
    let project = |text: Option<&str>| {
        text.map(|text| BunConfigFile {
            text: text.to_string(),
            users: false,
        })
        .into_iter()
        .collect()
    };
    let files = BunConfigFiles {
        npmrc: project(npmrc),
        bunfig: project(bunfig),
    };
    bun_lookup_layered(&files, env_registry, var, name, false)
}

/// One Bun config file: its text, and whether it is the user's own (the
/// user `.npmrc` or the global bunfig) rather than the project's.
pub(super) struct BunConfigFile {
    text: String,
    users: bool,
}

/// The config files Bun reads registries from, each kind highest
/// precedence first: the project `.npmrc` then the user's, the project
/// `bunfig.toml` then the global one. A key the project file sets wins
/// over the user's or global file; any other key still comes from those
/// (#1276, measured on Bun 1.1.39 – 1.4.2).
#[derive(Default)]
pub(super) struct BunConfigFiles {
    npmrc: Vec<BunConfigFile>,
    bunfig: Vec<BunConfigFile>,
}

/// Where Bun reads the user's `.npmrc` and the global bunfig, measured on
/// Bun 1.1.39 – 1.4.2 (#1276): `$XDG_CONFIG_HOME/.npmrc` when that file
/// exists, else `~/.npmrc` (Bun ignores `NPM_CONFIG_USERCONFIG`); and
/// `$XDG_CONFIG_HOME/.bunfig.toml` when `XDG_CONFIG_HOME` is set — Bun
/// then never looks in `~` — else `~/.bunfig.toml`. The home dir is
/// `HOME`, or `USERPROFILE` on Windows.
fn bun_user_config_paths(
    var: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    exists: &dyn Fn(&std::path::Path) -> bool,
) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    use std::path::PathBuf;
    let dir = |key: &str| var(key).filter(|v| !v.is_empty()).map(PathBuf::from);
    let xdg = dir("XDG_CONFIG_HOME");
    let home = dir(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    let npmrc = xdg
        .as_ref()
        .map(|xdg| xdg.join(".npmrc"))
        .filter(|path| exists(path))
        .or_else(|| home.as_ref().map(|home| home.join(".npmrc")));
    let bunfig = match xdg {
        Some(xdg) => Some(xdg.join(".bunfig.toml")),
        None => home.map(|home| home.join(".bunfig.toml")),
    };
    (npmrc, bunfig)
}

/// The variables a config file may expand: any for the user's own files,
/// as Bun does, but only the [`BUN_EXPANDED_VARS`] token variables for the
/// project's — those files come with the project, and any other reference
/// (say `$GITHUB_TOKEN`) would hand that secret to a host the project
/// names. It expands to nothing instead.
fn bun_file_var<'a>(
    var: &'a dyn Fn(&str) -> Option<String>,
    users: bool,
) -> impl Fn(&str) -> Option<String> + 'a {
    move |key: &str| {
        (users || BUN_EXPANDED_VARS.contains(&key))
            .then(|| var(key))
            .flatten()
    }
}

/// The registry Bun resolves `name` against (#992, #1276), from `files`:
/// a scoped package's scope registry, else `env_registry`
/// (`BUN_CONFIG_REGISTRY` / `NPM_CONFIG_REGISTRY`), else the configured
/// default registry. `None` means Bun's default registry, npmjs.
///
/// Bun keys every file's settings into one config, so a key comes from the
/// highest-precedence file that sets it: a project file over the user's or
/// global one of its kind, and between kinds, any `.npmrc` over any
/// bunfig on Bun ≤ 1.3 but any bunfig over any `.npmrc` on Bun ≥ 1.4
/// (`bunfig_first`). A scope's entry with no URL (a bunfig token only)
/// takes the configured default registry with its own token.
///
/// The registry carries the credentials Bun sends it: the bunfig entry's
/// own `token` (Bearer) or `username` / `password` (Basic), else the
/// `.npmrc` `//host/path/:_authToken` / `:_auth` / `:username` +
/// `:_password` whose path covers the registry URL. `$VAR` / `${VAR}` in a
/// bunfig value and `${VAR}` in an `.npmrc` value read `var`, as Bun
/// expands them, limited by [`bun_file_var`]. A private scope registry
/// answers 401 without them.
fn bun_lookup_layered(
    files: &BunConfigFiles,
    env_registry: Option<&str>,
    var: &dyn Fn(&str) -> Option<String>,
    name: &str,
    bunfig_first: bool,
) -> Option<ProjectRegistry> {
    use super::super::npmrc::npmrc_top_level_value;

    fn url(value: &str) -> Option<String> {
        let value = value.trim().trim_matches(['"', '\'']);
        (value.starts_with("https://") || value.starts_with("http://")).then(|| value.to_string())
    }
    // A bunfig registry is a URL string or a table carrying `url` and
    // maybe its credentials.
    let toml_url = |item: &toml_edit::Item, var: &dyn Fn(&str) -> Option<String>| {
        let value = item
            .as_str()
            .or_else(|| item.get("url").and_then(toml_edit::Item::as_str))?;
        url(&expand_url_env(value, var, true))
    };
    let toml_auth = |item: &toml_edit::Item, var: &dyn Fn(&str) -> Option<String>| {
        let field = |key: &str| {
            item.get(key)
                .and_then(toml_edit::Item::as_str)
                .map(|v| expand_env(v, var, true))
                .filter(|v| !v.is_empty())
        };
        if let Some(token) = field("token") {
            return Some(format!("Bearer {token}"));
        }
        let (user, password) = (field("username")?, field("password")?);
        use base64::Engine as _;
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        ))
    };
    // An `.npmrc` key from the highest-precedence `.npmrc` that sets it.
    let npmrc_value = |key: &str| {
        files.npmrc.iter().find_map(|file| {
            let value = npmrc_top_level_value(&file.text, key)?;
            Some(expand_env(&value, &bun_file_var(var, file.users), false))
        })
    };
    // Credentials in the URL itself (`https://user:${TOKEN}@host/`) go on
    // the request only: the base is written into bun.lock and warnings.
    let with_npmrc_auth = |base: String, own: Option<String>| -> ProjectRegistry {
        let (base, userinfo) = split_userinfo(&base);
        let authorization = own
            .or(userinfo)
            .or_else(|| npmrc_registry_auth(&base, &npmrc_value));
        ProjectRegistry {
            base,
            authorization,
        }
    };
    enum Source<'a> {
        Npmrc(&'a BunConfigFile),
        Bunfig(toml_edit::DocumentMut, bool),
    }
    let npmrcs = files.npmrc.iter().map(Source::Npmrc);
    let bunfigs = files.bunfig.iter().filter_map(|file| {
        let doc = file.text.parse::<toml_edit::DocumentMut>().ok()?;
        Some(Source::Bunfig(doc, file.users))
    });
    let sources: Vec<Source> = if bunfig_first {
        bunfigs.chain(npmrcs).collect()
    } else {
        npmrcs.chain(bunfigs).collect()
    };
    // The configured default registry before the environment applies,
    // and whether the user's own file (not the project's) set it.
    let configured = || {
        sources.iter().find_map(|source| match source {
            Source::Npmrc(file) => {
                let value = npmrc_top_level_value(&file.text, "registry")?;
                let base = url(&expand_url_env(
                    &value,
                    &bun_file_var(var, file.users),
                    false,
                ))?;
                Some((with_npmrc_auth(base, None), file.users))
            }
            Source::Bunfig(doc, users) => {
                let item = doc.get("install")?.get("registry")?;
                let var = bun_file_var(var, *users);
                let base = toml_url(item, &var)?;
                Some((with_npmrc_auth(base, toml_auth(item, &var)), *users))
            }
        })
    };
    if let Some((scope, _)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        let key = format!("@{scope}:registry");
        let scoped = sources.iter().find_map(|source| match source {
            Source::Npmrc(file) => {
                let value = npmrc_top_level_value(&file.text, &key)?;
                let base = url(&expand_url_env(
                    &value,
                    &bun_file_var(var, file.users),
                    false,
                ))?;
                Some(Some(with_npmrc_auth(base, None)))
            }
            Source::Bunfig(doc, users) => {
                let scopes = doc.get("install")?.get("scopes")?;
                let entry = scopes
                    .get(scope)
                    .or_else(|| scopes.get(format!("@{scope}")))?;
                let var = bun_file_var(var, *users);
                if let Some(base) = toml_url(entry, &var) {
                    return Some(Some(with_npmrc_auth(base, toml_auth(entry, &var))));
                }
                // A scope entry with no URL (a token only) takes the
                // configured default registry, never the environment's,
                // with its own credentials. With no default configured
                // that is npmjs, which still gets the scope's token: a
                // private npmjs scope 401s without it. A token from the
                // user's own file never goes to a default registry the
                // project's file names: the repository would pick the host
                // that receives the user's credential.
                if !entry.is_table_like() || entry.get("url").is_some() {
                    return None;
                }
                let own = toml_auth(entry, &var);
                Some(match configured() {
                    Some((r, from_users)) => Some(ProjectRegistry {
                        authorization: if *users && !from_users {
                            r.authorization
                        } else {
                            own.or(r.authorization)
                        },
                        ..r
                    }),
                    None => own.map(|own| ProjectRegistry {
                        base: format!("{}/", crate::vendor::registry_fetch::DEFAULT_NPM_REGISTRY),
                        authorization: Some(own),
                    }),
                })
            }
        });
        if let Some(scoped) = scoped {
            return scoped;
        }
    }
    match env_registry.and_then(url) {
        Some(base) => Some(with_npmrc_auth(base, None)),
        None => configured().map(|(r, _)| r),
    }
}

/// The variables a project's bunfig.toml / .npmrc may expand into the
/// registry and credentials a Bun restore sends: the conventional npm
/// token variables, nothing else.
const BUN_EXPANDED_VARS: &[&str] = &["NPM_TOKEN", "NODE_AUTH_TOKEN", "BUN_AUTH_TOKEN"];

/// A registry URL with its variables expanded only inside its userinfo
/// (`https://user:${NPM_TOKEN}@host/`), which goes on the request's
/// `Authorization` header (see [`split_userinfo`]). A reference anywhere
/// else expands to nothing: the rest of the URL is requested, printed in
/// `upstream_registry_fallback` and written into the lock, so a token
/// there would leak into all three.
fn expand_url_env(value: &str, var: &dyn Fn(&str) -> Option<String>, bare: bool) -> String {
    let none = |_: &str| None;
    let (scheme, rest) = value.split_once("://").unwrap_or(("", value));
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (userinfo, after) = match rest[..authority_end].rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), &rest[authority_end - host.len()..]),
        None => (None, rest),
    };
    let mut out = String::with_capacity(value.len());
    if value.contains("://") {
        out.push_str(scheme);
        out.push_str("://");
    }
    if let Some(userinfo) = userinfo {
        out.push_str(&expand_env(userinfo, var, bare));
        out.push('@');
    }
    out.push_str(&expand_env(after, &none, bare));
    out
}

/// `value` with each `${VAR}` (and, for a bunfig value, `$VAR`) replaced
/// by `var(VAR)`, empty when unset.
fn expand_env(value: &str, var: &dyn Fn(&str) -> Option<String>, bare: bool) -> String {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(braced) = after.strip_prefix('{') {
            if let Some(end) = braced.find('}') {
                out.push_str(&var(&braced[..end]).unwrap_or_default());
                rest = &braced[end + 1..];
                continue;
            }
        } else if bare {
            let end = after.find(|c| !is_name(c)).unwrap_or(after.len());
            if end > 0 {
                out.push_str(&var(&after[..end]).unwrap_or_default());
                rest = &after[end..];
                continue;
            }
        }
        out.push('$');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// `base` without its URL userinfo, and the Basic `Authorization` that
/// userinfo stood for (percent-decoded, as a URL parser reads it).
fn split_userinfo(base: &str) -> (String, Option<String>) {
    use crate::utils::purl::percent_decode_purl_component as decode;
    let Some((scheme, rest)) = base.split_once("://") else {
        return (base.to_string(), None);
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some((userinfo, host)) = rest[..authority_end].rsplit_once('@') else {
        return (base.to_string(), None);
    };
    let stripped = format!("{scheme}://{host}{}", &rest[authority_end..]);
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (user, password) = (decode(user), decode(password));
    let authorization = (!user.is_empty() || !password.is_empty()).then(|| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    });
    (stripped, authorization)
}

/// The `Authorization` an `.npmrc` configures for the registry at `base`:
/// the `//host[:port]/path/:`-keyed `_authToken` (Bearer), `_auth` (Basic)
/// or `username` + base64 `_password` (Basic) of the longest path that
/// covers `base`'s, on the same host.
fn npmrc_registry_auth(base: &str, value: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let rest = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if host.is_empty() {
        return None;
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let non_empty = |v: Option<String>| v.filter(|v| !v.is_empty());
    for depth in (0..=segments.len()).rev() {
        let mut dart = format!("//{host}/");
        for segment in &segments[..depth] {
            dart.push_str(segment);
            dart.push('/');
        }
        if let Some(token) = non_empty(value(&format!("{dart}:_authToken"))) {
            return Some(format!("Bearer {token}"));
        }
        if let Some(auth) = non_empty(value(&format!("{dart}:_auth"))) {
            return Some(format!("Basic {auth}"));
        }
        if let (Some(user), Some(password)) = (
            non_empty(value(&format!("{dart}:username"))),
            non_empty(value(&format!("{dart}:_password"))),
        ) {
            use base64::Engine as _;
            let engine = base64::engine::general_purpose::STANDARD;
            let password = engine.decode(password.trim()).ok()?;
            let password = String::from_utf8(password).ok()?;
            return Some(format!(
                "Basic {}",
                engine.encode(format!("{user}:{password}"))
            ));
        }
    }
    None
}

/// The registry Bun takes from its environment: the first of
/// `BUN_CONFIG_REGISTRY`, `NPM_CONFIG_REGISTRY`, `npm_config_registry`
/// that is an http(s) URL — Bun skips a key that is not and reads the
/// next (`PackageManagerOptions.load`).
fn bun_env_registry(var: impl Fn(&str) -> Option<String>) -> Option<String> {
    [
        "BUN_CONFIG_REGISTRY",
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
    ]
    .iter()
    .find_map(|key| var(key).filter(|v| v.starts_with("https://") || v.starts_with("http://")))
}

/// Which kind of Bun config file wins a key both kinds set, as far as the
/// lock tells (#1276, measured on Bun 1.1.39 – 1.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BunConfigOrder {
    /// A lockfileVersion-2 `bun.lock`, which only Bun ≥ 1.4 writes (Bun
    /// 1.3 ignores it): any bunfig over any `.npmrc`.
    BunfigFirst,
    /// A lockfileVersion-0/1 `bun.lock`, which Bun 1.4 keeps as is, or a
    /// `bun.lockb`: Bun ≤ 1.3 takes any `.npmrc` over any bunfig and Bun
    /// ≥ 1.4 the other way round, so the lock does not say which.
    Unknown,
}

impl BunConfigOrder {
    /// The order for the `bun.lock` `text`.
    pub(super) fn of_text_lock(text: &str) -> Self {
        match crate::vendor::bun_lock_text::lock_version(text) {
            Some(v) if v >= 2 => Self::BunfigFirst,
            _ => Self::Unknown,
        }
    }
}

/// The settings that decide which registry Bun resolves each package of a
/// lock against, and so which tarball URL it recorded (#992): the
/// `.npmrc` and `bunfig.toml` beside the lock, the user's `.npmrc` and the
/// global bunfig (#1276), and the registry environment variables.
pub(super) struct BunRegistrySettings {
    files: BunConfigFiles,
    env_registry: Option<String>,
    order: BunConfigOrder,
}

impl BunRegistrySettings {
    pub(super) async fn read(view: &mut View<'_>, rel: &str, order: BunConfigOrder) -> Self {
        let dir_prefix = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => String::new(),
        };
        let mut files = BunConfigFiles::default();
        for (name, kind) in [
            (".npmrc", &mut files.npmrc),
            ("bunfig.toml", &mut files.bunfig),
        ] {
            if let Some(text) = view
                .read(&format!("{dir_prefix}{name}"))
                .await
                .ok()
                .flatten()
            {
                kind.push(BunConfigFile { text, users: false });
            }
        }
        // Unit tests read no ambient registry or user config: npm exports
        // `npm_config_registry` to child processes whenever one is
        // configured, and a developer's `~/.npmrc` would steer the
        // fixtures' restores the same way.
        let env_registry = if cfg!(test) {
            None
        } else {
            let (npmrc, bunfig) =
                bun_user_config_paths(&|key| std::env::var_os(key), &|path| path.is_file());
            for (path, kind) in [(npmrc, &mut files.npmrc), (bunfig, &mut files.bunfig)] {
                let Some(path) = path else { continue };
                if let Ok(text) = crate::utils::fs::read_regular_to_string(&path).await {
                    kind.push(BunConfigFile { text, users: true });
                }
            }
            bun_env_registry(|key| std::env::var(key).ok())
        };
        Self {
            files,
            env_registry,
            order,
        }
    }

    #[cfg(test)]
    fn from_files(files: BunConfigFiles, order: BunConfigOrder) -> Self {
        Self {
            files,
            env_registry: None,
            order,
        }
    }

    fn lookup(&self, name: &str, bunfig_first: bool) -> Option<ProjectRegistry> {
        // Unit tests read no ambient variables, as for `env_registry`.
        let var = |key: &str| {
            if cfg!(test) {
                None
            } else {
                std::env::var(key).ok()
            }
        };
        bun_lookup_layered(
            &self.files,
            self.env_registry.as_deref(),
            &var,
            name,
            bunfig_first,
        )
    }

    /// The registry Bun resolves `name` against; `None` means npmjs.
    pub(super) fn registry(&self, name: &str) -> Option<String> {
        self.registry_with_credentials(name).map(|r| r.base)
    }

    /// [`Self::registry`] with the credentials Bun sends it. Under
    /// [`BunConfigOrder::Unknown`] it is Bun ≤ 1.3's answer: call it only
    /// for a package [`Self::refuse_ambiguous`] kept, where both agree.
    pub(super) fn registry_with_credentials(&self, name: &str) -> Option<ProjectRegistry> {
        self.lookup(name, self.order == BunConfigOrder::BunfigFirst)
    }

    /// Why the registry Bun resolves `name` against can't be told: under
    /// [`BunConfigOrder::Unknown`], Bun ≤ 1.3 and Bun ≥ 1.4 resolve it
    /// against different registries (or credentials) because an `.npmrc`
    /// and a bunfig both set the deciding key.
    fn ambiguity(&self, rel: &str, name: &str) -> Option<String> {
        if self.order != BunConfigOrder::Unknown {
            return None;
        }
        let (old, new) = (self.lookup(name, false), self.lookup(name, true));
        let same = |a: &Option<ProjectRegistry>, b: &Option<ProjectRegistry>| match (a, b) {
            (Some(a), Some(b)) => a.base == b.base && a.authorization == b.authorization,
            (None, None) => true,
            _ => false,
        };
        if same(&old, &new) {
            return None;
        }
        // Never a credential: only the bases, which carry no userinfo.
        let shown = |r: &Option<ProjectRegistry>| match r {
            Some(r) => r.base.clone(),
            None => "npmjs".to_string(),
        };
        let (old_shown, new_shown) = (shown(&old), shown(&new));
        let against = if old_shown == new_shown {
            format!("{old_shown} with different credentials")
        } else {
            format!("{old_shown} (an .npmrc setting wins) but Bun 1.4+ against {new_shown} (a bunfig setting wins)")
        };
        Some(format!(
            "Bun ≤ 1.3 resolves {name} against {against}, and {rel} does not say which Bun \
             installs it"
        ))
    }

    /// `wanted` (uuid, name, version) without the packages whose registry
    /// can't be told ([`Self::ambiguity`]), each refused in `result`.
    pub(super) fn refuse_ambiguous(
        &self,
        rel: &str,
        wanted: BTreeSet<(String, String, String)>,
        result: &mut FormatResult,
    ) -> BTreeSet<(String, String, String)> {
        wanted
            .into_iter()
            .filter(|(uuid, name, version)| match self.ambiguity(rel, name) {
                Some(why) => {
                    result.refuse(uuid, format!("{name}@{version}: {why}"));
                    false
                }
                None => true,
            })
            .collect()
    }
}

/// The tarball URL Bun recorded for `name@version` resolved against
/// `project_registry`: the `dist.tarball` of the document read, except
/// that a fallback from an unreadable mirror to the default registry's
/// document re-bases its conventional URL on the mirror, the URL Bun
/// derived there.
pub(super) fn bun_tarball_url(
    project_registry: Option<&str>,
    name: &str,
    version: &str,
    found: &ProjectDist,
) -> String {
    use crate::vendor::registry_fetch::{
        npm_registry_base, npm_tarball_is_conventional, npm_tarball_url,
    };
    let tarball = &found.dist.tarball;
    // Only a fallback from a registry the default document does not stand
    // for is re-based: npmjs, its yarnpkg alias and `SOCKET_NPM_REGISTRY`
    // advertise the very `dist.tarball` that was read, which is what Bun
    // recorded.
    match project_registry.and_then(non_default_registry) {
        Some(base)
            if !found.from_project
                && npm_tarball_is_conventional(&npm_registry_base(), name, version, tarball) =>
        {
            npm_tarball_url(&base, name, version)
        }
        _ => tarball.clone(),
    }
}

/// The registry slot Bun writes in a `bun.lock` 4-tuple: `""` for a
/// package from registry.npmjs.org (Bun's own prefix test), else the full
/// tarball URL — which Bun 1.1.39–1.3.6 need, as they read `""` as npmjs
/// whatever the project configures (#992).
fn bun_registry_slot(
    project_registry: Option<&str>,
    name: &str,
    version: &str,
    found: &ProjectDist,
) -> String {
    use crate::vendor::registry_fetch::DEFAULT_NPM_REGISTRY;
    // Bun resolved npmjs (unconfigured, or npmjs / its yarnpkg alias,
    // whose documents advertise npmjs tarballs): the empty slot, whatever
    // `SOCKET_NPM_REGISTRY` the restore itself read.
    let Some(base) = project_registry.filter(|base| !is_npmjs_registry(base)) else {
        return String::new();
    };
    let url = bun_tarball_url(Some(base), name, version, found);
    if url.starts_with(DEFAULT_NPM_REGISTRY) {
        String::new()
    } else {
        url
    }
}

pub(crate) async fn restore_bun_locks(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::vendor::bun_lock_text::{decode_json_string, split_name_spec};

    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some(text) = read_or_refuse(view, rel, &pins, &mut result).await else {
            continue;
        };
        let (mut lines, entries) = match super::super::parse_bun_hosted_lock(&text) {
            Ok(parsed) => parsed,
            Err(w) => {
                refuse_all_in(&pins, rel, &mut result, w.detail);
                continue;
            }
        };
        // (line, uuid, name, version, deps)
        let mut hits: Vec<(usize, String, String, String, String)> = Vec::new();
        for entry in &entries {
            if !matches!(entry.elems.len(), 2 | 3) || !entry.elems[1].starts_with('{') {
                continue;
            }
            let Some(spec) = entry.elems.first().and_then(|e| decode_json_string(e)) else {
                continue;
            };
            let Some((name, url)) = split_name_spec(&spec) else {
                continue;
            };
            let Some(uuid) = ctx.hosted_uuid(url) else {
                continue;
            };
            let Some(pin) = pins.get(uuid.as_str()) else {
                continue;
            };
            match pin.name_version() {
                Some((pin_name, version)) if pin_name == name => hits.push((
                    entry.line_idx,
                    uuid,
                    name.to_string(),
                    version,
                    entry.elems[1].clone(),
                )),
                _ => result.refuse(
                    &uuid,
                    format!(
                        "the {rel} entry `{}` wiring it is not {}",
                        entry.key, pin.purl
                    ),
                ),
            }
        }
        let wanted = hits
            .iter()
            .map(|(_, u, n, v, _)| (u.clone(), n.clone(), v.clone()))
            .collect();
        // Bun records the tarball URL of a package from any registry but
        // npmjs, so the restore reads the registry settings Bun does.
        let settings =
            BunRegistrySettings::read(view, rel, BunConfigOrder::of_text_lock(&text)).await;
        let wanted = settings.refuse_ambiguous(rel, wanted, &mut result);
        let dists = fetch_dists_on(
            &wanted,
            |n| settings.registry_with_credentials(n),
            ctx,
            &mut result,
        )
        .await;
        let mut changed = false;
        for (line_idx, uuid, name, version, deps) in hits {
            if result.refused.contains_key(&uuid) {
                continue;
            }
            let Some(found) = dists.get(&(name.clone(), version.clone())) else {
                continue;
            };
            let Some(integrity) = found.dist.integrity.clone() else {
                result.refuse(
                    &uuid,
                    format!("the registry records no integrity for {name}@{version}"),
                );
                continue;
            };
            let Some(entry) = entries.iter().find(|e| e.line_idx == line_idx) else {
                continue;
            };
            let original = &lines[line_idx];
            let cr = if original.ends_with('\r') { "\r" } else { "" };
            let json = |s: &str| serde_json::to_string(s).expect("a str serializes to JSON");
            let slot =
                bun_registry_slot(settings.registry(&name).as_deref(), &name, &version, found);
            lines[line_idx] = format!(
                "{indent}{key}: [{spec}, {slot}, {deps}, {integrity}]{comma}{cr}",
                indent = entry.indent,
                key = entry.key_raw,
                spec = json(&format!("{name}@{version}")),
                slot = json(&slot),
                integrity = json(&integrity),
                comma = if entry.trailing_comma { "," } else { "" },
            );
            result.handled.insert(uuid);
            changed = true;
        }
        if changed {
            view.write(rel, lines.join("\n"));
        }
    }
    result
}

// ── side settings ────────────────────────────────────────────────────────────

/// Whether any npm / pnpm lock in the view still resolves a hosted URL.
async fn still_hosted(view: &mut View<'_>, rels: &[&str], ctx: &Ctx<'_>) -> bool {
    for rel in rels {
        let Ok(Some(text)) = view.read(rel).await else {
            continue;
        };
        if !crate::vex::discover::hosted_uuids_in_text(&text, ctx.origins).is_empty() {
            return true;
        }
    }
    false
}

/// Remove the `.npmrc` / pnpm-workspace.yaml a hosted run CREATED (still
/// byte-identical to the scaffold) once no lock entry needs it; warn about
/// the setting when the file carries other content too (the line may be
/// the user's own, so it is never removed from a file the user wrote).
pub(crate) async fn cleanup_side_config(
    view: &mut View<'_>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    use super::super::npmrc::{NPMRC_ALLOW_REMOTE_LINE, NPMRC_CREATED, NPMRC_REL};

    let restored_npm_lock = view.staged.keys().any(|k| {
        matches!(
            k.rsplit('/').next(),
            Some("package-lock.json" | "npm-shrinkwrap.json")
        )
    });
    if restored_npm_lock
        && !still_hosted(view, &["package-lock.json", "npm-shrinkwrap.json"], ctx).await
    {
        if let Ok(Some(npmrc)) = view.read(NPMRC_REL).await {
            if npmrc == NPMRC_CREATED {
                view.remove(NPMRC_REL);
            } else if npmrc.lines().any(|l| l.trim() == NPMRC_ALLOW_REMOTE_LINE) {
                result.warnings.push((
                    "npm_allow_remote_left",
                    format!(
                        "{NPMRC_REL} keeps `{NPMRC_ALLOW_REMOTE_LINE}`, which hosted mode may \
                         have added; no lock entry needs it any more, so remove the line if \
                         nothing else does"
                    ),
                ));
            }
        }
    }

    let restored_pnpm = view.staged.keys().any(|k| k == "pnpm-lock.yaml");
    if restored_pnpm && !still_hosted(view, &["pnpm-lock.yaml"], ctx).await {
        const WORKSPACE: &str = "pnpm-workspace.yaml";
        if let Ok(Some(ws)) = view.read(WORKSPACE).await {
            if ws == "packages:\n  - '.'\ntrustLockfile: true\n" {
                view.remove(WORKSPACE);
            } else if ws.lines().any(|l| {
                crate::formats::pnpm::workspace::top_level_key(l).is_some_and(|(key, value)| {
                    key == "trustLockfile" && value.trim_matches(['\'', '"']) == "true"
                })
            }) {
                result.warnings.push((
                    "pnpm_trust_lockfile_left",
                    format!(
                        "{WORKSPACE} keeps `trustLockfile: true`, which hosted mode may have \
                         added; no lock entry needs it any more, so remove the line if nothing \
                         else does"
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        berry_lookup_registry, berry_registry_locator, bun_env_registry, bun_lookup_registry,
        bun_registry_slot, bun_tarball_url, expand_url_env, modules_yaml_pnpm_major,
        non_default_registry, package_json_pnpm_major, pnpm_include_tarball, pnpm_lookup_registry,
        pnpm_tarball_guess_warning, registry_derives_tarball, rush_json_pnpm_major, rush_lock_root,
        split_userinfo, yaml_top_level_value, yarn_expand_env, PnpmTarballGuess, ProjectDist,
    };
    use crate::patch::redirect::upstream::client::NpmDist;

    fn files(npmrc: &[(&str, bool)], bunfig: &[(&str, bool)]) -> super::BunConfigFiles {
        let layer = |list: &[(&str, bool)]| {
            list.iter()
                .map(|(text, users)| super::BunConfigFile {
                    text: text.to_string(),
                    users: *users,
                })
                .collect()
        };
        super::BunConfigFiles {
            npmrc: layer(npmrc),
            bunfig: layer(bunfig),
        }
    }

    #[test]
    fn bun_user_config_paths_follow_bun_s_lookup() {
        use std::ffi::OsString;
        use std::path::{Path, PathBuf};
        let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                let key = if key == home_var { "HOME" } else { key };
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let paths = |pairs: &'static [(&'static str, &'static str)], existing: &[&str]| {
            let existing: Vec<PathBuf> = existing.iter().map(PathBuf::from).collect();
            super::bun_user_config_paths(&env(pairs), &|p: &Path| existing.iter().any(|e| e == p))
        };
        let some = |p: &str| Some(PathBuf::from(p));
        // No XDG: both under the home dir.
        assert_eq!(
            paths(&[("HOME", "/h")], &[]),
            (some("/h/.npmrc"), some("/h/.bunfig.toml"))
        );
        // XDG set: the XDG `.npmrc` replaces `~/.npmrc` only when it exists,
        // while the global bunfig is the XDG one whether or not it exists.
        assert_eq!(
            paths(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")], &[]),
            (some("/h/.npmrc"), some("/x/.bunfig.toml"))
        );
        assert_eq!(
            paths(
                &[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")],
                &["/x/.npmrc", "/h/.npmrc"]
            ),
            (some("/x/.npmrc"), some("/x/.bunfig.toml"))
        );
        // An empty variable counts as unset; no home and no XDG: nothing.
        assert_eq!(
            paths(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "")], &[]),
            (some("/h/.npmrc"), some("/h/.bunfig.toml"))
        );
        assert_eq!(paths(&[], &[]), (None, None));
        // Bun never reads `NPM_CONFIG_USERCONFIG`.
        assert_eq!(
            paths(&[("NPM_CONFIG_USERCONFIG", "/u/npmrc")], &[]),
            (None, None)
        );
    }

    #[test]
    fn bun_layers_take_each_key_from_the_highest_file_that_sets_it() {
        let lookup = |files: &super::BunConfigFiles, name: &str, bunfig_first: bool| {
            super::bun_lookup_layered(files, None, &|_| None, name, bunfig_first).map(|r| r.base)
        };
        let some = |s: &str| Some(s.to_string());
        // The project `.npmrc` wins its own keys; the user's file still
        // supplies the rest (a scope, the default registry).
        let npmrc = files(
            &[
                ("@p:registry=https://proj.example/\n", false),
                (
                    "@p:registry=https://user-p.example/\n@u:registry=https://user.example/\nregistry=https://ureg.example/\n",
                    true,
                ),
            ],
            &[],
        );
        assert_eq!(lookup(&npmrc, "@p/a", false), some("https://proj.example/"));
        assert_eq!(lookup(&npmrc, "@u/a", false), some("https://user.example/"));
        assert_eq!(lookup(&npmrc, "a", false), some("https://ureg.example/"));
        // The project bunfig wins over the global one, key by key.
        let bunfig = files(
            &[],
            &[
                ("[install.scopes]\np = \"https://proj.example/\"\n", false),
                (
                    "[install]\nregistry = \"https://greg.example/\"\n\n[install.scopes]\np = \"https://glob-p.example/\"\ng = \"https://glob.example/\"\n",
                    true,
                ),
            ],
        );
        assert_eq!(
            lookup(&bunfig, "@p/a", false),
            some("https://proj.example/")
        );
        assert_eq!(
            lookup(&bunfig, "@g/a", false),
            some("https://glob.example/")
        );
        assert_eq!(lookup(&bunfig, "a", false), some("https://greg.example/"));
        // Between kinds: Bun ≤ 1.3 takes any `.npmrc` first, Bun ≥ 1.4 any
        // bunfig — the user `.npmrc` against the project bunfig here.
        let both = files(
            &[("@s:registry=https://user-npmrc.example/\n", true)],
            &[(
                "[install.scopes]\ns = \"https://proj-bunfig.example/\"\n",
                false,
            )],
        );
        assert_eq!(
            lookup(&both, "@s/a", false),
            some("https://user-npmrc.example/")
        );
        assert_eq!(
            lookup(&both, "@s/a", true),
            some("https://proj-bunfig.example/")
        );
        // A scope beats the default registry wherever each is set.
        let mixed = files(
            &[("registry=https://proj-reg.example/\n", false)],
            &[(
                "[install.scopes]\ns = \"https://glob-scope.example/\"\n",
                true,
            )],
        );
        for bunfig_first in [false, true] {
            assert_eq!(
                lookup(&mixed, "@s/a", bunfig_first),
                some("https://glob-scope.example/")
            );
        }
        // A global token-only scope entry takes the user's default registry.
        let token_only = files(
            &[("registry=https://ureg.example/\n", true)],
            &[("[install.scopes]\ns = { token = \"t\" }\n", true)],
        );
        let r = super::bun_lookup_layered(&token_only, None, &|_| None, "@s/a", false).unwrap();
        assert_eq!(
            (r.base.as_str(), r.authorization.as_deref()),
            ("https://ureg.example/", Some("Bearer t"))
        );
        // It never goes to a default registry the project's file names,
        // in either order: the repository would pick the host that gets
        // the user's token.
        for (npmrc, bunfig) in [
            (vec![("registry=https://evil.example/\n", false)], vec![]),
            (
                vec![],
                vec![("[install]\nregistry = \"https://evil.example/\"\n", false)],
            ),
        ] {
            let mut bunfig = bunfig;
            bunfig.push(("[install.scopes]\ns = { token = \"t\" }\n", true));
            let leaked = files(&npmrc, &bunfig);
            for bunfig_first in [false, true] {
                let r = super::bun_lookup_layered(&leaked, None, &|_| None, "@s/a", bunfig_first)
                    .unwrap();
                assert_eq!(
                    (r.base.as_str(), r.authorization.as_deref()),
                    ("https://evil.example/", None)
                );
            }
        }
    }

    #[test]
    fn bun_user_files_expand_any_variable_project_files_only_token_ones() {
        let vars = |key: &str| (key == "GITHUB_TOKEN").then(|| "gh".to_string());
        let auth = |users: bool| {
            let files = files(
                &[(
                    "@s:registry=https://npm.pkg.example/\n//npm.pkg.example/:_authToken=${GITHUB_TOKEN}\n",
                    users,
                )],
                &[],
            );
            super::bun_lookup_layered(&files, None, &vars, "@s/a", false)
                .and_then(|r| r.authorization)
        };
        // The user wrote `~/.npmrc`: Bun expands any variable in it.
        assert_eq!(auth(true), Some("Bearer gh".to_string()));
        // The project's file can't send `$GITHUB_TOKEN` anywhere.
        assert_eq!(auth(false), None);
        // The token key from the user's file covers a project-set scope
        // registry on the same host, as in Bun.
        let split = files(
            &[
                ("@s:registry=https://npm.pkg.example/\n", false),
                ("//npm.pkg.example/:_authToken=${GITHUB_TOKEN}\n", true),
            ],
            &[],
        );
        assert_eq!(
            super::bun_lookup_layered(&split, None, &vars, "@s/a", false)
                .and_then(|r| r.authorization),
            Some("Bearer gh".to_string())
        );
    }

    #[test]
    fn bun_refuses_a_registry_the_lock_s_bun_version_would_decide() {
        use super::{BunConfigOrder, BunRegistrySettings};
        assert_eq!(
            BunConfigOrder::of_text_lock("{\n  \"lockfileVersion\": 2,\n}"),
            BunConfigOrder::BunfigFirst
        );
        for v in ["0", "1"] {
            assert_eq!(
                BunConfigOrder::of_text_lock(&format!("{{\n  \"lockfileVersion\": {v},\n}}")),
                BunConfigOrder::Unknown
            );
        }
        let conflict = || {
            files(
                &[("@s:registry=https://n.example/\n", true)],
                &[("[install.scopes]\ns = \"https://b.example/\"\n", false)],
            )
        };
        let unknown = BunRegistrySettings::from_files(conflict(), BunConfigOrder::Unknown);
        let why = unknown.ambiguity("bun.lock", "@s/a").expect("ambiguous");
        assert!(
            why.contains("https://n.example/")
                && why.contains("https://b.example/")
                && why.contains("bun.lock does not say which Bun"),
            "{why}"
        );
        // A package no conflicting key decides is not ambiguous.
        assert_eq!(unknown.ambiguity("bun.lock", "a"), None);
        assert_eq!(unknown.ambiguity("bun.lock", "@t/a"), None);
        // A v2 lock is Bun ≥ 1.4's: the bunfig wins, nothing is refused.
        let v2 = BunRegistrySettings::from_files(conflict(), BunConfigOrder::BunfigFirst);
        assert_eq!(v2.ambiguity("bun.lock", "@s/a"), None);
        assert_eq!(v2.registry("@s/a").as_deref(), Some("https://b.example/"));
        // Same registry, different credentials: still refused.
        let creds = files(
            &[("//r.example/:_authToken=n\n", true)],
            &[(
                "[install]\nregistry = { url = \"https://r.example/\", token = \"b\" }\n",
                false,
            )],
        );
        let mut creds = creds;
        creds.npmrc[0]
            .text
            .insert_str(0, "registry=https://r.example/\n");
        let creds = BunRegistrySettings::from_files(creds, BunConfigOrder::Unknown);
        assert!(creds
            .ambiguity("bun.lock", "a")
            .is_some_and(|why| why.contains("different credentials") && !why.contains("Bearer")));
    }

    #[test]
    fn bun_reads_the_registry_in_bun_s_own_order() {
        let bunfig = "[install]\nregistry = \"https://b.example/\"\n\n\
                      [install.scopes]\ns = \"https://s.example/\"\n\"@t\" = { url = \"https://t.example/\", token = \"x\" }\n";
        let npmrc = "registry=https://n.example/\n@u:registry=https://u.example/\n";
        let lookup = |npmrc, bunfig, env, name| {
            bun_lookup_registry(npmrc, bunfig, env, &|_| None, name).map(|r| r.base)
        };
        assert_eq!(
            lookup(None, Some(bunfig), None, "a").as_deref(),
            Some("https://b.example/")
        );
        // A table registry carries `url`.
        assert_eq!(
            lookup(
                None,
                Some("[install.registry]\nurl = \"https://c.example\"\n"),
                None,
                "a"
            )
            .as_deref(),
            Some("https://c.example")
        );
        // .npmrc wins over bunfig, the environment over both.
        assert_eq!(
            lookup(Some(npmrc), Some(bunfig), None, "a").as_deref(),
            Some("https://n.example/")
        );
        assert_eq!(
            lookup(Some(npmrc), Some(bunfig), Some("https://e.example"), "a").as_deref(),
            Some("https://e.example")
        );
        // A scope's registry wins over every default one; either spelling.
        for (name, want) in [
            ("@s/a", "https://s.example/"),
            ("@t/a", "https://t.example/"),
            ("@u/a", "https://u.example/"),
            ("@v/a", "https://e.example"),
        ] {
            assert_eq!(
                lookup(Some(npmrc), Some(bunfig), Some("https://e.example"), name).as_deref(),
                Some(want),
                "{name}"
            );
        }
        // A scope entry with no URL takes the configured default registry,
        // not the environment's (Bun's `registry.url = base.url`).
        let token_only = "[install]\nregistry = \"https://b.example/\"\n\n\
                          [install.scopes]\nw = { token = \"x\" }\n";
        assert_eq!(
            lookup(None, Some(token_only), Some("https://e.example"), "@w/a").as_deref(),
            Some("https://b.example/")
        );
        assert_eq!(
            lookup(None, Some(token_only), Some("https://e.example"), "a").as_deref(),
            Some("https://e.example")
        );
        // Nothing configured, or nothing that is a URL: npmjs.
        assert_eq!(lookup(None, None, None, "a"), None);
        assert_eq!(
            lookup(Some("registry=${R}\n"), Some("not toml ["), Some("x"), "a"),
            None
        );
    }

    #[test]
    fn bun_registry_userinfo_goes_on_the_request_not_the_base() {
        let vars = |key: &str| (key == "NPM_TOKEN").then(|| "s3cret".to_string());
        let lookup = |npmrc: Option<&str>, bunfig: Option<&str>, env: Option<&str>, name: &str| {
            bun_lookup_registry(npmrc, bunfig, env, &vars, name).map(|r| (r.base, r.authorization))
        };
        let basic = |pair: &str| {
            use base64::Engine as _;
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair)
            ))
        };
        // bunfig `$VAR` / `${VAR}`, an .npmrc `${VAR}` and the environment's
        // registry: the expanded secret never reaches the base that
        // bun.lock, bun.lockb and upstream_registry_fallback print.
        let bunfig = "[install]\nregistry = \"https://ci:$NPM_TOKEN@b.example/npm/\"\n\n\
                      [install.scopes]\n\
                      corp = { url = \"https://u:${NPM_TOKEN}@corp.example/\", token = \"own\" }\n";
        assert_eq!(
            lookup(None, Some(bunfig), None, "a"),
            Some(("https://b.example/npm/".to_string(), basic("ci:s3cret")))
        );
        // An explicit token still wins; the userinfo is dropped all the same.
        assert_eq!(
            lookup(None, Some(bunfig), None, "@corp/w"),
            Some((
                "https://corp.example/".to_string(),
                Some("Bearer own".to_string())
            ))
        );
        assert_eq!(
            lookup(
                Some("@s:registry=https://x:${NPM_TOKEN}@s.example/\n"),
                None,
                None,
                "@s/w"
            ),
            Some(("https://s.example/".to_string(), basic("x:s3cret")))
        );
        assert_eq!(
            lookup(None, None, Some("https://e%40m:p%3Aw@e.example/"), "a"),
            Some(("https://e.example/".to_string(), basic("e@m:p:w")))
        );
        // No userinfo: unchanged.
        assert_eq!(
            split_userinfo("https://h.example/a@b"),
            ("https://h.example/a@b".to_string(), None)
        );
    }

    #[test]
    fn bun_sends_the_credentials_its_settings_give_each_registry() {
        let vars = |key: &str| match key {
            "NODE_AUTH_TOKEN" => Some("from-env".to_string()),
            "BUN_AUTH_TOKEN" => Some("npmrc-env".to_string()),
            "GITHUB_TOKEN" => Some("not-for-registries".to_string()),
            _ => None,
        };
        let auth = |npmrc: Option<&str>, bunfig: Option<&str>, env: Option<&str>, name: &str| {
            bun_lookup_registry(npmrc, bunfig, env, &vars, name).map(|r| (r.base, r.authorization))
        };
        let some =
            |base: &str, auth: Option<&str>| Some((base.to_string(), auth.map(str::to_string)));
        // The scope entry's own token, `$VAR` / `${VAR}` expanded; Basic
        // from username + password.
        let bunfig = "[install]\nregistry = { url = \"https://b.example/\", token = \"bt\" }\n\n\
                      [install.scopes]\n\
                      corp = { url = \"https://corp.example/npm/\", token = \"$NODE_AUTH_TOKEN\" }\n\
                      braced = { url = \"https://br.example/\", token = \"x${NODE_AUTH_TOKEN}y\" }\n\
                      basic = { url = \"https://ba.example/\", username = \"u\", password = \"p\" }\n\
                      bare = \"https://bare.example/\"\n\
                      own = { token = \"own\" }\n\
                      unset = { url = \"https://un.example/\", token = \"$NOPE\" }\n\
                      other = { url = \"https://ot.example/\", token = \"${GITHUB_TOKEN}\" }\n\
                      inurl = \"https://u:$GITHUB_TOKEN@iu.example/\"\n\
                      inpath = \"https://ip.example/$NODE_AUTH_TOKEN/\"\n";
        assert_eq!(
            auth(None, Some(bunfig), None, "@corp/w"),
            some("https://corp.example/npm/", Some("Bearer from-env"))
        );
        assert_eq!(
            auth(None, Some(bunfig), None, "@braced/w"),
            some("https://br.example/", Some("Bearer xfrom-envy"))
        );
        assert_eq!(
            auth(None, Some(bunfig), None, "@basic/w"),
            some("https://ba.example/", Some("Basic dTpw"))
        );
        assert_eq!(
            auth(None, Some(bunfig), None, "@bare/w"),
            some("https://bare.example/", None)
        );
        assert_eq!(
            auth(None, Some(bunfig), None, "@unset/w"),
            some("https://un.example/", None)
        );
        // A variable that is not a registry token variable is never
        // expanded: the project's files cannot send it anywhere.
        assert_eq!(
            auth(None, Some(bunfig), None, "@other/w"),
            some("https://ot.example/", None)
        );
        let (base, authorization) = auth(None, Some(bunfig), None, "@inurl/w").unwrap();
        assert_eq!(base, "https://iu.example/");
        let sent = authorization.and_then(|a| {
            use base64::Engine as _;
            let encoded = a.strip_prefix("Basic ")?.to_string();
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        });
        assert!(
            !String::from_utf8_lossy(&sent.unwrap_or_default()).contains("not-for-registries"),
            "the userinfo expanded $GITHUB_TOKEN"
        );
        // Even an allowed token stays out of the URL's host, path and
        // query, which are requested, printed and written into the lock;
        // only userinfo (moved onto the request header) expands.
        assert_eq!(
            auth(None, Some(bunfig), None, "@inpath/w"),
            some("https://ip.example//", None)
        );
        assert_eq!(
            auth(
                Some("@p:registry=https://h.example/${BUN_AUTH_TOKEN}/?t=${BUN_AUTH_TOKEN}\n"),
                None,
                None,
                "@p/w"
            ),
            some("https://h.example//?t=", None)
        );
        assert_eq!(
            expand_url_env(
                "https://u:$NODE_AUTH_TOKEN@h.example/$NODE_AUTH_TOKEN",
                &vars,
                true
            ),
            "https://u:from-env@h.example/"
        );
        // A token-only scope: the configured default registry, its own token.
        assert_eq!(
            auth(None, Some(bunfig), Some("https://e.example/"), "@own/w"),
            some("https://b.example/", Some("Bearer own"))
        );
        // ...and with no default registry configured, npmjs with that
        // token (a private npmjs scope), still not the environment's.
        let npmjs_scope = "[install.scopes]\nown = { token = \"$NODE_AUTH_TOKEN\" }\n\
                           none = { username = \"u\" }\n";
        for env in [None, Some("https://e.example/")] {
            assert_eq!(
                auth(None, Some(npmjs_scope), env, "@own/w"),
                some("https://registry.npmjs.org/", Some("Bearer from-env")),
                "{env:?}"
            );
        }
        // A token-less scope entry with nothing configured stays npmjs.
        assert_eq!(auth(None, Some(npmjs_scope), None, "@none/w"), None);
        // The default registry's table token; the environment's registry
        // carries none of bunfig's.
        assert_eq!(
            auth(None, Some(bunfig), None, "a"),
            some("https://b.example/", Some("Bearer bt"))
        );
        assert_eq!(
            auth(None, Some(bunfig), Some("https://e.example/"), "a"),
            some("https://e.example/", None)
        );

        // `.npmrc` nerf-darted credentials: the longest covering path on
        // the same host; never another host's.
        let npmrc = "@corp:registry=https://corp.example/npm/private/\n\
                     @other:registry=https://other.example/\n\
                     @basic:registry=https://nb.example/\n\
                     @legacy:registry=https://lg.example/r/\n\
                     registry=https://n.example/\n\
                     //corp.example/:_authToken=host-wide\n\
                     //corp.example/npm/private/:_authToken=${BUN_AUTH_TOKEN}\n\
                     //n.example/:_authToken=default\n\
                     //nb.example/:_auth=dTpw\n\
                     //lg.example/r/:username=u\n//lg.example/r/:_password=cA==\n";
        assert_eq!(
            auth(Some(npmrc), None, None, "@corp/w"),
            some(
                "https://corp.example/npm/private/",
                Some("Bearer npmrc-env")
            )
        );
        assert_eq!(
            auth(Some(npmrc), None, None, "@other/w"),
            some("https://other.example/", None)
        );
        assert_eq!(
            auth(Some(npmrc), None, None, "@basic/w"),
            some("https://nb.example/", Some("Basic dTpw"))
        );
        assert_eq!(
            auth(Some(npmrc), None, None, "@legacy/w"),
            some("https://lg.example/r/", Some("Basic dTpw"))
        );
        assert_eq!(
            auth(Some(npmrc), None, None, "a"),
            some("https://n.example/", Some("Bearer default"))
        );
        // A bunfig scope registry picks up the `.npmrc` credentials for
        // its URL; its own token wins over them.
        let corp_npmrc = "//corp.example/:_authToken=host-wide\n";
        assert_eq!(
            auth(
                Some(corp_npmrc),
                Some("[install.scopes]\ncorp = \"https://corp.example/x/\"\n"),
                None,
                "@corp/w"
            ),
            some("https://corp.example/x/", Some("Bearer host-wide"))
        );
        assert_eq!(
            auth(Some(corp_npmrc), Some(bunfig), None, "@corp/w"),
            some("https://corp.example/npm/", Some("Bearer from-env"))
        );
    }

    #[test]
    #[serial_test::serial]
    fn bun_writes_the_tarball_url_unless_it_is_on_npmjs() {
        let found = |tarball: &str, from_project| ProjectDist {
            dist: NpmDist {
                tarball: tarball.to_string(),
                integrity: None,
                shasum: None,
                bin: Default::default(),
                node_gyp: false,
            },
            from_project,
        };
        let mirror = found("https://m.example/npm/a/-/a-1.0.0.tgz", true);
        assert_eq!(
            bun_registry_slot(Some("https://m.example/npm/"), "a", "1.0.0", &mirror),
            "https://m.example/npm/a/-/a-1.0.0.tgz"
        );
        // A mirror's off-path URL is kept as the mirror advertises it.
        let cdn = found("https://cdn.example/f/a.tgz", true);
        assert_eq!(
            bun_registry_slot(Some("https://m.example"), "a", "1.0.0", &cdn),
            "https://cdn.example/f/a.tgz"
        );
        // npmjs, configured or not, or its aliases, is Bun's empty slot:
        // their documents advertise npmjs tarballs, never re-based.
        let npmjs = found("https://registry.npmjs.org/a/-/a-1.0.0.tgz", false);
        for registry in [
            None,
            Some("https://registry.npmjs.org/"),
            Some("http://registry.npmjs.org/"),
            Some("https://registry.yarnpkg.com/"),
        ] {
            assert_eq!(bun_registry_slot(registry, "a", "1.0.0", &npmjs), "");
            assert_eq!(
                bun_tarball_url(registry, "a", "1.0.0", &npmjs),
                "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                "{registry:?}"
            );
        }
        // A fallback from an unreadable mirror re-bases the conventional URL.
        assert_eq!(
            bun_tarball_url(Some("https://m.example/npm/"), "a", "1.0.0", &npmjs),
            "https://m.example/npm/a/-/a-1.0.0.tgz"
        );
    }

    #[test]
    fn bun_env_registry_skips_keys_that_are_not_urls() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(
            bun_env_registry(env(&[
                ("BUN_CONFIG_REGISTRY", "not-a-url"),
                ("NPM_CONFIG_REGISTRY", ""),
                ("npm_config_registry", "https://n.example/"),
            ]))
            .as_deref(),
            Some("https://n.example/")
        );
        assert_eq!(
            bun_env_registry(env(&[
                ("BUN_CONFIG_REGISTRY", "http://b.example"),
                ("npm_config_registry", "https://n.example/"),
            ]))
            .as_deref(),
            Some("http://b.example")
        );
        assert_eq!(bun_env_registry(env(&[("BUN_CONFIG_REGISTRY", "x")])), None);
    }

    const HOSTED: &str = "https://patch.test/npm/u/a-1.0.0.tgz";
    const WS_ON: &str = "packages:\n  - '.'\nlockfileIncludeTarballUrl: true\n";
    const RC_ON: &str = "lockfile-include-tarball-url=true\n";

    /// A v9 lock: `a@1.0.0` pinned to the hosted tarball, plus `extra`
    /// `packages:` entries.
    fn lock(extra: &str) -> String {
        format!(
            "lockfileVersion: '9.0'\n\npackages:\n  a@1.0.0:\n    \
             resolution: {{integrity: sha512-A==, tarball: {HOSTED}}}\n{extra}\n\
             snapshots:\n  a@1.0.0: {{}}\n"
        )
    }

    fn include(text: &str, ws: Option<&str>, rc: Option<&str>, major: Option<u32>) -> bool {
        pnpm_include_tarball(text, ws, rc, major, |url| url == HOSTED).on
    }

    fn guessed(text: &str, ws: Option<&str>, rc: Option<&str>, major: Option<u32>) -> bool {
        pnpm_include_tarball(text, ws, rc, major, |url| url == HOSTED)
            .guess
            .is_some()
    }

    /// #902 tier 3: with no lock evidence and no pnpm major, the settings
    /// are read as pnpm 10 does, and flagged as a guess exactly when pnpm 9
    /// (`.npmrc` only) or pnpm >= 11 (the workspace file only), which also
    /// write a 9.0 lock, would read them the other way.
    #[test]
    fn pnpm_include_tarball_flags_the_guess() {
        let text = lock("");
        let rc_off = "lockfile-include-tarball-url=false\n";
        let ws_off = "lockfileIncludeTarballUrl: false\n";
        // (workspace, npmrc, pnpm 10's reading, guessed)
        for (ws, rc, on, guess) in [
            // pnpm >= 11 ignores `.npmrc`.
            (None, Some(RC_ON), true, true),
            // pnpm 9 ignores the workspace file.
            (Some(WS_ON), None, true, true),
            (Some(WS_ON), Some(rc_off), true, true),
            (Some(ws_off), Some(RC_ON), false, true),
            // Every major agrees.
            (Some(WS_ON), Some(RC_ON), true, false),
            (None, Some(rc_off), false, false),
            (None, None, false, false),
            (Some(ws_off), None, false, false),
            (Some(ws_off), Some(rc_off), false, false),
        ] {
            assert_eq!(include(&text, ws, rc, None), on, "{ws:?} {rc:?}");
            assert_eq!(guessed(&text, ws, rc, None), guess, "{ws:?} {rc:?}");
        }
        // Evidence: a known pnpm major, a pre-9 lock, lock entries.
        for major in [9, 10, 11] {
            assert!(!guessed(&text, None, Some(RC_ON), Some(major)));
            assert!(!guessed(&text, Some(WS_ON), None, Some(major)));
        }
        assert!(!guessed(
            &text.replace("'9.0'", "'6.0'"),
            None,
            Some(RC_ON),
            None
        ));
        let conventional = "  c@3.0.0:\n    resolution: {integrity: sha512-C==, \
                            tarball: https://registry.npmjs.org/c/-/c-3.0.0.tgz}\n";
        assert!(!guessed(&lock(conventional), None, Some(RC_ON), None));
        // An unconventional sibling is no evidence: still a guess.
        let cdn = "  d@1.0.0:\n    resolution: {integrity: sha512-D==, \
                   tarball: https://cdn.example/d.tgz}\n";
        assert!(guessed(&lock(cdn), None, Some(RC_ON), None));
    }

    /// The guess warning names what was followed, which pnpm reads it the
    /// other way, and remedies that hold on every pnpm: a pin, or the two
    /// files agreeing (never moving the setting, which pnpm 9 would lose).
    #[test]
    fn pnpm_tarball_guess_warning_names_the_disagreeing_pnpm() {
        let rel = "apps/web/pnpm-lock.yaml";
        let npmrc_only = PnpmTarballGuess {
            workspace: None,
            npmrc: Some(true),
        };
        let detail = pnpm_tarball_guess_warning(rel, "apps/web/", npmrc_only, false, &["a@1.0.0"]);
        for needle in [
            "apps/web/pnpm-lock.yaml: nothing shows which pnpm wrote this lock",
            "no unpinned registry entry that shows the setting",
            "from `lockfile-include-tarball-url=true` in apps/web/.npmrc",
            "restores a@1.0.0 with `tarball:`",
            "pnpm >= 11 reads only apps/web/pnpm-workspace.yaml (`lockfileIncludeTarballUrl` \
             unset) and would leave it out",
            "apps/web/package.json `packageManager`",
            "reinstall",
            "the same value",
            "restoring apps/web/pnpm-lock.yaml from version control and re-running",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        assert!(!detail.contains("pnpm 9 reads"), "{detail}");
        assert!(!detail.contains("move the setting"), "{detail}");
        assert!(!detail.contains("wrote `tarball:`"), "{detail}");

        let workspace_off = PnpmTarballGuess {
            workspace: Some(false),
            npmrc: Some(true),
        };
        let detail =
            pnpm_tarball_guess_warning("pnpm-lock.yaml", "", workspace_off, false, &["a@1.0.0"]);
        for needle in [
            "from `lockfileIncludeTarballUrl: false` in pnpm-workspace.yaml",
            "restores a@1.0.0 without `tarball:`",
            "pnpm 9 reads only .npmrc (`lockfile-include-tarball-url=true`) and would keep it",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
        assert!(!detail.contains("pnpm >= 11 reads"), "{detail}");

        // A Rush lock: the pin is rush.json's, at the Rush root.
        let detail = pnpm_tarball_guess_warning(
            "repo/common/config/rush/pnpm-lock.yaml",
            "repo/common/config/rush/",
            npmrc_only,
            true,
            &["a@1.0.0"],
        );
        assert!(
            detail.contains("no repo/rush.json `pnpmVersion`"),
            "{detail}"
        );
        assert!(
            detail.contains("set repo/rush.json `pnpmVersion`"),
            "{detail}"
        );
        assert!(!detail.contains("packageManager"), "{detail}");
        assert!(!detail.contains(".modules.yaml"), "{detail}");
    }

    #[test]
    fn rush_lock_roots_and_pnpm_version() {
        assert_eq!(
            rush_lock_root("common/config/rush/pnpm-lock.yaml"),
            Some("")
        );
        assert_eq!(
            rush_lock_root("repo/common/config/rush/pnpm-lock.yaml"),
            Some("repo/")
        );
        assert_eq!(
            rush_lock_root("common/config/subspaces/web/pnpm-lock.yaml"),
            Some("")
        );
        assert_eq!(rush_lock_root("xcommon/config/rush/pnpm-lock.yaml"), None);
        assert_eq!(rush_lock_root("pnpm-lock.yaml"), None);
        assert_eq!(
            rush_lock_root("common/config/subspaces/pnpm-lock.yaml"),
            None
        );
        let rush_json =
            "{\n  // \"pnpmVersion\": \"8.0.0\",\n  /* c */ \"pnpmVersion\": \"9.15.9\",\n  \
                         \"projects\": [],\n}\n";
        assert_eq!(rush_json_pnpm_major(rush_json), Some(9));
        assert_eq!(rush_json_pnpm_major("{ \"npmVersion\": \"10.0.0\" }"), None);
    }

    /// #902 tier 1: the lock's unpinned registry resolutions decide.
    #[test]
    fn pnpm_include_tarball_follows_lock_evidence() {
        let bare = "  b@2.0.0:\n    resolution: {integrity: sha512-B==}\n";
        let conventional = "  c@3.0.0:\n    resolution: {integrity: sha512-C==, \
                            tarball: https://registry.npmjs.org/c/-/c-3.0.0.tgz}\n";
        // A bare sibling: the setting was off, whatever .npmrc says.
        assert!(!include(&lock(bare), None, Some(RC_ON), None));
        assert!(!include(&lock(bare), Some(WS_ON), Some(RC_ON), Some(10)));
        // A derivable tarball on the sibling: it was on, with no setting seen.
        assert!(include(&lock(conventional), None, None, Some(9)));
        // Mixed: bare wins (the conventional one is under a second registry).
        let mixed = format!("{bare}{conventional}");
        assert!(!include(&lock(&mixed), None, Some(RC_ON), None));
        // Unconventional, `file:`, git and integrity-less entries are no
        // evidence either way: the settings decide.
        for silent in [
            "  d@1.0.0:\n    resolution: {integrity: sha512-D==, tarball: https://cdn.example/d.tgz}\n",
            "  e@file:.socket/vendor/npm/x/e-1.0.0.tgz:\n    resolution: {integrity: sha512-E==, tarball: file:.socket/vendor/npm/x/e-1.0.0.tgz}\n",
            "  f@1.0.0:\n    resolution: {integrity: sha512-F==, tarball: file:x.tgz}\n",
            "  g@1.0.0:\n    resolution: {type: git, repo: https://g.example/g, commit: abc}\n",
            "  h@1.0.0:\n    resolution: {tarball: https://registry.npmjs.org/h/-/h-1.0.0.tgz}\n",
        ] {
            assert!(include(&lock(silent), None, Some(RC_ON), None), "{silent}");
            assert!(!include(&lock(silent), None, None, None), "{silent}");
        }
    }

    /// #902: pnpm 11+'s env lockfile document (as `pnpm add --config`
    /// writes it, pnpm 11.27.0) records config dependencies bare even under
    /// lockfileIncludeTarballUrl; only the main document is evidence.
    #[test]
    fn pnpm_include_tarball_ignores_the_env_lockfile_document() {
        let env = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    \
                   configDependencies:\n      is-number:\n        specifier: 7.0.0\n        \
                   version: 7.0.0\n\npackages:\n\n  is-number@7.0.0:\n    \
                   resolution: {integrity: sha512-N==}\n\nsnapshots:\n\n  \
                   is-number@7.0.0: {}\n\n---\n";
        let conventional = "  c@3.0.0:\n    resolution: {integrity: sha512-C==, \
                            tarball: https://registry.npmjs.org/c/-/c-3.0.0.tgz}\n";
        let two_docs = format!("{env}{}", lock(conventional));
        assert!(include(&two_docs, None, None, Some(11)));
        // No evidence in the main document: the settings decide, not the
        // env document's bare entry.
        let pinned_only = format!("{env}{}", lock(""));
        assert!(include(&pinned_only, Some(WS_ON), None, Some(11)));
        assert!(!include(&pinned_only, None, None, Some(11)));
        // With no install record or pin, the env document itself proves
        // pnpm >= 11, which ignores `.npmrc`'s lockfile-include-tarball-url
        // (a fresh clone of the issue's repro).
        assert!(!include(&pinned_only, None, Some(RC_ON), None));
        assert!(include(&pinned_only, Some(WS_ON), Some(RC_ON), None));
        // A one-document lock with no pin keeps pnpm 10's reading.
        assert!(include(&lock(""), None, Some(RC_ON), None));
        // A lone leading `---` marker is no env document.
        let marker_only = format!("---\n{}", lock(""));
        assert!(include(&marker_only, None, Some(RC_ON), None));
        // A bare entry in the main document still proves it off.
        let bare = "  b@2.0.0:\n    resolution: {integrity: sha512-B==}\n";
        assert!(!include(
            &format!("{env}{}", lock(bare)),
            Some(WS_ON),
            None,
            Some(11)
        ));
    }

    /// #902 tier 2: the settings file the installed pnpm major reads.
    #[test]
    fn pnpm_include_tarball_reads_the_settings_file_of_the_pnpm_major() {
        let text = lock("");
        // pnpm <= 9 ignores pnpm-workspace.yaml settings.
        assert!(!include(&text, Some(WS_ON), None, Some(9)));
        assert!(include(&text, None, Some(RC_ON), Some(9)));
        // pnpm 10 reads both, the workspace file winning.
        assert!(include(&text, Some(WS_ON), None, Some(10)));
        assert!(include(&text, None, Some(RC_ON), Some(10)));
        let ws_off = "lockfileIncludeTarballUrl: false\n";
        assert!(!include(&text, Some(ws_off), Some(RC_ON), Some(10)));
        // pnpm 11+ ignores pnpm settings in .npmrc.
        for major in [11, 12] {
            assert!(!include(&text, None, Some(RC_ON), Some(major)));
            assert!(include(&text, Some(WS_ON), None, Some(major)));
        }
        // Unknown major: pnpm 10's reading.
        assert!(include(&text, Some(WS_ON), None, None));
        assert!(include(&text, None, Some(RC_ON), None));
        // js-yaml reads `True` / `TRUE` as true in the workspace file.
        for on in ["True", "TRUE", "'true'"] {
            let ws = format!("lockfileIncludeTarballUrl: {on}\n");
            assert!(include(&text, Some(&ws), None, Some(11)), "{on}");
            assert!(include(&text, Some(&ws), None, None), "{on}");
        }
        // Only pnpm <= 8 writes a pre-9 lock or a shrinkwrap.yaml.
        let v6 = text.replace("'9.0'", "'6.0'");
        assert!(!include(&v6, Some(WS_ON), None, None));
        assert!(include(&v6, None, Some(RC_ON), None));
        let shrinkwrap = format!(
            "shrinkwrapVersion: 3\n{}",
            text.replace("lockfileVersion: '9.0'\n", "")
        );
        assert!(!include(&shrinkwrap, Some(WS_ON), None, None));
    }

    #[test]
    fn pnpm_major_from_install_record_and_package_json() {
        let json = "{\n  \"layoutVersion\": 5,\n  \"packageManager\": \"pnpm@11.28.3\"\n}\n";
        assert_eq!(modules_yaml_pnpm_major(json), Some(11));
        assert_eq!(
            modules_yaml_pnpm_major("\u{feff}layoutVersion: 5\npackageManager: pnpm@9.15.9\n"),
            Some(9)
        );
        assert_eq!(
            modules_yaml_pnpm_major("packageManager: 'pnpm@8.6.0'\n"),
            Some(8)
        );
        assert_eq!(
            modules_yaml_pnpm_major("packageManager: yarn@4.0.0\n"),
            None
        );
        assert_eq!(modules_yaml_pnpm_major("{}"), None);
        assert_eq!(
            package_json_pnpm_major(r#"{"packageManager":"pnpm@10.4.1+sha512.abc"}"#),
            Some(10)
        );
        assert_eq!(
            package_json_pnpm_major(r#"{"packageManager":"npm@10.0.0"}"#),
            None
        );
        assert_eq!(package_json_pnpm_major("not json"), None);
    }

    #[test]
    fn pnpm_reads_the_npmrc_registry_and_scope_registries() {
        let rc_lookup = |rc, name| pnpm_lookup_registry(None, rc, None, name);
        let rc = "registry=https://m.example/npm/\n@s:registry = https://s.example/\n";
        assert_eq!(
            rc_lookup(Some(rc), "a").as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            rc_lookup(Some(rc), "@s/a").as_deref(),
            Some("https://s.example/")
        );
        // Another scope, and a name merely starting with the scope's text,
        // resolve against `registry`.
        assert_eq!(
            rc_lookup(Some(rc), "@t/a").as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            rc_lookup(Some("@s:registry=https://s.example\n"), "a"),
            None
        );
        assert_eq!(rc_lookup(None, "@s/a"), None);
        // An unexpanded `${VAR}` is never fetched as a URL; a scoped name
        // whose scope registry holds one keeps the default, not `registry`.
        assert_eq!(rc_lookup(Some("registry=${MIRROR}\n"), "a"), None);
        assert_eq!(
            rc_lookup(
                Some("registry=https://m.example\n@s:registry=${S}/npm\n"),
                "@s/a"
            ),
            None
        );
        // pnpm derives a scoped package's tarball under its scope registry,
        // so that registry's conventional URL stays out of the lock.
        let scope = rc_lookup(Some(rc), "@s/a");
        assert!(registry_derives_tarball(
            scope.as_deref(),
            "@s/a",
            "1.0.0",
            "https://s.example/@s/a/-/a-1.0.0.tgz"
        ));
    }

    /// #919: pnpm 10+ also read registries from pnpm-workspace.yaml, each
    /// major its own way (measured with pnpm 9.15, 10.34 and 11.27).
    #[test]
    fn pnpm_reads_the_workspace_registries_of_the_pnpm_major() {
        let rc = "registry=https://rc.example/\n@s:registry=https://rc-s.example/\n";
        let ws_registry = "packages:\n  - '.'\nregistry: https://ws.example/\n";
        let ws_map = "registries:\n  default: https://ws-default.example/\n  \
                      '@s': https://ws-s.example/\n  # '@t': x\n  \
                      \"@u\": \"https://ws-u.example/\" # c\n";
        let get = pnpm_lookup_registry;
        // pnpm <= 9 reads only .npmrc.
        for major in [Some(8), Some(9)] {
            assert_eq!(get(Some(ws_registry), None, major, "a"), None);
            assert_eq!(get(Some(ws_map), None, major, "@s/a"), None);
            assert_eq!(
                get(Some(ws_map), Some(rc), major, "@s/a").as_deref(),
                Some("https://rc-s.example/")
            );
        }
        // pnpm 10: a workspace `registries` map replaces .npmrc's wholesale;
        // a workspace `registry:` is ignored.
        let ten = Some(10);
        assert_eq!(
            get(Some(ws_registry), Some(rc), ten, "a").as_deref(),
            Some("https://rc.example/")
        );
        assert_eq!(get(Some(ws_registry), None, ten, "a"), None);
        assert_eq!(
            get(Some(ws_map), Some(rc), ten, "@s/a").as_deref(),
            Some("https://ws-s.example/")
        );
        assert_eq!(
            get(
                Some("registries:\n  default: https://d.example/\n"),
                Some(rc),
                ten,
                "@s/a"
            )
            .as_deref(),
            Some("https://d.example/")
        );
        assert_eq!(
            get(Some(ws_map), Some(rc), ten, "a").as_deref(),
            Some("https://ws-default.example/")
        );
        // pnpm 11+ and an unknown major: merged, the workspace winning per key.
        for major in [Some(11), Some(12), None] {
            assert_eq!(
                get(Some(ws_registry), Some(rc), major, "a").as_deref(),
                Some("https://ws.example/")
            );
            // .npmrc's scope registry beats the workspace's `registry:`.
            assert_eq!(
                get(Some(ws_registry), Some(rc), major, "@s/a").as_deref(),
                Some("https://rc-s.example/")
            );
            assert_eq!(
                get(Some(ws_map), Some(rc), major, "@s/a").as_deref(),
                Some("https://ws-s.example/")
            );
            assert_eq!(
                get(Some(ws_map), Some(rc), major, "@u/a").as_deref(),
                Some("https://ws-u.example/")
            );
            // A commented-out scope falls through to `default`.
            assert_eq!(
                get(Some(ws_map), Some(rc), major, "@t/a").as_deref(),
                Some("https://ws-default.example/")
            );
            let both = format!("{ws_registry}{ws_map}");
            assert_eq!(
                get(Some(&both), Some(rc), major, "a").as_deref(),
                Some("https://ws.example/")
            );
            assert_eq!(
                get(Some("registry: ${MIRROR}\n"), Some(rc), major, "a"),
                None
            );
        }
    }

    /// The `npmScopes` probe and `yaml_top_level_value` skip one leading
    /// BOM (`formats::text`, through `top_level_key`); a second one is
    /// content, so the first key is not `npmScopes`.
    #[test]
    fn berry_scopes_probe_reads_past_one_bom_only() {
        let lookup = |rc: &str, name: &str| {
            berry_lookup_registry(&[rc.to_string()], None, name, &|_: &str| None).unwrap()
        };
        let rc = "npmScopes:\n  s:\n    npmRegistryServer: https://s.example\n\
                  npmRegistryServer: https://m.example/\n";
        for bom in ["", "\u{feff}"] {
            let rc = format!("{bom}{rc}");
            assert_eq!(lookup(&rc, "@s/a").as_deref(), Some("https://s.example"));
        }
        let rc = format!("\u{feff}\u{feff}{rc}");
        assert_eq!(lookup(&rc, "@s/a").as_deref(), Some("https://m.example/"));
        let rc = "npmRegistryServer: https://m.example/\n";
        for bom in ["", "\u{feff}"] {
            assert_eq!(
                yaml_top_level_value(&format!("{bom}{rc}"), "npmRegistryServer").as_deref(),
                Some("https://m.example/")
            );
        }
        assert_eq!(
            yaml_top_level_value(&format!("\u{feff}\u{feff}{rc}"), "npmRegistryServer"),
            None
        );
    }

    /// #1017: yarn resolves a package's registry from every settings
    /// source it merges, not only the project rc's top-level key.
    #[test]
    fn berry_reads_the_registry_from_every_yarn_settings_source() {
        let none = |_: &str| None::<String>;
        let lookup = |rcs: &[&str], env: Option<&str>, name: &str| {
            let rcs: Vec<String> = rcs.iter().map(|s| s.to_string()).collect();
            berry_lookup_registry(&rcs, env, name, &none)
        };
        let rc = "npmRegistryServer: \"https://m.example/npm/\"\n";
        assert_eq!(
            lookup(&[rc], None, "a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            lookup(&[rc], None, "@s/a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(lookup(&[], None, "a").unwrap(), None);

        // npmScopes: the scope's own server, else the top-level one.
        let scoped = format!(
            "{rc}npmScopes:\n  s:\n    npmAlwaysAuth: true\n    npmRegistryServer: \
             \"https://s.example\"\n  t:\n    npmAlwaysAuth: true\n"
        );
        assert_eq!(
            lookup(&[&scoped], None, "a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            lookup(&[&scoped], None, "@s/a").unwrap().as_deref(),
            Some("https://s.example")
        );
        assert_eq!(
            lookup(&[&scoped], None, "@t/a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            lookup(&[&scoped], None, "@u/a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );
        // A scope beats the env registry; the env registry beats every rc.
        let env = Some("https://env.example");
        assert_eq!(
            lookup(&[&scoped], env, "@s/a").unwrap().as_deref(),
            Some("https://s.example")
        );
        assert_eq!(
            lookup(&[&scoped], env, "a").unwrap().as_deref(),
            Some("https://env.example")
        );
        assert_eq!(
            lookup(&[], env, "a").unwrap().as_deref(),
            Some("https://env.example")
        );
        assert_eq!(
            lookup(&[rc], Some(" "), "a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );

        // Layers: the closer rc wins per key; a farther one (a parent
        // directory's, the home one) fills in what the closer one lacks.
        let parent = "npmRegistryServer: https://parent.example\n";
        let home = "npmScopes:\n  s:\n    npmRegistryServer: https://home-s.example\n";
        let project = "nodeLinker: node-modules\n";
        assert_eq!(
            lookup(&[project, parent, home], None, "a")
                .unwrap()
                .as_deref(),
            Some("https://parent.example")
        );
        assert_eq!(
            lookup(&[project, parent, home], None, "@s/a")
                .unwrap()
                .as_deref(),
            Some("https://home-s.example")
        );
        assert_eq!(
            lookup(&[rc, parent], None, "a").unwrap().as_deref(),
            Some("https://m.example/npm/")
        );

        // A flow-style npmScopes is not guessed at for a scoped name.
        let flow = "npmScopes: {s: {npmRegistryServer: https://s.example}}\n";
        assert!(lookup(&[flow], None, "@s/a").is_err());
        assert_eq!(
            lookup(&[flow, parent], None, "a").unwrap().as_deref(),
            Some("https://parent.example")
        );
    }

    #[test]
    fn berry_registry_values_expand_env_references_like_yarn() {
        let var = |name: &str| match name {
            "REG" => Some("https://reg.example".to_string()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        for (value, want) in [
            // A set variable is never expanded (the rc file must not pick
            // which of the process's variables lands in a requested URL).
            ("${REG}", Err(())),
            ("${REG:-https://d.example}", Err(())),
            ("${REG-https://d.example}", Err(())),
            ("${UNSET:-https://d.example}", Ok("https://d.example")),
            ("${UNSET-https://d.example}", Ok("https://d.example")),
            ("${EMPTY:-https://d.example}", Ok("https://d.example")),
            ("${EMPTY-https://d.example}", Ok("")),
            ("${EMPTY}", Ok("")),
            ("https://h/${REG}/x", Err(())),
            ("https://h/${UNSET:-m}/x", Ok("https://h/m/x")),
            ("plain $ {REG} ${", Ok("plain $ {REG} ${")),
            ("${UNSET}", Err(())),
        ] {
            assert_eq!(
                yarn_expand_env(value, &var).map_err(|_| ()),
                want.map(str::to_string),
                "{value}"
            );
        }
        let rc = "npmRegistryServer: \"${REG:-http://127.0.0.1:8792}\"\n";
        assert_eq!(
            berry_lookup_registry(&[rc.to_string()], None, "a", &|_: &str| None)
                .unwrap()
                .as_deref(),
            Some("http://127.0.0.1:8792")
        );
        let rc = "npmRegistryServer: \"${REG}\"\n";
        assert!(berry_lookup_registry(&[rc.to_string()], None, "a", &|_: &str| None).is_err());
    }

    #[test]
    fn npmjs_and_its_yarnpkg_alias_are_the_default_registry() {
        for base in [
            "https://registry.npmjs.org",
            "https://registry.npmjs.org/",
            "http://registry.yarnpkg.com/",
            "",
        ] {
            assert_eq!(non_default_registry(base), None, "{base:?}");
        }
        assert_eq!(
            non_default_registry("https://m.example/npm/").as_deref(),
            Some("https://m.example/npm")
        );
    }

    #[test]
    fn project_registry_decides_a_mirrors_tarball_urls() {
        // A metadata mirror that hands back the project registry's own URLs:
        // the package manager derives them, so they stay out of the lock.
        assert!(registry_derives_tarball(
            Some("https://r.example/npm/"),
            "a",
            "1.0.0",
            "https://r.example/npm/a/-/a-1.0.0.tgz"
        ));
        // No configured registry means npmjs (yarnpkg is its alias).
        assert!(registry_derives_tarball(
            None,
            "@s/p",
            "2.0.0",
            "https://registry.yarnpkg.com/@s%2fp/-/p-2.0.0.tgz"
        ));
        assert!(!registry_derives_tarball(
            Some("https://r.example/npm"),
            "a",
            "1.0.0",
            "https://cdn.example/files/a-1.0.0.tgz"
        ));
    }

    #[test]
    fn berry_locator_binds_only_an_underived_tarball() {
        assert_eq!(
            berry_registry_locator(
                Some("https://r.example"),
                "a",
                "1.0.0",
                "https://r.example/a/-/a-1.0.0.tgz"
            ),
            "a@npm:1.0.0"
        );
        assert_eq!(
            berry_registry_locator(
                Some("https://r.example"),
                "a",
                "1.0.0",
                "https://cdn.example/f/a.tgz"
            ),
            "a@npm:1.0.0::__archiveUrl=https%3A%2F%2Fcdn.example%2Ff%2Fa.tgz"
        );
    }

    #[test]
    fn yaml_settings_read_the_last_top_level_key() {
        let text = "\u{feff}npmRegistryServer: \"https://a.example\"\nnpmScopes:\n  s:\n    npmRegistryServer: https://s.example\nnpmRegistryServer: 'https://b.example' # last wins\n";
        assert_eq!(
            yaml_top_level_value(text, "npmRegistryServer").as_deref(),
            Some("https://b.example")
        );
        assert_eq!(yaml_top_level_value("packages: []\n", "registry"), None);
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A member lock (`sharedWorkspaceLockfile: false`) rolled back from
    /// the member itself reads the workspace root's settings above the
    /// project root, as pnpm does; a path shaped like a Rush subspace lock
    /// is a Rush lock only with its `rush.json`.
    #[tokio::test]
    async fn pnpm_settings_come_from_the_governing_workspace_root() {
        use super::super::View;
        use super::{pnpm_settings_prefix, read_sibling};

        let dir = tempfile::tempdir().unwrap();
        let ws = std::fs::canonicalize(dir.path()).unwrap();
        write(
            &ws,
            "pnpm-workspace.yaml",
            "packages:\n  - 'packages/*'\n  - 'common/config/subspaces/*'\n",
        );
        write(&ws, ".npmrc", "registry=https://ws.example/\n");
        write(&ws, "packages/a/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(
            &ws,
            "packages/a/.npmrc",
            "registry=https://member.example/\n",
        );
        let sub = "common/config/subspaces/x/pnpm-lock.yaml";
        write(&ws, sub, "lockfileVersion: '9.0'\n");

        let member = ws.join("packages/a");
        let mut view = View::new(&member);
        let prefix = pnpm_settings_prefix(&mut view, "pnpm-lock.yaml").await;
        // The prefix is shown without Windows' verbatim `\\?\` prefix,
        // which `canonicalize` added to `ws`.
        let shown = crate::utils::pnpm_workspace::without_verbatim_prefix(ws.clone());
        assert_eq!(
            prefix,
            format!("{}{}", shown.display(), std::path::MAIN_SEPARATOR)
        );
        assert_eq!(
            read_sibling(&mut view, &prefix, ".npmrc").await.as_deref(),
            Some("registry=https://ws.example/\n")
        );

        // Inside the view, as before.
        let mut view = View::new(&ws);
        assert_eq!(
            pnpm_settings_prefix(&mut view, "packages/a/pnpm-lock.yaml").await,
            ""
        );
        // Not a Rush lock without rush.json: a listed member.
        assert_eq!(pnpm_settings_prefix(&mut view, sub).await, "");
        write(&ws, "rush.json", "{}");
        let mut view = View::new(&ws);
        assert_eq!(
            pnpm_settings_prefix(&mut view, sub).await,
            "common/config/subspaces/x/"
        );
    }
}
