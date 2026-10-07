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

use regex::Regex;
use serde_json::Value;

use super::client::NpmDist;
use super::{Ctx, FormatResult, HostedPin, View};
use crate::utils::line_endings::{to_lf, LineEndings};
use crate::vendor::lock_inventory::npm_legacy_identity;

/// The pins by uuid.
pub(super) fn by_uuid<'p>(pins: &[&'p HostedPin]) -> BTreeMap<&'p str, &'p HostedPin> {
    pins.iter().map(|p| (p.uuid.as_str(), *p)).collect()
}

/// Resolve the dist of every `(uuid, name, version)` wanted from the
/// default registry, concurrently. A failed lookup refuses its pin.
pub(super) async fn fetch_dists(
    wanted: &BTreeSet<(String, String, String)>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), NpmDist> {
    fetch_dists_on(wanted, |_| None, ctx, result)
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

/// [`fetch_dists`], reading each version document from the registry the
/// project resolves `name` against (`registry(name)`; `None` means the
/// default registry), since a mirror's `dist.tarball` need not be the
/// default registry's (#521, #908). When the project's registry can't be
/// read (a private mirror that wants credentials the restore does not
/// send), the default registry's document is used, as before, and
/// `upstream_registry_fallback` says so.
pub(super) async fn fetch_dists_on(
    wanted: &BTreeSet<(String, String, String)>,
    registry: impl Fn(&str) -> Option<String>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), ProjectDist> {
    let lookups = wanted.iter().map(|(uuid, name, version)| {
        let project = registry(name).as_deref().and_then(non_default_registry);
        async move {
            let mut fell_back = None;
            let found = match project {
                Some(base) => match ctx.client.npm_dist_on(&base, name, version).await {
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

fn npm_lock_hits(lock: &Value, ctx: &Ctx<'_>) -> Vec<NpmHit> {
    let mut hits = Vec::new();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages {
            let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            let Some(uuid) = entry
                .get("resolved")
                .and_then(Value::as_str)
                .and_then(|u| ctx.hosted_uuid(u))
            else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(key_name)
                .to_string();
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            hits.push(NpmHit {
                pointer: format!("/packages/{}", json_pointer_escape(key)),
                uuid,
                name,
                version: version.to_string(),
            });
        }
    }
    if let Some(deps) = lock.get("dependencies").and_then(Value::as_object) {
        v2_hits(deps, "/dependencies", ctx, &mut hits, 0);
    }
    hits
}

fn v2_hits(
    deps: &serde_json::Map<String, Value>,
    prefix: &str,
    ctx: &Ctx<'_>,
    hits: &mut Vec<NpmHit>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    for (name, entry) in deps {
        let pointer = format!("{prefix}/{}", json_pointer_escape(name));
        // An alias node (`"lp": {"version": "npm:left-pad@1.3.0"}`) restores
        // its target's registry dist (#432).
        let (node_name, node_version) =
            npm_legacy_identity(name, entry.get("version").and_then(Value::as_str));
        if let (Some(uuid), Some(version)) = (
            entry
                .get("resolved")
                .and_then(Value::as_str)
                .and_then(|u| ctx.hosted_uuid(u)),
            node_version,
        ) {
            hits.push(NpmHit {
                pointer: pointer.clone(),
                uuid,
                name: node_name.to_string(),
                version: version.to_string(),
            });
        }
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            v2_hits(
                nested,
                &format!("{pointer}/dependencies"),
                ctx,
                hits,
                depth + 1,
            );
        }
    }
}

fn json_pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
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

/// Read `rel` through the view; a missing or unreadable file refuses every
/// pin discovery found in it.
pub(super) async fn read_or_refuse(
    view: &mut View<'_>,
    rel: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    result: &mut FormatResult,
) -> Option<String> {
    match view.read(rel).await {
        Ok(Some(text)) => Some(text),
        Ok(None) => {
            refuse_all_in(pins, rel, result, format!("{rel} no longer exists"));
            None
        }
        Err(e) => {
            refuse_all_in(pins, rel, result, e);
            None
        }
    }
}

pub(super) fn refuse_all_in(
    pins: &BTreeMap<&str, &HostedPin>,
    rel: &str,
    result: &mut FormatResult,
    why: String,
) {
    for pin in pins.values() {
        if pin.files.iter().any(|f| f == rel) {
            result.refuse(&pin.uuid, why.clone());
        }
    }
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
        if super::super::is_berry_lock(&raw) {
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
    use crate::vendor::yarn_classic_lock::{classic_block_is_git, split_key_patterns};

    let eol = LineEndings::of(raw);
    if eol == LineEndings::Mixed {
        refuse_all_in(pins, rel, result, format!("{rel} mixes line endings"));
        return;
    }
    let content = to_lf(raw);
    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolved_re =
        Regex::new(r#"\n {2}resolved "([^"]*)""#).expect("static resolved-line regex is valid");
    let integrity_re =
        Regex::new(r"\n {2}integrity [^\n]*").expect("static integrity-line regex is valid");
    let version_re =
        Regex::new(r#"\n {2}version "([^"]*)""#).expect("static version-line regex is valid");

    // (block index, uuid, name, version) per hosted block.
    let mut hits: Vec<(usize, String, String, String)> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let Some(uuid) = resolved_re
            .captures(block)
            .and_then(|c| ctx.hosted_uuid(&c[1]))
        else {
            continue;
        };
        if !pins.contains_key(uuid.as_str()) {
            continue;
        }
        let head = super::super::yarn_classic_block_head(block);
        // yarn 1 fetches a git pattern with git, from `resolved` (#363): a
        // registry tarball there fails every install just as the hosted one
        // does, and the block's own git source was never recorded.
        let patterns = head
            .as_ref()
            .map(|(key, _)| split_key_patterns(key))
            .unwrap_or_default();
        if classic_block_is_git(&patterns, None) {
            result.refuse(
                &uuid,
                format!(
                    "the {rel} entry wiring it installs from git; a registry tarball there \
                     would still be fetched with git"
                ),
            );
            continue;
        }
        let name = head.and_then(|(_, n)| n);
        let version = version_re.captures(block).map(|c| c[1].to_string());
        match (name, version) {
            (Some(name), Some(version)) => hits.push((i, uuid, name, version)),
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
    let mut changed = false;
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
        let resolved = format!(
            "\n  resolved \"{}{frag}\"",
            yarn_classic_tarball(dist).replace('$', "$$")
        );
        let mut block = resolved_re
            .replace(&blocks[i], resolved.as_str())
            .into_owned();
        if integrity_re.is_match(&block) {
            block = integrity_re
                .replace(&block, format!("\n  integrity {integrity}").as_str())
                .into_owned();
        }
        blocks[i] = block;
        result.handled.insert(uuid);
        changed = true;
    }
    if changed {
        view.write(rel, eol.restore(&blocks.join("\n\n")).into_owned());
    }
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

/// The value of the last top-level `key` in a YAML settings file
/// (pnpm-workspace.yaml, .yarnrc.yml), quotes removed.
fn yaml_top_level_value(text: &str, key: &str) -> Option<String> {
    use crate::formats::pnpm::workspace::top_level_key;
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .filter_map(top_level_key)
        .rfind(|(k, _)| k == key)
        .map(|(_, value)| value.trim_matches(['"', '\'']).to_string())
        .filter(|value| !value.is_empty())
}

/// The registry a berry restore reads `name`'s version document from:
/// `.yarnrc.yml`'s `npmRegistryServer`. A scoped package may resolve
/// against an `npmScopes` registry instead, so with such a block present
/// it keeps the default registry's document.
fn berry_lookup_registry(yarnrc: Option<&str>, name: &str) -> Option<String> {
    let text = yarnrc?;
    let has_scopes = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .filter_map(crate::formats::pnpm::workspace::top_level_key)
        .any(|(key, _)| key == "npmScopes");
    if has_scopes && name.starts_with('@') {
        return None;
    }
    yaml_top_level_value(text, "npmRegistryServer")
}

async fn restore_berry(
    view: &mut View<'_>,
    rel: &str,
    raw: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    use crate::vendor::yarn_berry_lock::resolution_selector_target;
    use crate::vendor::yarn_classic_lock::{split_berry_key_patterns, split_pattern};

    let (bom, body) = match raw.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", raw),
    };
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
    let eol = LineEndings::of(body);
    let content = to_lf(body).into_owned();
    let trimmed = content.trim_end_matches('\n');
    let trailing_newlines = content[trimmed.len()..].to_string();
    let mut blocks: Vec<String> = trimmed.split("\n\n").map(String::from).collect();
    let was_sorted = super::super::berry_entries_sorted(&blocks);
    let resolution_re = Regex::new(r#"\n {2}resolution: "([^"]*)""#)
        .expect("static resolution-line regex is valid");
    let checksum_re =
        Regex::new(r"\n {2}checksum: [^\n]*").expect("static checksum-line regex is valid");
    let version_re =
        Regex::new(r"\n {2}version: ([^\n]*)").expect("static version-line regex is valid");

    let mut pkg: Option<serde_json::Value> = pkg_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t.strip_prefix('\u{feff}').unwrap_or(t)).ok())
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
    }
    let mut hits: Vec<Hit> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let Some(resolution) = resolution_re.captures(block).map(|c| c[1].to_string()) else {
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
        let key = block
            .lines()
            .next()
            .and_then(|l| l.strip_suffix(':'))
            .unwrap_or("");
        let patterns = split_berry_key_patterns(key);
        let names: BTreeSet<String> = patterns
            .iter()
            .filter_map(|p| split_pattern(p).map(|(n, _)| n.to_string()))
            .collect();
        let version = version_re
            .captures(block)
            .map(|c| c[1].trim().trim_matches('"').to_string());
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
        });
    }
    // The registry's `dist.tarball` decides the restored locator: yarn binds
    // a tarball URL off the conventional path as `::__archiveUrl=` (#817).
    let wanted = hits
        .iter()
        .map(|h| (h.uuid.clone(), h.name.clone(), h.version.clone()))
        .collect();
    let project_registry = yarnrc
        .as_deref()
        .and_then(|text| yaml_top_level_value(text, "npmRegistryServer"));
    let registry = |name: &str| berry_lookup_registry(yarnrc.as_deref(), name);
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
            Ok(c) => crate::vendor::yarn_berry_lock::checksum_in_lock_spelling(&content, &c),
            Err(why) => {
                result.refuse(&uuid, format!("{name}@{version}: {why}"));
                continue;
            }
        };
        let Some(dist) = dists.get(&(name.clone(), version.clone())).map(|d| &d.dist) else {
            continue;
        };
        let resolution = format!(
            "\n  resolution: \"{}\"",
            berry_registry_locator(project_registry.as_deref(), &name, &version, &dist.tarball)
        )
        .replace('$', "$$");
        let mut block = resolution_re
            .replace(&blocks[idx], resolution.as_str())
            .into_owned();
        if checksum_re.is_match(&block) {
            block = checksum_re
                .replace(&block, format!("\n  checksum: {checksum}").as_str())
                .into_owned();
        }
        if let Some(key) = key {
            let body_lines = block
                .split_once('\n')
                .map(|(_, r)| r.to_string())
                .unwrap_or_default();
            block = format!("{key}:\n{body_lines}");
            moved.push(key);
        }
        blocks[idx] = block;
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
    super::super::berry_reposition_blocks(&mut blocks, &moved, was_sorted);
    let out = format!("{}{trailing_newlines}", blocks.join("\n\n"));
    view.write(rel, format!("{bom}{}", eol.restore(&out)));
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────

/// What decides whether pnpm records a resolution's `tarball:` in the lock
/// at `rel`, read from its sibling settings files.
struct PnpmTarballPolicy {
    /// `lockfileIncludeTarballUrl` in pnpm-workspace.yaml (pnpm 10+, which
    /// wins over `.npmrc`), else `lockfile-include-tarball-url` in `.npmrc`:
    /// every resolution carries its tarball.
    always: bool,
    /// The `.npmrc` `registry`, which pnpm derives tarball URLs from.
    registry: Option<String>,
}

async fn pnpm_tarball_policy(view: &mut View<'_>, rel: &str) -> PnpmTarballPolicy {
    use super::super::npmrc::npmrc_top_level_value;

    let dir_prefix = match rel.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/"),
        None => String::new(),
    };
    let workspace = view
        .read(&format!("{dir_prefix}pnpm-workspace.yaml"))
        .await
        .ok()
        .flatten();
    let npmrc = view
        .read(&format!("{dir_prefix}.npmrc"))
        .await
        .ok()
        .flatten();
    let npmrc_value = |key: &str| {
        npmrc
            .as_deref()
            .and_then(|text| npmrc_top_level_value(text, key))
            .map(|value| value.trim().to_string())
    };
    let always = workspace
        .as_deref()
        .and_then(|text| yaml_top_level_value(text, "lockfileIncludeTarballUrl"))
        .or_else(|| npmrc_value("lockfile-include-tarball-url"))
        .is_some_and(|value| value == "true");
    PnpmTarballPolicy {
        always,
        registry: npmrc_value("registry").filter(|value| !value.is_empty()),
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
        let dists = fetch_dists(&wanted, ctx, &mut result).await;
        let policy = pnpm_tarball_policy(view, rel).await;
        let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
        let mut handled: Vec<String> = Vec::new();
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
            let Some(dist) = dists.get(&(name.clone(), version.clone())) else {
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
            let restored = if policy.always
                || !registry_derives_tarball(
                    policy.registry.as_deref(),
                    name,
                    version,
                    &dist.tarball,
                ) {
                resolution.rewrite(integrity, &dist.tarball)
            } else {
                resolution.restore(integrity)
            };
            splices.push((resolution.range.clone(), restored));
            handled.push(uuid.clone());
        }
        // A refusal recorded after a splice was planned (a second instance
        // of the same pin) drops that pin's splices too.
        let splices: Vec<_> = splices
            .into_iter()
            .zip(&handled)
            .filter(|(_, u)| !result.refused.contains_key(*u))
            .map(|(s, _)| s)
            .collect();
        if splices.is_empty() {
            continue;
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
        for uuid in handled {
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
/// `registry`, then `bunfig.toml` `[install] registry` — Bun's own order.
/// `None` means Bun's default registry, npmjs.
fn bun_lookup_registry(
    npmrc: Option<&str>,
    bunfig: Option<&str>,
    env_registry: Option<&str>,
    name: &str,
) -> Option<String> {
    use super::super::npmrc::npmrc_top_level_value;

    fn url(value: &str) -> Option<String> {
        let value = value.trim().trim_matches(['"', '\'']);
        (value.starts_with("https://") || value.starts_with("http://")).then(|| value.to_string())
    }
    // A registry is a URL string or a table carrying `url`.
    fn toml_url(item: Option<&toml_edit::Item>) -> Option<String> {
        let item = item?;
        let value = item
            .as_str()
            .or_else(|| item.get("url").and_then(toml_edit::Item::as_str))?;
        url(value)
    }
    let bunfig = bunfig.and_then(|text| text.parse::<toml_edit::DocumentMut>().ok());
    let install = bunfig.as_ref().and_then(|doc| doc.get("install"));
    // The configured default registry before the environment applies.
    let configured = || {
        npmrc
            .and_then(|text| npmrc_top_level_value(text, "registry"))
            .and_then(|value| url(&value))
            .or_else(|| toml_url(install?.get("registry")))
    };
    if let Some((scope, _)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        if let Some(scoped) = npmrc
            .and_then(|text| npmrc_top_level_value(text, &format!("@{scope}:registry")))
            .and_then(|value| url(&value))
        {
            return Some(scoped);
        }
        let entry = install.and_then(|i| i.get("scopes")).and_then(|scopes| {
            scopes
                .get(scope)
                .or_else(|| scopes.get(format!("@{scope}")))
        });
        if let Some(entry) = entry {
            // A scope entry with no URL (a token only) takes the configured
            // default registry, never the environment's.
            if let Some(scoped) = toml_url(Some(entry)) {
                return Some(scoped);
            }
            if entry.is_table_like() && entry.get("url").is_none() {
                return configured();
            }
        }
    }
    env_registry.and_then(url).or_else(configured)
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

/// The settings beside a Bun lock that decide which registry Bun resolves
/// each package against, and so which tarball URL it recorded (#992).
pub(super) struct BunRegistrySettings {
    npmrc: Option<String>,
    bunfig: Option<String>,
    env_registry: Option<String>,
}

impl BunRegistrySettings {
    pub(super) async fn read(view: &mut View<'_>, rel: &str) -> Self {
        let dir_prefix = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => String::new(),
        };
        let npmrc = view
            .read(&format!("{dir_prefix}.npmrc"))
            .await
            .ok()
            .flatten();
        let bunfig = view
            .read(&format!("{dir_prefix}bunfig.toml"))
            .await
            .ok()
            .flatten();
        // Unit tests read no ambient registry: npm exports
        // `npm_config_registry` to child processes whenever one is
        // configured, which would otherwise steer the fixtures' restores.
        let env_registry = if cfg!(test) {
            None
        } else {
            bun_env_registry(|key| std::env::var(key).ok())
        };
        Self {
            npmrc,
            bunfig,
            env_registry,
        }
    }

    /// The registry Bun resolves `name` against; `None` means npmjs.
    pub(super) fn registry(&self, name: &str) -> Option<String> {
        bun_lookup_registry(
            self.npmrc.as_deref(),
            self.bunfig.as_deref(),
            self.env_registry.as_deref(),
            name,
        )
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
        // npmjs, so the restore reads the project's registry settings.
        let settings = BunRegistrySettings::read(view, rel).await;
        let dists = fetch_dists_on(&wanted, |n| settings.registry(n), ctx, &mut result).await;
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
        bun_registry_slot, bun_tarball_url, non_default_registry, registry_derives_tarball,
        yaml_top_level_value, ProjectDist,
    };
    use crate::patch::redirect::upstream::client::NpmDist;

    #[test]
    fn bun_reads_the_registry_in_bun_s_own_order() {
        let bunfig = "[install]\nregistry = \"https://b.example/\"\n\n\
                      [install.scopes]\ns = \"https://s.example/\"\n\"@t\" = { url = \"https://t.example/\", token = \"x\" }\n";
        let npmrc = "registry=https://n.example/\n@u:registry=https://u.example/\n";
        let lookup = |npmrc, bunfig, env, name| bun_lookup_registry(npmrc, bunfig, env, name);
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
    #[serial_test::serial]
    fn bun_writes_the_tarball_url_unless_it_is_on_npmjs() {
        let found = |tarball: &str, from_project| ProjectDist {
            dist: NpmDist {
                tarball: tarball.to_string(),
                integrity: None,
                shasum: None,
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

    #[test]
    fn berry_reads_the_project_registry_except_for_npm_scopes() {
        let rc = "npmRegistryServer: \"https://m.example/npm/\"\n";
        assert_eq!(
            berry_lookup_registry(Some(rc), "a").as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(
            berry_lookup_registry(Some(rc), "@s/a").as_deref(),
            Some("https://m.example/npm/")
        );
        let scoped = format!("{rc}npmScopes:\n  s:\n    npmRegistryServer: https://s.example\n");
        assert_eq!(
            berry_lookup_registry(Some(&scoped), "a").as_deref(),
            Some("https://m.example/npm/")
        );
        assert_eq!(berry_lookup_registry(Some(&scoped), "@s/a"), None);
        assert_eq!(berry_lookup_registry(None, "a"), None);
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
}
