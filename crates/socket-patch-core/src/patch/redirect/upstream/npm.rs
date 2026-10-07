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

/// The registry base a project names, unless it is the default registry
/// (npmjs, its registry.yarnpkg.com alias, or `SOCKET_NPM_REGISTRY`), whose
/// document [`fetch_dists`] already reads.
pub(super) fn non_default_registry(base: &str) -> Option<String> {
    use crate::vendor::registry_fetch::npm_registry_base;
    let base = base.trim().trim_end_matches('/');
    let host = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    let npmjs = matches!(host, "registry.npmjs.org" | "registry.yarnpkg.com");
    (!base.is_empty() && !npmjs && base != npm_registry_base()).then(|| base.to_string())
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
    /// pnpm's `lockfileIncludeTarballUrl` was in effect when it wrote the
    /// lock, so every resolution carries its tarball
    /// (see [`pnpm_include_tarball`]).
    always: bool,
    /// The sibling pnpm-workspace.yaml and `.npmrc`, and the pnpm major
    /// that reads them ([`pnpm_settings_major`]), which name the registry
    /// pnpm resolves a package against (see [`pnpm_lookup_registry`]).
    workspace: Option<String>,
    npmrc: Option<String>,
    major: Option<u32>,
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
/// (only pnpm <= 8 writes those).
fn pnpm_settings_major(text: &str, pm_major: Option<u32>) -> Option<u32> {
    use crate::formats::pnpm::lock_version_major;

    let legacy_lock = lock_version_major(text).is_some_and(|major| major < 9)
        || text
            .lines()
            .any(|line| line.starts_with("shrinkwrapVersion:"));
    pm_major.or(legacy_lock.then_some(8))
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
///    visible through tier 1.
fn pnpm_include_tarball(
    text: &str,
    workspace: Option<&str>,
    npmrc: Option<&str>,
    pm_major: Option<u32>,
    is_hosted: impl Fn(&str) -> bool,
) -> bool {
    use super::super::npmrc::npmrc_top_level_value;

    let major = pnpm_settings_major(text, pm_major);
    let registry = |name: &str| pnpm_lookup_registry(workspace, npmrc, major, name);
    if let Some(evidence) = pnpm_lock_tarball_evidence(text, registry, is_hosted) {
        return evidence;
    }
    let from_workspace =
        || workspace.and_then(|text| yaml_top_level_value(text, "lockfileIncludeTarballUrl"));
    let from_npmrc = || {
        npmrc
            .and_then(|text| npmrc_top_level_value(text, "lockfile-include-tarball-url"))
            .map(|value| value.trim().to_string())
    };
    let value = match major {
        Some(major) if major <= 9 => from_npmrc(),
        Some(major) if major >= 11 => from_workspace(),
        _ => from_workspace().or_else(from_npmrc),
    };
    value.is_some_and(|value| value == "true")
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

/// The text of `name` next to the lock (`dir_prefix`); `None` when absent
/// or unreadable.
async fn read_sibling(view: &mut View<'_>, dir_prefix: &str, name: &str) -> Option<String> {
    view.read(&format!("{dir_prefix}{name}"))
        .await
        .ok()
        .flatten()
}

async fn pnpm_tarball_policy(
    view: &mut View<'_>,
    rel: &str,
    text: &str,
    ctx: &Ctx<'_>,
) -> PnpmTarballPolicy {
    let dir_prefix = match rel.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/"),
        None => String::new(),
    };
    let workspace = read_sibling(view, &dir_prefix, "pnpm-workspace.yaml").await;
    let npmrc = read_sibling(view, &dir_prefix, ".npmrc").await;
    // What installed the project, else what it pins.
    let mut pm_major = read_sibling(view, &dir_prefix, "node_modules/.modules.yaml")
        .await
        .as_deref()
        .and_then(modules_yaml_pnpm_major);
    if pm_major.is_none() {
        pm_major = read_sibling(view, &dir_prefix, "package.json")
            .await
            .as_deref()
            .and_then(package_json_pnpm_major);
    }
    let always = pnpm_include_tarball(
        text,
        workspace.as_deref(),
        npmrc.as_deref(),
        pm_major,
        |url| ctx.hosted_uuid(url).is_some(),
    );
    PnpmTarballPolicy {
        always,
        workspace,
        npmrc,
        major: pnpm_settings_major(text, pm_major),
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
            let restored = if policy.always
                || !registry_derives_tarball(
                    policy.registry(name).as_deref(),
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
        let dists = fetch_dists(&wanted, ctx, &mut result).await;
        let mut changed = false;
        for (line_idx, uuid, name, version, deps) in hits {
            if result.refused.contains_key(&uuid) {
                continue;
            }
            let Some(integrity) = dists
                .get(&(name.clone(), version.clone()))
                .and_then(|d| d.integrity.clone())
            else {
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
            lines[line_idx] = format!(
                "{indent}{key}: [{spec}, \"\", {deps}, {integrity}]{comma}{cr}",
                indent = entry.indent,
                key = entry.key_raw,
                spec = json(&format!("{name}@{version}")),
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
        berry_lookup_registry, berry_registry_locator, modules_yaml_pnpm_major,
        non_default_registry, package_json_pnpm_major, pnpm_include_tarball, pnpm_lookup_registry,
        registry_derives_tarball, yaml_top_level_value,
    };

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
        pnpm_include_tarball(text, ws, rc, major, |url| url == HOSTED)
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
