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

/// The pins by uuid.
pub(super) fn by_uuid<'p>(pins: &[&'p HostedPin]) -> BTreeMap<&'p str, &'p HostedPin> {
    pins.iter().map(|p| (p.uuid.as_str(), *p)).collect()
}

/// Resolve the dist of every `(uuid, name, version)` wanted, concurrently.
/// A failed lookup refuses its pin.
pub(super) async fn fetch_dists(
    wanted: &BTreeSet<(String, String, String)>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> BTreeMap<(String, String), NpmDist> {
    let lookups = wanted.iter().map(|(uuid, name, version)| async move {
        (
            uuid.clone(),
            name.clone(),
            version.clone(),
            ctx.client.npm_dist(name, version).await,
        )
    });
    let mut out = BTreeMap::new();
    for (uuid, name, version, dist) in futures_util::future::join_all(lookups).await {
        match dist {
            Ok(dist) => {
                out.insert((name, version), dist);
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
        if let (Some(uuid), Some(version)) = (
            entry
                .get("resolved")
                .and_then(Value::as_str)
                .and_then(|u| ctx.hosted_uuid(u)),
            entry.get("version").and_then(Value::as_str),
        ) {
            hits.push(NpmHit {
                pointer: pointer.clone(),
                uuid,
                name: name.clone(),
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
        let Ok(mut lock) = serde_json::from_str::<Value>(&text) else {
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
            view.write(rel, super::super::serialize_json(&lock));
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
        let name = super::super::yarn_classic_block_head(block).and_then(|(_, n)| n);
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

async fn restore_berry(
    view: &mut View<'_>,
    rel: &str,
    raw: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    use crate::vendor::yarn_classic_lock::{split_berry_key_patterns, split_pattern};

    let (bom, body) = match raw.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", raw),
    };
    let yarnrc_rel = match rel.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/.yarnrc.yml"),
        None => ".yarnrc.yml".to_string(),
    };
    let yarnrc = view.read(&yarnrc_rel).await.ok().flatten();
    if let Err(w) = super::super::preflight_yarn_berry_hosted(raw, yarnrc.as_deref()) {
        refuse_all_in(pins, rel, result, w.detail);
        return;
    }
    let eol = LineEndings::of(body);
    let content = to_lf(body).into_owned();
    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolution_re = Regex::new(r#"\n {2}resolution: "([^"]*)""#)
        .expect("static resolution-line regex is valid");
    let checksum_re =
        Regex::new(r"\n {2}checksum: [^\n]*").expect("static checksum-line regex is valid");
    let version_re =
        Regex::new(r"\n {2}version: ([^\n]*)").expect("static version-line regex is valid");

    let mut hits: Vec<(usize, String, String, String)> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let Some(resolution) = resolution_re.captures(block).map(|c| c[1].to_string()) else {
            continue;
        };
        let Some((_, archive)) = resolution.split_once("::__archiveUrl=") else {
            continue;
        };
        let archive = archive.split('&').next().unwrap_or(archive);
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
        match (names.len(), names.into_iter().next(), version) {
            (1, Some(name), Some(version)) => hits.push((i, uuid, name.to_string(), version)),
            _ => result.refuse(
                &uuid,
                format!("a {rel} entry wiring it names no single package and version"),
            ),
        }
    }
    let mut changed = false;
    for (i, uuid, name, version) in hits {
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
        let resolution = format!("\n  resolution: \"{name}@npm:{version}\"").replace('$', "$$");
        let mut block = resolution_re
            .replace(&blocks[i], resolution.as_str())
            .into_owned();
        if checksum_re.is_match(&block) {
            block = checksum_re
                .replace(&block, format!("\n  checksum: {checksum}").as_str())
                .into_owned();
        }
        blocks[i] = block;
        result.handled.insert(uuid);
        changed = true;
    }
    if changed {
        view.write(rel, format!("{bom}{}", eol.restore(&blocks.join("\n\n"))));
    }
}

// ── pnpm-lock.yaml ───────────────────────────────────────────────────────────

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
            let Some(integrity) = dists
                .get(&(name.clone(), version.clone()))
                .and_then(|d| d.integrity.clone())
            else {
                result.refuse(
                    uuid,
                    format!("the registry records no integrity for {name}@{version}"),
                );
                continue;
            };
            splices.push((resolution.range.clone(), resolution.restore(&integrity)));
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
