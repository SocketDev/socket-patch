//! yarn lockfiles: classic (`yarn.lock` v1) and berry (yarn 2+ `yarn.lock`,
//! recognizable by its top-level `__metadata:` block), hosted and vendored.
//!
//! The root `yarn.lock` is read once and dispatched on its grammar with the
//! rewriters' own sniff ([`is_berry_lock`]: `(?m)^__metadata:` ⇒ berry).
//! Both grammars are
//! read through the entry models the lock inventory shares
//! ([`classic_entries`] / [`berry_entries`], over the vendor backends' own
//! block scanner: key line at column 0 ending `:`, indented body,
//! CRLF-aware), so discovery sees exactly the blocks the writers edit.
//!
//! **Last block wins.** yarn parses a lock into an object, so a descriptor
//! (key pattern) repeated on a later block — a mangled merge — shadows the
//! earlier one. A block is read only while at least one of its patterns is
//! not re-keyed by a later block: a stale Socket block shadowed by a
//! registry re-lock wires nothing.
//!
//! ## Classic (`yarn.lock` v1)
//!
//! A block `name@range[, name@range2]:` with `version "X"` and
//! `resolved "<spec>"`. The package is the REAL name of the key patterns
//! (`alias@npm:real@range` names `real` —
//! [`crate::vendor::yarn_classic_lock::pattern_real_name`]); every pattern
//! must agree, otherwise a Socket-wired block is diagnosed (the rewriters
//! refuse mixed keys). `link:` keys are skipped: yarn installs them from the
//! working tree, never from `resolved`.
//!
//! * **Hosted** (`patch::redirect::rewrite_yarn_classic`):
//!   `resolved "<socket artifact url>[#<sha1>]"` → [`DiscoverCtx::hosted_uuid`]
//!   (the `#sha1` fragment is ignored there). Pin: the `integrity` SRI line,
//!   else the 40-hex `#<sha1>` fragment (yarn v1 enforces whichever is
//!   present). The rewriter refuses deps without a sha512 and always writes
//!   the `integrity` line, so `integrity_required = true`.
//! * **Vendored** (`vendor::yarn_classic_lock`):
//!   `resolved "file:./.socket/vendor/npm/<uuid>/<[@scope/]name-ver>.tgz#<sha1>"`
//!   → [`vendor_ref_decorated`] (fragment stripped). The leaf must name the block's own
//!   package ([`super::vendored_leaf_purl`]), like the npm extractor.
//!
//! ## Berry (yarn 2+)
//!
//! Every non-`__metadata` block's `resolution:` locator `name@<reference>`
//! names the package the entry installs (for an `npm:` alias key the
//! resolution carries the REAL ident); the version is the block's unquoted
//! `version:` line. `workspace:`, `patch:`, `portal:`, `link:`, `exec:`,
//! `git` and plain registry locators are not ours and are skipped silently.
//!
//! * **Hosted** (`patch::redirect::rewrite_yarn_berry`):
//!   `resolution: "name@npm:X::__archiveUrl=<encodeURIComponent(url)>"` —
//!   the `__archiveUrl` binding value (bindings are `&`-joined after `::`) is
//!   handed to [`DiscoverCtx::hosted_uuid`], which decodes a wholly
//!   percent-encoded url; a custom-registry `__archiveUrl` is not Socket's and
//!   is skipped. The locator's `npm:` version must equal `version:` (the
//!   rewriter writes both from the same coordinate). Hand-edit tolerance: a
//!   direct url locator `name@https://patch.socket.dev/…` (what a
//!   url-range dependency locks to) is accepted too. Pin: `checksum:`
//!   (`10c0/<hex>` — the cache-zip checksum, [`LockIntegrity::BerryChecksum`];
//!   yarn 4.0.x spells it as bare hex under `cacheKey: 10c0`, read as the
//!   same pin); the rewriter always writes it, so `integrity_required = true`.
//! * **Vendored** (`vendor::yarn_berry_lock`, spike B3 shape):
//!   key `"name@file:./<rel>::locator=<ws>"`, `version: X`, and
//!   `resolution: "name@file:./<rel>#./<rel>::hash=…&locator=…"` →
//!   [`vendor_ref_decorated`] on the locator reference (the `#…` / `::…`
//!   suffixes are stripped; the `#` selector must name the same artifact as
//!   the path before it). Berry only consumes that `file:` entry because the root
//!   `package.json` `resolutions` maps the package onto the same artifact
//!   (the dependency range itself still says `npm:`): without that mapping
//!   the entry is orphaned — `yarn install --immutable` fails and a plain
//!   install re-resolves from the registry — so the ref is emitted ONLY
//!   when a `resolutions` selector targeting the package (`name`,
//!   `name@range`, `**/name`, `parent/name`) points at the same
//!   `.socket/vendor/npm/<uuid>/<leaf>`; otherwise the entry is diagnosed
//!   ([`DIAG_REF_INVALID`]). A `resolutions` value into `.socket/vendor/`
//!   with no lock entry behind it is diagnosed as well (the lock was never
//!   re-resolved, so what installs is unknown). The pin is the `checksum:`
//!   line (informational — the committed artifact is hashed).
//!
//! In both grammars a `.socket/vendor/` reference that is root-anchored but
//! fails [`vendor_ref_decorated`] (a traversal leaf, a non-canonical uuid) is
//! diagnosed; a `../.socket/vendor/…` spelling points outside this project
//! (a sibling checkout's artifacts) and is skipped silently, as in the npm
//! extractor.

use serde_json::Value;

use super::{
    npm_purl, npm_vendored_tarball_names, parse_json, root_anchored_spelling, vendor_ref_decorated,
    DiscoverCtx, Discovery, LocateOpts, PatchedRef, VendorRef, Wired, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_REF_INVALID,
};
use crate::patch::redirect::is_berry_lock;
use crate::utils::digest::is_sri_pin;
use crate::vendor::lock_inventory::yarn::{
    berry_checksum_pin, berry_entries, classic_entries, BerryLock, YarnEntry,
};
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::yarn_berry_lock::{berry_field, resolution_selector_target, BerryLocator};
use crate::vendor::yarn_classic_lock::{
    classic_field, pattern_real_name, split_pattern, split_resolved_sha1,
};

const YARN_LOCK: &str = "yarn.lock";
const PACKAGE_JSON: &str = "package.json";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(text) = ctx.read_text(YARN_LOCK, out).await else {
        return;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if let Some(line) = stray_top_level_line(text) {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            YARN_LOCK,
            format!(
                "{YARN_LOCK} is not a yarn lockfile: top-level line {line:?} is neither a \
                 comment nor an entry key"
            ),
        );
        return;
    }
    if is_berry_lock(text) {
        extract_berry(ctx, berry_entries(text), out).await;
    } else {
        extract_classic(ctx, classic_entries(text), out);
    }
}

/// The first column-0 line that is neither blank, a `#` comment, nor an
/// entry key (`…:`) — both yarn grammars reject such a file, so nothing
/// read from it would be what yarn installs.
fn stray_top_level_line(text: &str) -> Option<&str> {
    text.lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .find(|l| !l.is_empty() && !l.starts_with([' ', '\t', '#']) && !l.ends_with(':'))
}

// ── classic ──────────────────────────────────────────────────────────────

fn extract_classic(ctx: &DiscoverCtx<'_>, entries: Vec<YarnEntry>, out: &mut Discovery) {
    for entry in entries {
        if entry.live && !entry.patterns.is_empty() {
            classic_block(ctx, &entry, out);
        }
    }
}

fn classic_block(ctx: &DiscoverCtx<'_>, entry: &YarnEntry, out: &mut Discovery) {
    let YarnEntry {
        block, patterns, ..
    } = entry;
    let Some(resolved) = classic_field(&block.lines, "resolved") else {
        return;
    };
    // `link:` ranges install from the working tree; `resolved` is inert.
    if patterns
        .iter()
        .any(|p| split_pattern(p).is_some_and(|(_, range)| range.starts_with("link:")))
    {
        return;
    }
    let names: std::collections::BTreeSet<Option<&str>> =
        patterns.iter().map(|p| pattern_real_name(p)).collect();
    let names: Vec<Option<&str>> = names.into_iter().collect();
    let Some(wiring) = classify(ctx, resolved, YARN_LOCK, &block.key, out) else {
        // Not Socket's (a rejected Socket spelling was diagnosed instead):
        // evidence against another lock's wiring of the same package.
        if let ([Some(name)], Some(version), false) = (
            names.as_slice(),
            classic_field(&block.lines, "version"),
            root_anchored_spelling(resolved),
        ) {
            out.resolved_elsewhere(YARN_LOCK, npm_purl(name, version));
        }
        return;
    };
    let name = match names.as_slice() {
        [Some(name)] => *name,
        _ => {
            out.diag(
                DIAG_REF_INVALID,
                YARN_LOCK,
                format!(
                    "{YARN_LOCK}: Socket-wired entry `{}` does not name exactly one package",
                    block.key
                ),
            );
            return;
        }
    };
    let Some(version) = classic_field(&block.lines, "version") else {
        out.diag(
            DIAG_REF_INVALID,
            YARN_LOCK,
            format!(
                "{YARN_LOCK}: Socket-wired entry `{}` has no version",
                block.key
            ),
        );
        return;
    };
    let integrity = classic_field(&block.lines, "integrity")
        .filter(|sri| is_sri_pin(sri))
        .map(|sri| LockIntegrity::Sri(sri.to_string()))
        .or_else(|| split_resolved_sha1(resolved).1.map(LockIntegrity::Sha1Hex));
    emit(name, version, resolved, wiring, integrity, &block.key, out);
}

// ── berry ────────────────────────────────────────────────────────────────

/// A berry lock entry wired to a committed artifact, awaiting its
/// `package.json` `resolutions` confirmation.
struct BerryVendored {
    name: String,
    purl: String,
    vref: VendorRef,
    integrity: Option<LockIntegrity>,
    key: String,
}

async fn extract_berry(ctx: &DiscoverCtx<'_>, lock: BerryLock, out: &mut Discovery) {
    let mut vendored: Vec<BerryVendored> = Vec::new();
    for entry in lock.entries.iter().filter(|e| e.live) {
        berry_block(ctx, entry, lock.cache_key.as_deref(), &mut vendored, out);
    }
    confirm_berry_vendored(ctx, vendored, out).await;
}

fn berry_block(
    ctx: &DiscoverCtx<'_>,
    entry: &YarnEntry,
    cache_key: Option<&str>,
    vendored: &mut Vec<BerryVendored>,
    out: &mut Discovery,
) {
    let block = &entry.block;
    let (Some(resolution), Some(locator)) = (entry.resolution(), entry.locator()) else {
        return;
    };
    let BerryLocator { name, reference } = locator;
    // The spec that carries the Socket identity, plus the version the
    // locator itself encodes (npm: locators only).
    let (spec, locator_version) = if let Some((version, _)) = locator.npm() {
        let Some(archive) = locator.archive_url() else {
            // A plain registry entry.
            let version = berry_field(&block.lines, "version").unwrap_or(version);
            out.resolved_elsewhere(YARN_LOCK, npm_purl(name, version));
            return;
        };
        (archive, Some(version))
    } else if reference.starts_with("file:") || reference.starts_with("http") {
        (reference, None)
    } else {
        return; // workspace: / patch: / portal: / link: / exec: / git
    };
    let Some(wiring) = classify(ctx, spec, YARN_LOCK, &block.key, out) else {
        // A custom-registry `__archiveUrl`: the registry package.
        if let (Some(v), false) = (locator_version, root_anchored_spelling(spec)) {
            let version = berry_field(&block.lines, "version").unwrap_or(v);
            out.resolved_elsewhere(YARN_LOCK, npm_purl(name, version));
        }
        return;
    };
    let Some(version) = berry_field(&block.lines, "version") else {
        out.diag(
            DIAG_REF_INVALID,
            YARN_LOCK,
            format!(
                "{YARN_LOCK}: Socket-wired entry `{}` has no version",
                block.key
            ),
        );
        return;
    };
    if locator_version.is_some_and(|v| v != version) {
        out.diag(
            DIAG_REF_INVALID,
            YARN_LOCK,
            format!(
                "{YARN_LOCK}: Socket-wired entry `{}` resolves {resolution:?} but records \
                 version {version:?}",
                block.key
            ),
        );
        return;
    }
    // yarn 4.0.x spells its `10c0` checksums as bare hex (4.1+ prefixes the
    // cache key); under cacheKey `10c0` a bare checksum is the same enforced
    // cache-zip pin.
    let integrity =
        berry_field(&block.lines, "checksum").and_then(|c| berry_checksum_pin(c, cache_key));
    match wiring {
        Wired::Vendored(vref) => {
            if !berry_selector_agrees(spec, &vref) {
                out.diag(
                    DIAG_REF_INVALID,
                    YARN_LOCK,
                    format!(
                        "{YARN_LOCK}: entry `{}` resolves {spec:?}, whose `#` selector does not \
                         name the same {} artifact as its path; it is ignored",
                        block.key, vref.artifact_rel
                    ),
                );
                return;
            }
            let Some(purl) = vendored_purl(name, version, spec, &vref, &block.key, out) else {
                return;
            };
            vendored.push(BerryVendored {
                name: name.to_string(),
                purl,
                vref,
                integrity,
                key: block.key.clone(),
            });
        }
        hosted => emit(name, version, spec, hosted, integrity, &block.key, out),
    }
}

/// Emit each berry vendored entry whose artifact the root `package.json`
/// `resolutions` routes the package to (see the module docs), and diagnose
/// the orphans on either side.
async fn confirm_berry_vendored(
    ctx: &DiscoverCtx<'_>,
    vendored: Vec<BerryVendored>,
    out: &mut Discovery,
) {
    // `(selector target name, selector, artifact)` for every resolutions
    // value that points into `.socket/vendor/`. A missing or malformed
    // package.json routes nothing; the malformed one is worth a diagnostic
    // only when it leaves a vendored entry unconfirmed (it is not a lock).
    let routes: Vec<(String, String, VendorRef)> = match ctx.read_bytes(PACKAGE_JSON, out).await {
        None => Vec::new(),
        Some(bytes) => {
            let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
            match parse_json(PACKAGE_JSON, bytes) {
                Ok(doc) => vendored_resolutions(&doc),
                Err(detail) => {
                    if !vendored.is_empty() {
                        out.diag(DIAG_LOCKFILE_UNPARSEABLE, PACKAGE_JSON, detail);
                    }
                    Vec::new()
                }
            }
        }
    };
    for entry in &vendored {
        let routed = routes.iter().any(|(target, _, vref)| {
            *target == entry.name && vref.artifact_rel == entry.vref.artifact_rel
        });
        if routed {
            out.push(PatchedRef::vendored(
                entry.purl.clone(),
                &entry.vref,
                YARN_LOCK,
                entry.integrity.clone(),
            ));
        } else {
            out.diag(
                DIAG_REF_INVALID,
                YARN_LOCK,
                format!(
                    "{YARN_LOCK}: vendored entry `{}` ({}) is orphaned: no {PACKAGE_JSON} \
                     `resolutions` entry maps the package onto {}, so yarn does not install it",
                    entry.key, entry.purl, entry.vref.artifact_rel
                ),
            );
        }
    }
    for (_, selector, vref) in &routes {
        if !vendored
            .iter()
            .any(|e| e.vref.artifact_rel == vref.artifact_rel)
        {
            out.diag(
                DIAG_REF_INVALID,
                PACKAGE_JSON,
                format!(
                    "{PACKAGE_JSON}: `resolutions` entry `{selector}` points at {} but \
                     {YARN_LOCK} has no entry resolving it (run `yarn install`)",
                    vref.artifact_rel
                ),
            );
        }
    }
}

/// `(target package name, selector, artifact)` for every root
/// `package.json` `resolutions` value that names a committed
/// `.socket/vendor/` artifact.
fn vendored_resolutions(doc: &Value) -> Vec<(String, String, VendorRef)> {
    let Some(res) = doc.get("resolutions").and_then(Value::as_object) else {
        return Vec::new();
    };
    res.iter()
        .filter_map(|(selector, value)| {
            let vref = vendor_ref_decorated(value.as_str()?)?;
            let target = resolution_selector_target(selector)?;
            Some((target.to_string(), selector.clone(), vref))
        })
        .collect()
}

// ── shared ───────────────────────────────────────────────────────────────

/// Classify `spec` (a classic `resolved`, a berry locator reference or
/// `__archiveUrl` value). `None` for anything not Socket's; a root-anchored
/// `.socket/vendor/` spelling that fails validation is diagnosed.
fn classify(
    ctx: &DiscoverCtx<'_>,
    spec: &str,
    file: &str,
    key: &str,
    out: &mut Discovery,
) -> Option<Wired> {
    let located = ctx.locate(spec, LocateOpts::DECORATED);
    if let Some(vref) = located.vendored {
        return Some(Wired::Vendored(vref));
    }
    if root_anchored_spelling(spec) {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: entry `{key}` is wired to {spec:?}, which is not a valid \
                 .socket/vendor/<eco>/<uuid>/<artifact> path"
            ),
        );
        return None;
    }
    located.hosted.map(Wired::Hosted)
}

/// A berry `file:` locator's `#` selector (what berry actually fetches for a
/// tarball locator bound to its parent: `file:./<rel>#./<rel>::…`) must name
/// the SAME artifact as the path before it — the leaf check runs on the
/// pre-`#` path, so a selector pointing elsewhere would attest one file
/// while yarn installs another. No selector is fine.
fn berry_selector_agrees(spec: &str, vref: &VendorRef) -> bool {
    let Some((_, selector)) = spec.split_once('#') else {
        return true;
    };
    let selector = selector.split("::").next().unwrap_or(selector);
    selector.is_empty()
        || super::vendor_ref(selector).is_some_and(|s| s.artifact_rel == vref.artifact_rel)
}

/// The purl of a vendored entry for `name@version`, or `None` (diagnosed)
/// when the coordinates are unsafe or the artifact leaf names another
/// package.
fn vendored_purl(
    name: &str,
    version: &str,
    spec: &str,
    vref: &VendorRef,
    key: &str,
    out: &mut Discovery,
) -> Option<String> {
    let purl = checked_purl(name, version, key, out)?;
    if !npm_vendored_tarball_names(vref, &purl) {
        out.diag(
            DIAG_REF_INVALID,
            YARN_LOCK,
            format!(
                "{YARN_LOCK}: {purl} (entry `{key}`) is wired to {spec:?}, which is not that \
                 package's vendored npm tarball"
            ),
        );
        return None;
    }
    Some(purl)
}

fn checked_purl(name: &str, version: &str, key: &str, out: &mut Discovery) -> Option<String> {
    let purl = npm_purl(name, version);
    if purl.is_none() {
        out.diag(
            DIAG_REF_INVALID,
            YARN_LOCK,
            format!(
                "{YARN_LOCK}: Socket-wired entry `{key}` has unsafe coordinates \
                 {name:?}@{version:?}"
            ),
        );
    }
    purl
}

/// Push the ref for a classic block or a berry hosted entry.
fn emit(
    name: &str,
    version: &str,
    spec: &str,
    wiring: Wired,
    integrity: Option<LockIntegrity>,
    key: &str,
    out: &mut Discovery,
) {
    match wiring {
        Wired::Hosted(uuid) => {
            let Some(purl) = checked_purl(name, version, key, out) else {
                return;
            };
            // Both yarn hosted rewriters always write the pin (classic:
            // `integrity sha512-…`; berry: `checksum: 10c0/…`).
            // Show berry's percent-encoded `__archiveUrl` value decoded.
            let url = if spec.to_ascii_lowercase().starts_with("http%3a") {
                crate::utils::purl::percent_decode_purl_component(spec)
            } else {
                std::borrow::Cow::Borrowed(spec)
            };
            out.push(PatchedRef::hosted(
                purl,
                uuid,
                YARN_LOCK,
                Some(&url),
                integrity,
                true,
            ));
        }
        Wired::Vendored(vref) => {
            let Some(purl) = vendored_purl(name, version, spec, &vref, key, out) else {
                return;
            };
            out.push(PatchedRef::vendored(purl, &vref, YARN_LOCK, integrity));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    const FIXTURE_UUID_CLASSIC: &str = "22222222-2222-2222-2222-222222222222";
    const FIXTURE_UUID_BERRY: &str = "77777777-7777-7777-7777-777777777777";
    const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
    const SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";
    const CHECKSUM: &str = "10c0/7785879d9a7dc9bee6730ec55926a0ab9ed6bfe0eaee0cbcbcf00841d42488fddda51265c73eeddd54c5deca87d131e846ff66d27d890ef73f12720b458d7ca3";

    const CLASSIC_HEADER: &str =
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n";
    const BERRY_HEADER: &str = "# This file is generated by running \"yarn install\" inside your project.\n# Manual changes might be lost - proceed with caution!\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n";
    const BERRY_WORKSPACE: &str = "\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  languageName: unknown\n  linkType: soft\n";

    fn classic_block(key: &str, version: &str, resolved: &str, integrity: Option<&str>) -> String {
        let mut b = format!("{key}:\n  version \"{version}\"\n  resolved \"{resolved}\"\n");
        if let Some(i) = integrity {
            b.push_str(&format!("  integrity {i}\n"));
        }
        b.push('\n');
        b
    }

    fn classic(blocks: &[String]) -> String {
        format!("{CLASSIC_HEADER}{}", blocks.concat())
    }

    fn berry_block(key: &str, version: &str, resolution: &str, checksum: Option<&str>) -> String {
        let mut b = format!("\"{key}\":\n  version: {version}\n  resolution: \"{resolution}\"\n");
        if let Some(c) = checksum {
            b.push_str(&format!("  checksum: {c}\n"));
        }
        b.push_str("  languageName: node\n  linkType: hard\n\n");
        b
    }

    fn berry(blocks: &[String]) -> String {
        format!("{BERRY_HEADER}{}{BERRY_WORKSPACE}", blocks.concat())
    }

    fn archive(url: &str) -> String {
        crate::utils::uri::encode_uri_component(url)
    }

    /// The vendored berry entry exactly as `vendor::yarn_berry_lock` writes it
    /// (spike B3 shape, root workspace `app`).
    fn berry_vendored_block(name: &str, version: &str, uuid: &str) -> String {
        let leaf = match name.split_once('/') {
            Some((scope, bare)) => format!("{scope}/{bare}-{version}.tgz"),
            None => format!("{name}-{version}.tgz"),
        };
        let rel = format!(".socket/vendor/npm/{uuid}/{leaf}");
        let locator = "app%40workspace%3A.";
        berry_block(
            &format!("{name}@file:./{rel}::locator={locator}"),
            version,
            &format!("{name}@file:./{rel}#./{rel}::hash=39ea9b&locator={locator}"),
            Some(CHECKSUM),
        )
    }

    fn package_json_with_resolutions(res: serde_json::Value) -> String {
        serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "dependencies": { "left-pad": "1.3.0" },
            "resolutions": res,
        })
        .to_string()
    }

    // ── classic ──────────────────────────────────────────────────────────

    /// The committed golden fixture (what `scan --mode hosted` / a depscan PR
    /// leaves behind): the uuid is the patch's, not the grant token's.
    #[tokio::test]
    async fn classic_golden_hosted_fixture() {
        for case in ["basic", "crlf"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/npm/yarn-classic/{case}/expected"));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[(
                    "pkg:npm/left-pad@1.3.0",
                    FIXTURE_UUID_CLASSIC,
                    WiringMode::Hosted,
                )],
            );
            let r = &out.refs[0];
            assert_eq!(r.source_file, std::path::PathBuf::from("yarn.lock"));
            assert!(r.integrity_required);
            assert!(r.lockfile_basis_ok(), "{case}: the golden lock pins sha512");
            assert!(matches!(r.locked_integrity, Some(LockIntegrity::Sri(_))));
            assert!(r
                .url
                .as_deref()
                .unwrap()
                .starts_with("https://patch.socket.dev/"));
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// Pre-rewrite inputs (registry-only locks, the alias-guard fork case)
    /// discover nothing, silently.
    #[tokio::test]
    async fn classic_registry_inputs_discover_nothing() {
        for case in ["basic", "crlf", "alias-guard"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/npm/yarn-classic/{case}/input"));
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{case}: {:#?}", out.refs);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// Multi-pattern keys, scoped names, and `npm:` alias keys: the purl is
    /// the REAL package every pattern stands for.
    #[tokio::test]
    async fn classic_hosted_scoped_multi_pattern_and_alias_keys() {
        let lp = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let core = hosted_url("npm", "@babel/core", "7.0.0", UUID_B, "core-7.0.0.tgz");
        let p = Project::new();
        p.write(
            "yarn.lock",
            classic(&[
                classic_block(
                    "left-pad@^1.0.0, left-pad@^1.3.0",
                    "1.3.0",
                    &format!("{lp}#{SHA1}"),
                    Some(SRI),
                ),
                classic_block(
                    "\"@babel/core@^7.0.0\"",
                    "7.0.0",
                    &format!("{core}#{SHA1}"),
                    Some(SRI),
                ),
                classic_block("\"pad-alias@npm:left-pad@^1.3.0\"", "1.3.0", &lp, Some(SRI)),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted),
                ("pkg:npm/@babel/core@7.0.0", UUID_B, WiringMode::Hosted),
            ],
        );
        assert!(out.refs.iter().all(|r| r.uuid != TOKEN));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The vendored classic block exactly as `vendor::yarn_classic_lock`
    /// writes it (`file:./<rel-tgz>#<sha1>` + integrity).
    #[tokio::test]
    async fn classic_vendored_blocks() {
        let p = Project::new();
        p.write(
            "yarn.lock",
            classic(&[
                classic_block(
                    "left-pad@^1.3.0",
                    "1.3.0",
                    &format!("file:./.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz#{SHA1}"),
                    Some(SRI),
                ),
                classic_block(
                    "\"@scope/pkg@^2.0.0\"",
                    "2.0.0",
                    &format!("file:./.socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz#{SHA1}"),
                    Some(SRI),
                ),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Vendored),
                ("pkg:npm/@scope/pkg@2.0.0", UUID_B, WiringMode::Vendored),
            ],
        );
        let v = out
            .refs
            .iter()
            .find(|r| r.uuid == UUID_B)
            .expect("scoped ref");
        assert_eq!(
            v.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz").as_str())
        );
        assert_eq!(
            v.locked_integrity,
            Some(LockIntegrity::Sri(SRI.to_string()))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The sha1 fragment is a pin when the integrity line is gone; with
    /// neither, the ref stays but cannot use the lockfile basis.
    #[tokio::test]
    async fn classic_pins_sha1_fallback_and_pinless() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "yarn.lock",
            classic(&[classic_block(
                "left-pad@^1.3.0",
                "1.3.0",
                &format!("{url}#{}", SHA1.to_uppercase()),
                None,
            )]),
        );
        let out = run(&p).await;
        assert_eq!(
            out.refs[0].locked_integrity,
            Some(LockIntegrity::Sha1Hex(SHA1.to_string()))
        );
        assert!(out.refs[0].lockfile_basis_ok());

        let pinless = Project::new();
        pinless.write(
            "yarn.lock",
            classic(&[classic_block("left-pad@^1.3.0", "1.3.0", &url, None)]),
        );
        let out = run(&pinless).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    /// yarn keeps the LAST block for a repeated key: a stale Socket block
    /// shadowed by a later registry re-lock wires nothing, and the reverse
    /// order wires the Socket one.
    #[tokio::test]
    async fn classic_duplicate_keys_are_last_wins() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let socket = classic_block("left-pad@^1.3.0", "1.3.0", &url, Some(SRI));
        let registry = classic_block(
            "left-pad@^1.3.0",
            "1.3.0",
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915ec1972a5f1bb07e",
            Some("sha512-ORIG=="),
        );
        let p = Project::new();
        p.write("yarn.lock", classic(&[socket.clone(), registry.clone()]));
        assert!(run(&p).await.refs.is_empty());

        let p = Project::new();
        p.write("yarn.lock", classic(&[registry, socket]));
        assert_refs(
            &run(&p).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Negative shapes: a uuid on a foreign host, placeholder token/uuid
    /// segments, a vendored path OUTSIDE the root, a link: key, and plain
    /// registry entries — none is a ref, and none is noisy.
    #[tokio::test]
    async fn classic_non_socket_references_are_silent() {
        let foreign =
            format!("https://evil.example/patch/npm/a/1.0.0/{TOKEN}/{UUID_A}/a-1.0.0.tgz");
        let placeholder = "https://patch.socket.dev/patch/npm/b/1.0.0/tok/uuid/b-1.0.0.tgz";
        let good = hosted_url("npm", "d", "1.0.0", UUID_A, "d-1.0.0.tgz");
        let p = Project::new();
        p.write(
            "yarn.lock",
            classic(&[
                classic_block("a@^1.0.0", "1.0.0", &foreign, Some(SRI)),
                classic_block("b@^1.0.0", "1.0.0", placeholder, Some(SRI)),
                classic_block(
                    "c@^1.0.0",
                    "1.0.0",
                    &format!("file:../.socket/vendor/npm/{UUID_B}/c-1.0.0.tgz"),
                    Some(SRI),
                ),
                classic_block("\"d@link:../d\"", "1.0.0", &good, None),
                classic_block(
                    "e@^1.0.0",
                    "1.0.0",
                    "https://registry.yarnpkg.com/e/-/e-1.0.0.tgz#5b8a3a7765dfe001261dde915ec1972a5f1bb07e",
                    Some(SRI),
                ),
            ]),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Socket-shaped blocks that fail validation are DIAGNOSED, never refs:
    /// no version, mixed-package key, unsafe name, a leaf naming another
    /// package, a traversal leaf, a non-canonical vendored uuid.
    #[tokio::test]
    async fn classic_invalid_socket_blocks_are_diagnosed() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let no_version = format!("left-pad@^1.3.0:\n  resolved \"{url}\"\n  integrity {SRI}\n\n");
        let p = Project::new();
        p.write(
            "yarn.lock",
            format!(
                "{CLASSIC_HEADER}{no_version}{}",
                [
                    classic_block("left-pad@^1.0.0, lodash@^4.0.0", "1.3.0", &url, Some(SRI)),
                    classic_block("\"../../etc@^1.0.0\"", "1.0.0", &url, Some(SRI)),
                    classic_block(
                        "lodash@^4.17.21",
                        "4.17.21",
                        &format!("file:./.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz#{SHA1}"),
                        Some(SRI),
                    ),
                    classic_block(
                        "x@^1.0.0",
                        "1.0.0",
                        &format!("file:./.socket/vendor/npm/{UUID_B}/../../../x-1.0.0.tgz"),
                        Some(SRI),
                    ),
                    classic_block(
                        "y@^1.0.0",
                        "1.0.0",
                        "file:./.socket/vendor/npm/not-a-uuid/y-1.0.0.tgz",
                        Some(SRI),
                    ),
                ]
                .concat()
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 6],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("yarn.lock")));
    }

    // ── berry ────────────────────────────────────────────────────────────

    /// Every committed berry golden fixture (basic, a pre-existing
    /// custom-registry `__archiveUrl`, a multi-descriptor key, multiple
    /// versions, a scoped package): the patched entry only.
    #[tokio::test]
    async fn berry_golden_hosted_fixtures() {
        for (case, purl) in [
            ("basic", "pkg:npm/left-pad@1.3.0"),
            ("existing-archive-url", "pkg:npm/left-pad@1.3.0"),
            ("multi-descriptor-key", "pkg:npm/left-pad@1.3.0"),
            ("multiple-versions", "pkg:npm/left-pad@1.3.0"),
            ("scoped-package", "pkg:npm/@babel/core@7.0.0"),
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/npm/yarn-berry/{case}/expected"));
            let out = run(&p).await;
            assert_refs(&out, &[(purl, FIXTURE_UUID_BERRY, WiringMode::Hosted)]);
            let r = &out.refs[0];
            assert!(r.integrity_required, "{case}");
            assert!(
                matches!(&r.locked_integrity, Some(LockIntegrity::BerryChecksum(c)) if c.starts_with("10c0/")),
                "{case}: {:?}",
                r.locked_integrity
            );
            assert!(r.lockfile_basis_ok(), "{case}");
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// Pre-rewrite and refused inputs: registry entries, a custom-registry
    /// `__archiveUrl`, workspace entries — nothing, silently.
    #[tokio::test]
    async fn berry_registry_inputs_discover_nothing() {
        for case in [
            "basic",
            "existing-archive-url",
            "multi-descriptor-key",
            "cachekey-mismatch-refusal",
            "yarnrc-compression-refusal",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/npm/yarn-berry/{case}/input"));
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{case}: {:#?}", out.refs);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// The vendored berry pair exactly as `vendor::yarn_berry_lock` writes it
    /// — spike B3's lock entry plus the root `package.json` `resolutions`
    /// value — for a plain and a scoped package.
    #[tokio::test]
    async fn berry_vendored_entry_confirmed_by_resolutions() {
        let p = Project::new();
        p.write(
            "yarn.lock",
            berry(&[
                berry_vendored_block("left-pad", "1.3.0", UUID_A),
                berry_vendored_block("@scope/pkg", "2.0.0", UUID_B),
            ]),
        );
        p.write(
            "package.json",
            package_json_with_resolutions(serde_json::json!({
                "left-pad": format!("file:./.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz"),
                // Hand-edited selector spellings target the same package.
                "**/@scope/pkg": format!("file:./.socket/vendor/npm/{UUID_B}/@scope/pkg-2.0.0.tgz"),
            })),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Vendored),
                ("pkg:npm/@scope/pkg@2.0.0", UUID_B, WiringMode::Vendored),
            ],
        );
        let v = out.refs.iter().find(|r| r.uuid == UUID_A).expect("ref");
        assert_eq!(
            v.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz").as_str())
        );
        assert_eq!(v.source_file, std::path::PathBuf::from("yarn.lock"));
        assert_eq!(
            v.locked_integrity,
            Some(LockIntegrity::BerryChecksum(CHECKSUM.to_string()))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A berry vendored locator whose `#` selector names a different file
    /// than its path (`…/left-pad-1.3.0.tgz#./…/evil.tgz`) is diagnosed: the
    /// leaf check reads the pre-`#` path, so trusting it would verify one
    /// tarball while yarn fetches the other.
    #[tokio::test]
    async fn berry_vendored_selector_must_name_the_same_artifact() {
        let rel = format!(".socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz");
        let evil = format!(".socket/vendor/npm/{UUID_A}/evil-1.3.0.tgz");
        let locator = "app%40workspace%3A.";
        let p = Project::new();
        p.write(
            "yarn.lock",
            berry(&[berry_block(
                &format!("left-pad@file:./{rel}::locator={locator}"),
                "1.3.0",
                &format!("left-pad@file:./{rel}#./{evil}::hash=39ea9b&locator={locator}"),
                Some(CHECKSUM),
            )]),
        );
        p.write(
            "package.json",
            package_json_with_resolutions(serde_json::json!({
                "left-pad": format!("file:./{rel}"),
            })),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        // The rejected entry, plus the `resolutions` value it leaves with no
        // lock entry behind it.
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 2],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .any(|d| d.detail.contains("selector")));
    }

    /// The verbatim spike B3 fixture pair the berry vendor backend's tests
    /// are pinned to (yarn 4.12-emitted), via the orchestrator.
    #[tokio::test]
    async fn berry_vendored_spike_b3_fixture_via_orchestrator() {
        let uuid = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        let rel = format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz");
        let lock = format!(
            "{BERRY_HEADER}\"left-pad@file:./{rel}::locator=vendor-spike%40workspace%3A.\":\n  version: 1.3.0\n  resolution: \"left-pad@file:./{rel}#./{rel}::hash=39ea9b&locator=vendor-spike%40workspace%3A.\"\n  checksum: {CHECKSUM}\n  languageName: node\n  linkType: hard\n\n\"vendor-spike@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"vendor-spike@workspace:.\"\n  dependencies:\n    left-pad: \"npm:1.3.0\"\n  languageName: unknown\n  linkType: soft\n"
        );
        let pkg = format!(
            "{{\n  \"name\": \"vendor-spike\",\n  \"version\": \"1.0.0\",\n  \"packageManager\": \"yarn@4.12.0\",\n  \"dependencies\": {{\n    \"left-pad\": \"1.3.0\"\n  }},\n  \"resolutions\": {{\n    \"left-pad\": \"file:./{rel}\"\n  }}\n}}\n"
        );
        let p = Project::new();
        p.write("yarn.lock", lock);
        p.write("package.json", pkg);
        let out = p.discover().await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", uuid, WiringMode::Vendored)],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// REGRESSION guard: without the `resolutions` mapping berry never
    /// installs the `file:` entry (the dependency's `npm:` descriptor has
    /// no lock entry any more), so the entry is diagnosed, not a ref — also
    /// when the mapping points at another uuid, or package.json is missing
    /// or malformed. A mapping with no lock entry is diagnosed too.
    #[tokio::test]
    async fn berry_vendored_entry_without_resolutions_is_orphaned() {
        let lock = berry(&[berry_vendored_block("left-pad", "1.3.0", UUID_A)]);
        for pkg in [
            None,
            Some(package_json_with_resolutions(serde_json::json!({}))),
            Some(package_json_with_resolutions(serde_json::json!({
                "left-pad": "1.3.0"
            }))),
            Some(package_json_with_resolutions(serde_json::json!({
                "left-pad": format!("file:./.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz")
            }))),
            Some(package_json_with_resolutions(serde_json::json!({
                "other": format!("file:./.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz")
            }))),
        ] {
            let p = Project::new();
            p.write("yarn.lock", &lock);
            if let Some(pkg) = &pkg {
                p.write("package.json", pkg);
            }
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{pkg:?}: {:#?}", out.refs);
            assert!(
                out.diagnostics
                    .iter()
                    .any(|d| d.code == DIAG_REF_INVALID && d.detail.contains("orphaned")),
                "{pkg:?}: {:#?}",
                out.diagnostics
            );
            // The orphan's patch is RECOGNIZED: a vendor ledger entry for it
            // is dead, never kept alive by the lock text naming its
            // artifact (rule 11).
            assert_eq!(
                out.vendored_claim(
                    "pkg:npm/left-pad@1.3.0",
                    UUID_A,
                    &format!(".socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz"),
                ),
                Some(false),
                "{pkg:?}"
            );
        }

        let malformed = Project::new();
        malformed.write("yarn.lock", &lock);
        malformed.write("package.json", "{ nope");
        let out = run(&malformed).await;
        assert!(out.refs.is_empty());
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID]
        );
        // A malformed package.json in a project with nothing vendored is
        // not discovery's business.
        let quiet = Project::new();
        quiet.write("yarn.lock", berry(&[]));
        quiet.write("package.json", "{ nope");
        assert!(run(&quiet).await.diagnostics.is_empty());

        let unlocked = Project::new();
        unlocked.write("yarn.lock", berry(&[]));
        unlocked.write(
            "package.json",
            package_json_with_resolutions(serde_json::json!({
                "left-pad": format!("file:./.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz")
            })),
        );
        let out = run(&unlocked).await;
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert_eq!(
            out.diagnostics[0].file,
            std::path::PathBuf::from("package.json")
        );
    }

    /// Hand-edit tolerance: a direct url locator on the patch server (what a
    /// url-range dependency locks to) and CRLF line endings (a
    /// `core.autocrlf` checkout of an LF lock).
    #[tokio::test]
    async fn berry_hosted_direct_url_locator_and_crlf() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "yarn.lock",
            berry(&[berry_block(
                &format!("left-pad@{url}"),
                "1.3.0",
                &format!("left-pad@{url}"),
                Some(CHECKSUM),
            )])
            .replace('\n', "\r\n"),
        );
        assert_refs(
            &run(&p).await,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Negative berry shapes: an `__archiveUrl` on a foreign host carrying
    /// uuids, placeholder segments, a `patch:` / `workspace:` / `portal:`
    /// locator, a vendored path outside the root — silent, no refs.
    #[tokio::test]
    async fn berry_non_socket_references_are_silent() {
        let foreign = format!("https://evil.example/patch/npm/{TOKEN}/{UUID_A}/a-1.0.0.tgz");
        let placeholder = "https://patch.socket.dev/patch/npm/tok/uuid/b-1.0.0.tgz";
        let p = Project::new();
        p.write(
            "yarn.lock",
            berry(&[
                berry_block(
                    "a@npm:^1.0.0",
                    "1.0.0",
                    &format!("a@npm:1.0.0::__archiveUrl={}", archive(&foreign)),
                    Some(CHECKSUM),
                ),
                berry_block(
                    "b@npm:^1.0.0",
                    "1.0.0",
                    &format!("b@npm:1.0.0::__archiveUrl={}", archive(placeholder)),
                    Some(CHECKSUM),
                ),
                berry_block(
                    "resolve@patch:resolve@npm%3A^1.22.0#optional!builtin<compat/resolve>",
                    "1.22.8",
                    "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d",
                    Some(CHECKSUM),
                ),
                berry_block(
                    "c@portal:../c",
                    "0.0.0-use.local",
                    "c@portal:../c::locator=app%40workspace%3A.",
                    None,
                ),
                berry_block(
                    "d@file:../.socket/vendor/npm/x::locator=app%40workspace%3A.",
                    "1.0.0",
                    &format!(
                        "d@file:../.socket/vendor/npm/{UUID_B}/d-1.0.0.tgz#../x::hash=1&locator=a"
                    ),
                    Some(CHECKSUM),
                ),
            ]),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Socket-shaped berry entries that fail validation are diagnosed: no
    /// `version:`, a locator version that disagrees with `version:`, an
    /// unsafe name, a vendored leaf for another package, a traversal leaf.
    #[tokio::test]
    async fn berry_invalid_socket_entries_are_diagnosed() {
        let enc = archive(&hosted_url(
            "npm",
            "left-pad",
            "1.3.0",
            UUID_A,
            "left-pad-1.3.0.tgz",
        ));
        let no_version = format!(
            "\"left-pad@npm:^1.3.0\":\n  resolution: \"left-pad@npm:1.3.0::__archiveUrl={enc}\"\n  checksum: {CHECKSUM}\n\n"
        );
        let lock = format!(
            "{BERRY_HEADER}{no_version}{}{BERRY_WORKSPACE}",
            [
                berry_block(
                    "left-pad@npm:^1.0.0",
                    "1.0.0",
                    &format!("left-pad@npm:1.3.0::__archiveUrl={enc}"),
                    Some(CHECKSUM),
                ),
                berry_block(
                    "../../x@npm:^1.0.0",
                    "1.0.0",
                    &format!("../../x@npm:1.0.0::__archiveUrl={enc}"),
                    Some(CHECKSUM),
                ),
                berry_block(
                    "lodash@file:./.socket/vendor/npm/x",
                    "4.17.21",
                    &format!(
                        "lodash@file:./.socket/vendor/npm/{UUID_B}/minimist-1.2.5.tgz#./x::hash=1"
                    ),
                    Some(CHECKSUM),
                ),
                berry_block(
                    "y@file:./.socket/vendor/npm/x",
                    "1.0.0",
                    &format!("y@file:./.socket/vendor/npm/{UUID_B}/../../y-1.0.0.tgz"),
                    Some(CHECKSUM),
                ),
            ]
            .concat()
        );
        let p = Project::new();
        p.write("yarn.lock", lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 5],
            "{:#?}",
            out.diagnostics
        );
    }

    /// A hosted berry entry that lost its `checksum:` is still a ref (its
    /// installed tree can verify it) but not lockfile-attestable; a
    /// shadowed duplicate key wires nothing.
    #[tokio::test]
    async fn berry_pinless_and_duplicate_keys() {
        let enc = archive(&hosted_url(
            "npm",
            "left-pad",
            "1.3.0",
            UUID_A,
            "left-pad-1.3.0.tgz",
        ));
        let socket = |checksum| {
            berry_block(
                "left-pad@npm:^1.3.0",
                "1.3.0",
                &format!("left-pad@npm:1.3.0::__archiveUrl={enc}"),
                checksum,
            )
        };
        let p = Project::new();
        p.write("yarn.lock", berry(&[socket(None)]));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert!(!out.refs[0].lockfile_basis_ok());

        let registry = berry_block(
            "left-pad@npm:^1.3.0",
            "1.3.0",
            "left-pad@npm:1.3.0",
            Some(CHECKSUM),
        );
        let p = Project::new();
        p.write("yarn.lock", berry(&[socket(Some(CHECKSUM)), registry]));
        assert!(run(&p).await.refs.is_empty());
    }

    /// yarn 4.0.x writes its cacheKey-`10c0` checksums as BARE hex (4.1+
    /// prefixes `10c0/`): the same enforced cache-zip pin, normalized to the
    /// prefixed form. A bare checksum under any other cacheKey (yarn 2/3's
    /// `7`/`8`) stays no pin, and a malformed bare value is no pin either.
    #[tokio::test]
    async fn berry_yarn40_bare_checksum_is_a_pin_only_at_cachekey_10c0() {
        let enc = archive(&hosted_url(
            "npm",
            "left-pad",
            "1.3.0",
            UUID_A,
            "left-pad-1.3.0.tgz",
        ));
        let hex = CHECKSUM.trim_start_matches("10c0/");
        let lock = |cache_key: &str, checksum: &str| {
            berry(&[berry_block(
                "left-pad@npm:^1.3.0",
                "1.3.0",
                &format!("left-pad@npm:1.3.0::__archiveUrl={enc}"),
                Some(checksum),
            )])
            .replace("cacheKey: 10c0", &format!("cacheKey: {cache_key}"))
        };
        let p = Project::new();
        p.write("yarn.lock", lock("10c0", hex));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(
            out.refs[0].locked_integrity,
            Some(LockIntegrity::BerryChecksum(CHECKSUM.to_string()))
        );
        assert!(out.refs[0].lockfile_basis_ok());
        for (cache_key, checksum) in [("8", hex), ("7", hex), ("10c0", &hex[..64]), ("10c0", "zz")]
        {
            let p = Project::new();
            p.write("yarn.lock", lock(cache_key, checksum));
            let out = run(&p).await;
            assert_eq!(out.refs.len(), 1, "{cache_key} {checksum}");
            assert!(
                out.refs[0].locked_integrity.is_none(),
                "{cache_key} {checksum}: no pin"
            );
        }
    }

    /// `--patch-server-url` deployments count for both grammars.
    #[tokio::test]
    async fn configured_patch_server_origin_is_accepted() {
        let url = format!("http://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        for lock in [
            classic(&[classic_block("left-pad@^1.3.0", "1.3.0", &url, Some(SRI))]),
            berry(&[berry_block(
                "left-pad@npm:^1.3.0",
                "1.3.0",
                &format!("left-pad@npm:1.3.0::__archiveUrl={}", archive(&url)),
                Some(CHECKSUM),
            )]),
        ] {
            let without = Project::new();
            without.write("yarn.lock", &lock);
            assert!(run(&without).await.refs.is_empty());
            let with = Project::new().with_origin("http://127.0.0.1:4545");
            with.write("yarn.lock", &lock);
            assert_refs(
                &run(&with).await,
                &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
            );
        }
    }

    #[tokio::test]
    async fn malformed_lock_is_diagnosed_not_fatal() {
        for text in [
            "{ not a lock",
            "left-pad@^1.0.0:\n  version \"1\"\ngarbage\n",
        ] {
            let p = Project::new();
            p.write("yarn.lock", text);
            let out = run(&p).await;
            assert!(out.refs.is_empty());
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text}");
        }
        // Non-UTF-8 bytes: unreadable, not a panic.
        let p = Project::new();
        p.write("yarn.lock", [0xff, 0xfe, 0x00, 0x80]);
        assert_eq!(diag_codes(&run(&p).await), vec![DIAG_LOCKFILE_UNREADABLE]);
        // No yarn.lock at all: silent.
        let out = run(&Project::new()).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
    }

    /// A live berry block without a `resolution:` line (a hand-trimmed
    /// entry) names nothing, in discovery and in the registry view alike;
    /// the hosted entry beside it is still read.
    #[tokio::test]
    async fn berry_block_without_resolution_is_skipped() {
        let enc = archive(&hosted_url(
            "npm",
            "left-pad",
            "1.3.0",
            UUID_A,
            "left-pad-1.3.0.tgz",
        ));
        let p = Project::new();
        p.write(
            "package.json",
            r#"{"name":"app","dependencies":{"left-pad":"^1.3.0","trimmed":"^1.0.0"}}"#,
        );
        p.write(
            "yarn.lock",
            berry(&[
                "\"trimmed@npm:^1.0.0\":\n  version: 1.0.0\n  checksum: 10c0/abc\n  \
                 languageName: node\n  linkType: hard\n\n"
                    .to_string(),
                berry_block(
                    "left-pad@npm:^1.3.0",
                    "1.3.0",
                    &format!("left-pad@npm:1.3.0::__archiveUrl={enc}"),
                    Some(CHECKSUM),
                ),
            ]),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A FIFO squatting the lock name fails fast (guarded read).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_is_unreadable_not_a_hang() {
        let p = Project::new();
        let path = p.root().join("yarn.lock");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }
}
