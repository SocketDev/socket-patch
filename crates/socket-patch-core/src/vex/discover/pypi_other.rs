//! The other Python wirings: `Pipfile.lock`, requirements files, and PEP
//! 508 direct references in `pyproject.toml` / `hatch.toml` (Hatch).
//!
//! Every file below is read when present (rule 1). All three share one
//! reference grammar: a `file`/`path` string or a `name @ <location>`
//! requirement whose location is
//!
//! * a Socket-HOSTED url ([`DiscoverCtx::hosted_uuid`]) on the path grammar
//!   `…/patch/pypi/<name>/<version>/<grant>/<uuid>/<artifact>` every pypi
//!   hosted rewriter copies verbatim from the grant's `artifactUrl` →
//!   [`WiringMode::Hosted`]. The package is the ENTRY's own name; the
//!   version comes from the url (the rewriters drop every `==` pin), and
//!   the path coordinates, the patch-uuid level and the artifact filename
//!   (PEP 427 wheel or sdist) must all agree with the entry — a
//!   placeholder in the uuid level behind a uuid-shaped grant token, or
//!   a url naming another package, is diagnosed, never trusted. When the
//!   url does not carry the `patch/pypi/…` levels (a self-hosted
//!   `--patch-server-url` layout), the artifact filename alone supplies
//!   the version. This is the host-allowlisted twin of
//!   `vendor::pypi_pipenv::is_socket_hosted_reference`, which accepts the
//!   same path shape on ANY https host because it only decides ownership
//!   of a lock entry, not attestation;
//! * a root-anchored `.socket/vendor/pypi/<uuid>/<wheel>` path
//!   ([`vendor_ref`]) → [`WiringMode::Vendored`]. The wheel must be a single
//!   PEP 427 filename naming the entry's own dist (PEP 503-canonical on both
//!   sides), and its version is the ref's.
//!
//! Anything else Socket-SHAPED (a `.socket/vendor/` path that escapes the
//! root or is not a pypi wheel, a patch-server url with no patch uuid) is a
//! [`DIAG_REF_INVALID`]; registry pins and users' own urls/paths are
//! skipped silently.
//!
//! ## Pipfile.lock
//!
//! JSON; every category except `_meta` (`default`, `develop`, custom
//! Pipfile categories) maps `name → {"file" | "path": <ref>, "hashes":
//! ["sha256:<hex>"], "markers"?, "extras"?}`:
//!
//! * hosted (`patch::redirect::pipenv::plan`): `file` (Pipenv 7.x–2017:
//!   `path`) = `<artifact_url>#sha256=<hex>`, `version` / `index` removed.
//!   A later Pipenv relock may keep our reference while restoring the
//!   registry `hashes` and `version: "==X"` (`reserialized_around_reference`):
//!   still a ref, but X must be the url's version;
//! * vendored (`vendor::pypi_pipenv`): `file` (`path` when the entry has
//!   extras) = `./.socket/vendor/pypi/<uuid>/<wheel>`.
//!
//! An entry carrying BOTH `file` and `path` is not something either writer
//! produces (the hosted planner refuses it as a conflict), so a
//! Socket-shaped one is diagnosed instead of guessing which Pipenv reads.
//!
//! ## requirements files
//!
//! The root `requirements.txt` plus every in-root `-r` / `--requirement`
//! include it reaches — [`crate::vendor::requirements_include_names`], the
//! very walk the vendored planner edits (the hosted rewriter only edits the
//! root file, which the walk names first). Sibling `requirements-*.txt`
//! files the root never includes are NOT read: neither writer touches them,
//! and a stale one would otherwise gate the live wiring as a
//! `wiring_conflict`. Lines are pip's logical lines, cut with the planner's
//! own lexer ([`crate::utils::requirements`]: `\` continuations joined, `#`
//! comments at column 0 or after whitespace, one leading BOM):
//!
//! * hosted (`patch::redirect::requirements`):
//!   `Name[extras] @ <artifact_url>[ ; marker] --hash=sha256:<hex>`;
//! * vendored (`vendor::pypi_requirements::vendor_line`):
//!   `./.socket/vendor/pypi/<uuid>/<wheel>[ ; marker] --hash=sha256:<hex>  # socket-patch vendor: <name>==<ver>[ (transitive)]`
//!   — the trailing tag, when present, must name the wheel's own
//!   `name==version`; a hand-edited line without it is attributed to the
//!   wheel it installs. `name @ file:.socket/vendor/…` spellings are
//!   accepted too.
//!
//! ## Hatch (`pyproject.toml`, `hatch.toml`)
//!
//! `utils::hatch::plan` rewrites exact pins to `Name[extras] @ <url>[ ;
//! marker]` in `[project].dependencies`, `[project.optional-dependencies]`,
//! `[dependency-groups]` (PEP 735 — hosted only), and every Hatch
//! environment's `dependencies` / `extra-dependencies` (`[tool.hatch.envs.*]`
//! in pyproject, `[envs.*]` in hatch.toml). Hosted urls are
//! `<artifact_url>#sha256=<hex>`; vendored ones
//! `{root:uri}/.socket/vendor/pypi/<uuid>/<wheel>#sha256=<hex>` — exactly the
//! `{root:uri}/` prefix is stripped before [`vendor_ref`] (Hatch expands it
//! to the project root), except in `[dependency-groups]`, where Hatch does
//! not expand it (the planner refuses to write one there), so such a string
//! wires nothing and is diagnosed. Like the planner, pyproject's
//! `[tool.hatch.envs]` is skipped when `hatch.toml` defines a top-level
//! `envs` (Hatch merges external config by top-level key). The PEP 621 /
//! 735 tables are read whether or not the project is a Hatch project: a
//! Socket direct reference there routes every PEP 517 frontend's
//! resolution of the package.
//!
//! ## Integrity (rule 8)
//!
//! `locked_integrity` is the `#sha256=` url fragment when present (the pin
//! pip enforces on that very url), else the entry's sha256 `hashes` /
//! `--hash` options (one → [`LockIntegrity::Sha256Hex`], several →
//! [`LockIntegrity::Sha256AnyOf`]). Every hosted writer here ALWAYS writes a
//! sha256 pin — the Pipenv planner and the Hatch rewriter refuse a grant
//! without a valid digest, the requirements rewriter skips one — so
//! `integrity_required` is set for all three formats.

use serde_json::Value;
use toml_edit::DocumentMut;

use super::{
    mentions_vendor_dir, pypi_purl, toml_or_diag, vendored_leaf_purl, DiscoverCtx, Discovery,
    LocateOpts, PatchedRef, TomlDiag, VendorRef, Wired, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_LOCKFILE_UNREADABLE, DIAG_REF_INVALID,
};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::digest::sha256_hex;
use crate::utils::hatch::dependency_specs;
use crate::utils::requirements::{
    exact_pin, hash_options, logical_lines, split_comment, url_sha256_fragment, vendor_tag,
};
use crate::vendor::common::DeclTable;
use crate::vendor::lock_inventory::pypi::{hosted_artifact_url, parse_pipfile_lock};
use crate::vendor::lock_inventory::{pipfile_lock_entries, LockIntegrity};

const PIPFILE_LOCK: &str = "Pipfile.lock";
const ROOT_REQUIREMENTS: &str = "requirements.txt";
const PYPROJECT: &str = "pyproject.toml";
const HATCH_TOML: &str = "hatch.toml";
/// Hatch's project-root context field, as the vendored Hatch backend writes
/// it in front of the committed wheel path.
const HATCH_ROOT_URI: &str = "{root:uri}/";
/// Bound on the requirements include tree (the walk has a cycle guard, but
/// the files are committed, tamper-able input).
const MAX_REQUIREMENTS_FILES: usize = 256;

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    extract_pipfile_lock(ctx, out).await;
    extract_requirements(ctx, out).await;
    extract_hatch(ctx, out).await;
}

// ── Pipfile.lock ─────────────────────────────────────────────────────────

async fn extract_pipfile_lock(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(text) = ctx.read_text(PIPFILE_LOCK, out).await else {
        return;
    };
    // Parsed as the inventory and the hosted rewriter parse it (a leading
    // BOM skipped).
    let doc: Value = match parse_pipfile_lock(&text) {
        Ok(doc) => doc,
        Err(e) => {
            out.diag(
                DIAG_LOCKFILE_UNPARSEABLE,
                PIPFILE_LOCK,
                format!("{PIPFILE_LOCK} is not valid JSON: {e}"),
            );
            return;
        }
    };
    // The inventory's own walk (every category but `_meta`).
    let Some(entries) = pipfile_lock_entries(&doc) else {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            PIPFILE_LOCK,
            format!("{PIPFILE_LOCK} is not a JSON object"),
        );
        return;
    };
    for pkg in entries {
        let (category, name) = (pkg.category, pkg.name);
        let references = pkg.references();
        let location = match references.as_slice() {
            [] => {
                // A registry pin (`version: "==X"`, no VCS / editable
                // source): evidence against another lock's wiring.
                if let (false, Some(version)) = (pkg.is_vcs(), pkg.exact_pin()) {
                    out.resolved_elsewhere(PIPFILE_LOCK, pypi_purl(name, version));
                }
                continue;
            }
            [location] => *location,
            _ => {
                if references
                    .iter()
                    .any(|r| !matches!(classify(ctx, r, url_form(r)), Ok(None)))
                {
                    out.diag(
                        DIAG_REF_INVALID,
                        PIPFILE_LOCK,
                        format!(
                            "{PIPFILE_LOCK}: {category}.{name} carries both `file` and \
                             `path`; neither Socket writer produces that shape"
                        ),
                    );
                }
                continue;
            }
        };
        // A relock's re-added `version` next to our reference; only an
        // exact `==` pin constrains anything.
        let hashes = pkg
            .sha256_hashes()
            .into_iter()
            .map(str::to_string)
            .collect();
        emit(
            ctx,
            &Entry {
                file: PIPFILE_LOCK,
                name: Some(name),
                pinned_version: pkg.exact_pin(),
                tag: None,
                root_uri: false,
            },
            location,
            integrity_of(location, hashes),
            out,
        );
    }
}

// ── requirements files ───────────────────────────────────────────────────

async fn extract_requirements(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let files = match crate::vendor::requirements_include_names(ctx.root).await {
        Ok(files) => files,
        Err(e) => {
            // A reached include exists but cannot be read: the tree is
            // unknowable past it. Still read the root file (its own read
            // diagnoses if IT is the unreadable one).
            out.diag(
                DIAG_LOCKFILE_UNREADABLE,
                ROOT_REQUIREMENTS,
                format!("cannot read the -r include tree of {ROOT_REQUIREMENTS}: {e}"),
            );
            vec![ROOT_REQUIREMENTS.to_string()]
        }
    };
    for file in files.iter().take(MAX_REQUIREMENTS_FILES) {
        let Some(text) = ctx.read_text(file, out).await else {
            continue;
        };
        for line in logical_lines(&text) {
            requirements_line(ctx, file, &line.text, out);
        }
    }
}

/// One logical requirements line (see the module docs for the two shapes).
fn requirements_line(ctx: &DiscoverCtx<'_>, file: &str, line: &str, out: &mut Discovery) {
    let (code, comment) = split_comment(line);
    let code = code.trim();
    // Blank lines, comments, and option lines (`-r`, `--index-url`, `-e`).
    if code.is_empty() || code.starts_with('-') {
        return;
    }
    let Some((name, location)) = requirement_location(code) else {
        // A registry requirement; an exact `name[extras]==X` pin is evidence
        // against another lock's wiring of the same package.
        out.resolved_elsewhere(file, registry_pin(code));
        return;
    };
    let tag = comment.and_then(vendor_tag);
    emit(
        ctx,
        &Entry {
            file,
            name,
            pinned_version: None,
            tag,
            root_uri: false,
        },
        location,
        integrity_of(location, hash_options(code)),
        out,
    );
}

/// The `pypi_purl` of an exact `name[extras]==X` registry requirement
/// ([`exact_pin`]).
fn registry_pin(code: &str) -> Option<String> {
    let (name, version) = exact_pin(code)?;
    pypi_purl(name, version)
}

/// The `(declared name, location)` of a requirement that names an artifact:
/// a PEP 508 direct reference `name[extras] @ <location>` (name `Some`), or
/// a bare path / url line (name `None` — pip installs whatever the artifact
/// is). `None` for registry specifiers (`name==1.0`, `name>=1`, …).
fn requirement_location(code: &str) -> Option<(Option<&str>, &str)> {
    let code = code.trim_start();
    let first = code.split_whitespace().next()?;
    if first.contains("://")
        || first.starts_with("file:")
        || mentions_vendor_dir(first)
        || !first.starts_with(|c: char| c.is_ascii_alphanumeric())
    {
        // pip separates a marker from a URL with `; ` (whitespace-split
        // above leaves a trailing `;`) and from a path with a bare `;`.
        let location = if first.contains("://") {
            first.trim_end_matches(';')
        } else {
            first.split(';').next().unwrap_or(first)
        };
        return Some((None, location));
    }
    let (name, location) = pep508_direct_reference(code)?;
    Some((Some(name), location))
}

/// `name[extras] @ <location>[ ; marker]` → `(name, location)`.
fn pep508_direct_reference(spec: &str) -> Option<(&str, &str)> {
    let spec = spec.trim_start();
    if !spec.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    let name = &spec[..name_end];
    let mut rest = spec[name_end..].trim_start();
    if let Some(extras) = rest.strip_prefix('[') {
        rest = extras[extras.find(']')? + 1..].trim_start();
    }
    let location = rest.strip_prefix('@')?.split_whitespace().next()?;
    let location = location.trim_end_matches(';');
    (!location.is_empty()).then_some((name, location))
}

// ── Hatch: pyproject.toml / hatch.toml ───────────────────────────────────

async fn extract_hatch(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let hatch_toml = read_toml(ctx, HATCH_TOML, out).await;
    let pyproject = read_toml(ctx, PYPROJECT, out).await;
    // Hatch's own table walk (`utils::hatch::dependency_specs`); PEP 735
    // groups are where Hatch leaves `{root:uri}` unexpanded.
    for s in dependency_specs(pyproject.as_ref(), hatch_toml.as_ref()) {
        hatch_spec(ctx, s.file, s.spec, s.table != DeclTable::Group, out);
    }
}

async fn read_toml(ctx: &DiscoverCtx<'_>, file: &str, out: &mut Discovery) -> Option<DocumentMut> {
    let text = ctx.read_text(file, out).await?;
    toml_or_diag(
        file,
        text.trim_start_matches('\u{feff}'),
        TomlDiag::BomFlattened,
        out,
    )
}

/// One PEP 508 dependency string. `root_uri_expanded`: whether Hatch
/// expands `{root:uri}` in the table it came from.
fn hatch_spec(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    spec: &str,
    root_uri_expanded: bool,
    out: &mut Discovery,
) {
    let Some((name, location)) = pep508_direct_reference(spec) else {
        return;
    };
    let expanded = location.starts_with(HATCH_ROOT_URI);
    let location = match location.strip_prefix(HATCH_ROOT_URI) {
        Some(rest) if root_uri_expanded => rest,
        Some(_) => {
            if mentions_vendor_dir(location) {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {name}: {location:?} sits in [dependency-groups], where Hatch \
                         does not expand {{root:uri}}; it wires nothing"
                    ),
                );
            }
            return;
        }
        None => location,
    };
    emit(
        ctx,
        &Entry {
            file,
            name: Some(name),
            pinned_version: None,
            tag: None,
            root_uri: expanded,
        },
        location,
        integrity_of(location, Vec::new()),
        out,
    );
}

// ── shared reference classification ──────────────────────────────────────

/// The entry a reference was read from.
struct Entry<'a> {
    /// Root-relative source file.
    file: &'a str,
    /// The declared package (lock key / requirement name); `None` for a bare
    /// requirements path line.
    name: Option<&'a str>,
    /// An exact `==` version the entry also pins (a Pipenv relock hybrid).
    pinned_version: Option<&'a str>,
    /// A requirements vendor tag's `(name, version)`.
    tag: Option<(&'a str, &'a str)>,
    /// The location had Hatch's `{root:uri}/` prefix expanded away: it is a
    /// URI, so a `#sha256=…` after the path is a fragment, not part of the
    /// file name.
    root_uri: bool,
}

impl Entry<'_> {
    fn subject<'s>(&'s self, location: &'s str) -> &'s str {
        self.name.unwrap_or(location)
    }
}

/// Whether `location` is url-form (`file:…`), where `#…` is a fragment pip
/// strips; a bare path is read literally (pip percent-encodes a `#` in it
/// into the file name).
fn url_form(location: &str) -> bool {
    location.trim_start().starts_with("file:")
}

/// `Ok(None)`: not Socket's (registry, a user's own url / path).
/// `Err(detail)`: Socket-SHAPED but unusable. `uri`: `location` is a URI
/// (see [`url_form`], Hatch's expanded `{root:uri}`), so a vendored path's
/// `#…` fragment is cut ([`super::vendor_ref_decorated`]); otherwise the path
/// is taken literally ([`super::vendor_ref`]) and a `#` in it is not our
/// artifact.
fn classify(ctx: &DiscoverCtx<'_>, location: &str, uri: bool) -> Result<Option<Wired>, String> {
    let located = ctx.locate(
        location,
        if uri {
            LocateOpts::DECORATED
        } else {
            LocateOpts::LITERAL
        },
    );
    if let Some(vref) = located.vendored {
        return Ok(Some(Wired::Vendored(vref)));
    }
    if let Some(uuid) = located.hosted {
        return Ok(Some(Wired::Hosted(uuid)));
    }
    if mentions_vendor_dir(location) {
        return Err(format!(
            "{location:?} is not a root-anchored .socket/vendor/pypi/<uuid>/<wheel> path"
        ));
    }
    if reqwest::Url::parse(location)
        .is_ok_and(|u| u.host_str() == Some(crate::patch::redirect::SOCKET_PATCH_SERVER_HOST))
    {
        return Err(format!(
            "{location:?} is a Socket patch-server url that names no patch uuid"
        ));
    }
    Ok(None)
}

/// Validate and push the ref `location` wires for `entry`, or diagnose it.
fn emit(
    ctx: &DiscoverCtx<'_>,
    entry: &Entry<'_>,
    location: &str,
    integrity: Option<LockIntegrity>,
    out: &mut Discovery,
) {
    let uri = entry.root_uri || url_form(location);
    let result = match classify(ctx, location, uri) {
        Ok(None) => return,
        Ok(Some(Wired::Hosted(uuid))) => hosted_ref(entry, location, uuid, integrity),
        Ok(Some(Wired::Vendored(vref))) => vendored_ref(entry, &vref, integrity),
        Err(detail) => Err(detail),
    };
    match result {
        Ok(r) => out.push(r),
        Err(detail) => out.diag(
            DIAG_REF_INVALID,
            entry.file,
            format!("{}: {}: {detail}", entry.file, entry.subject(location)),
        ),
    }
}

fn hosted_ref(
    entry: &Entry<'_>,
    url: &str,
    uuid: String,
    integrity: Option<LockIntegrity>,
) -> Result<PatchedRef, String> {
    let (coord_name, version) = hosted_coords(url, &uuid)?;
    let name = entry.name.unwrap_or(&coord_name);
    if canonicalize_pypi_name(name) != canonicalize_pypi_name(&coord_name) {
        return Err(format!(
            "wired to {url:?}, which is patch {uuid} for {coord_name:?}, another package"
        ));
    }
    check_pinned_version(entry, &version)?;
    let purl = pypi_purl(name, &version)
        .ok_or_else(|| format!("{name:?}@{version:?} has unsafe coordinates"))?;
    Ok(PatchedRef::hosted(
        purl,
        uuid,
        entry.file,
        Some(url),
        integrity,
        true,
    ))
}

/// `(name, version)` of a hosted pypi artifact url (see the module docs),
/// read with the lock inventory's hosted-url grammar
/// ([`hosted_artifact_url`]); a patch-server tail must carry `uuid`.
fn hosted_coords(url: &str, uuid: &str) -> Result<(String, String), String> {
    let coords = hosted_artifact_url(url)?;
    if let Some(level) = coords.uuid_level.as_deref().filter(|level| *level != uuid) {
        return Err(format!(
            "{url:?}: the patch-uuid level holds {level:?}, not a patch uuid"
        ));
    }
    Ok((coords.name, coords.version))
}

fn vendored_ref(
    entry: &Entry<'_>,
    vref: &VendorRef,
    integrity: Option<LockIntegrity>,
) -> Result<PatchedRef, String> {
    if vref.eco != "pypi" {
        return Err(format!(
            "{:?} is a vendored {} artifact, not a pypi wheel",
            vref.artifact_rel, vref.eco
        ));
    }
    let leaf_purl = (!vref.leaf.contains('/'))
        .then(|| vendored_leaf_purl("pypi", &vref.leaf))
        .flatten()
        .ok_or_else(|| {
            format!(
                "{:?} is not a single PEP 427 wheel filename",
                vref.artifact_rel
            )
        })?;
    let (leaf_name, version) = leaf_purl
        .strip_prefix("pkg:pypi/")
        .and_then(|nv| nv.rsplit_once('@'))
        .ok_or_else(|| format!("{:?} names no wheel version", vref.artifact_rel))?;
    let names_other = |name: &str| canonicalize_pypi_name(name) != leaf_name;
    if entry.name.is_some_and(names_other) {
        return Err(format!(
            "wired to {:?}, which is not that package's vendored wheel",
            vref.artifact_rel
        ));
    }
    if let Some((tag_name, tag_version)) = entry.tag {
        if names_other(tag_name) || tag_version != version {
            return Err(format!(
                "the socket-patch vendor tag {tag_name}=={tag_version} does not name the wired \
                 wheel {:?}",
                vref.artifact_rel
            ));
        }
    }
    check_pinned_version(entry, version)?;
    let purl = pypi_purl(leaf_name, version)
        .ok_or_else(|| format!("{:?} has unsafe coordinates", vref.artifact_rel))?;
    Ok(PatchedRef::vendored(purl, vref, entry.file, integrity))
}

fn check_pinned_version(entry: &Entry<'_>, version: &str) -> Result<(), String> {
    match entry.pinned_version {
        Some(pinned) if pinned != version => Err(format!(
            "pins version =={pinned} beside a reference to the {version} artifact"
        )),
        _ => Ok(()),
    }
}

// ── integrity ────────────────────────────────────────────────────────────

/// See "Integrity" in the module docs.
fn integrity_of(location: &str, hashes: Vec<String>) -> Option<LockIntegrity> {
    if let Some(fragment) = url_sha256_fragment(location) {
        return Some(LockIntegrity::Sha256Hex(fragment));
    }
    let mut hashes: Vec<String> = hashes.iter().filter_map(|hex| sha256_hex(hex)).collect();
    hashes.dedup();
    match hashes.len() {
        0 => None,
        1 => hashes.pop().map(LockIntegrity::Sha256Hex),
        _ => Some(LockIntegrity::Sha256AnyOf(hashes)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::testing::*;
    use super::super::*;
    use crate::patch::redirect::DepOverride;

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    /// A patched-wheel digest (`#sha256=` / `--hash` / `hashes`).
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";

    fn wheel_url(uuid: &str) -> String {
        hosted_url("pypi", "urllib3", "1.26.18", uuid, WHEEL)
    }

    fn vendored_wheel(uuid: &str, leaf: &str) -> String {
        format!(".socket/vendor/pypi/{uuid}/{leaf}")
    }

    /// The grant a hosted rewriter consumes (production artifact-URL shape).
    fn grant(name: &str, version: &str, uuid: &str, leaf: &str) -> DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "name": name,
            "version": version,
            "token": TOKEN,
            "patchUuid": uuid,
            "artifactUrl": hosted_url("pypi", name, version, uuid, leaf),
            "integrity": { "sha256": SHA },
        }))
        .expect("valid DepOverride")
    }

    fn files(entries: &[(&str, String)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn fixture_text(rel: &str) -> String {
        std::fs::read_to_string(fixture_path(rel)).expect("read fixture")
    }

    fn only_ref(out: &Discovery) -> &PatchedRef {
        assert_eq!(out.refs.len(), 1, "{:#?} {:#?}", out.refs, out.diagnostics);
        &out.refs[0]
    }

    fn pipfile_lock(entries: serde_json::Value) -> String {
        let mut doc = serde_json::json!({
            "_meta": { "pipfile-spec": 6, "hash": { "sha256": "x" }, "requires": {}, "sources": [] },
            "default": {},
            "develop": {},
        });
        for (category, members) in entries.as_object().unwrap() {
            doc[category] = members.clone();
        }
        serde_json::to_string_pretty(&doc).unwrap()
    }

    // ── Pipfile.lock ──────────────────────────────────────────────────────

    /// The real Pipenv 2026.8.0 lock, rewritten by the real hosted planner
    /// (both reference keys: `file`, and `path` for Pipenv 7.x–2017).
    #[tokio::test]
    async fn pipfile_lock_hosted_by_the_real_rewriter_every_reference_key() {
        for (major, key) in [(None, "file"), (Some(2026), "file"), (Some(2017), "path")] {
            let input = files(&[
                ("Pipfile", fixture_text("pipenv/2026.8.0/Pipfile")),
                ("Pipfile.lock", fixture_text("pipenv/2026.8.0/Pipfile.lock")),
            ]);
            let dep = grant("urllib3", "1.26.18", UUID_A, WHEEL);
            let result = crate::patch::redirect::rewrite_registry_redirect_with_pipenv_version(
                &input,
                &[dep],
                &BTreeMap::new(),
                major,
            );
            let lock = result.files.get("Pipfile.lock").expect("lock rewritten");
            assert!(lock.contains(&format!("\"{key}\": ")), "{lock}");
            assert!(!lock.contains("\"version\""), "{lock}");

            let p = Project::new();
            p.write("Pipfile", &input["Pipfile"])
                .write("Pipfile.lock", lock);
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Hosted)],
            );
            let r = only_ref(&out);
            assert_eq!(r.source_file, std::path::PathBuf::from("Pipfile.lock"));
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sha256Hex(SHA.into()))
            );
            assert!(r.integrity_required && r.lockfile_basis_ok());
            assert!(r
                .url
                .as_deref()
                .unwrap()
                .starts_with("https://patch.socket.dev/"));
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    /// The untouched real lock (registry pins only) discovers nothing.
    #[tokio::test]
    async fn pipfile_lock_registry_only_fixture_yields_nothing() {
        let p = Project::new();
        p.copy_fixture("pipenv/2026.8.0");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// `vendor::pypi_pipenv`'s shape: `file` (or `path` when the entry has
    /// extras) = `./<rel wheel>`, one sha256 hash, markers kept — in any
    /// category, with CRLF + BOM tolerated.
    #[tokio::test]
    async fn pipfile_lock_vendored_file_and_path_in_every_category() {
        let six = vendored_wheel(UUID_A, "six-1.16.0-py2.py3-none-any.whl");
        let req = vendored_wheel(UUID_B, "requests-2.31.0-py3-none-any.whl");
        let lock = pipfile_lock(serde_json::json!({
            "default": {
                "six": { "file": format!("./{six}"), "hashes": [format!("sha256:{SHA}")],
                         "markers": "python_version >= '2.7'" },
                "idna": { "version": "==3.6", "hashes": [format!("sha256:{SHA_B}")] },
            },
            "tests": {
                "requests": { "path": format!("./{req}"), "extras": ["socks"],
                              "hashes": [format!("sha256:{SHA_B}")] },
            },
        }));
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            format!("\u{feff}{}", lock.replace('\n', "\r\n")),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored),
                ("pkg:pypi/requests@2.31.0", UUID_B, WiringMode::Vendored),
            ],
        );
        let six_ref = out.refs.iter().find(|r| r.uuid == UUID_A).unwrap();
        assert_eq!(six_ref.artifact_rel.as_deref(), Some(six.as_str()));
        assert_eq!(
            six_ref.locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA.into()))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A Pipenv relock that kept our reference but restored the registry
    /// `version` + `hashes`: still wired (the fragment stays the pin) — but
    /// a `version` naming another release is not what either writer left.
    #[tokio::test]
    async fn pipfile_lock_relock_hybrid_keeps_the_ref_unless_the_version_disagrees() {
        let url = format!("{}#sha256={SHA}", wheel_url(UUID_A));
        let hashes = [
            format!("sha256:{SHA_B}"),
            format!("sha256:{}", "c".repeat(64)),
        ];
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                "urllib3": { "file": url, "version": "==1.26.18", "index": "pypi", "hashes": hashes },
            }})),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(
            only_ref(&out).locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA.into()))
        );

        // Without the fragment the entry's hash SET is the pin.
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                "urllib3": { "file": wheel_url(UUID_A), "hashes": hashes },
            }})),
        );
        let out = run(&p).await;
        assert_eq!(
            only_ref(&out).locked_integrity,
            Some(LockIntegrity::Sha256AnyOf(vec![
                SHA_B.to_string(),
                "c".repeat(64)
            ]))
        );

        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                "urllib3": { "file": url, "version": "==2.0.0" },
            }})),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// A hand-edited hosted entry without any pin is still a ref (the
    /// installed tree can verify it) but must not use the lockfile basis.
    #[tokio::test]
    async fn pinless_hosted_entry_cannot_use_the_lockfile_basis() {
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                "urllib3": { "file": wheel_url(UUID_A) },
            }})),
        );
        let out = run(&p).await;
        let r = only_ref(&out);
        assert_eq!(r.locked_integrity, None);
        assert!(r.integrity_required && !r.lockfile_basis_ok());
    }

    #[tokio::test]
    async fn pipfile_lock_rejects_mismatched_escaping_and_ambiguous_references() {
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                // The key names another package than the vendored wheel.
                "six": { "file": format!("./{}", vendored_wheel(UUID_A, "evil-1.0-py3-none-any.whl")) },
                // Escapes the project root.
                "idna": { "file": format!("../{}", vendored_wheel(UUID_A, "idna-3.6-py3-none-any.whl")) },
                // A nested leaf is not a single wheel filename.
                "attrs": { "file": vendored_wheel(UUID_A, "sub/attrs-23.1.0-py3-none-any.whl") },
                // Hosted url naming another package.
                "requests": { "file": wheel_url(UUID_B) },
                // Both reference keys.
                "urllib3": { "file": wheel_url(UUID_A), "path": wheel_url(UUID_A) },
                // A vendored npm tarball is not a pypi wheel.
                "left-pad": { "file": format!(".socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz") },
            }})),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 6]);
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("Pipfile.lock: ")));
    }

    #[tokio::test]
    async fn malformed_files_diagnose_instead_of_panicking() {
        for (file, text) in [
            ("Pipfile.lock", "{ not json"),
            ("Pipfile.lock", "[1, 2]"),
            ("pyproject.toml", "[project\ndependencies = ["),
            ("hatch.toml", "envs = = 1"),
        ] {
            let p = Project::new();
            p.write(file, text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{file}");
            assert_eq!(out.diagnostics[0].file, std::path::PathBuf::from(file));
        }
        // Wrong JSON types inside a valid lock are skipped silently.
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            r#"{"_meta": 1, "default": [1], "develop": {"six": "==1.0", "x": {"file": 7}}}"#,
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    // ── requirements ──────────────────────────────────────────────────────

    /// The committed golden output of the hosted requirements rewriter: a
    /// uuid-shaped grant token precedes the patch uuid.
    #[tokio::test]
    async fn requirements_golden_hosted_fixture() {
        let p = Project::new();
        p.copy_fixture("redirect/pypi/requirements/basic/expected");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:pypi/requests@2.28.1",
                "33333333-3333-3333-3333-333333333333",
                WiringMode::Hosted,
            )],
        );
        let r = only_ref(&out);
        assert_eq!(r.source_file, std::path::PathBuf::from("requirements.txt"));
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::Sha256Hex("deadbeef".repeat(8)))
        );
        assert!(r.integrity_required && r.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The real rewriter over extras, markers, options, a continuation and
    /// a trailing comment.
    #[tokio::test]
    async fn requirements_hosted_by_the_real_rewriter() {
        let input = files(&[(
            "requirements.txt",
            "flask==2.0.1\nURLLib3[socks] == 1.26.18 ; python_version >= \"3.7\" \\\n    --hash=sha256:0123 # keep\n"
                .to_string(),
        )]);
        let result = crate::patch::redirect::rewrite_registry_redirect(
            &input,
            &[grant("urllib3", "1.26.18", UUID_A, WHEEL)],
        );
        let text = result.files.get("requirements.txt").expect("rewritten");
        let p = Project::new();
        p.write("requirements.txt", text);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(
            only_ref(&out).locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA.into()))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// `vendor::pypi_requirements::vendor_line` shapes: marker + hash + tag,
    /// a transitive append, a hash-less line (the e2e ledger fixture), a
    /// continuation — across the root file and its in-root `-r` includes.
    #[tokio::test]
    async fn requirements_vendored_lines_across_includes() {
        let six = vendored_wheel(UUID_A, "six-1.16.0-py2.py3-none-any.whl");
        let idna = vendored_wheel(UUID_B, "idna-3.6-py3-none-any.whl");
        let attrs_uuid = "5d6e7f80-9a0b-4c1d-8e2f-3a4b5c6d7e8f";
        let attrs = vendored_wheel(attrs_uuid, "attrs-23.1.0-py3-none-any.whl");
        let p = Project::new();
        p.write(
            "requirements.txt",
            format!(
                "\u{feff}-r requirements/base.txt\nflask==2.0.1\n\
                 ./{six} ; python_version >= \"3\" --hash=sha256:{SHA}  # socket-patch vendor: six==1.16.0\n\
                 ./{idna} --hash=sha256:{SHA_B}  # socket-patch vendor: idna==3.6 (transitive)\n"
            ),
        );
        p.write(
            "requirements/base.txt",
            format!("./{attrs} \\\n    --hash=sha256:{SHA}\n# ./{six}\n"),
        );
        // Never included: not read.
        p.write(
            "requirements-old.txt",
            format!(
                "./{}\n",
                vendored_wheel(UUID_B, "six-1.16.0-py2.py3-none-any.whl")
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored),
                ("pkg:pypi/idna@3.6", UUID_B, WiringMode::Vendored),
                ("pkg:pypi/attrs@23.1.0", attrs_uuid, WiringMode::Vendored),
            ],
        );
        let attrs_ref = out.refs.iter().find(|r| r.uuid == attrs_uuid).unwrap();
        assert_eq!(
            attrs_ref.source_file,
            std::path::PathBuf::from("requirements/base.txt")
        );
        assert_eq!(attrs_ref.artifact_rel.as_deref(), Some(attrs.as_str()));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        // The hash-less shape the CLI's vendored e2e ledger fixture writes.
        let p = Project::new();
        p.write(
            "requirements.txt",
            format!("./{six}  # socket-patch vendor: six==1.16.0\n"),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(only_ref(&out).locked_integrity, None);
    }

    #[tokio::test]
    async fn requirements_hand_edit_tolerance_and_rejections() {
        let six = vendored_wheel(UUID_A, "six-1.16.0-py2.py3-none-any.whl");
        let attrs = vendored_wheel(UUID_A, "attrs-23.1.0-py3-none-any.whl");
        let lines = [
            // No tag: attributed to the wheel pip installs.
            format!(".socket/vendor/pypi/{UUID_B}/idna-3.6-py3-none-any.whl"),
            // `name @ file:` spelling, space-separated `--hash`.
            format!("Six @ file:./{six} --hash sha256:{SHA}"),
            // Tag naming another release than the wheel.
            format!("./{attrs}  # socket-patch vendor: attrs==99.0"),
            // Escapes the root / sits in a sub-project.
            format!("../{six}"),
            format!("sub/{six}"),
            // Registry pins and a foreign host's uuid-carrying url: silent.
            format!("requests==2.31.0 --hash=sha256:{SHA}"),
            format!(
                "foo @ https://example.com/patch/pypi/foo/1.0/{TOKEN}/{UUID_A}/foo-1.0-py3-none-any.whl"
            ),
        ];
        let p = Project::new();
        p.write("requirements.txt", lines.join("\n"));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:pypi/idna@3.6", UUID_B, WiringMode::Vendored),
                ("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored),
            ],
        );
        assert_eq!(
            out.refs
                .iter()
                .find(|r| r.uuid == UUID_A)
                .unwrap()
                .locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA.into()))
        );
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 3]);
        // Rule 11: the recognized uuid's claims are decided by the refs —
        // six's valid line keeps its claim live, the rejected attrs line
        // makes attrs' claim dead — while the foreign host's uuid-carrying
        // url recognizes nothing (left to the ledger's own evidence).
        assert_eq!(
            out.vendored_claim("pkg:pypi/six@1.16.0", UUID_A, &six),
            Some(true)
        );
        assert_eq!(
            out.vendored_claim("pkg:pypi/attrs@23.1.0", UUID_A, &attrs),
            Some(false)
        );
        assert_eq!(out.hosted_claim("pkg:pypi/foo@1.0", UUID_A), None);
    }

    /// A `#` is a url FRAGMENT only in url form (`file:…#sha256=…`, which
    /// pip strips); in a bare requirements path pip percent-encodes it into
    /// the file name, so `./…/six-….whl#evil.whl` names a different file than
    /// the committed wheel and is diagnosed, never attested from it.
    #[tokio::test]
    async fn a_vendored_fragment_is_cut_only_in_url_form() {
        let six = vendored_wheel(UUID_A, "six-1.16.0-py2.py3-none-any.whl");
        let url_form = Project::new();
        url_form.write(
            "requirements.txt",
            format!("six @ file:./{six}#sha256={SHA}\n"),
        );
        let out = run(&url_form).await;
        assert_refs(
            &out,
            &[("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(only_ref(&out).artifact_rel.as_deref(), Some(six.as_str()));

        let bare = Project::new();
        bare.write(
            "requirements.txt",
            format!("./{six}#evil.whl --hash=sha256:{SHA}\n"),
        );
        let out = run(&bare).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert_eq!(
            out.vendored_claim("pkg:pypi/six@1.16.0", UUID_A, &six),
            Some(false)
        );
    }

    /// A FIFO squatting a Python file (the root requirements file, an `-r`
    /// include, Pipfile.lock, pyproject.toml) is diagnosed, never a hang;
    /// the root file's refs survive an unreadable include.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifos_are_unreadable_not_a_hang() {
        fn mkfifo(path: &std::path::Path) {
            let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
            // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }
        let six = vendored_wheel(UUID_A, "six-1.16.0-py2.py3-none-any.whl");
        let p = Project::new();
        p.write(
            "requirements.txt",
            format!("-r base.txt\n./{six}  # socket-patch vendor: six==1.16.0\n"),
        );
        for file in ["base.txt", "Pipfile.lock", "pyproject.toml"] {
            mkfifo(&p.root().join(file));
        }
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert_refs(
            &out,
            &[("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored)],
        );
        assert!(diag_codes(&out)
            .iter()
            .all(|c| *c == DIAG_LOCKFILE_UNREADABLE));
        for file in ["Pipfile.lock", "pyproject.toml", "requirements.txt"] {
            assert!(
                out.diagnostics
                    .iter()
                    .any(|d| d.file.as_path() == std::path::Path::new(file)),
                "{file}: {:?}",
                out.diagnostics
            );
        }

        // A FIFO as the ROOT requirements file.
        let p = Project::new();
        mkfifo(&p.root().join("requirements.txt"));
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert_refs(&out, &[]);
        assert!(!out.diagnostics.is_empty());
        assert!(diag_codes(&out)
            .iter()
            .all(|c| *c == DIAG_LOCKFILE_UNREADABLE));
    }

    // ── hosted url validation (shared by all three formats) ──────────────

    #[tokio::test]
    async fn hosted_urls_need_the_socket_host_and_a_real_patch_uuid() {
        let placeholder = format!(
            "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/{TOKEN}/PATCH_UUID/{WHEEL}"
        );
        let no_uuid =
            format!("https://patch.socket.dev/patch/pypi/urllib3/1.26.18/token/uuid/{WHEEL}");
        let lookalike = format!(
            "https://patch.socket.dev.evil.test/patch/pypi/urllib3/1.26.18/{TOKEN}/{UUID_A}/{WHEEL}"
        );
        let userinfo = wheel_url(UUID_A).replace("https://", "https://user@");
        let wrong_version = hosted_url(
            "pypi",
            "urllib3",
            "1.26.18",
            UUID_A,
            "urllib3-2.0.0-py3-none-any.whl",
        );
        let not_python = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, "urllib3.tgz");
        let p = Project::new();
        p.write(
            "requirements.txt",
            [
                format!("urllib3 @ {placeholder}"),
                format!("urllib3 @ {no_uuid}"),
                format!("urllib3 @ {lookalike}"),
                format!("urllib3 @ {userinfo}"),
                format!("urllib3 @ {wrong_version}"),
                format!("urllib3 @ {not_python}"),
            ]
            .join("\n"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        // The placeholder (the uuid-shaped TOKEN would otherwise be taken
        // as the patch uuid), the uuid-less and the credentialed Socket
        // urls, and the version / artifact mismatches: diagnosed. The
        // lookalike host is not Socket's: silent.
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 5]);
        assert!(!out
            .diagnostics
            .iter()
            .any(|d| d.detail.contains("evil.test")));
    }

    /// A `--patch-server-url` origin counts (scheme + host + port), and a
    /// layout without the `patch/pypi/…` levels falls back to the artifact
    /// filename.
    #[tokio::test]
    async fn configured_origin_and_filename_fallback() {
        let p = Project::new().with_origin("http://127.0.0.1:4545");
        p.write(
            "requirements.txt",
            format!(
                "urllib3 @ http://127.0.0.1:4545/patch/pypi/urllib3/1.26.18/tok/{UUID_A}/{WHEEL} --hash=sha256:{SHA}\n\
                 six @ http://127.0.0.1:4545/p/{UUID_B}/six-1.16.0.tar.gz\n\
                 idna @ http://127.0.0.1:9999/patch/pypi/idna/3.6/tok/{UUID_B}/idna-3.6-py3-none-any.whl\n"
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Hosted),
                ("pkg:pypi/six@1.16.0", UUID_B, WiringMode::Hosted),
            ],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    // ── Hatch ─────────────────────────────────────────────────────────────

    /// The real hosted Hatch rewriter over project deps, optional deps and
    /// an environment.
    #[tokio::test]
    async fn hatch_hosted_by_the_real_rewriter() {
        let input = files(&[(
            "pyproject.toml",
            "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\
             [project]\nname = \"app\"\nversion = \"0\"\n\
             dependencies = [\"URLLib3[socks]==1.26.18 ; sys_platform != 'win32'\", \"idna>=3\"]\n\
             [project.optional-dependencies]\nfast = [\"urllib3==1.26.18\"]\n\
             [tool.hatch.envs.test]\nextra-dependencies = [\"urllib3==1.26.18\"]\n"
                .to_string(),
        )]);
        let result = crate::patch::redirect::rewrite_registry_redirect(
            &input,
            &[grant("urllib3", "1.26.18", UUID_A, WHEEL)],
        );
        let text = result.files.get("pyproject.toml").expect("rewritten");
        assert_eq!(text.matches(&wheel_url(UUID_A)).count(), 3, "{text}");
        let p = Project::new();
        p.write("pyproject.toml", text);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Hosted)],
        );
        let r = only_ref(&out);
        assert_eq!(r.source_file, std::path::PathBuf::from("pyproject.toml"));
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA.into()))
        );
        assert!(r.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// `vendor::pypi_hatch`'s url (`{root:uri}/<wheel>#sha256=<hex>`) planted
    /// by the real planner, in pyproject and hatch.toml environments.
    #[tokio::test]
    async fn hatch_vendored_root_uri_references() {
        let wheel = vendored_wheel(UUID_A, WHEEL);
        let url = format!("{{root:uri}}/{wheel}#sha256={SHA}");
        let input = files(&[
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\nversion = \"0\"\ndependencies = [\"urllib3==1.26.18\"]\n"
                    .to_string(),
            ),
            (
                "hatch.toml",
                "[envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n".to_string(),
            ),
        ]);
        let planned =
            crate::utils::hatch::rewrite(&input, "urllib3", "1.26.18", &url).expect("planned");
        let p = Project::new();
        for (file, text) in &input {
            p.write(file, planned.get(file).unwrap_or(text));
        }
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/urllib3@1.26.18", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(out.refs.len(), 2, "one per file: {:#?}", out.refs);
        for r in &out.refs {
            assert_eq!(r.artifact_rel.as_deref(), Some(wheel.as_str()));
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sha256Hex(SHA.into()))
            );
        }
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Hatch reads hatch.toml's top-level `envs` INSTEAD of pyproject's
    /// `[tool.hatch.envs]`; `{root:uri}` in PEP 735 groups is never
    /// expanded; other prefixes and traversal are rejected; registry and
    /// foreign pins are silent.
    #[tokio::test]
    async fn hatch_shadowed_envs_groups_and_rejections() {
        let wheel = vendored_wheel(UUID_A, WHEEL);
        let p = Project::new();
        p.write(
            "pyproject.toml",
            format!(
                "[project]\nname = \"app\"\nversion = \"0\"\ndependencies = [\n  \"idna==3.6\",\n  \
                 \"foo @ https://example.com/foo-1.0-py3-none-any.whl\",\n  \
                 \"attrs @ {{root:uri}}/../{attrs}\",\n]\n\
                 [dependency-groups]\nqa = [\"urllib3 @ {{root:uri}}/{wheel}\", {{ include-group = \"x\" }}]\n\
                 [tool.hatch.envs.default]\ndependencies = [\"urllib3 @ {{root:uri}}/{wheel}\"]\n",
                attrs = vendored_wheel(UUID_B, "attrs-23.1.0-py3-none-any.whl"),
            ),
        );
        p.write(
            "hatch.toml",
            "[envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 2]);
        assert!(out
            .diagnostics
            .iter()
            .any(|d| d.detail.contains("dependency-groups")));
    }

    // ── orchestrator ──────────────────────────────────────────────────────

    /// Through the full orchestrator, every format at once: each file is
    /// read (no precedence chain), each ref names its own file.
    #[tokio::test]
    async fn discover_reads_every_python_file_at_once() {
        let p = Project::new();
        p.write(
            "Pipfile.lock",
            pipfile_lock(serde_json::json!({ "default": {
                "urllib3": { "file": format!("{}#sha256={SHA}", wheel_url(UUID_A)) },
            }})),
        );
        p.write(
            "requirements.txt",
            format!("urllib3 @ {} --hash=sha256:{SHA}\n", wheel_url(UUID_A)),
        );
        p.write(
            "pyproject.toml",
            format!(
                "[project]\nname = \"app\"\nversion = \"0\"\ndependencies = [\"urllib3 @ {}#sha256={SHA}\"]\n",
                wheel_url(UUID_A)
            ),
        );
        let out = p.discover().await;
        let files: Vec<_> = out
            .refs
            .iter()
            .map(|r| r.source_file.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            files,
            ["Pipfile.lock", "pyproject.toml", "requirements.txt"]
        );
        assert!(out
            .refs
            .iter()
            .all(|r| r.purl == "pkg:pypi/urllib3@1.26.18" && r.uuid == UUID_A));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }
}
