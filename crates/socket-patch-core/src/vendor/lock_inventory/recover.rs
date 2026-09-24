//! Registry-fragment recovery from the vendor ledger
//! ([`recover_lock_entry`]).

use std::path::Path;

use serde_json::Value;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::digest::{is_hex, is_sri_pin, sha256_hex};
use crate::utils::purl::percent_decode_purl_component;

use super::gem::{gem_download_url, gem_remotes};
use super::pypi::python_lock_inventory;
use super::{http_url, LockIntegrity, LockfileEntry, SourceKind};

// ──────────────── registry-fragment recovery from the ledger ────────────────

/// Recover the PRE-VENDOR registry resolution of a vendored package from its
/// ledger entry's wiring `original` fragments (and `entry.lock` for cargo),
/// as a fetchable [`LockfileEntry`].
///
/// This is the rebuild path for artifacts that are referenced by the rewired
/// lockfile but missing on disk: the live lockfile no longer carries the
/// registry resolution (it points at `.socket/vendor/...`), but `--revert`'s
/// restore data does. golang is deliberately absent — go.sum is never
/// rewired, so the standard [`super::inventory_project`]/[`super::lookup`] path covers it.
///
/// SECURITY: state.json is committed and tamper-able. Recovered URLs go
/// through the same http(s)-only gate as inventoried ones, recovered hashes
/// are shape-validated here and verified against the fetched bytes
/// fail-closed by the fetch layer — a poisoned fragment can at worst make
/// the fetch fail, never land unverified content.
pub async fn recover_lock_entry(
    project_root: &Path,
    entry: &crate::vendor::state::VendorEntry,
) -> Result<LockfileEntry, String> {
    let (name, version) = parse_base_purl_coords(&entry.base_purl)
        .ok_or_else(|| format!("unparseable base purl `{}`", entry.base_purl))?;

    match entry.ecosystem.as_str() {
        "npm" => recover_npm_fragment(entry, &name, &version),
        "cargo" => {
            let checksum = entry
                .lock
                .as_ref()
                .and_then(|l| l.checksum.clone())
                .filter(|c| is_hex(c, 64))
                .ok_or_else(|| {
                    "the ledger records no pre-vendor Cargo.lock checksum".to_string()
                })?;
            // Vendoring only ever took over a crates.io entry: the recorded
            // checksum is the crates.io `.crate`'s sha256.
            Ok(LockfileEntry {
                ecosystem: "cargo",
                source_kind: SourceKind::CratesIo,
                purl: format!("pkg:cargo/{name}@{version}"),
                name,
                version,
                resolved: None,
                integrity: LockIntegrity::Sha256Hex(checksum.to_ascii_lowercase()),
            })
        }
        "composer" => {
            let original = wiring_original(entry, &["composer_lock_package"])
                .ok_or_else(|| "no pre-vendor composer.lock fragment recorded".to_string())?;
            let dist = original
                .get("dist")
                .ok_or_else(|| "the pre-vendor composer.lock fragment has no dist".to_string())?;
            let url = dist
                .get("url")
                .and_then(serde_json::Value::as_str)
                .and_then(http_url)
                .ok_or_else(|| "the pre-vendor dist has no http(s) url".to_string())?;
            let shasum = dist
                .get("shasum")
                .and_then(serde_json::Value::as_str)
                .filter(|s| is_hex(s, 40))
                .ok_or_else(|| {
                    "the pre-vendor dist records no shasum; refusing an unverifiable fetch"
                        .to_string()
                })?;
            Ok(LockfileEntry {
                ecosystem: "composer",
                source_kind: SourceKind::Unspecified,
                purl: format!("pkg:composer/{name}@{version}"),
                name,
                version,
                resolved: Some(url),
                integrity: LockIntegrity::Sha1Hex(shasum.to_ascii_lowercase()),
            })
        }
        "gem" => {
            let line = wiring_original(entry, &["gemfile_lock_checksum"])
                .and_then(|v| v.as_str().map(str::to_string))
                .ok_or_else(|| "no pre-vendor Gemfile.lock checksum recorded".to_string())?;
            let sha = line
                .split("sha256=")
                .nth(1)
                .map(|rest| {
                    rest.trim_end_matches(',')
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect::<String>()
                })
                .filter(|s| is_hex(s, 64))
                .ok_or_else(|| {
                    "the pre-vendor checksum line has no sha256; refusing an unverifiable fetch"
                        .to_string()
                })?;
            let base = match gem_remotes(project_root).await.as_slice() {
                [] => "https://rubygems.org".to_string(),
                [one] => http_url(one).ok_or_else(|| {
                    // A lone non-http remote (file:// gem repo): the registry
                    // conventions cannot reproduce its bytes, and defaulting
                    // to rubygems.org would leak the gem name off-site.
                    format!(
                        "the Gemfile.lock's GEM remote ({one}) is not an http(s) registry; \
                         refusing to fetch from a guessed remote"
                    )
                })?,
                several => {
                    // The vendored spec's own GEM section is gone (it moved
                    // into the PATH section), so with several sources its
                    // origin is genuinely ambiguous — a guessed remote
                    // would 404 at best and leak a private gem name to the
                    // public registry at worst.
                    return Err(format!(
                        "Gemfile.lock lists multiple GEM sources ({}); the vendored gem's \
                         pre-vendor source is ambiguous — refusing to fetch from a guessed \
                         remote",
                        several.join(", ")
                    ));
                }
            };
            Ok(LockfileEntry {
                ecosystem: "gem",
                source_kind: SourceKind::Unspecified,
                purl: format!("pkg:gem/{name}@{version}"),
                resolved: gem_download_url(&base, &name, &version),
                name,
                version,
                integrity: LockIntegrity::Sha256Hex(sha.to_ascii_lowercase()),
            })
        }
        "pypi" => {
            if entry.artifact.platform_locked == Some(true) {
                return Err(
                    "the vendored wheel is platform-locked (compiled); it cannot be rebuilt                      from the registry"
                        .to_string(),
                );
            }
            // The inventory canonicalizes names (PEP 503); the purl may carry
            // the project's own spelling (`PyYAML`, `typing_extensions`) —
            // compare in normalized form like `lookup` does.
            let canonical_name = canonicalize_pypi_name(&name);
            for wiring in entry
                .wiring
                .iter()
                .filter(|wiring| wiring.kind == "python_lock_document")
            {
                if let Some(text) = wiring.original.as_ref().and_then(Value::as_str) {
                    if let Some(entries) = python_lock_inventory(text) {
                        if let Some(resolution) = entries.into_iter().find(|candidate| {
                            candidate.name == canonical_name
                                && candidate.version == version
                                && candidate.resolved.is_some()
                                && candidate.integrity != LockIntegrity::None
                        }) {
                            return Ok(resolution);
                        }
                    }
                }
            }
            if entry
                .wiring
                .iter()
                .any(|wiring| wiring.kind == "python_lock_document")
            {
                return Err("the pre-vendor Python lock has no hash-pinned pure wheel for this package; reinstall it before repair".to_string());
            }
            // Every pypi package manager records the pre-vendor resolution under
            // its own wiring kind — uv writes `uv_lock_package`, pdm
            // `pdm_lock_package`, poetry `poetry_lock_package`, pipenv
            // `pipenv_lock_entry`, bare pip `requirements_line`. Accept them all
            // so recovery is not blind to non-uv projects.
            let fragment = wiring_original(
                entry,
                &[
                    "uv_lock_package",
                    "python_lock_document",
                    "pdm_lock_package",
                    "poetry_lock_package",
                    "pipenv_lock_entry",
                    "requirements_line",
                ],
            )
            .ok_or_else(|| "no pre-vendor pypi lock fragment recorded".to_string())?;
            // Only uv.lock and pdm's `static_urls` locks inline the wheel's
            // registry URL (`url = "…", hash = "sha256:…"`), which is all a
            // registry rebuild can fetch from. Default pdm/poetry (`file = …`),
            // pipenv (`hashes` only) and pip (`--hash=`) record the hash but no
            // fetchable URL — an honest, actionable message, not the false
            // "not installed / no recoverable fragment".
            const NO_URL: &str = "the pre-vendor pypi lock fragment records the wheel hash but \
                 no fetchable registry URL (only uv.lock and pdm `static_urls` locks carry wheel \
                 URLs); reinstall the package so repair can rebuild from the installed copy";
            // Pipenv's pre-vendor entry is a JSON object carrying every
            // release file's sha256 (`"hashes": ["sha256:…", …]`): fetchable
            // by digest through PyPI's JSON API like a fresh Pipfile.lock
            // inventory entry, so a lock-only checkout of an already-vendored
            // project re-scans green instead of `package_not_installed`.
            if let Some(object) = fragment.as_object() {
                let digests: Vec<String> = object
                    .get("hashes")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|h| h.strip_prefix("sha256:"))
                    .filter_map(sha256_hex)
                    .collect();
                if digests.is_empty() {
                    return Err(
                        "the pre-vendor Pipfile.lock entry records no sha256 digests; reinstall the \
                         package so repair can rebuild from the installed copy"
                            .to_string(),
                    );
                }
                return Ok(LockfileEntry {
                    ecosystem: "pypi",
                    source_kind: SourceKind::Unspecified,
                    purl: format!("pkg:pypi/{name}@{version}"),
                    name,
                    version,
                    resolved: None,
                    integrity: LockIntegrity::Sha256AnyOf(digests),
                });
            }
            let unit = fragment.as_str().ok_or_else(|| NO_URL.to_string())?;
            let (url, sha) = pure_wheel_from_uv_unit(unit).ok_or_else(|| NO_URL.to_string())?;
            Ok(LockfileEntry {
                ecosystem: "pypi",
                source_kind: SourceKind::Unspecified,
                purl: format!("pkg:pypi/{name}@{version}"),
                name,
                version,
                resolved: Some(url),
                integrity: LockIntegrity::Sha256Hex(sha),
            })
        }
        other => Err(format!(
            "no ledger-based registry recovery for ecosystem `{other}`"
        )),
    }
}

/// `pkg:<eco>/<name>@<version>` → (name, version). The name may itself
/// contain `/` (npm scopes, go modules); the version is after the LAST `@`.
/// Components percent-decode (`%40scope` → `@scope`): the ledger stores
/// `base_purl` verbatim as the manifest spelled it, while [`LockfileEntry`]
/// carries literal coordinates — the name feeds the registry URL and the
/// berry cache-zip recipe.
fn parse_base_purl_coords(base_purl: &str) -> Option<(String, String)> {
    let rest = base_purl.strip_prefix("pkg:")?;
    let (_, name_ver) = rest.split_once('/')?;
    let (name, version) = name_ver.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let name = name
        .split('/')
        .map(percent_decode_purl_component)
        .collect::<Vec<_>>()
        .join("/");
    let version = percent_decode_purl_component(version).into_owned();
    Some((name, version))
}

/// First wiring record of one of `kinds` carrying an `original` payload.
fn wiring_original<'a>(
    entry: &'a crate::vendor::state::VendorEntry,
    kinds: &[&str],
) -> Option<&'a serde_json::Value> {
    entry
        .wiring
        .iter()
        .find(|r| kinds.contains(&r.kind.as_str()) && r.original.is_some())
        .and_then(|r| r.original.as_ref())
}

/// Per-flavor npm recovery: the wiring kinds disambiguate the lock flavor,
/// each fragment yields (resolved?, integrity).
fn recover_npm_fragment(
    entry: &crate::vendor::state::VendorEntry,
    name: &str,
    version: &str,
) -> Result<LockfileEntry, String> {
    let mk = |resolved: Option<String>, integrity: LockIntegrity| LockfileEntry {
        ecosystem: "npm",
        source_kind: SourceKind::Unspecified,
        purl: format!("pkg:npm/{name}@{version}"),
        name: name.to_string(),
        version: version.to_string(),
        resolved,
        integrity,
    };

    // package-lock / shrinkwrap: the original is the full lock entry object.
    if let Some(obj) = wiring_original(entry, &["npm_lock_entry", "npm_lock_legacy_entry"]) {
        let resolved = obj
            .get("resolved")
            .and_then(serde_json::Value::as_str)
            .and_then(http_url);
        if let Some(sri) = obj
            .get("integrity")
            .and_then(serde_json::Value::as_str)
            .filter(|s| is_sri_pin(s))
        {
            return Ok(mk(resolved, LockIntegrity::Sri(sri.to_string())));
        }
    }
    // pnpm: the original is the packages block's lines; pull
    // `resolution: {integrity: …, tarball: …}`.
    if let Some(lines) = wiring_original(entry, &["pnpm_lock_package"]).and_then(lines_of) {
        let mut sri = None;
        let mut tarball = None;
        for line in &lines {
            if let Some(v) = inline_yaml_field(line, "integrity:") {
                sri = sri.or(Some(v));
            }
            if let Some(v) = inline_yaml_field(line, "tarball:") {
                tarball = tarball.or(http_url(&v));
            }
        }
        if let Some(sri) = sri.filter(|s| is_sri_pin(s)) {
            return Ok(mk(tarball, LockIntegrity::Sri(sri)));
        }
    }
    // yarn classic: block lines carry `integrity <sri>` (preferred) and/or
    // `resolved "<url>#<sha1>"`.
    if let Some(lines) = wiring_original(entry, &["yarn_lock_block"]).and_then(lines_of) {
        let mut url = None;
        let mut sha1 = None;
        let mut sri = None;
        for line in &lines {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("integrity ") {
                let v = rest.trim().trim_matches('"');
                if is_sri_pin(v) {
                    sri = Some(v.to_string());
                }
            }
            if let Some(rest) = t.strip_prefix("resolved ") {
                let v = rest.trim().trim_matches('"');
                let (u, frag_sha1) = crate::vendor::yarn_classic_lock::split_resolved_sha1(v);
                url = http_url(u);
                if frag_sha1.is_some() {
                    sha1 = frag_sha1;
                }
            }
        }
        if let Some(sri) = sri {
            return Ok(mk(url, LockIntegrity::Sri(sri)));
        }
        if let Some(sha1) = sha1 {
            return Ok(mk(url, LockIntegrity::Sha1Hex(sha1)));
        }
    }
    // yarn berry: block lines carry `checksum: <cacheKey>/<b64>`.
    if let Some(lines) = wiring_original(entry, &["yarn_berry_lock_entry"]).and_then(lines_of) {
        for line in &lines {
            if let Some(v) = inline_yaml_field(line, "checksum:") {
                if v.split_once('/')
                    .is_some_and(|(k, b)| !k.is_empty() && !b.is_empty())
                {
                    return Ok(mk(None, LockIntegrity::BerryChecksum(v)));
                }
            }
        }
    }
    // Binary Bun records carry semantic registry metadata alongside the
    // opaque fields needed for lossless restoration. Recovery must verify
    // the snapshot's coordinates before trusting its download and digest.
    for wiring in &entry.wiring {
        if wiring.kind != "bun_lockb_package" {
            continue;
        }
        let Some(original) = wiring.original.as_ref() else {
            continue;
        };
        if original.get("name").and_then(Value::as_str) != Some(name)
            || original.get("version").and_then(Value::as_str) != Some(version)
        {
            continue;
        }
        if let Some(sri) = original
            .get("integrity")
            .and_then(Value::as_str)
            .filter(|s| is_sri_pin(s))
        {
            let resolved = original
                .get("resolution")
                .and_then(Value::as_str)
                .and_then(http_url);
            return Ok(mk(resolved, LockIntegrity::Sri(sri.to_string())));
        }
    }
    // bun: the original is the raw tuple line; the integrity is its last
    // quoted SRI string.
    if let Some(line) =
        wiring_original(entry, &["bun_lock_package"]).and_then(|v| v.as_str().map(str::to_string))
    {
        if let Some(sri) = line
            .split('"')
            .rev()
            .find(|tok| is_sri_pin(tok))
            .map(str::to_string)
        {
            return Ok(mk(None, LockIntegrity::Sri(sri)));
        }
    }
    Err("no pre-vendor npm registry fragment with a verifiable integrity recorded".to_string())
}

/// A wiring `original` recorded as an array of text lines.
fn lines_of(v: &serde_json::Value) -> Option<Vec<String>> {
    v.as_array().map(|arr| {
        arr.iter()
            .filter_map(|l| l.as_str().map(str::to_string))
            .collect()
    })
}

/// `… field: value` (optionally inside an inline `{…}` map) → value, with
/// trailing `,`/`}` and quotes stripped.
pub(super) fn inline_yaml_field(line: &str, field: &str) -> Option<String> {
    let idx = line.find(field)?;
    let rest = &line[idx + field.len()..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    let v = rest[..end].trim().trim_matches(['\'', '"']).to_string();
    (!v.is_empty()).then_some(v)
}

/// First `{ url = "…", hash = "sha256:…" }` wheel in a uv.lock `[[package]]`
/// unit whose filename is a PURE wheel (`-none-any.whl`).
pub(super) fn pure_wheel_from_uv_unit(unit: &str) -> Option<(String, String)> {
    let mut search = unit;
    while let Some(uidx) = search.find("url = \"") {
        let after = &search[uidx + 7..];
        let uend = after.find('"')?;
        let url = &after[..uend];
        let rest = &after[uend..];
        let advance = uidx + 7 + uend;
        if url.ends_with("-none-any.whl") {
            if let Some(hidx) = rest.find("hash = \"sha256:") {
                let hafter = &rest[hidx + 15..];
                let hend = hafter.find('"')?;
                let sha = &hafter[..hend];
                if is_hex(sha, 64) {
                    if let Some(url) = http_url(url) {
                        return Some((url, sha.to_ascii_lowercase()));
                    }
                }
            }
        }
        search = &search[advance..];
    }
    None
}
