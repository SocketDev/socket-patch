//! pipenv wiring: a lock-ONLY `default`/`develop` entry rewrite of
//! `Pipfile.lock` (pipfile-spec 6).
//!
//! `pipenv verify` / `install --deploy` compare only `_meta.hash` (derived
//! from the Pipfile), so replacing a section entry with the V1/V2-captured
//! file-ref shape — `{"file": "./<rel wheel>", "hashes":
//! ["sha256:<patched>"], "markers": <preserved>}`, `index`/`version` dropped,
//! `_meta` untouched — survives `pipenv sync`, `install --deploy`, `verify`
//! and bare `pipenv install` byte-stably from a fresh checkout (spike
//! V2/V3). The serializer is pinned to pipenv's own
//! `json.dumps(obj, indent=4, sort_keys=True) + "\n"` (spike V7) so the lock
//! never churns. See `spikes/pipenv/` and the pipenv section of
//! `spikes/PHASE0-V2-FINDINGS.txt`.
//!
//! INTEGRITY caveat (spike V4, REFUTED claim): pipenv installs file-ref
//! entries through a separate pip phase with no `--hash`/`--require-hashes`,
//! so the recorded hash is NEVER enforced by pipenv itself — every vendor
//! run pushes a `vendor_integrity_unverified` warning and the committed
//! wheel bytes are the only tamper evidence (the hash we write becomes
//! enforced for free if pipenv ever fixes that phase).
//!
//! Drift caveat (spike V6): `pipenv lock` regenerates the entry to registry
//! shape and `pipenv update <pkg>` additionally rewrites the user's Pipfile
//! pin to `*` — both silent unpatch events; bare `pipenv install` is safe.

use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes;

use super::path::parse_vendor_path;
use super::state::{PipenvMeta, VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorWarning};

/// The only file this backend ever writes (and the revert allowlist).
const LOCK_FILE: &str = "Pipfile.lock";

/// The `WiringRecord.kind` discriminator this backend owns.
const KIND_LOCK_ENTRY: &str = "pipenv_lock_entry";

/// The Pipfile.lock sections searched/wired, in application order.
const SECTIONS: [&str; 2] = ["default", "develop"];

/// Pipfile.lock entry keys that mark a user-declared non-registry source.
const NON_REGISTRY_KEYS: [&str; 6] = ["path", "git", "hg", "svn", "bzr", "editable"];

/// A loaded-and-guard-checked pipenv project.
#[derive(Debug)]
pub struct PipenvProject {
    /// Verbatim Pipfile.lock text (byte-stability oracle for reverts).
    pub lock_text: String,
    /// Parsed lock (the edit substrate — re-serialized canonically).
    pub lock: Value,
    /// Non-fatal advisories raised during load. ALWAYS contains the
    /// `vendor_integrity_unverified` warning (spike V4: pipenv never enforces
    /// hashes on file-ref entries) — the orchestrator must surface these.
    pub warnings: Vec<VendorWarning>,
}

/// What the target entries already look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipenvTarget {
    /// At least one registry-shaped entry: proceed to build the wheel and
    /// wire.
    Fresh,
    /// Every matching entry is already wired to THIS patch uuid — the caller
    /// synthesizes an AlreadyPatched success, builds nothing, and records
    /// nothing (the first run's ledger entry holds the only copy of the
    /// originals).
    InSync,
}

/// Read + parse Pipfile.lock and run every project-level guard. Refuses
/// before ANY write — the orchestrator runs this (and the target guards)
/// before the wheel is built, so a refusal leaves the tree byte-untouched.
pub async fn load_pipenv_project(root: &Path) -> Result<PipenvProject, (&'static str, String)> {
    let lock_text = match tokio::fs::read_to_string(root.join(LOCK_FILE)).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err((
                "pypi_pipenv_no_lockfile",
                format!("no {LOCK_FILE} at the project root; run `pipenv lock` and re-run vendor"),
            ))
        }
        Err(e) => {
            return Err((
                "pypi_pipenv_lock_parse_failed",
                format!("cannot read {LOCK_FILE}: {e}"),
            ))
        }
    };
    let lock: Value = serde_json::from_str(&lock_text).map_err(|e| {
        (
            "pypi_pipenv_lock_parse_failed",
            format!("{LOCK_FILE} is not parseable JSON: {e}"),
        )
    })?;
    if !lock.is_object() {
        return Err((
            "pypi_pipenv_lock_parse_failed",
            format!("{LOCK_FILE} root is not a JSON object"),
        ));
    }
    let spec = lock
        .get("_meta")
        .and_then(|m| m.get("pipfile-spec"))
        .and_then(Value::as_u64);
    if spec != Some(6) {
        return Err((
            "pypi_pipenv_spec_unsupported",
            format!(
                "{LOCK_FILE} _meta.pipfile-spec is {spec:?}; only spec 6 locks are \
                 fixture-tested"
            ),
        ));
    }

    // ALWAYS pushed (spike V4 refuted hash enforcement): the recorded hash is
    // self-documentation, not a pipenv-enforced check.
    let warnings = vec![VendorWarning::new(
        "vendor_integrity_unverified",
        "pipenv never enforces the hashes recorded on file-ref lock entries (its file-ref \
         install phase invokes pip without --hash/--require-hashes), so the vendored wheel is \
         protected only by the committed wheel itself; `socket-patch verify` re-checks its \
         sha256 against the lock entry",
    )];
    Ok(PipenvProject {
        lock_text,
        lock,
        warnings,
    })
}

/// Target-specific guards (also re-run by [`wire_pipenv`] right before
/// writing). Entries match by PEP 503 canonical NAME in `default` and
/// `develop`; there is no version guard — the file-ref entry carries no
/// version key and the spike proved pipenv accepts a version pin-down
/// (V3's 1.17.0 → 1.16.0 splice installed cleanly).
pub(super) fn check_target_guards(
    p: &PipenvProject,
    canon_name: &str,
    record_uuid: &str,
) -> Result<PipenvTarget, (&'static str, String)> {
    let entries = find_entries(&p.lock, canon_name);
    if entries.is_empty() {
        return Err((
            "pypi_pipenv_lock_package_missing",
            format!(
                "{LOCK_FILE} names {canon_name} in neither default nor develop; run \
                 `pipenv lock` first"
            ),
        ));
    }
    let mut all_in_sync = true;
    for (section, key, entry) in &entries {
        let Some(obj) = entry.as_object() else {
            return Err((
                "pypi_pipenv_lock_parse_failed",
                format!("{LOCK_FILE} {section}.{key} is not a JSON object"),
            ));
        };
        if let Some(file_ref) = obj.get("file").and_then(Value::as_str) {
            match parse_vendor_path(file_ref) {
                // Ours, same patch generation.
                Some(parts) if parts.eco == "pypi" && parts.uuid == record_uuid => continue,
                // Ours, but a STALE patch generation: wiring over it would
                // lose the only recorded registry original — refuse with the
                // repair path (mirrors gem's stale-checksum refusal).
                Some(parts) if parts.eco == "pypi" => {
                    return Err((
                        "pypi_pipenv_source_already_exists",
                        format!(
                            "{LOCK_FILE} already routes {section}.{key} through \
                             .socket/vendor/pypi/{} (an earlier socket-patch vendor); run \
                             `socket-patch vendor --revert` for it and re-vendor",
                            parts.uuid
                        ),
                    ))
                }
                // A user-authored local file reference.
                _ => {
                    return Err((
                        "pypi_pipenv_source_already_exists",
                        format!(
                            "{LOCK_FILE} {section}.{key} is a user-declared file reference; \
                             refusing to overwrite it"
                        ),
                    ))
                }
            }
        }
        if let Some(non_registry) = NON_REGISTRY_KEYS.iter().find(|k| obj.contains_key(**k)) {
            return Err((
                "pypi_pipenv_source_already_exists",
                format!(
                    "{LOCK_FILE} {section}.{key} is a user-declared non-registry reference \
                     ({non_registry}); refusing to overwrite it"
                ),
            ));
        }
        all_in_sync = false;
    }
    Ok(if all_in_sync {
        PipenvTarget::InSync
    } else {
        PipenvTarget::Fresh
    })
}

/// Wire Pipfile.lock for the vendored wheel: replace every matching
/// `default`/`develop` entry with the V1/V2-captured file-ref shape (the new
/// document is fully computed, then committed atomically with the pinned
/// pipenv serialization). `rel_wheel` is the project-relative wheel path
/// (`.socket/vendor/pypi/<uuid>/<wheel>`, no `./` prefix — the fixture's
/// `./` spelling is applied here).
pub async fn wire_pipenv(
    p: &PipenvProject,
    root: &Path,
    canon_name: &str,
    rel_wheel: &str,
    wheel_sha256_hex: &str,
    record_uuid: &str,
) -> Result<(Vec<WiringRecord>, PipenvMeta), (&'static str, String)> {
    match check_target_guards(p, canon_name, record_uuid)? {
        // Defensive: the orchestrator short-circuits in-sync pre-flight and
        // never calls wire on it (we must never re-record our own edit as an
        // "original").
        PipenvTarget::InSync => {
            return Err((
                "pypi_pipenv_source_already_exists",
                format!(
                    "{LOCK_FILE} already wires {canon_name} to this patch's vendored wheel; \
                     nothing to wire"
                ),
            ))
        }
        PipenvTarget::Fresh => {}
    }

    let mut lock = p.lock.clone();
    let mut wiring: Vec<WiringRecord> = Vec::new();
    let mut sections: Vec<String> = Vec::new();
    for section in SECTIONS {
        let Some(map) = lock.get_mut(section).and_then(Value::as_object_mut) else {
            continue;
        };
        let keys: Vec<String> = map
            .keys()
            .filter(|k| canonicalize_pypi_name(k) == canon_name)
            .cloned()
            .collect();
        for key in keys {
            let old = map.get(&key).cloned().unwrap_or(Value::Null);
            // The V1/V2 entry shape: file + OUR hash; markers preserved
            // verbatim; index/version dropped (transitive entries never had
            // an index key — V3).
            let mut new_entry = Map::new();
            new_entry.insert("file".to_string(), Value::String(format!("./{rel_wheel}")));
            new_entry.insert(
                "hashes".to_string(),
                Value::Array(vec![Value::String(format!("sha256:{wheel_sha256_hex}"))]),
            );
            if let Some(markers) = old.get("markers") {
                new_entry.insert("markers".to_string(), markers.clone());
            }
            let new_value = Value::Object(new_entry);
            if old == new_value {
                // Per-entry idempotency: an entry already carrying our exact
                // shape needs no edit and no wiring record.
                continue;
            }
            // Never record one of our own edits as the "original" — revert
            // must restore the pre-vendor registry fragment (a vendor-pointing
            // old entry can only reach here through a same-uuid hash refresh;
            // stale uuids refuse in the guards).
            let was_vendored = old
                .get("file")
                .and_then(Value::as_str)
                .and_then(parse_vendor_path)
                .is_some();
            map.insert(key.clone(), new_value.clone());
            wiring.push(WiringRecord {
                file: LOCK_FILE.to_string(),
                kind: KIND_LOCK_ENTRY.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{section}:{key}")),
                original: if was_vendored { None } else { Some(old) },
                new: Some(new_value),
            });
            if !sections.iter().any(|s| s == section) {
                sections.push(section.to_string());
            }
        }
    }

    let new_text = to_canonical_json(&lock);
    atomic_write_bytes(&root.join(LOCK_FILE), new_text.as_bytes())
        .await
        .map_err(|e| {
            (
                "pypi_pipenv_write_failed",
                format!("cannot write {LOCK_FILE}: {e}"),
            )
        })?;
    Ok((wiring, PipenvMeta { sections }))
}

/// Reverse the wiring: restore the verbatim original entries (deep-equality
/// gated). An entry that no longer matches what we wrote is left alone with
/// a `vendor_lock_entry_drifted` warning — revert never clobbers third-party
/// edits.
pub async fn revert_pipenv(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    let lock_path = root.join(LOCK_FILE);
    let lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read {LOCK_FILE}: {e}")),
    };
    // Fail-closed: editing a lock we cannot parse risks destroying it.
    let mut lock: Value = match serde_json::from_str(&lock_text) {
        Ok(v) => v,
        Err(e) => {
            return RevertOutcome::failed(format!(
                "{LOCK_FILE} is not parseable JSON ({e}); fix it and re-run revert"
            ))
        }
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();
    let mut changed = false;

    for rec in entry.wiring.iter().rev() {
        // SECURITY: `rec.file` comes verbatim from the committed, tamper-able
        // state.json. This backend only ever wrote Pipfile.lock (the
        // per-flavor file allowlist); any other recorded path is skipped
        // fail-closed with a warning and is NEVER resolved against the
        // filesystem.
        if rec.file != LOCK_FILE {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for unexpected file `{}` (only {LOCK_FILE} is \
                     pipenv-owned)",
                    rec.file
                ),
            ));
            continue;
        }
        let drifted = || {
            VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{LOCK_FILE} entry for {:?} changed since vendoring; left untouched",
                    rec.key
                ),
            )
        };
        if rec.kind != KIND_LOCK_ENTRY {
            // Forward compatibility: a newer ledger's unknown kind degrades
            // to a warning (never guess at a fragment shape).
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown pipenv wiring kind {:?}; skipped", rec.kind),
            ));
            continue;
        }
        // SECURITY: the section component is also untrusted — only the two
        // known section names are ever dereferenced.
        let Some((section, name)) = rec.key.as_deref().and_then(|k| k.split_once(':')) else {
            warnings.push(drifted());
            continue;
        };
        if !SECTIONS.contains(&section) {
            warnings.push(drifted());
            continue;
        }
        let Some(map) = lock.get_mut(section).and_then(Value::as_object_mut) else {
            warnings.push(drifted());
            continue;
        };
        let (Some(new_value), Some(live)) = (rec.new.as_ref(), map.get(name)) else {
            warnings.push(drifted());
            continue;
        };
        if live != new_value {
            warnings.push(drifted());
            continue;
        }
        match (rec.action, rec.original.as_ref()) {
            (WiringAction::Rewritten, Some(orig)) => {
                map.insert(name.to_string(), orig.clone());
                changed = true;
            }
            // original=None means the pre-vendor entry was already
            // vendor-pointing (never recorded as an original) — there is no
            // registry fragment to restore.
            (WiringAction::Rewritten, None) => warnings.push(drifted()),
            (WiringAction::Added, _) => {
                map.remove(name);
                changed = true;
            }
        }
    }

    // Only re-serialize when something was restored: a no-op revert must not
    // churn a lock whose formatting we did not produce.
    if changed && !dry_run {
        let new_text = to_canonical_json(&lock);
        if let Err(e) = atomic_write_bytes(&lock_path, new_text.as_bytes()).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("cannot write {LOCK_FILE}: {e}")),
            };
        }
    }
    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Every `(section, key, entry)` whose key canonicalizes to `canon_name`.
fn find_entries<'a>(lock: &'a Value, canon_name: &str) -> Vec<(&'static str, String, &'a Value)> {
    let mut out = Vec::new();
    for section in SECTIONS {
        let Some(map) = lock.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (key, value) in map {
            if canonicalize_pypi_name(key) == canon_name {
                out.push((section, key.clone(), value));
            }
        }
    }
    out
}

/// pipenv's exact serialization (spike V7): 4-space indent, ALL keys sorted
/// at every nesting level, default separators, one trailing newline —
/// byte-identical to `json.dumps(obj, indent=4, sort_keys=True) + "\n"` for
/// the ASCII content pipenv locks carry.
fn to_canonical_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sorted(&map[k]));
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    sorted(value)
        .serialize(&mut ser)
        .expect("serializing a serde_json::Value cannot fail");
    let mut text = String::from_utf8(buf).expect("serde_json emits UTF-8");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    /// sha256 of the spike's patched wheel (spikes/pipenv/artifacts/SHA256SUMS).
    const WHEEL_SHA: &str = "573ecfcc2c1f54aeb4e3d6198d58069a3a3258a5a2b18906aae2761a4b2568a0";

    // ── fixture constants ──────────────────────────────────────────────
    // Byte-exact copies of the spikes/pipenv/ fixtures (pipenv 2026.6.2,
    // pipfile-spec 6; spike date 2026-06-10). The registry locks are
    // tool-generated (`pipenv lock`); the vendored locks are the
    // `.lock-only-edit` splices that pass sync / --deploy / verify
    // byte-stably (V2/V3). If these drift from the committed fixtures, the
    // spike dirs are the source of truth.

    /// spikes/pipenv/direct-registry/Pipfile.lock (verbatim).
    const LOCK_DIRECT_REGISTRY: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "55f44fe4c8bc29094f3076c7eddb912ca00f80c016020ffa2bcbd67ccc7114a1"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.14"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "six": {
            "hashes": [
                "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926",
                "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"
            ],
            "index": "pypi",
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
            "version": "==1.16.0"
        }
    },
    "develop": {}
}
"#;

    /// spikes/pipenv/direct-file/Pipfile.lock.lock-only-edit (verbatim —
    /// the V2 splice: file + patched hash, index/version dropped, markers
    /// kept, _meta untouched).
    const LOCK_DIRECT_VENDORED: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "55f44fe4c8bc29094f3076c7eddb912ca00f80c016020ffa2bcbd67ccc7114a1"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.14"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "six": {
            "file": "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl",
            "hashes": [
                "sha256:573ecfcc2c1f54aeb4e3d6198d58069a3a3258a5a2b18906aae2761a4b2568a0"
            ],
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'"
        }
    },
    "develop": {}
}
"#;

    /// spikes/pipenv/transitive-registry/Pipfile.lock (verbatim — six is
    /// FLAT in default at the resolver's 1.17.0, no index key).
    const LOCK_TRANSITIVE_REGISTRY: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "58546015c76e8085bff3be981f626feed276df866834bb057ab1c118de09ff77"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.14"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "python-dateutil": {
            "hashes": [
                "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86",
                "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"
            ],
            "index": "pypi",
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
            "version": "==2.8.2"
        },
        "six": {
            "hashes": [
                "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
                "sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81"
            ],
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
            "version": "==1.17.0"
        }
    },
    "develop": {}
}
"#;

    /// spikes/pipenv/transitive-file/Pipfile.lock.lock-only-edit (verbatim —
    /// the V3 splice; note the silent 1.17.0 → 1.16.0 pin-down, which pipenv
    /// accepts: install is per-entry with no cross-check).
    const LOCK_TRANSITIVE_VENDORED: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "58546015c76e8085bff3be981f626feed276df866834bb057ab1c118de09ff77"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.14"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "python-dateutil": {
            "hashes": [
                "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86",
                "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"
            ],
            "index": "pypi",
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
            "version": "==2.8.2"
        },
        "six": {
            "file": "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl",
            "hashes": [
                "sha256:573ecfcc2c1f54aeb4e3d6198d58069a3a3258a5a2b18906aae2761a4b2568a0"
            ],
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'"
        }
    },
    "develop": {}
}
"#;

    async fn write_lock(lock: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("Pipfile.lock"), lock).await.unwrap();
        tmp
    }

    async fn read_lock(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("Pipfile.lock")).await.unwrap()
    }

    fn entry_for(wiring: Vec<WiringRecord>, meta: PipenvMeta) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: REL_WHEEL.into(),
                sha256: WHEEL_SHA.into(),
                size: Some(11053),
                platform_locked: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            flavor: Some("pipenv".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: Some(meta),
        }
    }

    async fn wire_default(p: &PipenvProject, root: &Path) -> (Vec<WiringRecord>, PipenvMeta) {
        wire_pipenv(p, root, "six", REL_WHEEL, WHEEL_SHA, UUID).await.unwrap()
    }

    /// The load-bearing oracle: wiring the registry lock must produce the
    /// `.lock-only-edit` fixture BYTE-IDENTICALLY (direct V2 + transitive V3,
    /// which includes the version pin-down replacement), `_meta` untouched.
    #[tokio::test]
    async fn wiring_matches_fixtures_byte_identically() {
        let cases = [
            (LOCK_DIRECT_REGISTRY, LOCK_DIRECT_VENDORED, "direct"),
            (LOCK_TRANSITIVE_REGISTRY, LOCK_TRANSITIVE_VENDORED, "transitive"),
        ];
        for (before, after, label) in cases {
            let tmp = write_lock(before).await;
            let p = load_pipenv_project(tmp.path()).await.unwrap();
            assert_eq!(
                check_target_guards(&p, "six", UUID).unwrap(),
                PipenvTarget::Fresh
            );

            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            assert_eq!(
                read_lock(tmp.path()).await,
                after,
                "{label}: Pipfile.lock must byte-match the lock-only-edit fixture"
            );

            assert_eq!(wiring.len(), 1);
            assert_eq!(wiring[0].file, "Pipfile.lock");
            assert_eq!(wiring[0].kind, KIND_LOCK_ENTRY);
            assert_eq!(wiring[0].action, WiringAction::Rewritten);
            assert_eq!(wiring[0].key.as_deref(), Some("default:six"));
            // The verbatim registry entry is recorded for revert.
            assert!(
                wiring[0].original.as_ref().unwrap().get("hashes").is_some(),
                "original carries the registry entry: {:?}",
                wiring[0].original
            );
            assert_eq!(meta.sections, vec!["default".to_string()]);
        }
    }

    /// A package present in BOTH sections is wired in both, with one record
    /// per entry and both sections in the meta.
    #[tokio::test]
    async fn both_sections_wired_with_per_entry_records() {
        // Derive the before/after pair from the fixture parts: develop gets
        // the same registry entry (before) / vendored entry (after) as
        // default, re-rendered with the pinned pipenv serializer.
        let mut before: Value = serde_json::from_str(LOCK_DIRECT_REGISTRY).unwrap();
        let six_registry = before["default"]["six"].clone();
        before["develop"]["six"] = six_registry;
        let before_text = to_canonical_json(&before);

        let mut after: Value = serde_json::from_str(LOCK_DIRECT_VENDORED).unwrap();
        let six_vendored = after["default"]["six"].clone();
        after["develop"]["six"] = six_vendored;
        let after_text = to_canonical_json(&after);

        let tmp = write_lock(&before_text).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_default(&p, tmp.path()).await;

        assert_eq!(read_lock(tmp.path()).await, after_text);
        assert_eq!(wiring.len(), 2);
        let keys: Vec<&str> = wiring.iter().filter_map(|w| w.key.as_deref()).collect();
        assert_eq!(keys, vec!["default:six", "develop:six"]);
        assert_eq!(meta.sections, vec!["default".to_string(), "develop".to_string()]);

        // Round trip: both entries restored byte-identically.
        let outcome = revert_pipenv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(read_lock(tmp.path()).await, before_text);
    }

    /// Spike V4 (REFUTED): pipenv never enforces file-ref hashes, so EVERY
    /// load carries the integrity warning for the orchestrator to surface.
    #[tokio::test]
    async fn integrity_unverified_warning_always_present() {
        let tmp = write_lock(LOCK_DIRECT_REGISTRY).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        assert_eq!(p.warnings.len(), 1);
        assert_eq!(p.warnings[0].code, "vendor_integrity_unverified");
        assert!(
            p.warnings[0].detail.contains("protected only by the committed wheel itself"),
            "{}",
            p.warnings[0].detail
        );
        // Present on the already-vendored (in-sync) lock too.
        let tmp = write_lock(LOCK_DIRECT_VENDORED).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        assert_eq!(p.warnings[0].code, "vendor_integrity_unverified");
    }

    /// Spike V7: our serializer reproduces pipenv's own
    /// `json.dumps(indent=4, sort_keys=True) + "\n"` byte-for-byte, so a
    /// parse → serialize round trip of a pipenv-written lock is the identity.
    #[test]
    fn canonical_serializer_is_byte_stable_against_pipenv_output() {
        for fixture in [
            LOCK_DIRECT_REGISTRY,
            LOCK_DIRECT_VENDORED,
            LOCK_TRANSITIVE_REGISTRY,
            LOCK_TRANSITIVE_VENDORED,
        ] {
            let value: Value = serde_json::from_str(fixture).unwrap();
            assert_eq!(to_canonical_json(&value), fixture);
        }
        // And it actively sorts keys at every level (pipenv's sort_keys).
        let scrambled: Value = serde_json::from_str(r#"{"b": {"z": 1, "a": 2}, "a": []}"#).unwrap();
        assert_eq!(
            to_canonical_json(&scrambled),
            "{\n    \"a\": [],\n    \"b\": {\n        \"a\": 2,\n        \"z\": 1\n    }\n}\n"
        );
    }

    #[tokio::test]
    async fn guards_refuse_missing_lock_parse_spec_package_and_sources() {
        // missing lockfile
        let tmp = tempfile::tempdir().unwrap();
        let err = load_pipenv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_no_lockfile");
        assert!(err.1.contains("pipenv lock"), "{}", err.1);

        // unparseable / non-object lock
        let tmp = write_lock("{not json").await;
        let err = load_pipenv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_lock_parse_failed");
        let tmp = write_lock("[]").await;
        let err = load_pipenv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_lock_parse_failed");

        // pipfile-spec != 6 (and missing entirely)
        let tmp = write_lock(&LOCK_DIRECT_REGISTRY.replace("\"pipfile-spec\": 6", "\"pipfile-spec\": 7")).await;
        let err = load_pipenv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_spec_unsupported");
        let tmp = write_lock("{\"default\": {}}").await;
        let err = load_pipenv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_spec_unsupported");

        // package missing from both sections
        let tmp = write_lock(LOCK_DIRECT_REGISTRY).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "absent-pkg", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_lock_package_missing");

        // user-declared file reference
        let user = LOCK_DIRECT_VENDORED.replace(
            "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl",
            "./local/six-1.16.0-py2.py3-none-any.whl",
        );
        let tmp = write_lock(&user).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_source_already_exists");
        assert!(err.1.contains("user-declared"), "{}", err.1);

        // user-declared vcs reference
        let git = LOCK_DIRECT_REGISTRY.replace(
            "\"index\": \"pypi\",",
            "\"git\": \"https://github.com/benjaminp/six.git\",",
        );
        let tmp = write_lock(&git).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_source_already_exists");
        assert!(err.1.contains("git"), "{}", err.1);

        // wire re-runs the guards itself (refusal before any write)
        let before = read_lock(tmp.path()).await;
        let err = wire_pipenv(&p, tmp.path(), "six", REL_WHEEL, WHEEL_SHA, UUID)
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_source_already_exists");
        assert_eq!(read_lock(tmp.path()).await, before, "refusal writes nothing");
    }

    /// Re-running vendor on an already-wired lock with the SAME uuid is the
    /// in-sync hot path: the caller synthesizes AlreadyPatched and records
    /// nothing; a DIFFERENT uuid refuses with `vendor --revert` guidance.
    #[tokio::test]
    async fn rerun_same_uuid_in_sync_and_stale_uuid_refuses_with_guidance() {
        let tmp = write_lock(LOCK_DIRECT_VENDORED).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", UUID).unwrap(),
            PipenvTarget::InSync
        );

        let stale_uuid = "00000000-0000-4000-8000-000000000000";
        let err = check_target_guards(&p, "six", stale_uuid).unwrap_err();
        assert_eq!(err.0, "pypi_pipenv_source_already_exists");
        assert!(err.1.contains("--revert"), "{}", err.1);
        assert!(err.1.contains(UUID), "names the wired uuid: {}", err.1);
    }

    /// Dry-run purity: load + guards are pure reads, mirroring pypi_uv's
    /// compute/write split (the orchestrator never calls wire on a dry run).
    #[tokio::test]
    async fn load_and_guards_write_nothing() {
        let tmp = write_lock(LOCK_DIRECT_REGISTRY).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let _ = check_target_guards(&p, "six", UUID).unwrap();
        assert_eq!(read_lock(tmp.path()).await, LOCK_DIRECT_REGISTRY);
    }

    #[tokio::test]
    async fn revert_round_trip_restores_lock_byte_identically() {
        for before in [LOCK_DIRECT_REGISTRY, LOCK_TRANSITIVE_REGISTRY] {
            let tmp = write_lock(before).await;
            let p = load_pipenv_project(tmp.path()).await.unwrap();
            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            let entry = entry_for(wiring, meta);

            let outcome = revert_pipenv(&entry, tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(read_lock(tmp.path()).await, before, "byte-identical revert");
        }
    }

    #[tokio::test]
    async fn revert_dry_run_changes_nothing() {
        let tmp = write_lock(LOCK_DIRECT_REGISTRY).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_default(&p, tmp.path()).await;
        let wired = read_lock(tmp.path()).await;

        let outcome = revert_pipenv(&entry_for(wiring, meta), tmp.path(), true).await;
        assert!(outcome.success);
        assert_eq!(read_lock(tmp.path()).await, wired, "dry run must not write");
    }

    /// SECURITY: a poisoned state.json wiring record naming any file other
    /// than Pipfile.lock (or smuggling an unknown section into the key) is
    /// skipped fail-closed — the named path/pointer is never dereferenced.
    #[tokio::test]
    async fn revert_allowlist_skips_unexpected_files_and_sections_fail_closed() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("Pipfile.lock"), LOCK_DIRECT_REGISTRY)
            .await
            .unwrap();
        let precious = outer.path().join("precious.txt");
        tokio::fs::write(&precious, "keep me intact\n").await.unwrap();

        let bad_records = [
            ("Pipfile", "default:six"),
            ("../precious.txt", "default:six"),
            ("/etc/hosts", "default:six"),
            ("Pipfile.lock", "_meta:six"),
            ("Pipfile.lock", "no-colon-key"),
        ];
        for (file, key) in bad_records {
            let wiring = vec![WiringRecord {
                file: file.to_string(),
                kind: KIND_LOCK_ENTRY.to_string(),
                action: WiringAction::Rewritten,
                key: Some(key.to_string()),
                original: Some(serde_json::json!({"malicious": true})),
                new: Some(serde_json::json!("keep me intact")),
            }];
            let meta = PipenvMeta { sections: vec!["default".into()] };
            let outcome = revert_pipenv(&entry_for(wiring, meta), &root, false).await;
            assert!(outcome.success, "skipped fail-closed, not a hard error: {file}/{key}");
            assert!(
                outcome.warnings.iter().any(|w| w.code == "vendor_lock_entry_drifted"),
                "skip surfaced for {file}/{key}: {:?}",
                outcome.warnings
            );
        }
        assert_eq!(
            tokio::fs::read_to_string(&precious).await.unwrap(),
            "keep me intact\n",
            "out-of-tree file byte-untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Pipfile.lock")).await.unwrap(),
            LOCK_DIRECT_REGISTRY,
            "no record matched: the lock is not even re-serialized"
        );
    }

    /// A third-party edit to the entry we wrote (e.g. `pipenv lock`
    /// regenerated it — spike V6) is left alone with a drift warning;
    /// unknown wiring kinds from a newer ledger degrade the same way.
    #[tokio::test]
    async fn revert_warns_and_skips_on_drifted_entry_and_unknown_kind() {
        let tmp = write_lock(LOCK_DIRECT_REGISTRY).await;
        let p = load_pipenv_project(tmp.path()).await.unwrap();
        let (mut wiring, meta) = wire_default(&p, tmp.path()).await;
        wiring.push(WiringRecord {
            file: "Pipfile.lock".into(),
            kind: "pipenv_future_kind".into(),
            action: WiringAction::Added,
            key: Some("default:six".into()),
            original: None,
            new: Some(serde_json::json!("x")),
        });

        // Drift: someone replaced our hash in the vendored entry.
        let drifted = read_lock(tmp.path()).await.replace(WHEEL_SHA, &"0".repeat(64));
        tokio::fs::write(tmp.path().join("Pipfile.lock"), &drifted).await.unwrap();

        let outcome = revert_pipenv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(
            outcome
                .warnings
                .iter()
                .filter(|w| w.code == "vendor_lock_entry_drifted")
                .count(),
            2,
            "drifted entry + unknown kind: {:?}",
            outcome.warnings
        );
        assert_eq!(read_lock(tmp.path()).await, drifted, "drifted lock left alone");
    }
}
