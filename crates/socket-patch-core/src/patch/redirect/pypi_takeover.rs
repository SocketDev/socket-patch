//! Reach checks for the PyPI vendored → hosted takeover.
//!
//! The takeover reverts a purl's vendored wiring and only then asks the
//! hosted rewriter to pin it. Whatever the hosted rewriter would refuse
//! after that revert has to be refused BEFORE it, or the package lands in
//! neither mode: the vendored wheel is deleted and the next install gets
//! the unpatched upstream release. Each check here reads only the ledger
//! entry and the lock as it is on disk, so the dry run predicts the same
//! refusal the wet run makes.

use std::path::Path;

use toml_edit::{DocumentMut, Item};

use super::requirements::preflight_requirements_takeover;
use super::RewriteWarning;
use crate::utils::fs::read_regular_to_string;
use crate::utils::poetry_lock::lock_version;
use crate::vendor::state::VendorEntry;

/// Refuse a PyPI takeover the hosted rewriter cannot carry through once
/// the vendored wiring is reverted. `root` is the project root the ledger
/// entry's wiring paths are relative to.
pub async fn preflight_pypi_takeover(
    root: &Path,
    entry: &VendorEntry,
) -> Result<(), RewriteWarning> {
    if entry.ecosystem != "pypi" {
        return Ok(());
    }
    match entry.flavor.as_deref() {
        Some("requirements") => preflight_requirements_takeover(entry),
        Some("uv") => preflight_uv_takeover(entry),
        Some("poetry") => preflight_poetry_takeover(root, entry).await,
        _ => Ok(()),
    }
}

/// Vendored uv pins the lock's `[[package]]` unit to the patch's version
/// even when the lock resolved another one (#723). The revert restores the
/// recorded pre-vendor unit, and the hosted uv rewriter only pins an entry
/// whose `version` equals the patch's (`matching_package`), so a recorded
/// unit at another version can never be taken over.
fn preflight_uv_takeover(entry: &VendorEntry) -> Result<(), RewriteWarning> {
    let Some((_, patch_version)) = entry.base_purl.rsplit_once('@') else {
        return Ok(());
    };
    for record in entry.wiring.iter().filter(|r| r.kind == "uv_lock_package") {
        let Some(original) = record.original.as_ref().and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(locked) = recorded_unit_version(original) else {
            continue;
        };
        if locked != patch_version {
            return Err(RewriteWarning {
                code: "redirect_uv_takeover_version_unreachable".into(),
                detail: format!(
                    "{} is vendored over {}'s {} entry for version {locked}, which vendored \
                     mode pinned down to the patch's {patch_version}; reverting it brings \
                     {locked} back, and hosted mode only pins the version the lock resolves, \
                     so it is kept vendored (not switched to hosted). To switch it: make the \
                     project resolve {patch_version} (for example an exact `=={patch_version}` \
                     requirement), re-lock, then re-run `scan --mode hosted`",
                    entry.base_purl, record.file, record.file,
                ),
            });
        }
    }
    Ok(())
}

/// The `version` of a recorded `[[package]]` unit, or None when the
/// fragment doesn't parse (the revert's own drift handling owns that case).
fn recorded_unit_version(unit: &str) -> Option<String> {
    let doc: DocumentMut = unit.parse().ok()?;
    doc.get("package")
        .and_then(Item::as_array_of_tables)
        .and_then(|units| units.get(0))
        .and_then(|unit| unit.get("version"))
        .and_then(Item::as_str)
        .map(str::to_string)
}

/// Hosted mode refuses every Poetry 0.x lock (Poetry 0.12 ignores URL
/// sources), which vendored mode supports (#945). The revert never changes
/// the lock's format, so the lock on disk decides.
async fn preflight_poetry_takeover(root: &Path, entry: &VendorEntry) -> Result<(), RewriteWarning> {
    let lock_file = entry
        .wiring
        .iter()
        .map(|r| r.file.as_str())
        .find(|f| *f == "poetry.lock" || f.ends_with("/poetry.lock"))
        .unwrap_or("poetry.lock");
    let Ok(text) = read_regular_to_string(&root.join(lock_file)).await else {
        return Ok(());
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return Ok(());
    };
    if lock_version(&doc) != Ok("0") {
        return Ok(());
    }
    Err(RewriteWarning {
        code: "redirect_poetry_lock_unsupported".into(),
        detail: format!(
            "{lock_file}: Poetry 0.x ignores URL sources; hosted patches require Poetry >= 1.0, \
             so {} is kept vendored (not switched to hosted). To switch it: upgrade the \
             project to Poetry >= 1.0 and re-lock, then re-run `scan --mode hosted`",
            entry.base_purl
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::{VendorArtifact, WiringAction, WiringRecord};

    fn entry(flavor: &str, wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: "u".into(),
            artifact: VendorArtifact {
                yarn_berry10c0: None,
                path: ".socket/vendor/pypi/u/six-1.16.0-py2.py3-none-any.whl".into(),
                sha256: "0".repeat(64),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some(flavor.into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    fn uv_package(original_version: &str) -> WiringRecord {
        WiringRecord {
            file: "uv.lock".into(),
            kind: "uv_lock_package".into(),
            action: WiringAction::Rewritten,
            key: Some("six".into()),
            original: Some(serde_json::Value::String(format!(
                "[[package]]\nname = \"six\"\nversion = \"{original_version}\"\n\
                 source = {{ registry = \"https://pypi.org/simple\" }}"
            ))),
            new: None,
        }
    }

    /// #723: the recorded pre-vendor unit resolved another version, so the
    /// revert would leave hosted mode nothing to pin.
    #[test]
    fn uv_pinned_down_entry_is_refused() {
        let err = preflight_uv_takeover(&entry("uv", vec![uv_package("1.17.0")])).unwrap_err();
        assert_eq!(err.code, "redirect_uv_takeover_version_unreachable");
        assert!(err.detail.contains("1.17.0"), "{}", err.detail);
    }

    #[test]
    fn uv_entry_at_the_patch_version_is_admitted() {
        assert!(preflight_uv_takeover(&entry("uv", vec![uv_package("1.16.0")])).is_ok());
    }

    #[test]
    fn uv_entry_without_a_parseable_original_is_admitted() {
        let mut record = uv_package("1.16.0");
        record.original = Some(serde_json::Value::String("not = [toml".into()));
        assert!(preflight_uv_takeover(&entry("uv", vec![record])).is_ok());
    }

    const POETRY_0: &str = "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\n\
        [metadata]\ncontent-hash = \"x\"\npython-versions = \">=3.9\"\n\n\
        [metadata.hashes]\nsix = []\n";
    const POETRY_2: &str = "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\n\
        [metadata]\nlock-version = \"2.1\"\npython-versions = \">=3.9\"\ncontent-hash = \"x\"\n";

    fn poetry_entry() -> VendorEntry {
        entry(
            "poetry",
            vec![WiringRecord {
                file: "poetry.lock".into(),
                kind: "poetry_lock_package".into(),
                action: WiringAction::Rewritten,
                key: Some("six".into()),
                original: None,
                new: None,
            }],
        )
    }

    /// #945: hosted mode refuses every Poetry 0.x lock.
    #[tokio::test]
    async fn poetry_0_lock_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("poetry.lock"), POETRY_0).unwrap();
        let err = preflight_pypi_takeover(tmp.path(), &poetry_entry())
            .await
            .unwrap_err();
        assert_eq!(err.code, "redirect_poetry_lock_unsupported");
    }

    #[tokio::test]
    async fn poetry_2_lock_is_admitted() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("poetry.lock"), POETRY_2).unwrap();
        assert!(preflight_pypi_takeover(tmp.path(), &poetry_entry())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn other_flavors_are_admitted() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            preflight_pypi_takeover(tmp.path(), &entry("pdm", Vec::new()))
                .await
                .is_ok()
        );
    }
}
