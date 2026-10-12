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
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::read_regular_to_string;
use crate::utils::poetry_lock::{
    lock_version, pyproject_source_constraints, source_constraint_breaks_writer,
    source_constraint_refusal, Wired,
};
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
    preflight_sibling_requirements_takeover(entry)?;
    match entry.flavor.as_deref() {
        Some("requirements") => preflight_requirements_takeover(entry),
        Some("uv") => preflight_uv_takeover(entry),
        Some("poetry") => preflight_poetry_takeover(root, entry).await,
        _ => Ok(()),
    }
}

/// A Pipenv or uv entry also carries the `requirements_line` records of
/// the exported requirements pin wired with its lock (#612, #1368). After
/// the revert, the hosted requirements rewriter re-pins only the root
/// requirements.txt, so a line wired in a `-r` include is refused exactly
/// as for a requirements-flavor entry.
fn preflight_sibling_requirements_takeover(entry: &VendorEntry) -> Result<(), RewriteWarning> {
    if !matches!(entry.flavor.as_deref(), Some("uv" | "pipenv")) {
        return Ok(());
    }
    let lines: Vec<_> = entry
        .wiring
        .iter()
        .filter(|r| r.kind == "requirements_line")
        .cloned()
        .collect();
    if lines.is_empty() {
        return Ok(());
    }
    preflight_requirements_takeover(&VendorEntry {
        flavor: Some("requirements".into()),
        wiring: lines,
        ..entry.clone()
    })
}

/// Vendored uv pins the lock's `[[package]]` unit to the patch's version
/// even when the lock resolved another one (#723). The revert restores the
/// recorded pre-vendor unit, and the hosted uv rewriter only pins an entry
/// whose `version` equals the patch's (`matching_package`), so a recorded
/// unit at another version can never be taken over.
fn preflight_uv_takeover(entry: &VendorEntry) -> Result<(), RewriteWarning> {
    let Some((_, raw_version)) = entry.base_purl.rsplit_once('@') else {
        return Ok(());
    };
    // Ledger purls keep the API's encoding (a PEP 440 local `+` is `%2B`);
    // the lock and `matching_package` compare the decoded version.
    let patch_version = crate::utils::purl::percent_decode_purl_component(raw_version);
    for record in entry.wiring.iter().filter(|r| r.kind == "uv_lock_package") {
        let Some(original) = record.original.as_ref().and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(locked) = recorded_unit_version(original) else {
            continue;
        };
        if locked != *patch_version {
            return Err(RewriteWarning {
                code: "redirect_uv_takeover_version_unreachable".into(),
                detail: format!(
                    "{} is vendored over {}'s {} entry for version {locked}, which vendored \
                     mode pinned down to the patch's {patch_version}; reverting it brings \
                     {locked} back, and hosted mode only pins the version the lock resolves, \
                     so it is kept vendored (not switched to hosted). To switch it: run \
                     `socket-patch vendor --revert` (this reverts EVERY vendored package in the \
                     project, not just this one), make the project resolve {patch_version} (for \
                     example an exact `=={patch_version}` requirement) and re-lock, then re-run \
                     `scan --mode hosted`",
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
/// sources), which vendored mode supports (#945), and a package the
/// pyproject pins to a named source over a lock Poetry 1.4 – 2.2 wrote
/// (#1282). The revert never changes the lock's format, stamp or the
/// pyproject, so the files on disk decide.
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
        return preflight_poetry_source_constraint(root, lock_file, &text, entry).await;
    }
    Err(RewriteWarning {
        code: "redirect_poetry_lock_unsupported".into(),
        detail: format!(
            "{lock_file}: Poetry 0.x ignores URL sources; hosted patches require Poetry >= 1.0, \
             so {} is kept vendored (not switched to hosted). To switch it: run \
             `socket-patch vendor --revert` (this reverts EVERY vendored package in the \
             project, not just this one), upgrade the project to Poetry >= 1.0 and re-lock, \
             then re-run `scan --mode hosted`",
            entry.base_purl
        ),
    })
}

/// The hosted rewriter's source-pin refusal (#1282), predicted from the
/// pyproject beside the lock and the lock's writer stamp.
async fn preflight_poetry_source_constraint(
    root: &Path,
    lock_file: &str,
    lock_text: &str,
    entry: &VendorEntry,
) -> Result<(), RewriteWarning> {
    if !source_constraint_breaks_writer(lock_text) {
        return Ok(());
    }
    let pyproject_file = format!(
        "{}pyproject.toml",
        lock_file.strip_suffix("poetry.lock").unwrap_or("")
    );
    let Ok(pyproject) = read_regular_to_string(&root.join(&pyproject_file)).await else {
        return Ok(());
    };
    let name = entry
        .base_purl
        .strip_prefix("pkg:pypi/")
        .and_then(|rest| rest.split('@').next())
        .unwrap_or_default();
    let Some(source) =
        pyproject_source_constraints(&pyproject).remove(&canonicalize_pypi_name(name))
    else {
        return Ok(());
    };
    Err(RewriteWarning {
        code: "redirect_poetry_lock_unsupported".into(),
        detail: format!(
            "{lock_file}: {} is kept vendored (not switched to hosted): {}",
            entry.base_purl,
            source_constraint_refusal(
                &pyproject_file,
                lock_file,
                name,
                &source,
                "URL",
                Wired::Vendored
            ),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::{VendorArtifact, WiringAction, WiringRecord};

    fn entry(flavor: &str, wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            flavor: Some(flavor.into()),
            ..VendorEntry::new(
                "pypi".into(),
                "pkg:pypi/six@1.16.0".into(),
                "u".into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: ".socket/vendor/pypi/u/six-1.16.0-py2.py3-none-any.whl".into(),
                    sha256: "0".repeat(64),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring,
            )
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
        assert_remedy_reverts_first(&err.detail);
    }

    /// Re-locking while the package is still vendored can't clear the
    /// refusal and makes the later revert see drift, so the remedy must
    /// unwind the vendored wiring first.
    fn assert_remedy_reverts_first(detail: &str) {
        let revert = detail.find("vendor --revert").expect(detail);
        let relock = detail.find("re-lock").expect(detail);
        assert!(revert < relock, "{detail}");
        assert!(detail.contains("EVERY vendored package"), "{detail}");
    }

    fn requirements_line(file: &str) -> WiringRecord {
        WiringRecord {
            file: file.into(),
            kind: "requirements_line".into(),
            action: WiringAction::Rewritten,
            key: Some(format!("{file}:1")),
            original: None,
            new: None,
        }
    }

    /// #1368 / #612: the exported pin wired with a uv or Pipenv lock is
    /// re-pinned by the hosted requirements rewriter, which reaches only
    /// the root requirements.txt; one wired in a `-r` include is refused
    /// before the revert, a root one is admitted.
    #[tokio::test]
    async fn sibling_export_in_an_include_is_refused() {
        let root = tempfile::tempdir().unwrap();
        for (flavor, lock) in [
            ("uv", uv_package("1.16.0")),
            ("pipenv", uv_package("1.16.0")),
        ] {
            let e = entry(
                flavor,
                vec![lock.clone(), requirements_line("requirements.txt")],
            );
            assert!(
                preflight_pypi_takeover(root.path(), &e).await.is_ok(),
                "{flavor}"
            );
            let e = entry(flavor, vec![lock, requirements_line("req/base.txt")]);
            let err = preflight_pypi_takeover(root.path(), &e).await.unwrap_err();
            assert_eq!(
                err.code, "redirect_requirements_takeover_unreachable",
                "{flavor}"
            );
            assert!(err.detail.contains("req/base.txt"), "{}", err.detail);
        }
    }

    #[test]
    fn uv_entry_at_the_patch_version_is_admitted() {
        assert!(preflight_uv_takeover(&entry("uv", vec![uv_package("1.16.0")])).is_ok());
    }

    #[test]
    fn uv_entry_at_an_encoded_local_patch_version_is_admitted() {
        let mut e = entry("uv", vec![uv_package("1.16.0+socket.1")]);
        e.base_purl = "pkg:pypi/six@1.16.0%2Bsocket.1".into();
        assert!(preflight_uv_takeover(&e).is_ok());
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
        assert_remedy_reverts_first(&err.detail);
    }

    #[tokio::test]
    async fn poetry_2_lock_is_admitted() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("poetry.lock"), POETRY_2).unwrap();
        assert!(preflight_pypi_takeover(tmp.path(), &poetry_entry())
            .await
            .is_ok());
    }

    /// #1282: hosted mode refuses a source-pinned package over a lock
    /// Poetry 1.4 – 2.2 wrote, so the takeover must keep it vendored rather
    /// than revert it into neither mode. Other writers are admitted.
    #[tokio::test]
    async fn poetry_source_pinned_package_follows_the_writer() {
        const PYPROJECT: &str =
            "[tool.poetry.dependencies]\nsix = {version = \"1.16.0\", source = \"pypi\"}\n";
        for (stamp, refused) in [("1.8.5", true), ("2.2.1", true), ("2.3.4", false)] {
            let tmp = tempfile::tempdir().unwrap();
            let lock = format!(
                "# This file is automatically @generated by Poetry {stamp} and should not be \
                 changed by hand.\n\n{POETRY_2}"
            );
            std::fs::write(tmp.path().join("poetry.lock"), lock).unwrap();
            std::fs::write(tmp.path().join("pyproject.toml"), PYPROJECT).unwrap();
            let got = preflight_pypi_takeover(tmp.path(), &poetry_entry()).await;
            if refused {
                let err = got.unwrap_err();
                assert_eq!(err.code, "redirect_poetry_lock_unsupported", "{stamp}");
                assert!(err.detail.contains("kept vendored"), "{}", err.detail);
                assert!(err.detail.contains("source = \"pypi\""), "{}", err.detail);
                assert_remedy_reverts_first(&err.detail);
            } else {
                assert!(got.is_ok(), "{stamp}: {got:?}");
            }
            // Without the pin every writer is admitted.
            std::fs::write(
                tmp.path().join("pyproject.toml"),
                "[tool.poetry.dependencies]\nsix = \"1.16.0\"\n",
            )
            .unwrap();
            assert!(preflight_pypi_takeover(tmp.path(), &poetry_entry())
                .await
                .is_ok());
        }
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
