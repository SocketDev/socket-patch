use std::collections::BTreeMap;

use serde_json::json;

use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::pdm_lock::{pdm_lock_edits, rewrite_pdm_lock};

pub(super) fn rewrite(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let Some(original) = files.get("pdm.lock") else {
        return;
    };
    let mut text = original.clone();
    let mut stale_warned = false;
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        // A package `pdm.lock` simply does not contain is not installed by pdm —
        // a sibling `requirements.txt`/pylock may legitimately carry it — so we
        // neither redirect it here nor veto the other pypi rewriters. Only a
        // package the lock DOES contain but the plan refuses (source conflict,
        // unsupported format, forked variants, bad hashes) withholds siblings.
        if !lock_contains(&text, &dep.name) {
            continue;
        }
        match plan(&text, dep) {
            Ok((rewritten, edits)) => {
                result.confirmed_pdm_uuids.insert(dep.patch_uuid.clone());
                let lock_ver: Option<String> = rewritten
                    .parse::<toml_edit::DocumentMut>()
                    .ok()
                    .and_then(|lock| {
                        crate::utils::pdm_lock::lock_version(&lock)
                            .ok()
                            .map(str::to_string)
                    });
                if lock_ver.as_deref() == Some("2") {
                    result.warnings.push(RewriteWarning { code: "redirect_pdm_legacy_sync_required".into(), detail: "PDM 0.x may regenerate freshly generated locks during install; use `pdm sync` to preserve this patch, or upgrade PDM".into() });
                }
                // PDM < 2.11 (lock_version "2"/"4.3"/"4.4") does not replace an
                // already-installed package at the same version, so a warm
                // `pdm sync`/`pdm install` leaves the upstream bytes live
                // (measured: 1.4.5/2.9.3/2.10.4 keep them; 2.11+ reinstall). The
                // installed-byte probe only fires for a discoverable venv, so a
                // PEP 582 `__pypackages__` or a lock-only/CI scan gets no
                // warning: warn proactively once per lock, mirroring poetry's
                // `redirect_poetry_stale_install_risk`.
                if !stale_warned
                    && matches!(lock_ver.as_deref(), Some("2") | Some("4.3") | Some("4.4"))
                {
                    stale_warned = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_pdm_stale_install_risk".into(),
                        detail: format!(
                            "pdm.lock (lock_version {}) was written by PDM < 2.11, which does \
                             not replace an already-installed package at the same version: an \
                             existing environment keeps the upstream {} until it is reinstalled \
                             \u{2014} recreate the environment (or uninstall the package) before \
                             `pdm sync`/`pdm install`; a fresh install picks up the patched \
                             wheel. The installed files were left unchanged.",
                            lock_ver.as_deref().unwrap_or_default(),
                            dep.name
                        ),
                    });
                }
                text = rewritten;
                result.edits.extend(edits);
            }
            Err(detail) => {
                result.refused_pdm_uuids.insert(dep.patch_uuid.clone());
                result.warnings.push(RewriteWarning {
                    code: "redirect_pdm_refused".into(),
                    detail,
                });
            }
        }
    }
    if text != *original {
        result.files.insert("pdm.lock".into(), text);
    }
}

/// Whether `pdm.lock` carries a `[[package]]` entry for `name`. When it does
/// not, pdm does not install this package, so the caller leaves it to the
/// sibling rewriters rather than vetoing them. A malformed lock, or one with no
/// package array, returns `true` so the genuine refusal still surfaces from
/// `rewrite_pdm_lock` (and, when pdm drives, withholds the siblings).
fn lock_contains(text: &str, name: &str) -> bool {
    let Ok(lock) = text.parse::<toml_edit::DocumentMut>() else {
        return true;
    };
    let canon = canonicalize_pypi_name(name);
    match lock
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
    {
        None => true,
        Some(packages) => packages.iter().any(|package| {
            package
                .get("name")
                .and_then(toml_edit::Item::as_str)
                .is_some_and(|candidate| canonicalize_pypi_name(candidate) == canon)
        }),
    }
}

fn plan(text: &str, dep: &DepOverride) -> Result<(String, Vec<FileEdit>), String> {
    let sha256 = dep
        .integrity
        .sha256
        .as_deref()
        .ok_or("missing PDM SHA-256")?;
    let url = reqwest::Url::parse(&dep.artifact_url).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err("unsupported PDM artifact URL".into());
    }
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or("missing PDM wheel filename")?;
    let rewritten = rewrite_pdm_lock(
        text,
        &dep.name,
        &dep.version,
        ("url", &dep.artifact_url),
        filename,
        sha256,
    )?;
    let edits = pdm_lock_edits(text, &rewritten, &dep.name)?
        .into_iter()
        .map(|(old, new)| FileEdit {
            path: "pdm.lock".into(),
            kind: "redirect_pdm_lock_package".into(),
            action: "rewritten".into(),
            key: Some(dep.name.clone()),
            original: Some(json!(old)),
            new: Some(json!(new)),
        })
        .collect();
    Ok((rewritten, edits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::redirect::Integrity;

    fn dep() -> DepOverride {
        DepOverride {
            ecosystem: "pypi".into(), name: "urllib3".into(), version: "1.26.18".into(),
            patch_uuid: "e828efa5-5c6d-43f3-9909-03f5ac232b98".into(),
            artifact_url: "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl".into(),
            integrity: Integrity { sha256: Some("a".repeat(64)), ..Default::default() },
            namespace: None, token: "token".into(), berry_zip_url: None, registry_override: None,
        }
    }

    #[test]
    fn confirms_only_semantic_pdm_edits_and_replays() {
        let original = include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock");
        let (rewritten, edits) = plan(original, &dep()).unwrap();
        assert_eq!(edits.len(), 1);
        assert!(rewritten.contains(&dep().artifact_url));
        let (same, edits) = plan(&rewritten, &dep()).unwrap();
        assert_eq!(same, rewritten);
        assert!(edits.is_empty());
        for text in [
            original.replace("4.5.1", "4.2"),
            original.replace("version = \"1.26.18\"", "version = '1.26.19'"),
            original.replace(
                "name = \"urllib3\"",
                "name = 'urllib3'\nurl = 'https://example.com/original.whl'",
            ),
        ] {
            let mut result = RewriteResult::default();
            rewrite(
                &BTreeMap::from([("pdm.lock".into(), text)]),
                &[dep()],
                &mut result,
            );
            assert!(result.files.is_empty());
            assert!(result.edits.is_empty());
            assert!(result.confirmed_pdm_uuids.is_empty());
            assert!(result.refused_pdm_uuids.contains(&dep().patch_uuid));
        }
    }

    /// A package `pdm.lock` simply LACKS (a different dep is granted, or the
    /// package installs via a sibling requirements.txt) is neither redirected
    /// nor vetoed — the veto is reserved for packages the lock CONTAINS but
    /// refuses, so a sibling rewriter can still land the patch.
    #[test]
    fn absent_package_is_skipped_not_vetoed() {
        let original = include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock");
        let other = DepOverride {
            name: "left-pad".into(),
            version: "1.3.0".into(),
            patch_uuid: "11111111-1111-4111-8111-111111111111".into(),
            ..dep()
        };
        let mut result = RewriteResult::default();
        rewrite(
            &BTreeMap::from([("pdm.lock".into(), original.to_string())]),
            std::slice::from_ref(&other),
            &mut result,
        );
        assert!(
            result.refused_pdm_uuids.is_empty(),
            "a package pdm.lock lacks must not veto the siblings"
        );
        assert!(result.confirmed_pdm_uuids.is_empty());
        assert!(result.files.is_empty());
    }

    /// A lock_version 2 / 4.3 / 4.4 lock (PDM < 2.11) raises a proactive
    /// stale-install advisory once, since those releases don't reinstall over
    /// an already-installed same-version package.
    #[test]
    fn legacy_formats_warn_stale_install_risk_once() {
        for (fixture, warns) in [
            (include_str!("../../../tests/fixtures/pdm-native/0.12.3.lock"), true),
            (include_str!("../../../tests/fixtures/pdm-native/2.8.2.lock"), true),
            (include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock"), false),
        ] {
            let mut result = RewriteResult::default();
            rewrite(
                &BTreeMap::from([("pdm.lock".into(), fixture.to_string())]),
                &[dep()],
                &mut result,
            );
            assert!(result.confirmed_pdm_uuids.contains(&dep().patch_uuid));
            let n = result
                .warnings
                .iter()
                .filter(|w| w.code == "redirect_pdm_stale_install_risk")
                .count();
            assert_eq!(n, usize::from(warns), "stale advisory once for < 2.11 only");
        }
    }
}
