use std::collections::BTreeMap;

use serde_json::json;

use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
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
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        match plan(&text, dep) {
            Ok((rewritten, edits)) => {
                result.confirmed_pdm_uuids.insert(dep.patch_uuid.clone());
                let lock = rewritten.parse::<toml_edit::DocumentMut>().ok();
                if lock
                    .as_ref()
                    .and_then(|lock| crate::utils::pdm_lock::lock_version(lock).ok())
                    == Some("2")
                {
                    result.warnings.push(RewriteWarning { code: "redirect_pdm_legacy_sync_required".into(), detail: "PDM 0.x may regenerate freshly generated locks during install; use `pdm sync` to preserve this patch, or upgrade PDM".into() });
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
}
