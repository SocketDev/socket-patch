use std::collections::BTreeMap;

use serde_json::Value;

use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::utils::poetry_lock::{poetry_lock_edits, rewrite_poetry_lock};

pub(super) fn rewrite_poetry(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    for (path, original) in files
        .iter()
        .filter(|(path, _)| path.as_str() == "poetry.lock" || path.ends_with("/poetry.lock"))
    {
        let mut content = original.clone();
        for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
            let Some(sha256) = dep.integrity.sha256.as_deref() else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_poetry_missing_sha256".into(),
                    detail: format!("{} has no SHA-256 integrity", dep.name),
                });
                continue;
            };
            let filename = dep.artifact_url.rsplit('/').next().unwrap_or("");
            match rewrite_poetry_lock(
                &content,
                &dep.name,
                &dep.version,
                "url",
                &dep.artifact_url,
                filename,
                sha256,
            ) {
                Ok(Some(rewritten)) if rewritten != content => {
                    match poetry_lock_edits(&content, &rewritten, &dep.name) {
                        Ok(edits) => {
                            for (original, new) in edits {
                                result.edits.push(FileEdit {
                                    path: path.clone(),
                                    kind: "redirect_poetry_lock_package".into(),
                                    action: "rewritten".into(),
                                    key: Some(format!("{}@{}", dep.name, dep.version)),
                                    original: Some(Value::String(original)),
                                    new: Some(Value::String(new)),
                                });
                            }
                        }
                        Err(detail) => {
                            result.warnings.push(RewriteWarning {
                                code: "redirect_poetry_lock_unsupported".into(),
                                detail,
                            });
                            continue;
                        }
                    }
                    content = rewritten;
                }
                Ok(_) => {}
                Err(detail) => result.warnings.push(RewriteWarning {
                    code: "redirect_poetry_lock_unsupported".into(),
                    detail: format!("{path}: {detail}"),
                }),
            }
        }
        if content != *original {
            result.files.insert(path.clone(), content);
        }
    }
}
