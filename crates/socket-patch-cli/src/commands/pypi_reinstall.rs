//! The reinstall advisory for PyPI packages an unwind (`rollback`,
//! `remove`, `vendor --revert`, the manifest reconcile) put back on their
//! registry entry (#477).
//!
//! PDM, uv and Pipenv keep an installed release whose version the restored
//! lock still pins: their sync only reinstalls a same-version package when
//! the LOCKED candidate is a URL or file that differs from the installed
//! one. That is why the forward direction (registry → hosted / vendored)
//! installs the patch, and why the reverse (URL / file → registry) never
//! does: `pdm sync`, `uv sync` and `pipenv sync` all report nothing to do
//! and keep the patched build, whose `direct_url.json` still names the
//! patch server or the deleted `.socket/vendor/` wheel. So the generic
//! "until the next package-manager install" note is wrong for them, and
//! the advisory names the reinstall that does restore the upstream bytes.

use socket_patch_core::utils::purl::strip_purl_qualifiers;

/// A vendored revert's advisory, one per reverted entry.
pub(crate) const VENDOR_CODE: &str = "vendor_pypi_reinstall_required";
/// The hosted unwind's run-level advisory.
pub(crate) const HOSTED_CODE: &str = "redirect_pypi_reinstall_required";

/// Appended to rollback's generic reinstall note next to either advisory.
pub(crate) const NOTE_QUALIFIER: &str =
    " (PDM, uv and Pipenv keep a same-version install through a plain sync: \
     run the reinstall the pypi_reinstall_required warning names)";

/// True when `codes` carry a PyPI reinstall advisory.
pub(crate) fn advised<'a>(mut codes: impl Iterator<Item = &'a str>) -> bool {
    codes.any(|c| c == VENDOR_CODE || c == HOSTED_CODE)
}

/// The Python tool whose sync keeps a same-version install.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Tool {
    Pdm,
    Pipenv,
    Uv,
}

impl Tool {
    /// The tool of a vendored PyPI ledger entry's flavor.
    pub(crate) fn of_flavor(flavor: &str) -> Option<Tool> {
        match flavor {
            "pdm" => Some(Tool::Pdm),
            "pipenv" => Some(Tool::Pipenv),
            "uv" => Some(Tool::Uv),
            _ => None,
        }
    }

    /// The tool of a hosted pin's wiring file (`pdm.lock`, `Pipfile.lock`,
    /// `uv.lock`, in any directory).
    pub(crate) fn of_file(rel: &str) -> Option<Tool> {
        match rel.rsplit(['/', '\\']).next().unwrap_or(rel) {
            "pdm.lock" => Some(Tool::Pdm),
            "Pipfile.lock" => Some(Tool::Pipenv),
            "uv.lock" => Some(Tool::Uv),
            _ => None,
        }
    }
}

/// The distribution name of a `pkg:pypi/<name>@<version>` purl.
fn pypi_name(purl: &str) -> Option<&str> {
    strip_purl_qualifiers(purl)
        .strip_prefix("pkg:pypi/")
        .and_then(|rest| rest.split('@').next())
        .filter(|name| !name.is_empty())
}

/// The reinstall that brings back the upstream release of `name` under
/// `tool`. `pipfile_lock` is the project's parsed `Pipfile.lock` (it picks
/// the `pipenv sync` categories), when readable.
fn remedy(tool: Tool, name: &str, pipfile_lock: Option<&serde_json::Value>) -> String {
    match tool {
        Tool::Pdm => format!(
            "PDM keeps the installed {name} because the restored lock pins the same version \
             (`pdm sync` / `pdm install` report nothing to do): run `pdm sync --reinstall` (or \
             delete the virtualenv or `__pypackages__` and run `pdm sync`)"
        ),
        Tool::Uv => format!(
            "uv keeps the installed {name} because the restored lock pins the same version \
             (`uv sync` reports nothing to do): run `uv sync --reinstall-package {name}`"
        ),
        Tool::Pipenv => format!(
            "Pipenv never reinstalls a release that is already present (`pipenv install`, \
             `pipenv install --deploy` and `pipenv sync` all keep the installed {name}). {}",
            socket_patch_core::vendor::pypi_pipenv::stale_install_remedy(pipfile_lock, name)
        ),
    }
}

/// The advisory detail for `unwound` (`(purl, tool)` pairs), or `None` when
/// none of them is a PyPI package under PDM, uv or Pipenv.
pub(crate) async fn advisory(
    project_root: &std::path::Path,
    unwound: &[(String, Tool)],
) -> Option<String> {
    let mut parts: Vec<(String, String)> = Vec::new();
    let mut pipfile_lock: Option<Option<serde_json::Value>> = None;
    for (purl, tool) in unwound {
        let Some(name) = pypi_name(purl) else {
            continue;
        };
        let lock = if *tool == Tool::Pipenv {
            if pipfile_lock.is_none() {
                // A regular file only: a FIFO or device here must not
                // block the unwind.
                let text = socket_patch_core::utils::fs::read_regular_to_string(
                    &project_root.join("Pipfile.lock"),
                )
                .await
                .ok();
                pipfile_lock = Some(text.and_then(|t| serde_json::from_str(&t).ok()));
            }
            pipfile_lock.as_ref().and_then(Option::as_ref)
        } else {
            None
        };
        let base = strip_purl_qualifiers(purl).to_string();
        if parts.iter().any(|(p, _)| p == &base) {
            continue;
        }
        parts.push((base, remedy(*tool, name, lock)));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "the restored lock pins the same version as the patched build still installed, and \
         a plain sync keeps it: {}",
        parts
            .iter()
            .map(|(purl, remedy)| format!("{purl}: {remedy}"))
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

/// Push the vendored revert's advisory onto `warnings` when the reverted
/// ledger entry `key` (lockfile flavor `flavor`) is a PyPI package under
/// PDM, uv or Pipenv. The caller decides the revert unwired the entry.
pub(crate) async fn push_vendor_advisory(
    project_root: &std::path::Path,
    key: &str,
    flavor: Option<&str>,
    warnings: &mut Vec<socket_patch_core::vendor::VendorWarning>,
) {
    let Some(tool) = flavor.and_then(Tool::of_flavor) else {
        return;
    };
    if let Some(detail) = advisory(project_root, &[(key.to_string(), tool)]).await {
        warnings.push(socket_patch_core::vendor::VendorWarning::new(
            VENDOR_CODE,
            detail,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_follow_flavors_and_lock_files() {
        assert_eq!(Tool::of_flavor("pdm"), Some(Tool::Pdm));
        assert_eq!(Tool::of_flavor("pipenv"), Some(Tool::Pipenv));
        assert_eq!(Tool::of_flavor("uv"), Some(Tool::Uv));
        assert_eq!(Tool::of_flavor("poetry"), None);
        assert_eq!(Tool::of_flavor("package-lock"), None);
        assert_eq!(Tool::of_file("pdm.lock"), Some(Tool::Pdm));
        assert_eq!(Tool::of_file("app/Pipfile.lock"), Some(Tool::Pipenv));
        assert_eq!(Tool::of_file("uv.lock"), Some(Tool::Uv));
        assert_eq!(Tool::of_file("requirements.txt"), None);
    }

    #[tokio::test]
    async fn advisory_names_each_tools_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let detail = advisory(
            tmp.path(),
            &[
                ("pkg:pypi/urllib3@1.26.18".into(), Tool::Pdm),
                ("pkg:pypi/six@1.16.0?artifact_id=x".into(), Tool::Pipenv),
                ("pkg:pypi/idna@3.7".into(), Tool::Uv),
                ("pkg:npm/left-pad@1.3.0".into(), Tool::Uv),
            ],
        )
        .await
        .expect("an advisory");
        assert!(detail.contains("pkg:pypi/urllib3@1.26.18: PDM"), "{detail}");
        assert!(detail.contains("`pdm sync --reinstall`"), "{detail}");
        assert!(
            detail.contains("pkg:pypi/six@1.16.0: Pipenv")
                && detail.contains("pipenv run pip uninstall -y six && pipenv sync"),
            "{detail}"
        );
        assert!(
            detail.contains("`uv sync --reinstall-package idna`"),
            "{detail}"
        );
        assert!(!detail.contains("left-pad"), "{detail}");
        assert!(advisory(tmp.path(), &[]).await.is_none());
    }
}
