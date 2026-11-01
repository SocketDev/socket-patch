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
//! patch server or the deleted `.socket/vendor/` wheel. Plain pip does the
//! same for a requirements file (#1953): once the line is back to
//! `name==version`, `pip install -r` reports `Requirement already
//! satisfied` and keeps the patched wheel, and `pip freeze` keeps emitting
//! its URL. So the generic "until the next package-manager install" note
//! is wrong for them, and the advisory names the reinstall that does
//! restore the upstream bytes.

use socket_patch_core::utils::purl::strip_purl_qualifiers;

/// A vendored revert's advisory, one per reverted entry.
pub(crate) const VENDOR_CODE: &str = "vendor_pypi_reinstall_required";
/// The hosted unwind's run-level advisory.
pub(crate) const HOSTED_CODE: &str = "redirect_pypi_reinstall_required";

/// Appended to rollback's generic reinstall note next to either advisory.
pub(crate) const NOTE_QUALIFIER: &str =
    " (pip, PDM, uv and Pipenv keep a same-version install through a plain install or sync: \
     run the reinstall the pypi_reinstall_required warning names)";

/// True when `codes` carry a PyPI reinstall advisory.
pub(crate) fn advised<'a>(mut codes: impl Iterator<Item = &'a str>) -> bool {
    codes.any(|c| c == VENDOR_CODE || c == HOSTED_CODE)
}

/// The Python tool whose sync keeps a same-version install.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Tool {
    /// A requirements file installed with `pip install -r` (or
    /// `uv pip install -r`).
    Pip,
    Pdm,
    Pipenv,
    Uv,
}

impl Tool {
    /// The tool of a vendored PyPI ledger entry's flavor.
    pub(crate) fn of_flavor(flavor: &str) -> Option<Tool> {
        match flavor {
            "requirements" => Some(Tool::Pip),
            "pdm" => Some(Tool::Pdm),
            "pipenv" => Some(Tool::Pipenv),
            "uv" => Some(Tool::Uv),
            _ => None,
        }
    }

    /// The tool of a hosted pin's wiring file (`pdm.lock`, `Pipfile.lock`,
    /// `uv.lock`, in any directory, or a file the hosted restore reads as a
    /// pip requirements file).
    pub(crate) fn of_file(rel: &str) -> Option<Tool> {
        match rel.rsplit(['/', '\\']).next().unwrap_or(rel) {
            "pdm.lock" => Some(Tool::Pdm),
            "Pipfile.lock" => Some(Tool::Pipenv),
            "uv.lock" => Some(Tool::Uv),
            _ => socket_patch_core::patch::redirect::upstream::is_requirements_file(rel)
                .then_some(Tool::Pip),
        }
    }

    /// The tool of a hosted pin wired by `files`. A lock tool wins over a
    /// requirements file next to it (a `uv export` requirements.txt beside
    /// `uv.lock`): the project installs through the lock, whose sync is
    /// what keeps the patched build.
    pub(crate) fn of_files<S: AsRef<str>>(files: &[S]) -> Option<Tool> {
        files
            .iter()
            .filter_map(|f| Tool::of_file(f.as_ref()))
            .min_by_key(|tool| *tool == Tool::Pip)
    }
}

/// One unwound PyPI package: its purl, the tool whose plain sync or
/// install keeps the patched build, and (pip only) the project-relative
/// requirements files that wired it, which the remedy reinstalls from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unwound {
    pub(crate) purl: String,
    pub(crate) tool: Tool,
    pub(crate) requirements: Vec<String>,
}

impl Unwound {
    /// `purl` under `tool`, keeping the requirements files among `files`.
    pub(crate) fn new<S: AsRef<str>>(purl: &str, tool: Tool, files: &[S]) -> Self {
        let mut requirements: Vec<String> = files
            .iter()
            .map(AsRef::as_ref)
            .filter(|f| Tool::of_file(f) == Some(Tool::Pip))
            .map(str::to_string)
            .collect();
        requirements.sort();
        requirements.dedup();
        Unwound {
            purl: purl.to_string(),
            tool,
            requirements,
        }
    }
}

/// `path` as one POSIX shell word: as-is when it holds only safe
/// characters, else single-quoted.
fn shell_word(path: &str) -> String {
    if !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/+=:@,".contains(&b))
    {
        path.to_string()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
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
/// the `pipenv sync` categories), when readable. `requirements` are the
/// project-relative requirements files that wired a pip package.
fn remedy(
    tool: Tool,
    name: &str,
    requirements: &[String],
    pipfile_lock: Option<&serde_json::Value>,
) -> String {
    match tool {
        // Uninstall, then reinstall from the requirements files that
        // wired it: unlike a pinned `--force-reinstall`, that keeps the
        // files' own version range, index and `--hash` options.
        Tool::Pip => {
            let (from, args) = if requirements.is_empty() {
                (
                    "the requirements file".to_string(),
                    "-r <requirements file>".to_string(),
                )
            } else {
                (
                    format!(
                        "the requirements file{} that pinned it",
                        if requirements.len() == 1 { "" } else { "s" }
                    ),
                    requirements
                        .iter()
                        .map(|f| format!("-r {}", shell_word(f)))
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            };
            format!(
                "pip keeps the installed {name} because the patched build still satisfies the \
                 restored requirement (`pip install -r` reports `Requirement already \
                 satisfied`, and `pip freeze` still names the patched build): in each \
                 environment that installed it, run `pip uninstall -y {name}` and then \
                 reinstall from {from} from the project root (`pip install {args}`; under \
                 `uv pip`: `uv pip uninstall {name} && uv pip install {args}`)"
            )
        }
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

/// The advisory detail for `unwound`, or `None` when none of them is a
/// PyPI package under pip, PDM, uv or Pipenv.
pub(crate) async fn advisory(
    project_root: &std::path::Path,
    unwound: &[Unwound],
) -> Option<String> {
    let mut parts: Vec<(String, String)> = Vec::new();
    let mut pipfile_lock: Option<Option<serde_json::Value>> = None;
    for Unwound {
        purl,
        tool,
        requirements,
    } in unwound
    {
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
        parts.push((base, remedy(*tool, name, requirements, lock)));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "the restored lock or requirement pins the same version as the patched build still \
         installed, and a plain sync or install keeps it: {}",
        parts
            .iter()
            .map(|(purl, remedy)| format!("{purl}: {remedy}"))
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

/// Push the vendored revert's advisory onto `warnings` when the reverted
/// ledger entry `key` (lockfile flavor `flavor`, wiring files `files`) is
/// a PyPI package under pip (a requirements file), PDM, uv or Pipenv. The
/// caller decides the revert unwired the entry.
pub(crate) async fn push_vendor_advisory(
    project_root: &std::path::Path,
    key: &str,
    flavor: Option<&str>,
    files: &[String],
    warnings: &mut Vec<socket_patch_core::vendor::VendorWarning>,
) {
    let Some(tool) = flavor.and_then(Tool::of_flavor) else {
        return;
    };
    if let Some(detail) = advisory(project_root, &[Unwound::new(key, tool, files)]).await {
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
        assert_eq!(Tool::of_file("pyproject.toml"), None);
    }

    /// #1953: plain pip keeps a same-version install through
    /// `pip install -r` (`Requirement already satisfied`), so a vendored
    /// `requirements` entry and a hosted pin in any requirements file get
    /// the pip remedy.
    #[test]
    fn requirements_wiring_is_pip() {
        assert_eq!(Tool::of_flavor("requirements"), Some(Tool::Pip));
        assert_eq!(Tool::of_file("requirements.txt"), Some(Tool::Pip));
        assert_eq!(Tool::of_file("reqs/dev.txt"), Some(Tool::Pip));
        // Only what the hosted restore itself reads as requirements.
        assert_eq!(Tool::of_file("requirements.in"), None);
        assert_eq!(Tool::of_file("pylock.toml"), None);
        assert_eq!(Tool::of_flavor("python-lock"), None);
        // A `uv export` requirements.txt beside uv.lock: uv's sync is the
        // install that keeps the patched build.
        assert_eq!(
            Tool::of_files(&["requirements.txt", "uv.lock"]),
            Some(Tool::Uv)
        );
        assert_eq!(Tool::of_files(&["requirements.txt"]), Some(Tool::Pip));
        assert_eq!(Tool::of_files::<&str>(&[]), None);
    }

    #[tokio::test]
    async fn advisory_names_pips_uninstall_and_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let detail = advisory(
            tmp.path(),
            &[Unwound::new(
                "pkg:pypi/six@1.16.0?artifact_id=x",
                Tool::Pip,
                &["requirements.txt"],
            )],
        )
        .await
        .expect("an advisory");
        assert!(detail.contains("pkg:pypi/six@1.16.0: pip"), "{detail}");
        assert!(detail.contains("`pip uninstall -y six`"), "{detail}");
        assert!(
            detail.contains("`pip install -r requirements.txt`"),
            "{detail}"
        );
        assert!(
            detail.contains("`uv pip uninstall six && uv pip install -r requirements.txt`"),
            "{detail}"
        );
        assert!(!detail.contains("artifact_id"), "{detail}");
    }

    /// Bugbot on #1954: the remedy reinstalls from the files that wired
    /// the pin, not a guessed `requirements.txt`, and drops lock files.
    #[tokio::test]
    async fn pip_remedy_names_the_wiring_requirements_files() {
        let tmp = tempfile::tempdir().unwrap();
        let detail = advisory(
            tmp.path(),
            &[Unwound::new(
                "pkg:pypi/six@1.16.0",
                Tool::Pip,
                &[
                    "reqs/dev.txt",
                    "my reqs/base.txt",
                    "uv.lock",
                    "reqs/dev.txt",
                ],
            )],
        )
        .await
        .expect("an advisory");
        assert!(
            detail.contains("`pip install -r 'my reqs/base.txt' -r reqs/dev.txt`"),
            "{detail}"
        );
        assert!(!detail.contains("requirements.txt"), "{detail}");
        assert!(!detail.contains("uv.lock"), "{detail}");
        // No recorded wiring (a `repair`-reconstructed entry): a
        // placeholder, never a guessed file name.
        let none: &[&str] = &[];
        let detail = advisory(
            tmp.path(),
            &[Unwound::new("pkg:pypi/six@1.16.0", Tool::Pip, none)],
        )
        .await
        .expect("an advisory");
        assert!(
            detail.contains("`pip install -r <requirements file>`"),
            "{detail}"
        );
        assert_eq!(shell_word("a'b c"), "'a'\\''b c'");
    }

    #[tokio::test]
    async fn advisory_names_each_tools_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let none: &[&str] = &[];
        let detail = advisory(
            tmp.path(),
            &[
                Unwound::new("pkg:pypi/urllib3@1.26.18", Tool::Pdm, none),
                Unwound::new("pkg:pypi/six@1.16.0?artifact_id=x", Tool::Pipenv, none),
                Unwound::new("pkg:pypi/idna@3.7", Tool::Uv, none),
                Unwound::new("pkg:npm/left-pad@1.3.0", Tool::Uv, none),
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
