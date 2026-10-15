//! Read-only installed-byte checks for hosted Python redirects.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::crawlers::PythonCrawler;
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vex::verify::judge_installed_record;

use super::StaleInstallOutcome;

/// A lock rewrite cannot prove a warm virtualenv has installed the wheel.
/// Use the project's own venv discovery (`--global`/`--global-prefix` use
/// the crawler's global paths), and inspect every interpreter rather than
/// deduplicating by package name.
/// Missing/unreadable files are not positive evidence of stale bytes.
pub(super) async fn stale_install_warnings(
    common: &crate::args::GlobalArgs,
    confirmed: &[(String, String)],
    pipenv_uuids: &BTreeSet<String>,
    // The run's final Pipfile.lock text: the remedy's `pipenv sync`
    // arguments follow the categories that pin each package.
    pipenv_lock: Option<&str>,
    // This run's fetched records MERGED with the ledger's persisted ones
    // (the caller hands the post-merge ledger map), looked up by uuid.
    records: &BTreeMap<String, PatchRecord>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    let pipenv_lock: Option<serde_json::Value> = pipenv_lock.and_then(|text| {
        serde_json::from_str(socket_patch_core::formats::text::strip_bom(text)).ok()
    });
    let candidates: Vec<_> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:pypi/"))
        .filter_map(|(purl, uuid)| {
            records
                .values()
                .find(|record| &record.uuid == uuid)
                .filter(|record| !record.files.is_empty())
                .map(|record| (purl, record))
        })
        .collect();
    if candidates.is_empty() {
        return out;
    }

    let crawler = PythonCrawler::new();
    // Only venvs that belong to THIS project (VIRTUAL_ENV, ./.venv, ./venv,
    // Poetry's and Pipenv's out-of-tree venvs): the crawler's project-marker
    // fallback to the global interpreters would judge an unrelated Python's
    // copy of the release (a tool venv on PATH) and warn falsely.
    // --global / --global-prefix keep their meaning.
    // Hatch envs need their own remedy: a reinstall from the rewritten
    // pyproject does nothing there (#335).
    let hatch_envs = if common.is_global() {
        Vec::new()
    } else {
        socket_patch_core::crawlers::hatch_env::hatch_environments(&common.cwd).await
    };
    // The base interpreter dirs a `--site-packages` venv inherits: a copy
    // there survives Pipenv's usual remedies (#1450).
    let (paths, inherited) = if common.is_global() {
        let paths = crawler
            .get_site_packages_paths(&common.crawler_options())
            .await
            .unwrap_or_default();
        (paths, Default::default())
    } else {
        let sites =
            socket_patch_core::crawlers::python_crawler::find_local_venv_site_packages(&common.cwd)
                .await;
        // A `--system-site-packages` venv's own copy hides its base
        // interpreter's (#409).
        crawler.set_search_order(&sites).await;
        // Only Pipenv's remedy reads this, over the venvs Pipenv itself
        // resolves (a `.venv` it shares with Hatch included): a base dir
        // only a Hatch env reaches is not one `pipenv run` fixes.
        let inherited = if pipenv_uuids.is_empty() {
            Default::default()
        } else {
            let pipenv_sites =
                socket_patch_core::crawlers::python_crawler::non_hatch_local_venv_site_packages(
                    &common.cwd,
                )
                .await;
            socket_patch_core::crawlers::python_crawler::inherited_base_site_dirs(&pipenv_sites)
                .await
        };
        (sites, inherited)
    };

    #[derive(Default)]
    struct Judgment {
        purls: BTreeSet<String>,
        patched: bool,
        stale: bool,
    }
    // Python distributions share site-packages, so the key must include
    // the package identity. Any matching artifact variant can prove this
    // package patched; a healthy *different* package cannot.
    let mut judgments = BTreeMap::new();
    let mut pipenv_purls: BTreeSet<String> = BTreeSet::new();
    // Every candidate's installed copy in every site, from one listing per
    // site — the per-candidate lookups the loop below consumes, in the same
    // (candidate, site) order.
    let bases: Vec<String> = candidates
        .iter()
        .map(|(purl, _)| strip_purl_qualifiers(purl).to_string())
        .collect();
    let mut found_per_site = Vec::with_capacity(paths.len());
    for site in &paths {
        found_per_site.push(crawler.find_each_by_purl(site, &bases).await);
    }
    for (index, (purl, record)) in candidates.into_iter().enumerate() {
        if pipenv_uuids.contains(&record.uuid) {
            pipenv_purls.insert(purl.clone());
        }
        for found in &found_per_site {
            let Some(pkg) = &found[index] else {
                continue;
            };
            let judgment: &mut Judgment = judgments
                .entry((pkg.path.clone(), pkg.name.clone(), pkg.version.clone()))
                .or_default();
            judgment.purls.insert(purl.clone());
            let judged = judge_installed_record(&pkg.path, record).await;
            if judged.patched {
                judgment.patched = true;
            } else if judged.stale_evidence {
                judgment.stale = true;
            }
        }
    }
    for ((site, _, version), judgment) in judgments {
        if judgment.patched || !judgment.stale {
            continue;
        }
        for purl in judgment.purls {
            // Pipenv never reinstalls a release that is already present
            // (`install`, `install --deploy`, `sync` all keep the installed
            // bytes on every major), and `pipenv uninstall` rewrites the
            // Pipfile and re-locks the patch away — name the verified remedy.
            let hatch_env =
                socket_patch_core::crawlers::hatch_env::environment_of(&hatch_envs, &site);
            let remedy = if let Some(env) = hatch_env {
                socket_patch_core::crawlers::hatch_env::stale_install_remedy(&env.name)
            } else if pipenv_purls.contains(&purl) {
                let name = strip_purl_qualifiers(&purl)
                    .strip_prefix("pkg:pypi/")
                    .and_then(|rest| rest.split('@').next())
                    .unwrap_or("<package>")
                    .to_string();
                if inherited.contains(&site) {
                    let remedy =
                        socket_patch_core::vendor::pypi_pipenv::base_site_stale_install_remedy(
                            pipenv_lock.as_ref(),
                            &name,
                            &site.display().to_string(),
                        );
                    format!(
                        "{remedy}; then `socket-patch vex --product <purl>` re-verifies the \
                         installed files."
                    )
                } else if let Some(base) =
                    socket_patch_core::crawlers::python_crawler::inherited_same_release(
                        &site, &name, &version,
                    )
                    .await
                {
                    let remedy =
                        socket_patch_core::vendor::pypi_pipenv::shadowing_stale_install_remedy(
                            pipenv_lock.as_ref(),
                            &name,
                            &site.display().to_string(),
                            &base.display().to_string(),
                        );
                    format!(
                        "{remedy}; then `socket-patch vex --product <purl>` re-verifies the \
                         installed files."
                    )
                } else {
                    let remedy = socket_patch_core::vendor::pypi_pipenv::stale_install_remedy(
                        pipenv_lock.as_ref(),
                        &name,
                    );
                    format!(
                        "Pipenv does not reinstall a release that is already present (`pipenv \
                         install`, `pipenv install --deploy` and `pipenv sync` all keep those \
                         bytes), so the rewritten Pipfile.lock only protects fresh installs. \
                         {remedy}; then `socket-patch vex --product <purl>` re-verifies the \
                         installed files."
                    )
                }
            } else {
                "Reinstall from the rewritten lock in this interpreter and verify with \
                 `socket-patch vex`. Poetry before 1.4 may keep same-version packages: \
                 recreate the project virtualenv or uninstall this package before \
                 installing."
                    .to_string()
            };
            out.warnings.push(serde_json::json!({
                "code": "redirect_pypi_stale_install",
                "detail": format!(
                    "{purl} was switched to a hosted patch, but installed files in {} \
                     still differ from the patched hashes. {remedy} The installed files \
                     were left unchanged.",
                    site.display()
                ),
            }));
            out.stale_purls.insert(purl);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    use socket_patch_core::manifest::schema::PatchFileInfo;

    fn record(uuid: &str, file: &str, patched: &[u8]) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2026-09-17T00:00:00Z".to_string(),
            files: [(
                file.to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(b"upstream"),
                    after_hash: compute_git_sha256_from_bytes(patched),
                },
            )]
            .into(),
            vulnerabilities: Default::default(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
        }
    }

    #[tokio::test]
    async fn prefix_probe_groups_variants_by_package_and_uses_ledger_records() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("custom-site-packages");
        for name in ["first", "second"] {
            std::fs::create_dir_all(site.join(format!("{name}-1.0.dist-info"))).unwrap();
        }
        std::fs::write(site.join("first.py"), b"upstream").unwrap();
        std::fs::write(site.join("second.py"), b"patched").unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site.clone()),
            ..Default::default()
        };
        let first = "pkg:pypi/first@1.0?artifact_id=one";
        let second = "pkg:pypi/second@1.0";
        let mut confirmed = vec![
            (first.to_string(), "first-uuid".to_string()),
            (second.to_string(), "second-uuid".to_string()),
        ];
        // Deliberately unrelated keys: lookup must use each record's UUID.
        let mut ledger = BTreeMap::from([
            ("one".into(), record("first-uuid", "first.py", b"patched")),
            ("two".into(), record("second-uuid", "second.py", b"patched")),
        ]);
        let out =
            stale_install_warnings(&common, &confirmed, &BTreeSet::new(), None, &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([first.to_string()]));
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0]["detail"]
            .as_str()
            .unwrap()
            .contains(&site.display().to_string()));

        // An installed package can match a different wheel variant. That
        // variant, unlike the healthy sibling distribution, proves it patched.
        confirmed.push((
            "pkg:pypi/first@1.0?artifact_id=two".into(),
            "variant".into(),
        ));
        ledger.insert("three".into(), record("variant", "first.py", b"upstream"));
        let out =
            stale_install_warnings(&common, &confirmed, &BTreeSet::new(), None, &ledger).await;
        assert!(out.stale_purls.is_empty());
        assert!(out.warnings.is_empty());
    }

    /// #335: a Hatch env keeps the upstream release after the rewrite, and
    /// the probe must find it (Hatch keeps envs out of `./.venv`) and name
    /// Hatch's remedy, not "reinstall from the rewritten lock".
    #[tokio::test]
    async fn hatch_env_gets_the_stale_install_warning_with_hatch_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.hatch.envs.default]\npath = \"../hatch-envs/app\"\n",
        )
        .unwrap();
        let env = tmp.path().join("hatch-envs").join("app");
        std::fs::create_dir_all(&env).unwrap();
        std::fs::write(env.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        let site = if cfg!(windows) {
            env.join("Lib").join("site-packages")
        } else {
            env.join("lib").join("python3.12").join("site-packages")
        };
        let dist = site.join("six-1.16.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("METADATA"), "Name: six\nVersion: 1.16.0\n").unwrap();
        std::fs::write(site.join("six.py"), b"upstream").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: project.clone(),
            ..Default::default()
        };
        let purl = "pkg:pypi/six@1.16.0";
        let confirmed = vec![(purl.to_string(), "six-uuid".to_string())];
        let ledger = BTreeMap::from([("k".into(), record("six-uuid", "six.py", b"patched"))]);
        let out =
            stale_install_warnings(&common, &confirmed, &BTreeSet::new(), None, &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([purl.to_string()]));
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(detail.contains("hatch env remove default"), "{detail}");
        assert!(
            !detail.contains("Reinstall from the rewritten lock"),
            "{detail}"
        );

        // Patched in the env: nothing to warn about.
        std::fs::write(site.join("six.py"), b"patched").unwrap();
        let out =
            stale_install_warnings(&common, &confirmed, &BTreeSet::new(), None, &ledger).await;
        assert!(out.warnings.is_empty());
    }

    /// A legacy `.egg-info` install (pip < 23.1 building an sdist without
    /// `wheel`) is a real copy pip keeps on `install -r`, so the hosted
    /// stale-install guard must judge it like a `.dist-info` one (#447).
    #[tokio::test]
    async fn egg_info_install_gets_the_stale_install_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        let egg = site.join("six-1.16.0-py3.11.egg-info");
        std::fs::create_dir_all(&egg).unwrap();
        std::fs::write(egg.join("PKG-INFO"), "Name: six\nVersion: 1.16.0\n").unwrap();
        std::fs::write(site.join("six.py"), b"upstream").unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site.clone()),
            ..Default::default()
        };
        let purl = "pkg:pypi/six@1.16.0";
        let confirmed = vec![(purl.to_string(), "six-uuid".to_string())];
        let ledger = BTreeMap::from([("k".into(), record("six-uuid", "six.py", b"patched"))]);
        let out =
            stale_install_warnings(&common, &confirmed, &BTreeSet::new(), None, &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([purl.to_string()]));
        assert_eq!(out.warnings[0]["code"], "redirect_pypi_stale_install");
    }

    /// #790: the Pipenv remedy names the lock category that pins the
    /// package. Plain `pipenv sync` installs only `default`, so for a
    /// `[dev-packages]` entry it uninstalled the package and left it
    /// uninstalled.
    #[tokio::test]
    async fn pipenv_remedy_resyncs_the_category_that_pins_the_package() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        std::fs::create_dir_all(site.join("six-1.16.0.dist-info")).unwrap();
        std::fs::write(site.join("six.py"), b"upstream").unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site.clone()),
            ..Default::default()
        };
        let purl = "pkg:pypi/six@1.16.0";
        let confirmed = vec![(purl.to_string(), "six-uuid".to_string())];
        let ledger = BTreeMap::from([("k".into(), record("six-uuid", "six.py", b"patched"))]);
        let pipenv = BTreeSet::from(["six-uuid".to_string()]);
        let detail = |lock: &str| {
            let lock = lock.to_string();
            let (common, confirmed, ledger, pipenv) = (&common, &confirmed, &ledger, &pipenv);
            async move {
                let out =
                    stale_install_warnings(common, confirmed, pipenv, Some(&lock), ledger).await;
                assert_eq!(out.warnings.len(), 1);
                out.warnings[0]["detail"].as_str().unwrap().to_string()
            }
        };

        let develop = detail(
            r#"{"_meta": {"pipfile-spec": 6}, "default": {}, "develop": {"six": {"file": "x"}}}"#,
        )
        .await;
        assert!(
            develop.contains("`pipenv run pip uninstall -y six && pipenv sync --dev`"),
            "{develop}"
        );
        assert!(
            develop.contains("`pipenv --rm && pipenv sync --dev`"),
            "{develop}"
        );

        let docs = detail(
            r#"{"_meta": {"pipfile-spec": 6}, "default": {"requests": {}}, "docs": {"six": {}}}"#,
        )
        .await;
        assert!(
            docs.contains("-y six && pipenv sync --categories \"docs\"`"),
            "{docs}"
        );
        assert!(
            docs.contains("`pipenv --rm && pipenv sync --categories \"packages docs\"`"),
            "{docs}"
        );
    }

    /// #1450: a `--site-packages` venv imports the upstream release from its
    /// base interpreter. pip refuses to uninstall that copy from the venv
    /// and `pipenv sync` (also in a recreated venv) counts it as installed,
    /// so the warning names an install over it inside the venv instead, and
    /// does not claim the lock protects fresh installs.
    #[tokio::test]
    async fn pipenv_base_site_copy_gets_an_install_over_it() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        let venv = project.join(".venv");
        let base = tmp.path().join("base");
        let (home, venv_site, base_site) = if cfg!(windows) {
            std::fs::create_dir_all(base.join("Lib")).unwrap();
            std::fs::write(base.join("Lib").join("os.py"), "").unwrap();
            (
                base.clone(),
                venv.join("Lib").join("site-packages"),
                base.join("Lib").join("site-packages"),
            )
        } else {
            let lib = base.join("lib").join("python3.12");
            std::fs::create_dir_all(&lib).unwrap();
            std::fs::write(lib.join("os.py"), "").unwrap();
            std::fs::create_dir_all(base.join("bin")).unwrap();
            (
                base.join("bin"),
                venv.join("lib").join("python3.12").join("site-packages"),
                lib.join("site-packages"),
            )
        };
        std::fs::create_dir_all(&venv_site).unwrap();
        std::fs::write(
            venv.join("pyvenv.cfg"),
            format!(
                "home = {}\ninclude-system-site-packages = true\nversion = 3.12.4\n",
                home.display()
            ),
        )
        .unwrap();
        let dist = base_site.join("six-1.16.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("METADATA"), "Name: six\nVersion: 1.16.0\n").unwrap();
        std::fs::write(base_site.join("six.py"), b"upstream").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: project.clone(),
            ..Default::default()
        };
        let purl = "pkg:pypi/six@1.16.0";
        let confirmed = vec![(purl.to_string(), "six-uuid".to_string())];
        let ledger = BTreeMap::from([("k".into(), record("six-uuid", "six.py", b"patched"))]);
        let pipenv = BTreeSet::from(["six-uuid".to_string()]);
        let lock = r#"{"_meta": {"pipfile-spec": 6}, "default": {}, "develop": {"six": {}}}"#;
        let out = stale_install_warnings(&common, &confirmed, &pipenv, Some(lock), &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([purl.to_string()]));
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains(&base_site.display().to_string()),
            "{detail}"
        );
        assert!(
            detail.contains(
                "`pipenv requirements --dev > pipenv-locked.txt && pipenv run pip install \
                 --no-deps --ignore-installed -r pipenv-locked.txt`"
            ),
            "{detail}"
        );
        for broken in [
            "pip uninstall",
            "pipenv --rm",
            "only protects fresh installs",
        ] {
            assert!(!detail.contains(broken), "{broken}: {detail}");
        }

        // The venv's own stale copy hides the same release in the base dir:
        // uninstalling it would only expose the base copy to `pipenv sync`,
        // so it gets the install-over remedy too.
        let dist = venv_site.join("six-1.16.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("METADATA"), "Name: six\nVersion: 1.16.0\n").unwrap();
        std::fs::write(venv_site.join("six.py"), b"upstream").unwrap();
        let out = stale_install_warnings(&common, &confirmed, &pipenv, Some(lock), &ledger).await;
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains(&format!(
                "hides the same release in {}",
                base_site.display()
            )),
            "{detail}"
        );
        assert!(
            detail.contains("pipenv run pip install --no-deps --ignore-installed"),
            "{detail}"
        );
        assert!(!detail.contains("pip uninstall -y six"), "{detail}");

        // A different release in the base dir is not one `pipenv sync`
        // counts as installed: the usual remedy replaces the venv's copy.
        let base_dist = base_site.join("six-1.16.0.dist-info");
        std::fs::write(base_dist.join("METADATA"), "Name: six\nVersion: 1.15.0\n").unwrap();
        let out = stale_install_warnings(&common, &confirmed, &pipenv, Some(lock), &ledger).await;
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("`pipenv run pip uninstall -y six && pipenv sync --dev`"),
            "{detail}"
        );
        std::fs::write(base_dist.join("METADATA"), "Name: six\nVersion: 1.16.0\n").unwrap();

        // A `.venv` Pipenv shares with Hatch (`path = ".venv"`) is still
        // Pipenv's: its inherited base copy keeps the install-over remedy.
        std::fs::remove_file(venv_site.join("six.py")).unwrap();
        std::fs::remove_dir_all(venv_site.join("six-1.16.0.dist-info")).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.hatch.envs.default]\npath = \".venv\"\n",
        )
        .unwrap();
        let out = stale_install_warnings(&common, &confirmed, &pipenv, Some(lock), &ledger).await;
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("pipenv run pip install --no-deps --ignore-installed"),
            "{detail}"
        );
    }
}
