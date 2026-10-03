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
    // This run's fetched records MERGED with the ledger's persisted ones
    // (the caller hands the post-merge ledger map), looked up by uuid.
    records: &BTreeMap<String, PatchRecord>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
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
    let paths = if common.is_global() {
        crawler
            .get_site_packages_paths(&common.crawler_options())
            .await
            .unwrap_or_default()
    } else {
        socket_patch_core::crawlers::python_crawler::find_local_venv_site_packages(&common.cwd)
            .await
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
    for ((site, _, _), judgment) in judgments {
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
                format!(
                    "Pipenv does not reinstall a release that is already present (`pipenv \
                     install`, `pipenv install --deploy` and `pipenv sync` all keep those \
                     bytes), so the rewritten Pipfile.lock only protects fresh installs. \
                     Reinstall it from the lock without touching the Pipfile: `pipenv run pip \
                     uninstall -y {name} && pipenv sync` (`pipenv install --deploy` before \
                     Pipenv 2018), or `pipenv --rm && pipenv sync` for a clean virtualenv — \
                     NOT `pipenv uninstall`, which rewrites the Pipfile and re-locks the \
                     patch away; then `socket-patch vex --product <purl>` re-verifies the \
                     installed files."
                )
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
        assert!(out.stale_purls.is_empty());
        assert!(out.warnings.is_empty());
    }

    /// #335: a Hatch env keeps the upstream release after the rewrite, and
    /// the probe must find it (Hatch keeps envs out of `./.venv`) and name
    /// Hatch's remedy, not "reinstall from the rewritten lock".
    #[tokio::test]
    async fn hatch_env_gets_the_stale_install_warning_with_hatch_remedy() {
        if std::env::var_os("VIRTUAL_ENV").is_some() {
            return; // an activated venv takes precedence over project envs
        }
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
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
        let out = stale_install_warnings(&common, &confirmed, &BTreeSet::new(), &ledger).await;
        assert_eq!(out.stale_purls, BTreeSet::from([purl.to_string()]));
        assert_eq!(out.warnings[0]["code"], "redirect_pypi_stale_install");
    }
}
