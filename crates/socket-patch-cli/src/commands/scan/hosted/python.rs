//! Read-only installed-byte checks for hosted Python redirects.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::api::client::ApiClient;
use socket_patch_core::crawlers::PythonCrawler;
use socket_patch_core::hosted::wheel_record::{
    fetch_patched_wheel_record, judge_installed_wheel, WheelRecord,
};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::DepOverride;
use socket_patch_core::utils::purl::{purl_parts, strip_purl_qualifiers};
use socket_patch_core::vex::verify::{judge_installed_record, InstalledRecordJudgment};

use super::{StaleInstallOutcome, ViewFallback};

/// What an installed copy of one confirmed patch is judged against.
enum Evidence<'a> {
    /// An agent-mode manifest record of the same patch: its `afterHash`
    /// map, already local.
    Local(&'a PatchRecord),
    /// The patched wheel the lock now pins, fetched on the first installed
    /// copy found (`Some(None)` once that fetch failed).
    Wheel {
        dep: &'a DepOverride,
        sha256: &'a str,
        fetched: Option<Option<WheelRecord>>,
    },
    /// No wheel to judge by: an sdist pin, no pinned sha256, or `--offline`.
    Unavailable,
}

impl Evidence<'_> {
    /// `None` when this evidence cannot judge the copy in `site`: there is
    /// no wheel, its download failed, or the copy is another build.
    async fn judge(
        &mut self,
        api: &ApiClient,
        site: &std::path::Path,
    ) -> Option<InstalledRecordJudgment> {
        match self {
            Evidence::Local(record) => Some(judge_installed_record(site, record).await),
            Evidence::Wheel {
                dep,
                sha256,
                fetched,
            } => {
                if fetched.is_none() {
                    *fetched =
                        Some(fetch_patched_wheel_record(api, &dep.artifact_url, sha256).await);
                }
                match fetched {
                    Some(Some(record)) => judge_installed_wheel(site, record).await,
                    _ => None,
                }
            }
            Evidence::Unavailable => None,
        }
    }
}

/// A lock rewrite cannot prove a warm virtualenv has installed the wheel.
/// Use the project's own venv discovery (`--global`/`--global-prefix` use
/// the crawler's global paths), and inspect every interpreter rather than
/// deduplicating by package name.
///
/// Each installed copy is judged against an agent-mode manifest record of
/// the same patch when one exists, else against the patched wheel's own
/// `RECORD` ([`socket_patch_core::hosted::wheel_record`]), downloaded only
/// when a copy is installed. When that cannot judge it (an sdist pin, a
/// failed download, a copy of another build, `--offline`) and no other
/// variant proved the copy patched, the patch's view record judges it
/// ([`ViewFallback`]); a copy that record cannot judge either is reported
/// in `unjudged_purls`. Missing/unreadable files are not positive evidence
/// of stale bytes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stale_install_warnings(
    common: &crate::args::GlobalArgs,
    api_client: &ApiClient,
    confirmed: &[(String, String)],
    pipenv_uuids: &BTreeSet<String>,
    // The run's final Pipfile.lock text: the remedy's `pipenv sync`
    // arguments follow the categories that pin each package.
    pipenv_lock: Option<&str>,
    // The overrides the rewrite pinned: each patch's wheel URL and sha256.
    overrides: &[DepOverride],
    // The agent-mode manifest's records, looked up by uuid.
    local_records: &BTreeMap<String, PatchRecord>,
    views: &mut ViewFallback<'_>,
) -> StaleInstallOutcome {
    let mut out = StaleInstallOutcome::default();
    let pipenv_lock: Option<serde_json::Value> = pipenv_lock.and_then(|text| {
        serde_json::from_str(socket_patch_core::formats::text::strip_bom(text)).ok()
    });
    let mut candidates: Vec<(&String, &str, Evidence<'_>)> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:pypi/"))
        .map(|(purl, uuid)| {
            let local = local_records
                .values()
                .find(|record| &record.uuid == uuid && !record.files.is_empty());
            let wheel = || {
                // `--offline` downloads nothing, so there is no wheel to judge by.
                if common.offline {
                    return None;
                }
                let dep = overrides.iter().find(|dep| {
                    dep.ecosystem == "pypi"
                        && &dep.patch_uuid == uuid
                        && dep
                            .artifact_url
                            .split(['?', '#'])
                            .next()
                            .is_some_and(|path| path.ends_with(".whl"))
                })?;
                Some(Evidence::Wheel {
                    dep,
                    sha256: dep.integrity.sha256.as_deref()?,
                    fetched: None,
                })
            };
            let evidence = match local {
                Some(record) => Evidence::Local(record),
                None => wheel().unwrap_or(Evidence::Unavailable),
            };
            (purl, uuid.as_str(), evidence)
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
        /// Some variant had no evidence at all (see `unjudged_purls`).
        unjudged: bool,
    }
    impl Judgment {
        fn record(&mut self, judged: InstalledRecordJudgment) {
            if judged.patched {
                self.patched = true;
            } else if judged.stale_evidence {
                self.stale = true;
            }
        }
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
        .map(|(purl, _, _)| strip_purl_qualifiers(purl).to_string())
        .collect();
    let mut found_per_site = Vec::with_capacity(paths.len());
    for site in &paths {
        found_per_site.push(crawler.find_each_by_purl(site, &bases).await);
    }
    // Copies the candidate's own evidence could not judge, for the view
    // fallback below.
    let mut pending = Vec::new();
    for (index, (purl, uuid, evidence)) in candidates.iter_mut().enumerate() {
        if pipenv_uuids.contains(*uuid) {
            pipenv_purls.insert((*purl).clone());
        }
        for found in &found_per_site {
            let Some(pkg) = &found[index] else {
                continue;
            };
            let key = (pkg.path.clone(), pkg.name.clone(), pkg.version.clone());
            let judgment: &mut Judgment = judgments.entry(key.clone()).or_default();
            judgment.purls.insert((*purl).clone());
            match evidence.judge(api_client, &pkg.path).await {
                Some(judged) => judgment.record(judged),
                None => pending.push((key, *uuid)),
            }
        }
    }
    // Unless another variant already proved the copy patched, the patch's
    // view record judges it.
    for (key, uuid) in pending {
        let Some(judgment) = judgments.get_mut(&key) else {
            continue;
        };
        if judgment.patched {
            continue;
        }
        match views.record(uuid).await {
            Some(record) => judgment.record(judge_installed_record(&key.0, record).await),
            None => judgment.unjudged = true,
        }
    }
    for ((site, _, version), judgment) in judgments {
        if judgment.patched {
            continue;
        }
        if !judgment.stale {
            if judgment.unjudged {
                out.unjudged_purls.extend(judgment.purls);
            }
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
                let name = purl_parts(&purl)
                    .map(|(_, name, _)| name)
                    .or_else(|| {
                        let rest = strip_purl_qualifiers(&purl).strip_prefix("pkg:pypi/")?;
                        Some(rest.split('@').next().unwrap_or(rest).to_string())
                    })
                    .unwrap_or_default();
                socket_patch_core::vendor::pypi_pipenv::stale_install_detail(
                    pipenv_lock.as_ref(),
                    &name,
                    &version,
                    std::slice::from_ref(&site),
                    &inherited,
                    "rewritten",
                )
                .await
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

    /// A client nothing answers: these tests judge by local records only.
    fn offline_api() -> ApiClient {
        ApiClient::new(socket_patch_core::api::client::ApiClientOptions {
            api_url: "http://127.0.0.1:1".into(),
            api_token: None,
            route: socket_patch_core::api::client::ApiRoute::Proxy,
        })
    }

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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &BTreeSet::new(),
            None,
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &BTreeSet::new(),
            None,
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &BTreeSet::new(),
            None,
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &BTreeSet::new(),
            None,
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &BTreeSet::new(),
            None,
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
        assert_eq!(out.stale_purls, BTreeSet::from([purl.to_string()]));
        assert_eq!(out.warnings[0]["code"], "redirect_pypi_stale_install");
    }

    /// #1878: hosted words the Pipenv remedy through core's shared
    /// `stale_install_detail`, as vendored does: the lock categories pick
    /// the `pipenv sync` arguments (core's tests cover each category), and
    /// the re-verify step names a runnable command, with no `<purl>` or
    /// `<package>` placeholder left in.
    #[tokio::test]
    async fn pipenv_remedy_is_the_shared_core_wording() {
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
        let text =
            r#"{"_meta": {"pipfile-spec": 6}, "default": {}, "develop": {"six": {"file": "x"}}}"#;
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(text),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        let lock: serde_json::Value = serde_json::from_str(text).unwrap();
        let shared = socket_patch_core::vendor::pypi_pipenv::stale_install_detail(
            Some(&lock),
            "six",
            "1.16.0",
            std::slice::from_ref(&site),
            &Default::default(),
            "rewritten",
        )
        .await;
        assert_eq!(
            detail,
            format!(
                "{purl} was switched to a hosted patch, but installed files in {} still differ \
                 from the patched hashes. {shared} The installed files were left unchanged.",
                site.display()
            )
        );
        assert!(
            detail.contains("`pipenv run pip uninstall -y six && pipenv sync --dev`"),
            "{detail}"
        );
        assert!(
            detail.contains("so the rewritten Pipfile.lock only protects fresh installs"),
            "{detail}"
        );
        assert!(
            detail.contains("Then `socket-patch vex` re-verifies the installed files."),
            "{detail}"
        );
        assert!(!detail.contains("<purl>"), "{detail}");
        assert!(!detail.contains("<package>"), "{detail}");

        // #790: a named category reaches the hosted remedy too.
        let docs =
            r#"{"_meta": {"pipfile-spec": 6}, "default": {"requests": {}}, "docs": {"six": {}}}"#;
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(docs),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("-y six && pipenv sync --categories \"docs\"`"),
            "{detail}"
        );
        assert!(
            detail.contains("`pipenv --rm && pipenv sync --categories \"packages docs\"`"),
            "{detail}"
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(lock),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(lock),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(lock),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
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
        let out = stale_install_warnings(
            &common,
            &offline_api(),
            &confirmed,
            &pipenv,
            Some(lock),
            &[],
            &ledger,
            &mut ViewFallback::offline(),
        )
        .await;
        assert_eq!(out.warnings.len(), 1);
        let detail = out.warnings[0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("pipenv run pip install --no-deps --ignore-installed"),
            "{detail}"
        );
    }

    /// The view fallback's fixture: an installed `six 1.16.0` (upstream
    /// bytes, `py3-none-any` metadata) in a custom site, a confirmed patch
    /// whose grant pins `artifact` (a wheel URL the server answers with
    /// `wheel_status`, or an sdist), and a view of the patch answering
    /// `view_status`.
    struct FallbackFixture {
        _tmp: tempfile::TempDir,
        common: crate::args::GlobalArgs,
        server: wiremock::MockServer,
        api: ApiClient,
        overrides: Vec<DepOverride>,
        confirmed: Vec<(String, String)>,
    }

    const SIX: &str = "pkg:pypi/six@1.16.0";
    const SIX_WHEEL_TAGS: &str = "Wheel-Version: 1.0\nTag: py3-none-any\n";

    fn six_wheel(module: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        use std::io::Write as _;
        let b64 = |bytes: &[u8]| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
        };
        let record = format!(
            "six.py,sha256={},{}\nsix-1.16.0.dist-info/RECORD,,\n",
            b64(module),
            module.len()
        );
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut out);
            let options = zip::write::SimpleFileOptions::default();
            for (name, body) in [
                ("six.py", module),
                ("six-1.16.0.dist-info/WHEEL", SIX_WHEEL_TAGS.as_bytes()),
                ("six-1.16.0.dist-info/RECORD", record.as_bytes()),
            ] {
                zip.start_file(name, options).unwrap();
                zip.write_all(body).unwrap();
            }
            zip.finish().unwrap();
        }
        out.into_inner()
    }

    async fn fallback_fixture(
        artifact: &str,
        wheel_status: u16,
        view_status: u16,
    ) -> FallbackFixture {
        use sha2::{Digest as _, Sha256};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        let dist = site.join("six-1.16.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("WHEEL"), SIX_WHEEL_TAGS).unwrap();
        std::fs::write(site.join("six.py"), b"upstream").unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site),
            ..Default::default()
        };

        let server = wiremock::MockServer::start().await;
        let wheel = six_wheel(b"patched");
        Mock::given(method("GET"))
            .and(path(format!("/{artifact}")))
            .respond_with(ResponseTemplate::new(wheel_status).set_body_bytes(wheel.clone()))
            .mount(&server)
            .await;
        let view = record("six-uuid", "six.py", b"patched");
        let files: serde_json::Map<String, serde_json::Value> = view
            .files
            .iter()
            .map(|(path, info)| {
                (
                    path.clone(),
                    serde_json::json!({
                        "beforeHash": info.before_hash,
                        "afterHash": info.after_hash,
                    }),
                )
            })
            .collect();
        Mock::given(method("GET"))
            .and(path("/patch/view/six-uuid"))
            .respond_with(
                ResponseTemplate::new(view_status).set_body_json(serde_json::json!({
                    "uuid": "six-uuid",
                    "purl": SIX,
                    "publishedAt": "Thu, 17 Sep 2026 00:00:00 GMT",
                    "files": files,
                    "vulnerabilities": {},
                    "description": "",
                    "license": "MIT",
                    "tier": "free",
                })),
            )
            .mount(&server)
            .await;
        let api = ApiClient::new(socket_patch_core::api::client::ApiClientOptions {
            api_url: server.uri(),
            api_token: None,
            route: socket_patch_core::api::client::ApiRoute::Proxy,
        });
        let overrides = vec![serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "name": "six",
            "version": "1.16.0",
            "token": "t",
            "patchUuid": "six-uuid",
            "artifactUrl": format!("{}/{artifact}", server.uri()),
            "integrity": { "sha256": hex::encode(Sha256::digest(&wheel)) },
        }))
        .unwrap()];
        FallbackFixture {
            _tmp: tmp,
            common,
            server,
            api,
            overrides,
            confirmed: vec![(SIX.to_string(), "six-uuid".to_string())],
        }
    }

    impl FallbackFixture {
        async fn probe(&self) -> StaleInstallOutcome {
            let mut views = ViewFallback::new(&self.api, self.common.offline);
            stale_install_warnings(
                &self.common,
                &self.api,
                &self.confirmed,
                &BTreeSet::new(),
                None,
                &self.overrides,
                &BTreeMap::new(),
                &mut views,
            )
            .await
        }

        async fn requests(&self, part: &str) -> usize {
            self.server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| request.url.path().contains(part))
                .count()
        }
    }

    /// No wheel to judge by (its download fails, or the pin is an sdist):
    /// the patch's view record judges the copy, fetched once.
    #[tokio::test]
    async fn without_a_wheel_the_view_record_judges_the_copy() {
        for artifact in ["six-1.16.0-py3-none-any.whl", "six-1.16.0.tar.gz"] {
            let wheel_status = if artifact.ends_with(".whl") { 500 } else { 200 };
            let fixture = fallback_fixture(artifact, wheel_status, 200).await;
            let out = fixture.probe().await;
            assert_eq!(
                out.stale_purls,
                BTreeSet::from([SIX.to_string()]),
                "{artifact}"
            );
            assert_eq!(out.warnings.len(), 1, "{artifact}");
            assert!(out.unjudged_purls.is_empty(), "{artifact}");
            assert_eq!(fixture.requests("/view/").await, 1, "{artifact}");
        }
    }

    /// Neither a wheel nor a view record (the view fetch fails too, or
    /// `--offline` fetches nothing): the copy is unjudged, never healthy.
    #[tokio::test]
    async fn without_a_wheel_or_a_view_the_copy_is_unjudged() {
        let fixture = fallback_fixture("six-1.16.0-py3-none-any.whl", 500, 500).await;
        let out = fixture.probe().await;
        assert!(out.warnings.is_empty() && out.stale_purls.is_empty());
        assert_eq!(out.unjudged_purls, BTreeSet::from([SIX.to_string()]));
        assert_eq!(fixture.requests("/view/").await, 1);

        let mut fixture = fallback_fixture("six-1.16.0-py3-none-any.whl", 200, 200).await;
        fixture.common.offline = true;
        let out = fixture.probe().await;
        assert!(out.warnings.is_empty() && out.stale_purls.is_empty());
        assert_eq!(out.unjudged_purls, BTreeSet::from([SIX.to_string()]));
        assert_eq!(fixture.requests("/").await, 0, "--offline fetches nothing");
    }

    /// The patched wheel judges the copy: no view is fetched.
    #[tokio::test]
    async fn a_judging_wheel_fetches_no_view() {
        let fixture = fallback_fixture("six-1.16.0-py3-none-any.whl", 200, 200).await;
        let out = fixture.probe().await;
        assert_eq!(out.stale_purls, BTreeSet::from([SIX.to_string()]));
        assert!(out.unjudged_purls.is_empty());
        assert_eq!(fixture.requests(".whl").await, 1);
        assert_eq!(fixture.requests("/view/").await, 0);
    }
}
