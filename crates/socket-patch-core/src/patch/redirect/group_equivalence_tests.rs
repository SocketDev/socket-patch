//! Group equivalence: the rewriter groups run concurrently and merged in order
//! produce the same [`RewriteResult`] — every channel, edits and warnings in
//! order — as the serial chain they replaced.

use super::*;
use std::path::{Path, PathBuf};

/// The serial chain exactly as it was written before the groups existed —
/// the oracle.
fn serial_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
    pipenv_major: Option<u32>,
    bun_lockb_present: bool,
) -> RewriteResult {
    let mut result = RewriteResult::default();
    if pdm_drives(files) {
        pdm::rewrite(files, overrides, &mut result);
    }
    let overrides = withhold(overrides, &result.refused_pdm_uuids);
    pipenv::rewrite(files, &overrides, pipenv_major, &mut result);
    let overrides = withhold(&overrides, &result.refused_pipenv_uuids);
    let overrides: &[DepOverride] = &overrides;
    rewrite_npm_lock(files, overrides, &mut result);
    plan_hosted(files, overrides, &mut result);
    rewrite_yarn_classic(files, overrides, &mut result);
    rewrite_yarn_berry(files, overrides, &mut result);
    rewrite_bun_lock(files, overrides, &mut result);
    vlt::rewrite_vlt_lock(files, overrides, bun_lockb_present, &mut result);
    result.vlt_drives = vlt::vlt_drives(files, bun_lockb_present);
    requirements::rewrite(files, overrides, &mut result);
    rewrite_hatch(files, overrides, &mut result);
    rewrite_uv_lock(files, overrides, python_metadata, &mut result);
    poetry::rewrite_poetry(files, overrides, &mut result);
    rewrite_cargo(files, overrides, &mut result);
    rewrite_composer_lock(files, overrides, &mut result);
    rewrite_nuget(files, overrides, &mut result);
    rewrite_gem(files, overrides, &mut result);
    rewrite_maven_pom(files, overrides, &mut result);
    rewrite_golang(files, overrides, &mut result);
    result
}

/// One golden case's input files and overrides.
type Case = (BTreeMap<String, String>, Vec<DepOverride>);

fn fixture_roots() -> Vec<PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    vec![base.join("redirect")]
}

fn cases(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("input").is_dir() && dir.join("overrides.json").is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for p in entries {
        cases(&p, out);
    }
}

fn read_tree(base: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Ok(text) = std::fs::read_to_string(&p) {
                let rel = p.strip_prefix(base).unwrap().to_string_lossy();
                out.insert(rel.replace('\\', "/"), text);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(base, base, &mut out);
    out
}

fn assert_same(label: &str, files: &BTreeMap<String, String>, overrides: &[DepOverride]) {
    assert_same_with_metadata(label, files, overrides, &BTreeMap::new());
}

fn assert_same_with_metadata(
    label: &str,
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
) {
    for (pipenv_major, bun_lockb_present) in [
        (None, false),
        (Some(2023), false),
        (Some(2026), false),
        (None, true),
    ] {
        let want = serial_oracle(
            files,
            overrides,
            python_metadata,
            pipenv_major,
            bun_lockb_present,
        );
        let got = rewrite_registry_redirect_with_pipenv_version(
            files,
            overrides,
            python_metadata,
            pipenv_major,
            bun_lockb_present,
        );
        assert_eq!(got, want, "{label} (pipenv {pipenv_major:?})");

        // And the parallel merge itself — not the serial fallback — is what
        // produced it: real rewriters only append, to files of their own.
        let mut prefix = RewriteResult::default();
        if pdm_drives(files) {
            pdm::rewrite(files, overrides, &mut prefix);
        }
        let overrides = withhold(overrides, &prefix.refused_pdm_uuids);
        pipenv::rewrite(files, &overrides, pipenv_major, &mut prefix);
        let overrides = withhold(&overrides, &prefix.refused_pipenv_uuids);
        let groups = rewriter_groups(
            files,
            &overrides,
            &overrides,
            bun_lockb_present,
            python_metadata,
        );
        let merged = merge_group_outputs(&prefix, run_groups_concurrently(&prefix, &groups))
            .map(|mut merged| {
                merged.vlt_drives = vlt::vlt_drives(files, bun_lockb_present);
                merged
            });
        assert_eq!(
            merged.as_ref(),
            Some(&want),
            "{label} merge (pipenv {pipenv_major:?})"
        );
    }
}

#[test]
fn parallel_groups_match_the_serial_chain_on_golden_fixtures() {
    let mut dirs = Vec::new();
    for root in fixture_roots() {
        cases(&root, &mut dirs);
    }
    assert!(dirs.len() > 50, "golden fixtures not found: {}", dirs.len());
    // Per ecosystem, the (files, overrides) of each case.
    let mut by_eco: BTreeMap<String, Vec<Case>> = BTreeMap::new();
    for case in &dirs {
        let Ok(overrides) = serde_json::from_str::<Vec<DepOverride>>(
            &std::fs::read_to_string(case.join("overrides.json")).unwrap(),
        ) else {
            continue;
        };
        let files = read_tree(&case.join("input"));
        assert_same(&case.display().to_string(), &files, &overrides);
        let eco = case
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        by_eco.entry(eco).or_default().push((files, overrides));
    }
    assert!(by_eco.len() >= 8, "ecosystems: {:?}", by_eco.keys());

    // Polyglot projects: the i-th case of every ecosystem in one tree, so
    // several groups rewrite (and warn) in the same run and the merge order
    // is exercised. A file name two cases share keeps the first case's text.
    let widest = by_eco.values().map(Vec::len).max().unwrap();
    for i in 0..widest {
        let mut files = BTreeMap::new();
        let mut overrides = Vec::new();
        for list in by_eco.values() {
            let (f, o) = &list[i % list.len()];
            for (k, v) in f {
                files.entry(k.clone()).or_insert_with(|| v.clone());
            }
            overrides.extend(o.iter().cloned());
        }
        assert_same(&format!("polyglot combination {i}"), &files, &overrides);
    }
}

fn warn(code: &str) -> RewriteWarning {
    RewriteWarning {
        code: code.into(),
        detail: code.into(),
    }
}

/// Groups that write the same file, or a file the prefix already carries, or
/// do more than append, fall back to the serial chain — never a merge whose
/// last writer differs from the serial one.
#[test]
fn parallel_groups_fall_back_to_serial_when_the_merge_could_differ() {
    let mut prefix = RewriteResult::default();
    prefix.files.insert("p".into(), "prefix".into());
    prefix.warnings.push(warn("prefix"));

    type Case = Vec<RewriterGroup<'static>>;
    let cases: Vec<(&str, Case)> = vec![
        (
            "disjoint",
            vec![
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("a".into(), "1".into());
                    r.warnings.push(warn("a"));
                }),
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("b".into(), "2".into());
                    r.warnings.push(warn("b"));
                    r.confirmed_cargo_uuids.insert("u".into());
                }),
            ],
        ),
        (
            "same file",
            vec![
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("a".into(), "first".into());
                }),
                Box::new(|r: &mut RewriteResult| {
                    let seen = r.files.get("a").cloned().unwrap_or_default();
                    r.files.insert("a".into(), format!("{seen}+second"));
                }),
            ],
        ),
        (
            "rewrites a prefix file with its own bytes after another group changed it",
            vec![
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("p".into(), "changed".into());
                }),
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("p".into(), "prefix".into());
                }),
            ],
        ),
        (
            "drops a prefix warning",
            vec![
                Box::new(|r: &mut RewriteResult| r.warnings.clear()),
                Box::new(|r: &mut RewriteResult| r.warnings.push(warn("later"))),
            ],
        ),
        (
            "removes a prefix file",
            vec![
                Box::new(|r: &mut RewriteResult| {
                    r.files.remove("p");
                }),
                Box::new(|r: &mut RewriteResult| {
                    r.files.insert("q".into(), "q".into());
                }),
            ],
        ),
    ];
    for (label, groups) in cases {
        let want = rewrite_groups_serial(prefix.clone(), &groups);
        let got = rewrite_groups_parallel(prefix.clone(), &groups);
        assert_eq!(got, want, "{label}");
        let merged = merge_group_outputs(&prefix, run_groups_concurrently(&prefix, &groups));
        assert_eq!(merged.is_some(), label == "disjoint", "{label}");
    }
}

/// A panicking group re-raises the FIRST panic in serial order.
#[test]
fn parallel_groups_reraise_the_first_panic_in_serial_order() {
    let groups: Vec<RewriterGroup<'static>> = vec![
        Box::new(|_: &mut RewriteResult| {}),
        Box::new(|_: &mut RewriteResult| panic!("first")),
        Box::new(|_: &mut RewriteResult| panic!("second")),
    ];
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rewrite_groups_parallel(RewriteResult::default(), &groups)
    }))
    .expect_err("a group panicked");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"first"));
}

fn pypi_dep(name: &str, uuid: &str) -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: name.into(),
        namespace: None,
        version: "1.0.0".into(),
        token: String::new(),
        patch_uuid: uuid.into(),
        artifact_url: format!("https://patch.test/{name}-1.0.0-py3-none-any.whl"),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha256: Some("a".repeat(64)),
            ..Default::default()
        },
    }
}

/// The Python projects whose rewriters read one another's output or the
/// wheel metadata — none of which the golden fixtures carry: a hatch project
/// confirmed through a pinned `requirements.txt` (hatch reads the requirements
/// rewriter's confirmations), a native uv project fed wheel metadata, and a
/// PEP 723 script lock.
fn python_cases() -> Vec<(&'static str, BTreeMap<String, String>, Vec<DepOverride>)> {
    let alpha = pypi_dep("alpha", "alpha-uuid");
    let bravo = pypi_dep("bravo", "bravo-uuid");
    let hatch = BTreeMap::from([
        (
            "pyproject.toml".to_string(),
            "[project]\nname='p'\ndependencies=['alpha==1.0.0']\n[build-system]\nrequires=['hatchling']\nbuild-backend='hatchling.build'\n"
                .to_string(),
        ),
        (
            "requirements.txt".to_string(),
            "alpha==1.0.0\nbravo==1.0.0\n".to_string(),
        ),
    ]);
    let uv_native = BTreeMap::from([
        (
            "pyproject.toml".to_string(),
            "[project]\nname = 'project'\nversion = '1'\ndependencies = ['alpha==1.0.0']\n"
                .to_string(),
        ),
        (
            "uv.lock".to_string(),
            "version = 1\nrevision = 3\n[[package]]\nname = 'project'\nversion = '1'\nsource = {virtual='.'}\ndependencies=[{name='alpha'}]\n[package.metadata]\nrequires-dist=[{name='alpha',specifier='==1.0.0'}]\n[[package]]\nname='alpha'\nversion='1.0.0'\nsource={registry='https://pypi.org/simple'}\nwheels=[{url='https://pypi.org/alpha-1.0.0-py3-none-any.whl',hash='sha256:original'}]\n"
                .to_string(),
        ),
    ]);
    let mut script_lock = "version = 1\nrevision = 3\n\n[manifest]\nrequirements = [{ name = \"alpha\", specifier = \"==1.0.0\" }, { name = \"bravo\", specifier = \"==1.0.0\" }]\n".to_string();
    for name in ["alpha", "bravo"] {
        script_lock.push_str(&format!("\n[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://pypi.org/{name}-1.0.0-py3-none-any.whl\", hash = \"sha256:original\" }}]\n"));
    }
    let script = BTreeMap::from([
        ("example.py.lock".to_string(), script_lock),
        (
            "example.py".to_string(),
            "# /// script\n# dependencies = [\"alpha==1.0.0\", \"bravo==1.0.0\"]\n# ///\nprint('x')\n"
                .to_string(),
        ),
    ]);
    let both = vec![alpha.clone(), bravo];
    vec![
        ("hatch + requirements.txt", hatch, both.clone()),
        ("native uv", uv_native, vec![alpha]),
        ("uv script lock", script, both),
    ]
}

fn wheel_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([(
        pypi_dep("alpha", "alpha-uuid").artifact_url,
        "[package.metadata]\nrequires-dist = []\nprovides-extras = ['testing']\n".to_string(),
    )])
}

/// The cross-rewriter reads inside the python group, and the wheel metadata,
/// survive the parallel merge.
#[test]
fn parallel_groups_match_the_serial_chain_on_python_cross_reads() {
    let metadata = wheel_metadata();
    for (label, files, overrides) in python_cases() {
        for md in [&BTreeMap::new(), &metadata] {
            assert_same_with_metadata(label, &files, &overrides, md);
        }
    }
    // The hatch case really exercises the requirements → hatch read.
    let (_, files, overrides) = &python_cases()[0];
    let result = rewrite_registry_redirect(files, overrides);
    assert!(
        result.confirmed_hatch_uuids.contains("alpha-uuid"),
        "{result:?}"
    );
    // And the metadata reaches the uv lock.
    let (_, files, overrides) = &python_cases()[1];
    let with = rewrite_registry_redirect_with_python_metadata(files, overrides, &metadata);
    let without = rewrite_registry_redirect(files, overrides);
    assert!(with.warnings.is_empty(), "{:?}", with.warnings);
    assert_ne!(with.files.get("uv.lock"), without.files.get("uv.lock"));
}

/// The oracle catches a regrouping that splits a real dependency: hatch in a
/// group of its own no longer sees the requirements rewriter's
/// confirmations, and the merge differs from the serial chain.
#[test]
fn group_oracle_detects_hatch_split_from_requirements() {
    let (_, files, overrides) = &python_cases()[0];
    let files = files.clone();
    let overrides = overrides.clone();
    let prefix = RewriteResult::default();
    let split: Vec<RewriterGroup<'_>> = vec![
        Box::new(|r: &mut RewriteResult| requirements::rewrite(&files, &overrides, r)),
        Box::new(|r: &mut RewriteResult| rewrite_hatch(&files, &overrides, r)),
    ];
    let serial = rewrite_groups_serial(prefix.clone(), &split);
    let merged = merge_group_outputs(&prefix, run_groups_concurrently(&prefix, &split));
    assert_ne!(merged, Some(serial));
}

/// A group whose thread the OS refuses runs on the calling thread, in order:
/// same result, same first-panic-in-order.
#[test]
fn parallel_groups_run_inline_when_a_thread_is_refused() {
    struct Refuse;
    impl Drop for Refuse {
        fn drop(&mut self) {
            REFUSE_GROUP_THREADS.with(|c| c.set(false));
        }
    }
    REFUSE_GROUP_THREADS.with(|c| c.set(true));
    let _reset = Refuse;

    let metadata = wheel_metadata();
    for (label, files, overrides) in python_cases() {
        assert_same_with_metadata(label, &files, &overrides, &metadata);
    }
    let groups: Vec<RewriterGroup<'static>> = vec![
        Box::new(|r: &mut RewriteResult| r.warnings.push(warn("a"))),
        Box::new(|r: &mut RewriteResult| {
            r.files.insert("b".into(), "2".into());
        }),
        Box::new(|r: &mut RewriteResult| r.warnings.push(warn("c"))),
    ];
    let prefix = RewriteResult::default();
    assert_eq!(
        rewrite_groups_parallel(prefix.clone(), &groups),
        rewrite_groups_serial(prefix.clone(), &groups)
    );
    assert!(merge_group_outputs(&prefix, run_groups_concurrently(&prefix, &groups)).is_some());

    let panicking: Vec<RewriterGroup<'static>> = vec![
        Box::new(|_: &mut RewriteResult| {}),
        Box::new(|_: &mut RewriteResult| panic!("first")),
        Box::new(|_: &mut RewriteResult| panic!("second")),
    ];
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rewrite_groups_parallel(RewriteResult::default(), &panicking)
    }))
    .expect_err("a group panicked");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"first"));
}
