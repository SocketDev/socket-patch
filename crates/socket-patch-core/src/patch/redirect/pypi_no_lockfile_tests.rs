//! #638: a granted pypi patch in a project with no file a PyPI rewriter
//! reads (no root requirements.txt, uv.lock, poetry.lock, pdm.lock,
//! Pipfile.lock or PEP 751 / PEP 723 lock, and no Hatch configuration) is
//! reported once per run as `redirect_pypi_no_lockfile`, the PyPI twin of
//! `redirect_npm_no_lockfile` / `redirect_composer_no_lockfile`, so a
//! `--json` consumer sees why nothing was pinned.

use super::*;

const CODE: &str = "redirect_pypi_no_lockfile";

fn six(uuid: &str) -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: "six".into(),
        namespace: None,
        version: "1.16.0".into(),
        token: "11111111-1111-4111-8111-111111111111".into(),
        patch_uuid: uuid.into(),
        artifact_url: format!(
            "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-4111-8111-111111111111/{uuid}/six-1.16.0-py2.py3-none-any.whl"
        ),
        registry_override: None,
        integrity: Integrity {
            sha256: Some("c".repeat(64)),
            ..Default::default()
        },
    }
}

fn files(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn codes(result: &RewriteResult) -> Vec<&str> {
    result.warnings.iter().map(|w| w.code.as_str()).collect()
}

fn no_lockfile_warnings(result: &RewriteResult) -> Vec<&RewriteWarning> {
    result.warnings.iter().filter(|w| w.code == CODE).collect()
}

const UV_PROJECT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\", \"idna==3.7\"]\n";

/// The issue's matrix: only `requirements-dev.txt`, only
/// `requirements/base.txt`, no Python file at all, and a uv project whose
/// `uv.lock` is not committed. Each warns exactly once, however many pypi
/// patches are granted, and the detail names what was looked for.
#[test]
fn every_lockless_layout_warns_once() {
    let dev = "six==1.16.0\nidna==3.7\n";
    let layouts: [(&str, BTreeMap<String, String>); 4] = [
        (
            "requirements-dev.txt only",
            files(&[("requirements-dev.txt", dev)]),
        ),
        (
            "requirements/base.txt only",
            files(&[("requirements/base.txt", dev)]),
        ),
        ("no python file", BTreeMap::new()),
        (
            "pyproject without uv.lock",
            files(&[("pyproject.toml", UV_PROJECT)]),
        ),
    ];
    let overrides = [
        six("aaaaaaaa-0000-4000-8000-000000000638"),
        six("bbbbbbbb-0000-4000-8000-000000000638"),
    ];
    for (layout, files) in layouts {
        let result = rewrite_registry_redirect(&files, &overrides);
        assert!(result.files.is_empty(), "{layout}: {:?}", result.files);
        let warnings = no_lockfile_warnings(&result);
        assert_eq!(warnings.len(), 1, "{layout}: {:?}", codes(&result));
        let detail = &warnings[0].detail;
        for looked_for in [
            "requirements.txt",
            "uv.lock",
            "poetry.lock",
            "pdm.lock",
            "Pipfile.lock",
            "pylock.toml",
        ] {
            assert!(detail.contains(looked_for), "{layout}: {detail}");
        }
    }
}

/// A uv project without its lock is told how to get one; a project without
/// a pyproject.toml is not.
#[test]
fn pyproject_without_a_lock_names_the_lock_step() {
    let overrides = [six("aaaaaaaa-0000-4000-8000-000000000638")];
    let result = rewrite_registry_redirect(&files(&[("pyproject.toml", UV_PROJECT)]), &overrides);
    let detail = &no_lockfile_warnings(&result)[0].detail;
    assert!(detail.contains("pyproject.toml"), "{detail}");
    assert!(detail.contains("uv lock"), "{detail}");

    let result = rewrite_registry_redirect(&BTreeMap::new(), &overrides);
    let detail = &no_lockfile_warnings(&result)[0].detail;
    assert!(!detail.contains("uv lock"), "{detail}");
}

/// Any file a PyPI rewriter reads owns the diagnostics for its deps: no
/// run-level warning beside it, even when it does not pin the package
/// (that is `redirect_requirements_entry_not_found` and friends).
#[test]
fn a_python_lock_or_root_requirements_suppresses_the_warning() {
    let overrides = [six("aaaaaaaa-0000-4000-8000-000000000638")];
    let hatch = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n";
    let present = [
        ("requirements.txt", "idna==3.7\n"),
        ("uv.lock", "version = 1\n"),
        ("poetry.lock", "# empty\n"),
        ("pdm.lock", "# empty\n"),
        ("Pipfile.lock", "{}"),
        ("pylock.toml", "lock-version = \"1.0\"\n"),
        ("pylock.dev.toml", "lock-version = \"1.0\"\n"),
        ("tool.py.lock", "version = 1\n"),
        ("hatch.toml", "[envs.default]\n"),
        ("pyproject.toml", hatch),
    ];
    for (name, text) in present {
        let result = rewrite_registry_redirect(&files(&[(name, text)]), &overrides);
        assert!(
            no_lockfile_warnings(&result).is_empty(),
            "{name}: {:?}",
            result.warnings
        );
    }
}

/// No pypi patch granted, or every one withheld before the PyPI lane (a
/// platform wheel, #701): nothing to warn about.
#[test]
fn no_warning_without_a_pypi_patch_in_the_lane() {
    let result = rewrite_registry_redirect(&BTreeMap::new(), &[]);
    assert!(no_lockfile_warnings(&result).is_empty());

    let mut wheel = six("aaaaaaaa-0000-4000-8000-000000000638");
    wheel.artifact_url = wheel.artifact_url.replace(
        "six-1.16.0-py2.py3-none-any.whl",
        "six-1.16.0-cp311-cp311-manylinux_2_17_x86_64.whl",
    );
    let result = rewrite_registry_redirect(&BTreeMap::new(), &[wheel]);
    assert!(
        codes(&result).contains(&"redirect_pypi_platform_wheel"),
        "{:?}",
        codes(&result)
    );
    assert!(
        no_lockfile_warnings(&result).is_empty(),
        "{:?}",
        codes(&result)
    );
}
