//! #701 / #932: a pypi patch granted as a platform- or ABI-tagged wheel is
//! never pinned into a cross-platform Python lock. Each lane first proves
//! its fixture redirects a pure wheel (the control), then that the same
//! project with a `cp311-cp311-manylinux` wheel, or an interpreter-bound
//! `cp311-none-any` one (#1048), is left untouched, warned about once, and
//! confirms nothing.

use super::*;

const PURE: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
const PLATFORM: &str = "urllib3-1.26.18-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
/// #1048: pip installs a `cp311-none-any` wheel on CPython 3.11 only.
const INTERPRETER: &str = "urllib3-1.26.18-cp311-none-any.whl";
/// Every wheel each lane must withhold, with the tag the warning names.
const REFUSED: [(&str, &str); 2] = [
    (PLATFORM, "cp311-cp311-manylinux"),
    (INTERPRETER, "cp311-none-any"),
];
const UUID: &str = "aaaaaaaa-0000-4000-8000-000000000701";
const HEX: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";

fn dep(wheel: &str) -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: "urllib3".into(),
        namespace: None,
        version: "1.26.18".into(),
        token: "11111111-1111-4111-8111-111111111111".into(),
        patch_uuid: UUID.into(),
        artifact_url: format!(
            "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/11111111-1111-4111-8111-111111111111/{UUID}/{wheel}"
        ),
        registry_override: None,
        integrity: Integrity {
            sha256: Some(HEX.into()),
            ..Default::default()
        },
    }
}

fn confirmed(result: &RewriteResult) -> bool {
    [
        &result.confirmed_pipenv_uuids,
        &result.confirmed_pdm_uuids,
        &result.confirmed_python_lock_uuids,
        &result.confirmed_hatch_uuids,
        &result.confirmed_requirements_uuids,
    ]
    .iter()
    .any(|set| set.contains(UUID))
}

fn platform_warnings(result: &RewriteResult) -> usize {
    result
        .warnings
        .iter()
        .filter(|w| w.code == "redirect_pypi_platform_wheel")
        .count()
}

/// The control redirects `lock`; the platform wheel leaves every file alone.
fn assert_lane(lane: &str, files: &[(&str, &str)], lock: &str) {
    let files: BTreeMap<String, String> = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let control = rewrite_registry_redirect(&files, &[dep(PURE)]);
    assert!(
        control
            .files
            .get(lock)
            .is_some_and(|text| text.contains(PURE)),
        "{lane}: control did not pin the pure wheel into {lock}: {:?}",
        control.warnings
    );
    assert!(confirmed(&control), "{lane}: control not confirmed");
    assert_eq!(platform_warnings(&control), 0, "{lane}");

    for (wheel, tag) in REFUSED {
        let result = rewrite_registry_redirect(&files, &[dep(wheel)]);
        assert!(
            result.files.is_empty() && result.edits.is_empty(),
            "{lane}: {wheel} was pinned: {:?}",
            result.files.keys().collect::<Vec<_>>()
        );
        assert!(!confirmed(&result), "{lane}: {wheel} confirmed");
        assert_eq!(
            platform_warnings(&result),
            1,
            "{lane}: {wheel}: {:?}",
            result.warnings
        );
        let detail = &result.warnings[0].detail;
        assert!(
            detail.contains("urllib3==1.26.18") && detail.contains(tag),
            "{lane}: {detail}"
        );
    }
}

/// #701: a uv project's `uv.lock` (and its `[tool.uv.sources]`).
#[test]
fn uv_project_lock_refuses_a_platform_wheel() {
    let project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"urllib3==1.26.18\"]\n";
    let lock = format!("version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\ndependencies = [{{ name = \"urllib3\" }}]\n\n[package.metadata]\nrequires-dist = [{{ name = \"urllib3\", specifier = \"==1.26.18\" }}]\n\n[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://files.pythonhosted.org/packages/{PURE}\", hash = \"sha256:{HEX}\" }}]\n");
    for newline in ["\n", "\r\n"] {
        assert_lane(
            "uv.lock",
            &[
                ("pyproject.toml", &project.replace('\n', newline)),
                ("uv.lock", &lock.replace('\n', newline)),
            ],
            "uv.lock",
        );
    }
}

/// #701 (comment): a PEP 723 script lock.
#[test]
fn uv_script_lock_refuses_a_platform_wheel() {
    let script =
        "# /// script\n# requires-python = \">=3.9\"\n# dependencies = [\"urllib3==1.26.18\"]\n# ///\nimport urllib3\n";
    let lock = format!("version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[manifest]\nrequirements = [{{ name = \"urllib3\", specifier = \"==1.26.18\" }}]\n\n[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://files.pythonhosted.org/packages/{PURE}\", hash = \"sha256:{HEX}\" }}]\n");
    assert_lane(
        "script lock",
        &[("tool.py", script), ("tool.py.lock", &lock)],
        "tool.py.lock",
    );
}

/// #701: the PEP 751 lane (`uv export --format pylock.toml`).
#[test]
fn pylock_refuses_a_platform_wheel() {
    let lock = format!("lock-version = \"1.0\"\ncreated-by = \"uv\"\nrequires-python = \">=3.9\"\n\n[[packages]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nindex = \"https://pypi.org/simple\"\nwheels = [{{ url = \"https://files.pythonhosted.org/packages/{PURE}\", size = 1, hashes = {{ sha256 = \"{HEX}\" }} }}]\n");
    assert_lane("pylock", &[("pylock.toml", &lock)], "pylock.toml");
}

/// #932: Pipenv's `Pipfile.lock`.
#[test]
fn pipfile_lock_refuses_a_platform_wheel() {
    let lock = format!(
        "{{\n    \"_meta\": {{\n        \"hash\": {{\n            \"sha256\": \"unchanged\"\n        }},\n        \"pipfile-spec\": 6,\n        \"sources\": [\n            {{\n                \"name\": \"pypi\",\n                \"url\": \"https://pypi.org/simple\",\n                \"verify_ssl\": true\n            }}\n        ]\n    }},\n    \"default\": {{\n        \"urllib3\": {{\n            \"hashes\": [\n                \"sha256:{HEX}\"\n            ],\n            \"index\": \"pypi\",\n            \"markers\": \"python_version >= '3.7'\",\n            \"version\": \"==1.26.18\"\n        }}\n    }},\n    \"develop\": {{}}\n}}\n"
    );
    let pipfile = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nurllib3 = \"==1.26.18\"\n";
    for major in [None, Some(11), Some(2026)] {
        let files: BTreeMap<String, String> = [
            ("Pipfile".to_string(), pipfile.to_string()),
            ("Pipfile.lock".to_string(), lock.clone()),
        ]
        .into_iter()
        .collect();
        let control = rewrite_registry_redirect_with_pipenv_version(
            &files,
            &[dep(PURE)],
            &BTreeMap::new(),
            major,
            false,
        );
        assert!(
            control
                .files
                .get("Pipfile.lock")
                .is_some_and(|t| t.contains(PURE)),
            "pipenv {major:?}: control did not pin: {:?}",
            control.warnings
        );
        assert!(confirmed(&control));
        for (wheel, _) in REFUSED {
            let result = rewrite_registry_redirect_with_pipenv_version(
                &files,
                &[dep(wheel)],
                &BTreeMap::new(),
                major,
                false,
            );
            assert!(
                result.files.is_empty(),
                "pipenv {major:?}: {wheel}: {:?}",
                result.files
            );
            assert!(!confirmed(&result));
            assert_eq!(platform_warnings(&result), 1, "{:?}", result.warnings);
        }
    }
    assert_lane(
        "Pipfile.lock",
        &[("Pipfile", pipfile), ("Pipfile.lock", &lock)],
        "Pipfile.lock",
    );
}

/// #701 (comment): a `requirements.txt` pin, CRLF and hashed spellings too.
#[test]
fn requirements_refuses_a_platform_wheel() {
    for text in [
        "urllib3==1.26.18\n".to_string(),
        "idna==3.7\r\nurllib3==1.26.18\r\n".to_string(),
        format!("urllib3==1.26.18 \\\n    --hash=sha256:{HEX}\n"),
    ] {
        assert_lane(
            "requirements",
            &[("requirements.txt", &text)],
            "requirements.txt",
        );
    }
}

#[test]
fn poetry_lock_refuses_a_platform_wheel() {
    let pyproject = "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = []\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\nurllib3 = \"1.26.18\"\n";
    assert_lane(
        "poetry",
        &[
            ("pyproject.toml", pyproject),
            (
                "poetry.lock",
                include_str!("../../../tests/fixtures/poetry/1.0.10/poetry.lock"),
            ),
        ],
        "poetry.lock",
    );
}

#[test]
fn pdm_lock_refuses_a_platform_wheel() {
    let pyproject =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"urllib3==1.26.18\"]\n";
    assert_lane(
        "pdm",
        &[
            ("pyproject.toml", pyproject),
            (
                "pdm.lock",
                include_str!("../../../tests/fixtures/pdm-native/2.29.2.lock"),
            ),
        ],
        "pdm.lock",
    );
}

/// Hatch's own pyproject environment pin (a lock-less Hatch project).
#[test]
fn hatch_refuses_a_platform_wheel() {
    let pyproject = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"urllib3==1.26.18\"]\n\n[tool.hatch.envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n";
    assert_lane("hatch", &[("pyproject.toml", pyproject)], "pyproject.toml");
}

/// The tag rule matches vendored mode's: a wheel any Python 3 accepts
/// (`py3`, `py2.py3`, `py311`, which later 3.x accept too) and an sdist
/// stay redirectable; an interpreter-bound python tag (`cp311`, `pp310`,
/// #1048), a Python-2-only one, an `abi3` or a platform-only tag does
/// not; and a query or fragment on the serve URL is ignored.
#[test]
fn only_platform_or_abi_tagged_wheels_are_withheld() {
    let files: BTreeMap<String, String> = [(
        "requirements.txt".to_string(),
        "urllib3==1.26.18\n".to_string(),
    )]
    .into_iter()
    .collect();
    for (artifact, refused) in [
        (PURE.to_string(), false),
        ("urllib3-1.26.18-py3-none-any.whl".to_string(), false),
        ("urllib3-1.26.18-py311-none-any.whl".to_string(), false),
        ("urllib3-1.26.18-cp311.py3-none-any.whl".to_string(), false),
        (INTERPRETER.to_string(), true),
        ("urllib3-1.26.18-pp310-none-any.whl".to_string(), true),
        ("urllib3-1.26.18-py2-none-any.whl".to_string(), true),
        ("urllib3-1.26.18-cp311.cp312-none-any.whl".to_string(), true),
        ("urllib3-1.26.18.tar.gz".to_string(), false),
        (format!("{PURE}?token=x#sha256={HEX}"), false),
        (PLATFORM.to_string(), true),
        (format!("{PLATFORM}#sha256={HEX}"), true),
        (
            "urllib3-1.26.18-cp38-abi3-macosx_11_0_arm64.whl".to_string(),
            true,
        ),
        ("urllib3-1.26.18-py3-none-win_amd64.whl".to_string(), true),
    ] {
        let result = rewrite_registry_redirect(&files, &[dep(&artifact)]);
        assert_eq!(
            platform_warnings(&result),
            usize::from(refused),
            "{artifact}"
        );
        assert_eq!(
            result.files.is_empty(),
            refused,
            "{artifact}: {:?}",
            result.warnings
        );
    }
}

/// Withholding is per patch: a portable sibling patch in the same run is
/// still pinned, and a non-pypi override is never inspected.
#[test]
fn a_platform_wheel_withholds_only_its_own_patch() {
    let files: BTreeMap<String, String> = [(
        "requirements.txt".to_string(),
        "idna==3.7\nurllib3==1.26.18\n".to_string(),
    )]
    .into_iter()
    .collect();
    let idna = DepOverride {
        name: "idna".into(),
        version: "3.7".into(),
        patch_uuid: "aaaaaaaa-0000-4000-8000-000000000702".into(),
        artifact_url: "https://patch.socket.dev/patch/pypi/idna/3.7/t/u/idna-3.7-py3-none-any.whl"
            .into(),
        ..dep(PURE)
    };
    let npm = DepOverride {
        ecosystem: "npm".into(),
        name: "left-pad".into(),
        patch_uuid: "aaaaaaaa-0000-4000-8000-000000000703".into(),
        artifact_url: format!("https://patch.socket.dev/{PLATFORM}"),
        ..dep(PURE)
    };
    let result = rewrite_registry_redirect(&files, &[dep(PLATFORM), idna.clone(), npm]);
    assert_eq!(platform_warnings(&result), 1, "{:?}", result.warnings);
    let text = &result.files["requirements.txt"];
    assert!(text.contains(&idna.artifact_url), "{text}");
    assert!(!text.contains(PLATFORM), "{text}");
    assert!(text.contains("urllib3==1.26.18"), "{text}");
    assert!(result
        .confirmed_requirements_uuids
        .contains(&idna.patch_uuid));
    assert!(!confirmed(&result));
}
