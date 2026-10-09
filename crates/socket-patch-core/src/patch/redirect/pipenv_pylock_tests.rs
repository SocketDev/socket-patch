//! #912 / #1122: a PEP 751 `pylock*.toml` beside a `Pipfile` is read by
//! Pipenv, not by a PEP 751 installer. Pipenv's pylock reader
//! (`PylockFile.convert_to_pipenv_lockfile`) keeps only each package's
//! version, marker and wheel / sdist hashes, so the `archive` entry a hosted
//! pin writes is dropped and `pipenv sync` installs the upstream release.
//! With no `Pipfile.lock` (which Pipenv prefers when both exist) the pin is
//! refused; with one, both locks are pinned as before.

use super::*;

const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
const UUID: &str = "aaaaaaaa-0000-4000-8000-000000000912";
const HEX: &str = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";
const PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nsix = \"==1.16.0\"\n\n[pipenv]\nuse_pylock = true\n";

fn dep() -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: "six".into(),
        namespace: None,
        version: "1.16.0".into(),
        token: "11111111-1111-4111-8111-111111111111".into(),
        patch_uuid: UUID.into(),
        artifact_url: format!(
            "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-4111-8111-111111111111/{UUID}/{WHEEL}"
        ),
        registry_override: None,
        integrity: Integrity {
            sha256: Some(HEX.into()),
            ..Default::default()
        },
    }
}

/// A pylock as `pipenv lock` (use_pylock = true) writes it.
fn pylock() -> String {
    format!(
        "lock-version = \"1.0\"\nenvironments = []\nextras = []\ndependency-groups = []\ndefault-groups = []\ncreated-by = \"pipenv\"\n\n[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\nindex = \"https://pypi.org/simple\"\nwheels = [{{ name = \"{WHEEL}\", url = \"https://files.pythonhosted.org/packages/d9/5a/{WHEEL}\", hashes = {{ sha256 = \"{HEX}\" }} }}]\n\n[tool.pipenv]\ngenerated_from = \"Pipfile.lock\"\n"
    )
}

fn pipfile_lock() -> String {
    format!(
        "{{\n    \"_meta\": {{\n        \"hash\": {{\n            \"sha256\": \"unchanged\"\n        }},\n        \"pipfile-spec\": 6,\n        \"sources\": [\n            {{\n                \"name\": \"pypi\",\n                \"url\": \"https://pypi.org/simple\",\n                \"verify_ssl\": true\n            }}\n        ]\n    }},\n    \"default\": {{\n        \"six\": {{\n            \"hashes\": [\n                \"sha256:{HEX}\"\n            ],\n            \"index\": \"pypi\",\n            \"version\": \"==1.16.0\"\n        }}\n    }},\n    \"develop\": {{}}\n}}\n"
    )
}

fn files(entries: &[(&str, String)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn rewrite(files: &BTreeMap<String, String>) -> RewriteResult {
    rewrite_registry_redirect_with_pipenv_version(
        files,
        &[dep()],
        &BTreeMap::new(),
        Some(2026),
        false,
    )
}

/// #912: a pylock-only Pipenv checkout (any `pylock_name`) is refused,
/// loudly, and nothing is written or confirmed for it.
#[test]
fn pylock_read_by_pipenv_is_refused_without_pipfile_lock() {
    for (pipfile, lock) in [("Pipfile", "pylock.toml"), ("Pipfile", "pylock.dev.toml")] {
        let result = rewrite(&files(&[(pipfile, PIPFILE.into()), (lock, pylock())]));
        assert!(
            result.files.is_empty() && result.edits.is_empty(),
            "{lock}: pinned {:?}",
            result.files.keys().collect::<Vec<_>>()
        );
        assert!(
            !result.confirmed_python_lock_uuids.contains(UUID),
            "{lock}: confirmed"
        );
        assert!(result.refused_python_lock_uuids.contains(UUID), "{lock}");
        let refusals: Vec<&RewriteWarning> = result
            .warnings
            .iter()
            .filter(|w| w.code == "redirect_pipenv_pylock_unsupported")
            .collect();
        assert_eq!(refusals.len(), 1, "{lock}: {:?}", result.warnings);
        assert!(
            refusals[0].detail.contains(lock)
                && refusals[0].detail.contains("pipenv lock")
                && refusals[0].detail.contains("six==1.16.0"),
            "{lock}: {}",
            refusals[0].detail
        );
    }
}

/// Controls: a pylock with no Pipfile beside it is pinned as before, and a
/// `use_pylock = true` project with both locks still pins both (#1122's
/// hosted control).
#[test]
fn pylock_without_a_pipenv_consumer_or_beside_pipfile_lock_still_pins() {
    let result = rewrite(&files(&[("pylock.toml", pylock())]));
    assert!(
        result
            .files
            .get("pylock.toml")
            .is_some_and(|t| t.contains(WHEEL) && t.contains("archive")),
        "{:?}",
        result.warnings
    );
    assert!(result.confirmed_python_lock_uuids.contains(UUID));

    let result = rewrite(&files(&[
        ("Pipfile", PIPFILE.into()),
        ("Pipfile.lock", pipfile_lock()),
        ("pylock.toml", pylock()),
    ]));
    for lock in ["Pipfile.lock", "pylock.toml"] {
        assert!(
            result.files.get(lock).is_some_and(|t| t.contains(UUID)),
            "{lock}: {:?}",
            result.warnings
        );
    }
    assert!(result
        .warnings
        .iter()
        .all(|w| w.code != "redirect_pipenv_pylock_unsupported"));
}

/// A leftover `Pipfile` beside a governing uv / Poetry / PDM lock does not
/// make Pipenv the installer: the pylock is pinned as before, and no Pipenv
/// refusal vetoes the sibling lock's confirmation.
#[test]
fn pylock_beside_a_governing_tool_lock_is_not_pipenvs() {
    let uv_lock = format!(
        "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://files.pythonhosted.org/packages/d9/5a/{WHEEL}\", hash = \"sha256:{HEX}\" }}]\n"
    );
    for (lock, text) in [
        ("uv.lock", uv_lock),
        ("poetry.lock", String::new()),
        ("pdm.lock", String::new()),
    ] {
        let result = rewrite(&files(&[
            ("Pipfile", PIPFILE.into()),
            (lock, text),
            ("pylock.toml", pylock()),
        ]));
        assert!(
            result
                .warnings
                .iter()
                .all(|w| w.code != "redirect_pipenv_pylock_unsupported"),
            "{lock}: {:?}",
            result.warnings
        );
        // Only the real uv.lock fixture pins cleanly; the empty Poetry /
        // PDM stubs are refused by their own rewriters.
        if lock != "uv.lock" {
            continue;
        }
        assert!(
            !result.refused_python_lock_uuids.contains(UUID),
            "{lock}: {:?}",
            result.warnings
        );
        assert!(
            result
                .files
                .get("pylock.toml")
                .is_some_and(|t| t.contains(WHEEL) && t.contains("archive")),
            "{lock}: {:?}",
            result.warnings
        );
    }
}
