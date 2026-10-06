use std::collections::BTreeMap;

use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride, Integrity};

fn patch(name: &str) -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: name.into(),
        namespace: None,
        version: "1.0.0".into(),
        token: "11111111-1111-4111-8111-111111111111".into(),
        patch_uuid: "22222222-2222-4222-8222-222222222222".into(),
        artifact_url: format!("https://patch.socket.dev/pkg/{name}-1.0.0-py3-none-any.whl"),
        registry_override: None,
        integrity: Integrity {
            sha256: Some("a".repeat(64)),
            ..Integrity::default()
        },
    }
}

fn files() -> BTreeMap<String, String> {
    let mut lock = "version = 1\nrevision = 3\n\n[manifest]\nrequirements = [{ name = \"alpha\", specifier = \"==1.0.0\" }, { name = \"bravo\", specifier = \"==1.0.0\" }]\n".to_string();
    for name in ["alpha", "bravo"] {
        lock.push_str(&format!("\n[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://pypi.org/{name}-1.0.0-py3-none-any.whl\", hash = \"sha256:original\" }}]\n"));
    }
    BTreeMap::from([
        ("example.py.lock".to_string(), lock),
        ("example.py".to_string(), "# /// script\n# dependencies = [\"alpha==1.0.0\", \"bravo==1.0.0\"]\n# ///\nprint('preserved')\n".to_string()),
    ])
}

#[test]
fn script_redirect_is_idempotent() {
    let original = files();
    let overrides = [patch("alpha"), patch("bravo")];
    let result = rewrite_registry_redirect(&original, &overrides);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(result.files.len(), 2);
    let again = rewrite_registry_redirect(&result.files, &overrides);
    assert!(again.warnings.is_empty(), "{:?}", again.warnings);
    assert!(again.files.is_empty());
    assert!(again.edits.is_empty());
}

#[test]
fn conflicting_or_missing_script_metadata_refuses_lock_changes() {
    let mut original = files();
    original.insert("example.py".into(), "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# [tool.uv.sources]\n# alpha = { git = \"https://example.test/alpha\" }\n# ///\n".into());
    let result = rewrite_registry_redirect(&original, &[patch("alpha")]);
    assert!(result.files.is_empty());
    assert!(result.edits.is_empty());
    assert_eq!(result.warnings[0].code, "redirect_uv_script_unsupported");

    original.remove("example.py");
    let result = rewrite_registry_redirect(&original, &[patch("alpha")]);
    assert!(result.files.is_empty());
    assert!(result.edits.is_empty());
    assert_eq!(result.warnings[0].code, "redirect_uv_script_missing");
}

#[test]
fn native_projects_keep_sources_and_metadata_in_sync() {
    use socket_patch_core::patch::redirect::rewrite_registry_redirect_with_python_metadata;

    for direct in [true, false] {
        let declared = if direct { "alpha" } else { "bravo" };
        let project = format!(
            "[project]\nname = 'project'\nversion = '1'\ndependencies = ['{declared}==1.0.0']\n"
        );
        let lock = format!("version = 1\nrevision = 3\n[[package]]\nname = 'project'\nversion = '1'\nsource = {{virtual='.'}}\ndependencies=[{{name='{declared}'}}]\n[package.metadata]\nrequires-dist=[{{name='{declared}',specifier='==1.0.0'}}]\n[[package]]\nname='alpha'\nversion='1.0.0'\nsource={{registry='https://pypi.org/simple'}}\nwheels=[{{url='https://pypi.org/alpha-1.0.0-py3-none-any.whl',hash='sha256:original'}}]\n");
        let original = BTreeMap::from([
            ("pyproject.toml".to_string(), project),
            ("uv.lock".to_string(), lock),
        ]);
        let dep = patch("alpha");
        let metadata = BTreeMap::from([(
            dep.artifact_url.clone(),
            "[package.metadata]\nrequires-dist = []\nprovides-extras = ['testing']\n".to_string(),
        )]);
        let result = rewrite_registry_redirect_with_python_metadata(
            &original,
            std::slice::from_ref(&dep),
            &metadata,
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let project: toml_edit::DocumentMut = result.files["pyproject.toml"].parse().unwrap();
        assert_eq!(
            project["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(dep.artifact_url.as_str())
        );
        let lock: toml_edit::DocumentMut = result.files["uv.lock"].parse().unwrap();
        let packages = lock["package"].as_array_of_tables().unwrap();
        if direct {
            assert_eq!(
                packages.get(0).unwrap()["metadata"]["requires-dist"][0]["url"].as_str(),
                Some(dep.artifact_url.as_str())
            );
        } else {
            assert_eq!(
                lock["manifest"]["overrides"][0]["url"].as_str(),
                Some(dep.artifact_url.as_str())
            );
            assert_eq!(
                project["tool"]["uv"]["override-dependencies"][0].as_str(),
                Some("alpha==1.0.0")
            );
        }
        assert_eq!(
            packages.get(1).unwrap()["metadata"]["provides-extras"][0].as_str(),
            Some("testing")
        );
        let again =
            rewrite_registry_redirect_with_python_metadata(&result.files, &[dep], &metadata);
        assert!(again.files.is_empty(), "{:?}", again.files);
        assert!(again.warnings.is_empty(), "{:?}", again.warnings);
    }
}

#[test]
fn native_project_refuses_global_sources_for_other_locked_versions() {
    let lock = "version=1\n[[package]]\nname='alpha'\nversion='1.0.0'\nsource={registry='https://pypi.org/simple'}\nwheels=[{url='https://pypi.org/alpha-1.0.0-py3-none-any.whl',hash='sha256:old'}]\n[[package]]\nname='alpha'\nversion='2.0.0'\nsource={registry='https://pypi.org/simple'}\n";
    let files = BTreeMap::from([("uv.lock".to_string(), lock.to_string()), ("pyproject.toml".to_string(), "[project]\nname='project'\ndependencies=['alpha==1.0.0; python_version < \"3.10\"', 'alpha==2.0.0; python_version >= \"3.10\"']\n".to_string())]);
    let result = rewrite_registry_redirect(&files, &[patch("alpha")]);
    assert!(result.files.is_empty());
    assert!(result.edits.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.detail.contains("multiple versions")));
}
