use super::*;

const WHEEL_SHA: &str = "abababababababababababababababababababababababababababababababab";

fn uv_style_lock(name: &str, version: &str) -> String {
    format!(
        "version = 1\n\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"https://files.pythonhosted.org/{name}-{version}-py3-none-any.whl\", hash = \"sha256:{WHEEL_SHA}\" }}]\n"
    )
}

fn names(entries: &[LockfileEntry]) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.version.clone()))
        .collect();
    pairs.sort();
    pairs
}

/// A script lock is scoped to its script: it must ADD to the project's
/// requirements.txt / poetry.lock pins, not replace them (the base only
/// ever let uv.lock short-circuit the fallbacks).
#[tokio::test]
async fn script_lock_supplements_project_pins() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("requirements.txt"), "requests==2.31.0\n")
        .await
        .unwrap();
    tokio::fs::write(
        tmp.path().join("tool.py.lock"),
        uv_style_lock("flask", "3.0.0"),
    )
    .await
    .unwrap();
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        names(&entries),
        vec![
            ("flask".to_string(), "3.0.0".to_string()),
            ("requests".to_string(), "2.31.0".to_string()),
        ]
    );
}

/// uv.lock keeps its exclusive precedence over the fallbacks.
#[tokio::test]
async fn uv_lock_still_hides_requirements_pins() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("requirements.txt"), "requests==2.31.0\n")
        .await
        .unwrap();
    tokio::fs::write(tmp.path().join("uv.lock"), uv_style_lock("flask", "3.0.0"))
        .await
        .unwrap();
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        names(&entries),
        vec![("flask".to_string(), "3.0.0".to_string())]
    );
}

/// Without a uv.lock, poetry.lock is the project's tool lock: it hides
/// requirements.txt (the base's poetry → requirements ordering) while a
/// script lock still UNIONS with it — the standalone lock supplements
/// whichever tool lock the project has, never just uv.lock.
#[tokio::test]
async fn poetry_lock_unions_with_script_lock_and_hides_requirements() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(
        tmp.path().join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\n",
    )
    .await
    .unwrap();
    tokio::fs::write(
        tmp.path().join("tool.py.lock"),
        uv_style_lock("flask", "3.0.0"),
    )
    .await
    .unwrap();
    tokio::fs::write(tmp.path().join("requirements.txt"), "click==8.1.7\n")
        .await
        .unwrap();
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        names(&entries),
        vec![
            ("flask".to_string(), "3.0.0".to_string()),
            ("requests".to_string(), "2.31.0".to_string()),
        ]
    );
}

/// Exclusivity is keyed on a uv.lock that PARSES, not on the file's
/// presence: garbage TOML contributes nothing and must not hide the
/// requirements.txt pins behind it (hosted skips the same file with
/// `redirect_uv_lock_unsupported`, so the inventories agree).
#[tokio::test]
async fn unparseable_uv_lock_falls_through_to_requirements() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(
        tmp.path().join("uv.lock"),
        "version = 1\n[[package]\nname = \"flask\"\n= broken\n",
    )
    .await
    .unwrap();
    tokio::fs::write(tmp.path().join("requirements.txt"), "requests==2.31.0\n")
        .await
        .unwrap();
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        names(&entries),
        vec![("requests".to_string(), "2.31.0".to_string())]
    );
}

/// Ledger recovery must match a purl spelled the project's way
/// (`PyYAML`) against the PEP 503 names the inventory records.
#[tokio::test]
async fn python_document_recovery_canonicalizes_the_purl_name() {
    let tmp = tempfile::tempdir().unwrap();
    let lock = format!(
        "lock-version = '1.0'\n[[packages]]\nname = 'pyyaml'\nversion = '6.0.1'\narchive = {{ url = 'https://pypi.org/PyYAML-6.0.1-py3-none-any.whl', hashes = {{ sha256 = '{WHEEL_SHA}' }} }}\n"
    );
    let entry = crate::vendor::state::VendorEntry {
        ecosystem: "pypi".into(),
        base_purl: "pkg:pypi/PyYAML@6.0.1".into(),
        uuid: "11111111-1111-4111-8111-111111111111".into(),
        artifact: crate::vendor::state::VendorArtifact {
            path: ".socket/vendor/pypi/11111111-1111-4111-8111-111111111111/PyYAML-6.0.1-py3-none-any.whl".into(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        },
        wiring: vec![crate::vendor::state::WiringRecord {
            file: "pylock.toml".into(),
            kind: "python_lock_document".into(),
            action: crate::vendor::state::WiringAction::Rewritten,
            key: Some("pyyaml".into()),
            original: Some(serde_json::Value::String(lock)),
            new: None,
        }],
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some("python-lock".into()),
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    let recovered = recover_lock_entry(tmp.path(), &entry).await.unwrap();
    assert_eq!(
        recovered.resolved.as_deref(),
        Some("https://pypi.org/PyYAML-6.0.1-py3-none-any.whl")
    );
    assert_eq!(
        recovered.integrity,
        LockIntegrity::Sha256Hex(WHEEL_SHA.into())
    );
}
