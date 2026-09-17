use socket_patch_core::patch::redirect::{
    revert_remaining_redirect_edits, rewrite_registry_redirect, DepOverride, Integrity,
    RedirectState,
};
use socket_patch_core::utils::poetry_lock::rewrite_poetry_lock;
use std::collections::BTreeMap;

const VERSIONS: &[&str] = &[
    "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1", "1.8.5",
    "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.3",
];
const WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
const URL: &str = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";

fn original(version: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/poetry/{version}/poetry.lock",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .replace("\r\n", "\n")
}

fn patch() -> DepOverride {
    DepOverride {
        ecosystem: "pypi".into(),
        name: "urllib3".into(),
        namespace: None,
        version: "1.26.18".into(),
        token: "7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e".into(),
        patch_uuid: "e828efa5-5c6d-43f3-9909-03f5ac232b98".into(),
        artifact_url: URL.into(),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha256: Some("a".repeat(64)),
            ..Integrity::default()
        },
    }
}

#[tokio::test]
async fn native_lock_generations_redirect_idempotently_and_restore_every_byte() {
    for version in VERSIONS {
        for crlf in [false, true] {
            let pristine = if crlf {
                original(version).replace('\n', "\r\n")
            } else {
                original(version)
            };
            let files = BTreeMap::from([("poetry.lock".into(), pristine.clone())]);
            let result = rewrite_registry_redirect(&files, &[patch()]);
            if *version == "0.12.17" {
                assert!(result.files.is_empty());
                assert!(result.edits.is_empty());
                assert!(result
                    .warnings
                    .iter()
                    .any(|warning| warning.detail.contains("ignores URL sources")));
                continue;
            }
            // Poetry < 1.4 writers (0/1.0/1.1 locks, and 1.3's unstamped 2.0 lock)
            // get the warm-virtualenv advisory; nothing else may warn.
            let pre_1_4 = matches!(*version, "1.0.10" | "1.1.15" | "1.2.2" | "1.3.2");
            let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
            assert_eq!(
                codes,
                if pre_1_4 { vec!["redirect_poetry_stale_install_risk"] } else { vec![] },
                "{version}: {:?}",
                result.warnings
            );
            let redirected = &result.files["poetry.lock"];
            assert!(redirected.contains(URL));
            let again = rewrite_registry_redirect(&result.files, &[patch()]);
            assert!(again.warnings.is_empty(), "{version}: {:?}", again.warnings);
            assert!(again.files.is_empty());
            assert!(again.edits.is_empty());
            let directory = tempfile::tempdir().unwrap();
            tokio::fs::write(directory.path().join("poetry.lock"), redirected)
                .await
                .unwrap();
            let mut state = RedirectState {
                edits: result.edits,
                ..RedirectState::default()
            };
            let outcome =
                revert_remaining_redirect_edits(directory.path(), &mut state, false).await;
            assert!(outcome.fully_reverted(), "{:?}", outcome.refusals);
            assert_eq!(
                tokio::fs::read_to_string(directory.path().join("poetry.lock"))
                    .await
                    .unwrap(),
                pristine
            );
        }
    }
}

#[test]
fn every_native_lock_generation_supports_file_sources() {
    for version in VERSIONS {
        let pristine = original(version);
        let path = format!(".socket/vendor/pypi/e828efa5-5c6d-43f3-9909-03f5ac232b98/{WHEEL}");
        let rewritten = rewrite_poetry_lock(
            &pristine,
            "URLLib3",
            "1.26.18",
            "file",
            &path,
            WHEEL,
            &"a".repeat(64),
        )
        .unwrap()
        .unwrap();
        let lock: toml_edit::DocumentMut = rewritten.parse().unwrap();
        let package = lock["package"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(package["source"]["url"].as_str(), Some(path.as_str()));
        assert_eq!(
            rewrite_poetry_lock(
                &rewritten,
                "urllib3",
                "1.26.18",
                "file",
                &path,
                WHEEL,
                &"a".repeat(64)
            )
            .unwrap()
            .unwrap(),
            rewritten
        );
        let old: toml_edit::DocumentMut = pristine.parse().unwrap();
        assert_eq!(
            old["metadata"]["content-hash"].as_str(),
            lock["metadata"]["content-hash"].as_str()
        );
    }
}

#[test]
fn invalid_inputs_never_produce_edits() {
    let pristine = original("2.4.3");
    let source = "\n[package.source]\ntype='git'\nurl='https://example.test/urllib3'\n";
    let fork = "\n[[package]]\nname='urllib3'\nversion='1.26.18'\n";
    for lock in [
        pristine.replace("[metadata]", &format!("{source}\n[metadata]")),
        format!("{pristine}{fork}"),
        pristine.replace("lock-version = \"2.1\"", "lock-version = \"3.0\""),
        "[[invalid".into(),
    ] {
        let files = BTreeMap::from([("poetry.lock".into(), lock)]);
        let result = rewrite_registry_redirect(&files, &[patch()]);
        assert!(result.files.is_empty());
        assert!(result.edits.is_empty());
        assert!(!result.warnings.is_empty());
    }
    for (filename, hash) in [
        ("requests-1.26.18-py3-none-any.whl", "a".repeat(64)),
        ("urllib3-1.0-py3-none-any.whl", "a".repeat(64)),
        (WHEEL, "bad".into()),
        (WHEEL, "z".repeat(64)),
    ] {
        assert!(
            rewrite_poetry_lock(&pristine, "urllib3", "1.26.18", "url", URL, filename, &hash)
                .is_err()
        );
    }
    let files = BTreeMap::from([("poetry.lock".into(), pristine)]);
    let mut missing_hash = patch();
    missing_hash.integrity.sha256 = None;
    let result = rewrite_registry_redirect(&files, &[missing_hash]);
    assert!(result.files.is_empty());
    assert_eq!(result.warnings[0].code, "redirect_poetry_missing_sha256");
}

#[tokio::test]
async fn drift_keeps_the_lock_and_rollback_ledger() {
    let files = BTreeMap::from([("poetry.lock".into(), original("1.1.15"))]);
    let result = rewrite_registry_redirect(&files, &[patch()]);
    let changed = result.files["poetry.lock"].replace("sha256:aaaa", "sha256:bbbb");
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::write(directory.path().join("poetry.lock"), &changed)
        .await
        .unwrap();
    let mut state = RedirectState {
        edits: result.edits,
        ..RedirectState::default()
    };
    let outcome = revert_remaining_redirect_edits(directory.path(), &mut state, false).await;
    assert!(!outcome.fully_reverted());
    assert!(!state.edits.is_empty());
    assert_eq!(
        tokio::fs::read_to_string(directory.path().join("poetry.lock"))
            .await
            .unwrap(),
        changed
    );
}

#[tokio::test]
async fn either_patch_reverts_independently_with_unrelated_edits() {
    for version in VERSIONS.iter().filter(|version| **version != "0.12.17") {
        for crlf in [false, true] {
            for first_name in ["urllib3", "six"] {
                let mut lock: toml_edit::DocumentMut = original(version).parse().unwrap();
                let packages = lock["package"].as_array_of_tables_mut().unwrap();
                let mut second = packages.get(0).unwrap().clone();
                second["name"] = toml_edit::value("six");
                second["version"] = toml_edit::value("1.16.0");
                second.set_position(None);
                second.remove("extras");
                packages.push(second);
                if let Some(files) = lock["metadata"].get_mut("files") {
                    if let Some(value) = files.get("urllib3").cloned() {
                        files["six"] = value;
                    }
                }
                let pristine = lock.to_string();
                let pristine = if crlf {
                    pristine.replace('\n', "\r\n")
                } else {
                    pristine
                };
                let second_patch = DepOverride {
                    name: "six".into(),
                    version: "1.16.0".into(),
                    artifact_url: URL.replace("urllib3", "six").replace("1.26.18", "1.16.0"),
                    ..patch()
                };
                let files = BTreeMap::from([("poetry.lock".into(), pristine.clone())]);
                let first = rewrite_registry_redirect(&files, &[patch()]);
                assert!(
                    !first.files.is_empty(),
                    "{version}: {:?}\n{pristine}",
                    first.warnings
                );
                let second = rewrite_registry_redirect(&first.files, &[second_patch]);
                assert!(
                    !second.files.is_empty(),
                    "{version}: {:?}\n{}",
                    second.warnings,
                    first.files["poetry.lock"]
                );
                assert!(
                    second
                        .warnings
                        .iter()
                        .all(|w| w.code == "redirect_poetry_stale_install_risk"),
                    "{:?}",
                    second.warnings
                );
                let directory = tempfile::tempdir().unwrap();
                let unrelated = if crlf {
                    "# retained user edit\r\n"
                } else {
                    "# retained user edit\n"
                };
                tokio::fs::write(
                    directory.path().join("poetry.lock"),
                    format!("{unrelated}{}", second.files["poetry.lock"]),
                )
                .await
                .unwrap();
                let mut states: Vec<_> = [first, second]
                    .into_iter()
                    .map(|result| RedirectState {
                        edits: result.edits,
                        ..RedirectState::default()
                    })
                    .collect();
                if first_name == "six" {
                    states.reverse();
                }
                for state in &mut states {
                    let outcome =
                        revert_remaining_redirect_edits(directory.path(), state, false).await;
                    assert!(
                        outcome.fully_reverted(),
                        "{version}: {:?}",
                        outcome.refusals
                    );
                }
                assert_eq!(
                    tokio::fs::read_to_string(directory.path().join("poetry.lock"))
                        .await
                        .unwrap(),
                    format!("{unrelated}{pristine}")
                );
            }
        }
    }
}

#[test]
fn absent_entries_warn_once_and_missing_sha256_is_gated_once_per_dep() {
    let files = BTreeMap::from([
        ("poetry.lock".to_string(), original("2.4.3")),
        ("packages/app/poetry.lock".to_string(), original("1.8.5")),
    ]);
    let mut six = patch();
    six.name = "six".into();
    six.version = "1.16.0".into();
    six.artifact_url = URL.replace("urllib3", "six").replace("1.26.18", "1.16.0");
    let result = rewrite_registry_redirect(&files, &[six]);
    assert!(result.files.is_empty());
    let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(
        codes,
        vec!["redirect_poetry_entry_not_found", "redirect_poetry_entry_not_found"]
    );
    let mut missing_hash = patch();
    missing_hash.integrity.sha256 = None;
    let result = rewrite_registry_redirect(&files, &[missing_hash]);
    assert!(result.files.is_empty());
    let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(codes, vec!["redirect_poetry_missing_sha256"], "gated once, not once per lock");
}

/// A future Poetry that bumps the lock minor (2.2) is rewritten like 2.1 in
/// hosted mode — the vendored loader already accepts it with an advisory, and
/// the same lock must not be a silent no-op on one path and applied on another.
#[tokio::test]
async fn newer_2x_minor_redirects_and_reverts() {
    let lock = original("2.4.3").replace("lock-version = \"2.1\"", "lock-version = \"2.2\"");
    let files = BTreeMap::from([("poetry.lock".to_string(), lock.clone())]);
    let result = rewrite_registry_redirect(&files, &[patch()]);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert!(result.files["poetry.lock"].contains(URL));
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::write(directory.path().join("poetry.lock"), &result.files["poetry.lock"])
        .await
        .unwrap();
    let mut state = RedirectState {
        edits: result.edits,
        ..RedirectState::default()
    };
    let outcome = revert_remaining_redirect_edits(directory.path(), &mut state, false).await;
    assert!(outcome.fully_reverted(), "{:?}", outcome.refusals);
    assert_eq!(
        tokio::fs::read_to_string(directory.path().join("poetry.lock")).await.unwrap(),
        lock
    );
}

/// A rotated grant token (or republished patch) supersedes the earlier hosted
/// URL in place; rollback of the SECOND run restores the FIRST run's fragment,
/// exactly as the ledger records it.
#[test]
fn rotated_grant_token_supersedes_the_prior_hosted_url() {
    let files = BTreeMap::from([("poetry.lock".to_string(), original("1.8.5"))]);
    let first = rewrite_registry_redirect(&files, &[patch()]);
    let mut rotated = patch();
    rotated.token = "00000000-0000-4000-8000-000000000000".into();
    rotated.artifact_url = URL.replace("7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e", "00000000-0000-4000-8000-000000000000");
    let second = rewrite_registry_redirect(&first.files, &[rotated.clone()]);
    assert!(second.warnings.is_empty(), "{:?}", second.warnings);
    let lock = &second.files["poetry.lock"];
    assert!(lock.contains(&rotated.artifact_url) && !lock.contains(URL));
    assert_eq!(second.edits.len(), 1);
    assert!(second.edits[0].original.as_ref().unwrap().as_str().unwrap().contains(URL));
}
