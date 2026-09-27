use std::collections::BTreeMap;
use std::path::Path;

use crate::utils::fs::{atomic_write_bytes_preserving_mode, is_symlink, read_regular_to_string};
use crate::utils::hatch;
use crate::vendor::common::record;
use crate::vendor::state::{VendorEntry, WiringAction, WiringRecord};
use crate::vendor::RevertOutcome;

type Failure = (&'static str, String);
const KIND: &str = "hatch_document";

pub(super) struct HatchProject {
    files: BTreeMap<String, String>,
    pub in_sync: bool,
    pub pin: Option<(String, String)>,
}

async fn read_files(root: &Path) -> Result<BTreeMap<String, String>, Failure> {
    let mut files = BTreeMap::new();
    for file in ["pyproject.toml", "hatch.toml"] {
        if is_symlink(&root.join(file)).await {
            return Err(("pypi_hatch_symlink", format!("{file} is a symbolic link")));
        }
        match read_regular_to_string(&root.join(file)).await {
            Ok(text) => {
                files.insert(file.to_owned(), text);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(("pypi_hatch_read_failed", format!("{file}: {error}"))),
        }
    }
    Ok(files)
}

pub(super) async fn load(
    root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
) -> Result<HatchProject, Failure> {
    let files = read_files(root).await?;
    if std::env::var("HATCH_ENV_TYPE_VIRTUAL_UV_PATH").is_ok_and(|path| !path.is_empty()) {
        return Err(("pypi_hatch_unsupported", "vendored Hatch wheels require the pip installer: uv does not enforce local wheel fragment hashes".into()));
    }
    let prefix = format!("{{root:uri}}/.socket/vendor/pypi/{uuid}/");
    let state = super::state::load_state_shared(root)
        .await
        .map_err(|error| ("pypi_hatch_ledger_invalid", error.to_string()))?;
    let entry = state
        .entries
        .values()
        .find(|entry| entry.ecosystem == "pypi" && entry.uuid == uuid);
    let pin = entry.map(|entry| (entry.artifact.path.clone(), entry.artifact.sha256.clone()));
    if let Some((wheel, hash)) = &pin {
        let relative_prefix = format!(".socket/vendor/pypi/{uuid}/");
        let leaf = wheel.strip_prefix(&relative_prefix).ok_or_else(|| {
            (
                "pypi_hatch_pin_invalid",
                "wheel path does not match patch".to_owned(),
            )
        })?;
        if leaf.contains(['/', '\\', '%', ':'])
            || !leaf.ends_with(".whl")
            || hash.len() != 64
            || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err((
                "pypi_hatch_pin_invalid",
                "invalid recorded wheel pin".into(),
            ));
        }
        let path = root.join(wheel);
        let mut component_path = root.to_path_buf();
        for component in wheel.split('/') {
            component_path.push(component);
            if is_symlink(&component_path).await {
                return Err((
                    "pypi_hatch_pin_invalid",
                    "wheel path contains a symlink".into(),
                ));
            }
        }
        if tokio::fs::try_exists(&path).await.unwrap_or(true)
            && super::verify::file_sha256_hex(&path).await.as_deref() != Some(hash.as_str())
        {
            return Err((
                "pypi_hatch_pin_invalid",
                "wheel digest does not match the recorded artifact".into(),
            ));
        }
    }
    let url = pin
        .as_ref()
        .map(|(wheel, hash)| format!("{{root:uri}}/{wheel}#sha256={hash}"))
        .unwrap_or_else(|| {
            format!(
                "{prefix}{name}-{version}-py3-none-any.whl#sha256={}",
                "0".repeat(64)
            )
        });
    let changes = hatch::rewrite(&files, name, version, &url)
        .map_err(|error| ("pypi_hatch_unsupported", error))?;
    if hatch::has_environment_dependency(&files, name) {
        require_environment_context_support(root).await?;
    }
    let in_sync = pin.is_some() && changes.is_empty();
    Ok(HatchProject {
        files,
        in_sync,
        pin,
    })
}

async fn require_environment_context_support(root: &Path) -> Result<(), Failure> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new("hatch")
            .arg("--version")
            .current_dir(root)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    if let Ok(Ok(output)) = output {
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .filter_map(|word| semver::Version::parse(word).ok())
                .any(|version| version >= semver::Version::new(1, 2, 0))
        {
            return Ok(());
        }
    }
    Err(("pypi_hatch_unsupported", "vendored environment dependencies require Hatch >=1.2 on PATH for root URI expansion; upgrade Hatch or use the install hook".into()))
}

async fn write_files(
    root: &Path,
    original: &BTreeMap<String, String>,
    edits: &BTreeMap<String, String>,
) -> Result<(), String> {
    let live = read_files(root).await.map_err(|(_, error)| error)?;
    if live != *original {
        return Err("Hatch configuration changed during patching".into());
    }
    let mut written = Vec::new();
    for (file, new) in edits {
        if let Err(error) =
            atomic_write_bytes_preserving_mode(&root.join(file), new.as_bytes()).await
        {
            let mut failures = Vec::new();
            for file in written.into_iter().rev() {
                if let Err(error) =
                    atomic_write_bytes_preserving_mode(&root.join(file), original[file].as_bytes())
                        .await
                {
                    failures.push(format!("{file}: {error}"));
                }
            }
            return Err(format!(
                "{file}: {error}; rollback failures: {}",
                failures.join(", ")
            ));
        }
        written.push(file);
    }
    Ok(())
}

pub(super) async fn wire(
    project: &HatchProject,
    root: &Path,
    name: &str,
    version: &str,
    wheel: &str,
    hash: &str,
) -> Result<Vec<WiringRecord>, Failure> {
    let url = format!("{{root:uri}}/{wheel}#sha256={hash}");
    let plan = hatch::plan(&project.files, name, version, &url)
        .map_err(|error| ("pypi_hatch_unsupported", error))?;
    let mut originals = project.files.clone();
    let mut permission_record = None;
    if let Some(permission) = plan.permission {
        originals.insert(permission.file.clone(), permission.new.clone());
        let state = super::state::load_state_shared(root)
            .await
            .map_err(|error| ("pypi_hatch_ledger_invalid", error.to_string()))?;
        permission_record = Some(
            state
                .entries
                .values()
                .flat_map(|entry| &entry.wiring)
                .find(|record| record.kind == "hatch_permission" && record.file == permission.file)
                .cloned()
                .unwrap_or_else(|| {
                    record(
                        &permission.file,
                        "hatch_permission",
                        WiringAction::Rewritten,
                        "allow-direct-references",
                        Some(permission.original),
                        permission.new,
                    )
                }),
        );
    }
    write_files(root, &project.files, &plan.files)
        .await
        .map_err(|error| ("pypi_hatch_write_failed", error))?;
    let mut records: Vec<WiringRecord> = plan
        .files
        .into_iter()
        .filter(|(file, new)| originals.get(file) != Some(new))
        .map(|(file, new)| {
            record(
                &file,
                KIND,
                WiringAction::Rewritten,
                name,
                originals.get(&file).cloned(),
                new,
            )
        })
        .collect();
    records.extend(permission_record);
    Ok(records)
}

pub(super) async fn revert(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    let files = match read_files(root).await {
        Ok(files) => files,
        Err((_, error)) => return RevertOutcome::failed(error),
    };
    let mut edits = BTreeMap::new();
    for record in entry
        .wiring
        .iter()
        .rev()
        .filter(|record| record.kind != "hatch_permission")
    {
        if !matches!(record.file.as_str(), "pyproject.toml" | "hatch.toml") || record.kind != KIND {
            return RevertOutcome::failed("invalid Hatch wiring record");
        }
        let (Some(original), Some(new), Some(live)) = (
            record.original.as_ref().and_then(serde_json::Value::as_str),
            record.new.as_ref().and_then(serde_json::Value::as_str),
            files.get(&record.file),
        ) else {
            return RevertOutcome::failed("missing Hatch wiring document");
        };
        match super::pypi_lock::restore_document(live, original, new) {
            Ok((restored, false)) => {
                edits.insert(record.file.clone(), restored);
            }
            Ok((_, true)) => {
                return RevertOutcome::failed(format!("{} changed since patching", record.file))
            }
            Err(error) => return RevertOutcome::failed(error),
        }
    }
    let mut restored_files = files.clone();
    restored_files.extend(edits.clone());
    if !hatch::has_project_direct_references(&restored_files) {
        for permission in entry
            .wiring
            .iter()
            .filter(|record| record.kind == "hatch_permission")
        {
            if !matches!(permission.file.as_str(), "pyproject.toml" | "hatch.toml") {
                return RevertOutcome::failed("invalid Hatch permission record");
            }
            let (Some(original), Some(new), Some(live)) = (
                permission
                    .original
                    .as_ref()
                    .and_then(serde_json::Value::as_str),
                permission.new.as_ref().and_then(serde_json::Value::as_str),
                restored_files.get(&permission.file),
            ) else {
                return RevertOutcome::failed("missing Hatch permission document");
            };
            match super::pypi_lock::restore_document(live, original, new) {
                Ok((restored, false)) => {
                    edits.insert(permission.file.clone(), restored);
                }
                _ => {
                    return RevertOutcome::failed(
                        "Hatch direct-reference permission changed since patching",
                    )
                }
            }
        }
    }
    if !dry_run {
        if let Err(error) = write_files(root, &files, &edits).await {
            return RevertOutcome::failed(error);
        }
    }
    RevertOutcome::ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::{save_state, VendorState};
    use serde_json::json;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIGINAL: &str =
        "[project]\ndependencies=[\"one==1\", \"two==2\"]\n[tool.hatch.envs.default]\n";

    fn entry(
        uuid: &str,
        name: &str,
        wheel: &str,
        hash: &str,
        wiring: Vec<WiringRecord>,
    ) -> VendorEntry {
        serde_json::from_value(json!({
            "ecosystem": "pypi", "basePurl": format!("pkg:pypi/{name}@1"),
            "uuid": uuid, "flavor": "hatch", "wiring": wiring,
            "artifact": {"path": wheel, "sha256": hash}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn recorded_pin_drift_missing_artifact_and_ledgerless_source() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        tokio::fs::write(root.join("pyproject.toml"), ORIGINAL)
            .await
            .unwrap();
        let project = load(root, "one", "1", UUID).await.unwrap();
        let wheel = format!(".socket/vendor/pypi/{UUID}/one-1-py3-none-any.whl");
        tokio::fs::create_dir_all(root.join(&wheel).parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(root.join(&wheel), b"real file bytes")
            .await
            .unwrap();
        let hash = crate::vendor::verify::file_sha256_hex(&root.join(&wheel))
            .await
            .unwrap();
        let wiring = wire(&project, root, "one", "1", &wheel, &hash)
            .await
            .unwrap();
        let patched = tokio::fs::read_to_string(root.join("pyproject.toml"))
            .await
            .unwrap();
        assert!(load(root, "one", "1", UUID).await.is_err());
        let mut state = VendorState::default();
        state.entries.insert(
            "pkg:pypi/one@1".into(),
            entry(UUID, "one", &wheel, &hash, wiring),
        );
        save_state(root, &state).await.unwrap();
        assert!(load(root, "one", "1", UUID).await.unwrap().in_sync);
        for changed in [
            patched.replace(&hash, &"a".repeat(64)),
            patched.replace("one-1-py3", "other-1-py3"),
            patched.replace("one-1-py3", "../one-1-py3"),
        ] {
            tokio::fs::write(root.join("pyproject.toml"), changed)
                .await
                .unwrap();
            assert!(load(root, "one", "1", UUID).await.is_err());
        }
        tokio::fs::write(root.join("pyproject.toml"), &patched)
            .await
            .unwrap();
        tokio::fs::write(root.join(&wheel), b"corrupt")
            .await
            .unwrap();
        assert!(load(root, "one", "1", UUID).await.is_err());
        tokio::fs::remove_file(root.join(&wheel)).await.unwrap();
        assert!(load(root, "one", "1", UUID).await.unwrap().in_sync);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_configuration_is_refused_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let target = external.path().join("pyproject.toml");
        tokio::fs::write(&target, ORIGINAL).await.unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join("pyproject.toml")).unwrap();
        assert!(load(temp.path(), "one", "1", UUID).await.is_err());
        assert_eq!(tokio::fs::read_to_string(target).await.unwrap(), ORIGINAL);
    }

    #[tokio::test]
    async fn concurrent_edits_are_not_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        tokio::fs::write(root.join("pyproject.toml"), ORIGINAL)
            .await
            .unwrap();
        let project = load(root, "one", "1", UUID).await.unwrap();
        let changed = format!("{ORIGINAL}# concurrent edit\n");
        tokio::fs::write(root.join("pyproject.toml"), &changed)
            .await
            .unwrap();
        assert!(wire(
            &project,
            root,
            "one",
            "1",
            ".socket/vendor/a.whl",
            &"0".repeat(64)
        )
        .await
        .is_err());
        assert_eq!(
            tokio::fs::read_to_string(root.join("pyproject.toml"))
                .await
                .unwrap(),
            changed
        );
    }

    #[tokio::test]
    async fn shared_permission_survives_selective_and_preserved_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        tokio::fs::write(root.join("pyproject.toml"), ORIGINAL)
            .await
            .unwrap();
        let mut state = VendorState::default();
        let mut entries = Vec::new();
        for (name, version, uuid) in [
            ("one", "1", UUID),
            ("two", "2", "a0f74f9a-ce65-4451-ab60-025159b4d410"),
        ] {
            let project = load(root, name, version, uuid).await.unwrap();
            let wheel = format!(".socket/vendor/pypi/{uuid}/{name}-{version}-py3-none-any.whl");
            let wiring = wire(&project, root, name, version, &wheel, &"0".repeat(64))
                .await
                .unwrap();
            let entry = entry(uuid, name, &wheel, &"0".repeat(64), wiring);
            state.entries.insert(name.into(), entry.clone());
            entries.push(entry);
            save_state(root, &state).await.unwrap();
        }
        let both = tokio::fs::read_to_string(root.join("pyproject.toml"))
            .await
            .unwrap();
        assert!(revert(&entries[0], root, false).await.success);
        let remaining = tokio::fs::read_to_string(root.join("pyproject.toml"))
            .await
            .unwrap();
        assert_ne!(remaining, both);
        assert!(remaining.contains("allow-direct-references = true"));
        assert!(remaining.contains("two-2-py3-none-any.whl"));
        assert!(revert(&entries[1], root, false).await.success);

        assert!(revert(&entries[0], root, false).await.success);
        assert_eq!(
            tokio::fs::read_to_string(root.join("pyproject.toml"))
                .await
                .unwrap(),
            ORIGINAL
        );
    }
}
