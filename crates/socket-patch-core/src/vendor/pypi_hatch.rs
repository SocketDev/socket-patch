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
            || !super::pypi_distribution::supported(leaf)
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
    require_environment_context_support_with(root, &|var| std::env::var_os(var)).await
}

/// [`require_environment_context_support`] over an injected environment
/// reader (tests).
///
/// `hatch` is looked up on ABSOLUTE `PATH` entries only and the RESOLVED path
/// is spawned: the probe runs from the scanned project, so a bare
/// `Command::new("hatch")` under a relative `PATH` entry (`.`, an empty
/// component) would execute a `hatch` committed to that repository. No
/// `hatch` found takes the same refusal as one too old.
async fn require_environment_context_support_with(
    root: &Path,
    var: &impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<(), Failure> {
    let output = match crate::utils::process::resolve_tool_with("hatch", var) {
        Some(program) => {
            let mut command = crate::utils::process::command_for(&program);
            command.arg("--version").current_dir(root);
            crate::utils::fs::run_blocking(move || {
                crate::utils::process::output_within(command, crate::utils::process::PROBE_TIMEOUT)
            })
            .await
            .ok()
        }
        None => None,
    };
    if let Some(output) = output {
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .filter_map(|word| semver::Version::parse(word).ok())
                .any(|version| version >= semver::Version::new(1, 2, 0))
        {
            return Ok(());
        }
    }
    Err(("pypi_hatch_unsupported", "vendored environment dependencies require Hatch >=1.2 on PATH for root URI expansion; upgrade Hatch or use agent mode".into()))
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
                    // A permission live references hold is recorded as the
                    // value it has once they are gone, the same rule the
                    // hosted unwind applies.
                    let original = permission_held_by_live_references(&project.files)
                        .then(|| drop_owned_permission(&permission.original, &permission.file))
                        .flatten()
                        .unwrap_or(permission.original);
                    record(
                        &permission.file,
                        "hatch_permission",
                        WiringAction::Rewritten,
                        "allow-direct-references",
                        Some(original),
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
            Ok((restored, false))
                if !super::pypi_lock::still_references_artifact(
                    &restored,
                    original,
                    &entry.uuid,
                ) =>
            {
                edits.insert(record.file.clone(), restored);
            }
            Ok((_, false)) => {
                return RevertOutcome::failed(format!(
                "{} still references the vendored artifact after restoring the recorded entries",
                record.file
            ))
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

/// Whether `files` hold a project direct reference the vendored ledger does
/// not own, so any direct-reference permission there is held for it. A
/// hosted→vendored takeover unwinds hosted pins one at a time (#674), so
/// when the first package is vendored the other packages' hosted references
/// still hold the permission hosted mode added. Recording that state as the
/// permission's "original" would make rollback restore a permission the user
/// never had. Vendored references don't count: a permission they need was
/// recorded before them.
fn permission_held_by_live_references(files: &BTreeMap<String, String>) -> bool {
    files
        .get(hatch::HATCH_FILES[0])
        .and_then(|text| text.trim_start_matches('\u{feff}').parse().ok())
        .is_some_and(|document: toml_edit::DocumentMut| {
            crate::vendor::common::pyproject_dependency_specs(&document)
                .into_iter()
                .filter_map(|(_, spec)| spec.split(';').next()?.split_once('@'))
                .any(|(_, location)| {
                    !location
                        .trim_start()
                        .starts_with("{root:uri}/.socket/vendor/")
                })
        })
}

/// `text` without its direct-reference permission and the tables that
/// leaves empty, or `None` when the permission is not set there.
fn drop_owned_permission(text: &str, file: &str) -> Option<String> {
    let body = text.trim_start_matches('\u{feff}');
    let bom = &text[..text.len() - body.len()];
    let mut document = body.parse::<toml_edit::DocumentMut>().ok()?;
    let keys = hatch::permission_keys(file == hatch::HATCH_FILES[1]);
    hatch::drop_direct_reference_permission(&mut document, keys)
        .then(|| crate::utils::python_lock::preserve_line_endings(text, format!("{bom}{document}")))
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

    /// #674: a hosted→vendored takeover reverts one hosted pin at a time,
    /// so the first package's ledger snapshots the permission the OTHER
    /// package's still-live hosted reference needs. Once the last project
    /// direct reference is unwired, in either order, the pyproject is back
    /// to its pre-hosted bytes.
    #[tokio::test]
    async fn takeover_snapshot_of_hosted_permission_is_not_restored() {
        let original = "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"toml==0.10.2\"]\n";
        let packages = [
            ("six", "1.16.0", UUID),
            ("toml", "0.10.2", "a0f74f9a-ce65-4451-ab60-025159b4d410"),
        ];
        let hosted_url = |name: &str, version: &str| {
            format!(
                "https://patches.example/{name}-{version}-py3-none-any.whl#sha256={}",
                "b".repeat(64)
            )
        };
        for order in [[0, 1], [1, 0]] {
            for external in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path();
                let mut files =
                    BTreeMap::from([("pyproject.toml".to_owned(), original.to_owned())]);
                if external {
                    files.insert(
                        "hatch.toml".into(),
                        "[metadata]\nallow-ambiguous-features = true\n".into(),
                    );
                }
                let before = files.clone();
                // Hosted scan: both packages redirected, permission enabled.
                for (name, version, _) in packages {
                    let plan =
                        hatch::plan(&files, name, version, &hosted_url(name, version)).unwrap();
                    files.extend(plan.files);
                }
                let permission_file = if external {
                    "hatch.toml"
                } else {
                    "pyproject.toml"
                };
                assert!(files[permission_file].contains("allow-direct-references = true"));
                for (file, text) in &files {
                    tokio::fs::write(root.join(file), text).await.unwrap();
                }
                // Takeover: unwind one hosted pin (the other keeps the
                // permission live), then vendor that package.
                let mut state = VendorState::default();
                let mut entries = Vec::new();
                for (name, version, uuid) in packages {
                    let text = tokio::fs::read_to_string(root.join("pyproject.toml"))
                        .await
                        .unwrap();
                    let unwound = text.replace(
                        &format!("{name} @ {}", hosted_url(name, version)),
                        &format!("{name}=={version}"),
                    );
                    assert_ne!(unwound, text);
                    tokio::fs::write(root.join("pyproject.toml"), unwound)
                        .await
                        .unwrap();
                    let project = load(root, name, version, uuid).await.unwrap();
                    let wheel =
                        format!(".socket/vendor/pypi/{uuid}/{name}-{version}-py3-none-any.whl");
                    let wiring = wire(&project, root, name, version, &wheel, &"0".repeat(64))
                        .await
                        .unwrap();
                    let entry = entry(uuid, name, &wheel, &"0".repeat(64), wiring);
                    state.entries.insert(name.into(), entry.clone());
                    entries.push(entry);
                    save_state(root, &state).await.unwrap();
                }
                for index in order {
                    let outcome = revert(&entries[index], root, false).await;
                    assert!(outcome.success, "{:?}", outcome.error);
                }
                for (file, text) in &before {
                    assert_eq!(
                        &tokio::fs::read_to_string(root.join(file)).await.unwrap(),
                        text,
                        "{file}, order {order:?}, external {external}"
                    );
                }
            }
        }
    }

    /// #674 end to end through the real lanes: the hosted rewrite, then the
    /// takeover's per-pin `restore_upstream` and vendored wiring for each
    /// package in turn, then a revert in either order.
    #[tokio::test]
    async fn takeover_through_hosted_unwind_reverts_byte_exact() {
        use crate::patch::redirect::upstream::{restore_upstream, HostedPin, RestoreOptions};
        let original = "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"toml==0.10.2\"]\n";
        let packages = [
            ("six", "1.16.0", UUID),
            ("toml", "0.10.2", "a0f74f9a-ce65-4451-ab60-025159b4d410"),
        ];
        let deps: Vec<crate::patch::redirect::DepOverride> = packages
            .iter()
            .map(|(name, version, uuid)| {
                serde_json::from_value(json!({
                    "ecosystem": "pypi", "name": name, "version": version,
                    "token": "11111111-1111-1111-1111-111111111111",
                    "patchUuid": uuid,
                    "artifactUrl": format!(
                        "https://patch.socket.dev/patch/pypi/{name}/{version}/11111111-1111-1111-1111-111111111111/{uuid}/{name}-{version}-py3-none-any.whl"
                    ),
                    "integrity": { "sha256": "d".repeat(64) }
                }))
                .unwrap()
            })
            .collect();
        let input = BTreeMap::from([("pyproject.toml".to_owned(), original.to_owned())]);
        let hosted = crate::patch::redirect::rewrite_registry_redirect_with_pipenv_version(
            &input,
            &deps,
            &BTreeMap::new(),
            None,
            false,
        );
        let hosted = &hosted.files["pyproject.toml"];
        assert!(
            hosted.contains("allow-direct-references = true"),
            "{hosted}"
        );
        for order in [[0, 1], [1, 0]] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            tokio::fs::write(root.join("pyproject.toml"), hosted)
                .await
                .unwrap();
            let pins = HostedPin::all(&crate::vex::discover_patched_refs(root).await);
            assert_eq!(pins.len(), 2, "{pins:?}");
            let mut state = VendorState::default();
            let mut entries = Vec::new();
            for (name, version, uuid) in packages {
                let pin = pins.iter().find(|pin| pin.uuid == uuid).unwrap();
                let restore = restore_upstream(
                    root,
                    std::slice::from_ref(pin),
                    &RestoreOptions {
                        offline: true,
                        ..RestoreOptions::default()
                    },
                )
                .await;
                assert_eq!(restore.refused().count(), 0, "{name}");
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
            for index in order {
                let outcome = revert(&entries[index], root, false).await;
                assert!(outcome.success, "{:?}", outcome.error);
            }
            assert_eq!(
                tokio::fs::read_to_string(root.join("pyproject.toml"))
                    .await
                    .unwrap(),
                original,
                "order {order:?}"
            );
        }
    }

    /// The #674 drop only applies to a permission recorded while
    /// non-vendored direct references were live. A permission the user set
    /// is restored verbatim after two vendored packages are reverted, inline
    /// and in hatch.toml alike.
    #[tokio::test]
    async fn user_permission_survives_vendored_revert() {
        let pyproject = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"toml==0.10.2\"]\n";
        for (file, text) in [
            (
                "pyproject.toml",
                format!("{pyproject}\n[tool.hatch.metadata]\nallow-direct-references = true\n"),
            ),
            (
                "hatch.toml",
                "[metadata]\nallow-direct-references = true\n".to_owned(),
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            let mut before = BTreeMap::from([("pyproject.toml".to_owned(), pyproject.to_owned())]);
            before.insert(file.to_owned(), text);
            for (file, text) in &before {
                tokio::fs::write(root.join(file), text).await.unwrap();
            }
            let mut state = VendorState::default();
            let mut entries = Vec::new();
            for (name, version, uuid) in [
                ("six", "1.16.0", UUID),
                ("toml", "0.10.2", "a0f74f9a-ce65-4451-ab60-025159b4d410"),
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
            for entry in entries.iter().rev() {
                let outcome = revert(entry, root, false).await;
                assert!(outcome.success, "{:?}", outcome.error);
            }
            for (name, text) in &before {
                assert_eq!(
                    &tokio::fs::read_to_string(root.join(name)).await.unwrap(),
                    text,
                    "{name} ({file} permission)"
                );
            }
        }
    }

    /// #385: ordinary pyproject edits after vendoring (a release bump, a
    /// comment on `name`, a new sibling dependency) must not block rollback.
    #[tokio::test]
    async fn revert_keeps_unrelated_project_edits() {
        let original =
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n";
        let edits: [(&str, &str); 4] = [
            ("version = \"0.1.0\"", "version = \"0.2.0\""),
            ("name = \"app\"", "name = \"app\" # renamed soon"),
            ("dependencies = [", "dependencies = [\"idna==3.7\", "),
            (
                "version = \"0.1.0\"\n",
                "version = \"0.3.0\"\ndescription = \"x\"\n",
            ),
        ];
        for (from, to) in edits {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            tokio::fs::write(root.join("pyproject.toml"), original)
                .await
                .unwrap();
            let project = load(root, "six", "1.16.0", UUID).await.unwrap();
            let wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
            let wiring = wire(&project, root, "six", "1.16.0", &wheel, &"0".repeat(64))
                .await
                .unwrap();
            let entry = entry(UUID, "six", &wheel, &"0".repeat(64), wiring);
            let mut state = VendorState::default();
            state.entries.insert("six".into(), entry.clone());
            save_state(root, &state).await.unwrap();
            let patched = tokio::fs::read_to_string(root.join("pyproject.toml"))
                .await
                .unwrap();
            assert!(patched.contains(&wheel));
            assert!(patched.contains(from), "{patched}");
            tokio::fs::write(root.join("pyproject.toml"), patched.replacen(from, to, 1))
                .await
                .unwrap();
            let outcome = revert(&entry, root, false).await;
            assert!(outcome.success, "{from} -> {to}: {:?}", outcome.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join("pyproject.toml"))
                    .await
                    .unwrap(),
                original.replacen(from, to, 1),
                "{from} -> {to}"
            );
        }
    }

    /// Review on #481: a user-added copy of the vendored requirement (here
    /// with an environment marker) survives the merge as a sibling, so the
    /// revert must refuse rather than delete the wheel it installs from.
    #[tokio::test]
    async fn revert_refuses_while_an_added_line_references_the_artifact() {
        let original =
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        tokio::fs::write(root.join("pyproject.toml"), original)
            .await
            .unwrap();
        let project = load(root, "six", "1.16.0", UUID).await.unwrap();
        let wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wiring = wire(&project, root, "six", "1.16.0", &wheel, &"0".repeat(64))
            .await
            .unwrap();
        let entry = entry(UUID, "six", &wheel, &"0".repeat(64), wiring);
        let patched = tokio::fs::read_to_string(root.join("pyproject.toml"))
            .await
            .unwrap();
        let start = patched.find("\"six @").unwrap();
        let end = start + 1 + patched[start + 1..].find('"').unwrap();
        let requirement = &patched[start + 1..end];
        let edited = patched.replacen(
            "dependencies = [",
            &format!("dependencies = [\"{requirement} ; python_version >= '3.8'\", "),
            1,
        );
        tokio::fs::write(root.join("pyproject.toml"), &edited)
            .await
            .unwrap();
        let outcome = revert(&entry, root, false).await;
        assert!(!outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("still references the vendored artifact"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("pyproject.toml"))
                .await
                .unwrap(),
            edited
        );
    }

    /// An executable `hatch` script in `dir` that touches `marker` and prints
    /// a Hatch version banner that passes the >=1.2 gate.
    #[cfg(unix)]
    fn fake_hatch(dir: &Path, marker: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("hatch");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n: > '{}'\necho 'Hatch, version 1.13.0'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn planted_hatch_in_the_project_is_never_executed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let marker = temp.path().join("PWNED");
        fake_hatch(&root, &marker);
        // `.` and an empty component both resolve against the child's cwd,
        // which is the scanned project.
        for path in [".", "", ":/nonexistent-socket-patch-bin"] {
            let result = require_environment_context_support_with(&root, &|var| {
                (var == "PATH").then(|| path.into())
            })
            .await;
            assert!(!marker.exists(), "planted hatch ran with PATH={path:?}");
            assert_eq!(result.unwrap_err().0, "pypi_hatch_unsupported");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hatch_on_an_absolute_path_entry_passes_the_version_gate() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        let bin = temp.path().join("bin");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let marker = temp.path().join("ran");
        fake_hatch(&bin, &marker);
        let path = std::env::join_paths([bin.as_path()]).unwrap();
        require_environment_context_support_with(&root, &|var| {
            (var == "PATH").then(|| path.clone())
        })
        .await
        .unwrap();
        assert!(marker.exists(), "the resolved hatch was not run");
    }

    /// A `hatch` that never answers is killed at the shared probe budget
    /// and takes the same refusal as one too old.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hung_hatch_is_refused_within_the_probe_budget() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        let bin = temp.path().join("bin");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let hatch = bin.join("hatch");
        std::fs::write(&hatch, "#!/bin/sh\nexec sleep 60\n").unwrap();
        std::fs::set_permissions(&hatch, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([bin.as_path()]).unwrap();
        let start = std::time::Instant::now();
        let result = require_environment_context_support_with(&root, &|var| {
            (var == "PATH").then(|| path.clone())
        })
        .await;
        assert_eq!(result.unwrap_err().0, "pypi_hatch_unsupported");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(40),
            "the probe budget must bound hatch, took {:?}",
            start.elapsed()
        );
    }
}
