use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, first_symlink, read_regular_to_string};
use crate::utils::python_lock::{
    is_python_lock_name, python_lock_paths, rewrite_python_lock, script_of_lock, ArtifactSource,
};
use crate::utils::python_script::{
    replace_script_metadata, rewrite_script_metadata, script_metadata,
};

use super::common::record;
use super::parse_memo::ParseMemo;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorWarning};

const KIND: &str = "python_lock_document";
const SCRIPT_KIND: &str = "python_script_metadata";
type Failure = (&'static str, String);

struct LockFile {
    name: String,
    text: String,
    script: Option<String>,
}

pub(super) struct PythonLocks {
    files: Vec<LockFile>,
    pub in_sync: bool,
    pub pin: Option<(String, String)>,
}

/// FIFO-safe read that FOLLOWS a symlink to a regular file. Discovery
/// (`python_lock_paths`) follows links too, so a shared `pylock.dev.toml`
/// link beside a regular `pylock.toml` reads like the file it points at —
/// an lstat-based "is this a regular file" pre-check here rejected the
/// link, and because `contains_target`/`load_python_locks` bubble the FIRST
/// unreadable sibling, one stray link blocked vendoring of the whole
/// project. Whether a linked file may be WRITTEN is a separate question,
/// answered by [`refuse_symlinked`] right before the writers run.
async fn read_file(path: &Path) -> Result<String, Failure> {
    read_regular_to_string(path).await.map_err(|error| {
        (
            "pypi_lock_read_failed",
            if error.kind() == std::io::ErrorKind::InvalidInput {
                error.to_string()
            } else {
                format!("cannot read {}: {error}", path.display())
            },
        )
    })
}

/// Every writer here stages a replacement next to `file` and renames over
/// it, which REPLACES a symlink with a regular file: the link target goes
/// stale (uv itself writes through the link), and a later revert restores
/// bytes but never the link (git shows a 120000→100644 typechange). Refuse
/// before the first write instead — same fail-closed policy as the hosted
/// replay flush guard.
fn symlink_refusal(file: &str) -> String {
    format!(
        "{file} is a symbolic link; socket-patch rewrites files in place with an atomic \
         rename, which would replace the link — replace the link with a regular file (or \
         run socket-patch in the directory it points to) and re-run"
    )
}

async fn refuse_symlinked(root: &Path, files: impl Iterator<Item = &String>) -> Option<String> {
    first_symlink(root, files.map(String::as_str))
        .await
        .map(symlink_refusal)
}

/// The run's PEP 751 / script-lock parses. Both readers below re-read AND
/// re-parsed every one of the project's locks for every patched package;
/// the lock set is small but the documents are not. Four slots so a project
/// with a handful of locks does not evict its own parses between packages;
/// see [`ParseMemo`].
static LOCK_MEMO: ParseMemo<DocumentMut, 4> = ParseMemo::new();

/// `text` parsed as a python lockfile, reusing the run's parse while it is
/// the text that produced it.
fn lock_document(text: &str) -> Result<Arc<DocumentMut>, toml_edit::TomlError> {
    LOCK_MEMO.parse(text.as_bytes(), || text.parse::<DocumentMut>())
}

fn package<'a>(document: &'a DocumentMut, name: &str, version: &str) -> Option<&'a Table> {
    let collection = if document.contains_key("lock-version") {
        "packages"
    } else {
        "package"
    };
    document
        .get(collection)?
        .as_array_of_tables()?
        .iter()
        .find(|table| {
            table
                .get("name")
                .and_then(Item::as_str)
                .is_some_and(|value| canonicalize_pypi_name(value) == name)
                && table.get("version").and_then(Item::as_str) == Some(version)
        })
}

fn source_path(table: &Table) -> Option<&str> {
    table
        .get("archive")
        .or_else(|| table.get("source"))?
        .as_table_like()?
        .get("path")?
        .as_str()
}

fn source_sha(table: &Table) -> Option<String> {
    if let Some(sha) = table
        .get("archive")
        .and_then(Item::as_table_like)
        .and_then(|archive| archive.get("hashes"))
        .and_then(Item::as_table_like)
        .and_then(|hashes| hashes.get("sha256"))
        .and_then(Item::as_str)
    {
        return Some(sha.to_string());
    }
    table.get("wheels")?.as_array()?.iter().find_map(|wheel| {
        wheel
            .as_inline_table()?
            .get("hash")?
            .as_str()?
            .strip_prefix("sha256:")
            .map(str::to_string)
    })
}

pub(super) async fn contains_target(
    root: &Path,
    paths: &[String],
    name: &str,
    version: &str,
) -> Result<bool, Failure> {
    for path in paths {
        let text = read_file(&root.join(path)).await?;
        let document = lock_document(&text)
            .map_err(|error| ("pypi_lock_parse_failed", format!("{path}: {error}")))?;
        if package(&document, name, version).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) async fn load_python_locks(
    root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
) -> Result<PythonLocks, Failure> {
    let paths =
        python_lock_paths(root).map_err(|error| ("pypi_lock_read_failed", error.to_string()))?;
    let directory = format!(".socket/vendor/pypi/{uuid}/");
    let placeholder = format!("{directory}{name}-{version}-py3-none-any.whl");
    let mut files = Vec::new();
    let mut in_sync = true;
    let mut pin = None;
    for path in paths.into_iter().filter(|path| path != "uv.lock") {
        let text = read_file(&root.join(&path)).await?;
        let rewritten = rewrite_python_lock(
            &text,
            name,
            version,
            ArtifactSource::Path(&placeholder),
            &"0".repeat(64),
        )
        .map_err(|error| ("pypi_lock_unsupported", format!("{path}: {error}")))?;
        if rewritten.is_none() {
            continue;
        }
        let document = lock_document(&text)
            .map_err(|error| ("pypi_lock_parse_failed", format!("{path}: {error}")))?;
        let Some(package) = package(&document, name, version) else {
            continue;
        };
        if let Some(path) = source_path(package) {
            let path = path.trim_start_matches("./");
            if !path.starts_with(&directory) {
                return Err(("pypi_lock_source_already_exists", format!("{name} already uses {path}; run vendor --revert before changing its source")));
            }
            let sha = source_sha(package)
                .filter(|sha| sha.len() == 64 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .ok_or_else(|| {
                    (
                        "pypi_lock_missing_hash",
                        format!("{path} has no vendored wheel hash"),
                    )
                })?;
            let candidate = (path.to_string(), sha);
            if pin.as_ref().is_some_and(|pin| pin != &candidate) {
                return Err((
                    "pypi_lock_conflicting_pins",
                    format!("lockfiles disagree on the vendored artifact for {name}"),
                ));
            }
            pin = Some(candidate);
        } else {
            in_sync = false;
        }
        let script = if let Some(script_name) = script_of_lock(&path) {
            if document
                .get("package")
                .and_then(Item::as_array_of_tables)
                .is_some_and(|packages| {
                    packages
                        .iter()
                        .filter(|package| {
                            package
                                .get("name")
                                .and_then(Item::as_str)
                                .is_some_and(|value| canonicalize_pypi_name(value) == name)
                        })
                        .count()
                        > 1
                })
            {
                return Err(("pypi_script_multiple_versions", format!("{path} resolves multiple versions of {name}; a script source override cannot select only {version}")));
            }
            let script = read_file(&root.join(script_name)).await?;
            let script_wheel = source_path(package).unwrap_or(&placeholder);
            if rewrite_script_metadata(&script, name, version, ArtifactSource::Path(script_wheel))
                .map_err(|error| {
                    (
                        "pypi_script_metadata_invalid",
                        format!("{script_name}: {error}"),
                    )
                })?
                .is_some()
            {
                in_sync = false;
            }
            Some(script)
        } else {
            None
        };
        files.push(LockFile {
            name: path,
            text,
            script,
        });
    }
    if files.is_empty() {
        return Err((
            "pypi_lock_package_missing",
            format!("no supported script lock or PEP 751 lockfile contains {name}@{version}"),
        ));
    }
    Ok(PythonLocks {
        files,
        in_sync,
        pin,
    })
}

pub(super) async fn wire_python_locks(
    project: &PythonLocks,
    root: &Path,
    name: &str,
    version: &str,
    wheel: &str,
    sha: &str,
) -> Result<Vec<WiringRecord>, Failure> {
    let mut edits = Vec::new();
    for file in &project.files {
        let Some(mut rewritten) =
            rewrite_python_lock(&file.text, name, version, ArtifactSource::Path(wheel), sha)
                .map_err(|error| ("pypi_lock_unsupported", error))?
        else {
            continue;
        };
        if let Some(script) = &file.script {
            let script_name = script_of_lock(&file.name).expect("script lock name");
            if let Some(script_output) =
                rewrite_script_metadata(script, name, version, ArtifactSource::Path(wheel))
                    .map_err(|error| ("pypi_script_metadata_invalid", error))?
            {
                edits.push((
                    script_name.to_string(),
                    script.clone(),
                    script_output,
                    SCRIPT_KIND,
                ));
            }
            if let Some(metadata) = super::pypi_uv::wheel_metadata_block(&root.join(wheel)).await {
                let metadata = metadata
                    .strip_prefix("[package.metadata]\n")
                    .unwrap_or(&metadata);
                let metadata: DocumentMut = metadata.parse().map_err(|error| {
                    ("pypi_lock_parse_failed", format!("wheel metadata: {error}"))
                })?;
                let mut document: DocumentMut = rewritten.parse().map_err(|error| {
                    ("pypi_lock_parse_failed", format!("rewritten lock: {error}"))
                })?;
                if let Some(packages) = document
                    .get_mut("package")
                    .and_then(Item::as_array_of_tables_mut)
                {
                    for package in packages.iter_mut() {
                        if package.get("name").and_then(Item::as_str) == Some(name)
                            && package.get("version").and_then(Item::as_str) == Some(version)
                        {
                            let mut metadata = metadata.as_table().clone();
                            metadata.set_position(None);
                            package.insert("metadata", Item::Table(metadata));
                        }
                    }
                }
                rewritten = crate::utils::python_lock::preserve_line_endings(
                    &file.text,
                    document.to_string(),
                );
            }
        }
        if rewritten != file.text {
            edits.push((file.name.clone(), file.text.clone(), rewritten, KIND));
        }
    }
    if let Some(detail) = refuse_symlinked(root, edits.iter().map(|(file, ..)| file)).await {
        return Err(("pypi_lock_symlink_unsupported", detail));
    }
    for (file, original, _, _) in &edits {
        if read_file(&root.join(file)).await? != *original {
            return Err((
                "pypi_lock_changed",
                format!("{file} changed during vendoring"),
            ));
        }
    }
    let mut written: Vec<(&String, &String)> = Vec::new();
    for (file, original, new, _) in &edits {
        LOCK_MEMO.invalidate();
        if let Err(error) =
            atomic_write_bytes_preserving_mode(&root.join(file), new.as_bytes()).await
        {
            let mut rollback_errors = Vec::new();
            for (file, original) in written.into_iter().rev() {
                LOCK_MEMO.invalidate();
                if let Err(error) =
                    atomic_write_bytes_preserving_mode(&root.join(file), original.as_bytes()).await
                {
                    rollback_errors.push(format!("{file}: {error}"));
                }
            }
            return Err((
                "pypi_lock_write_failed",
                format!(
                    "cannot write {file}: {error}; rollback errors: {}",
                    rollback_errors.join(", ")
                ),
            ));
        }
        written.push((file, original));
    }
    Ok(edits
        .into_iter()
        .map(|(file, original, new, kind)| {
            record(
                &file,
                kind,
                WiringAction::Rewritten,
                name,
                Some(original),
                new,
            )
        })
        .collect())
}

fn item_text(item: &Item) -> String {
    let mut document = DocumentMut::new();
    document.insert("item", item.clone());
    document.to_string()
}

fn equal_item(left: Option<&Item>, right: Option<&Item>) -> bool {
    left.map(item_text) == right.map(item_text)
}

fn same_identity(live: &dyn TableLike, expected: &dyn TableLike) -> bool {
    ["name", "version"]
        .iter()
        .all(|key| equal_item(live.get(key), expected.get(key)))
}

fn restore_table(live: &mut dyn TableLike, original: &dyn TableLike, new: &dyn TableLike) -> bool {
    let keys: BTreeSet<String> = original
        .iter()
        .chain(new.iter())
        .map(|(key, _)| key.to_string())
        .collect();
    let mut drifted = false;
    for key in keys {
        let before = original.get(&key);
        let after = new.get(&key);
        if equal_item(before, after) || equal_item(live.get(&key), before) {
            continue;
        }
        if equal_item(live.get(&key), after) {
            if let Some(before) = before {
                live.insert(&key, before.clone());
            } else {
                live.remove(&key);
            }
            continue;
        }
        let Some(current) = live.get_mut(&key) else {
            drifted = true;
            continue;
        };
        match (before, after) {
            (Some(before), Some(after)) => drifted |= restore_item(current, before, after),
            (None, Some(after)) if current.is_table_like() && after.is_table_like() => {
                let empty = Item::Table(Table::new());
                drifted |= restore_item(current, &empty, after);
                if current
                    .as_table_like()
                    .is_some_and(|table| table.is_empty())
                {
                    live.remove(&key);
                }
            }
            _ => drifted = true,
        }
    }
    drifted
}

fn restore_value(live: &mut Value, original: &Value, new: &Value) -> bool {
    if original.to_string() == new.to_string() || live.to_string() == original.to_string() {
        return false;
    }
    if live.to_string() == new.to_string() {
        *live = original.clone();
        return false;
    }
    if let (Some(live), Some(original), Some(new)) = (
        live.as_inline_table_mut(),
        original.as_inline_table(),
        new.as_inline_table(),
    ) {
        if !same_identity(live, new) {
            return true;
        }
        return restore_table(live, original, new);
    }
    if let (Some(live), Some(original), Some(new)) =
        (live.as_array_mut(), original.as_array(), new.as_array())
    {
        if live.len() != new.len() || original.len() != new.len() {
            return true;
        }
        let mut drifted = false;
        for ((live, original), new) in live.iter_mut().zip(original.iter()).zip(new.iter()) {
            drifted |= restore_value(live, original, new);
        }
        return drifted;
    }
    true
}

fn restore_item(live: &mut Item, original: &Item, new: &Item) -> bool {
    if item_text(original) == item_text(new) || item_text(live) == item_text(original) {
        return false;
    }
    if item_text(live) == item_text(new) {
        *live = original.clone();
        return false;
    }
    if let (Some(live), Some(original), Some(new)) = (
        live.as_table_like_mut(),
        original.as_table_like(),
        new.as_table_like(),
    ) {
        if !same_identity(live, new) {
            return true;
        }
        return restore_table(live, original, new);
    }
    if let (Some(live), Some(original), Some(new)) = (
        live.as_array_of_tables_mut(),
        original.as_array_of_tables(),
        new.as_array_of_tables(),
    ) {
        if live.len() != new.len() || original.len() != new.len() {
            return true;
        }
        let mut drifted = false;
        for ((live, original), new) in live.iter_mut().zip(original.iter()).zip(new.iter()) {
            if same_identity(live, new) {
                drifted |= restore_table(live, original, new);
            } else {
                drifted = true;
            }
        }
        return drifted;
    }
    if let (Some(live), Some(original), Some(new)) =
        (live.as_value_mut(), original.as_value(), new.as_value())
    {
        return restore_value(live, original, new);
    }
    true
}

pub(crate) fn restore_document(
    live: &str,
    original: &str,
    new: &str,
) -> Result<(String, bool), String> {
    if live == new || live == original {
        return Ok((original.to_string(), false));
    }
    let current_text = live.to_string();
    let mut live: DocumentMut = live
        .parse()
        .map_err(|error| format!("invalid live TOML: {error}"))?;
    let original: DocumentMut = original
        .parse()
        .map_err(|error| format!("invalid original TOML: {error}"))?;
    let new: DocumentMut = new
        .parse()
        .map_err(|error| format!("invalid vendored TOML: {error}"))?;
    let drifted = restore_item(live.as_item_mut(), original.as_item(), new.as_item());
    Ok((
        if drifted {
            current_text
        } else {
            crate::utils::python_lock::preserve_line_endings(&current_text, live.to_string())
        },
        drifted,
    ))
}

fn allowed_file(file: &str, kind: &str) -> bool {
    Path::new(file).file_name().and_then(|name| name.to_str()) == Some(file)
        && ((kind == KIND && is_python_lock_name(file) && file != "uv.lock")
            || (kind == SCRIPT_KIND && file.ends_with(".py")))
}

pub(super) async fn revert_python_locks(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    let mut warnings = Vec::new();
    let mut edits = Vec::new();
    for record in entry.wiring.iter().rev() {
        if !allowed_file(&record.file, &record.kind) {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "unexpected Python wiring file or kind: {} ({})",
                    record.file, record.kind
                ),
            ));
            continue;
        }
        let (Some(original), Some(new)) = (
            record.original.as_ref().and_then(serde_json::Value::as_str),
            record.new.as_ref().and_then(serde_json::Value::as_str),
        ) else {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("{} has no recorded original", record.file),
            ));
            continue;
        };
        let live = match read_file(&root.join(&record.file)).await {
            Ok(live) => live,
            Err((_, error)) => return RevertOutcome::failed(error),
        };
        let restored = if record.kind == SCRIPT_KIND {
            (|| {
                if live == new || live == original {
                    return Ok((original.to_string(), false));
                }
                let (_, live_metadata) = script_metadata(&live)?;
                let (_, original_metadata) = script_metadata(original)?;
                let (_, new_metadata) = script_metadata(new)?;
                let (restored, drifted) =
                    restore_document(&live_metadata, &original_metadata, &new_metadata)?;
                Ok((replace_script_metadata(&live, &restored)?, drifted))
            })()
        } else {
            restore_document(&live, original, new)
        };
        let (restored, drifted) = match restored {
            Ok(result) => result,
            Err(error) => return RevertOutcome::failed(error),
        };
        if drifted {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} changed since vendoring; conflicting fields were preserved",
                    record.file
                ),
            ));
        }
        if restored != live {
            edits.push((record.file.clone(), live, restored));
        }
    }
    if !dry_run && warnings.is_empty() {
        // A refused write fails the revert outright: the artifact and the
        // ledger entry stay so the restore can be retried once the link is
        // a regular file again.
        if let Some(detail) = refuse_symlinked(root, edits.iter().map(|(file, ..)| file)).await {
            return RevertOutcome::failed(detail);
        }
        for (file, original, _) in &edits {
            match read_file(&root.join(file)).await {
                Ok(live) if live == *original => {}
                Ok(_) => return RevertOutcome::failed(format!("{file} changed during revert")),
                Err((_, error)) => return RevertOutcome::failed(error),
            }
        }
        let mut written: Vec<(&String, &String)> = Vec::new();
        for (file, original, restored) in &edits {
            LOCK_MEMO.invalidate();
            if let Err(error) =
                atomic_write_bytes_preserving_mode(&root.join(file), restored.as_bytes()).await
            {
                let mut rollback_errors = Vec::new();
                for (file, original) in written.into_iter().rev() {
                    LOCK_MEMO.invalidate();
                    if let Err(error) =
                        atomic_write_bytes_preserving_mode(&root.join(file), original.as_bytes())
                            .await
                    {
                        rollback_errors.push(format!("{file}: {error}"));
                    }
                }
                return RevertOutcome::failed(format!(
                    "cannot restore {file}: {error}; rollback errors: {}",
                    rollback_errors.join(", ")
                ));
            }
            written.push((file, original));
        }
    }
    RevertOutcome {
        success: true,
        warnings,
        error: None,
        kept_artifact: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "# original\nlock-version = \"1.0\"\n\n[[packages]]\nname = \"one\"\nversion = \"1\"\nwheels = [{url = \"https://example.test/one.whl\", hashes = {sha256 = \"one\"}}]\n\n[[packages]]\nname = \"two\"\nversion = \"2\"\nwheels = [{url = \"https://example.test/two.whl\", hashes = {sha256 = \"two\"}}]\n";

    #[tokio::test]
    async fn script_wheel_metadata_stays_with_its_package() {
        let temp = tempfile::tempdir().unwrap();
        let lock = "version = 1\n[[package]]\nname = \"one\"\nversion = \"1\"\nsource = {registry = \"https://pypi.org/simple\"}\n[[package]]\nname = \"two\"\nversion = \"2\"\nsource = {registry = \"https://pypi.org/simple\"}\n";
        let script = "# /// script\n# dependencies = [\"two==2\"]\n# ///\n";
        tokio::fs::write(temp.path().join("job.py.lock"), lock)
            .await
            .unwrap();
        tokio::fs::write(temp.path().join("job.py"), script)
            .await
            .unwrap();
        let bytes = super::super::common::write_zip_entries(&[(
            "two-2.dist-info/METADATA".to_string(),
            b"Metadata-Version: 2.1\nName: two\nVersion: 2\nRequires-Dist: one>=1\n".to_vec(),
            0o644,
        )])
        .unwrap();
        tokio::fs::write(temp.path().join("two-2-py3-none-any.whl"), bytes)
            .await
            .unwrap();
        let project = load_python_locks(
            temp.path(),
            "two",
            "2",
            "11111111-1111-4111-8111-111111111111",
        )
        .await
        .unwrap();
        wire_python_locks(
            &project,
            temp.path(),
            "two",
            "2",
            "two-2-py3-none-any.whl",
            &"a".repeat(64),
        )
        .await
        .unwrap();
        let output = tokio::fs::read_to_string(temp.path().join("job.py.lock"))
            .await
            .unwrap();
        let document: DocumentMut = output.parse().unwrap();
        let packages = document["package"].as_array_of_tables().unwrap();
        assert!(packages.get(0).unwrap().get("metadata").is_none());
        assert_eq!(
            packages.get(1).unwrap()["metadata"]["requires-dist"][0]["name"].as_str(),
            Some("one")
        );
        assert_eq!(
            packages.get(1).unwrap()["metadata"]["requires-dist"][0]["specifier"].as_str(),
            Some(">=1")
        );
    }

    #[tokio::test]
    async fn script_global_sources_cannot_replace_multiple_versions() {
        let temp = tempfile::tempdir().unwrap();
        let lock = "version = 1\n[[package]]\nname = \"one\"\nversion = \"1\"\nsource = {registry = \"https://pypi.org/simple\"}\n[[package]]\nname = \"one\"\nversion = \"2\"\nsource = {registry = \"https://pypi.org/simple\"}\n";
        tokio::fs::write(temp.path().join("job.py.lock"), lock)
            .await
            .unwrap();
        tokio::fs::write(
            temp.path().join("job.py"),
            "# /// script\n# dependencies = [\"one\"]\n# ///\n",
        )
        .await
        .unwrap();
        let result = load_python_locks(
            temp.path(),
            "one",
            "1",
            "11111111-1111-4111-8111-111111111111",
        )
        .await;
        assert!(matches!(result, Err(("pypi_script_multiple_versions", _))));
        assert_eq!(
            tokio::fs::read_to_string(temp.path().join("job.py.lock"))
                .await
                .unwrap(),
            lock
        );
        assert!(!temp.path().join(".socket").exists());
    }

    #[test]
    fn separate_package_reverts_do_not_depend_on_order() {
        let first = rewrite_python_lock(
            LOCK,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        let both = rewrite_python_lock(
            &first,
            "two",
            "2",
            ArtifactSource::Path(".socket/vendor/two-2-py3-none-any.whl"),
            "second",
        )
        .unwrap()
        .unwrap();
        let (second_only, drifted) = restore_document(&both, LOCK, &first).unwrap();
        assert!(!drifted);
        assert!(second_only.contains("https://example.test/one.whl"));
        assert!(second_only.contains(".socket/vendor/two-2-py3-none-any.whl"));
        let (restored, drifted) = restore_document(&second_only, &first, &both).unwrap();
        assert!(!drifted);
        assert_eq!(restored, LOCK);
    }

    #[test]
    fn script_sources_revert_out_of_order_without_empty_tables() {
        for suffix in ["", "\n[tool.uv.sources]\n"] {
            let metadata = format!("dependencies = [\"one==1\", \"two==2\"]\n{suffix}");
            let script =
                replace_script_metadata("# /// script\n# ///\nprint('unchanged')\n", &metadata)
                    .unwrap();
            let first = rewrite_script_metadata(
                &script,
                "one",
                "1",
                ArtifactSource::Path(".socket/vendor/one.whl"),
            )
            .unwrap()
            .unwrap();
            let both = rewrite_script_metadata(
                &first,
                "two",
                "2",
                ArtifactSource::Path(".socket/vendor/two.whl"),
            )
            .unwrap()
            .unwrap();
            let (_, first_metadata) = script_metadata(&first).unwrap();
            let (_, both_metadata) = script_metadata(&both).unwrap();
            let (second_only, drifted) =
                restore_document(&both_metadata, &metadata, &first_metadata).unwrap();
            assert!(!drifted);
            let (restored, drifted) =
                restore_document(&second_only, &first_metadata, &both_metadata).unwrap();
            assert!(!drifted);
            assert_eq!(restored, metadata);
        }
    }

    #[test]
    fn conflicting_fields_are_preserved_and_reported() {
        let patched = rewrite_python_lock(
            LOCK,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        let edited = patched.replace(
            ".socket/vendor/one-1-py3-none-any.whl",
            "user/one-1-py3-none-any.whl",
        );
        let (restored, drifted) = restore_document(&edited, LOCK, &patched).unwrap();
        assert!(drifted);
        assert_eq!(restored, edited);
    }

    #[test]
    fn reordered_packages_cannot_receive_another_packages_original() {
        let patched = rewrite_python_lock(
            LOCK,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        let edited = patched.replace("name = \"one\"", "name = \"other\"");
        let (restored, drifted) = restore_document(&edited, LOCK, &patched).unwrap();
        assert!(drifted);
        assert_eq!(restored, edited);
    }

    #[test]
    fn recorded_files_cannot_escape_the_project() {
        for file in [
            "../pylock.toml",
            "/tmp/pylock.toml",
            "nested/pylock.toml",
            "uv.lock",
        ] {
            assert!(!allowed_file(file, KIND));
        }
        assert!(allowed_file("pylock.toml", KIND));
        assert!(allowed_file("job.py.lock", KIND));
        assert!(allowed_file("job.py", SCRIPT_KIND));
        assert!(!allowed_file("../job.py", SCRIPT_KIND));
    }

    /// The two-package PEP 751 document with every newline CRLF.
    fn crlf(text: &str) -> String {
        text.replace('\n', "\r\n")
    }

    const UUID: &str = "11111111-1111-4111-8111-111111111111";

    /// `pylock.toml` locking `one` and `two` upstream, plus the second copy a
    /// sibling symlink points at.
    async fn write_pylock(root: &Path, name: &str, text: &str) {
        tokio::fs::write(root.join(name), text).await.unwrap();
    }

    /// A stray `pylock.dev.toml` SYMLINK (pointing at a lock that does not
    /// contain the target) beside a REGULAR `pylock.toml` that does. On main
    /// the symlink was invisible (`python_lock_paths` skipped links); since
    /// discovery started following links, `read_file`'s
    /// `symlink_metadata().is_file()` pre-check rejected it with
    /// `pypi_lock_read_failed`, and because `contains_target` /
    /// `load_python_locks` bubble the FIRST unreadable sibling, the stray link
    /// blocked vendoring of the whole project. A link to a regular file must
    /// read like the file (`open_regular_file`'s fstat already accepts it).
    #[cfg(unix)]
    #[tokio::test]
    async fn stray_sibling_symlink_does_not_block_regular_pylock() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_pylock(root, "pylock.toml", LOCK).await;
        let other = "lock-version = \"1.0\"\n\n[[packages]]\nname = \"other\"\nversion = \"9\"\nwheels = [{url = \"https://example.test/other.whl\", hashes = {sha256 = \"other\"}}]\n";
        std::fs::create_dir_all(root.join("shared")).unwrap();
        write_pylock(root, "shared/pylock.dev.toml", other).await;
        std::os::unix::fs::symlink("shared/pylock.dev.toml", root.join("pylock.dev.toml")).unwrap();

        let paths = python_lock_paths(root).unwrap();
        assert_eq!(
            paths,
            vec!["pylock.dev.toml".to_string(), "pylock.toml".to_string()],
            "discovery must still FOLLOW the link (a shared pylock is a real project file)"
        );
        assert_eq!(
            contains_target(root, &paths, "one", "1").await,
            Ok(true),
            "a readable non-referencing sibling link must not fail the routing probe"
        );
        assert_eq!(
            contains_target(root, &paths, "other", "9").await,
            Ok(true),
            "the link itself reads like the file it points at"
        );
        let project = load_python_locks(root, "one", "1", UUID).await.unwrap();
        assert!(!project.in_sync);
        let records = wire_python_locks(
            &project,
            root,
            "one",
            "1",
            ".socket/vendor/pypi/11111111-1111-4111-8111-111111111111/one-1-py3-none-any.whl",
            &"a".repeat(64),
        )
        .await
        .unwrap();
        assert_eq!(
            records.iter().map(|r| r.file.as_str()).collect::<Vec<_>>(),
            vec!["pylock.toml"],
            "only the regular lock that contains the target is wired"
        );
        assert!(std::fs::read_to_string(root.join("pylock.toml"))
            .unwrap()
            .contains("one-1-py3-none-any.whl"));
        assert!(
            std::fs::symlink_metadata(root.join("pylock.dev.toml"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the stray link is left alone"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("shared/pylock.dev.toml")).unwrap(),
            other
        );
    }

    /// A DANGLING sibling link is not a lock: discovery's `fs::metadata`
    /// follow fails, so the name is skipped and the regular lock beside it
    /// routes/wires as if the link were absent.
    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_sibling_symlink_is_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_pylock(root, "pylock.toml", LOCK).await;
        std::os::unix::fs::symlink("missing/pylock.dev.toml", root.join("pylock.dev.toml"))
            .unwrap();

        let paths = python_lock_paths(root).unwrap();
        assert_eq!(paths, vec!["pylock.toml".to_string()]);
        assert_eq!(contains_target(root, &paths, "one", "1").await, Ok(true));
        let project = load_python_locks(root, "one", "1", UUID).await.unwrap();
        assert_eq!(project.files.len(), 1);
        // Reading the dangling name directly still fails as unreadable — the
        // filter lives in discovery, not in a swallowed read error.
        assert!(matches!(
            read_file(&root.join("pylock.dev.toml")).await,
            Err(("pypi_lock_read_failed", _))
        ));
    }

    fn symlink_refusal_names(result: &Result<Vec<WiringRecord>, Failure>, file: &str) {
        match result {
            Err((code, detail)) => {
                assert_eq!(*code, "pypi_lock_symlink_unsupported", "{detail}");
                assert!(
                    detail.starts_with(&format!("{file} is a symbolic link")),
                    "the refusal must name the linked file: {detail}"
                );
                assert!(detail.contains("atomic rename"), "{detail}");
                assert!(detail.contains("re-run"), "{detail}");
            }
            Ok(records) => panic!("must refuse before writing, wired {records:?}"),
        }
    }

    /// The lock the wiring is about to rewrite is a symlink. Every writer
    /// here stages next to the path and renames over it, which REPLACES the
    /// link with a regular file (the target goes stale, rollback restores
    /// bytes but never the link — git shows a 120000→100644 typechange). The
    /// hosted replay side already refuses such a flush; the vendored write
    /// side must refuse BEFORE touching anything, with a stable code naming
    /// the file.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_target_lock_refused_before_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("shared")).unwrap();
        write_pylock(root, "shared/pylock.toml", LOCK).await;
        std::os::unix::fs::symlink("shared/pylock.toml", root.join("pylock.toml")).unwrap();

        let project = load_python_locks(root, "one", "1", UUID).await.unwrap();
        let result = wire_python_locks(
            &project,
            root,
            "one",
            "1",
            ".socket/vendor/pypi/11111111-1111-4111-8111-111111111111/one-1-py3-none-any.whl",
            &"a".repeat(64),
        )
        .await;
        symlink_refusal_names(&result, "pylock.toml");
        assert!(
            std::fs::symlink_metadata(root.join("pylock.toml"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive: a rename-over would have turned it into a regular file"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("shared/pylock.toml")).unwrap(),
            LOCK,
            "the link target must stay byte-identical"
        );
        assert!(!root.join(".socket").exists());
    }

    /// The paired PEP 723 script is the symlink (its `.py.lock` is regular):
    /// the script's `[tool.uv.sources]` rewrite goes through the same
    /// rename-over writer, so the refusal must cover it too and name the
    /// SCRIPT, not the lock.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_paired_script_refused_before_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let lock = "version = 1\n[[package]]\nname = \"one\"\nversion = \"1\"\nsource = {registry = \"https://pypi.org/simple\"}\n";
        let script = "# /// script\n# dependencies = [\"one==1\"]\n# ///\nprint('hi')\n";
        write_pylock(root, "example.py.lock", lock).await;
        std::fs::create_dir_all(root.join("shared")).unwrap();
        tokio::fs::write(root.join("shared/example.py"), script)
            .await
            .unwrap();
        std::os::unix::fs::symlink("shared/example.py", root.join("example.py")).unwrap();

        let project = load_python_locks(root, "one", "1", UUID).await.unwrap();
        let result = wire_python_locks(
            &project,
            root,
            "one",
            "1",
            "one-1-py3-none-any.whl",
            &"a".repeat(64),
        )
        .await;
        symlink_refusal_names(&result, "example.py");
        assert!(std::fs::symlink_metadata(root.join("example.py"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(root.join("shared/example.py")).unwrap(),
            script
        );
        assert_eq!(
            std::fs::read_to_string(root.join("example.py.lock")).unwrap(),
            lock,
            "the regular lock must not be written when its paired script is refused"
        );
    }

    /// Revert twin: the lock was wired as a regular file, then the checkout
    /// restored the committed SYMLINK (git typechange back) pointing at a copy
    /// carrying the vendored bytes. `read_file` follows the link fine, so the
    /// restore plan is computable — but writing it would replace the link.
    /// The revert must FAIL (artifact + ledger entry kept, nothing written).
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_refuses_symlinked_lock_and_keeps_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_pylock(root, "pylock.toml", LOCK).await;
        let project = load_python_locks(root, "one", "1", UUID).await.unwrap();
        let wheel =
            ".socket/vendor/pypi/11111111-1111-4111-8111-111111111111/one-1-py3-none-any.whl";
        let records = wire_python_locks(&project, root, "one", "1", wheel, &"a".repeat(64))
            .await
            .unwrap();
        let vendored = std::fs::read_to_string(root.join("pylock.toml")).unwrap();
        assert_ne!(vendored, LOCK);
        let entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/one@1",
            "uuid": UUID,
            "artifact": { "path": wheel, "sha256": "a".repeat(64) },
            "wiring": serde_json::to_value(&records).unwrap(),
            "flavor": "python-lock",
        }))
        .unwrap();

        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::rename(root.join("pylock.toml"), root.join("shared/pylock.toml")).unwrap();
        std::os::unix::fs::symlink("shared/pylock.toml", root.join("pylock.toml")).unwrap();

        let outcome = revert_python_locks(&entry, root, false).await;
        assert!(!outcome.success, "{outcome:?}");
        let error = outcome.error.expect("a failed revert carries its reason");
        assert!(
            error.starts_with("pylock.toml is a symbolic link"),
            "the failure must name the linked file: {error}"
        );
        assert!(error.contains("atomic rename"), "{error}");
        assert!(
            std::fs::symlink_metadata(root.join("pylock.toml"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive the refused revert"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("shared/pylock.toml")).unwrap(),
            vendored,
            "the target keeps the vendored bytes: nothing was restored through the link"
        );
        // Dry runs plan only — they never reach the writer, so the link is no
        // obstacle and the plan reports a clean restore.
        let dry = revert_python_locks(&entry, root, true).await;
        assert!(dry.success && dry.warnings.is_empty(), "{dry:?}");
    }

    /// `restore_document`'s post-restore `preserve_line_endings`: the ledger
    /// recorded LF `original`/`new`, but the live file is the vendored text
    /// checked out under autocrlf (every newline CRLF). `live != new`
    /// byte-wise, so this takes the structural path (not the `live == new`
    /// short-circuit) and must converge on the ORIGINAL in the live file's
    /// CRLF convention with no drift.
    #[test]
    fn restore_document_converges_lf_ledger_crlf_live() {
        let new = rewrite_python_lock(
            LOCK,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        let live = crlf(&new);
        assert_ne!(live, new, "the CRLF live text must not short-circuit");
        let (restored, drifted) = restore_document(&live, LOCK, &new).unwrap();
        assert!(!drifted, "a pure line-ending difference is not drift");
        assert_eq!(restored, crlf(LOCK));
    }

    /// The mirror: CRLF-recorded `original`/`new` (vendored on Windows), live
    /// file normalized to LF by a later checkout. Converges on the original
    /// content in LF.
    #[test]
    fn restore_document_converges_crlf_ledger_lf_live() {
        let original = crlf(LOCK);
        let new = rewrite_python_lock(
            &original,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        assert!(
            new.contains("\r\n"),
            "the rewriter keeps the CRLF convention"
        );
        let live = new.replace("\r\n", "\n");
        let (restored, drifted) = restore_document(&live, &original, &new).unwrap();
        assert!(!drifted);
        assert_eq!(restored, LOCK);
    }

    /// Two packages vendored in sequence under CRLF and reverted OUT of
    /// order (`one` first, while `two`'s edit is still live). The
    /// single-package pure-CRLF revert short-circuits at `live == new`, so
    /// only this shape exercises the structural restore + line-ending
    /// re-application on a CRLF document — both steps must converge without
    /// drift and the final text must be the CRLF original.
    #[test]
    fn crlf_two_package_reverts_converge_out_of_order() {
        let original = crlf(LOCK);
        let first = rewrite_python_lock(
            &original,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one-1-py3-none-any.whl"),
            "first",
        )
        .unwrap()
        .unwrap();
        let both = rewrite_python_lock(
            &first,
            "two",
            "2",
            ArtifactSource::Path(".socket/vendor/two-2-py3-none-any.whl"),
            "second",
        )
        .unwrap()
        .unwrap();
        assert!(both.contains("\r\n") && !both.replace("\r\n", "").contains('\n'));
        let (second_only, drifted) = restore_document(&both, &original, &first).unwrap();
        assert!(!drifted);
        assert!(second_only.contains("https://example.test/one.whl"));
        assert!(second_only.contains(".socket/vendor/two-2-py3-none-any.whl"));
        assert!(
            !second_only.replace("\r\n", "").contains('\n'),
            "the intermediate document keeps CRLF throughout: {second_only:?}"
        );
        let (restored, drifted) = restore_document(&second_only, &first, &both).unwrap();
        assert!(!drifted);
        assert_eq!(restored, original);
    }

    /// KNOWN LIMITATION (documented, not fixed here): two TRANSITIVE deps
    /// vendored into one PEP 723 script share the `[tool.uv]
    /// override-dependencies` ARRAY. Reverting the OLDER one first (`one`,
    /// while `two`'s override is still live) cannot be expressed by
    /// `restore_value`: the array grew from absent → 1 → 2 entries, the live
    /// 2-entry array matches neither recorded shape, and an array is not
    /// table-like, so the key is flagged as drift and the script is left
    /// untouched (`vendor_lock_entry_drifted`, entry kept). Reverting `two`
    /// first (`live == new`) then `one` converges; so does a SECOND pass over
    /// `one` after `two` is gone. Direct deps (`[tool.uv.sources]` table
    /// entries) revert in any order — see
    /// `script_sources_revert_out_of_order_without_empty_tables`.
    #[test]
    fn script_transitive_pair_revert_out_of_order() {
        let metadata = "dependencies = [\"top==1\"]\n";
        let script =
            replace_script_metadata("# /// script\n# ///\nprint('unchanged')\n", metadata).unwrap();
        let first = rewrite_script_metadata(
            &script,
            "one",
            "1",
            ArtifactSource::Path(".socket/vendor/one.whl"),
        )
        .unwrap()
        .unwrap();
        let both = rewrite_script_metadata(
            &first,
            "two",
            "2",
            ArtifactSource::Path(".socket/vendor/two.whl"),
        )
        .unwrap()
        .unwrap();
        let (_, first_metadata) = script_metadata(&first).unwrap();
        let (_, both_metadata) = script_metadata(&both).unwrap();
        assert!(both_metadata.contains("override-dependencies"));

        // Older first: flagged as drift, text preserved verbatim.
        let (kept, drifted) = restore_document(&both_metadata, metadata, &first_metadata).unwrap();
        assert!(
            drifted,
            "current behavior: the shared override array reads as drift"
        );
        assert_eq!(kept, both_metadata, "drift keeps the live text untouched");

        // Newer first converges (short-circuit), then the older one does too.
        let (second_reverted, drifted) =
            restore_document(&both_metadata, &first_metadata, &both_metadata).unwrap();
        assert!(!drifted);
        assert_eq!(second_reverted, first_metadata);
        let (restored, drifted) =
            restore_document(&second_reverted, metadata, &first_metadata).unwrap();
        assert!(!drifted);
        assert_eq!(restored, metadata);
    }
}
