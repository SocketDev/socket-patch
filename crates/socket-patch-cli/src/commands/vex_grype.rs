//! `vex --grype-config`: keep a Grype config's `vex-documents` list naming
//! the document `vex` writes, so a plain `grype dir:.` reads it.
//!
//! Grype fails the whole scan when a listed document is missing, so a run
//! that leaves no document at `--output` (it could attest nothing and
//! removed the previous one) takes the entry out again. A config whose
//! shape the editor cannot read with certainty is left as it is, and the
//! run warns with the line to add by hand. Either way the VEX document and
//! the exit status are the run's own.

use std::path::{Component, Path, PathBuf};

use serde_json::json;
use socket_patch_core::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use socket_patch_core::vex::grype_config::{
    add_vex_document, remove_vex_document, GrypeConfigEdit, VEX_DOCUMENTS_KEY,
};

use crate::json_envelope::RunWarning;

/// The run warning for a config the run could not update.
pub(crate) const GRYPE_CONFIG_NOT_UPDATED: &str = "grype_config_not_updated";

/// What a run did to the Grype config.
pub(crate) struct GrypeConfigOutcome {
    pub path: PathBuf,
    /// The path the config lists, relative to its directory.
    pub entry: Option<String>,
    /// `created`, `added`, `listed` (already there), `removed`, `absent`
    /// (nothing to remove), `not_updated`, or `would_create` /
    /// `would_add` / `would_remove` under `--dry-run`.
    pub change: &'static str,
    pub warning: Option<RunWarning>,
}

impl GrypeConfigOutcome {
    /// The envelope's `grypeConfig` object.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        json!({
            "path": self.path.display().to_string(),
            "entry": self.entry,
            "change": self.change,
        })
    }

    /// The line a human run prints, when the config changed.
    pub(crate) fn human_line(&self) -> Option<String> {
        let entry = self.entry.as_deref()?;
        let path = self.path.display();
        let line = match self.change {
            "created" => format!("Created {path}, listing {entry} in {VEX_DOCUMENTS_KEY}"),
            "added" => format!("Listed {entry} in {VEX_DOCUMENTS_KEY} of {path}"),
            "removed" => format!(
                "Removed {entry} from {VEX_DOCUMENTS_KEY} of {path}, since the document is gone"
            ),
            "would_create" => {
                format!("Would create {path}, listing {entry} in {VEX_DOCUMENTS_KEY}")
            }
            "would_add" => format!("Would list {entry} in {VEX_DOCUMENTS_KEY} of {path}"),
            "would_remove" => {
                format!("Would remove {entry} from {VEX_DOCUMENTS_KEY} of {path}")
            }
            _ => return None,
        };
        Some(line)
    }
}

/// List `output` in the config at `config` after the document was written.
pub(crate) async fn list_document(
    config: &Path,
    output: &Path,
    dry_run: bool,
) -> GrypeConfigOutcome {
    let entry = match entry_for(config, output) {
        Ok(entry) => entry,
        Err(why) => return not_updated(config, None, output, &why),
    };
    let text = match read_config(config).await {
        Ok(text) => text,
        Err(why) => return not_updated(config, Some(entry), output, &why),
    };
    let existed = text.is_some();
    match add_vex_document(text.as_deref(), &entry) {
        Ok(GrypeConfigEdit::Unchanged) => outcome(config, entry, "listed"),
        Ok(GrypeConfigEdit::Write(new)) => {
            let change = match (existed, dry_run) {
                (false, false) => "created",
                (true, false) => "added",
                (false, true) => "would_create",
                (true, true) => "would_add",
            };
            if !dry_run {
                if let Err(e) = atomic_write_bytes_preserving_mode(config, new.as_bytes()).await {
                    let why = format!("could not be written ({e})");
                    return not_updated(config, Some(entry), output, &why);
                }
            }
            outcome(config, entry, change)
        }
        Err(why) => not_updated(config, Some(entry), output, &why),
    }
}

/// Take `output` out of the config at `config` when no document is left
/// there. `None` when the document is still there, or nothing is to be done.
pub(crate) async fn unlist_missing_document(
    config: &Path,
    output: &Path,
    dry_run: bool,
) -> Option<GrypeConfigOutcome> {
    if tokio::fs::symlink_metadata(output).await.is_ok() {
        return None;
    }
    let entry = entry_for(config, output).ok()?;
    let text = read_config(config).await.ok()??;
    match remove_vex_document(&text, &entry) {
        Ok(GrypeConfigEdit::Unchanged) => None,
        Ok(GrypeConfigEdit::Write(_)) if dry_run => Some(outcome(config, entry, "would_remove")),
        Ok(GrypeConfigEdit::Write(new)) => {
            match atomic_write_bytes_preserving_mode(config, new.as_bytes()).await {
                Ok(()) => Some(outcome(config, entry, "removed")),
                Err(e) => Some(stale_entry(
                    config,
                    entry,
                    &format!("could not be written ({e})"),
                )),
            }
        }
        Err(why) => Some(stale_entry(config, entry, &why)),
    }
}

fn outcome(config: &Path, entry: String, change: &'static str) -> GrypeConfigOutcome {
    GrypeConfigOutcome {
        path: config.to_path_buf(),
        entry: Some(entry),
        change,
        warning: None,
    }
}

fn not_updated(
    config: &Path,
    entry: Option<String>,
    output: &Path,
    why: &str,
) -> GrypeConfigOutcome {
    let listed = entry
        .clone()
        .unwrap_or_else(|| output.display().to_string());
    GrypeConfigOutcome {
        path: config.to_path_buf(),
        entry,
        change: "not_updated",
        warning: Some(RunWarning {
            code: GRYPE_CONFIG_NOT_UPDATED.to_string(),
            detail: format!(
                "{} not updated: it {why}. List `{listed}` in `{VEX_DOCUMENTS_KEY}` yourself, \
                 or run grype with `--vex {}`.",
                config.display(),
                output.display()
            ),
        }),
    }
}

fn stale_entry(config: &Path, entry: String, why: &str) -> GrypeConfigOutcome {
    GrypeConfigOutcome {
        path: config.to_path_buf(),
        warning: Some(RunWarning {
            code: GRYPE_CONFIG_NOT_UPDATED.to_string(),
            detail: format!(
                "{} still lists `{entry}` in `{VEX_DOCUMENTS_KEY}`, and Grype fails a scan \
                 whose listed document is missing: it {why}. Remove the entry by hand.",
                config.display()
            ),
        }),
        entry: Some(entry),
        change: "not_updated",
    }
}

/// The config's text; `None` when there is no file.
async fn read_config(config: &Path) -> Result<Option<String>, String> {
    match tokio::fs::symlink_metadata(config).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not be read ({e})")),
        Ok(meta) if !meta.is_file() => return Err("is not a regular file".to_string()),
        Ok(_) => {}
    }
    read_regular_to_string(config)
        .await
        .map(Some)
        .map_err(|e| format!("could not be read ({e})"))
}

/// `output` as the config lists it: relative to the config's directory,
/// with `/` separators. Grype resolves the list against the directory it
/// runs in, so it is run from the config's directory.
fn entry_for(config: &Path, output: &Path) -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("has no base directory ({e})"))?;
    let dir = lexical(&cwd.join(config));
    let dir = dir.parent().map(Path::to_path_buf).unwrap_or(dir);
    let document = lexical(&cwd.join(output));
    let relative = document.strip_prefix(&dir).map_err(|_| {
        format!(
            "is not above the VEX document {}, and Grype reads a listed path from the \
             directory it runs in",
            output.display()
        )
    })?;
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        return Err("names the VEX document's own path".to_string());
    }
    Ok(parts.join("/"))
}

/// `path` with `.` dropped and `..` folded into its parent, without
/// touching the file system (the document may not exist yet).
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_relative_to_the_config() {
        assert_eq!(
            entry_for(Path::new(".grype.yaml"), Path::new("socket.vex.json")).unwrap(),
            "socket.vex.json"
        );
        assert_eq!(
            entry_for(
                Path::new("./.grype.yaml"),
                Path::new("out/./socket.vex.json")
            )
            .unwrap(),
            "out/socket.vex.json"
        );
        assert!(entry_for(Path::new("sub/.grype.yaml"), Path::new("socket.vex.json")).is_err());
    }
}
