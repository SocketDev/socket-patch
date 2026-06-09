//! Add / remove the managed `plugin "socket-patch"` block in a Bundler
//! `Gemfile`, and statically check whether it is present.
//!
//! A Gemfile is Ruby, not a structured config, so this appends/strips a
//! clearly-marked, byte-exact block under a reversibility contract: idempotent,
//! `dry_run`-aware, `Updated`/`AlreadyConfigured`/`Error`, and a `--remove` that
//! restores the file byte-for-byte.

use std::path::Path;

use tokio::fs;

use super::{add_plugin_files, remove_plugin_files, BundlerProject};

/// Outcome of one setup edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemSetupStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

#[derive(Debug, Clone)]
pub struct GemEditResult {
    /// Envelope `files[].kind` (`gemfile` | `gem_plugin`).
    pub kind: &'static str,
    pub path: String,
    pub status: GemSetupStatus,
    pub error: Option<String>,
}

impl GemEditResult {
    /// Build a result from an `Ok(changed)` / `Err(message)` outcome.
    pub(crate) fn from_result(
        kind: &'static str,
        path: String,
        result: Result<bool, String>,
    ) -> Self {
        match result {
            Ok(true) => Self {
                kind,
                path,
                status: GemSetupStatus::Updated,
                error: None,
            },
            Ok(false) => Self {
                kind,
                path,
                status: GemSetupStatus::AlreadyConfigured,
                error: None,
            },
            Err(e) => Self {
                kind,
                path,
                status: GemSetupStatus::Error,
                error: Some(e),
            },
        }
    }
}

/// Stable substring identifying our managed block — `setup --check` and the
/// add/remove edits all key on it, so a user-authored `plugin` line is never
/// mistaken for ours.
pub const MANAGED_MARKER: &str = "# >>> socket-patch:managed";

/// The exact block `setup` appends to the Gemfile (trailing newline included).
/// `File.expand_path(..., __dir__)` resolves relative to the Gemfile's own dir,
/// so the reference is correct regardless of where `bundle` is invoked from.
const MANAGED_BLOCK: &str = "\
# >>> socket-patch:managed (added by `socket-patch setup`; do not edit) >>>\n\
plugin 'socket-patch', git: File.expand_path('.socket/bundler-plugin', __dir__)\n\
# <<< socket-patch:managed <<<\n";

/// What we append after the user's content: a blank-line separator + the block.
/// Removing this exact string restores the Gemfile byte-for-byte.
fn appended() -> String {
    format!("\n{MANAGED_BLOCK}")
}

/// Static check: does this Gemfile contain our managed plugin block? Pure
/// substring scan — exactly what a repo auditor reads. A user's own
/// `plugin "foo"` line does not match (the marker comment does).
pub fn is_plugin_directive_present(content: &str) -> bool {
    content.contains(MANAGED_MARKER)
}

/// Pure transform: append the managed block, or `None` if already present.
fn gemfile_add(content: &str) -> Option<String> {
    if is_plugin_directive_present(content) {
        return None;
    }
    Some(format!("{content}{}", appended()))
}

/// Pure transform: strip the managed block (and the separator we added),
/// restoring the pre-setup bytes. `None` if our block is absent.
fn gemfile_remove(content: &str) -> Option<String> {
    if !is_plugin_directive_present(content) {
        return None;
    }
    // Remove the exact "\n<block>" we appended; fall back to stripping just the
    // block if the leading separator was edited away.
    let appended = appended();
    if let Some(idx) = content.find(&appended) {
        let mut out = content.to_string();
        out.replace_range(idx..idx + appended.len(), "");
        Some(out)
    } else {
        // Separator edited away: strip just the block. If the block body was
        // also edited (so this matches nothing), report nothing-removed rather
        // than a false "Updated" on an unchanged, still-marked file.
        let stripped = content.replace(MANAGED_BLOCK, "");
        (stripped != content).then_some(stripped)
    }
}

/// Append the managed `plugin` block to the Gemfile. Idempotent
/// (`AlreadyConfigured` when already present). A missing Gemfile is an error
/// (we don't synthesize one — `discover_bundler_project` guarantees it exists).
/// `kind = "gemfile"`.
async fn edit_gemfile_add(gemfile: &Path, dry_run: bool) -> GemEditResult {
    let result = async {
        let content = fs::read_to_string(gemfile)
            .await
            .map_err(|e| e.to_string())?;
        match gemfile_add(&content) {
            None => Ok(false),
            Some(new) => {
                if !dry_run {
                    fs::write(gemfile, &new).await.map_err(|e| e.to_string())?;
                }
                Ok(true)
            }
        }
    }
    .await;
    GemEditResult::from_result("gemfile", gemfile.display().to_string(), result)
}

/// Strip the managed block from the Gemfile. Idempotent (already-absent →
/// `AlreadyConfigured`); a missing Gemfile is a no-op.
async fn edit_gemfile_remove(gemfile: &Path, dry_run: bool) -> GemEditResult {
    let result = async {
        let content = match fs::read_to_string(gemfile).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        match gemfile_remove(&content) {
            None => Ok(false),
            Some(new) => {
                if !dry_run {
                    fs::write(gemfile, &new).await.map_err(|e| e.to_string())?;
                }
                Ok(true)
            }
        }
    }
    .await;
    GemEditResult::from_result("gemfile", gemfile.display().to_string(), result)
}

/// Wire the project: append the Gemfile `plugin` block and generate the in-tree
/// plugin directory. Returns one result per artifact (`gemfile`, `gem_plugin`).
pub async fn add_plugin_directive(project: &BundlerProject, dry_run: bool) -> Vec<GemEditResult> {
    vec![
        edit_gemfile_add(&project.gemfile, dry_run).await,
        add_plugin_files(&project.root, dry_run).await,
    ]
}

/// Unwire the project: strip the Gemfile block (byte-for-byte restore) and
/// delete the generated plugin directory.
pub async fn remove_plugin_directive(project: &BundlerProject, dry_run: bool) -> Vec<GemEditResult> {
    vec![
        edit_gemfile_remove(&project.gemfile, dry_run).await,
        remove_plugin_files(&project.root, dry_run).await,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

    #[test]
    fn test_add_appends_block_and_is_idempotent() {
        let out = gemfile_add(GEMFILE).unwrap();
        assert!(out.starts_with(GEMFILE), "original bytes preserved as a prefix");
        assert!(is_plugin_directive_present(&out));
        assert!(out.contains("plugin 'socket-patch'"));
        assert!(out.contains("File.expand_path('.socket/bundler-plugin', __dir__)"));
        // Idempotent.
        assert!(gemfile_add(&out).is_none());
    }

    #[test]
    fn test_add_then_remove_round_trips_byte_for_byte() {
        let added = gemfile_add(GEMFILE).unwrap();
        let removed = gemfile_remove(&added).unwrap();
        assert_eq!(removed, GEMFILE, "remove must restore the original bytes exactly");
    }

    #[test]
    fn test_remove_absent_is_noop() {
        assert!(gemfile_remove(GEMFILE).is_none());
    }

    #[test]
    fn test_user_plugin_line_is_not_detected_as_ours() {
        let user = "source 'https://rubygems.org'\nplugin 'some-other-plugin'\n";
        assert!(!is_plugin_directive_present(user));
        // Adding ours leaves the user's line intact.
        let out = gemfile_add(user).unwrap();
        assert!(out.contains("plugin 'some-other-plugin'"));
        assert!(out.contains("plugin 'socket-patch'"));
    }

    #[test]
    fn test_round_trips_without_trailing_newline() {
        // A Gemfile whose last line has no trailing newline must still restore
        // byte-for-byte (add appends "\n<block>"; remove strips exactly that).
        let no_nl = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'";
        let added = gemfile_add(no_nl).unwrap();
        assert!(is_plugin_directive_present(&added));
        assert_eq!(gemfile_remove(&added).unwrap(), no_nl);
    }

    #[test]
    fn test_round_trips_empty_gemfile() {
        let added = gemfile_add("").unwrap();
        assert!(is_plugin_directive_present(&added));
        assert_eq!(gemfile_remove(&added).unwrap(), "");
    }

    #[test]
    fn test_remove_via_block_fallback_when_separator_edited_away() {
        // User deleted the blank-line separator, leaving the block glued to a
        // no-newline final line. find(&appended) misses; the block-only
        // fallback still strips it.
        let glued = format!("gem 'x'{MANAGED_BLOCK}");
        assert!(is_plugin_directive_present(&glued));
        assert_eq!(gemfile_remove(&glued).unwrap(), "gem 'x'");
    }

    #[test]
    fn test_remove_reports_nothing_removed_when_block_body_edited() {
        // Marker present but the block body was hand-edited so neither the
        // "\n<block>" nor the bare-block match fires. Removing nothing must NOT
        // masquerade as a successful edit — the file is still configured.
        let edited = format!(
            "gem 'x'\n{MANAGED_MARKER} (added by `socket-patch setup`) >>>\nplugin 'socket-patch' # USER EDIT\n# <<< socket-patch:managed <<<\n"
        );
        assert!(is_plugin_directive_present(&edited));
        assert!(
            gemfile_remove(&edited).is_none(),
            "an un-matchable edited block reports nothing-removed, not a no-op Updated"
        );
    }

    #[test]
    fn test_remove_preserves_user_gems_added_below_the_block() {
        // Real-world flow: setup appends the block, then the user adds more
        // gems AFTER it. `remove` must excise exactly our "\n<block>" and leave
        // the user's later additions intact with clean formatting — never strip
        // a user line or glue two lines together.
        let added = gemfile_add(GEMFILE).unwrap();
        let user_edited = format!("{added}gem 'extra', '2.0'\n");
        assert!(is_plugin_directive_present(&user_edited));
        assert_eq!(
            gemfile_remove(&user_edited).unwrap(),
            format!("{GEMFILE}gem 'extra', '2.0'\n"),
            "only our block is removed; the user's later gems survive verbatim"
        );
    }

    #[test]
    fn test_round_trips_crlf_content_byte_for_byte() {
        // A Windows-authored Gemfile uses CRLF line endings. add appends an
        // LF-delimited block; remove must still restore the original CRLF bytes
        // exactly (the separator/block we strip is our own LF, not the user's).
        let crlf = "source 'https://rubygems.org'\r\ngem 'colorize', '1.1.0'\r\n";
        let added = gemfile_add(crlf).unwrap();
        assert!(is_plugin_directive_present(&added));
        assert_eq!(
            gemfile_remove(&added).unwrap(),
            crlf,
            "CRLF user content restored byte-for-byte"
        );
    }

    #[test]
    fn test_closing_marker_alone_is_not_detected_as_present() {
        // The "<<<" closing line must not satisfy the ">>>" opening marker.
        let closing_only = "gem 'x'\n# <<< socket-patch:managed <<<\n";
        assert!(!is_plugin_directive_present(closing_only));
    }

    #[tokio::test]
    async fn test_full_roundtrip_via_gems_rb() {
        // discover prefers Gemfile, so exercise the gems.rb manifest directly.
        let dir = tempfile::tempdir().unwrap();
        let gems_rb = dir.path().join("gems.rb");
        fs::write(&gems_rb, GEMFILE).await.unwrap();
        assert_eq!(
            edit_gemfile_add(&gems_rb, false).await.status,
            GemSetupStatus::Updated
        );
        assert!(is_plugin_directive_present(
            &fs::read_to_string(&gems_rb).await.unwrap()
        ));
        assert_eq!(
            edit_gemfile_remove(&gems_rb, false).await.status,
            GemSetupStatus::Updated
        );
        assert_eq!(fs::read_to_string(&gems_rb).await.unwrap(), GEMFILE);
    }

    #[tokio::test]
    async fn test_remove_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        let configured = gemfile_add(GEMFILE).unwrap();
        fs::write(&gemfile, &configured).await.unwrap();
        let res = edit_gemfile_remove(&gemfile, true).await;
        assert_eq!(res.status, GemSetupStatus::Updated);
        assert_eq!(
            fs::read_to_string(&gemfile).await.unwrap(),
            configured,
            "dry-run remove must not write"
        );
    }

    #[tokio::test]
    async fn test_edit_gemfile_missing_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let res = edit_gemfile_add(&dir.path().join("Gemfile"), false).await;
        assert_eq!(res.status, GemSetupStatus::Error);
    }

    #[tokio::test]
    async fn test_edit_gemfile_remove_missing_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let res = edit_gemfile_remove(&dir.path().join("Gemfile"), false).await;
        assert_eq!(res.status, GemSetupStatus::AlreadyConfigured);
    }

    #[tokio::test]
    async fn test_add_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, GEMFILE).await.unwrap();
        let res = edit_gemfile_add(&gemfile, true).await;
        assert_eq!(res.status, GemSetupStatus::Updated);
        assert_eq!(
            fs::read_to_string(&gemfile).await.unwrap(),
            GEMFILE,
            "dry-run must not write"
        );
    }

    #[tokio::test]
    async fn test_full_roundtrip_via_project() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Gemfile"), GEMFILE).await.unwrap();
        let project = super::super::discover_bundler_project(root).await.unwrap();

        let added = add_plugin_directive(&project, false).await;
        assert!(added.iter().all(|r| r.status == GemSetupStatus::Updated));
        assert!(is_plugin_directive_present(
            &fs::read_to_string(root.join("Gemfile")).await.unwrap()
        ));
        assert!(super::super::plugin_files_present(root).await);

        // Idempotent re-run.
        let again = add_plugin_directive(&project, false).await;
        assert!(again.iter().all(|r| r.status == GemSetupStatus::AlreadyConfigured));

        let removed = remove_plugin_directive(&project, false).await;
        assert!(removed.iter().all(|r| r.status == GemSetupStatus::Updated));
        assert_eq!(
            fs::read_to_string(root.join("Gemfile")).await.unwrap(),
            GEMFILE,
            "Gemfile restored byte-for-byte"
        );
        assert!(!super::super::plugin_files_present(root).await);
    }
}
