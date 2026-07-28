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
use crate::utils::fs::atomic_write_bytes_preserving_mode;

/// Outcome of one setup edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemSetupStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

#[derive(Debug)]
pub struct GemEditResult {
    /// Envelope `files[].kind` (`gemfile` | `gem_plugin`).
    pub kind: &'static str,
    pub path: String,
    pub status: GemSetupStatus,
    pub error: Option<String>,
}

impl GemEditResult {
    /// Build a result from an `Ok(changed)` / `Err(message)` outcome.
    pub(super) fn from_result(
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
const MANAGED_MARKER: &str = "# >>> socket-patch:managed";

/// The exact block `setup` appends to the Gemfile (trailing newline included).
/// `File.expand_path(..., __dir__)` resolves relative to the Gemfile's own dir,
/// so the reference is correct regardless of where `bundle` is invoked from.
/// The source MUST be `path:`, not `git:`: Bundler fetches a `git:` plugin via
/// `git clone <dir>`, and the generated dir is a plain directory (committing it
/// to the parent repo does not give it a `.git`), so a `git:` source fails
/// every `bundle install` with "repository ... does not exist". A `path:`
/// source loads the directory in place.
const MANAGED_BLOCK: &str = "\
# >>> socket-patch:managed (added by `socket-patch setup`; do not edit) >>>\n\
plugin 'socket-patch', path: File.expand_path('.socket/bundler-plugin', __dir__)\n\
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

/// Every on-disk form of the managed block, paired with the separator that
/// precedes it: the LF bytes `setup` writes, and the CRLF rewrite handed back by
/// a `core.autocrlf` checkout (Git for Windows' default) or an editor that saves
/// the whole Gemfile CRLF. Both are ours, so `--remove` must match both — the
/// marker survives such a rewrite, so a CRLF block otherwise reads as
/// "configured" forever while `remove` reports nothing to do.
fn block_variants() -> [(&'static str, String); 2] {
    [
        ("\n", MANAGED_BLOCK.to_string()),
        ("\r\n", MANAGED_BLOCK.replace('\n', "\r\n")),
    ]
}

/// Pure transform: strip the managed block (and the separator we added),
/// restoring the pre-setup bytes. `None` if our block is absent.
fn gemfile_remove(content: &str) -> Option<String> {
    if !is_plugin_directive_present(content) {
        return None;
    }
    let mut out = content.to_string();
    let mut changed = false;
    for (separator, block) in block_variants() {
        // Remove every "<separator><block>" we appended — a Gemfile can carry
        // more than one copy (a merge that kept both sides, a hand-copied
        // Gemfile), and leaving one behind reports "removed" while a `plugin`
        // line pointing at the just-deleted plugin dir fails every later
        // `bundle install`.
        let appended = format!("{separator}{block}");
        while let Some(idx) = out.find(&appended) {
            let end = idx + appended.len();
            // The separator doubles as the terminator of a final unterminated
            // pre-setup line. Stripping it is only safe when the block sits at
            // EOF (the byte-exact restore) or the separator is a pure blank
            // line (preceded by a newline, or at the start of the file);
            // otherwise the user's lines on either side of the block would glue
            // into one.
            let start = if end == out.len() || idx == 0 || out[..idx].ends_with('\n') {
                idx
            } else {
                idx + separator.len()
            };
            out.replace_range(start..end, "");
            changed = true;
        }
        // Separator edited away: strip the bare block.
        if out.contains(&block) {
            out = out.replace(&block, "");
            changed = true;
        }
    }
    // If the block body itself was hand-edited (so nothing above matched),
    // report nothing-removed rather than a false "Updated" on an unchanged,
    // still-marked file.
    changed.then_some(out)
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
                    // Stage+fsync+rename via the crate-wide hardened writer:
                    // the user's committed Gemfile must never be left torn by
                    // a crash mid-write. Mode-preserving, because the Gemfile
                    // is the user's file and we only edit it — the rename swaps
                    // in a fresh inode, so the plain writer would reset a 0600
                    // private or 0664 group-writable Gemfile to umask defaults.
                    atomic_write_bytes_preserving_mode(gemfile, new.as_bytes())
                        .await
                        .map_err(|e| e.to_string())?;
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
                    atomic_write_bytes_preserving_mode(gemfile, new.as_bytes())
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(true)
            }
        }
    }
    .await;
    GemEditResult::from_result("gemfile", gemfile.display().to_string(), result)
}

/// Wire the project: generate the in-tree plugin directory, then append the
/// Gemfile `plugin` block. Returns one result per artifact (`gemfile`,
/// `gem_plugin`).
///
/// The plugin dir is generated FIRST and the Gemfile wired only if that
/// succeeded, because Bundler hard-fails `bundle install` on a `plugin ... path:`
/// directive whose source is missing ("The path ... does not exist", exit 13).
/// Wiring first and then failing to write the files would leave the project
/// unable to install at all — strictly worse than never having run `setup`.
/// Wiring last keeps a failure's blast radius at "not configured".
pub async fn add_plugin_directive(project: &BundlerProject, dry_run: bool) -> Vec<GemEditResult> {
    let files = add_plugin_files(&project.root, dry_run).await;
    if files.status == GemSetupStatus::Error {
        return vec![files];
    }
    // Envelope order stays gemfile-then-gem_plugin; only execution order moved.
    let gemfile = edit_gemfile_add(&project.gemfile, dry_run).await;
    vec![gemfile, files]
}

/// Unwire the project: strip the Gemfile block (byte-for-byte restore), then
/// delete the generated plugin directory.
///
/// Mirror of [`add_plugin_directive`]'s ordering contract, from the other end:
/// the files are deleted only once the directive referencing them is gone. A
/// failed un-wire that still deleted the plugin dir would leave the Gemfile
/// pointing at a path that no longer exists, breaking every later
/// `bundle install` (exit 13) on a project that installed fine before.
pub async fn remove_plugin_directive(
    project: &BundlerProject,
    dry_run: bool,
) -> Vec<GemEditResult> {
    let gemfile = edit_gemfile_remove(&project.gemfile, dry_run).await;
    if gemfile.status == GemSetupStatus::Error {
        return vec![gemfile];
    }
    vec![gemfile, remove_plugin_files(&project.root, dry_run).await]
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

    #[test]
    fn test_add_appends_block_and_is_idempotent() {
        let out = gemfile_add(GEMFILE).unwrap();
        assert!(
            out.starts_with(GEMFILE),
            "original bytes preserved as a prefix"
        );
        assert!(is_plugin_directive_present(&out));
        // `path:`-sourced, never `git:`: Bundler git-clones a `git:` plugin
        // source, and the plain generated dir is uncloneable, breaking every
        // `bundle install` on the wired project.
        assert!(out.contains("plugin 'socket-patch', path:"));
        assert!(out.contains("File.expand_path('.socket/bundler-plugin', __dir__)"));
        // Idempotent.
        assert!(gemfile_add(&out).is_none());
    }

    #[test]
    fn test_add_then_remove_round_trips_byte_for_byte() {
        let added = gemfile_add(GEMFILE).unwrap();
        let removed = gemfile_remove(&added).unwrap();
        assert_eq!(
            removed, GEMFILE,
            "remove must restore the original bytes exactly"
        );
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
    fn test_remove_does_not_glue_lines_when_original_lacked_trailing_newline() {
        // Original Gemfile has no final newline; setup's "\n" separator becomes
        // the terminator of that last line. The user then adds gems AFTER our
        // block. remove must not strip that separator along with the block —
        // doing so glues `gem 'colorize', '1.1.0'` onto `gem 'extra', '2.0'`
        // (one invalid Ruby line).
        let no_nl = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'";
        let added = gemfile_add(no_nl).unwrap();
        let user_edited = format!("{added}gem 'extra', '2.0'\n");
        assert_eq!(
            gemfile_remove(&user_edited).unwrap(),
            format!("{no_nl}\ngem 'extra', '2.0'\n"),
            "the separator newline must survive as the last line's terminator"
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
    fn test_remove_strips_a_crlf_rewritten_block() {
        // Git for Windows' default `core.autocrlf` ("checkout Windows-style,
        // commit Unix-style") rewrites the LF block we wrote into CRLF on
        // checkout — as does a Windows editor that saves the whole Gemfile
        // CRLF. `--remove` must still strip it. Otherwise it reports
        // "not_configured" and leaves the `plugin` line behind while
        // `remove_plugin_files` DOES delete the generated plugin dir (its
        // marker survives the rewrite), so every later `bundle install` dies
        // on a plugin path that no longer exists.
        let crlf_block = MANAGED_BLOCK.replace('\n', "\r\n");
        let user = "source 'https://rubygems.org'\r\ngem 'colorize', '1.1.0'\r\n";
        let configured = format!("{user}\r\n{crlf_block}");
        assert!(is_plugin_directive_present(&configured));
        let out =
            gemfile_remove(&configured).expect("a CRLF-rewritten block is still ours to strip");
        assert_eq!(
            out, user,
            "the CRLF checkout's pre-setup bytes are restored"
        );
        assert!(!is_plugin_directive_present(&out));
    }

    #[test]
    fn test_remove_strips_a_crlf_block_without_gluing_later_user_lines() {
        // Same CRLF rewrite, but the user added gems AFTER our block and the
        // pre-setup file had no final newline (so the separator terminates that
        // last line). Stripping the CRLF separator too would glue two `gem`
        // lines into one invalid Ruby line.
        let crlf_block = MANAGED_BLOCK.replace('\n', "\r\n");
        let configured = format!("gem 'colorize'\r\n{crlf_block}gem 'extra', '2.0'\r\n");
        assert_eq!(
            gemfile_remove(&configured).unwrap(),
            "gem 'colorize'\r\ngem 'extra', '2.0'\r\n",
            "the CRLF separator survives as the previous line's terminator"
        );
    }

    #[test]
    fn test_remove_strips_every_managed_block() {
        // A Gemfile can end up carrying two copies of the block — a merge that
        // kept both sides, or a hand-copied Gemfile. `--remove` must strip all
        // of them: leaving one behind reports "removed" while a `plugin` line
        // pointing at the just-deleted plugin dir survives and fails every
        // later `bundle install`.
        let added = gemfile_add(GEMFILE).unwrap();
        let doubled = format!("{added}\n{MANAGED_BLOCK}");
        assert!(is_plugin_directive_present(&doubled));
        let out = gemfile_remove(&doubled).unwrap();
        assert!(
            !is_plugin_directive_present(&out),
            "no managed block may survive `--remove`"
        );
        assert_eq!(out, GEMFILE, "both blocks stripped, user bytes restored");
    }

    #[test]
    fn test_closing_marker_alone_is_not_detected_as_present() {
        // The "<<<" closing line must not satisfy the ">>>" opening marker.
        let closing_only = "gem 'x'\n# <<< socket-patch:managed <<<\n";
        assert!(!is_plugin_directive_present(closing_only));
    }

    #[tokio::test]
    async fn test_full_roundtrip_via_gems_rb() {
        // Exercise Bundler's alternate manifest name end to end.
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

    // ── atomic-write contract (no truncation / no stage litter) ──────
    //
    // The Gemfile edit must go through stage+fsync+rename, never a bare
    // truncating write, so a crash can't leave the user's committed Gemfile
    // truncated or empty.

    #[cfg(unix)]
    #[tokio::test]
    async fn test_add_replaces_readonly_gemfile_atomically() {
        use std::os::unix::fs::PermissionsExt;
        // Oracle for the truncating-write bug: rename needs only directory
        // write permission, while a bare `fs::write` must open the target
        // itself for writing — so a read-only Gemfile distinguishes the two
        // (EACCES under truncate, clean replace under stage+rename, same as
        // the composer/npm/pypi/cargo/go manifest writers).
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, GEMFILE).await.unwrap();
        std::fs::set_permissions(&gemfile, std::fs::Permissions::from_mode(0o444)).unwrap();

        let res = edit_gemfile_add(&gemfile, false).await;
        assert_eq!(res.status, GemSetupStatus::Updated, "err: {:?}", res.error);
        assert!(is_plugin_directive_present(
            &fs::read_to_string(&gemfile).await.unwrap()
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_remove_replaces_readonly_gemfile_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, gemfile_add(GEMFILE).unwrap())
            .await
            .unwrap();
        std::fs::set_permissions(&gemfile, std::fs::Permissions::from_mode(0o444)).unwrap();

        let res = edit_gemfile_remove(&gemfile, false).await;
        assert_eq!(res.status, GemSetupStatus::Updated, "err: {:?}", res.error);
        assert_eq!(
            fs::read_to_string(&gemfile).await.unwrap(),
            GEMFILE,
            "read-only Gemfile restored byte-for-byte via stage+rename"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_add_preserves_gemfile_permissions() {
        use std::os::unix::fs::PermissionsExt;
        // The rename swaps in a fresh stage inode created with umask defaults,
        // so the plain writer resets the mode of a file the USER owns and we
        // merely edit: a 0600 private Gemfile silently becomes world-readable.
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, GEMFILE).await.unwrap();
        std::fs::set_permissions(&gemfile, std::fs::Permissions::from_mode(0o600)).unwrap();

        let res = edit_gemfile_add(&gemfile, false).await;
        assert_eq!(res.status, GemSetupStatus::Updated, "err: {:?}", res.error);
        let mode = std::fs::metadata(&gemfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the user's Gemfile mode must survive the edit (got {mode:o})"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_remove_preserves_gemfile_permissions() {
        use std::os::unix::fs::PermissionsExt;
        // Inverse of the 0600 case: a group-writable Gemfile (shared checkout)
        // must not come back 0644, locking the group out.
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, gemfile_add(GEMFILE).unwrap())
            .await
            .unwrap();
        std::fs::set_permissions(&gemfile, std::fs::Permissions::from_mode(0o664)).unwrap();

        let res = edit_gemfile_remove(&gemfile, false).await;
        assert_eq!(res.status, GemSetupStatus::Updated, "err: {:?}", res.error);
        let mode = std::fs::metadata(&gemfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o664,
            "group-writable Gemfile stays group-writable (got {mode:o})"
        );
    }

    #[tokio::test]
    async fn test_edit_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        fs::write(&gemfile, GEMFILE).await.unwrap();

        assert_eq!(
            edit_gemfile_add(&gemfile, false).await.status,
            GemSetupStatus::Updated
        );
        assert_eq!(
            edit_gemfile_remove(&gemfile, false).await.status,
            GemSetupStatus::Updated
        );
        assert_eq!(fs::read_to_string(&gemfile).await.unwrap(), GEMFILE);

        // No half-written `.socket-stage-*` sibling left behind.
        let mut rd = fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.starts_with(".socket-stage-"), "stage litter: {name}");
        }
    }

    // ── the Gemfile directive must never point at a missing plugin dir ──
    //
    // Bundler HARD-FAILS `bundle install` on a `plugin ... path:` directive
    // whose source directory does not exist:
    //
    //     $ bundle install
    //     The path `/tmp/x/.socket/bundler-plugin` does not exist.
    //     $ echo $?
    //     13
    //
    // (verified on bundler 4.0.15). So a half-applied add — Gemfile wired, files
    // not written — is strictly WORSE than never running setup: the project can
    // no longer install at all. Same for a half-applied remove: files deleted,
    // directive left behind. Both orderings must keep the directive's lifetime
    // inside the plugin dir's.

    #[tokio::test]
    async fn test_add_leaves_gemfile_unwired_when_plugin_dir_cannot_be_generated() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Gemfile"), GEMFILE).await.unwrap();
        // `.socket` as a regular FILE makes `create_dir_all(".socket/bundler-
        // plugin")` fail on every platform — the portable stand-in for a
        // read-only checkout / ENOSPC / a clobbered `.socket`.
        fs::write(root.join(".socket"), "not a directory\n")
            .await
            .unwrap();
        let project = super::super::discover_bundler_project(root).await.unwrap();

        let results = add_plugin_directive(&project, false).await;

        assert!(
            results.iter().any(|r| r.status == GemSetupStatus::Error),
            "the failed plugin-dir generation must surface as an error: {results:?}"
        );
        assert_eq!(
            fs::read_to_string(root.join("Gemfile")).await.unwrap(),
            GEMFILE,
            "the Gemfile must NOT be wired to a plugin dir that does not exist — \
             that breaks every `bundle install` (exit 13)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_remove_keeps_plugin_files_when_gemfile_cannot_be_unwired() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Gemfile"), GEMFILE).await.unwrap();
        let project = super::super::discover_bundler_project(root).await.unwrap();
        assert!(add_plugin_directive(&project, false)
            .await
            .iter()
            .all(|r| r.status == GemSetupStatus::Updated));

        // A read-only project root blocks the Gemfile's stage+rename (the stage
        // sibling cannot be created) while leaving `.socket/bundler-plugin/`
        // itself writable — so the un-wire fails but the deletes would succeed.
        fs::set_permissions(root, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let results = remove_plugin_directive(&project, false).await;

        // Restore before any assertion can unwind, so the tempdir cleans up.
        fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(
            results.iter().any(|r| r.status == GemSetupStatus::Error),
            "the failed Gemfile un-wire must surface as an error: {results:?}"
        );
        assert!(
            is_plugin_directive_present(&fs::read_to_string(root.join("Gemfile")).await.unwrap()),
            "precondition: the directive is still in the Gemfile"
        );
        assert!(
            super::super::plugin_files_present(root).await,
            "the plugin files must SURVIVE a failed un-wire — deleting them while \
             the directive remains breaks every `bundle install` (exit 13)"
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
        assert!(again
            .iter()
            .all(|r| r.status == GemSetupStatus::AlreadyConfigured));

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
