//! The finish step every vendored `revert_*` runs once its wiring is
//! restored: the dry-run return, the drift-keep, the `--preserve-state`
//! return and the artifact deletion, in that order. Each backend names its
//! keep rule as a [`KeepPolicy`] instead of re-writing the sequence (#989).

use std::path::Path;

use crate::constants::SOCKET_DIR;
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::any_live_file_references;
use super::npm_flavor::keep_artifact_while_lock_references_it;
use super::{RevertOpts, RevertOutcome};

/// When a revert keeps the artifact instead of deleting it. `CLI_CONTRACT.md`
/// documents the rule each backend uses.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeepPolicy<'a> {
    /// Any left-alone record (`vendor_lock_entry_drifted`) keeps the
    /// artifact (gem).
    OnDrift,
    /// A left-alone record keeps the artifact only while one of these
    /// root-relative files still names the uuid dir (composer, Maven,
    /// NuGet): a converged file never does, so the keep cannot outlive the
    /// drift. See [`any_live_file_references`].
    OnDriftWhileReferenced(&'a [&'a str]),
    /// The npm family (pnpm, bun): any left-alone record keeps the
    /// artifact, and a vanished lock entry keeps it while one of `locks`
    /// may still resolve through `uuid` (#665). A failed deletion fails
    /// the whole revert with the relative dir in the message.
    NpmFamily { locks: &'a [&'a str], uuid: &'a str },
}

/// Finish a revert whose wiring restore produced `outcome`: return it
/// untouched on a dry run, keep the artifact per `policy` when a record
/// was left alone, skip only the deletion under `--preserve-state`, and
/// otherwise remove `uuid_dir_rel` and prune the vendor levels it empties
/// (non-recursive: siblings keep them).
pub(crate) async fn finish(
    mut outcome: RevertOutcome,
    project_root: &Path,
    uuid_dir_rel: &str,
    opts: RevertOpts,
    policy: KeepPolicy<'_>,
) -> RevertOutcome {
    if opts.dry_run {
        return outcome;
    }
    let drift_keeps = match policy {
        KeepPolicy::OnDrift | KeepPolicy::NpmFamily { .. } => outcome.drift_skipped(),
        KeepPolicy::OnDriftWhileReferenced(files) => {
            outcome.drift_skipped()
                && any_live_file_references(project_root, files, uuid_dir_rel).await
        }
    };
    if drift_keeps {
        outcome.keep_artifact(uuid_dir_rel);
        return outcome;
    }
    // `--preserve-state`: the artifact dir stays behind and the caller
    // keeps the ledger entry, so only the deletion is skipped.
    if opts.keep_artifact {
        return outcome;
    }
    if let KeepPolicy::NpmFamily { locks, uuid } = policy {
        if keep_artifact_while_lock_references_it(
            &mut outcome,
            project_root,
            locks,
            uuid,
            uuid_dir_rel,
        )
        .await
        {
            return outcome;
        }
    }
    let uuid_dir = project_root.join(uuid_dir_rel);
    if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
        if let KeepPolicy::NpmFamily { .. } = policy {
            return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
        }
        outcome.success = false;
        outcome.error = Some(format!("failed to remove {}: {e}", uuid_dir.display()));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::{VendorWarning, LOCK_ENTRY_REMOVED_CODE};

    const UUID: &str = "11111111-2222-4333-8444-555555555555";

    fn rel(eco: &str) -> String {
        format!(".socket/vendor/{eco}/{UUID}")
    }

    /// A project with a vendored artifact under `.socket/vendor/<eco>/`.
    fn project(eco: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let uuid_dir = dir.path().join(rel(eco));
        std::fs::create_dir_all(&uuid_dir).unwrap();
        std::fs::write(uuid_dir.join("artifact"), b"patched").unwrap();
        dir
    }

    fn with(code: &'static str) -> RevertOutcome {
        let mut outcome = RevertOutcome::ok();
        outcome
            .warnings
            .push(VendorWarning::new(code, "left alone".to_string()));
        outcome
    }

    fn drifted() -> RevertOutcome {
        with("vendor_lock_entry_drifted")
    }

    fn wet() -> RevertOpts {
        RevertOpts::new(false)
    }

    fn preserve() -> RevertOpts {
        RevertOpts {
            dry_run: false,
            keep_artifact: true,
        }
    }

    const LOCKS: &[&str] = &["pnpm-lock.yaml"];

    /// Every policy a former copy used: gem, composer/Maven/Nuget and the
    /// npm family (pnpm).
    fn policies() -> [KeepPolicy<'static>; 3] {
        [
            KeepPolicy::OnDrift,
            KeepPolicy::OnDriftWhileReferenced(&["composer.lock"]),
            KeepPolicy::NpmFamily {
                locks: LOCKS,
                uuid: UUID,
            },
        ]
    }

    #[tokio::test]
    async fn a_dry_run_returns_the_outcome_untouched_under_every_policy() {
        for policy in policies() {
            let dir = project("gem");
            let outcome = finish(
                drifted(),
                dir.path(),
                &rel("gem"),
                RevertOpts::new(true),
                policy,
            )
            .await;
            assert!(outcome.success && !outcome.kept_artifact, "{policy:?}");
            assert_eq!(outcome.warnings.len(), 1, "{policy:?}");
            assert!(dir.path().join(rel("gem")).is_dir(), "{policy:?}");
        }
    }

    #[tokio::test]
    async fn a_clean_revert_removes_the_artifact_and_prunes_empty_levels() {
        for policy in policies() {
            let dir = project("gem");
            let outcome = finish(RevertOutcome::ok(), dir.path(), &rel("gem"), wet(), policy).await;
            assert!(outcome.success && !outcome.kept_artifact, "{policy:?}");
            assert!(outcome.warnings.is_empty(), "{policy:?}");
            assert!(!dir.path().join(".socket/vendor").exists(), "{policy:?}");
        }
    }

    #[tokio::test]
    async fn preserve_state_skips_only_the_deletion() {
        for policy in policies() {
            let dir = project("gem");
            let outcome = finish(
                RevertOutcome::ok(),
                dir.path(),
                &rel("gem"),
                preserve(),
                policy,
            )
            .await;
            assert!(outcome.success && !outcome.kept_artifact, "{policy:?}");
            assert!(outcome.warnings.is_empty(), "{policy:?}");
            assert!(dir.path().join(rel("gem")).is_dir(), "{policy:?}");
        }
    }

    #[tokio::test]
    async fn drift_keeps_unconditionally_for_gem_and_the_npm_family() {
        for policy in [policies()[0], policies()[2]] {
            for opts in [wet(), preserve()] {
                let dir = project("gem");
                let outcome = finish(drifted(), dir.path(), &rel("gem"), opts, policy).await;
                assert!(outcome.success && outcome.kept_artifact, "{policy:?}");
                assert!(
                    outcome
                        .warnings
                        .iter()
                        .any(|w| w.code == "vendor_artifact_kept"),
                    "{policy:?}"
                );
                assert!(dir.path().join(rel("gem")).is_dir(), "{policy:?}");
            }
        }
    }

    #[tokio::test]
    async fn drift_keeps_only_while_a_live_file_names_the_uuid_dir() {
        let policy = KeepPolicy::OnDriftWhileReferenced(&["composer.lock", "pom.xml"]);

        let dir = project("composer");
        std::fs::write(dir.path().join("composer.lock"), "{}").unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            format!("<url>{}</url>", rel("composer")),
        )
        .unwrap();
        let outcome = finish(drifted(), dir.path(), &rel("composer"), wet(), policy).await;
        assert!(outcome.success && outcome.kept_artifact);
        assert!(dir.path().join(rel("composer")).is_dir());

        // A converged file (no reference left) lets the drift-skipped
        // revert delete the artifact.
        let dir = project("composer");
        std::fs::write(dir.path().join("composer.lock"), "{}").unwrap();
        let outcome = finish(drifted(), dir.path(), &rel("composer"), wet(), policy).await;
        assert!(outcome.success && !outcome.kept_artifact);
        assert!(!dir.path().join(rel("composer")).exists());
        assert_eq!(outcome.warnings.len(), 1, "the drift warning is kept");
    }

    #[tokio::test]
    async fn npm_family_keeps_a_removed_entry_while_a_lock_names_the_uuid() {
        let policy = policies()[2];
        let dir = project("npm");
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            format!("x: file:{}/pkg.tgz\n", rel("npm")),
        )
        .unwrap();
        let outcome = finish(
            with(LOCK_ENTRY_REMOVED_CODE),
            dir.path(),
            &rel("npm"),
            wet(),
            policy,
        )
        .await;
        assert!(outcome.success && outcome.kept_artifact);
        assert!(dir.path().join(rel("npm")).is_dir());

        // Proven unreferenced: the artifact goes.
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "x: 1.0.0\n").unwrap();
        let outcome = finish(
            with(LOCK_ENTRY_REMOVED_CODE),
            dir.path(),
            &rel("npm"),
            wet(),
            policy,
        )
        .await;
        assert!(outcome.success && !outcome.kept_artifact);
        assert!(!dir.path().join(rel("npm")).exists());

        // The other policies never consult the locks for a removed entry.
        for policy in [policies()[0], policies()[1]] {
            let dir = project("npm");
            std::fs::write(
                dir.path().join("pnpm-lock.yaml"),
                format!("x: file:{}/pkg.tgz\n", rel("npm")),
            )
            .unwrap();
            let outcome = finish(
                with(LOCK_ENTRY_REMOVED_CODE),
                dir.path(),
                &rel("npm"),
                wet(),
                policy,
            )
            .await;
            assert!(outcome.success && !outcome.kept_artifact, "{policy:?}");
            assert!(!dir.path().join(rel("npm")).exists(), "{policy:?}");
        }
    }

    /// A symlinked vendor level makes the containment guard refuse the
    /// delete (works as root, unlike a read-only parent).
    #[cfg(unix)]
    fn undeletable(eco: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join(UUID)).unwrap();
        std::fs::create_dir_all(dir.path().join(".socket/vendor")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(format!(".socket/vendor/{eco}")))
            .unwrap();
        dir
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_deletion_keeps_the_warnings_outside_the_npm_family() {
        for policy in [policies()[0], policies()[1]] {
            let dir = undeletable("gem");
            let outcome = finish(
                with(LOCK_ENTRY_REMOVED_CODE),
                dir.path(),
                &rel("gem"),
                wet(),
                policy,
            )
            .await;
            assert!(!outcome.success && !outcome.kept_artifact, "{policy:?}");
            let expected = format!(
                "failed to remove {}: ",
                dir.path().join(rel("gem")).display()
            );
            assert!(
                outcome
                    .error
                    .as_deref()
                    .is_some_and(|e| e.starts_with(&expected)),
                "{policy:?}: {:?}",
                outcome.error
            );
            assert_eq!(outcome.warnings.len(), 1, "{policy:?}");
            assert!(dir.path().join("elsewhere").join(UUID).is_dir());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_deletion_fails_bare_in_the_npm_family() {
        let dir = undeletable("npm");
        let outcome = finish(
            RevertOutcome::ok(),
            dir.path(),
            &rel("npm"),
            wet(),
            policies()[2],
        )
        .await;
        assert!(!outcome.success && !outcome.kept_artifact);
        let expected = format!("cannot remove {}: ", rel("npm"));
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with(&expected)),
            "{:?}",
            outcome.error
        );
        assert!(outcome.warnings.is_empty());
        assert!(dir.path().join("elsewhere").join(UUID).is_dir());
    }
}
