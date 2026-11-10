//! The finish step every vendored `revert_*` runs once its wiring is
//! restored: the dry-run return, the drift-keep, the `--preserve-state`
//! return and the artifact deletion, in that order. Each backend names its
//! keep rule as a [`KeepPolicy`] instead of re-writing the sequence (#989).

use std::path::Path;

use crate::constants::SOCKET_DIR;
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::any_live_file_references;
use super::npm_flavor::{lock_text_mentions_uuid, uuid_proven_unreferenced};
use super::{RevertOpts, RevertOutcome, VendorWarning};

/// Warning code: a recorded lock entry was re-resolved since vendoring (the
/// dependency was upgraded or re-locked) and no wired file references the
/// artifact any more, so the revert removed it with nothing to restore.
pub(crate) const DEPENDENCY_MOVED_ON_CODE: &str = "vendor_revert_dependency_moved_on";

/// Refusal code: the recorded wiring was restored, but a wired file still
/// resolves through the artifact, so deleting it would break installs.
pub(crate) const STILL_WIRED_CODE: &str = "vendor_lock_still_wired_revert_blocked";

/// How a `vendor_lock_entry_drifted` warning reads when the recorded
/// fragment is still in the lock but resolves somewhere else now.
const RE_RESOLVED: &str = "was re-resolved since vendoring";

/// The `vendor_lock_entry_drifted` warning for a recorded lock fragment
/// (`what`) that is still there but no longer resolves through the entry's
/// artifact: the user upgraded or re-locked the dependency (`now` is what
/// it resolves to, where the fragment says). The fragment is theirs and is
/// left alone, and it is the one kind of left-alone record with nothing to
/// restore later, which [`KeepPolicy::NpmFamily`] reads back.
pub(crate) fn re_resolved(what: std::fmt::Arguments<'_>, now: Option<&str>) -> VendorWarning {
    let now = now.map(|now| format!(" ({now})")).unwrap_or_default();
    VendorWarning::new(
        "vendor_lock_entry_drifted",
        format!("{what} {RE_RESOLVED}{now}; left alone"),
    )
}

/// Whether every record `outcome` left alone was re-resolved elsewhere
/// ([`re_resolved`]). Any other left-alone record (a kind or file this
/// build does not know, a fragment with no recorded original, a taken-over
/// pin the user changed) may still need the ledger entry's recorded
/// originals, so it keeps the artifact and the entry whatever the lock says.
fn only_re_resolved(outcome: &RevertOutcome) -> bool {
    outcome
        .warnings
        .iter()
        .filter(|w| w.code == "vendor_lock_entry_drifted")
        .all(|w| w.detail.contains(RE_RESOLVED))
}

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
    /// The npm family (pnpm, yarn classic, yarn berry): the artifact goes
    /// only once none of `locks` — the files the wiring edits — references
    /// `uuid` any more.
    ///
    /// - A recorded entry that was re-resolved elsewhere ([`re_resolved`])
    ///   or has vanished (`vendor_lock_entry_removed`, #665) keeps the
    ///   artifact while a file still references it. Once every file that
    ///   exists was read and none does, the dependency has moved on
    ///   (upgraded past the patched version, or removed): there is nothing
    ///   left to restore, and keeping the artifact would keep it on every
    ///   later revert too.
    /// - Any other left-alone record (`vendor_lock_entry_drifted`) keeps
    ///   the artifact unconditionally, as [`Self::OnDrift`] does.
    /// - A restore that left nothing alone but did not reach every
    ///   reference in `wired` refuses. `wired` is the subset of `locks`
    ///   where any mention of the uuid is a reference the package manager
    ///   resolves (yarn's lock and manifest). pnpm passes none: an override
    ///   no entry matches names the artifact without resolving through it,
    ///   and its revert checks the lock's entries itself, before it writes.
    ///
    /// A failed deletion fails the whole revert with the relative dir in
    /// the message.
    NpmFamily {
        locks: &'a [&'a str],
        wired: &'a [&'a str],
        uuid: &'a str,
    },
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
    let left_alone = outcome.drift_skipped();
    let drift_keeps = match policy {
        KeepPolicy::OnDrift => left_alone,
        KeepPolicy::OnDriftWhileReferenced(files) => {
            left_alone && any_live_file_references(project_root, files, uuid_dir_rel).await
        }
        KeepPolicy::NpmFamily { locks, uuid, .. } => {
            left_alone
                && !(only_re_resolved(&outcome)
                    && uuid_proven_unreferenced(project_root, locks, uuid).await)
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
    if let KeepPolicy::NpmFamily { locks, wired, uuid } = policy {
        if outcome.lock_entry_removed()
            && !uuid_proven_unreferenced(project_root, locks, uuid).await
        {
            outcome.keep_artifact(uuid_dir_rel);
            return outcome;
        }
        // Nothing was left alone, or what was is proven unreferenced. A
        // file that still names the artifact resolves through a reference
        // the restore never reached: deleting the artifact would fail
        // every later install on the missing tarball. Each file is probed
        // on its own; one that is absent or unreadable references nothing
        // here (the wired revert's missing-file tolerance).
        for file in wired {
            if lock_text_mentions_uuid(project_root, &[file], uuid).await == Some(true) {
                let detail = format!(
                    "refusing to remove {uuid_dir_rel}: after restoring the recorded wiring, \
                     {file} still resolves through it (was the entry re-keyed or hand-copied \
                     since vendoring?) — deleting the artifact would make every subsequent \
                     install fail; restore the pre-vendor {file} (or remove the dependency and \
                     re-lock) and re-run `vendor --revert`"
                );
                outcome.success = false;
                outcome.error = Some(detail.clone());
                outcome
                    .warnings
                    .push(VendorWarning::new(STILL_WIRED_CODE, detail));
                return outcome;
            }
        }
        if left_alone {
            outcome.warnings.push(VendorWarning::new(
                DEPENDENCY_MOVED_ON_CODE,
                format!(
                    "removed {uuid_dir_rel}: the lock entries vendoring wired were re-resolved \
                     since (the dependency was upgraded or re-locked) and no project file \
                     references the vendored artifact any more, so there was nothing left to \
                     restore"
                ),
            ));
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
                wired: LOCKS,
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
    async fn drift_keeps_unconditionally_for_gem() {
        for opts in [wet(), preserve()] {
            let dir = project("gem");
            let outcome = finish(drifted(), dir.path(), &rel("gem"), opts, policies()[0]).await;
            assert!(outcome.success && outcome.kept_artifact);
            assert!(outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"));
            assert!(dir.path().join(rel("gem")).is_dir());
        }
    }

    /// A record the restore left alone because the dependency was
    /// re-resolved elsewhere.
    fn re_resolved_elsewhere() -> RevertOutcome {
        let mut outcome = RevertOutcome::ok();
        outcome.warnings.push(re_resolved(
            format_args!("lock block `left-pad@^1.3.0`"),
            Some("1.3.1"),
        ));
        outcome
    }

    const UPGRADED_LOCK: &str = "left-pad: 1.3.1\n";

    /// In the npm family a re-resolved record keeps the artifact while a
    /// wired file may still resolve through it: one that names the uuid, or
    /// none readable to prove otherwise. Any other left-alone record keeps
    /// it whatever the lock says.
    #[tokio::test]
    async fn npm_family_drift_keeps_while_a_lock_may_name_the_uuid() {
        let wired = format!("x: file:{}/pkg.tgz\n", rel("npm"));
        let mut mixed = re_resolved_elsewhere();
        mixed.warnings.extend(drifted().warnings);
        let cases = [
            (re_resolved_elsewhere(), Some(wired.as_str())),
            (re_resolved_elsewhere(), None),
            (drifted(), Some(wired.as_str())),
            (drifted(), Some(UPGRADED_LOCK)),
            (mixed, Some(UPGRADED_LOCK)),
        ];
        for (outcome, lock) in cases {
            for opts in [wet(), preserve()] {
                let dir = project("npm");
                if let Some(text) = lock {
                    std::fs::write(dir.path().join("pnpm-lock.yaml"), text).unwrap();
                }
                let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
                let mut again = RevertOutcome::ok();
                again.warnings.clone_from(&outcome.warnings);
                let outcome = finish(again, dir.path(), &rel("npm"), opts, policies()[2]).await;
                assert!(
                    outcome.success && outcome.kept_artifact,
                    "{codes:?} {lock:?}"
                );
                assert!(outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_artifact_kept"));
                assert!(dir.path().join(rel("npm")).is_dir(), "{codes:?} {lock:?}");
            }
        }
    }

    /// Once every wired file that exists was read and none names the uuid,
    /// the re-resolved dependency has moved on: the revert finishes (and
    /// says why) instead of keeping the artifact on every later run.
    #[tokio::test]
    async fn npm_family_drift_finishes_once_no_lock_names_the_uuid() {
        let dir = project("npm");
        std::fs::write(dir.path().join("pnpm-lock.yaml"), UPGRADED_LOCK).unwrap();
        let outcome = finish(
            re_resolved_elsewhere(),
            dir.path(),
            &rel("npm"),
            wet(),
            policies()[2],
        )
        .await;
        assert!(outcome.success && !outcome.kept_artifact);
        let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
        assert_eq!(
            codes,
            ["vendor_lock_entry_drifted", DEPENDENCY_MOVED_ON_CODE],
            "the left-alone record stays reported, the keep does not"
        );
        assert!(!dir.path().join(rel("npm")).exists());

        // `--preserve-state` deletes nothing, so it claims no removal.
        let dir = project("npm");
        std::fs::write(dir.path().join("pnpm-lock.yaml"), UPGRADED_LOCK).unwrap();
        let outcome = finish(
            re_resolved_elsewhere(),
            dir.path(),
            &rel("npm"),
            preserve(),
            policies()[2],
        )
        .await;
        assert!(outcome.success && !outcome.kept_artifact);
        assert_eq!(outcome.warnings.len(), 1);
        assert!(dir.path().join(rel("npm")).is_dir());
    }

    /// A restore that left nothing alone but did not reach every reference
    /// (one added after vendoring) must not delete the artifact the lock
    /// still installs from, nor report success.
    #[tokio::test]
    async fn npm_family_refuses_a_clean_restore_that_left_a_reference() {
        let dir = project("npm");
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            format!("x: file:{}/pkg.tgz\n", rel("npm")),
        )
        .unwrap();
        let outcome = finish(
            RevertOutcome::ok(),
            dir.path(),
            &rel("npm"),
            wet(),
            policies()[2],
        )
        .await;
        assert!(!outcome.success && !outcome.kept_artifact);
        assert!(outcome.warnings.iter().any(|w| w.code == STILL_WIRED_CODE));
        let error = outcome.error.unwrap_or_default();
        assert!(
            error.contains("pnpm-lock.yaml still resolves through it"),
            "{error}"
        );
        assert!(dir.path().join(rel("npm")).is_dir());

        // `--preserve-state` never deletes, so it has nothing to refuse.
        let outcome = finish(
            RevertOutcome::ok(),
            dir.path(),
            &rel("npm"),
            preserve(),
            policies()[2],
        )
        .await;
        assert!(outcome.success && outcome.warnings.is_empty());
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

    /// The keep-check reads every spelling a lock may give the uuid dir: an
    /// older composer.lock's `\/`-escaped JSON slashes, single and doubled
    /// Windows backslashes, `./` / `file:` prefixes. A plain text match
    /// missed them and deleted an artifact the lock still installs from.
    #[tokio::test]
    async fn drift_keeps_while_a_live_file_names_the_uuid_dir_in_any_spelling() {
        let policy = KeepPolicy::OnDriftWhileReferenced(&["composer.lock"]);
        let rel = rel("composer");
        let spellings = [
            format!(
                "{{\"dist\": {{\"type\": \"path\", \"url\": \"{}\\/psr\\/log@3.0.2\"}}}}",
                rel.replace('/', "\\/")
            ),
            format!("{{\"url\": \"{}\\psr\"}}", rel.replace('/', "\\")),
            format!("{{\"url\": \"{}\\\\psr\"}}", rel.replace('/', "\\\\")),
            format!("{{\"url\": \"./{rel}/psr\"}}"),
            format!("{{\"url\": \"file:{rel}/psr\"}}"),
        ];
        for lock in spellings {
            let dir = project("composer");
            std::fs::write(dir.path().join("composer.lock"), &lock).unwrap();
            let outcome = finish(drifted(), dir.path(), &rel, wet(), policy).await;
            assert!(outcome.success && outcome.kept_artifact, "{lock}");
            assert!(dir.path().join(&rel).is_dir(), "{lock}");
        }

        // Another uuid's dir, in any spelling, is no reference to this one.
        let other = rel.replace(UUID, "99999999-2222-4333-8444-555555555555");
        for lock in [
            format!("{{\"url\": \"{}\\/psr\"}}", other.replace('/', "\\/")),
            format!("{{\"url\": \"{}\\psr\"}}", other.replace('/', "\\")),
            format!("{{\"url\": \"{other}/psr\"}}"),
        ] {
            let dir = project("composer");
            std::fs::write(dir.path().join("composer.lock"), &lock).unwrap();
            let outcome = finish(drifted(), dir.path(), &rel, wet(), policy).await;
            assert!(outcome.success && !outcome.kept_artifact, "{lock}");
            assert!(!dir.path().join(&rel).exists(), "{lock}");
        }
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
