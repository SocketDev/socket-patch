//! The CLI consent gate. --yes, --force, UUID selection and socket.yml do
//! not grant permission to combine a Socket patch with a project's own patch.
//!
//! The project's own patches are what the walk of `UserPatchIndex` reads
//! (pnpm, yarn, patch-package, Composer, Cargo, Go) and, under a Bazel
//! workspace, what its Starlark declares: a `patches` entry, a
//! `pip.override`, a `crate.annotation`, a replacement tag (design HZ-17).
//! The second list is `bazel::consent`'s, the one the lane gate and `vex`
//! judge, read for every Bazel root at or above the scope root.

use std::path::Path;

use socket_patch_core::bazel::exec;
use socket_patch_core::bazel::model::{Index, Site};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::patch::user_patches::{ReadScope, UserPatchIndex};

use crate::args::GlobalArgs;
use crate::bazel_gate::{IndexState, Loader, RunCx};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

pub(crate) const CONFLICT: &str = "user_patch_conflict";
pub(crate) const ALLOWED: &str = "user_patch_override";

/// Ecosystems the walk reads evidence for. A purl of another ecosystem
/// can conflict only with a declaration of a Bazel workspace
/// ([`UserPatchIndex::bazel_detects`]: PyPI and Maven beside these).
const DETECTED: &[&str] = &["pkg:npm/", "pkg:composer/", "pkg:cargo/", "pkg:golang/"];

/// Whether any of `purls` could match project evidence, so a run with no
/// such purl (an empty or pypi-only manifest) skips discovery entirely.
/// A PyPI or Maven purl counts only under a Bazel workspace, which is the
/// one place evidence for it comes from: where no workspace file lies at
/// or above the scope root, the answer costs that purl a few stats and is
/// what it was before.
fn any_detectable<'a>(common: &GlobalArgs, purls: impl Iterator<Item = &'a str>) -> bool {
    let mut under_a_hub = false;
    for purl in purls.filter(|purl| common.purl_ecosystem_selected(purl)) {
        let walked = DETECTED.iter().any(|prefix| {
            purl.get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        });
        if walked {
            return true;
        }
        under_a_hub = under_a_hub || UserPatchIndex::bazel_detects(purl);
    }
    under_a_hub && under_bazel(common)
}

/// What the loader of a consent check is told about the run: it reads and
/// writes nothing, whatever the command it runs for goes on to do.
fn run_cx(common: &GlobalArgs) -> RunCx {
    RunCx {
        read_only: true,
        dry_run: common.dry_run,
        ..RunCx::default()
    }
}

/// Whether a Bazel workspace file lies at or above the scope root, inside
/// the repository. Stats only. A global run inspects no project, so it
/// has none.
fn under_bazel(common: &GlobalArgs) -> bool {
    let workspace = common.read_scope() == ReadScope::Workspace;
    workspace
        && !Loader::new(run_cx(common))
            .survey(&common.cwd)
            .roots
            .is_empty()
}

pub(crate) async fn inspect(common: &GlobalArgs) -> UserPatchIndex {
    match common.read_scope() {
        // A local checkout does not govern a separately selected global
        // tree, so a global run inspects no project (it would read one
        // with no repository bound, `ReadScope::Global`).
        ReadScope::Global => UserPatchIndex::default(),
        scope @ ReadScope::Workspace => {
            let mut index = UserPatchIndex::discover_scoped(&common.cwd, scope).await;
            index.absorb(bazel_declarations(common).await);
            index
        }
    }
}

/// [`starlark`] for this check, read where the blocking walks of a
/// command run.
///
/// The check has a loader of its own, so it sees the files as they are
/// now, whatever the command has written since its own load: the callers
/// hand this module their arguments and nothing else. It costs one read
/// of each root per check. A caller that holds the run's loader, and
/// tells it of its commits, can hand [`starlark`] that one instead.
async fn bazel_declarations(common: &GlobalArgs) -> UserPatchIndex {
    let (cwd, run) = (common.cwd.clone(), run_cx(common));
    let read = move || starlark(&Loader::new(run), &cwd);
    match tokio::task::spawn_blocking(read).await {
        Ok(index) => index,
        // The task did not run to its end (the runtime is shutting down,
        // or the reader panicked). "No declaration" is not an answer a
        // consent check may make up: read on this thread, where a panic
        // is this command's own.
        Err(_) => starlark(&Loader::new(run), &common.cwd),
    }
}

/// What the Bazel workspaces at and above `cwd` declare about packages of
/// their own, as evidence for the consent gate.
///
/// Under no Bazel root this stats and reads nothing more. Otherwise every
/// root between the scope root and the repository root counts, the
/// nearest and the ones above it: a nested workspace file does not cut
/// its directory out of the outer workspace (design 2.2). A workspace
/// file above the repository is not read and adds nothing here: no hosted
/// or vendored patch is written under one (design 2.12, obligation 1;
/// owner decision O15), and the run says that it is there.
///
/// The own-wiring filter is the lane gate's, `exec::own_site` over the
/// root's owned index. An index that cannot be relied on proves no
/// statement socket-patch's own, so every declaration is the user's.
///
/// What `loader` queues to say about the workspace is left to the command
/// whose run it is.
fn starlark(loader: &Loader, cwd: &Path) -> UserPatchIndex {
    let mut found = UserPatchIndex::default();
    if loader.survey(cwd).roots.is_empty() {
        return found;
    }
    let loaded = loader.load(cwd);
    let unproven = Index::default();
    for root in loaded.roots() {
        let at = root.root();
        // A file of the scope root is reported as the walk reports it,
        // under the directory as the command spells it, so that a pnpm
        // lock both of them read is one source. A root above is reported
        // at its resolved path, as the walk reports an ancestor.
        let shown = match at.project_rel.is_empty() {
            true => std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf()),
            false => at.root.clone(),
        };
        match root.model() {
            Ok(ws) => {
                let rows = match root.index() {
                    IndexState::Ours(index) => index,
                    IndexState::Faulty(_) => &unproven,
                };
                let own = |site: &Site, _: Option<&str>| exec::own_site(rows, site);
                found.add_bazel(&shown, ws, &own);
            }
            Err(gap) => found.bazel_unreadable(&shown, gap),
        }
    }
    found
}

/// The project-patch sources protecting `purl`, if its ecosystem is selected
/// and it has any.
fn protecting(common: &GlobalArgs, index: &UserPatchIndex, purl: &str) -> Option<Vec<String>> {
    if !common.purl_ecosystem_selected(purl) {
        return None;
    }
    let sources = index.conflicts(purl);
    (!sources.is_empty()).then_some(sources)
}

/// The `user_patch_conflict` / `user_patch_override` text for `purl`.
/// `unreadable` ([`UserPatchIndex::unreadable_only`]): nothing the project
/// declares protects it, only files that could not be read or parsed. That
/// is a broken file, not a conflict, so the text says to fix it rather than
/// to switch the check off.
pub(crate) fn detail(purl: &str, sources: &[String], allowed: bool, unreadable: bool) -> String {
    let fix = plural(sources);
    let sources = sources.join(", ");
    if unreadable && !allowed {
        return format!(
            "{purl}: not patched, because this project's own patches for it could not be \
             checked: {sources}. Fix {fix} and run again."
        );
    }
    if allowed {
        format!("{purl}: --allow-patch-conflicts permits attempting a Socket patch alongside project patches in {sources}; review and test the combined result. Backend safety checks still apply")
    } else {
        format!("{purl}: protected by project patch/replacement metadata in {sources}; leaving this package untouched. Merge the fixes manually, or explicitly accept the conflict risk with --allow-patch-conflicts (ordinary --yes/--force do not approve this)")
    }
}

/// [`detail`] for every package of `ecosystem` at once, where what
/// protects them is a Bazel declaration that names no single package
/// ([`UserPatchIndex::bazel_ecosystem_wide`]): a computed `patches`
/// argument, a use of a ruleset that led to no hub, a workspace file that
/// could not be read. One such declaration holds back each package of the
/// ecosystem for the same reason, so a run says it once, with the file
/// and what was not read there (the sources), and not once per package.
fn wide_detail(
    ecosystem: Ecosystem,
    sources: &[String],
    allowed: bool,
    unreadable: bool,
) -> String {
    let (packages, fix) = (ecosystem.cli_name(), plural(sources));
    let sources = sources.join(", ");
    if unreadable && !allowed {
        return format!(
            "every {packages} package: not patched, because this project's own patches for \
             them could not be checked: {sources}. Fix {fix} and run again."
        );
    }
    if allowed {
        format!("every {packages} package: --allow-patch-conflicts permits attempting a Socket patch alongside whatever this Bazel workspace patches or replaces itself, which is not known: {sources}; review and test the combined result. Backend safety checks still apply")
    } else {
        format!("every {packages} package: protected, because this Bazel workspace may patch or replace any of them itself, and which ones is not known: {sources}; leaving these packages untouched. Make the declaration name its packages, or explicitly accept the conflict risk with --allow-patch-conflicts (ordinary --yes/--force do not approve this)")
    }
}

/// "that file" or "those files", for the remedy of unreadable `sources`.
fn plural(sources: &[String]) -> &'static str {
    if sources.len() == 1 {
        "that file"
    } else {
        "those files"
    }
}

/// The run-level lines of one consent check. A protected package has a
/// line of its own ([`detail`]); the packages that share a
/// [`wide_detail`] line have it once between them. A loop that reports
/// protected packages one by one keeps one of these for the run.
#[derive(Default)]
pub(crate) struct Lines {
    wide: Vec<String>,
}

impl Lines {
    /// The text for `purl`'s own event, and the line the run adds for it:
    /// `None` when the line its ecosystem shares has been added already.
    pub(crate) fn of(
        &mut self,
        index: &UserPatchIndex,
        purl: &str,
        sources: &[String],
        allowed: bool,
    ) -> (String, Option<String>) {
        let unreadable = index.unreadable_only(purl);
        let own = detail(purl, sources, allowed, unreadable);
        let Some(ecosystem) = index.bazel_ecosystem_wide(purl) else {
            return (own.clone(), Some(own));
        };
        let shared = wide_detail(ecosystem, sources, allowed, unreadable);
        let first = !self.wide.contains(&shared);
        if first {
            self.wide.push(shared.clone());
        }
        (own, first.then_some(shared))
    }
}

/// Explicit-target commands fail before mutation rather than silently succeeding
/// without the requested patch. Approved overrides come back as warnings for
/// the caller to print once (see [`warn`]) and attach to its own envelope.
/// Nothing here downloads or applies the user's patch.
pub(crate) async fn check(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<(String, String)>, EnvelopeError> {
    let sorted = sort(common, purls).await;
    if sorted.conflicts.is_empty() {
        Ok(sorted.warnings)
    } else {
        let mut messages = sorted.refusals;
        messages.sort();
        messages.dedup();
        Err(EnvelopeError::new(CONFLICT, messages.join("\n")))
    }
}

/// [`check`]'s two outcomes kept apart: approved-override warnings, and the
/// `(purl, message)` of each refused conflict.
pub(crate) async fn partition(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let sorted = sort(common, purls).await;
    (sorted.warnings, sorted.conflicts)
}

/// What one consent check found for a selection.
#[derive(Default)]
struct Sorted {
    /// The approved overrides, as run-level warnings.
    warnings: Vec<(String, String)>,
    /// `(purl, message)` of each refused conflict.
    conflicts: Vec<(String, String)>,
    /// What a refusal over `conflicts` says: the message of each, with
    /// the line an ecosystem shares given once ([`Lines`]).
    refusals: Vec<String>,
}

async fn sort(common: &GlobalArgs, purls: impl IntoIterator<Item = impl AsRef<str>>) -> Sorted {
    let purls: Vec<String> = purls.into_iter().map(|p| p.as_ref().to_string()).collect();
    let mut sorted = Sorted::default();
    if !any_detectable(common, purls.iter().map(String::as_str)) {
        return sorted;
    }
    let index = inspect(common).await;
    let mut lines = Lines::default();
    for purl in &purls {
        let purl = purl.as_str();
        let Some(sources) = protecting(common, &index, purl) else {
            continue;
        };
        let (message, line) = lines.of(&index, purl, &sources, common.allow_patch_conflicts);
        if common.allow_patch_conflicts {
            sorted
                .warnings
                .extend(line.map(|line| (ALLOWED.into(), line)));
        } else {
            sorted.conflicts.push((purl.to_string(), message));
            sorted.refusals.extend(line);
        }
    }
    sorted
}

/// The project-patch evidence of each of `purls` that has any, with or
/// without consent: `apply --check` names it on a drift a plain `apply`
/// would leave in place.
pub(crate) async fn evidence(
    common: &GlobalArgs,
    purls: &[&str],
) -> std::collections::HashMap<String, Vec<String>> {
    let mut found = std::collections::HashMap::new();
    if !any_detectable(common, purls.iter().copied()) {
        return found;
    }
    let index = inspect(common).await;
    for &purl in purls {
        if let Some(sources) = protecting(common, &index, purl) {
            found.insert(purl.to_string(), sources);
        }
    }
    found
}

/// The human copy of [`check`]'s approved overrides; JSON carries them in
/// the envelope and `--silent` mutes them.
pub(crate) fn warn(common: &GlobalArgs, warnings: &[(String, String)]) {
    if !common.silent && !common.json {
        for (_, detail) in warnings {
            eprintln!("Warning: {detail}");
        }
    }
}

/// The manifest-wide gate for `apply`: rather than refuse a whole run over
/// one protected entry (a postinstall apply would fail every install), drop
/// the protected records from this run's in-memory copy and report each as
/// a `user_patch_conflict` warning. Approved overrides stay in and come back
/// as `user_patch_override` warnings. Only the caller's copy changes; the
/// manifest on disk is never rewritten here. Also returns skipped events with
/// the evidence and UUID: callers must preserve these outcomes, and nothing may
/// reconcile their records away as dropped.
pub(crate) async fn skip_protected(
    common: &GlobalArgs,
    patches: &mut std::collections::HashMap<
        String,
        socket_patch_core::manifest::schema::PatchRecord,
    >,
) -> (Vec<(String, String)>, Vec<PatchEvent>) {
    let mut warnings = Vec::new();
    let mut skipped = Vec::new();
    if !any_detectable(common, patches.keys().map(String::as_str)) {
        return (warnings, skipped);
    }
    let index = inspect(common).await;
    let mut lines = Lines::default();
    patches.retain(|purl, record| {
        let Some(sources) = protecting(common, &index, purl) else {
            return true;
        };
        let (message, line) = lines.of(&index, purl, &sources, common.allow_patch_conflicts);
        if common.allow_patch_conflicts {
            warnings.extend(line.map(|line| (ALLOWED.into(), line)));
            true
        } else {
            warnings.extend(line.map(|line| (CONFLICT.into(), line)));
            skipped.push(
                PatchEvent::new(PatchAction::Skipped, purl)
                    .with_uuid(&record.uuid)
                    .with_reason(CONFLICT, message),
            );
            false
        }
    });
    warnings.sort();
    skipped.sort_by(|a, b| a.purl.cmp(&b.purl));
    (warnings, skipped)
}

pub(crate) fn refuse(common: &GlobalArgs, command: Command, error: EnvelopeError) -> i32 {
    if common.json {
        let mut env = Envelope::new(command);
        env.dry_run = common.dry_run;
        env.mark_error(error);
        crate::ui::print_json(&env.to_value());
    } else {
        eprintln!("Error: {}", error.message);
    }
    1
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use socket_patch_core::manifest::schema::PatchRecord;

    use super::*;

    #[test]
    fn detail_tells_an_unreadable_file_from_a_declared_patch() {
        let declared = ["/p/package.json".to_string()];
        let blocked = detail("pkg:npm/a@1.0.0", &declared, false, false);
        assert!(
            blocked.starts_with("pkg:npm/a@1.0.0: protected by project patch/replacement metadata in /p/package.json;"),
            "{blocked}"
        );
        assert!(blocked.contains("--allow-patch-conflicts"), "{blocked}");

        // A file that could not be read: say so and how to fix it. Switching
        // the safety check off is not the remedy for a syntax error.
        let unreadable = ["/p/package.json (not valid JSON: EOF at line 2 column 0)".to_string()];
        assert_eq!(
            detail("pkg:npm/a@1.0.0", &unreadable, false, true),
            "pkg:npm/a@1.0.0: not patched, because this project's own patches for it could not \
             be checked: /p/package.json (not valid JSON: EOF at line 2 column 0). Fix that file \
             and run again."
        );
        let two = [
            unreadable[0].clone(),
            "pnpm-lock.yaml (cannot be read: denied)".to_string(),
        ];
        assert!(
            detail("pkg:npm/a@1.0.0", &two, false, true)
                .ends_with(". Fix those files and run again."),
            "{}",
            detail("pkg:npm/a@1.0.0", &two, false, true)
        );
        // Consent given: the override wording is the same for both.
        assert!(detail("pkg:npm/a@1.0.0", &unreadable, true, true)
            .contains("--allow-patch-conflicts permits"),);
    }

    /// The line an ecosystem shares names the ecosystem and never a
    /// package, carries the sources as given, and keeps the three forms
    /// of [`detail`]: a conflict offers the flag, a broken file says to
    /// fix it and does not, consent says what it permits.
    #[test]
    fn the_line_of_a_whole_ecosystem_has_the_three_forms_of_a_package_line() {
        let computed = ["/ws/MODULE.bazel (the declaration is not literal)".to_string()];
        let blocked = wide_detail(Ecosystem::Pypi, &computed, false, false);
        let opens = "every pypi package: protected, because";
        assert!(blocked.starts_with(opens), "{blocked}");
        assert!(blocked.contains(&computed[0]), "{blocked}");
        assert!(blocked.contains("--allow-patch-conflicts"), "{blocked}");

        let broken = ["/ws/MODULE.bazel (MODULE.bazel:3: an unmatched bracket)".to_string()];
        assert_eq!(
            wide_detail(Ecosystem::Npm, &broken, false, true),
            "every npm package: not patched, because this project's own patches for them could \
             not be checked: /ws/MODULE.bazel (MODULE.bazel:3: an unmatched bracket). Fix that \
             file and run again."
        );
        let two = [broken[0].clone(), computed[0].clone()];
        let fix = wide_detail(Ecosystem::Npm, &two, false, true);
        assert!(fix.ends_with(". Fix those files and run again."), "{fix}");
        for unreadable in [false, true] {
            let allowed = wide_detail(Ecosystem::Golang, &broken, true, unreadable);
            let opens = "every golang package: --allow-patch-conflicts permits";
            assert!(allowed.starts_with(opens), "{allowed}");
            assert!(allowed.contains(&broken[0]), "{allowed}");
        }
    }

    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
    const IS_ODD: &str = "pkg:npm/is-odd@3.0.1";
    const REQUESTS: &str = "pkg:pypi/requests@2.31.0";
    const GUAVA: &str = "pkg:maven/com.google.guava/guava@32.1.3-jre";
    const PNPM_LOCK: &str = "lockfileVersion: '9.0'\n";

    /// A rules_js `MODULE.bazel` whose hub carries `attrs`.
    fn js_module(attrs: &str) -> String {
        format!(
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\"{attrs})\n\
             use_repo(npm, \"npm\")\n"
        )
    }

    /// A checkout in a temporary directory, at its resolved path: `.git`
    /// bounds every upward read, so the Bazel roots of a test are the
    /// ones it writes.
    struct Checkout {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Checkout {
        fn new(files: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let checkout = Self { _tmp: tmp, top };
            let fixed = [(".git/HEAD", "ref: refs/heads/main\n")];
            for (rel, text) in fixed.iter().chain(files) {
                let path = checkout.at(rel);
                std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
                std::fs::write(path, text).expect("write");
            }
            checkout
        }

        /// `rel` below the checkout, level by level.
        fn at(&self, rel: &str) -> PathBuf {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(self.top.clone(), |at, level| at.join(level))
        }

        /// The path of `rel` as a source names it.
        fn named(&self, rel: &str) -> String {
            self.at(rel).display().to_string()
        }

        /// The arguments of a run in the directory `rel`.
        fn run_in(&self, rel: &str) -> GlobalArgs {
            GlobalArgs {
                cwd: self.at(rel),
                ..GlobalArgs::default()
            }
        }
    }

    /// Every Bazel root at or above the scope root is read, the nearest
    /// and the ones above it, and none below it. A file of the scope root
    /// is named under the directory as the command spells it, one of a
    /// root above at that root. An owned index that cannot be relied on
    /// proves no statement socket-patch's own, so nothing is subtracted.
    /// A global run inspects no project, so no workspace either.
    #[tokio::test]
    async fn the_gate_reads_the_bazel_roots_at_and_above_the_scope_root() {
        let outer = js_module(", patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"]}");
        let inner = js_module(", patches = {\"is-odd@3.0.1\": [\"//:is-odd.patch\"]}");
        let repo = Checkout::new(&[
            (".bazelversion", "8.4.2\n"),
            ("MODULE.bazel", &outer),
            ("pnpm-lock.yaml", PNPM_LOCK),
            (".socket/bazel/index.json", "{\"name\": \"mine\"}\n"),
            ("svc/MODULE.bazel", &inner),
            ("svc/pnpm-lock.yaml", PNPM_LOCK),
        ]);
        let index = inspect(&repo.run_in("svc")).await;
        assert_eq!(index.conflicts(IS_ODD), [repo.named("svc/MODULE.bazel")]);
        assert_eq!(index.conflicts(LEFT_PAD), [repo.named("MODULE.bazel")]);

        let index = inspect(&repo.run_in("")).await;
        assert_eq!(index.conflicts(LEFT_PAD), [repo.named("MODULE.bazel")]);
        assert_eq!(index.conflicts(IS_ODD), [""; 0]);

        let global = GlobalArgs {
            global: true,
            ..repo.run_in("svc")
        };
        assert!(inspect(&global).await.is_empty() && !under_bazel(&global));
    }

    /// PyPI and Maven have evidence only under Bazel, so a run over such
    /// packages alone builds the index only where a workspace file lies
    /// at or above the scope root. Elsewhere it is skipped, as it always
    /// was, and an ecosystem the run does not select is never a reason to
    /// build it.
    #[tokio::test]
    async fn a_pypi_or_maven_run_is_checked_only_under_a_bazel_workspace() {
        let detectable =
            |common: &GlobalArgs, purl: &str| any_detectable(common, [purl].into_iter());
        let plain = Checkout::new(&[("requirements.txt", "requests==2.31.0\n")]);
        let common = plain.run_in("");
        for purl in [REQUESTS, GUAVA, "pkg:gem/rack@2.2.8"] {
            assert!(!detectable(&common, purl), "{purl}");
        }
        assert!(detectable(&common, LEFT_PAD) && !under_bazel(&common));
        let sorted = sort(&common, [REQUESTS, GUAVA]).await;
        assert!(sorted.conflicts.is_empty() && sorted.warnings.is_empty());

        let module = "bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
            pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
            pip.parse(hub_name = \"pypi\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n\
            pip.override(file = \"requests-2.31.0-py3-none-any.whl\", patches = [\"//:r.patch\"])\n\
            use_repo(pip, \"pypi\")\n";
        let bazel = Checkout::new(&[
            (".bazelversion", "8.4.2\n"),
            ("MODULE.bazel", module),
            ("requirements.txt", "requests==2.31.0 --hash=sha256:aaaa\n"),
            ("svc/package.json", "{}\n"),
        ]);
        // From a directory below the root as well: the root is above it.
        for dir in ["", "svc"] {
            let common = bazel.run_in(dir);
            assert!(detectable(&common, REQUESTS) && detectable(&common, GUAVA));
            // No ruleset with a hook builds gems.
            assert!(!detectable(&common, "pkg:gem/rack@2.2.8"), "{dir}");
            let sorted = sort(&common, [REQUESTS, GUAVA]).await;
            let [(purl, message)] = &sorted.conflicts[..] else {
                panic!("{dir}: {:?}", sorted.conflicts);
            };
            assert_eq!(purl, REQUESTS, "{dir}");
            assert!(message.contains(&bazel.named("MODULE.bazel")), "{message}");
        }
        let npm_only = GlobalArgs {
            ecosystems: Some(vec!["npm".to_string()]),
            ..bazel.run_in("")
        };
        let global = GlobalArgs {
            global: true,
            ..bazel.run_in("")
        };
        assert!(!detectable(&npm_only, REQUESTS) && !detectable(&global, REQUESTS));
    }

    /// ROUTED R-144: what holds back a whole ecosystem is said once, by
    /// the refusal of an explicit command and by the warnings of `apply`,
    /// while every package keeps a message and an event of its own. A
    /// package with a declaration of its own beside it keeps its own
    /// line.
    #[tokio::test]
    async fn a_whole_ecosystem_is_reported_once_and_each_package_keeps_its_event() {
        let own = r#"{"pnpm":{"patchedDependencies":{"is-odd@3.0.1":"p.patch"}}}"#;
        let repo = Checkout::new(&[
            (".bazelversion", "8.4.2\n"),
            ("MODULE.bazel", &js_module(", patches = PATCHES")),
            ("pnpm-lock.yaml", PNPM_LOCK),
            ("package.json", own),
        ]);
        let once = "pkg:npm/%40tootallnate/once@2.0.0";
        let purls = [LEFT_PAD, once, IS_ODD, REQUESTS];
        // `(lines an ecosystem shares, lines)` of what a run says.
        let lines = |list: Vec<String>| {
            let shared = |line: &&String| line.starts_with("every npm package: ");
            (list.iter().filter(shared).count(), list.len())
        };
        let texts = |list: &[(String, String)]| list.iter().map(|(_, text)| text.clone()).collect();

        let common = repo.run_in("");
        let sorted = sort(&common, purls).await;
        let held: Vec<&str> = sorted.conflicts.iter().map(|(purl, _)| &**purl).collect();
        assert_eq!(held, [LEFT_PAD, once, IS_ODD]);
        for (purl, message) in &sorted.conflicts {
            assert!(message.starts_with(&format!("{purl}: ")), "{message}");
        }
        assert_eq!(lines(sorted.refusals), (1, 2));
        let refused = check(&common, purls).await.expect_err("a refusal");
        assert_eq!(refused.code, CONFLICT);
        assert_eq!(refused.message.lines().count(), 2, "{}", refused.message);

        let consent = GlobalArgs {
            allow_patch_conflicts: true,
            ..repo.run_in("")
        };
        let allowed = check(&consent, purls).await.expect("consent lifts it");
        assert!(allowed.iter().all(|(code, _)| code == ALLOWED));
        assert_eq!(lines(texts(&allowed)), (1, 2));

        let manifest = || -> HashMap<String, PatchRecord> {
            let record = |(at, purl): (usize, &&str)| {
                let record = PatchRecord {
                    uuid: format!("9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a9{at}"),
                    exported_at: "2026-01-01T00:00:00Z".to_string(),
                    files: HashMap::new(),
                    vulnerabilities: HashMap::new(),
                    description: String::new(),
                    license: "MIT".to_string(),
                    tier: "free".to_string(),
                };
                (purl.to_string(), record)
            };
            purls.iter().enumerate().map(record).collect()
        };
        let mut patches = manifest();
        let (warnings, skipped) = skip_protected(&common, &mut patches).await;
        assert_eq!(patches.keys().collect::<Vec<_>>(), [REQUESTS]);
        assert!(warnings.iter().all(|(code, _)| code == CONFLICT));
        assert_eq!(lines(texts(&warnings)), (1, 2));
        let events: Vec<&str> = skipped.iter().filter_map(|e| e.purl.as_deref()).collect();
        assert_eq!(events, [once, IS_ODD, LEFT_PAD]);
        for event in &skipped {
            let own = format!("{}: ", event.purl.as_deref().expect("a purl"));
            let reason = event.reason.as_deref().expect("a reason");
            assert!(reason.starts_with(&own), "{reason}");
        }

        let mut patches = manifest();
        let (warnings, skipped) = skip_protected(&consent, &mut patches).await;
        assert!(patches.len() == 4 && skipped.is_empty());
        assert!(warnings.iter().all(|(code, _)| code == ALLOWED));
        assert_eq!(lines(texts(&warnings)), (1, 2));
    }
}
