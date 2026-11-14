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
use socket_patch_core::bazel::govern::WORKSPACE_UNREADABLE;
use socket_patch_core::bazel::model::{BazelWorkspace, Gap, Index, Site};
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
/// the repository: a root the check reads, or a workspace the project
/// could not be placed under ([`Loader::unplaced`]), which protects like
/// a root with no model. Stats only. A global run inspects no project, so
/// it has none.
fn under_bazel(common: &GlobalArgs) -> bool {
    if common.read_scope() != ReadScope::Workspace {
        return false;
    }
    let loader = Loader::new(run_cx(common));
    !loader.survey(&common.cwd).roots.is_empty() || loader.unplaced(&common.cwd).is_some()
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
    read_apart(&common.cwd, move || starlark(&Loader::new(run), &cwd)).await
}

/// What `read` finds, run on a blocking thread.
///
/// A read that does not come back (the reader panicked, or the runtime is
/// shutting down) is answered here and never run a second time: the
/// reader is deterministic over the same files, so on this thread it
/// would stop the command the same way, and a command that dies in its
/// consent check fails every install whose hook runs it. "No declaration"
/// is not an answer a consent check may make up either. So the workspace
/// at `cwd` counts as one that could not be read: every package a ruleset
/// with a hook can build is held back, the run says why, and it ends like
/// any other run that skipped packages.
async fn read_apart(
    cwd: &Path,
    read: impl FnOnce() -> UserPatchIndex + Send + 'static,
) -> UserPatchIndex {
    match tokio::task::spawn_blocking(read).await {
        Ok(index) => index,
        Err(_) => {
            let gap = Gap {
                token: WORKSPACE_UNREADABLE,
                file: String::new(),
                detail: "socket-patch stopped while it read the Bazel workspace files at or \
                         above this directory, which is a defect of this version: please report \
                         it"
                .to_string(),
            };
            let mut found = UserPatchIndex::default();
            found.bazel_unreadable(&shown(cwd), &gap);
            found
        }
    }
}

/// The scope root as the walk reports a file of it: under the directory as
/// the command spells it.
fn shown(cwd: &Path) -> std::path::PathBuf {
    std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf())
}

/// What the Bazel workspaces at and above `cwd` declare about packages of
/// their own, as evidence for the consent gate.
///
/// Under no Bazel root this stats and reads nothing more. Otherwise every
/// root between the scope root and the repository root counts, the
/// nearest and the ones above it: a nested workspace file does not cut
/// its directory out of the outer workspace (design 2.2).
///
/// A workspace inside the repository that the project cannot be placed
/// under ([`Loader::unplaced`]) has no root to read and is no less a
/// workspace: it protects like a root with no model, as the loader
/// reports it unreadable.
///
/// A workspace file above the repository is not read and adds nothing
/// here, confirmed or not: no hosted or vendored patch is written under
/// one (design 2.12, obligation 1; owner decision O15), and the run says
/// that it is there. Holding five ecosystems back in every checkout that
/// lies below some Bazel workspace would cost each of them its installed
/// patches over a file this run may not read.
///
/// What `loader` queues to say about the workspace is left to the command
/// whose run it is.
fn starlark(loader: &Loader, cwd: &Path) -> UserPatchIndex {
    let mut found = UserPatchIndex::default();
    if loader.survey(cwd).roots.is_empty() {
        if let Some(marker) = loader.unplaced(cwd) {
            found.bazel_unreadable(&marker, &unplaced());
        }
        return found;
    }
    let loaded = loader.load(cwd);
    for root in loaded.roots() {
        let at = root.root();
        // A file of the scope root is reported as the walk reports it,
        // under the directory as the command spells it, so that a pnpm
        // lock both of them read is one source. A root above is reported
        // at its resolved path, as the walk reports an ancestor.
        let at = match at.project_rel.is_empty() {
            true => shown(cwd),
            false => at.root.clone(),
        };
        declared(&mut found, &at, root.model(), root.index(), &exec::own_site);
    }
    found
}

/// What one Bazel root adds to `found`, reported under `shown`.
///
/// A root with no model (`Err`: none of its boundary files could be read)
/// protects every package a ruleset with a hook can build until the file
/// is fixed. One with a model adds what it declares, less socket-patch's
/// own wiring: `claims` is the lane gate's filter, `exec::own_site`, asked
/// over the root's owned index. An index that cannot be relied on proves
/// no statement socket-patch's own, so the filter is not asked at all and
/// every declaration is the user's.
fn declared(
    found: &mut UserPatchIndex,
    shown: &Path,
    model: Result<&BazelWorkspace, &Gap>,
    index: &IndexState,
    claims: &dyn Fn(&Index, &Site) -> bool,
) {
    match model {
        Ok(ws) => {
            let own = |site: &Site, _: Option<&str>| match index {
                IndexState::Ours(rows) => claims(rows, site),
                IndexState::Faulty(_) => false,
            };
            found.add_bazel(shown, ws, &own);
        }
        Err(gap) => found.bazel_unreadable(shown, gap),
    }
}

/// Why a workspace the project cannot be placed under has nothing read:
/// the loader's own words for it (`Code::WorkspaceUnreadable`). The source
/// it follows is the workspace file.
fn unplaced() -> Gap {
    Gap {
        token: WORKSPACE_UNREADABLE,
        file: String::new(),
        detail: "this project's directory cannot be named under the Bazel workspace of this \
                 file: a directory name between them is not UTF-8, or the working directory \
                 could not be read"
            .to_string(),
    }
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

/// What holds a package back, which decides what its line tells the user
/// to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// The project declares a patch or a replacement of it: the user
    /// merges the fixes, or accepts the conflict risk.
    Declared,
    /// Nothing the project declares protects it, only files that could
    /// not be read or parsed ([`UserPatchIndex::unreadable_only`]). That
    /// is a broken file, not a conflict, so the text says to fix it
    /// rather than to switch the check off.
    Unreadable,
    /// Nothing protects it but replacements in a Bazel workspace
    /// ([`UserPatchIndex::bazel_replaced_only`]): Bazel builds something
    /// else in its place, with or without consent, so the remedy for that
    /// build is to remove the replacement, and the flag is offered for
    /// what it permits, the installed copy.
    ReplacedInBazel,
}

impl Held {
    fn of(index: &UserPatchIndex, purl: &str) -> Self {
        if index.unreadable_only(purl) {
            Self::Unreadable
        } else if index.bazel_replaced_only(purl) {
            Self::ReplacedInBazel
        } else {
            Self::Declared
        }
    }
}

/// The `user_patch_conflict` / `user_patch_override` text for `purl`.
fn detail(purl: &str, sources: &[String], allowed: bool, held: Held) -> String {
    let fix = plural(sources);
    let sources = sources.join(", ");
    if allowed {
        return format!("{purl}: --allow-patch-conflicts permits attempting a Socket patch alongside project patches in {sources}; review and test the combined result. Backend safety checks still apply");
    }
    match held {
        Held::Unreadable => format!(
            "{purl}: not patched, because this project's own patches for it could not be \
             checked: {sources}. Fix {fix} and run again."
        ),
        Held::ReplacedInBazel => format!("{purl}: protected by a replacement in {sources}; leaving this package untouched. Remove the replacement to have the package patched where Bazel builds it; --allow-patch-conflicts permits patching the installed copy only (ordinary --yes/--force do not approve this)"),
        Held::Declared => format!("{purl}: protected by project patch/replacement metadata in {sources}; leaving this package untouched. Merge the fixes manually, or explicitly accept the conflict risk with --allow-patch-conflicts (ordinary --yes/--force do not approve this)"),
    }
}

/// [`detail`] for every package of `ecosystem` at once, where what
/// protects them is a Bazel declaration that names no single package
/// ([`UserPatchIndex::bazel_ecosystem_wide`]): a computed `patches`
/// argument, a use of a ruleset that led to no hub, a statement that was
/// not read, a workspace file that could not be read. One such
/// declaration holds back each package of the ecosystem for the same
/// reason, so a run says it once, with the file and what was not read
/// there (the sources), and not once per package.
///
/// The remedy names no one edit: the sources say what was not read, and
/// not each of them is a declaration the user can make name its packages
/// (a call in a macro file, the `annotations` of a rule). Where it can be
/// written as a literal the gate reads it; where it cannot, the flag is
/// how the user says the workspace patches none of them.
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
        format!("every {packages} package: protected, because this Bazel workspace may patch or replace any of them itself, and which ones is not known: {sources}; leaving these packages untouched. Where what is named there can be written as a literal declaration, do that; otherwise explicitly accept the conflict risk with --allow-patch-conflicts (ordinary --yes/--force do not approve this)")
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
        let held = Held::of(index, purl);
        let own = detail(purl, sources, allowed, held);
        let Some(ecosystem) = index.bazel_ecosystem_wide(purl) else {
            return (own.clone(), Some(own));
        };
        let shared = wide_detail(ecosystem, sources, allowed, held == Held::Unreadable);
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
    let sorted = partition(common, purls).await;
    if sorted.conflicts.is_empty() {
        Ok(sorted.warnings)
    } else {
        Err(EnvelopeError::new(CONFLICT, sorted.refusals.join("\n")))
    }
}

/// [`check`]'s outcomes kept apart, for a caller that reports a refusal
/// its own way (`vendor`, which may have written before it checks). The
/// refusal lines are sorted, each once.
pub(crate) async fn partition(
    common: &GlobalArgs,
    purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> Sorted {
    let mut sorted = sort(common, purls).await;
    sorted.refusals.sort();
    sorted.refusals.dedup();
    sorted
}

/// What one consent check found for a selection.
#[derive(Default)]
pub(crate) struct Sorted {
    /// The approved overrides, as run-level warnings.
    pub(crate) warnings: Vec<(String, String)>,
    /// `(purl, message)` of each refused conflict: what the package's own
    /// event says.
    pub(crate) conflicts: Vec<(String, String)>,
    /// What a refusal over `conflicts` says to the run: the message of
    /// each, with the line an ecosystem shares given once ([`Lines`]).
    pub(crate) refusals: Vec<String>,
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
        let blocked = detail("pkg:npm/a@1.0.0", &declared, false, Held::Declared);
        assert!(
            blocked.starts_with("pkg:npm/a@1.0.0: protected by project patch/replacement metadata in /p/package.json;"),
            "{blocked}"
        );
        assert!(blocked.contains("--allow-patch-conflicts"), "{blocked}");

        // A file that could not be read: say so and how to fix it. Switching
        // the safety check off is not the remedy for a syntax error.
        let unreadable = ["/p/package.json (not valid JSON: EOF at line 2 column 0)".to_string()];
        assert_eq!(
            detail("pkg:npm/a@1.0.0", &unreadable, false, Held::Unreadable),
            "pkg:npm/a@1.0.0: not patched, because this project's own patches for it could not \
             be checked: /p/package.json (not valid JSON: EOF at line 2 column 0). Fix that file \
             and run again."
        );
        let two = [
            unreadable[0].clone(),
            "pnpm-lock.yaml (cannot be read: denied)".to_string(),
        ];
        assert!(
            detail("pkg:npm/a@1.0.0", &two, false, Held::Unreadable)
                .ends_with(". Fix those files and run again."),
            "{}",
            detail("pkg:npm/a@1.0.0", &two, false, Held::Unreadable)
        );
        // Consent given: the override wording is the same for each.
        for held in [Held::Declared, Held::Unreadable, Held::ReplacedInBazel] {
            assert!(detail("pkg:npm/a@1.0.0", &unreadable, true, held)
                .contains("--allow-patch-conflicts permits"),);
        }
    }

    /// Review finding consent-design-4. A package that only a Bazel
    /// replacement protects is not patched in that build whatever the
    /// consent, so its line names the remedy that works there, removing
    /// the replacement, and offers the flag for what it permits: the
    /// installed copy. It never tells the user to merge fixes into a
    /// patch there is none of.
    #[test]
    fn a_package_only_a_bazel_replacement_protects_is_told_the_remedy_that_works() {
        let replaced = [
            "/ws/MODULE.bazel (replaces the package in the Bazel build, where a \
                         hosted or vendored Socket patch of it is refused with or without \
                         --allow-patch-conflicts)"
                .to_string(),
        ];
        let line = detail("pkg:npm/a@1.0.0", &replaced, false, Held::ReplacedInBazel);
        let opens = "pkg:npm/a@1.0.0: protected by a replacement in /ws/MODULE.bazel (";
        assert!(line.starts_with(opens), "{line}");
        assert!(line.contains("Remove the replacement"), "{line}");
        let flag = "--allow-patch-conflicts permits patching the installed copy only";
        assert!(line.contains(flag), "{line}");
        assert!(
            !line.contains("Merge the fixes") && !line.contains("accept the conflict risk"),
            "{line}"
        );
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

    /// The five ecosystems a Bazel declaration can protect, one package of
    /// each, and one of an ecosystem none can.
    const HOOKED: [&str; 5] = [
        LEFT_PAD,
        REQUESTS,
        GUAVA,
        "pkg:cargo/serde@1.0.200",
        "pkg:golang/github.com/foo/bar@v1.2.3",
    ];
    const RACK: &str = "pkg:gem/rack@2.2.8";

    /// Asserts that `index` holds every package of [`HOOKED`] back for
    /// one source that opens with `source`, as a file to fix and not as a
    /// conflict to accept, with one line per ecosystem.
    fn assert_all_unreadable(index: &UserPatchIndex, source: &str) {
        let mut lines = Lines::default();
        for purl in HOOKED {
            let sources = index.conflicts(purl);
            assert!(
                sources.len() == 1 && sources[0].starts_with(source),
                "{purl}: {sources:?}"
            );
            assert!(index.unreadable_only(purl), "{purl}");
            let (own, shared) = lines.of(index, purl, &sources, false);
            let shared = shared.expect("the first package of its ecosystem");
            for line in [&own, &shared] {
                assert!(line.ends_with(". Fix that file and run again."), "{line}");
                assert!(!line.contains("--allow-patch-conflicts"), "{line}");
            }
        }
        assert_eq!(index.conflicts(RACK), [""; 0]);
    }

    /// Review finding H5: the two arms of a root that fail closed. A root
    /// with no model protects every ecosystem a hook can build for, as a
    /// file to fix. A root whose owned index cannot be relied on has no
    /// statement proven socket-patch's own: a filter that would claim the
    /// declaration over a sound index is not asked, and the declaration
    /// stays the user's.
    #[test]
    fn a_root_with_no_model_or_with_a_faulty_index_fails_closed() {
        use socket_patch_core::bazel::exec::IndexFault;

        let gap = Gap {
            token: WORKSPACE_UNREADABLE,
            file: String::new(),
            detail: "the root holds no workspace file that can be read".to_string(),
        };
        let claims_all = |_: &Index, _: &Site| true;
        let sound = IndexState::Ours(Index::default());
        let mut found = UserPatchIndex::default();
        declared(&mut found, Path::new("ws"), Err(&gap), &sound, &claims_all);
        assert_all_unreadable(&found, "ws (the root holds no workspace file");

        let patched = js_module(", patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"]}");
        let repo = Checkout::new(&[
            (".bazelversion", "8.4.2\n"),
            ("MODULE.bazel", &patched),
            ("pnpm-lock.yaml", PNPM_LOCK),
        ]);
        let loaded = Loader::new(RunCx::default()).load(&repo.at(""));
        let root = loaded.roots().next().expect("the root");
        let ws = root.model().expect("a model");
        let over = |index: &IndexState, claims: &dyn Fn(&Index, &Site) -> bool| {
            let mut found = UserPatchIndex::default();
            declared(&mut found, &repo.at(""), Ok(ws), index, claims);
            found.conflicts(LEFT_PAD)
        };
        let users = [repo.named("MODULE.bazel")];
        // The filter is the one asked over a sound index: what it claims
        // is subtracted, and the real one claims nothing in this build.
        assert_eq!(over(&sound, &claims_all), [""; 0]);
        assert_eq!(over(&sound, &exec::own_site), users);
        for fault in [
            IndexFault::Foreign,
            IndexFault::Unreadable,
            IndexFault::Modified("a row was edited".to_string()),
        ] {
            let faulty = IndexState::Faulty(fault);
            assert_eq!(over(&faulty, &claims_all), users, "{faulty:?}");
        }
    }

    /// Review finding H6: a read that does not come back is not run a
    /// second time on the command's own thread, where the same panic
    /// would end the command, and is not "no declaration" either. The
    /// workspace counts as one that could not be read, at the scope root.
    #[tokio::test]
    async fn a_read_that_does_not_come_back_protects_and_is_not_run_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let repo = Checkout::new(&[]);
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let read = move || -> UserPatchIndex {
            counted.fetch_add(1, Ordering::SeqCst);
            panic!("a reader that fails (expected by this test)");
        };
        let found = read_apart(&repo.at(""), read).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let source = format!("{} (socket-patch stopped while it read", repo.named(""));
        assert_all_unreadable(&found, &source);

        // A read that comes back is the answer, whatever it found.
        let found = read_apart(&repo.at(""), UserPatchIndex::default).await;
        assert!(found.is_empty());
    }

    /// Review finding consent-design-3, shape (2), and disclosed
    /// deviation 7: a workspace file above the repository is never read,
    /// so what it declares protects nothing here, confirmed or not, and a
    /// PyPI-only run under one is not checked. (Hosted and vendored
    /// patches are refused under a confirmed one by the lane gate, and the
    /// run says that the file is there.)
    #[tokio::test]
    async fn a_workspace_above_the_repository_adds_nothing_to_the_check() {
        let outer = js_module(", patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"]}");
        for confirmed in [true, false] {
            let mut files = vec![
                ("MODULE.bazel", outer.as_str()),
                ("pnpm-lock.yaml", PNPM_LOCK),
                ("repo/.git/HEAD", "ref: refs/heads/main\n"),
                ("repo/package.json", "{}\n"),
            ];
            if confirmed {
                files.push((".bazelversion", "8.4.2\n"));
            }
            let above = Checkout::new(&files);
            let common = above.run_in("repo");
            let loader = Loader::new(run_cx(&common));
            let survey = loader.survey(&common.cwd);
            assert!(survey.roots.is_empty() && survey.above.is_some());
            assert_eq!(loader.unplaced(&common.cwd), None);
            assert!(!under_bazel(&common), "{confirmed}");
            let index = inspect(&common).await;
            assert_eq!(index.conflicts(LEFT_PAD), [""; 0], "{confirmed}");
            // The same file inside the repository holds the package back.
            let index = inspect(&above.run_in("")).await;
            assert_eq!(index.conflicts(LEFT_PAD), [above.named("MODULE.bazel")]);
        }
    }

    /// Review finding consent-design-3, shape (1): what a workspace the
    /// project cannot be placed under adds. The loader reports it as a
    /// workspace it cannot read, and so does the check: every ecosystem a
    /// hook can build for is held back as by a root with no model, with
    /// the workspace file as the source.
    #[test]
    fn a_workspace_the_project_cannot_be_placed_under_protects_like_one_with_no_model() {
        let marker = Path::new("ws").join("MODULE.bazel");
        let mut found = UserPatchIndex::default();
        found.bazel_unreadable(&marker, &unplaced());
        let source = format!(
            "{} (this project's directory cannot be named",
            marker.display()
        );
        assert_all_unreadable(&found, &source);
    }

    /// The same, end to end over a disk. (Linux only: the disks of macOS
    /// and Windows refuse a directory name that is not Unicode.)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_unplaced_project_is_checked_and_protected() {
        use std::os::unix::ffi::OsStrExt as _;
        let repo = Checkout::new(&[
            (".bazelversion", "8.4.2\n"),
            ("MODULE.bazel", &js_module("")),
            ("pnpm-lock.yaml", PNPM_LOCK),
        ]);
        let odd = repo.top.join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
        let project = odd.join("app");
        std::fs::create_dir_all(&project).expect("a directory whose name is not UTF-8");
        let common = GlobalArgs {
            cwd: project,
            ..GlobalArgs::default()
        };
        // No root to read, and a workspace all the same: a PyPI-only run
        // is checked.
        assert!(under_bazel(&common));
        assert!(any_detectable(&common, [REQUESTS].into_iter()));
        let index = inspect(&common).await;
        let source = format!("{} (this project's directory", repo.named("MODULE.bazel"));
        // Whatever the walk makes of the directory's name for a file of
        // its own, the workspace is a source for each ecosystem.
        for purl in HOOKED {
            let sources = index.conflicts(purl);
            let named = sources.iter().any(|found| found.starts_with(&source));
            assert!(named, "{purl}: {sources:?}");
        }
        // The walk reads nothing for PyPI and Maven: the workspace is all
        // that holds them back, as a file to fix.
        for purl in [REQUESTS, GUAVA] {
            assert_eq!(index.conflicts(purl).len(), 1, "{purl}");
            assert!(index.unreadable_only(purl), "{purl}");
        }
        assert_eq!(index.conflicts(RACK), [""; 0]);
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
