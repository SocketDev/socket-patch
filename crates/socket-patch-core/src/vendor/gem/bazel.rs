//! RubyGems vendored mode for a gem whose `Gemfile` and lock a Bazel hub
//! reads.
//!
//! rules_ruby's `ruby.bundle_fetch` copies the two files into a repository
//! of Bazel's, has Bazel download `<remote>gems/<name>-<version>.gem` for
//! every gem of a `GEM` section, and runs `bundle install --local` there.
//! The unpacked copy that vendored mode commits everywhere else
//! ([`super`]: named by a `path:`) is not in that repository, and the build
//! fails on it. What the hub does build is the pair hosted mode writes,
//! with a relative `file:` URL of the checkout in the place of the patch
//! registry's, and the patched gem committed where the ruleset asks that
//! source for it:
//!
//! ```text
//! gem "<name>", …, source: "file:.socket/vendor/gem/<uuid>/"   # Gemfile
//!
//! GEM                                                          # Gemfile.lock
//!   remote: file:.socket/vendor/gem/<uuid>/
//!   specs:
//!     <name> (<version>)
//! DEPENDENCIES
//!   <name> (…)!
//! CHECKSUMS
//!   <name> (<version>) sha256=<the patched gem>
//!
//! .socket/vendor/gem/<uuid>/gems/<name>-<version>.gem          # the patched gem
//! ```
//!
//! Bazel's server runs in the root of the workspace and opens the URL from
//! there, and Bundler holds the file to the lock's `CHECKSUMS` line. Built
//! on Bazel 9.3.2, 8.8.2 and 7.7.2 with rules_ruby 1.0.0-rc2 on a machine
//! that reaches no patch host; one changed byte of the gem fails the build
//! of a machine that fetches the hub anew (`ruby::` in the CLI's
//! `e2e_bazel_build`). No file of Bazel's is written.
//!
//! The pair is the hosted planner's own ([`plan_gem_source`]), and its undo
//! is that edit in reverse ([`revert`]). It is written only where [`gate`]
//! shows that it builds, and never on the user's word
//! ([`ALLOW_IN_BAZEL_ENV`]), which asks for the copy of every other
//! project. Anywhere else the gem is declined
//! ([`crate::vendor::bazel_hub`]).
//!
//! What the form costs, which the run says ([`ADVISORY`]): Bundler by
//! itself does not install from such a source (`bundle install` on a
//! machine without the gem and `bundle lock --update` fail, and on a
//! machine that installed the gem before the patch it passes and keeps
//! that unpatched copy), so the checkout builds its gems through Bazel
//! only; and Bazel does not watch the gem, so an output base that fetched
//! the hub before keeps what it fetched.

use std::path::Path;

use serde_json::{json, Value};

use super::{
    checksum_entry, dep_entry_name, gem_edits, gem_service_archive, is_one_line,
    restore_uuid_metadata, GemPrelude, RevertFiles, GEMFILE, GEMFILE_LOCK, GEM_STUB_ARTIFACT_KIND,
};
use crate::api::client::PlannedDownload;
use crate::bazel::built::{hub_calls, lock_text, reader, workspace_as_built};
use crate::bazel::rc::{declared_release, mentions, Release};
use crate::bazel::starlark::Value as Starlark;
use crate::bazel::workspace::{disk, Doubt, Tag, Workspace};
use crate::bazel::BazelRoot;
use crate::formats::gem::declarations;
use crate::formats::gem::hosted::bundled_with_version;
use crate::formats::gem::{parse, parse_spec};
use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::copy_tree::remove_tree;
use crate::patch::redirect::{gem_pair_agrees, plan_gem_source, DepOverride, FileEdit};
use crate::utils::digest::sha256_hex_of;
use crate::utils::env_compat::env_flag;
use crate::utils::fs::{
    atomic_write_artifact, atomic_write_bytes_preserving_mode, read_regular_to_bytes, run_blocking,
};
use crate::utils::purl::{build_gem_purl, parse_gem_purl};
use crate::vendor::bazel_hub::GEM_CODE;
use crate::vendor::common::{
    already_patched_result, copy_matches_after_hashes, done, failed_result, preview_result,
    prune_empty_vendor_levels, refused, service_offline_conflict,
};
use crate::vendor::npm_dir::ignored_root_refusal;
use crate::vendor::path::vendor_uuid_dir_rel;
use crate::vendor::refusals::ALLOW_IN_BAZEL_ENV;
use crate::vendor::registry_fetch::{extract_gem_data, extract_on_blocking_pool};
use crate::vendor::revert::{self, KeepPolicy};
use crate::vendor::service_fetch::ServicePolicy;
use crate::vendor::state::{
    write_marker_or_warn, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use crate::vendor::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// The advisory of a run that vendored a gem this way: what the form costs
/// (see the module docs).
pub(crate) const ADVISORY: &str = "vendor_gem_bazel_file_source";

/// The warning of an undo ([`revert`]) after which a `gem_checksums` entry
/// still holds the gem to the patched one's sha256: the entry is the
/// user's own edit, which the run asked for and no undo takes back, and
/// Bazel fails the download of the upstream gem on it.
const ENTRY_LEFT: &str = "vendor_gem_bazel_checksum_left";

/// The wiring records of an entry: the source `Gemfile` gives the gem, and
/// what `Gemfile.lock` held before it followed (`original`: the `remote` of
/// the section the gem came from, its `dependency` entry and its `checksum`
/// line, each as the lock spelled it, the last two only where it had one).
pub(crate) const GEMFILE_KIND: &str = "gemfile_file_source";
pub(crate) const LOCK_KIND: &str = "gemfile_lock_file_source";

/// The calls of the hub that read the `Gemfile` and the lock of a project
/// for which a gem committed as its archive is known to build ([`gate`]).
pub(crate) struct Hub {
    /// The lock, as Bazel reads it.
    lock: String,
    /// Those calls, each as a message names it ([`named`]). Every one of
    /// them fetches the gem for a hub of its own.
    calls: Vec<String>,
    /// What the `gem_checksums` of those calls hold a gem to: its
    /// `<name>-<version>`, the sha256, and the call, by its place among
    /// them.
    pins: Vec<(String, String, usize)>,
}

/// A call of the hub, as a message names it.
fn named(tag: &Tag<'_>) -> String {
    format!("`ruby.bundle_fetch` ({}:{})", tag.file, tag.call.line)
}

/// Whether a gem of the project at the Bazel root `root`, whose `Gemfile`
/// or lock a call of the hub names, can be committed as its archive: the
/// calls that read the two files, or why that is not known to build here.
/// Read from the files of the checkout alone:
///
/// - The workspace is read with certainty, and no `WORKSPACE` file that
///   the Bazel of the checkout reads defines a repository
///   ([`workspace_as_built`]): every call that reads the two files is
///   among the ones seen.
/// - The project is the root of the workspace, where Bazel opens the URL
///   from.
/// - Each call of the hub writes out the files it reads, and one that reads
///   the `Gemfile` or the lock of the project reads both, with
///   `gem_checksums` that are written out.
/// - The checkout names a Bazel release whose downloader opens such a URL
///   ([`opens_file_urls`]), and no rc file of it takes the download from
///   that downloader ([`reads_the_checkout`]).
/// - The lock names a Bundler that the hub is known to build such a source
///   with ([`bundler_builds`]).
pub(crate) async fn gate(root: &BazelRoot) -> Result<Hub, String> {
    let (dir, project) = (root.dir.clone(), root.project.clone());
    run_blocking(move || read(&dir, &project)).await
}

fn read(dir: &Path, project: &Path) -> Result<Hub, String> {
    let view = disk(dir);
    let workspace = workspace_as_built(&view);
    let (calls, doubts) = hub_calls(&workspace, "gem");
    if let Some(doubt) = workspace.doubts.first().or(doubts.first()) {
        return Err(uncertain(doubt));
    }
    if workspace.legacy.is_some() {
        return Err(
            "a `WORKSPACE` file of the workspace defines repositories, which are not read".into(),
        );
    }
    if !project.as_os_str().is_empty() {
        return Err(
            "the project is not the root of the Bazel workspace, where Bazel opens such a URL \
             from"
                .into(),
        );
    }
    let (mut reading, mut pins) = (Vec::new(), Vec::new());
    for (tag, files) in &calls {
        let call = named(tag);
        let plain = |name| matches!(tag.call.arg(name), None | Some(Starlark::Str(_)));
        if tag.call.unpacks() || !plain("gemfile") || !plain("gemfile_lock") {
            return Err(format!("{call} does not write out the files it reads"));
        }
        let reads = |file| files.iter().any(|path| path == file);
        match (reads(GEMFILE), reads(GEMFILE_LOCK)) {
            (false, false) => continue,
            (true, true) => {}
            _ => {
                return Err(format!(
                    "{call} reads one of Gemfile and Gemfile.lock alone"
                ))
            }
        }
        let unwritten = || format!("the `gem_checksums` of {call} are not written out");
        match tag.call.arg("gem_checksums") {
            None => {}
            Some(Starlark::Dict(sums)) => {
                for (gem, sum) in sums {
                    let Starlark::Str(sum) = sum else {
                        return Err(unwritten());
                    };
                    pins.push((gem.clone(), sum.clone(), reading.len()));
                }
            }
            Some(_) => return Err(unwritten()),
        }
        reading.push(call);
    }
    if reading.is_empty() {
        return Err("no `ruby.bundle_fetch` call is seen to read Gemfile and Gemfile.lock".into());
    }
    opens_file_urls(declared_release(&view))?;
    reads_the_checkout(mentions(&view, &KEEPS_BAZEL_OFF, false))?;
    let unread = || "Gemfile.lock cannot be read".to_string();
    let lock = lock_text(dir, GEMFILE_LOCK).ok_or_else(unread)?;
    bundler_builds(&lock)?;
    let calls = reading;
    Ok(Hub { lock, calls, pins })
}

/// Whether the hub is known to build a gem of such a source with the
/// Bundler the lock names (`BUNDLED WITH`), which rules_ruby installs in
/// the hub and runs there. Built with 2.6.9 and 4.0.15, which also hold
/// the gem to the lock's `CHECKSUMS` line; the later releases of the 2
/// line and the ones of the 4 line are taken to do the same. Every such
/// lock has one `GEM` section per source, which the pair is written for.
fn bundler_builds(lock: &str) -> Result<(), String> {
    match bundled_with_version(lock) {
        Some(((2, 6..) | (4, _), _)) => Ok(()),
        Some((_, version)) => Err(format!(
            "it is not known to build with Bundler {version}, which Gemfile.lock names \
             (`BUNDLED WITH`) and the hub runs (it does with 2.6.9 and 4.0.15)"
        )),
        None => Err(
            "Gemfile.lock names no Bundler (`BUNDLED WITH`) for the hub to run, and not every \
             Bundler is known to build such a source"
                .into(),
        ),
    }
}

/// The options of an rc file under which Bazel may not read the committed
/// gem: a remote downloader is handed the URL in the place of Bazel's own
/// (read in Bazel's source: 9.3.2 keeps a `file:` URL to itself, 7.7.2 does
/// not), a build that may not download fetches nothing, and a hub pinned in
/// a vendor directory keeps the gems it has. None was built.
const KEEPS_BAZEL_OFF: [&str; 3] = [
    "experimental_remote_downloader",
    "repository_disable_download",
    "vendor_dir",
];

/// Whether the rc files of the checkout leave the download of the gem to
/// Bazel's own downloader, by what [`mentions`] found of
/// [`KEEPS_BAZEL_OFF`] in them. An option that is named counts however it
/// is set, and so does an rc file that cannot be read.
fn reads_the_checkout(found: Result<Vec<(String, usize, String)>, String>) -> Result<(), String> {
    match found.map(|found| found.into_iter().next()) {
        Ok(None) => Ok(()),
        Ok(Some((file, line, word))) => Err(format!(
            "{file}:{line} names `{word}`, under which Bazel may not read the committed gem"
        )),
        Err(file) => Err(format!(
            "the rc file {file} cannot be read, and may keep Bazel from reading the committed gem"
        )),
    }
}

/// What a doubt of the reader of the workspace's files says of them.
fn uncertain(Doubt { file, line, why }: &Doubt) -> String {
    let line = match line {
        0 => String::new(),
        line => format!(":{line}"),
    };
    format!("the files of the Bazel workspace are not read with certainty ({file}{line}: {why})")
}

/// Whether the downloader of the Bazel `release` a checkout names opens a
/// relative `file:` URL from the root of the workspace. Built on 7.7.2,
/// 8.8.2 and 9.3.2, and the other releases of those three lines are taken
/// to do the same but for 9.1.0: Bazel's own history says that
/// `repository_ctx.download` fails on such a URL there, and that 9.1.1 and
/// 9.2.0 fixed it. A checkout that names no release, or one that is not
/// three numbers (`latest`, a release candidate), may be built by that one,
/// and by any release to come.
fn opens_file_urls(release: Option<Release>) -> Result<(), String> {
    match release {
        None => Err(
            "the checkout names no Bazel release as three numbers (`.bazelversion`, or \
             `USE_BAZEL_VERSION` in `.bazeliskrc`), and not every release opens such a URL"
                .into(),
        ),
        Some((9, 1, 0)) => Err("Bazel 9.1.0 fails on such a URL (9.1.1 and later open it)".into()),
        Some((7..=9, _, _)) => Ok(()),
        Some((major, minor, patch)) => Err(format!(
            "it is not known to build on Bazel {major}.{minor}.{patch} (it does on 7.7.2, 8.8.2 \
             and 9.3.2)"
        )),
    }
}

impl Hub {
    /// Why version `version` of the gem `name` is not committed for these
    /// calls, before its bytes are known: the lock holds it as platform
    /// gems, which no build has been run with, or in the hub of one of the
    /// calls nothing would hold the committed gem to its bytes. Bundler
    /// holds it to the lock's `CHECKSUMS` line and Bazel to the
    /// `gem_checksums` entry of the call that fetches it, and to nothing
    /// else.
    pub(crate) fn declines(&self, name: &str, version: &str) -> Option<String> {
        let lock = parse(&self.lock);
        if !lock.locked_builds(name, version).platforms.is_empty() {
            return Some(format!(
                "Gemfile.lock holds {name} {version} as platform gems"
            ));
        }
        if lock.has_checksums() {
            return None;
        }
        let key = format!("{name}-{version}");
        let held = |call: &usize| self.entries(&key).any(|(_, of)| of == *call);
        let call = &self.calls[(0..self.calls.len()).find(|call| !held(call))?];
        Some(format!(
            "Gemfile.lock has no CHECKSUMS section and {call} has no `gem_checksums` entry for \
             {key}, so nothing would hold the committed gem to its bytes there (`bundle lock \
             --add-checksums` writes the section)"
        ))
    }

    /// The `gem_checksums` entries of the gem `key` (`<name>-<version>`):
    /// the sha256 and the call of each.
    fn entries<'a>(&'a self, key: &'a str) -> impl Iterator<Item = (&'a str, usize)> {
        let of = move |(gem, sum, call): &'a (String, String, usize)| {
            (gem == key).then_some((sum.as_str(), *call))
        };
        self.pins.iter().filter_map(of)
    }

    /// Why the patched gem, whose bytes hash to `sha256`, is not committed
    /// for these calls: a `gem_checksums` entry of one of them holds the
    /// gem to other bytes, and Bazel would fail that hub's download of the
    /// committed ones. The call is the user's to edit.
    fn pinned_to_other_bytes(&self, name: &str, version: &str, sha256: &str) -> Option<String> {
        let key = format!("{name}-{version}");
        let other = |(sum, _): &(&str, usize)| !sum.eq_ignore_ascii_case(sha256);
        let (sum, call) = self.entries(&key).find(other)?;
        let call = &self.calls[call];
        Some(format!(
            "the `gem_checksums` of {call} hold {key} to sha256 {sum}, and the patched gem has \
             {sha256}: write that value there and run again (socket-patch does not edit the \
             call, and no undo puts the old value back)"
        ))
    }
}

/// Where the gem of one patch is committed for a hub, and the lock it is
/// named in.
struct Site {
    /// The directory of the patch, from the project.
    dir: String,
    /// The source the pair names: `file:.socket/vendor/gem/<uuid>/`.
    source: String,
    /// The patched gem, from the project: where rules_ruby asks that
    /// source for it.
    archive: String,
    /// `Gemfile.lock`, as it was read.
    lock: String,
    /// The gem, as the hosted planner takes it.
    dep: DepOverride,
}

impl Site {
    fn of(prelude: &GemPrelude, uuid: &str) -> Option<Site> {
        let dir = vendor_uuid_dir_rel("gem", uuid)?;
        let (name, version) = (&prelude.name, &prelude.version);
        Some(Site {
            source: format!("file:{dir}/"),
            archive: format!("{dir}/gems/{name}-{version}.gem"),
            dir,
            lock: prelude.lock_eol.restore(&prelude.lock_text).into_owned(),
            dep: DepOverride {
                ecosystem: "gem".into(),
                name: name.clone(),
                namespace: None,
                version: version.clone(),
                token: String::new(),
                patch_uuid: uuid.to_string(),
                artifact_url: String::new(),
                npm_registry_url: None,
                registry_override: None,
                integrity: Default::default(),
            },
        })
    }

    /// How the gem of `prelude` is vendored in the project at `project`.
    /// `None`: as it is without Bazel. `Ok(None)`: the pair names the
    /// source already. `Ok(Some)`: for these calls. `Err`: not at all, and
    /// this is why.
    async fn lane(
        &self,
        prelude: &GemPrelude,
        project: &Path,
    ) -> Option<Result<Option<Hub>, String>> {
        if prelude.lock_wired {
            return None;
        }
        let gemfile = &prelude.gemfile_text;
        if gemfile.contains(&self.source)
            && gem_pair_agrees(gemfile, &self.lock, &self.dep, &self.source).is_ok()
        {
            return Some(Ok(None));
        }
        if env_flag(ALLOW_IN_BAZEL_ENV) {
            return None;
        }
        let dir = project.to_path_buf();
        let root = run_blocking(move || crate::bazel::bazel_root(&dir)).await?;
        let files = [GEMFILE, GEMFILE_LOCK].map(String::from).to_vec();
        Some(match reader(&root, "gem", files).await? {
            Err(doubt) => Err(uncertain(&doubt)),
            Ok(_) => gate(&root).await.and_then(|hub| {
                let declined = hub.declines(&prelude.name, &prelude.version);
                declined.map_or(Ok(Some(hub)), Err)
            }),
        })
    }

    /// Whether the committed gem is the one the pair names: it holds every
    /// file of `record` as patched, and hashes to what the lock pins.
    async fn intact(&self, project: &Path, record: &PatchRecord) -> bool {
        let Ok(bytes) = read_regular_to_bytes(&project.join(&self.archive)).await else {
            return false;
        };
        self.pinned().is_none_or(|sum| sum == sha256_hex_of(&bytes))
            && carries(bytes, &record.files).await
    }

    /// The sha256 the lock's `CHECKSUMS` holds the gem to.
    fn pinned(&self) -> Option<String> {
        let lock = parse(&self.lock);
        let sum = lock.checksum(&self.dep.name, &self.dep.version)?;
        Some(sum.to_ascii_lowercase())
    }

    /// Whether the `Gemfile` gives the gem the source of an earlier patch:
    /// the new one takes its place, as the hosted planner follows a patch
    /// that supersedes one.
    fn follows(&self, gemfile: &str) -> bool {
        let decls = declarations::declarations(gemfile);
        let ours = |url: &str| crate::origin::vendor_uuid_dir(url).is_some();
        let mut sources = decls.of(&self.dep.name).filter_map(|decl| decl.source()?.1);
        sources.any(ours)
    }
}

/// Whether the gem archive `bytes` holds every file of a patch as patched.
pub(crate) async fn carries(
    bytes: Vec<u8>,
    files: &std::collections::HashMap<String, PatchFileInfo>,
) -> bool {
    let Ok(stage) = tempfile::tempdir() else {
        return false;
    };
    let unpacked = extract_on_blocking_pool(bytes, stage.path(), extract_gem_data).await;
    unpacked.is_ok() && copy_matches_after_hashes(stage.path(), files).await
}

/// Whether the artifact of a ledger entry is a gem committed as its
/// archive.
pub(crate) fn is_archive(entry: &VendorEntry) -> bool {
    entry.ecosystem == "gem" && archive_path(&entry.artifact.path)
}

/// Whether `path` (with `/` between its parts) is where this form commits
/// a gem: `<source>/gems/<file>.gem`, the path rules_ruby asks a source
/// for. A copy that is vendored by its path is a directory named for its
/// gem and version, and a version may end in `.gem`.
pub(crate) fn archive_path(path: &str) -> bool {
    let dir = path.rsplit_once('/').map(|(dir, _)| dir);
    path.ends_with(".gem") && dir.is_some_and(|dir| dir.ends_with("/gems"))
}

/// Hold the committed gem `archive` to `record`: every file of the patch
/// is in it as patched. The error is the routing tag of
/// [`crate::vendor::verify::verify_vendored_patch_record`].
pub(crate) async fn verify(archive: &Path, record: &PatchRecord) -> Result<(), String> {
    let unreadable = |_| "vendor_artifact_unreadable".to_string();
    let bytes = read_regular_to_bytes(archive).await.map_err(unreadable)?;
    match carries(bytes, &record.files).await {
        true => Ok(()),
        false => Err("vendor_hash_mismatch".to_string()),
    }
}

/// The download [`vendor`] makes for the gem of `prelude`: the archive and
/// its stub gemspec, which says whether the gem is one the lane takes.
/// `None` where the gem is vendored as it is without Bazel; `Some(None)`
/// where it is declined, or in place.
pub(super) async fn preflight(
    purl: &str,
    prelude: &GemPrelude,
    project: &Path,
    record: &PatchRecord,
) -> Option<Option<PlannedDownload>> {
    let site = Site::of(prelude, &record.uuid)?;
    let asks = match site.lane(prelude, project).await? {
        Err(_) => false,
        Ok(None) => !site.intact(project, record).await,
        Ok(Some(_)) => site.follows(&prelude.gemfile_text) || gem_edits(purl, prelude).is_ok(),
    };
    Some(asks.then(|| PlannedDownload {
        secondary: Some(GEM_STUB_ARTIFACT_KIND.to_string()),
        ..PlannedDownload::archive(record.uuid.clone())
    }))
}

/// Vendor the gem of `prelude` as its archive, for a hub that reads the
/// `Gemfile` and the lock of the project (see the module docs). `None`
/// where no hub reads them, or the user asked for the copy of every other
/// project: the caller goes on.
pub(super) async fn vendor(
    purl: &str,
    prelude: &GemPrelude,
    project: &Path,
    record: &PatchRecord,
    vendored_at: &str,
    dry_run: bool,
    service: Option<&VendorServiceConfig>,
) -> Option<VendorOutcome> {
    let site = Site::of(prelude, &record.uuid)?;
    let hub = match site.lane(prelude, project).await? {
        Ok(hub) => hub,
        Err(why) => {
            let detail = format!(
                "a call of rules_ruby in the Bazel workspace reads the lock of this project, \
                 and the patched gem cannot be committed for it: {why}"
            );
            return Some(refused(GEM_CODE, detail));
        }
    };
    let (name, version) = (prelude.name.as_str(), prelude.version.as_str());
    let archive = project.join(&site.archive);
    if hub.is_none() && site.intact(project, record).await {
        let result = already_patched_result(purl, &archive, &record.files);
        return Some(done(result, None, Vec::new()));
    }
    // The gem meets the refusals of every vendored gem first. A
    // declaration that carries the source of an earlier patch passed them
    // when that patch was vendored.
    if hub.is_some() && !site.follows(&prelude.gemfile_text) {
        if let Err(outcome) = gem_edits(purl, prelude) {
            return Some(*outcome);
        }
    }
    // Dry run or not, before anything is downloaded: a directory that git
    // ignores holds no gem a clone would have.
    if let Some((code, detail)) = ignored_root_refusal(project, &site.dir).await {
        return Some(refused(code, detail));
    }
    if let Some(refusal) = service_offline_conflict(service) {
        return Some(refusal);
    }
    let fetched = match gem_service_archive(service, record, name).await {
        Ok((fetched, _)) => fetched,
        Err(outcome) => return Some(*outcome),
    };
    let sha256 = fetched.sha256_hex().to_string();
    if !carries(fetched.bytes.clone(), &record.files).await {
        return Some(*ServicePolicy::Refused.miss(format!(
            "prebuilt .gem for {name} extracted to an unexpected layout (patched files absent \
             at their recorded paths)"
        )));
    }
    let declined = |why: String| Some(refused(GEM_CODE, why));
    let plan = match &hub {
        // The pair is in place and the gem is not: only the gem is
        // written, and it has to be the one the lock pins.
        None => match site.pinned().filter(|sum| *sum != sha256) {
            Some(sum) => {
                return declined(format!(
                    "Gemfile.lock holds {name} {version} to sha256 {sum}, and the patch \
                     service's gem has {sha256}; {}",
                    crate::vendor::common::REVERT_ALL_AND_REVENDOR
                ))
            }
            None => None,
        },
        Some(hub) => {
            if let Some(why) = hub.pinned_to_other_bytes(name, version, &sha256) {
                return declined(why);
            }
            let (gemfile, lock) = (&prelude.gemfile_text, &site.lock);
            match plan_gem_source(gemfile, lock, &site.dep, &site.source, &sha256) {
                Ok(plan) => Some(plan),
                Err(warning) => {
                    return declined(format!(
                        "Gemfile and Gemfile.lock cannot name the committed gem as hosted mode \
                         names a patch registry, and for the reason a hosted run gives ({}: {}); \
                         the way on that reason names is the one of a hosted run",
                        warning.code, warning.detail
                    ))
                }
            }
        }
    };
    if dry_run {
        let result = preview_result(purl, &archive, &record.files);
        return Some(done(result, None, Vec::new()));
    }

    // ── the gem, where rules_ruby asks the source for it ─────────────────
    let uuid_dir = prelude.uuid_dir.as_path();
    // A gem whose pair was in place keeps what it has.
    let fresh = plan.is_some();
    let unwind = || async {
        if fresh {
            let _ = remove_tree(uuid_dir).await;
            prune_empty_vendor_levels(uuid_dir).await;
        }
    };
    let failed = |what: &str, e: std::io::Error| {
        let error = format!("failed to write {what}: {e}");
        Some(done(failed_result(purl, &archive, error), None, Vec::new()))
    };
    let written = async {
        tokio::fs::create_dir_all(archive.parent().unwrap_or(uuid_dir)).await?;
        atomic_write_artifact(&archive, &fetched.bytes).await?;
        // Stock ignore templates name `*.gem`.
        restore_uuid_metadata(uuid_dir).await
    };
    if let Err(e) = written.await {
        unwind().await;
        return failed(&site.archive, e);
    }
    let mut warnings = vec![fetched.downloaded_warning(name)];
    let artifact = VendorArtifact {
        yarn_berry10c0: None,
        path: site.archive.clone(),
        sha256,
        size: Some(fetched.bytes.len() as u64),
        platform_locked: None,
        file_inventory: None,
    };
    let entry = |wiring| {
        let purl = build_gem_purl(name, version);
        VendorEntry::new("gem".into(), purl, record.uuid.clone(), artifact, wiring)
    };
    let result = already_patched_result(purl, &archive, &record.files);
    let Some((gemfile, lock, edits)) = plan else {
        warnings.push(VendorWarning::new(
            "vendor_artifact_rebuilt",
            format!(
                "the committed gem for {name}@{version} was missing or not the patched one; \
                 written again at {} (Gemfile and Gemfile.lock untouched)",
                site.archive
            ),
        ));
        // The wiring is the first run's, which the caller carries forward.
        return Some(done(result, Some(entry(Vec::new())), warnings));
    };

    // ── Gemfile, then Gemfile.lock (a failure unwinds the Gemfile) ───────
    if let Err(e) =
        atomic_write_bytes_preserving_mode(&prelude.gemfile_path, gemfile.as_bytes()).await
    {
        unwind().await;
        return failed(GEMFILE, e);
    }
    if let Err(e) = atomic_write_bytes_preserving_mode(&prelude.lock_path, lock.as_bytes()).await {
        let before = prelude.gemfile_text.as_bytes();
        let _ = atomic_write_bytes_preserving_mode(&prelude.gemfile_path, before).await;
        unwind().await;
        return failed(GEMFILE_LOCK, e);
    }
    let marker = VendorMarker::new("gem", &build_gem_purl(name, version), record, vendored_at);
    write_marker_or_warn(uuid_dir, &marker, &mut warnings).await;
    warnings.push(VendorWarning::new(
        ADVISORY,
        format!(
            "{name} {version} is vendored for the Bazel hub that reads Gemfile.lock: Gemfile and \
             Gemfile.lock name {} by a relative `file:` URL, which Bazel builds. Bundler by \
             itself does not install from such a source (`bundle install` on a machine without \
             the gem and `bundle lock --update` fail; on a machine that installed the gem before, \
             `bundle install` passes and keeps that unpatched copy), so this checkout builds its \
             gems through Bazel only; `--mode hosted` serves both. Bazel does not watch the gem: \
             an output base that fetched the hub before keeps what it fetched",
            site.archive
        ),
    ));
    Some(done(
        result,
        Some(entry(records(name, &site.source, &edits))),
        warnings,
    ))
}

/// The wiring records of the pair edit `edits` made for the gem `name`
/// ([`GEMFILE_KIND`], [`LOCK_KIND`]). An edit that followed an earlier
/// patch moved no entry of the lock: its record has no `original`, and the
/// caller carries the one of the entry it replaces forward.
fn records(name: &str, source: &str, edits: &[FileEdit]) -> Vec<WiringRecord> {
    let before = |kind: &str| {
        let edit = edits.iter().find(|edit| edit.kind == kind)?;
        edit.original.clone()
    };
    let original = before("redirect_gemfile_lock_gem_source").map(|remote| {
        json!({
            "remote": remote,
            "dependency": before("redirect_gemfile_lock_dependency_pin"),
            "checksum": before("redirect_gemfile_lock_checksum"),
        })
    });
    let record = |file: &str, kind: &str, action, original| WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action,
        key: Some(name.to_string()),
        original,
        new: Some(Value::String(source.to_string())),
    };
    vec![
        record(GEMFILE, GEMFILE_KIND, WiringAction::Added, None),
        record(GEMFILE_LOCK, LOCK_KIND, WiringAction::Rewritten, original),
    ]
}

/// Revert the entry of a gem committed as its archive: the `Gemfile` loses
/// the source, the lock's entry goes back to the section it came from with
/// its `DEPENDENCIES` entry and its `CHECKSUMS` line, and the directory of
/// the patch is removed. A file that names the source nowhere has been put
/// back already, and the other goes back by itself; a file that names it
/// and no longer holds what [`vendor`] wrote leaves both alone
/// (`vendor_lock_entry_drifted`) with the gem.
pub(super) async fn revert(
    entry: &VendorEntry,
    project: &Path,
    uuid_dir_rel: &str,
    opts: RevertOpts,
) -> RevertOutcome {
    let Some((name, version)) = parse_gem_purl(&entry.base_purl) else {
        return RevertOutcome::failed(format!("not a gem purl: {}", entry.base_purl));
    };
    let source = format!("file:{uuid_dir_rel}/");
    let mut files = RevertFiles::new(project);
    let mut texts = Vec::new();
    for file in [GEMFILE_LOCK, GEMFILE] {
        match files.text(file).await {
            Ok(text) => texts.push(text.map(|text| text.text().to_string())),
            Err(e) => return RevertOutcome::failed(e),
        }
    }
    let mut outcome = RevertOutcome::ok();
    let before = entry.wiring.iter().find(|w| w.kind == LOCK_KIND);
    let before = before.and_then(|w| w.original.as_ref());
    match (&texts[0], &texts[1]) {
        (Some(lock), Some(gemfile)) if lock.contains(&source) || gemfile.contains(&source) => {
            // A file that names the source nowhere has been put back
            // already: the other one goes back by itself.
            let lock = match lock.contains(&source) {
                true => before.and_then(|b| unwire_lock(lock, &name, &version, &source, b)),
                false => Some(lock.clone()),
            };
            let gemfile = match gemfile.contains(&source) {
                true => unwire_gemfile(gemfile, &name, &source),
                false => Some(gemfile.clone()),
            };
            match (lock, gemfile) {
                (Some(lock), Some(gemfile)) => {
                    for (file, text) in [(GEMFILE_LOCK, lock), (GEMFILE, gemfile)] {
                        if let Ok(Some(file)) = files.text(file).await {
                            file.set(text);
                        }
                    }
                    let key = format!("{name}-{version}");
                    let (dir, sum) = (project.to_path_buf(), entry.artifact.sha256.clone());
                    let left = run_blocking(move || entry_left(&dir, &key, &sum)).await;
                    outcome.warnings.extend(left);
                }
                _ => outcome.warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!(
                        "{GEMFILE} and {GEMFILE_LOCK} no longer carry what vendor wrote for \
                         {name}; left alone, and neither was changed"
                    ),
                )),
            }
        }
        (Some(_), Some(_)) => {}
        _ => outcome.warnings.push(VendorWarning::new(
            "vendor_lockfile_missing",
            format!("{GEMFILE} or {GEMFILE_LOCK} is missing; the {name} entry cannot be restored"),
        )),
    }
    if !opts.dry_run {
        if let Err(e) = files.write_changed().await {
            return RevertOutcome::failed(e);
        }
    }
    revert::finish(outcome, project, uuid_dir_rel, opts, KeepPolicy::OnDrift).await
}

/// What an undo in the project at `project` says of a call of the hub
/// whose `gem_checksums` still hold the gem `key` (`<name>-<version>`) to
/// `sha256`, the one of the committed gem ([`ENTRY_LEFT`]). Read apart from
/// [`gate`]: the entry fails the build whatever else the checkout says.
/// And read whatever the switch says ([`crate::bazel::off`]): the undo of
/// what an earlier run wrote for Bazel says what it says without it.
fn entry_left(project: &Path, key: &str, sha256: &str) -> Option<VendorWarning> {
    let root = crate::bazel::root_of(project)?;
    let workspace = Workspace::read(&disk(&root.dir));
    let holds = |tag: &Tag<'_>| match tag.call.arg("gem_checksums") {
        Some(Starlark::Dict(sums)) => sums.iter().any(|(gem, sum)| {
            gem == key && matches!(sum, Starlark::Str(sum) if sum.eq_ignore_ascii_case(sha256))
        }),
        _ => false,
    };
    let (calls, _) = hub_calls(&workspace, "gem");
    let call = calls
        .iter()
        .find(|(tag, _)| holds(tag))
        .map(|(tag, _)| named(tag))?;
    Some(VendorWarning::new(
        ENTRY_LEFT,
        format!(
            "the `gem_checksums` of {call} still hold {key} to the sha256 of the patched gem \
             ({sha256}), and the lock names the upstream gem again: the Bazel build fails on \
             that entry until it holds the upstream gem's sha256, or is removed (socket-patch \
             does not edit the call)"
        ),
    ))
}

/// `gemfile` without the source `source` of the gem `name`: the option
/// goes from the one declaration that carries it, or the whole line where
/// the pair added it. `None` unless exactly one declaration carries it.
fn unwire_gemfile(gemfile: &str, name: &str, source: &str) -> Option<String> {
    let decls = declarations::declarations(gemfile);
    let ours = |decl: &&declarations::Declaration| {
        decl.source().is_some_and(|(_, url)| url == Some(source))
    };
    let mut ours = decls.of(name).filter(ours);
    let (decl, None) = (ours.next()?, ours.next()) else {
        return None;
    };
    Some(match declarations::is_added_line(gemfile, decl) {
        true => declarations::without_added_line(gemfile, decl),
        false => declarations::without_arg(gemfile, decl.source()?.0),
    })
}

/// `lock` (with `\n` line endings) with version `version` of the gem
/// `name` back where it was before the pair named `source`, as `before`
/// records it ([`LOCK_KIND`]): the entry in the section of that remote,
/// where Bundler sorts it; its `DEPENDENCIES` entry as it was, or gone
/// where the pair added it; and its `CHECKSUMS` line likewise. `None` for a
/// lock that does not hold exactly what the pair wrote, and for a record
/// that would put back a line that is not this gem's.
fn unwire_lock(
    lock: &str,
    name: &str,
    version: &str,
    source: &str,
    before: &Value,
) -> Option<String> {
    let mut lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
    // The `GEM` section whose one remote is `remote`: the line of its
    // first entry.
    let entries = |lines: &[String], remote: &str| {
        let remote = format!("  remote: {remote}");
        let head = ["GEM", remote.as_str(), "  specs:"];
        let heads = |at: &usize| lines.get(*at..at + 3).is_some_and(|l| l[..] == head[..]);
        (0..lines.len()).find(heads).map(|at| at + 3)
    };
    // The entry of a line that is this gem's own, as the lock spells it.
    let own = |key: &str, names: &dyn Fn(&str) -> bool| match before.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(entry)) => {
            let line = format!("  {entry}");
            (is_one_line(&line, false) && names(&line)).then_some(Some(line))
        }
        Some(_) => None,
    };
    let dependency = own("dependency", &|line| dep_entry_name(line) == Some(name))?;
    let checksum = own("checksum", &|line| {
        checksum_entry(line).is_some_and(|(gem, _)| gem == name)
    })?;

    // The section of the patch: the gem's entry with its dependencies, and
    // the blank line after it.
    let first = entries(&lines, source)?;
    if lines.get(first) != Some(&format!("    {name} ({version})")) {
        return None;
    }
    let deps = lines[first + 1..]
        .iter()
        .take_while(|l| l.starts_with("      "));
    let end = first + 1 + deps.count();
    if lines.get(end).is_none_or(|line| !line.is_empty()) {
        return None;
    }
    let block: Vec<String> = lines.drain(first - 3..=end).skip(3).collect();
    let block = &block[..block.len() - 1];

    // Back into the section it came from, by its full name.
    let full = |line: &str| {
        let spec = parse_spec(line.strip_prefix("    ")?)?;
        let platform = spec.platform.map(|platform| format!("-{platform}"));
        let platform = platform.unwrap_or_default();
        Some(format!("{}-{}{platform}", spec.name, spec.version))
    };
    let ours = format!("{name}-{version}");
    let mut at = entries(&lines, before.get("remote")?.as_str()?)?;
    while lines.get(at).is_some_and(|line| line.starts_with("    ")) {
        if full(&lines[at]).is_some_and(|other| other > ours) {
            break;
        }
        at += 1;
    }
    lines.splice(at..at, block.iter().cloned());

    // The lines of a section that is all two-space entries.
    let section = |lines: &[String], header: &str| {
        let start = lines.iter().position(|line| line == header)? + 1;
        let len = lines[start..].iter().take_while(|l| l.starts_with("  "));
        Some(start..start + len.count())
    };
    let pinned = |line: &String| line.ends_with('!') && dep_entry_name(line) == Some(name);
    let at = section(&lines, "DEPENDENCIES")?.find(|at| pinned(&lines[*at]))?;
    match dependency {
        Some(entry) => lines[at] = entry,
        None => drop(lines.remove(at)),
    }
    let sums = section(&lines, "CHECKSUMS").unwrap_or(0..0);
    let pins = |line: &String| checksum_entry(line) == Some((name, version));
    match (sums.clone().find(|at| pins(&lines[*at])), checksum) {
        (Some(at), Some(line)) => lines[at] = line,
        (Some(at), None) => drop(lines.remove(at)),
        (None, None) => {}
        (None, Some(_)) => return None,
    }
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const NEWER: &str = "33333333-3333-4333-8333-333333333333";
    const MODULE: &str = r#"ruby = use_extension("@rules_ruby//ruby:extensions.bzl", "ruby")
ruby.bundle_fetch(name = "bundle", gemfile = "//:Gemfile", gemfile_lock = "//:Gemfile.lock")
"#;
    const GEMFILE_TEXT: &str = "source \"https://rubygems.org/\"\n\ngem \"rack\", \"~> 2.2\"\n";

    fn sum(of: char) -> String {
        of.to_string().repeat(64)
    }

    /// A lock that resolves `rack 2.2.3`, which depends on `zeitwerk`,
    /// between two other gems, with a `CHECKSUMS` section.
    fn lock() -> String {
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    ast (1.0.0)\n    rack (2.2.3)\n      \
             zeitwerk (~> 2.6)\n    zeitwerk (2.6.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack \
             (~> 2.2)\n\nCHECKSUMS\n  ast (1.0.0) sha256={}\n  rack (2.2.3) sha256={}\n  zeitwerk \
             (2.6.0) sha256={}\n\nBUNDLED WITH\n   2.6.9\n",
            sum('a'),
            sum('b'),
            sum('c')
        )
    }

    /// A checkout whose root `MODULE.bazel` is `module`, canonical, with
    /// the files `files` and Bazel 9.3.2 in `.bazelversion`.
    fn checkout(module: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (lock, head) = (lock(), "ref: refs/heads/main\n");
        let all = [
            (".git/HEAD", head),
            ("MODULE.bazel", module),
            (".bazelversion", "9.3.2\n"),
            (GEMFILE, GEMFILE_TEXT),
            (GEMFILE_LOCK, lock.as_str()),
        ];
        for (path, text) in all.iter().chain(files) {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        (tmp, root)
    }

    /// Why [`gate`] declines the project at `project`, or `None`.
    async fn declined(project: &Path) -> Option<String> {
        let root = crate::bazel::bazel_root(project).expect("a Bazel workspace");
        gate(&root).await.err()
    }

    #[tokio::test]
    async fn the_gate_holds_where_each_condition_is_read_from_the_checkout() {
        let (_tmp, root) = checkout(MODULE, &[]);
        assert_eq!(declined(&root).await, None);
        // Each edit of that checkout, and what the gate then names.
        let call = "ruby.bundle_fetch(name = \"bundle\", gemfile = \"//:Gemfile\", ";
        let lock_arg = "gemfile_lock = \"//:Gemfile.lock\"";
        let pinned = |sums: &str| MODULE.replace(lock_arg, &format!("{lock_arg}, {sums}"));
        let bundler = |version: &str| lock().replace("   2.6.9", &format!("   {version}"));
        let unnamed = "names no Bazel release as three numbers";
        let cases: [(&str, String, &str); 17] = [
            (".bazelversion", String::new(), unnamed),
            (".bazelversion", "latest\n".into(), unnamed),
            (".bazelversion", "9.3.2rc1\n".into(), unnamed),
            (
                ".bazelversion",
                "9.1.0\n".into(),
                "Bazel 9.1.0 fails on such a URL",
            ),
            (
                ".bazelversion",
                "6.5.0\n".into(),
                "not known to build on Bazel 6.5.0",
            ),
            (
                "MODULE.bazel",
                format!("{MODULE}include(\"//:more.MODULE.bazel\")\n"),
                "not read with certainty (more.MODULE.bazel: it does not exist",
            ),
            (
                "MODULE.bazel",
                MODULE.replace(lock_arg, "**LOCK"),
                "`ruby.bundle_fetch` (MODULE.bazel:2) does not write out the files it reads",
            ),
            (
                "MODULE.bazel",
                format!("{MODULE}{call}gemfile_lock = \"//svc:Gemfile.lock\")\n"),
                "`ruby.bundle_fetch` (MODULE.bazel:3) reads one of Gemfile and Gemfile.lock alone",
            ),
            (
                "MODULE.bazel",
                pinned("gem_checksums = SUMS"),
                "the `gem_checksums` of `ruby.bundle_fetch` (MODULE.bazel:2) are not written out",
            ),
            (
                "MODULE.bazel",
                pinned("gem_checksums = {\"rack-2.2.3\": SUM}"),
                "the `gem_checksums` of `ruby.bundle_fetch` (MODULE.bazel:2) are not written out",
            ),
            (
                "MODULE.bazel",
                MODULE.replace("//:", "//svc:"),
                "no `ruby.bundle_fetch` call is seen to read Gemfile and Gemfile.lock",
            ),
            (
                GEMFILE_LOCK,
                bundler("1.17.3"),
                "not known to build with Bundler 1.17.3, which Gemfile.lock names",
            ),
            (
                GEMFILE_LOCK,
                bundler("2.5.23"),
                "not known to build with Bundler 2.5.23, which Gemfile.lock names",
            ),
            (
                GEMFILE_LOCK,
                String::new(),
                "Gemfile.lock names no Bundler (`BUNDLED WITH`)",
            ),
            (
                ".bazelrc",
                "build --experimental_remote_downloader=grpcs://cache.example\n".into(),
                ".bazelrc:1 names `--experimental_remote_downloader=grpcs://cache.example`, under \
                 which Bazel may not read the committed gem",
            ),
            (
                ".bazelrc",
                "build \"--copt\n".into(),
                "the rc file .bazelrc:1 cannot be read",
            ),
            (
                ".bazelrc",
                "common --vendor_dir=third_party/bazel\n".into(),
                ".bazelrc:1 names `--vendor_dir=third_party/bazel`",
            ),
        ];
        for (file, text, why) in cases {
            let (_tmp, root) = checkout(MODULE, &[(file, &text)]);
            let said = declined(&root).await.unwrap_or_default();
            assert!(
                said.contains(why),
                "{file} = {text:?}: {said:?}, not {why:?}"
            );
        }
        // A `WORKSPACE` file that defines repositories stands against the
        // gem where a Bazel that reads it may build the checkout, and not
        // under the Bazel 9.3.2 this checkout names, which reads none.
        let legacy = (
            "WORKSPACE",
            "local_repository(name = \"x\", path = \"x\")\n",
        );
        let (_tmp, root) = checkout(MODULE, &[legacy, (".bazelversion", "7.7.2\n")]);
        let said = declined(&root).await.unwrap_or_default();
        let why = "a `WORKSPACE` file of the workspace defines repositories";
        assert!(said.contains(why), "{said:?}");
        let (_tmp, root) = checkout(MODULE, &[legacy]);
        assert_eq!(declined(&root).await, None, "under Bazel 9.3.2");
        // A call that reads the files of another project is none of this
        // one's, whatever it holds its gems to.
        let other = MODULE
            .replace("//:", "//svc:")
            .replace(lock_arg, "gem_checksums = SUMS");
        let (_tmp, root) = checkout(&format!("{MODULE}{}", other.lines().nth(1).unwrap()), &[]);
        assert_eq!(declined(&root).await, None);
        // A project below the root: Bazel opens the URL from the root.
        let below = MODULE.replace("//:", "//api:");
        let files = [("api/Gemfile", GEMFILE_TEXT), ("api/Gemfile.lock", "")];
        let (_tmp, root) = checkout(&below, &files);
        let said = declined(&root.join("api")).await.unwrap_or_default();
        assert!(
            said.contains("is not the root of the Bazel workspace"),
            "{said}"
        );
    }

    #[test]
    fn a_release_opens_the_url_where_one_of_its_line_was_built() {
        for known in [
            (7, 0, 0),
            (7, 7, 2),
            (8, 8, 2),
            (9, 0, 2),
            (9, 1, 1),
            (9, 3, 2),
        ] {
            assert_eq!(opens_file_urls(Some(known)), Ok(()), "{known:?}");
        }
        for unknown in [None, Some((9, 1, 0)), Some((6, 5, 0)), Some((10, 0, 0))] {
            assert!(opens_file_urls(unknown).is_err(), "{unknown:?}");
        }
    }

    #[test]
    fn the_hub_builds_with_a_bundler_of_a_line_that_was_built() {
        let named = |version: &str| format!("GEM\n  specs:\n\nBUNDLED WITH\n   {version}\n");
        for known in ["2.6.0", "2.6.9", "2.7.2", "4.0.15"] {
            assert_eq!(bundler_builds(&named(known)), Ok(()), "{known}");
        }
        for unknown in ["2.2.19", "2.5.23", "3.0.0", "5.0.0", "two"] {
            assert!(bundler_builds(&named(unknown)).is_err(), "{unknown}");
        }
    }

    /// The artifact of the form is known by its place, so a copy vendored
    /// by its path, a directory, keeps the checks of one whatever its
    /// version ends in.
    #[test]
    fn a_committed_gem_is_known_by_its_place() {
        use crate::vendor::verify::artifact_is_file_shaped;
        let committed = ".socket/vendor/gem/u/gems/rack-2.2.3.gem";
        assert!(archive_path(committed) && artifact_is_file_shaped(committed));
        assert!(artifact_is_file_shaped(&committed.replace('/', "\\")));
        for copy in [".socket/vendor/gem/u/rack-1.0.0.gem", "rack.gem"] {
            assert!(
                !archive_path(copy) && !artifact_is_file_shaped(copy),
                "{copy}"
            );
        }
    }

    /// The committed gem is held to its bytes by the lock's `CHECKSUMS`
    /// line or by the `gem_checksums` entry of every call that reads the
    /// pair, and an entry of any of them that holds the gem to other bytes
    /// declines it.
    #[tokio::test]
    async fn a_gem_is_committed_only_where_its_bytes_are_held() {
        let entry = format!("gem_checksums = {{\"rack-2.2.3\": \"{}\"}}", sum('B'));
        let lock_arg = "gemfile_lock = \"//:Gemfile.lock\"";
        let pinned = MODULE.replace(lock_arg, &format!("{lock_arg}, {entry}"));
        let unchecked =
            lock().split("CHECKSUMS").next().unwrap().to_string() + "BUNDLED WITH\n   2.6.2\n";
        let hub = |module: &str, lock: &str| {
            let (module, lock) = (module.to_string(), lock.to_string());
            async move {
                let (_tmp, root) = checkout(&module, &[(GEMFILE_LOCK, &lock)]);
                let root = crate::bazel::bazel_root(&root).unwrap();
                gate(&root).await.expect("the gate holds")
            }
        };
        let (rack, version) = ("rack", "2.2.3");
        assert_eq!(hub(MODULE, &lock()).await.declines(rack, version), None);
        let declined = hub(MODULE, &unchecked).await.declines(rack, version);
        let unheld = |line: u32| {
            format!(
                "has no CHECKSUMS section and `ruby.bundle_fetch` (MODULE.bazel:{line}) has no \
                 `gem_checksums` entry for rack-2.2.3"
            )
        };
        assert!(declined.is_some_and(|said| said.contains(&unheld(2))));
        assert_eq!(hub(&pinned, &unchecked).await.declines(rack, version), None);
        // The entry is of the gem alone, and is read without regard to case.
        let held = hub(&pinned, &lock()).await;
        assert_eq!(held.pinned_to_other_bytes(rack, version, &sum('b')), None);
        assert_eq!(held.pinned_to_other_bytes("ast", "1.0.0", &sum('d')), None);
        let other = held.pinned_to_other_bytes(rack, version, &sum('d'));
        let other = other.unwrap_or_default();
        let named = [
            "the `gem_checksums` of `ruby.bundle_fetch` (MODULE.bazel:2) hold rack-2.2.3 to sha256",
            &sum('B'),
            &sum('d'),
            "socket-patch does not edit the call",
        ];
        assert!(named.iter().all(|part| other.contains(part)), "{other}");
        // A second call that reads the pair fetches the gem for a hub of
        // its own: its entry holds the gem too, and where the lock has no
        // section it needs one.
        let second = |sums: &str| {
            let call = MODULE.lines().nth(1).unwrap();
            let call = call.replace("\"bundle\"", "\"tools\"");
            format!(
                "{pinned}{}\n",
                call.replace(lock_arg, &format!("{lock_arg}{sums}"))
            )
        };
        let upstream = format!(", gem_checksums = {{\"rack-2.2.3\": \"{}\"}}", sum('d'));
        let held = hub(&second(&upstream), &lock()).await;
        let other = held.pinned_to_other_bytes(rack, version, &sum('b'));
        let other = other.unwrap_or_default();
        let named = [
            "`ruby.bundle_fetch` (MODULE.bazel:3) hold rack-2.2.3",
            &sum('d'),
        ];
        assert!(named.iter().all(|part| other.contains(part)), "{other}");
        assert_eq!(
            held.pinned_to_other_bytes(rack, version, &sum('d'))
                .is_some(),
            true
        );
        let declined = hub(&second(""), &unchecked).await.declines(rack, version);
        assert!(declined.is_some_and(|said| said.contains(&unheld(3))));
        let both = second(&upstream.replace(&sum('d'), &sum('b')));
        let held = hub(&both, &unchecked).await;
        assert_eq!(held.declines(rack, version), None);
        assert_eq!(held.pinned_to_other_bytes(rack, version, &sum('b')), None);
        // A gem the lock holds as platform gems.
        let platform = lock().replace("    rack (2.2.3)\n", "    rack (2.2.3-java)\n");
        let declined = hub(MODULE, &platform).await.declines(rack, version);
        assert!(declined.is_some_and(|said| said.contains("as platform gems")));
    }

    /// The pair the planner writes for the gem `name` of patch `uuid` in
    /// the project at `dir`, on disk, with its gem committed: the ledger
    /// entry of it.
    fn wire(dir: &Path, name: &str, version: &str, uuid: &str) -> VendorEntry {
        let rel = vendor_uuid_dir_rel("gem", uuid).unwrap();
        let (source, archive) = (
            format!("file:{rel}/"),
            format!("{rel}/gems/{name}-{version}.gem"),
        );
        let dep = DepOverride {
            ecosystem: "gem".into(),
            name: name.into(),
            namespace: None,
            version: version.into(),
            token: String::new(),
            patch_uuid: uuid.into(),
            artifact_url: String::new(),
            npm_registry_url: None,
            registry_override: None,
            integrity: Default::default(),
        };
        let read = |file: &str| fs::read_to_string(dir.join(file)).unwrap();
        let (gemfile, lock) = (read(GEMFILE), read(GEMFILE_LOCK));
        let planned = plan_gem_source(&gemfile, &lock, &dep, &source, &sum('f'));
        let (gemfile, lock, edits) = planned.expect("a plan");
        assert_eq!(gem_pair_agrees(&gemfile, &lock, &dep, &source), Ok(()));
        fs::write(dir.join(GEMFILE), gemfile).unwrap();
        fs::write(dir.join(GEMFILE_LOCK), lock).unwrap();
        fs::create_dir_all(dir.join(&archive).parent().unwrap()).unwrap();
        fs::write(dir.join(&archive), "a gem").unwrap();
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: archive,
            sha256: sum('f'),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        let purl = build_gem_purl(name, version);
        VendorEntry::new(
            "gem".into(),
            purl,
            uuid.into(),
            artifact,
            records(name, &source, &edits),
        )
    }

    async fn reverted(entry: &VendorEntry, dir: &Path) -> RevertOutcome {
        let rel = vendor_uuid_dir_rel("gem", &entry.uuid).unwrap();
        revert(entry, dir, &rel, RevertOpts::new(false)).await
    }

    /// Every pair the planner writes goes back byte for byte, with the
    /// directory of the patch: a declared gem with its own requirement,
    /// options and comment, an undeclared one, a pair with CRLF line
    /// endings, and a lock with no `CHECKSUMS` section.
    #[tokio::test]
    async fn the_revert_puts_the_pair_back_byte_for_byte() {
        let decorated = "source \"https://rubygems.org/\"\n\ngem 'ast'\ngem \"rack\", \"~> 2.2\", \
                         require: false # the web server\n";
        let unchecked =
            lock().split("CHECKSUMS").next().unwrap().to_string() + "BUNDLED WITH\n   2.5.0";
        let crlf = |text: &str| text.replace('\n', "\r\n");
        let cases = [
            ("rack", "2.2.3", GEMFILE_TEXT.to_string(), lock()),
            ("rack", "2.2.3", decorated.to_string(), lock()),
            (
                "zeitwerk",
                "2.6.0",
                GEMFILE_TEXT.trim_end().to_string(),
                lock(),
            ),
            ("rack", "2.2.3", crlf(GEMFILE_TEXT), crlf(&lock())),
            ("zeitwerk", "2.6.0", crlf(decorated), crlf(&lock())),
            ("rack", "2.2.3", GEMFILE_TEXT.to_string(), unchecked),
        ];
        for (name, version, gemfile, lock) in cases {
            let files = [(GEMFILE, gemfile.as_str()), (GEMFILE_LOCK, lock.as_str())];
            let (_tmp, root) = checkout(MODULE, &files);
            let entry = wire(&root, name, version, UUID);
            let wired = fs::read_to_string(root.join(GEMFILE_LOCK)).unwrap();
            assert!(wired.contains(&format!("  remote: file:.socket/vendor/gem/{UUID}/")));
            let outcome = reverted(&entry, &root).await;
            assert!(
                outcome.success && outcome.warnings.is_empty(),
                "{outcome:?}"
            );
            let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
            assert_eq!(
                [read(GEMFILE), read(GEMFILE_LOCK)],
                [gemfile, lock],
                "{name}"
            );
            assert!(
                !root.join(".socket/vendor").exists(),
                "{name}: the gem is left"
            );
        }
    }

    /// An undo leaves the call as the user wrote it: where its
    /// `gem_checksums` still hold the gem to the committed gem's sha256,
    /// which fails the build of the lock the undo puts back, it says so.
    #[tokio::test]
    async fn an_undo_names_the_entry_it_leaves_in_the_call() {
        let lock_arg = "gemfile_lock = \"//:Gemfile.lock\"";
        let pinned = |sum: &str| {
            let entry = format!("{lock_arg}, gem_checksums = {{\"rack-2.2.3\": \"{sum}\"}}");
            MODULE.replace(lock_arg, &entry)
        };
        // `wire` commits a gem whose sha256 is all `f`.
        for (module, left) in [
            (pinned(&sum('F')), true),
            (pinned(&sum('a')), false),
            (MODULE.to_string(), false),
        ] {
            let (_tmp, root) = checkout(&module, &[]);
            let entry = wire(&root, "rack", "2.2.3", UUID);
            let outcome = reverted(&entry, &root).await;
            let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
            assert!(outcome.success, "{outcome:?}");
            assert_eq!(
                [read(GEMFILE), read(GEMFILE_LOCK)],
                [GEMFILE_TEXT.to_string(), lock()]
            );
            let said: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
            assert_eq!(said, [ENTRY_LEFT][..usize::from(left)], "{module}");
            let named = [
                "`ruby.bundle_fetch` (MODULE.bazel:2) still hold rack-2.2.3",
                &sum('f'),
            ];
            let detail = outcome.warnings.first().map(|w| w.detail.as_str());
            let detail = detail.unwrap_or_default();
            assert!(
                !left || named.iter().all(|part| detail.contains(part)),
                "{detail}"
            );
        }
    }

    /// A newer patch of the gem takes the source over in place, and its
    /// entry, with what the caller carries forward from the one it
    /// replaces, puts back the pair of before the first.
    #[tokio::test]
    async fn a_patch_that_follows_another_reverts_to_the_pair_of_before_both() {
        let (_tmp, root) = checkout(MODULE, &[]);
        let first = wire(&root, "rack", "2.2.3", UUID);
        let mut second = wire(&root, "rack", "2.2.3", NEWER);
        let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
        assert!(!read(GEMFILE_LOCK).contains(UUID) && !read(GEMFILE).contains(UUID));
        // The second edit moved no entry: its record holds no original.
        assert_eq!(second.wiring[1].original, None);
        assert!(!reverted(&second, &root).await.warnings.is_empty());
        crate::vendor::state::carry_forward_wiring(&first, &mut second);
        let outcome = reverted(&second, &root).await;
        assert!(
            outcome.success && outcome.warnings.is_empty(),
            "{outcome:?}"
        );
        assert_eq!(
            [read(GEMFILE), read(GEMFILE_LOCK)],
            [GEMFILE_TEXT.to_string(), lock()]
        );
    }

    /// A pair that no longer holds what the run wrote is left alone with
    /// the gem, and so is one whose record would put back a line that is
    /// not this gem's; a pair that names the source nowhere has been put
    /// back, and the gem goes.
    #[tokio::test]
    async fn a_pair_that_drifted_is_left_alone_and_one_put_back_by_hand_is_done() {
        let (_tmp, root) = checkout(MODULE, &[]);
        let entry = wire(&root, "rack", "2.2.3", UUID);
        let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
        let (gemfile, wired) = (read(GEMFILE), read(GEMFILE_LOCK));
        let kept = |outcome: &RevertOutcome| {
            let drifted = |w: &VendorWarning| w.code == "vendor_lock_entry_drifted";
            let pair = [read(GEMFILE), read(GEMFILE_LOCK)];
            outcome.success
                && outcome.warnings.iter().any(drifted)
                && root.join(".socket/vendor").exists()
                && pair[0] == gemfile
        };
        // Another gem moved into the section of the patch.
        let drifted = wired.replacen(
            "    rack (2.2.3)\n",
            "    rack (2.2.3)\n    ast (1.0.0)\n",
            1,
        );
        fs::write(root.join(GEMFILE_LOCK), &drifted).unwrap();
        assert!(kept(&reverted(&entry, &root).await));
        assert_eq!(read(GEMFILE_LOCK), drifted);
        fs::write(root.join(GEMFILE_LOCK), &wired).unwrap();
        // A record that names another gem's line, or more than one line.
        for (key, line) in [
            ("checksum", format!("ast (1.0.0) sha256={}", sum('e'))),
            (
                "checksum",
                format!("rack (2.2.3) sha256={}\n  evil (1.0.0)", sum('e')),
            ),
            ("dependency", "ast".to_string()),
        ] {
            let mut tampered = entry.clone();
            tampered.wiring[1].original.as_mut().unwrap()[key] = json!(line);
            assert!(kept(&reverted(&tampered, &root).await), "{key}: {line}");
            assert_eq!(read(GEMFILE_LOCK), wired, "{key}: {line}");
        }
        // Put back by hand: nothing is left to do but to remove the gem.
        fs::write(root.join(GEMFILE), GEMFILE_TEXT).unwrap();
        fs::write(root.join(GEMFILE_LOCK), lock()).unwrap();
        let outcome = reverted(&entry, &root).await;
        assert!(
            outcome.success && outcome.warnings.is_empty(),
            "{outcome:?}"
        );
        assert!(!root.join(".socket/vendor").exists());
        // One of the two put back by hand: the other goes back by itself,
        // and the gem goes.
        for by_hand in [GEMFILE, GEMFILE_LOCK] {
            let (_tmp, root) = checkout(MODULE, &[]);
            let entry = wire(&root, "rack", "2.2.3", UUID);
            let before = match by_hand {
                GEMFILE => GEMFILE_TEXT.to_string(),
                _ => lock(),
            };
            fs::write(root.join(by_hand), before).unwrap();
            let outcome = reverted(&entry, &root).await;
            assert!(
                outcome.success && outcome.warnings.is_empty(),
                "{by_hand}: {outcome:?}"
            );
            let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
            assert_eq!(
                [read(GEMFILE), read(GEMFILE_LOCK)],
                [GEMFILE_TEXT.to_string(), lock()],
                "{by_hand}"
            );
            assert!(!root.join(".socket/vendor").exists(), "{by_hand}");
        }
    }

    /// A committed gem is held to the patch by the files in it.
    #[tokio::test]
    async fn a_committed_gem_is_held_to_the_files_of_the_patch() {
        let patched = b"module Rack\nend\n";
        let record: PatchRecord = serde_json::from_value(json!({
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "lib/rack.rb": {
                "beforeHash": sum('0'),
                "afterHash": crate::hash::git_sha256::compute_git_sha256_from_bytes(patched),
            }},
            "vulnerabilities": {}, "description": "", "license": "MIT", "tier": "free",
        }))
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("rack-2.2.3.gem");
        let gem = |source: &[u8]| super::super::tests::make_gem(&[("lib/rack.rb", source)]);
        fs::write(&archive, gem(patched)).unwrap();
        assert_eq!(verify(&archive, &record).await, Ok(()));
        fs::write(&archive, gem(b"module Rack\n  # unpatched\nend\n")).unwrap();
        assert_eq!(
            verify(&archive, &record).await,
            Err("vendor_hash_mismatch".into())
        );
        fs::write(&archive, b"no gem").unwrap();
        assert_eq!(
            verify(&archive, &record).await,
            Err("vendor_hash_mismatch".into())
        );
        fs::remove_file(&archive).unwrap();
        assert_eq!(
            verify(&archive, &record).await,
            Err("vendor_artifact_unreadable".into())
        );
    }
}
