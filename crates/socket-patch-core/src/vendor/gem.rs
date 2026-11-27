//! Gem (Bundler) vendor backend: the Gemfile + Gemfile.lock pair edit.
//!
//! Empirically verified mechanism (bundler 2.5):
//! BOTH files must be edited. A lock-only edit is a silent unpatch on the next
//! plain `bundle install` (bundler re-resolves from the Gemfile and rewrites
//! the lock back to a registry GEM source; frozen/CI mode errors with exit 16
//! but dev machines do not). The pair edit is the form bundler itself
//! regenerates BYTE-IDENTICALLY, so the committed lock stays churn-free:
//!
//! ```text
//! PATH
//!   remote: .socket/vendor/gem/<uuid>/<name>-<version>
//!   specs:
//!     <name> (<version>)
//!       <dep> (<constraint>)    # the spec block's dependency sublines move over verbatim
//! ```
//!
//! * the PATH section sits BEFORE the GEM section; `remote:` is the RELATIVE
//!   path — no leading `./`, no trailing slash;
//! * the gem's spec block (its 4-space line plus 6-space dependency sublines)
//!   MOVES from GEM/specs into the PATH specs;
//! * the GEM section is retained with the block removed; when its specs run
//!   empty the empty `specs:` stanza is KEPT (that is what bundler writes);
//! * the DEPENDENCIES entry becomes `<name> (= <version>)!` — exact pin plus
//!   the `!` path-source marker; PLATFORMS / BUNDLED WITH / everything else is
//!   byte-preserved;
//! * bundler ≥ 2.6 with `lockfile_checksums` adds a CHECKSUMS section whose
//!   registry entries read `  <name> (<version>) sha256=<hex>`; a path-sourced
//!   gem keeps a BARE `  <name> (<version>)` entry (verified on bundler
//!   2.7.2). The registry token
//!   MUST be stripped on vendor — bundler never repairs it itself (a stale
//!   token is silently preserved, i.e. permanent lock-vs-regen churn) — and
//!   restored verbatim on revert: a bare entry on a registry-sourced gem
//!   hard-fails `BUNDLE_FROZEN=true bundle install` (exit 16).
//!
//! The Gemfile gains `path:` on the gem's declaration (rewritten in place when
//! it is a statically-parseable single top-level line, quote style and
//! trailing options like `require: false` preserved) or, for a transitive
//! dependency, a managed block appended at EOF whose declaration is
//! `require: false`, so `Bundler.require` does not start loading the gem. Anything
//! the conservative line grammar cannot prove safe to rewrite is REFUSED —
//! never guessed at. The one exception is OUR OWN previous wiring: a patch
//! update moves the manifest to a new uuid (same purl), and a `path:` that
//! parses as the socket vendor dir for exactly this gem is repointed in
//! place (the older patch uuid is re-vendored automatically, like the
//! npm/cargo/golang backends — no revert-first).
//!
//! The stub gemspec from `<gem_home>/specifications/` is copied into the
//! vendored dir as `<name>.gemspec` (a path source needs one; the spike showed
//! the stub works warning-free). Gems whose gemspec declares native
//! extensions are refused: bundler silently skips extension builds for path
//! sources and the missing `.so` only fails at `require` time with a
//! confusing error — refusing up front is the honest failure.
//!
//! ## A gem locked as precompiled platform gems
//!
//! Bundler installs a native gem such as nokogiri as PRECOMPILED PLATFORM
//! gems: the lock holds one entry per platform
//! (`nokogiri (1.18.10-x86_64-linux-gnu)`, `nokogiri (1.18.10-arm64-darwin)`)
//! and usually no plain `nokogiri (1.18.10)`. Such a gem cannot be vendored
//! as its ruby-platform tree (the extensions would never be built), so it is
//! vendored as the patch service's PATCHED PLATFORM GEMS, one unpacked tree
//! per locked platform, each with the stub gemspec the service serves for
//! it (verified against real bundler 4.0.15). The gem's fix is the patch
//! of its ruby gem (`<uuid>` below, whatever the platforms); each patched
//! platform gem has a patch of its own, which the fix's package reference
//! names (`gemBuilds[].patchUuid`) and whose `tarball` and stub gemspec
//! the tree is unpacked from:
//!
//! ```text
//! .socket/vendor/gem/<uuid>/<name>-<version>/<platform>/…        # the unpacked platform gem
//! .socket/vendor/gem/<uuid>/<name>-<version>/<platform>/<name>.gemspec
//!
//! PATH
//!   remote: .socket/vendor/gem/<uuid>/<name>-<version>
//!   specs:
//!     <name> (<version>-<platform>)     # every platform block, verbatim
//!       <dep> (<constraint>)
//!     <name> (<version>-<platform>)
//!       <dep> (<constraint>)
//! ```
//!
//! * the vendored dir, the Gemfile `path:` and the `PATH` `remote:` are the
//!   ones of a ruby-platform gem: bundler's path glob (`{,*,*/*}.gemspec`)
//!   finds the gemspec of every platform tree, locks one spec per platform
//!   under the one section, and loads the tree of the running platform with
//!   no build step;
//! * EVERY platform block of the gem moves into the section, and every
//!   `CHECKSUMS` line of the gem becomes bare;
//! * the trees hold compiled extensions (`*.so`, `*.bundle`, a JRuby gem's
//!   `*.jar`), which stock ignore templates name, so the uuid dir gets the
//!   `.gitignore` (`!*`) and `.gitattributes` every backend that commits
//!   binaries writes: they re-include the trees and keep a project filter
//!   (a Git LFS rule, EOL conversion) off their bytes. A `.gitignore` a
//!   platform gem ships inside its own tree would override that, so it is
//!   emptied in the copy. A tree git would still not commit in full is
//!   refused: wired without its binary, the gem would install everywhere
//!   and fail to load;
//! * every locked platform needs a patched build. While the fix's
//!   reference names none for one of them (the patch registry serves
//!   upstream's own gem for it, does not list it, or lists no platform gem
//!   at all), or the patch it names for one is not served (it is still
//!   being built, or the service does not grant it), the gem is left as it
//!   is and reported as a skip
//!   ([`super::VENDOR_PREBUILT_PLATFORM_PENDING`]): a build is named and
//!   served only once published, so the next run may find it. A plain
//!   `<name> (<version>)` entry beside the platform ones (the ruby platform,
//!   which no prebuilt tree serves) is refused with nothing written, and so
//!   is a lock written by a bundler older than the layout was run against
//!   (`PLATFORM_LAYOUT_MIN_BUNDLER`);
//! * the ledger entry records each tree's platform, patch and the digests
//!   its downloads were verified against
//!   ([`VendorEntry::gem_builds`]), which is what a restore fetches the
//!   tree again by. The trees are verified against the FIX's record for
//!   the patched files they ship; a platform patch's own record is never
//!   read here.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::formats::gem::gemfile;
use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{normalize_file_path, ApplyResult, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::path_safety::is_safe_single_segment;
use crate::patch::redirect::gem_line_tail_blocks_edit;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::line_endings::{self, to_lf, LineEndings};
use crate::utils::purl::{build_gem_purl, parse_gem_purl, purl_qualifier};
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::registry_fetch::artifact_matches_integrity;

use super::common::{
    already_patched_result, cleanup_failed_stage, copy_matches_after_hashes, done, failed_result,
    inventory_or_warn, prune_empty_vendor_levels, refused, service_offline_conflict, stage_dir_for,
    swap_stage_into_place, synthesized_result,
};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::registry_fetch::{extract_gem_data, extract_on_blocking_pool};
use super::revert::{self, KeepPolicy};
use super::service_fetch::{
    claim_prestaged, downloaded_warning, fetch_served_reference, fetch_served_references,
    fetch_verified_archive, fetch_verified_artifact, fetch_verified_secondary,
    SecondaryArtifactResult, ServicePolicy, Unserved,
};
use super::source::PackageSource;
use super::state::{
    write_marker_or_warn, GemBuildEntry, VendorArtifact, VendorEntry, VendorMarker, WiringAction,
    WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};
use crate::formats::gem::{
    is_plain_gem_token, listed_specs, split_checksum_entry, split_entry, GemfileLock,
};

pub(crate) mod bazel;

/// The code of the advisory a run gives for a gem it vendored for a Bazel
/// hub, whose build alone installs it.
pub const BAZEL_FILE_SOURCE: &str = bazel::ADVISORY;

pub(super) const GEMFILE: &str = "Gemfile";
pub(super) const GEMFILE_LOCK: &str = "Gemfile.lock";

/// Wiring-record discriminators (`key` is the gem name for all three).
///
/// `gemfile_line`: `original`/`new` are verbatim line/block strings.
///
/// `gemfile_lock_spec`: `original` and `new` are arrays of verbatim lock
/// lines. In `original`, lines indented 4+ spaces are the gem's GEM spec
/// block (one block per platform, in lock order, for a gem vendored as
/// platform gems) and the single 2-space line (if any) other than a `  remote: ` line
/// is the pre-vendor DEPENDENCIES entry — its absence means the gem was
/// transitive and revert deletes the added entry. A `  remote: ` line names
/// the GEM section the block came from, and revert restores into it. It is
/// left out when that section is the lock's first GEM section (#779) and
/// not a hosted gem's own ([`hosted_gem_section`]); revert then restores
/// into the first GEM section that is not a hosted gem's (#2090). In
/// `new`, the last element is the DEPENDENCIES entry we wrote and the rest
/// is the emitted PATH section.
///
/// `gemfile_lock_checksum`: `original`/`new` are the verbatim CHECKSUMS line
/// strings (the registry `  <name> (<version>) sha256=<hex>` form vs the bare
/// `  <name> (<version>)` path form). A SEPARATE record — never appended into
/// `gemfile_lock_spec`'s arrays, whose revert parses them positionally. For
/// a gem vendored as platform gems each is an ARRAY of such lines, one per
/// platform entry the edit made bare (`new`) and the registry line each
/// replaced (`original`); revert pairs them by their `<name> (<token>)`.
const GEMFILE_WIRING_KIND: &str = "gemfile_line";
const LOCK_WIRING_KIND: &str = "gemfile_lock_spec";
const LOCK_CHECKSUM_WIRING_KIND: &str = "gemfile_lock_checksum";

/// Managed-block fence for transitive (not-Gemfile-declared) gems.
const MANAGED_OPEN: &str = "# >>> socket-patch vendor (managed) >>>";
const MANAGED_CLOSE: &str = "# <<< socket-patch vendor (managed) <<<";
/// The option that ends the managed block's declaration. The block declares
/// a gem the Gemfile did not, and `Bundler.require` loads every declared
/// gem of the groups it is given unless the declaration says
/// `require: false` (#2084). Hosted mode writes the same option on the line
/// it adds for such a gem.
const REQUIRE_FALSE: &str = ", require: false";

/// Everything [`vendor_gem`] decides before it can first ask the patch
/// service, up to its dry-run branch: the coordinate guards, the no-op of an
/// empty patch, the platform refusals, the Gemfile and Gemfile.lock reads,
/// the local stub gemspec and its native-extension refusal, and the hot
/// path's tests (with the stale-CHECKSUMS refusal). With [`gem_edits`] it is
/// every refusal a wet run raises before its first service call, so the
/// download plan evaluates the same functions ahead of the vendor loop
/// ([`service_preflight`]). `installed_path` is the source's
/// [`PackageSource::path`] — only its name and parents are read.
struct GemPrelude {
    name: String,
    version: String,
    copy_rel: String,
    uuid_dir: PathBuf,
    copy_dir: PathBuf,
    gemfile_path: PathBuf,
    gemfile_text: String,
    lock_path: PathBuf,
    /// The lock in LF form; [`GemPrelude::lock_eol`] spells an edit back.
    lock_text: String,
    /// The lock's own line ending (#1808): a CRLF lock (a Git for Windows
    /// `autocrlf` checkout; bundler keeps CRLF) is edited in LF form and
    /// written back in CRLF.
    lock_eol: LineEndings,
    /// Gemfile and Gemfile.lock already wire this uuid's copy.
    lock_wired: bool,
    /// ...and the committed copy is intact (the in-sync hot path, which
    /// never asks the service).
    copy_ok: bool,
    /// The platforms the lock pins the gem for, in lock order, when it
    /// locks it as precompiled platform gems (see the module docs): the
    /// copy is then one patched platform gem's tree per platform. Empty
    /// for the plain `name (version)` entry, vendored as the gem's own
    /// tree.
    platforms: Vec<String>,
}

/// What `Gemfile.lock` resolves `name`@`version` to, read from every source
/// section (`GEM`, `PATH`, `GIT`, `PLUGIN SOURCE`; a lock already vendored
/// holds the entries in our `PATH` section): the plain `name (version)`
/// entry of the ruby platform, and the platforms of its platform-suffixed
/// entries (`name (version-arm64-darwin)`), in lock order.
struct LockedGem {
    plain: bool,
    platforms: Vec<String>,
}

impl LockedGem {
    /// No section resolves the gem at this version (#2075): there is no
    /// entry to move into a `PATH` section. What [`listed_specs`] says of
    /// the same lock.
    fn absent(&self) -> bool {
        !self.plain && self.platforms.is_empty()
    }
}

fn locked_gem(lock: &GemfileLock<'_>, name: &str, version: &str) -> LockedGem {
    let mut locked = LockedGem {
        plain: false,
        platforms: Vec::new(),
    };
    let specs = lock
        .sections
        .iter()
        .flat_map(|s| s.specs.iter().filter_map(|l| l.parsed))
        .filter(|spec| spec.name == name && spec.version == version);
    for spec in specs {
        match spec.platform {
            None => locked.plain = true,
            Some(platform) if !locked.platforms.iter().any(|p| p == platform) => {
                locked.platforms.push(platform.to_string());
            }
            Some(_) => {}
        }
    }
    locked
}

/// Why vendored mode must not wire this project's Gemfile, if it must not:
/// bundler loads a different manifest. This backend edits the `Gemfile` +
/// `Gemfile.lock` pair, so a project where bundler loads `gems.rb` (it wins
/// over a Gemfile twin) or a `BUNDLE_GEMFILE`-configured manifest is refused
/// before any write: wiring the ignored Gemfile would report success while
/// bundler installs the upstream gem. The CLI's hosted→vendored takeover
/// asks this BEFORE it reverts a live hosted pin, so a refused gem keeps
/// its hosted wiring instead of ending up unpatched in both modes.
pub async fn gem_manifest_refusal(project_root: &Path) -> Option<(&'static str, String)> {
    use crate::formats::gem::manifest::LoadedManifest;
    let loaded = crate::crawlers::ruby_crawler::bundler_loaded_manifest(project_root).await;
    let gems_rb_present = tokio::fs::symlink_metadata(project_root.join("gems.rb"))
        .await
        .is_ok();
    match loaded.pair(gems_rb_present) {
        Some((GEMFILE, GEMFILE_LOCK)) => None,
        // A `gems.rb` twin is refused whatever bundler runs: bundler >= 2
        // loads `gems.rb` (with a "Multiple gemfiles" warning) while 1.x
        // still reads the Gemfile first, so wiring the Gemfile is only
        // right on a bundler this backend cannot see.
        Some((manifest, lock)) if matches!(loaded, LoadedManifest::Default) => Some((
            "gemfile_not_loaded",
            format!(
                "a {manifest} sits beside the Gemfile and bundler >= 2 loads {manifest} + \
                 {lock} instead of the Gemfile + Gemfile.lock pair vendored mode wires (a \
                 gems.rb project cannot vendor yet); use hosted mode, or remove gems.rb / \
                 gems.locked if the Gemfile is the real manifest"
            ),
        )),
        Some((manifest, lock)) => Some((
            "gemfile_not_loaded",
            format!(
                "BUNDLE_GEMFILE makes bundler load {manifest} + {lock}, not the Gemfile + \
                 Gemfile.lock pair vendored mode wires (a gems.rb project cannot vendor yet); \
                 use hosted mode"
            ),
        )),
        None => Some((
            "gemfile_not_loaded",
            loaded.unsupported_detail().unwrap_or_default(),
        )),
    }
}

/// Refusal code of a gem version the project's `Gemfile.lock` doesn't
/// resolve. An expected skip, not a failure: the gem belongs to another
/// project (or to Ruby itself), and there is nothing in this one to wire.
pub const GEM_VERSION_NOT_LOCKED: &str = "vendor_gem_version_not_locked";

fn version_not_locked_detail(name: &str, version: &str) -> String {
    format!(
        "{GEMFILE_LOCK} does not resolve {name} {version}: this project doesn't lock that \
         version, so there is nothing to vendor"
    )
}

/// The refusals the backend raises for the gem purls of `purls` from
/// `Gemfile.lock` alone, each with its purl, decided before the patch
/// service is asked for anything:
///
/// * [`GEM_VERSION_NOT_LOCKED`] for a version the lock doesn't resolve. A
///   project that installs to a shared gem home (the Bundler default) is
///   crawled together with the versions Ruby ships and the ones other
///   projects installed; vendoring is a `Gemfile.lock` edit, and for those
///   versions there is no entry to edit (#2075, the vendored twin of hosted
///   mode's `redirect_gem_version_not_locked`). A spec entry in any source
///   section counts as resolved.
/// * [`platform_lock_refusal`] for a gem the lock pins as platform gems in
///   a way that cannot be vendored (the ruby platform locked beside them, a
///   lock written by an older bundler). The CLI raises it with its other
///   pre-download refusals, so a gem under a hosted pin is refused BEFORE
///   the hosted→vendored takeover restores its upstream entry; refused by
///   the backend afterwards, it would end up unpatched in both modes.
///
/// Read-only: the lock is read and parsed once for every purl. Nothing is
/// returned when bundler loads another manifest or the lock can't be read:
/// the backend reports those itself.
pub async fn gem_lock_refusals(
    project_root: &Path,
    purls: &[&str],
) -> Vec<(String, (&'static str, String))> {
    let gems: Vec<(&str, String, String)> = purls
        .iter()
        .filter_map(|purl| {
            let (name, version) = parse_gem_purl(purl)?;
            Some((*purl, name.to_string(), version.to_string()))
        })
        .collect();
    if gems.is_empty() || gem_manifest_refusal(project_root).await.is_some() {
        return Vec::new();
    }
    let Ok(lock_text) = read_regular_to_string(&project_root.join(GEMFILE_LOCK)).await else {
        return Vec::new();
    };
    let lock = crate::formats::gem::parse(&lock_text);
    gems.into_iter()
        .filter_map(|(purl, name, version)| {
            let locked = locked_gem(&lock, &name, &version);
            let refusal = match locked.absent() {
                true => (
                    GEM_VERSION_NOT_LOCKED,
                    version_not_locked_detail(&name, &version),
                ),
                false => platform_lock_refusal(&name, &version, &locked, &lock_text)?,
            };
            Some((purl.to_string(), refusal))
        })
        .collect()
}

/// The gem purls of `purls`, as given, that `Gemfile.lock` resolves as
/// precompiled platform gems (see the module docs), in any source section
/// (a lock already vendored holds them in our `PATH` section). What is
/// vendored for such a gem is the lock's to say: an installed copy is one
/// platform's gem at most, and its files say nothing of the patch's.
/// Read-only; none when bundler loads another manifest or the lock cannot
/// be read.
pub async fn gems_locked_as_platform_gems(project_root: &Path, purls: &[&str]) -> Vec<String> {
    let gems: Vec<(&str, String, String)> = purls
        .iter()
        .filter_map(|purl| {
            let (name, version) = parse_gem_purl(purl)?;
            Some((*purl, name.to_string(), version.to_string()))
        })
        .collect();
    if gems.is_empty() || gem_manifest_refusal(project_root).await.is_some() {
        return Vec::new();
    }
    let Ok(lock_text) = read_regular_to_string(&project_root.join(GEMFILE_LOCK)).await else {
        return Vec::new();
    };
    let lock = crate::formats::gem::parse(&lock_text);
    gems.into_iter()
        .filter(|(_, name, version)| !locked_gem(&lock, name, version).platforms.is_empty())
        .map(|(purl, ..)| purl.to_string())
        .collect()
}

/// The [`GEM_VERSION_NOT_LOCKED`] refusals of [`gem_lock_refusals`].
pub async fn gem_version_not_locked_refusals(
    project_root: &Path,
    purls: &[&str],
) -> Vec<(String, (&'static str, String))> {
    let mut refusals = gem_lock_refusals(project_root, purls).await;
    refusals.retain(|(_, (code, _))| *code == GEM_VERSION_NOT_LOCKED);
    refusals
}

/// The per-gem twin of [`gem_manifest_refusal`] for the hosted→vendored
/// takeover: the backend's Gemfile declaration gate ([`plan_gemfile_edit`]
/// and [`refuse_append_of_direct_dependency`], refused as
/// `gemfile_declaration_not_editable`, with [`gemspec_merge_refusal`]) for
/// `purl`. Evaluated on the files
/// as the takeover's restore of `pin` will leave them: a dry-run
/// [`restore_upstream`] supplies the restored `Gemfile` / `Gemfile.lock`
/// text, so the hosted `source … do` block socket-patch itself wrote is
/// never mistaken for the user's declaration. A gem declared inside a
/// `group` block is the common case: hosted mode wires it, vendored mode
/// cannot, and without this gate the takeover un-hosts it first (#775).
/// Returns `(code, detail)`, exactly the refusal the backend would raise
/// after the restore; `None` when it would not refuse, when the restore
/// itself would refuse (the takeover reports that), or when the files are
/// unreadable (which the backend reports itself).
///
/// [`restore_upstream`]: crate::patch::redirect::upstream::restore_upstream
pub async fn gem_vendor_target_preflight(
    project_root: &Path,
    purl: &str,
    pin: &crate::patch::redirect::upstream::HostedPin,
    opts: &crate::patch::redirect::upstream::RestoreOptions,
) -> Option<(&'static str, String)> {
    use crate::patch::redirect::upstream::{restore_upstream, RestoreOptions};
    let (name, version) = parse_gem_purl(purl)?;
    // The copy path only shapes a plan that passes; any refusal is decided
    // by the declaration alone, so an unsafe uuid is left to the backend.
    let copy_rel = format!(
        "{}/{name}-{version}",
        vendor_uuid_dir_rel("gem", &pin.uuid)?
    );
    let dry = RestoreOptions {
        dry_run: true,
        ..opts.clone()
    };
    let restore = restore_upstream(project_root, std::slice::from_ref(pin), &dry).await;
    if restore.refused().next().is_some() {
        return None;
    }
    let restored = |file: &str| restore.staged_text.get(file).cloned();
    let gemfile_text = match restored(GEMFILE) {
        Some(text) => text?,
        None => read_regular_to_string(&project_root.join(GEMFILE))
            .await
            .ok()?,
    };
    let lock_text = match restored(GEMFILE_LOCK) {
        Some(text) => text?,
        None => read_regular_to_string(&project_root.join(GEMFILE_LOCK))
            .await
            .ok()?,
    };
    plan_gemfile_edit(&gemfile_text, &name, &version, &copy_rel)
        .and_then(|plan| refuse_append_of_direct_dependency(plan, &gemfile_text, &lock_text, &name))
        .and_then(|plan| {
            let after = apply_gemfile_plan(&gemfile_text, &plan);
            gemspec_merge_refusal(project_root, &after, &lock_text, &name, &version)
                .map_or(Ok(()), Err)
        })
        .err()
        .map(|detail| ("gemfile_declaration_not_editable", detail))
}

async fn gem_prelude(
    purl: &str,
    installed_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
) -> Result<GemPrelude, VendorOutcome> {
    gem_prelude_of(
        purl,
        installed_path,
        project_root,
        &record.uuid,
        Some(&record.files),
    )
    .await
}

/// [`gem_prelude`] for the patch `uuid` and its `files`. A caller that has
/// not fetched the patch's record passes no files (a preview): the copy of
/// a lock already wired to the patch is then not tested, and reads as not
/// in sync.
async fn gem_prelude_of(
    purl: &str,
    installed_path: &Path,
    project_root: &Path,
    uuid: &str,
    files: Option<&HashMap<String, PatchFileInfo>>,
) -> Result<GemPrelude, VendorOutcome> {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some((name, version)) = parse_gem_purl(purl) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("not a gem purl: {purl}"),
        ));
    };
    let (name, version) = (name.to_string(), version.to_string());
    let (name, version) = (name.as_str(), version.as_str());
    // SECURITY: `uuid`, `name` and `version` come from committed, tamper-able
    // manifest data. They key the copy dir vendor creates and `--revert`
    // deletes, and — stricter than the path guard — they are embedded
    // VERBATIM into the user's Gemfile (ruby source executed on every
    // `bundle`) and into Gemfile.lock's line grammar. A quote, space, paren,
    // or newline would be a code/grammar injection, so only the plain gem
    // token charset is accepted. Reject fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("gem", uuid) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {uuid:?}"),
        ));
    };
    if !is_safe_single_segment(name)
        || !is_safe_single_segment(version)
        || !is_plain_gem_token(name)
        || !is_plain_gem_token(version)
    {
        return Err(refused(
            "unsafe_coordinates",
            format!("unsafe gem coordinates `{name}` @ `{version}`"),
        ));
    }

    let leaf = format!("{name}-{version}");
    let copy_rel = format!("{uuid_dir_rel}/{leaf}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if files.is_some_and(HashMap::is_empty) {
        return Err(done(
            synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            None,
            Vec::new(),
        ));
    }

    // A platform-specific (precompiled) gem build ships machine-specific
    // artifacts — committing ONE would break every other platform — so the
    // installed build is never what gets vendored. Two independent signals
    // say the copy is such a build:
    //
    //   1. The purl's own `?platform=` qualifier (the AUTHORITATIVE production
    //      key). RubyGems' default portable platform is `ruby`; a bare purl
    //      (no qualifier) is likewise the portable build. A *native* platform
    //      value (`x86_64-linux`, `arm64-darwin`, `java`, `x64-mingw32`, …)
    //      names a patch of one platform's build and is refused: a patch's
    //      prebuilds belong to its `ruby` record.
    //   2. The resolved install dir's own name. A locally-installed native
    //      variant is `<name>-<version>-<platform>` even when the manifest
    //      purl looked portable (the crawler strips the suffix to the base
    //      purl, so a `?platform=ruby` lookup can still land on a native
    //      install dir). Whether that is vendorable is the lock's to say,
    //      below: a lock that pins the gem as platform gems is vendored from
    //      the patch service's patched gem of EVERY platform it pins (the
    //      installed dir is one of them, and is not read).
    //
    // Gating on the platform (not only the staging dir name) lets
    // `?platform=ruby` and bare purls vendor whatever the staging dir is
    // called, while still refusing true native builds by either signal.
    if let Some(platform) = purl_qualifier(purl, "platform") {
        if !platform.is_empty() && !platform.eq_ignore_ascii_case("ruby") {
            return Err(refused(
                "platform_gem_unsupported",
                format!(
                    "`{name}@{version}` is a platform-specific gem build (`platform={platform}`); precompiled platform gems cannot be vendored portably. {}",
                    platform_gem_remedy(name)
                ),
            ));
        }
    }
    let dir_name = installed_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Fail closed: only three dir names are legitimate here — the gem's own
    // `<name>-<version>` leaf (installed, or staged by
    // a server download), a literal `gem` staging dir, still
    // admitted for compatibility though fetch_gem no longer produces it, and
    // a `<name>-<version>-<platform>` precompiled build, which is judged
    // against the lock once it is read (below). Everything else is refused;
    // an allowlist (not a suffix match) means an unexpected install dir
    // name can never slip through into a vendored copy.
    let installed_as_dir = installed_path.is_dir();
    let platform_install = installed_as_dir
        && dir_name
            .strip_prefix(leaf.as_str())
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|platform| !platform.is_empty());
    let not_portable = || {
        refused(
            "platform_gem_unsupported",
            format!(
                "installed dir `{dir_name}` is not the portable `{leaf}` gem (platform-specific or unexpected gem builds cannot be vendored portably). {}",
                    platform_gem_remedy(name)
            ),
        )
    };
    if installed_as_dir && dir_name != leaf && dir_name != "gem" && !platform_install {
        return Err(not_portable());
    }

    // ── project files ────────────────────────────────────────────────────
    if let Some((code, detail)) = gem_manifest_refusal(project_root).await {
        return Err(refused(code, detail));
    }
    let gemfile_path = project_root.join(GEMFILE);
    let gemfile_text = match read_regular_to_string(&gemfile_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused(
                "gemfile_missing",
                format!("no Gemfile at {}", gemfile_path.display()),
            ));
        }
        Err(e) => {
            return Err(refused(
                "gemfile_missing",
                format!("unreadable Gemfile: {e}"),
            ));
        }
    };
    let lock_path = project_root.join(GEMFILE_LOCK);
    let lock_text = match read_regular_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused(
                "vendor_lockfile_missing",
                format!(
                    "no Gemfile.lock at {} (the pair edit needs the lock)",
                    lock_path.display()
                ),
            ));
        }
        Err(e) => {
            return Err(refused(
                "vendor_lockfile_missing",
                format!("unreadable Gemfile.lock: {e}"),
            ));
        }
    };
    let (lock_eol, lock_text) = lock_lf_form(lock_text);
    // A version the lock doesn't resolve has no entry to move into a PATH
    // section: an expected skip (see [`gem_lock_refusals`]), decided before
    // the patch service is asked for anything.
    if !listed_specs(&lock_text).contains(&(name, version)) {
        return Err(refused(
            GEM_VERSION_NOT_LOCKED,
            version_not_locked_detail(name, version),
        ));
    }

    // ── a gem the lock pins as precompiled platform gems ─────────────────
    // The lock decides what is vendored: the gem's own tree for the plain
    // `name (version)` entry, the patch service's patched platform gems
    // for platform-suffixed ones (see the module docs). Decided here,
    // before the patch service is asked for anything.
    let locked = locked_gem(&crate::formats::gem::parse(&lock_text), name, version);
    if locked.platforms.is_empty() {
        // Locked for the ruby platform alone: the copy to vendor is the
        // ruby gem's tree, which a precompiled install is not (and whose
        // extensions bundler would never build from a `path:`).
        if platform_install {
            return Err(not_portable());
        }
    } else if let Some((code, detail)) = platform_lock_refusal(name, version, &locked, &lock_text) {
        return Err(refused(code, detail));
    }

    let local_stub = {
        let spec_src = installed_path
            .parent()
            .filter(|gems| gems.file_name().is_some_and(|n| n == "gems"))
            .and_then(Path::parent)
            .map(|home| home.join("specifications").join(format!("{leaf}.gemspec")));
        match spec_src {
            Some(p) => read_regular_to_string(&p).await.ok(),
            None => None,
        }
    };
    // Textual heuristic, deliberately fail-closed on a match: bundler skips
    // extension builds for path sources entirely, so a native gem would
    // install fine and then fail at `require` time with a missing `.so`.
    // Only the local stub is checked here (when present); the service stub is
    // re-checked in `gem_service_copy`, and a native gem emits no service stub
    // at all (the converter refuses it), so the service path also misses.
    // A gem locked as platform gems is vendored from patched platform
    // gems, which have nothing to build: an installed ruby-platform copy of
    // it (compiled on this machine, beside the lock's platform gems) says
    // nothing of them.
    if let Some(text) = local_stub.as_ref().filter(|_| locked.platforms.is_empty()) {
        if gemspec_declares_extensions(text) {
            return Err(refused(
                "native_extensions_unsupported",
                format!(
                    "{leaf}.gemspec declares native extensions; bundler does not build extensions for path-sourced gems. {}",
                    native_extensions_remedy(name, !declaration_selects_source(&gemfile_text, name))
                ),
            ));
        }
    }

    // The idempotent hot path's tests (see `vendor_gem`): the pair edit
    // already wires this uuid's copy; the lock's CHECKSUMS entry is in the
    // bare path form (a stale registry line is refused, dry run or not); and
    // the committed copy — gemspec included — is intact.
    let remote_line = format!("  remote: {copy_rel}");
    let lock_wired =
        lock_text.split('\n').any(|l| l == remote_line) && gemfile_text.contains(&copy_rel);
    let mut copy_ok = false;
    if let (true, Some(files)) = (lock_wired, files) {
        if lock_checksum_in_sync(&lock_text, name, version, &locked.platforms) {
            // Probe the copy only once the lock is known to be wired (the
            // common fresh vendor has no copy to hash). Invalid-stub heal: a
            // project vendored before the stub check carries a defective
            // SERVED stub on disk, so EXISTS is not enough — an
            // on-disk stub that fails the required-attribute bar routes into
            // the artifact rebuild (which re-materialises a valid stub)
            // instead of the silent `already_vendored` no-op. The stub read
            // runs second so a hash mismatch short-circuits it.
            copy_ok = match locked.platforms.as_slice() {
                [] => {
                    copy_matches_after_hashes(&copy_dir, files).await
                        && stub_gemspec_valid(&copy_dir, name).await
                }
                platforms => {
                    let recorded = recorded_copy(project_root, uuid, &copy_rel).await;
                    platform_copy_intact(&copy_dir, name, platforms, recorded.as_ref(), files).await
                }
            };
        } else {
            // Wired everywhere EXCEPT the lock's CHECKSUMS entry, which still
            // carries the registry form — a lock wired by a pre-CHECKSUMS-aware
            // socket-patch. Bundler never repairs this itself (spike G4: install,
            // frozen install and `bundle lock` all silently preserve a stale
            // token), and we cannot strip it here: this run records no ledger
            // entry, so a revert would put back everything EXCEPT the token —
            // leaving a bare CHECKSUMS entry on a registry-sourced gem, which
            // hard-fails frozen installs (exit 16). Refuse with the repair path
            // instead of the generic "already carries `path:`" Gemfile refusal.
            return Err(refused(
                "vendor_stale_lock_checksum",
                format!(
                    "Gemfile.lock already wires `{name}` to {copy_rel} but its CHECKSUMS entry is not bundler's bare path-gem form (an earlier socket-patch left the registry line in place); {remedy} to repair {purl}",
                    remedy = super::common::REVERT_ALL_AND_REVENDOR,
                ),
            ));
        }
    }
    // ── prebuilt trees git would not commit ──────────────────────────────
    // Short of the in-sync no-op, this run (or the wet run a dry run
    // previews) writes prebuilt binaries under the uuid dir. A rule that
    // ignores the dir itself (`.socket/`) cannot be overridden from inside
    // it, so the commit would drop the trees the lock names: refused here,
    // dry run or not, before anything is downloaded. Rules that ignore
    // single files are for [`keep_platform_trees_committable`], once the
    // trees are known.
    let in_sync = lock_wired && copy_ok;
    if !locked.platforms.is_empty() && !in_sync {
        if let Some((code, detail)) =
            super::npm_dir::ignored_root_refusal(project_root, &uuid_dir_rel).await
        {
            return Err(refused(code, detail));
        }
    }
    Ok(GemPrelude {
        name: name.to_string(),
        version: version.to_string(),
        copy_rel,
        uuid_dir,
        copy_dir,
        gemfile_path,
        gemfile_text,
        lock_path,
        lock_text,
        lock_eol,
        lock_wired,
        copy_ok,
        platforms: locked.platforms,
    })
}

/// The oldest bundler whose lock is wired to a directory of prebuilt
/// platform gems: the oldest one the layout is run against (the gate of the
/// real-bundler capstone in the CLI's `e2e_vendor_gem_build` suite, which
/// frozen-installs it on 2.3 up to 4.x). Whether an older bundler locks
/// one spec per platform for such a directory and loads the tree of the
/// running platform is not known, so its lock is left alone.
const PLATFORM_LAYOUT_MIN_BUNDLER: (u32, u32) = (2, 3);

/// Why a gem the lock pins as platform gems cannot be vendored as patched
/// platform gems, when the lock alone says so: it also locks the plain
/// `name (version)` entry — the ruby platform, which no prebuilt tree
/// serves and whose extensions bundler never builds for a `path:` gem —
/// one of its platforms is no directory name, or the bundler that wrote
/// the lock (`BUNDLED WITH`) is unknown or older than
/// [`PLATFORM_LAYOUT_MIN_BUNDLER`]. `None` for a gem the lock does not pin
/// as platform gems.
fn platform_lock_refusal(
    name: &str,
    version: &str,
    locked: &LockedGem,
    lock_text: &str,
) -> Option<(&'static str, String)> {
    if locked.platforms.is_empty() {
        return None;
    }
    if locked.plain {
        let entries: Vec<String> = locked
            .platforms
            .iter()
            .map(|platform| format!("`{name} ({version}-{platform})`"))
            .collect();
        return Some((
            "platform_gem_unsupported",
            format!(
                "{GEMFILE_LOCK} locks `{name} ({version})` (the ruby platform) beside the platform gems {}: a vendored directory of prebuilt platform gems has nothing for the ruby platform, and bundler never builds a `path:` gem's extensions. Remove the ruby platform from the lock (`bundle lock --remove-platform ruby`) to vendor {name}",
                entries.join(", ")
            ),
        ));
    }
    // SECURITY: each platform names a directory under the copy dir.
    if let Some(unsafe_platform) = locked.platforms.iter().find(|p| !is_platform_dir_name(p)) {
        return Some((
            "unsafe_coordinates",
            format!("unsafe gem platform `{unsafe_platform}` for `{name}` @ `{version}`"),
        ));
    }
    let (major, minor) = PLATFORM_LAYOUT_MIN_BUNDLER;
    let written_by = match crate::formats::gem::hosted::bundled_with_version(lock_text) {
        Some((bundler, _)) if bundler >= PLATFORM_LAYOUT_MIN_BUNDLER => return None,
        Some((_, written)) => format!("was written by Bundler {written}"),
        None => "does not say which Bundler wrote it (no `BUNDLED WITH`)".to_string(),
    };
    Some((
        "platform_gem_unsupported",
        format!(
            "{GEMFILE_LOCK} locks `{name}` as precompiled platform gems and {written_by}: a vendored directory of prebuilt platform gems needs Bundler {major}.{minor} or later, the oldest it is verified on. Re-lock with Bundler {major}.{minor} or later (`bundle update --bundler`) to vendor {name}"
        ),
    ))
}

/// The [`platform_lock_refusal`]s of [`gem_lock_refusals`].
pub async fn gem_platform_lock_refusals(
    project_root: &Path,
    purls: &[&str],
) -> Vec<(String, (&'static str, String))> {
    let mut refusals = gem_lock_refusals(project_root, purls).await;
    refusals.retain(|(_, (code, _))| *code != GEM_VERSION_NOT_LOCKED);
    refusals
}

/// Whether a gem platform may name a directory under the vendored dir: one
/// safe path segment in the plain gem-token charset. The platforms of a
/// lock entry and of a ledger entry both come from committed, tamper-able
/// files.
pub(super) fn is_platform_dir_name(platform: &str) -> bool {
    is_safe_single_segment(platform) && is_plain_gem_token(platform)
}

/// Whether `tree` holds the stub gemspec of the gem `name`
/// (`<name>.gemspec`, which a path source needs) with the attributes
/// bundler requires of one.
async fn stub_gemspec_valid(tree: &Path, name: &str) -> bool {
    match read_regular_to_string(&tree.join(format!("{name}.gemspec"))).await {
        Ok(text) => gemspec_missing_required_attrs(&text).is_empty(),
        Err(_) => false,
    }
}

/// The vendor ledger's entry for the copy at `copy_rel` of the patch
/// `uuid`: its file inventory is what vouches for the bytes of the
/// platform trees once they are vendored (see [`verify_platform_tree`]),
/// and it names the patch each tree came from. `None` when the ledger has
/// no entry for that copy or cannot be read.
///
/// [`verify_platform_tree`]: super::verify::verify_platform_tree
async fn recorded_copy(project_root: &Path, uuid: &str, copy_rel: &str) -> Option<VendorEntry> {
    let state = super::state::load_state_shared(project_root).await.ok()?;
    state
        .entries
        .values()
        .find(|e| {
            e.ecosystem == "gem" && e.uuid == uuid && e.artifact.path.replace('\\', "/") == copy_rel
        })
        .cloned()
}

/// Whether the copy the ledger records at `copy_rel` for the patch `uuid`
/// is intact as recorded: every tree the entry names passes
/// [`platform_copy_intact`]. What a run that cannot bring the copy up to
/// date asks before it leaves it in force.
async fn recorded_copy_stands(
    project_root: &Path,
    record: &PatchRecord,
    copy_rel: &str,
    copy_dir: &Path,
    name: &str,
) -> bool {
    let Some(entry) = recorded_copy(project_root, &record.uuid, copy_rel).await else {
        return false;
    };
    let platforms: Vec<String> = entry
        .gem_tree_platforms()
        .into_iter()
        .map(str::to_string)
        .collect();
    !platforms.is_empty()
        && platforms.iter().all(|p| is_platform_dir_name(p))
        && platform_copy_intact(copy_dir, name, &platforms, Some(&entry), &record.files).await
}

/// The in-sync test of a copy vendored as platform gems: the tree of every
/// locked platform is there, passes
/// [`super::verify::verify_platform_tree`] (every file of it is the one
/// the ledger's `inventory` of the copy records; without an inventory it
/// must hold a patched file) and has a valid stub gemspec. With an
/// inventory, the copy as a whole must also match it, as `vendor --check`
/// requires: a file outside every locked tree (at the copy root, or the
/// tree of a platform the lock does not name) is not in sync.
async fn platform_copy_intact(
    copy_dir: &Path,
    name: &str,
    platforms: &[String],
    entry: Option<&VendorEntry>,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    let inventory = entry.and_then(|entry| entry.artifact.file_inventory.as_ref());
    for platform in platforms {
        let tree = copy_dir.join(platform);
        let voucher = super::verify::TreeVoucher::Ledger(inventory);
        // Each tree is a build of its own patch (`GemBuildEntry::files`).
        let files = entry.map_or_else(
            || files.clone(),
            |entry| entry.gem_tree_files(platform, files),
        );
        if super::verify::verify_platform_tree(&tree, &files, voucher)
            .await
            .is_err()
            || !stub_gemspec_valid(&tree, name).await
        {
            return false;
        }
    }
    match inventory {
        Some(inventory) => super::verify::verify_dir_inventory(copy_dir, inventory, None)
            .await
            .is_ok(),
        None => true,
    }
}

/// A fresh wet vendor's pure edits, computed before any download or write:
/// the Gemfile declaration plan (refused when not editable) and the
/// Gemfile.lock surgery (a failed `Done` when the lock's shape defeats it).
fn gem_edits(
    purl: &str,
    prelude: &GemPrelude,
) -> Result<(GemfilePlan, LockEdit), Box<VendorOutcome>> {
    let (name, version) = (prelude.name.as_str(), prelude.version.as_str());
    // ── a lock the edit cannot be written back into (#1808) ──────────────
    // Checked first: no Gemfile fix makes such a lock editable.
    if prelude.lock_eol == LineEndings::Mixed {
        return Err(Box::new(done(
            failed_result(
                purl,
                &prelude.copy_dir,
                "failed to edit Gemfile.lock: it mixes CRLF and LF line endings, so there is no one line ending to write the edit back in (normalize the file, e.g. re-run `bundle lock`, first)".to_string(),
            ),
            None,
            Vec::new(),
        )));
    }
    // ── Gemfile edit plan (refusals before any write) ────────────────────
    let plan = match plan_gemfile_edit(&prelude.gemfile_text, name, version, &prelude.copy_rel)
        .and_then(|plan| {
            refuse_append_of_direct_dependency(
                plan,
                &prelude.gemfile_text,
                &prelude.lock_text,
                name,
            )
        }) {
        Ok(p) => p,
        Err(detail) => {
            return Err(Box::new(refused(
                "gemfile_declaration_not_editable",
                detail,
            )))
        }
    };
    // ── gemspec development dependency (#985) ────────────────────────────
    let project_root = prelude.gemfile_path.parent().unwrap_or(Path::new("."));
    if let Some(detail) = gemspec_merge_refusal(
        project_root,
        &apply_gemfile_plan(&prelude.gemfile_text, &plan),
        &prelude.lock_text,
        name,
        version,
    ) {
        return Err(Box::new(refused(
            "gemfile_declaration_not_editable",
            detail,
        )));
    }
    // ── Gemfile.lock edit (pure text surgery, computed before any write) ──
    // A lock-shape failure therefore costs no download / copy / patch and no
    // Gemfile write.
    let lock_edit = edit_lock(&prelude.lock_text, name, version, &prelude.copy_rel).and_then(
        |edit| match edit.platforms == prelude.platforms {
            true => Ok(edit),
            // The copy holds one tree per platform the lock resolves the
            // gem for, and the edit moves the entries of one section:
            // an entry it leaves behind (in a GIT or foreign PATH section)
            // would have a tree and no spec in the vendored section.
            false => Err(format!(
                "Gemfile.lock lists platform entries of `{name} ({version})` outside the one section the edit moves"
            )),
        },
    );
    let lock_edit = match lock_edit {
        Ok(edit) => edit,
        Err(e) => {
            return Err(Box::new(done(
                failed_result(
                    purl,
                    &prelude.copy_dir,
                    format!("failed to edit Gemfile.lock: {e}"),
                ),
                None,
                Vec::new(),
            )));
        }
    };
    Ok((plan, lock_edit))
}

/// The archive download [`vendor_gem`] — a wet run with the service
/// enabled — makes for `record`: past every refusal it raises first
/// ([`gem_prelude`], [`gem_edits`]) and not answered by the in-sync hot
/// path. The vendor loop's download plan consults this; the `.gem`'s
/// `gem-stub-gemspec` secondary rides the same planned download. `None`
/// for a gem the lock pins as platform gems: it is vendored from the
/// patches the service's package reference names for its platforms
/// ([`stage_platform_builds`]), and the ruby gem is never downloaded.
pub(crate) async fn service_preflight(
    purl: &str,
    installed_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<crate::api::client::PlannedDownload> {
    let prelude = gem_prelude(purl, installed_path, project_root, record)
        .await
        .ok()?;
    if let Some(planned) = bazel::preflight(purl, &prelude, project_root, record).await {
        return planned;
    }
    let asks = match prelude.lock_wired {
        true => !prelude.copy_ok,
        false => gem_edits(purl, &prelude).is_ok(),
    };
    (asks && prelude.platforms.is_empty()).then(|| {
        // `gem_service_copy` fetches the stub gemspec right after the `.gem`,
        // and extracts the `.gem`'s data.tar.gz into the copy dir's stage.
        crate::api::client::PlannedDownload {
            secondary: Some(GEM_STUB_ARTIFACT_KIND.to_string()),
            stage: Some(super::prestage::PrestageRecipe::extract(
                project_root,
                &prelude.copy_dir,
                extract_gem_data,
            )),
            ..crate::api::client::PlannedDownload::archive(record.uuid.clone())
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn vendor_gem<'a>(
    purl: &str,
    installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    vendor_gem_previewing(
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        vendored_at,
        dry_run,
        force,
        service,
        false,
        &mut Vec::new(),
    )
    .await
}

/// [`vendor_gem`] for a caller that reports a gem vendored as platform
/// gems once per platform gem. A wet run names the trees it vendored in
/// the entry it hands back; a dry run hands back no entry, so the trees
/// the wet run would vendor, each with the patch it comes from, are put
/// in `previewed` (in lock order) when the dry run of such a gem passes.
/// Left as it is otherwise.
///
/// `hosted`: the lockfile pins the gem hosted, and the caller keeps that
/// pin when this call does not vendor the gem (a takeover or an eject,
/// which restores the gem's upstream entry before it calls and puts the
/// pin back after a refusal). The skip of a gem with a locked platform
/// that has no patched build then says that the gem stays hosted.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_gem_previewing<'a>(
    purl: &str,
    installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    _force: bool,
    service: Option<&VendorServiceConfig>,
    hosted: bool,
    previewed: &mut Vec<GemBuildEntry>,
) -> VendorOutcome {
    let installed_dir = installed_dir.into();
    let prelude = match gem_prelude(purl, installed_dir.path(), project_root, record).await {
        Ok(prelude) => prelude,
        Err(outcome) => return outcome,
    };
    // A gem whose lock a Bazel hub reads is committed as its archive.
    let for_hub = bazel::vendor(
        purl,
        &prelude,
        project_root,
        record,
        vendored_at,
        dry_run,
        service,
    );
    if let Some(outcome) = for_hub.await {
        return outcome;
    }
    let GemPrelude {
        name,
        version,
        copy_rel,
        uuid_dir,
        copy_dir,
        gemfile_path,
        gemfile_text,
        lock_path,
        lock_text: _,
        lock_eol,
        lock_wired,
        copy_ok,
        platforms,
    } = &prelude;
    let (name, version) = (name.as_str(), version.as_str());
    let (copy_rel, uuid_dir, copy_dir) =
        (copy_rel.as_str(), uuid_dir.as_path(), copy_dir.as_path());
    let (lock_wired, copy_ok) = (*lock_wired, *copy_ok);
    // What is vendored for each locked platform, once the service names it.
    let label = format!("{name}@{version}");
    let locked = |standing: Standing| PlatformTrees {
        gem: &label,
        from: BuildsFrom::Locked(platforms),
        standing,
    };

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy (incl. the gemspec) already carries every afterHash and both files
    // already reference the uuid path → touch nothing. `entry` stays `None`:
    // the first run's ledger entry holds the only copy of the pre-vendor
    // originals.
    if lock_wired {
        if copy_ok {
            // The uuid dir's `.gitignore` / `.gitattributes` are not part
            // of the copy: one that was deleted (or never written) is put
            // back, or a project `*.so` rule drops the binaries from the
            // next commit.
            let mut warnings: Vec<VendorWarning> = Vec::new();
            if !platforms.is_empty() && !dry_run {
                if let Err(e) = restore_uuid_metadata(uuid_dir).await {
                    warnings.push(VendorWarning::new(
                        super::npm_dir::GITIGNORE_UNCHECKED,
                        super::npm_dir::gitignore_unchecked_detail(
                            copy_rel,
                            &format!("cannot write the vendored dir's git metadata: {e}"),
                        ),
                    ));
                }
            }
            return done(
                already_patched_result(purl, copy_dir, &record.files),
                None,
                warnings,
            );
        }
        // Wired (Gemfile + lock + CHECKSUMS) but the committed copy is
        // missing/stale: rebuild the ARTIFACT only — the pair edit is
        // already correct and the full path would re-record the live
        // vendored fragments as `original`, breaking a later --revert.
        // Service-preferred like the full path (an auto-fetched gem has no
        // local stub to rebuild from — only the service can). The rebuild
        // is staged: a failure must leave the previous (drifted-but-
        // buildable) copy and the live pair edit exactly as they were,
        // never a deleted uuid dir under a still-pointing `path:`.
        if !dry_run {
            if let Some(refusal) = service_offline_conflict(service) {
                return refusal;
            }
            let mut warnings: Vec<VendorWarning> = Vec::new();
            let (result, builds) = match materialise_patched_copy(
                purl,
                copy_dir,
                uuid_dir,
                name,
                &locked(Standing::Wired),
                record,
                false, // live-wired: never unwind the uuid dir on failure
                service,
                &mut warnings,
            )
            .await
            {
                Ok(materialised) => materialised,
                Err(outcome) => {
                    return wired_copy_not_rebuilt(*outcome, project_root, record, &prelude).await
                }
            };
            if !result.success {
                return done(result, None, warnings);
            }
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored copy for {name}@{version} was missing or stale; \
                     rebuilt at {copy_rel} (Gemfile and Gemfile.lock untouched)"
                ),
            ));
            // The rebuilt tree may differ from the one the ledger
            // inventoried (a service ↔ local flip swaps the stub gemspec):
            // hand back a refreshed entry. Its wiring is empty ON PURPOSE —
            // the caller's `carry_forward_wiring` (same uuid) re-attaches the
            // first run's records, the only copy of the pre-vendor originals.
            let file_inventory =
                inventory_or_warn(copy_dir, &format!("{name}@{version}"), &mut warnings).await;
            let entry = gem_entry(
                build_gem_purl(name, version),
                record,
                copy_rel.to_string(),
                builds,
                file_inventory,
                Vec::new(),
            );
            return done(result, Some(entry), warnings);
        }
        // Dry runs fall through to the verify-only preview below.
    }

    if dry_run {
        // An unwired gem previews the Gemfile and lock edit refusals the wet
        // run raises (a declaration inside a `group` block, #1761), so a
        // takeover or eject preview over the restored text refuses too.
        let mut standing = Standing::Wired;
        if !lock_wired {
            match gem_edits(purl, &prelude) {
                Ok((plan, _)) => standing = plan.standing(hosted),
                Err(outcome) => return *outcome,
            }
        }
        let checked = match platforms.as_slice() {
            [] => super::service_fetch::preview_service(service, record, extract_gem_data)
                .await
                .map(|()| Vec::new()),
            _ => preview_platform_builds(service, record, name, &locked(standing)).await,
        };
        match checked {
            Ok(builds) => *previewed = builds,
            Err(outcome) => {
                return match lock_wired {
                    true => wired_copy_not_rebuilt(*outcome, project_root, record, &prelude).await,
                    false => *outcome,
                };
            }
        }
        return done(
            super::common::preview_result(purl, copy_dir, &record.files),
            None,
            Vec::new(),
        );
    }

    // ── Gemfile + Gemfile.lock edits (pure, computed before any write) ────
    let (plan, lock_edit) = match gem_edits(purl, &prelude) {
        Ok(edits) => edits,
        Err(outcome) => return *outcome,
    };

    // ── materialise the patched copy ──────────────────────────────────────
    // Prefer the prebuilt `.gem` + stub gemspec from the patch service
    // (download + extract; no local install or patch-apply needed); else copy
    // the installed gem, drop in the local stub gemspec, and apply the patch.
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(refusal) = service_offline_conflict(service) {
        return refusal;
    }
    let (mut result, builds) = match materialise_patched_copy(
        purl,
        copy_dir,
        uuid_dir,
        name,
        &locked(plan.standing(hosted)),
        record,
        true, // fresh vendor: nothing pre-existing worth keeping
        service,
        &mut warnings,
    )
    .await
    {
        Ok(materialised) => materialised,
        Err(outcome) => return *outcome,
    };
    if !result.success {
        // The copy / stub / patch step left the result un-successful (and
        // cleaned up its own partial copy); neither project file was touched.
        return done(result, None, warnings);
    }
    result.package_path = copy_dir.display().to_string();

    // ── prebuilt trees git would not commit ──────────────────────────────
    // Asked before either project file is written (see
    // `keep_platform_trees_committable`). The inventory taken for it is
    // the entry's, below.
    let mut platform_inventory = None;
    if !platforms.is_empty() {
        let inventory =
            inventory_or_warn(copy_dir, &format!("{name}@{version}"), &mut warnings).await;
        if let Err(refusal) = keep_platform_trees_committable(
            project_root,
            copy_rel,
            inventory.as_ref(),
            &mut warnings,
        )
        .await
        {
            let _ = remove_tree(uuid_dir).await;
            prune_empty_vendor_levels(uuid_dir).await;
            return refusal;
        }
        platform_inventory = Some(inventory);
    }

    // ── Gemfile edit ─────────────────────────────────────────────────────
    // Both project files are user-owned: preserve their permission bits.
    let new_gemfile = apply_gemfile_plan(gemfile_text, &plan);
    if let Err(e) = atomic_write_bytes_preserving_mode(gemfile_path, new_gemfile.as_bytes()).await {
        let _ = remove_tree(uuid_dir).await;
        prune_empty_vendor_levels(uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write Gemfile: {e}"));
        return done(result, None, warnings);
    }

    // ── Gemfile.lock write (a failure here unwinds the Gemfile) ──────────
    let new_lock = lock_eol.restore(&lock_edit.text);
    if let Err(e) = atomic_write_bytes_preserving_mode(lock_path, new_lock.as_bytes()).await {
        let mut detail = format!("failed to write Gemfile.lock: {e}");
        // Unwind: a Gemfile pointing at a path the lock doesn't agree with
        // is exactly the half-wired state the pair edit exists to prevent —
        // restore the recorded original bytes.
        if let Err(e) =
            atomic_write_bytes_preserving_mode(gemfile_path, gemfile_text.as_bytes()).await
        {
            detail.push_str(&format!(" (Gemfile unwind also failed: {e})"));
        }
        let _ = remove_tree(uuid_dir).await;
        prune_empty_vendor_levels(uuid_dir).await;
        result.success = false;
        result.error = Some(detail);
        return done(result, None, warnings);
    }

    // ── marker + ledger entry ────────────────────────────────────────────
    let base_purl = build_gem_purl(name, version);
    let marker = VendorMarker::new("gem", &base_purl, record, vendored_at);
    write_marker_or_warn(uuid_dir, &marker, &mut warnings).await;

    let gemfile_record = match &plan {
        GemfilePlan::Rewrite {
            original_line,
            new_line,
        } => WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: Some(Value::String(original_line.clone())),
            new: Some(Value::String(new_line.clone())),
        },
        GemfilePlan::Append { block } => WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some(name.to_string()),
            original: None,
            new: Some(Value::String(block.clone())),
        },
        // Re-vendor over our own wiring (see `GemfilePlan::RewireOurs`):
        // `original: None`, carried forward by the caller. The managed-fence
        // form stays `Added` with the whole updated block so revert deletes
        // the fence too.
        GemfilePlan::RewireOurs {
            new_line,
            managed_block,
            ..
        } => match managed_block {
            Some(block) => WiringRecord {
                file: GEMFILE.to_string(),
                kind: GEMFILE_WIRING_KIND.to_string(),
                action: WiringAction::Added,
                key: Some(name.to_string()),
                original: None,
                new: Some(Value::String(block.clone())),
            },
            None => WiringRecord {
                file: GEMFILE.to_string(),
                kind: GEMFILE_WIRING_KIND.to_string(),
                action: WiringAction::Rewritten,
                key: Some(name.to_string()),
                original: None,
                new: Some(Value::String(new_line.clone())),
            },
        },
    };
    // A rewire lifted OUR OWN previous PATH section, not pre-vendor
    // fragments: record `original: None` — the true originals live in the
    // ledger entry being replaced, which the caller carries forward by
    // wiring identity (`persist_vendor_entry`).
    let (original_lines, new_lines) = lock_record_lines(&lock_edit);
    let to_array =
        |lines: Vec<String>| Value::Array(lines.into_iter().map(Value::String).collect());
    let lock_record = WiringRecord {
        file: GEMFILE_LOCK.to_string(),
        kind: LOCK_WIRING_KIND.to_string(),
        action: WiringAction::Rewritten,
        key: Some(name.to_string()),
        original: (!lock_edit.rewired_ours).then(|| to_array(original_lines)),
        new: Some(to_array(new_lines)),
    };
    let mut wiring = vec![gemfile_record, lock_record];
    // The CHECKSUMS rewrite (when the lock had a registry entry for the gem)
    // rides in its OWN record: revert must restore the registry `sha256=`
    // line verbatim — it is not recomputable offline, and a bare entry on a
    // registry-sourced gem hard-fails frozen installs (spike, exit 16).
    // One line for the plain entry, one per rewritten platform entry for a
    // gem vendored as platform gems (see [`LOCK_CHECKSUM_WIRING_KIND`]).
    let checksum_lines = |lines: Vec<String>| match platforms.is_empty() {
        true => lines.into_iter().next().map(Value::String),
        false => Some(to_array(lines)),
    };
    let (originals, bares): (Vec<String>, Vec<String>) =
        lock_edit.checksum_rewrites.iter().cloned().unzip();
    if !bares.is_empty() {
        wiring.push(WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: LOCK_CHECKSUM_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: checksum_lines(originals),
            new: checksum_lines(bares),
        });
    } else if lock_edit.rewired_ours && !lock_edit.checksum_bare.is_empty() {
        // Re-vendor with the bare path-form line already in place (our
        // previous run stripped the registry token): the record must ride
        // again with `original: None` — dropped, the first run's registry
        // `sha256=` line would vanish from the ledger with the entry being
        // replaced, and a later --revert could no longer restore it (a bare
        // leftover on a registry gem hard-fails frozen installs, exit 16).
        wiring.push(WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: LOCK_CHECKSUM_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(name.to_string()),
            original: None,
            new: checksum_lines(lock_edit.checksum_bare.clone()),
        });
    }

    // The whole tree, stub gemspec included: no lockfile integrity covers a
    // path source's bytes.
    let file_inventory = match platform_inventory {
        Some(inventory) => inventory,
        None => inventory_or_warn(copy_dir, &format!("{name}@{version}"), &mut warnings).await,
    };
    let entry = gem_entry(
        base_purl,
        record,
        copy_rel.to_string(),
        builds,
        file_inventory,
        wiring,
    );

    done(result, Some(entry), warnings)
}

/// The outcome of a copy the lock is ALREADY wired to that this run could
/// not rebuild because a locked platform has no patched build
/// ([`super::VENDOR_PREBUILT_PLATFORM_PENDING`]). While the copy the
/// ledger records is intact (the lock gained a platform since) it stays
/// in force as it is, and the outcome stays that skip. Otherwise the lock
/// names a tree that is missing or damaged and no older patch stands in
/// for it: the plain miss, a failure.
async fn wired_copy_not_rebuilt(
    outcome: VendorOutcome,
    project_root: &Path,
    record: &PatchRecord,
    prelude: &GemPrelude,
) -> VendorOutcome {
    match outcome {
        VendorOutcome::Refused { code, detail }
            if code == super::VENDOR_PREBUILT_PLATFORM_PENDING =>
        {
            let stands = recorded_copy_stands(
                project_root,
                record,
                &prelude.copy_rel,
                &prelude.copy_dir,
                &prelude.name,
            )
            .await;
            match stands {
                true => refused(
                    code,
                    format!("{detail}; its vendored copy stays in force as it is."),
                ),
                false => refused(
                    super::VENDOR_PREBUILT_REQUIRED,
                    format!(
                        "{detail}; its vendored copy is missing or damaged and cannot be \
                         rebuilt until then."
                    ),
                ),
            }
        }
        other => other,
    }
}

/// The ledger entry for a vendored gem copy: `wiring` is the Gemfile + lock
/// records on a full vendor, empty on an artifact-only rebuild (see the hot
/// path). `builds` are the platform trees of a copy vendored as platform
/// gems (empty for the gem's own tree).
fn gem_entry(
    base_purl: String,
    record: &PatchRecord,
    copy_rel: String,
    builds: Vec<GemBuildEntry>,
    file_inventory: Option<std::collections::BTreeMap<String, String>>,
    wiring: Vec<WiringRecord>,
) -> VendorEntry {
    VendorEntry {
        gem_builds: builds,
        ..VendorEntry::new(
            "gem".to_string(),
            base_purl,
            record.uuid.clone(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: copy_rel,
                sha256: String::new(), // dir-shaped: whole-tree integrity is the inventory
                size: None,
                platform_locked: None,
                file_inventory,
            },
            wiring,
        )
    }
}

/// The path-source stub gemspec served as the gem's SECOND artifact, alongside
/// the `.gem` (mirrors npm's `yarn-berry-zip`). The converter generates it
/// because a `.gem` only carries the gemspec as YAML in `metadata.gz`, not the
/// eval-able Ruby form a bundler path source loads.
pub(crate) const GEM_STUB_ARTIFACT_KIND: &str = "gem-stub-gemspec";

/// Download and verify the `.gem` and its stub gemspec. Missing, invalid, or
/// native-extension stubs are refused.
async fn gem_service_archive(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
) -> Result<(super::service_fetch::VerifiedArchive, Vec<u8>), Box<VendorOutcome>> {
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(super::service_fetch::required()))?;
    // Step 1: the prebuilt `.gem` (sha512-verified against the reference).
    let fetched = fetch_verified_archive(cfg, &record.uuid).await;
    let subject = format!(".gem for {name}");
    let policy = ServicePolicy::Refused;
    let archive = policy.settle(fetched, ".gem", &subject)?;

    // Step 2: the stub gemspec the converter generated alongside the `.gem`.
    let stub = match fetch_verified_secondary(cfg, &archive, GEM_STUB_ARTIFACT_KIND).await {
        SecondaryArtifactResult::Ready(bytes) => bytes,
        SecondaryArtifactResult::Absent => {
            return Err(policy.miss(
                "the patch service served no stub gemspec for this gem (a native-extension \
                 gem, or a patch built before the stub rollout)"
                    .to_string(),
            ));
        }
        SecondaryArtifactResult::IntegrityMismatch(reason) => {
            return Err(policy.hard(
                "vendor_prebuilt_integrity_mismatch",
                format!(
                    "prebuilt stub gemspec for {name} failed integrity verification ({reason}); \
                     refusing to fall back to a local build on tampered bytes"
                ),
            ));
        }
        SecondaryArtifactResult::Failed(reason) => {
            return Err(policy.miss(format!("could not fetch the stub gemspec ({reason})")));
        }
    };
    refuse_unusable_stub(policy, name, name, &String::from_utf8_lossy(&stub))?;
    Ok((archive, stub))
}

/// [`gem_service_archive`], then atomically replace the copy with the
/// unpacked gem and its stub gemspec.
pub(super) async fn gem_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    unwind_uuid_dir: bool,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), Box<VendorOutcome>> {
    let (mut archive, stub) = gem_service_archive(service, record, name).await?;
    let policy = ServicePolicy::Refused;

    // Extract the patched `.gem`'s data.tar.gz into a STAGE sibling, add the
    // stub as `<name>.gemspec` (a `.gem`'s data.tar.gz never carries one —
    // the gemspec lives in metadata.gz), and swap it into the copy dir only
    // once fully verified — a failure then leaves any pre-existing (possibly
    // live-wired) copy untouched and no husk behind.
    let stage = stage_dir_for(copy_dir);
    // A tree the download plan already extracted from these bytes (see
    // `prestage`) is moved into the stage instead; otherwise — or should
    // the move fail — extract here, as always.
    if !claim_prestaged(&mut archive, &stage, copy_dir).await {
        let _ = remove_tree(&stage).await;
        if let Err(e) = tokio::fs::create_dir_all(&stage).await {
            cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
            return Err(policy.hard(
                "vendor_prebuilt_write_failed",
                format!("cannot create {}: {e}", stage.display()),
            ));
        }
        let gem_bytes = std::mem::take(&mut archive.bytes);
        if let Err(e) = extract_on_blocking_pool(gem_bytes, &stage, extract_gem_data).await {
            cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
            return Err(policy.hard(
                "vendor_prebuilt_extract_failed",
                format!("cannot extract the prebuilt .gem: {e}"),
            ));
        }
    }
    if let Err(e) = tokio::fs::write(stage.join(format!("{name}.gemspec")), &stub).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(policy.hard(
            "vendor_prebuilt_write_failed",
            format!("cannot write the stub gemspec into the vendored dir: {e}"),
        ));
    }
    if !copy_matches_after_hashes(&stage, &record.files).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(policy.miss(format!(
            "prebuilt .gem for {name} extracted to an unexpected layout \
                 (patched files absent at their recorded paths)"
        )));
    }
    if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(policy.hard(
            "vendor_prebuilt_write_failed",
            format!("cannot move the extracted .gem into place: {e}"),
        ));
    }
    warnings.push(archive.downloaded_warning(name));
    Ok(())
}

/// Why the stub gemspec the service served for `subject` (the gem `name`,
/// or one platform's prebuild of it) cannot be vendored, checked before
/// anything is written so an unusable stub leaves no partial artifact.
fn refuse_unusable_stub(
    policy: ServicePolicy<'_>,
    name: &str,
    subject: &str,
    stub_text: &str,
) -> Result<(), Box<VendorOutcome>> {
    // Defense in depth: the converter does not emit a stub for native gems, but
    // refuse one here too — bundler silently skips extension builds for path
    // sources, so a native gem would install and then fail at `require` time.
    if gemspec_declares_extensions(stub_text) {
        return Err(policy.hard(
            "native_extensions_unsupported",
            format!(
                "the served stub gemspec for {subject} declares native extensions; bundler does \
                 not build extensions for path-sourced gems. {}",
                // The Gemfile plan passed before the service was asked, so
                // the declaration is one hosted mode can edit too.
                native_extensions_remedy(name, true)
            ),
        ));
    }

    // Bundler rejects path-source gemspecs without summary/authors.
    let missing_attrs = gemspec_missing_required_attrs(stub_text);
    if !missing_attrs.is_empty() {
        let licenses_note = if gemspec_assigns_attr(stub_text, &["licenses", "license"]) {
            ""
        } else {
            " (it also omits `licenses`, a rubygems warning)"
        };
        let reason = format!(
            "the served stub gemspec for {subject} is invalid: it does not assign the \
             rubygems-required attribute(s) {}{licenses_note}; bundler validates \
             path-source gemspecs, so vendoring it would make every later \
             `bundle install` fail",
            missing_attrs.join(", "),
        );
        return Err(policy.hard(
            "vendor_prebuilt_stub_invalid",
            format!(
                "{}. Retry after the patch service publishes a corrected artifact",
                reason
            ),
        ));
    }
    Ok(())
}

/// How many platforms' gems (a patched platform gem and its stub gemspec
/// each) are downloaded at once.
const PREBUILD_DOWNLOADS_AT_ONCE: usize = 4;

/// Which patches the trees of a copy vendored as platform gems come from.
pub(super) enum BuildsFrom<'a> {
    /// The platforms the lock names, in lock order, each from the patch
    /// the gem patch's package reference names for it
    /// (`gemBuilds[].patchUuid`).
    Locked(&'a [String]),
    /// The trees a ledger entry records, each from its recorded patch: a
    /// restore of that copy.
    Recorded(&'a [GemBuildEntry]),
}

/// What a gem has in place of the patch being vendored, should a locked
/// platform turn out to have no patched build: how that skip is worded.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Standing {
    /// Nothing: the gem is not vendored.
    NotVendored,
    /// Nothing vendored, and the lockfile pins the gem hosted: the pin
    /// stays while the gem is not vendored.
    Hosted,
    /// The lock is wired to this patch's copy.
    Wired,
    /// The Gemfile is wired to the copy of another patch of the gem.
    EarlierPatch,
}

/// The platform trees one call stages, and how a miss is worded.
pub(super) struct PlatformTrees<'a> {
    /// `<name>@<version>`, for messages.
    pub(super) gem: &'a str,
    pub(super) from: BuildsFrom<'a>,
    pub(super) standing: Standing,
}

/// One platform tree to stage: the patch it is unpacked from, and what its
/// downloads must match beyond the digests that patch's own reference
/// states for them.
struct BuildSource {
    platform: String,
    uuid: String,
    pinned: BuildPin,
    /// The files of this build's own patch as the ledger entry being
    /// restored records them; `None` asks the patch service for them.
    files: Option<BTreeMap<String, PatchFileInfo>>,
}

enum BuildPin {
    /// sha256 (hex) of the `.gem` the gem patch's registry lists for the
    /// platform (`gemBuilds[].gemChecksumSha256`).
    Registry(String),
    /// sha512 (SRI) of the `.gem` and of the stub gemspec the ledger
    /// recorded when the tree was vendored. An empty one pins nothing.
    Ledger { gem: String, gemspec: String },
}

/// `a`, `a and b`, `a, b and c`.
fn listed(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// The locked platforms of a gem that have no patched build to vendor, in
/// lock order.
#[derive(Default)]
struct NoPatchedBuild<'a> {
    /// None yet, as far as the service says: the gem patch's registry
    /// serves upstream's own gem for the platform, does not list it, or
    /// the patch of its build is still being built.
    yet: Vec<&'a str>,
    /// The gem patch names a patched build, and the service does not
    /// grant this caller the patch of it.
    unavailable: Vec<&'a str>,
}

impl NoPatchedBuild<'_> {
    fn is_empty(&self) -> bool {
        self.yet.is_empty() && self.unavailable.is_empty()
    }
}

/// The one line for a gem left as it is because the locked platforms of
/// `missing` have no patched build, while `patched` (the other locked
/// platforms) have one. Its last clause says what the gem's `standing`
/// leaves it with: hosted mode can patch the platforms that do have a
/// build, unless the gem is hosted already, and a vendored copy stays in
/// force. For a lock already wired to this patch's copy
/// ([`Standing::Wired`]) the caller ends the line with what became of
/// that copy ([`wired_copy_not_rebuilt`]); otherwise it is the whole
/// line.
fn no_patched_build_detail(
    gem: &str,
    missing: &NoPatchedBuild<'_>,
    patched: &[&str],
    standing: Standing,
) -> String {
    let lead = match standing {
        Standing::NotVendored | Standing::Hosted => "is not vendored",
        Standing::Wired | Standing::EarlierPatch => "was not brought up to date",
    };
    let none = match (missing.yet.as_slice(), missing.unavailable.as_slice()) {
        (yet, []) => format!("no patched build yet for {}", listed(yet)),
        ([], unavailable) => format!("no patched build available for {}", listed(unavailable)),
        (yet, unavailable) => format!(
            "no patched build yet for {} and none available for {}",
            listed(yet),
            listed(unavailable)
        ),
    };
    let have = match patched {
        [] => String::new(),
        [one] => format!(" ({one} has one)"),
        patched => format!(" ({} have one)", listed(patched)),
    };
    let tail = match (standing, patched.is_empty()) {
        (Standing::Wired, _) => "",
        (Standing::EarlierPatch, _) => {
            "; its vendored copy of an earlier patch stays in force as it is."
        }
        (Standing::NotVendored | Standing::Hosted, true) => ".",
        (Standing::NotVendored, false) => "; `scan --mode hosted` can patch the others now.",
        (Standing::Hosted, false) => "; the gem stays hosted.",
    };
    format!("{gem} {lead}: {none}{have}. Vendored mode needs every locked platform{tail}")
}

/// The skip of a gem left as it is because locked platforms have no
/// patched build ([`super::VENDOR_PREBUILT_PLATFORM_PENDING`]). Not a
/// failure: a platform's patched build is named and served only once it
/// is published, so this is as likely "not yet" as "never", and nothing
/// was touched.
fn no_patched_build(
    trees: &PlatformTrees<'_>,
    missing: &NoPatchedBuild<'_>,
    patched: &[&str],
) -> Box<VendorOutcome> {
    Box::new(refused(
        super::VENDOR_PREBUILT_PLATFORM_PENDING,
        no_patched_build_detail(trees.gem, missing, patched, trees.standing),
    ))
}

/// The patch of each of `platforms`' patched build, as the package
/// reference of the gem's fix `uuid` names them, with the sha256 its
/// registry lists for that platform gem: ONE request, and nothing
/// downloaded. While a locked platform has no patched build (the registry
/// serves upstream's own gem for it, does not list it, or lists no
/// platform gem at all) the gem is skipped ([`no_patched_build`]).
async fn locked_build_sources(
    cfg: &VendorServiceConfig,
    uuid: &str,
    name: &str,
    trees: &PlatformTrees<'_>,
    platforms: &[String],
) -> Result<Vec<BuildSource>, Box<VendorOutcome>> {
    let policy = ServicePolicy::Refused;
    let reference = fetch_served_reference(cfg, uuid).await;
    let served = policy.settle(
        reference,
        "platform gem",
        &format!("platform gems for {name}"),
    )?;
    let builds = served.gem_builds.as_deref().unwrap_or_default();
    let mut sources: Vec<BuildSource> = Vec::with_capacity(platforms.len());
    let mut missing = NoPatchedBuild::default();
    for platform in platforms {
        let build = builds.iter().find(|build| build.platform == *platform);
        match build.and_then(|build| Some((build, build.patch_uuid.as_deref()?))) {
            Some((build, uuid)) => sources.push(BuildSource {
                platform: platform.clone(),
                uuid: uuid.to_string(),
                pinned: BuildPin::Registry(build.gem_checksum_sha256.clone()),
                files: None,
            }),
            None => missing.yet.push(platform),
        }
    }
    if missing.is_empty() {
        return Ok(sources);
    }
    let patched: Vec<&str> = sources.iter().map(|s| s.platform.as_str()).collect();
    Err(no_patched_build(trees, &missing, &patched))
}

/// One platform tree whose patch the service serves: its source, how
/// messages name it (`<name> (<platform>)`), and the gem and the stub
/// gemspec that patch's reference lists.
type ServedBuild<'a> = (
    &'a BuildSource,
    String,
    crate::api::client::SecondaryArtifact,
    crate::api::client::SecondaryArtifact,
);

/// What the patch of each of `sources` serves, asked for in ONE request
/// and with nothing downloaded: its patched platform gem and stub gemspec.
///
/// A patch the gem's fix names ([`BuildsFrom::Locked`]) that the service
/// does not serve, because it is still being built or is not granted to
/// this caller, leaves its platform without a patched build to vendor, as
/// if the fix named none: the gem is skipped ([`no_patched_build`]). The
/// trees of a ledger entry have nothing to wait for, so a patch of theirs
/// that is not served is a miss, as is a patch the service does not answer
/// for and a granted one that lists no gem or no stub.
async fn served_builds<'a>(
    cfg: &VendorServiceConfig,
    name: &str,
    trees: &PlatformTrees<'_>,
    sources: &'a [BuildSource],
) -> Result<Vec<ServedBuild<'a>>, Box<VendorOutcome>> {
    let policy = ServicePolicy::Refused;
    let uuids: Vec<String> = sources.iter().map(|source| source.uuid.clone()).collect();
    let references = fetch_served_references(cfg, &uuids)
        .await
        .map_err(|reason| policy.miss(format!("patch service request failed ({reason})")))?;
    let mut builds = Vec::with_capacity(sources.len());
    let mut missing = NoPatchedBuild::default();
    for (source, (reference, unserved)) in sources.iter().zip(references) {
        if let (BuildsFrom::Locked(_), Some(unserved)) = (&trees.from, unserved) {
            match unserved {
                Unserved::Building => missing.yet.push(&source.platform),
                Unserved::NotGranted => missing.unavailable.push(&source.platform),
            }
            continue;
        }
        let subject = format!("{name} ({})", source.platform);
        let served = policy.settle(
            reference,
            "platform gem",
            &format!("platform gem for {subject}"),
        )?;
        let Some(gem) = served.archive.clone() else {
            return Err(policy.miss(format!(
                "the patch service served no patched platform gem for {subject}"
            )));
        };
        let Some(stub) = served.secondary(GEM_STUB_ARTIFACT_KIND).cloned() else {
            return Err(policy.miss(format!(
                "the patch service served no stub gemspec for {subject}"
            )));
        };
        builds.push((source, subject, gem, stub));
    }
    if !missing.is_empty() {
        let patched: Vec<&str> = builds
            .iter()
            .map(|(source, ..)| source.platform.as_str())
            .collect();
        return Err(no_patched_build(trees, &missing, &patched));
    }
    Ok(builds)
}

/// The files `source`'s own patch changes, with their hashes: what its
/// tree is verified against. A platform gem is a patch of its own, so
/// these are not the files of the gem's fix: a compiled build changes
/// binaries the fix does not name, and the service stamps the files of
/// each patch with that patch's own header. Taken from the ledger entry
/// being restored where it records them, else from that patch's record:
/// ONE request per platform, asked without file contents.
async fn build_files(
    cfg: &VendorServiceConfig,
    source: &BuildSource,
    subject: &str,
) -> Result<BTreeMap<String, PatchFileInfo>, Box<VendorOutcome>> {
    if let Some(files) = &source.files {
        return Ok(files.clone());
    }
    let policy = ServicePolicy::Refused;
    let Some(client) = cfg.client.as_ref() else {
        return Err(policy.miss("vendor service not configured".to_string()));
    };
    match client.fetch_patch_summary(&source.uuid).await {
        Ok(Some(view)) if view.uuid.eq_ignore_ascii_case(&source.uuid) => {
            Ok(crate::manifest::records::files_for_manifest(&view)
                .into_iter()
                .collect())
        }
        Ok(_) => Err(policy.miss(format!(
            "the patch service has no record of the patch of the platform gem for {subject}"
        ))),
        Err(e) => Err(policy.miss(format!("patch service request failed ({e})"))),
    }
}

/// Download and verify the patched gem of each platform of `trees` and its
/// stub gemspec, and unpack them into `stage`: `<stage>/<platform>/` holds
/// the platform gem's files and `<name>.gemspec` (see the module docs).
/// Each platform's gem is the `tarball` of that platform's own patch, and
/// its stub that patch's [`GEM_STUB_ARTIFACT_KIND`]; each tree is verified
/// against the files of that same patch ([`build_files`]). `record` is the
/// gem's fix, which names the builds. The ruby gem of the fix is never
/// downloaded (bundler would have to build its extensions).
///
/// The patches are named by the fix's package reference (one request,
/// [`locked_build_sources`]) or by the ledger entry being restored, and
/// their own references are asked for in ONE request more
/// ([`served_builds`]). Every download
/// is verified against the digest its patch's reference states, and the
/// gem also against the sha256 the fix's registry lists for that platform
/// (or, on a restore, both against what the ledger recorded). A failure
/// leaves a partial `stage` for the caller to remove. Returns the run's
/// advisories (the download, and the ignore files that were emptied) and
/// what the ledger records of each tree.
async fn stage_platform_builds(
    cfg: &VendorServiceConfig,
    record: &PatchRecord,
    name: &str,
    trees: &PlatformTrees<'_>,
    stage: &Path,
) -> Result<(Vec<VendorWarning>, Vec<GemBuildEntry>), Box<VendorOutcome>> {
    use futures_util::StreamExt as _;
    let policy = ServicePolicy::Refused;
    let platforms: Vec<&str> = match &trees.from {
        BuildsFrom::Locked(platforms) => platforms.iter().map(String::as_str).collect(),
        BuildsFrom::Recorded(builds) => builds.iter().map(|b| b.platform.as_str()).collect(),
    };
    // SECURITY: a platform names a directory under the stage, and the
    // ledger a restore reads them from is committed, tamper-able data.
    if let Some(platform) = platforms.iter().find(|p| !is_platform_dir_name(p)) {
        return Err(policy.hard(
            "unsafe_coordinates",
            format!("unsafe gem platform `{platform}` for `{name}`"),
        ));
    }
    let sources: Vec<BuildSource> = match &trees.from {
        BuildsFrom::Locked(platforms) => {
            locked_build_sources(cfg, &record.uuid, name, trees, platforms).await?
        }
        BuildsFrom::Recorded(builds) => builds
            .iter()
            .map(|built| BuildSource {
                platform: built.platform.clone(),
                uuid: built.uuid.clone(),
                pinned: BuildPin::Ledger {
                    gem: built.gem_integrity.clone(),
                    gemspec: built.gemspec_integrity.clone(),
                },
                files: (!built.files.is_empty()).then(|| built.files.clone()),
            })
            .collect(),
    };

    let builds = served_builds(cfg, name, trees, &sources).await?;

    // The gems, a few platforms at a time and taken in lock order.
    let mut downloads = std::pin::pin!(futures_util::stream::iter(&builds)
        .map(|(source, subject, gem, stub)| async move {
            let gem_bytes = build_artifact(cfg, gem, "patched platform gem", subject).await?;
            source.pinned.check_gem(&gem_bytes, subject)?;
            let stub_bytes = build_artifact(cfg, stub, "stub gemspec", subject).await?;
            source.pinned.check_stub(&stub_bytes, subject)?;
            let files = build_files(cfg, source, subject).await?;
            Ok::<_, Box<VendorOutcome>>((gem_bytes, stub_bytes, files))
        })
        .buffered(PREBUILD_DOWNLOADS_AT_ONCE));

    let mut emptied: Vec<String> = Vec::new();
    let mut built: Vec<GemBuildEntry> = Vec::with_capacity(builds.len());
    for (source, subject, gem, stub) in &builds {
        let Some(downloaded) = downloads.next().await else {
            break;
        };
        let (gem_bytes, stub_bytes, files) = downloaded?;
        let own: HashMap<String, PatchFileInfo> = files.clone().into_iter().collect();
        let platform = source.platform.as_str();
        refuse_unusable_stub(policy, name, subject, &String::from_utf8_lossy(&stub_bytes))?;

        let tree = stage.join(platform);
        if let Err(e) = tokio::fs::create_dir_all(&tree).await {
            return Err(policy.hard(
                "vendor_prebuilt_write_failed",
                format!("cannot create {}: {e}", tree.display()),
            ));
        }
        if let Err(e) = extract_on_blocking_pool(gem_bytes, &tree, extract_gem_data).await {
            return Err(policy.hard(
                "vendor_prebuilt_extract_failed",
                format!("cannot extract the patched platform gem for {subject}: {e}"),
            ));
        }
        match empty_shipped_gitignores(&tree, &own).await {
            Ok(files) => emptied.extend(files.into_iter().map(|file| format!("{platform}/{file}"))),
            Err(e) => {
                return Err(policy.hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot empty a `.gitignore` the patched platform gem for {subject} ships: {e}"),
                ));
            }
        }
        if let Err(e) = tokio::fs::write(tree.join(format!("{name}.gemspec")), &stub_bytes).await {
            return Err(policy.hard(
                "vendor_prebuilt_write_failed",
                format!("cannot write the stub gemspec for {subject} into the vendored dir: {e}"),
            ));
        }
        // The gem passed the digests stated for this platform above, which
        // is what vouches for a tree that ships none of the files its patch
        // names: only one it does ship can contradict that patch.
        let verified = super::verify::TreeVoucher::VerifiedDownload;
        if super::verify::verify_platform_tree(&tree, &own, verified)
            .await
            .is_err()
        {
            return Err(policy.miss(format!(
                "patched platform gem for {subject} does not carry the patch (a patched \
                 file it ships is not the patched one)"
            )));
        }
        built.push(GemBuildEntry {
            platform: platform.to_string(),
            uuid: source.uuid.clone(),
            gem_integrity: gem.integrity_sri.clone(),
            gemspec_integrity: stub.integrity_sri.clone(),
            files,
        });
    }

    let source_url = builds
        .first()
        .map(|(_, _, gem, _)| gem.url.as_str())
        .unwrap_or_default();
    let mut warnings = vec![downloaded_warning(
        format_args!("{name} as patched platform gems ({})", platforms.join(", ")),
        source_url,
    )];
    if !emptied.is_empty() {
        warnings.push(VendorWarning::new(
            GITIGNORE_NEUTRALIZED,
            format!(
                "{name}: the patched platform gems ship their own `.gitignore` ({}), whose \
                 rules would keep git from committing files of the vendored trees; emptied in \
                 the vendored copy (commit it)",
                super::npm_dir::summarize_rules(&emptied)
            ),
        ));
    }
    Ok((warnings, built))
}

impl BuildPin {
    /// Whether the downloaded platform gem is the one this tree is pinned
    /// to; a mismatch is never vendored.
    fn check_gem(&self, gem: &[u8], subject: &str) -> Result<(), Box<VendorOutcome>> {
        let mismatch = |why: String| {
            ServicePolicy::Refused.hard(
                "vendor_prebuilt_integrity_mismatch",
                format!("patched platform gem for {subject} {why}; refusing to vendor it"),
            )
        };
        match self {
            Self::Registry(listed) => {
                let sha256 = crate::utils::digest::sha256_hex_of(gem);
                match sha256.eq_ignore_ascii_case(listed) {
                    true => Ok(()),
                    false => Err(mismatch(format!(
                        "is not the gem the patch registry lists for that platform (sha256 \
                         {sha256}, listed {listed})"
                    ))),
                }
            }
            Self::Ledger { gem: recorded, .. } => {
                Self::check_recorded(gem, recorded).map_err(|why| {
                    mismatch(format!(
                        "is not the gem this copy was vendored from ({why})"
                    ))
                })
            }
        }
    }

    /// [`Self::check_gem`] for the stub gemspec, which only the ledger pins.
    fn check_stub(&self, stub: &[u8], subject: &str) -> Result<(), Box<VendorOutcome>> {
        let Self::Ledger { gemspec, .. } = self else {
            return Ok(());
        };
        Self::check_recorded(stub, gemspec).map_err(|why| {
            ServicePolicy::Refused.hard(
                "vendor_prebuilt_integrity_mismatch",
                format!(
                    "stub gemspec for {subject} is not the one this copy was vendored with \
                     ({why}); refusing to vendor it"
                ),
            )
        })
    }

    fn check_recorded(bytes: &[u8], recorded: &str) -> Result<(), String> {
        if recorded.is_empty() {
            return Ok(());
        }
        // The Sri verifier never reads the name arg.
        artifact_matches_integrity(bytes, "", &LockIntegrity::Sri(recorded.to_string()))
    }
}

/// The advisory of [`empty_shipped_gitignores`]: the vendored trees differ
/// from the prebuilds in the ignore files named.
const GITIGNORE_NEUTRALIZED: &str = "vendor_gem_gitignore_neutralized";

/// Empty every `.gitignore` a prebuild ships inside `tree`. Git reads one
/// at any depth, and for the files below it its rules win over the uuid
/// dir's `!*`: a `*.so` rule the gem's own repository used would leave the
/// binary out of the commit, with no rule of the project's to remove. The
/// file stays, empty, so the tree keeps the gem's file list — the way the
/// Composer backend neutralises the filters of a mirrored copy. Done while
/// the tree is staged, so the ledger's inventory and `repair`'s restore
/// see the same bytes.
///
/// A `.gitignore` the patch itself rewrites is left as the patch has it
/// (its hash is the record's); what it ignores is then for
/// [`keep_platform_trees_committable`] to refuse. Returns the paths
/// emptied, relative to `tree`.
async fn empty_shipped_gitignores(
    tree: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> std::io::Result<Vec<String>> {
    let root = tree.to_path_buf();
    let shipped = tokio::task::spawn_blocking(move || {
        let mut shipped: Vec<(PathBuf, String)> = Vec::new();
        // Links are not followed (and none is extracted): only the
        // regular files of the tree itself.
        for entry in walkdir::WalkDir::new(&root).sort_by_file_name() {
            let entry = entry?;
            if entry.file_name() != ".gitignore"
                || !entry.file_type().is_file()
                || entry.metadata()?.len() == 0
            {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&root)
                .map_err(std::io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            shipped.push((entry.into_path(), rel));
        }
        Ok::<_, std::io::Error>(shipped)
    })
    .await
    .map_err(std::io::Error::other)??;
    let mut emptied = Vec::new();
    for (path, rel) in shipped {
        if files.keys().any(|key| normalize_file_path(key) == rel) {
            continue;
        }
        atomic_write_bytes_preserving_mode(&path, b"").await?;
        emptied.push(rel);
    }
    Ok(emptied)
}

/// One artifact of a platform's patch (`what`, for messages about
/// `subject`), downloaded and verified against its served integrity like
/// the ruby gem's stub: a mismatch is never vendored. The check is not
/// optional: an artifact the service states no digest for is not listed
/// at all, and for a platform gem that ships none of the patched files it
/// is the only evidence that the tree is the patched build.
async fn build_artifact(
    cfg: &VendorServiceConfig,
    artifact: &crate::api::client::SecondaryArtifact,
    what: &str,
    subject: &str,
) -> Result<Vec<u8>, Box<VendorOutcome>> {
    let policy = ServicePolicy::Refused;
    match fetch_verified_artifact(cfg, Some(artifact)).await {
        SecondaryArtifactResult::Ready(bytes) => Ok(bytes),
        SecondaryArtifactResult::Absent => {
            Err(policy.miss(format!("the patch service served no {what} for {subject}")))
        }
        SecondaryArtifactResult::IntegrityMismatch(reason) => Err(policy.hard(
            "vendor_prebuilt_integrity_mismatch",
            format!(
                "{what} for {subject} failed integrity verification ({reason}); \
                 refusing to vendor tampered bytes"
            ),
        )),
        SecondaryArtifactResult::Failed(reason) => Err(policy.miss(format!(
            "could not fetch the {what} for {subject} ({reason})"
        ))),
    }
}

/// [`gem_service_copy`] for a gem the lock pins as platform gems: the copy
/// is the verified patched gem of each platform of `trees`, each from its
/// own patch, staged in full and then swapped into place, so a failure
/// leaves any pre-existing (possibly live-wired) copy untouched and no
/// husk behind. The uuid dir's git metadata is the caller's to write
/// ([`restore_uuid_metadata`]): `copy_dir` may itself sit in a stage
/// (`repair`'s restore). Returns what the ledger records of each tree.
#[allow(clippy::too_many_arguments)]
pub(super) async fn gem_platform_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    trees: &PlatformTrees<'_>,
    copy_dir: &Path,
    uuid_dir: &Path,
    unwind_uuid_dir: bool,
    warnings: &mut Vec<VendorWarning>,
) -> Result<Vec<GemBuildEntry>, Box<VendorOutcome>> {
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(super::service_fetch::required()))?;
    let stage = stage_dir_for(copy_dir);
    let _ = remove_tree(&stage).await;
    let (staged, built) = match stage_platform_builds(cfg, record, name, trees, &stage).await {
        Ok(staged) => staged,
        Err(outcome) => {
            cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
            return Err(outcome);
        }
    };
    if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(ServicePolicy::Refused.hard(
            "vendor_prebuilt_write_failed",
            format!("cannot move the extracted platform gems into place: {e}"),
        ));
    }
    warnings.extend(staged);
    Ok(built)
}

/// `<uuid>/.gitignore` of a gem vendored as platform gems: re-includes
/// everything under the uuid dir against the project's own ignore rules.
/// A prebuild's tree holds the compiled extension (`*.so`, `*.bundle`,
/// `*.dll`, a JRuby gem's `*.jar`), which stock ignore templates name; a
/// gem vendored as its own tree is source files and gets none.
const UUID_GITIGNORE: &str = "!*\n";

/// Rewrite `<uuid>/.gitignore` ([`UUID_GITIGNORE`]) and
/// `<uuid>/.gitattributes` of a gem vendored as platform gems when absent
/// or different, with the writer every backend that commits binaries
/// shares: the attributes keep a project rule such as `*.so filter=lfs`,
/// or an EOL conversion, from changing the bytes git commits. Neither file
/// is part of the copy, so writing them is no rebuild. `true` when either
/// was rewritten.
pub(crate) async fn restore_uuid_metadata(uuid_dir: &Path) -> std::io::Result<bool> {
    super::npm_dir::write_uuid_metadata(uuid_dir, UUID_GITIGNORE).await
}

/// Ask git whether it would commit every file of the platform trees just
/// written (`inventory`: the copy's files) and the uuid dir's `.gitignore`
/// and `.gitattributes`. A rule the `.gitignore` cannot override refuses
/// `vendor_artifact_gitignored`, and the caller unwinds; git failing to
/// answer is only a warning. Nothing is asked without an inventory, whose
/// absence is already reported.
async fn keep_platform_trees_committable(
    project_root: &Path,
    copy_rel: &str,
    inventory: Option<&BTreeMap<String, String>>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), VendorOutcome> {
    let Some(inventory) = inventory else {
        return Ok(());
    };
    let mut paths: Vec<String> = inventory
        .keys()
        .map(|file| format!("{copy_rel}/{file}"))
        .collect();
    if let Some((uuid_dir_rel, _)) = copy_rel.rsplit_once('/') {
        paths.push(format!("{uuid_dir_rel}/.gitignore"));
        paths.push(format!("{uuid_dir_rel}/.gitattributes"));
    }
    match super::npm_dir::gitignore_probe(project_root, &paths).await {
        Ok(Some(rules)) => Err(refused(
            super::npm_dir::GITIGNORED,
            super::npm_dir::gitignored_detail(copy_rel, &rules),
        )),
        Ok(None) => Ok(()),
        Err(why) => {
            warnings.push(VendorWarning::new(
                super::npm_dir::GITIGNORE_UNCHECKED,
                super::npm_dir::gitignore_unchecked_detail(copy_rel, &why),
            ));
            Ok(())
        }
    }
}

/// A dry run's check of a gem the lock pins as platform gems: the whole
/// download, verification and unpacking of [`gem_platform_service_copy`],
/// into a scratch directory. Returns what the wet run's ledger entry
/// would record of each tree.
async fn preview_platform_builds(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    trees: &PlatformTrees<'_>,
) -> Result<Vec<GemBuildEntry>, Box<VendorOutcome>> {
    if let Some(outcome) = service_offline_conflict(service) {
        return Err(Box::new(outcome));
    }
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(super::service_fetch::required()))?;
    let scratch = tempfile::tempdir()
        .map_err(|e| Box::new(refused("vendor_prebuilt_extract_failed", e.to_string())))?;
    stage_platform_builds(cfg, record, name, trees, scratch.path())
        .await
        .map(|(_, built)| built)
}

/// What a run would do with a gem `Gemfile.lock` names as precompiled
/// platform gems, as far as the patch service's package references tell
/// ([`preview_locked_builds`]).
#[derive(Debug)]
pub enum LockedBuildsPreview {
    /// Every locked platform has a patched build, and the service serves
    /// the patch of each: the tree of each, in lock order, with the patch
    /// it is vendored from. Nothing was downloaded, so the entries carry
    /// no digest.
    Vendor(Vec<GemBuildEntry>),
    /// What the backend refuses the gem with before it downloads
    /// anything: the skip of a gem with a locked platform that has no
    /// patched build ([`super::VENDOR_PREBUILT_PLATFORM_PENDING`]), a
    /// refusal of its prelude or of the Gemfile edit, or why the patch
    /// service could not say.
    Refused { code: &'static str, detail: String },
}

/// The preview of [`vendor_gem`] for a run that has not fetched the
/// record of the patch `uuid`: what a wet run decides for the gem `purl`
/// before its first download. That takes the requests the wet run makes
/// up to there and no other: the package reference of the patch and,
/// only where it names a patched build for every locked platform, the
/// references of those builds' patches, in ONE request more
/// ([`served_builds`]). None is made when the backend refuses the gem
/// first, or the service may not be asked. Nothing is downloaded and
/// nothing written.
///
/// `hosted`: the lockfile pins the gem hosted, and a wet run restores its
/// upstream entry before it vendors. The Gemfile edit is then planned
/// over text this preview does not have, so it is not judged here, and
/// the skip of a locked platform with no patched build says that the gem
/// stays hosted, as the wet run's does ([`vendor_gem_previewing`]).
///
/// `None` for a gem this does not judge, so the caller's own verdict
/// stands: one the lock does not name as platform gems, one whose lock is
/// already wired to this patch's copy (only the copy tells what a run
/// does with it), one a hub of a Bazel workspace takes, and a lock the
/// edit fails on.
pub async fn preview_locked_builds(
    project_root: &Path,
    purl: &str,
    uuid: &str,
    hosted: bool,
    service: Option<&VendorServiceConfig>,
) -> Option<LockedBuildsPreview> {
    let refusal = |outcome: VendorOutcome| match outcome {
        VendorOutcome::Refused { code, detail } => {
            Some(LockedBuildsPreview::Refused { code, detail })
        }
        VendorOutcome::Done { .. } => None,
    };
    // No installed copy is read: what is vendored for such a gem is the
    // lock's to say.
    let prelude = match gem_prelude_of(purl, Path::new(""), project_root, uuid, None).await {
        Ok(prelude) => prelude,
        Err(outcome) => return refusal(outcome),
    };
    if prelude.platforms.is_empty()
        || prelude.lock_wired
        || bazel::takes(&prelude, project_root, uuid).await
    {
        return None;
    }
    let standing = match hosted {
        true => Standing::Hosted,
        false => match gem_edits(purl, &prelude) {
            Ok((plan, _)) => plan.standing(false),
            Err(outcome) => return refusal(*outcome),
        },
    };
    if let Some(outcome) = service_offline_conflict(service) {
        return refusal(outcome);
    }
    let Some(cfg) = service.filter(|cfg| cfg.service_enabled()) else {
        return refusal(super::service_fetch::required());
    };
    let label = format!("{}@{}", prelude.name, prelude.version);
    let trees = PlatformTrees {
        gem: &label,
        from: BuildsFrom::Locked(&prelude.platforms),
        standing,
    };
    let named = locked_build_sources(cfg, uuid, &prelude.name, &trees, &prelude.platforms).await;
    let sources = match named {
        Ok(sources) => sources,
        Err(outcome) => return refusal(*outcome),
    };
    // A patched build is only one to vendor once its own patch is served.
    if let Err(outcome) = served_builds(cfg, &prelude.name, &trees, &sources).await {
        return refusal(*outcome);
    }
    Some(LockedBuildsPreview::Vendor(
        sources
            .into_iter()
            .map(|source| GemBuildEntry {
                platform: source.platform,
                uuid: source.uuid,
                gem_integrity: String::new(),
                gemspec_integrity: String::new(),
                files: BTreeMap::new(),
            })
            .collect(),
    ))
}

/// Acquire a verified service copy without replacing the prior copy on
/// failure: the gem's own tree, or one patched platform gem's tree per
/// platform of `trees` when the lock pins the gem as platform gems (with
/// the uuid dir's git metadata, see [`restore_uuid_metadata`]). Returns
/// what the ledger records of each such tree, with the result.
#[allow(clippy::too_many_arguments)]
async fn materialise_patched_copy(
    purl: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    name: &str,
    trees: &PlatformTrees<'_>,
    record: &PatchRecord,
    unwind_uuid_dir: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(ApplyResult, Vec<GemBuildEntry>), Box<VendorOutcome>> {
    let mut builds = Vec::new();
    match &trees.from {
        BuildsFrom::Locked([]) => {
            gem_service_copy(
                service,
                record,
                name,
                copy_dir,
                uuid_dir,
                unwind_uuid_dir,
                warnings,
            )
            .await?
        }
        _ => {
            builds = gem_platform_service_copy(
                service,
                record,
                name,
                trees,
                copy_dir,
                uuid_dir,
                unwind_uuid_dir,
                warnings,
            )
            .await?;
            if let Err(e) = restore_uuid_metadata(uuid_dir).await {
                if unwind_uuid_dir {
                    let _ = remove_tree(uuid_dir).await;
                    prune_empty_vendor_levels(uuid_dir).await;
                }
                return Err(ServicePolicy::Refused.hard(
                    "vendor_prebuilt_write_failed",
                    format!(
                        "cannot write the git metadata of {}: {e}",
                        uuid_dir.display()
                    ),
                ));
            }
        }
    }
    Ok((
        already_patched_result(purl, copy_dir, &record.files),
        builds,
    ))
}

/// Revert a gem vendor entry: restore the Gemfile line / delete the managed
/// block, splice the lock's spec block back into GEM specs (sorted), the
/// original DEPENDENCIES entry back in and the registry CHECKSUMS line back
/// over the bare path form, then remove the validated uuid dir.
/// A fragment that no longer looks like what vendor wrote — a hand edit, a
/// `bundle update`, a newer vendor run — gets a `vendor_lock_entry_drifted`
/// warning, and then neither file is written: the Gemfile and the lock are
/// reverted together or not at all (#988).
pub async fn revert_gem(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    revert_gem_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_gem`] with full [`RevertOpts`]: `keep_artifact` skips ONLY the
/// artifact deletion; the wiring restore — and the empty-wiring refusal,
/// which applies under `keep_artifact` too — runs unchanged.
///
/// LOSSINESS GUARD (the [`RevertOutcome`] contract every backend honors): a
/// record left alone as genuine drift keeps the artifact dir (and the caller
/// keeps the ledger entry) — the Gemfile `path:` or the lock's PATH section
/// may still route through it, and the entry holds the only pre-vendor
/// originals. A record whose live state already equals its reverted state
/// is convergence, not drift, and stays silent (LIVENESS CONTRACT), so an
/// earlier partial revert or a `bundle update` regeneration never wedges
/// the entry forever.
pub async fn revert_gem_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid
    // grammar is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("gem", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let mut warnings = Vec::new();

    // Fail-closed guard: an entry with NO wiring records (one an older
    // socket-patch repair re-synthesized from the lockfiles, or a
    // hand-stripped state.json) must not "succeed" by deleting the artifact — the
    // Gemfile `path:` and the lock's PATH section would keep pointing at
    // the removed dir and the next `bundle install` hard-fails. Refuse
    // loudly with the manual cleanup steps instead. (Every entry
    // `vendor_gem` records carries at least the Gemfile + lock records.)
    // NOT skipped under `keep_artifact`: a
    // preserve-state revert that cannot restore the wiring must not report
    // the system restored while the pair edit still wires the vendored dir
    // in — the patch would silently stay applied.
    if entry.wiring.is_empty() {
        let name = parse_gem_purl(&entry.base_purl)
            .map(|(n, _)| n.into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());
        return RevertOutcome::failed(format!(
            "vendor_wiring_unknown: the ledger records no wiring for `{name}` (an \
             entry without recoverable originals); refusing to delete {} and \
             strand the pair edit — manually remove the `path:` option (or the socket-patch \
             managed block) for `{name}` from the Gemfile, restore its registry entry in \
             Gemfile.lock (or delete the lock and re-run `bundle install`), then delete \
             {uuid_dir_rel} and this state.json entry",
            entry.artifact.path
        ));
    }

    // A gem committed as its archive, for a Bazel hub.
    if bazel::is_archive(entry) {
        return bazel::revert(entry, project_root, &uuid_dir_rel, opts).await;
    }

    // Wiring is restored in reverse application order: lock first, Gemfile
    // last (the mirror image of vendor's Gemfile-then-lock). Every record is
    // planned against in-memory text first and nothing is written unless
    // none drifted: the Gemfile `path:` and the lock's PATH section must
    // move together, or bundler refuses the pair on every frozen install
    // (#988).
    let Some((name, version)) = parse_gem_purl(&entry.base_purl) else {
        return RevertOutcome::failed(format!("not a gem purl: {}", entry.base_purl));
    };
    let own = OwnGem {
        entry,
        name: name.into_owned(),
        version: version.into_owned(),
    };
    let mut files = RevertFiles::new(project_root);
    let mut drifted = false;
    for w in entry.wiring.iter().rev() {
        let restored = match w.kind.as_str() {
            LOCK_WIRING_KIND => revert_lock_record(&mut files, w, &own).await,
            LOCK_CHECKSUM_WIRING_KIND => revert_lock_checksum_record(&mut files, w, &own).await,
            GEMFILE_WIRING_KIND => revert_gemfile_record(&mut files, w, &own).await,
            _ => {
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
                ));
                continue;
            }
        };
        let key = w.key_label();
        match restored {
            Ok(RecordRevert::Done) => {}
            Ok(RecordRevert::Drifted) => {
                drifted = true;
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!(
                        "{} no longer carries what vendor wrote for {key}; left \
                         alone, and neither {GEMFILE} nor {GEMFILE_LOCK} was changed",
                        w.file
                    ),
                ));
            }
            // A missing wired file cannot still route through the copy dir:
            // reported, but not drift — the artifact may still be removed.
            Ok(RecordRevert::FileMissing) => warnings.push(VendorWarning::new(
                "vendor_lockfile_missing",
                format!("{} is missing; the {key} entry cannot be restored", w.file),
            )),
            Err(e) => {
                return RevertOutcome {
                    kept_artifact: false,
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    let outcome = RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    };
    // All-or-nothing: a drifted record leaves every file as found. A record
    // of a kind this build cannot read still lets the known ones restore
    // (forward compatibility); its warning keeps the artifact below.
    if !drifted && !opts.dry_run {
        if let Err(e) = files.write_changed().await {
            return RevertOutcome {
                success: false,
                error: Some(e),
                ..outcome
            };
        }
    }
    // Drift-keep (see the fn doc): never delete a copy dir a left-alone
    // record may still reference.
    revert::finish(
        outcome,
        project_root,
        &uuid_dir_rel,
        opts,
        KeepPolicy::OnDrift,
    )
    .await
}

// ── Gemfile editing ──────────────────────────────────────────────────────────

/// The planned Gemfile edit.
enum GemfilePlan {
    /// The gem is declared on a safe single top-level line: rewrite it in
    /// place (quote style preserved).
    Rewrite {
        original_line: String,
        new_line: String,
    },
    /// The declaration already carries OUR OWN `path:` wiring from an older
    /// patch uuid (a patch update changes the uuid, never the purl):
    /// repoint it at the new copy in place, everything else on the line
    /// byte-preserved. The wiring record carries `original: None` — the true
    /// pre-vendor line lives in the ledger entry being replaced and the
    /// caller carries it forward by wiring identity (`persist_vendor_entry`);
    /// recording the old-uuid line would make a later revert "restore" a
    /// dangling vendor pointer. `managed_block` is `Some(updated block)` when
    /// the line sits inside our managed fence (the transitive-gem form): the
    /// record then stays `Added` with the whole block, so revert still
    /// deletes the fence.
    RewireOurs {
        original_line: String,
        new_line: String,
        managed_block: Option<String>,
    },
    /// The gem is transitive (not declared): append a fenced managed block.
    Append { block: String },
}

impl GemfilePlan {
    /// What the gem has in place of the patch this plan wires. `hosted`:
    /// the lockfile pins the gem hosted (see [`vendor_gem_previewing`]).
    fn standing(&self, hosted: bool) -> Standing {
        match self {
            Self::RewireOurs { .. } => Standing::EarlierPatch,
            Self::Rewrite { .. } | Self::Append { .. } if hosted => Standing::Hosted,
            Self::Rewrite { .. } | Self::Append { .. } => Standing::NotVendored,
        }
    }
}

/// The way out of a native-extension refusal (#2091): the modes that
/// compile the extension ("Ruby gems: native extensions" in
/// `docs/ecosystems.md`). Worded as hosted mode words its own refusals
/// ("patch <gem> with `--mode vendored` or `--mode agent`"): it names the
/// mode for this gem, not a whole-project command. `hosted` is false when
/// hosted mode would refuse the gem's declaration as well
/// ([`declaration_selects_source`]), and agent mode alone is named.
fn native_extensions_remedy(name: &str, hosted: bool) -> String {
    let modes = if hosted {
        "`--mode hosted` or `--mode agent`, which build"
    } else {
        "`--mode agent`, which builds"
    };
    format!("Patch {name} with {modes} the extension")
}

/// Whether a `gem "<name>"` declaration of the Gemfile `text` picks the
/// gem's source: it sits inside a `source` / `git` / `github` / `path`
/// block, or carries a source option, read by the shared
/// [`gemfile::source_option`] that hosted mode refuses with (so `gitlab:`
/// and custom `git_source` keys count too). Hosted mode refuses such a gem
/// (`redirect_gem_source_option`), so a remedy must not name it. Errs
/// towards `true`: a mode left out of a remedy costs less than one that
/// refuses.
fn declaration_selects_source(text: &str, name: &str) -> bool {
    let mut line_start = 0;
    for line in text.split('\n') {
        let start = line_start;
        line_start += line.len() + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(decl) = gem_declaration(trimmed, name) else {
            continue;
        };
        if crate::formats::gem::ruby::block_stack(text, start)
            .iter()
            .any(|frame| frame.source.is_some())
        {
            return true;
        }
        if gemfile::source_option(decl.rest).is_some() {
            return true;
        }
    }
    false
}

/// The way out of a platform-build refusal (#2091): agent mode, which
/// patches a precompiled gem where it is installed. The refusals that
/// carry it are of an installed copy the lock does not name as a platform
/// build, and of the patch of one platform's build, which only agent mode
/// applies. (Hosted mode patches a gem its lock names as platform builds
/// through the patch registry.)
fn platform_gem_remedy(name: &str) -> String {
    format!(
        "Patch {name} with `--mode agent`, which patches a precompiled gem where it is installed"
    )
}

/// The way out of an indented-declaration refusal (#2091), for the
/// declaration on the line that starts at byte `line_start` of `text`.
///
/// - Inside a `source` / `git` / `github` / `path` block, hosted mode
///   refuses the gem as well (`redirect_gem_source_option`), so agent mode
///   is the one named.
/// - Otherwise the top level is a way out, and so is hosted mode, which
///   edits a declaration where it is. When exactly one block is open and it
///   is a plain `group … do`, the `group:` option that replaces it is
///   spelled out ([`group_option`]). The takeover and eject of a hosted gem
///   raise this refusal too, so hosted mode is worded as the mode to leave
///   the gem to, which reads true whether or not it is hosted already.
fn indented_declaration_remedy(text: &str, line_start: usize, name: &str) -> String {
    let frames = crate::formats::gem::ruby::block_stack(text, line_start);
    if frames.iter().any(|frame| frame.source.is_some()) {
        return format!("patch {name} with `--mode agent`");
    }
    let top_level = match frames.as_slice() {
        [] => "write it without indentation".to_string(),
        [frame] if frame.line == frame.opener => {
            let header = text[frame.line..].lines().next().unwrap_or_default();
            match group_option(header) {
                Some(option) => format!("move it to the top level with the option `{option}`"),
                None => "move it to the top level".to_string(),
            }
        }
        _ => "move it to the top level".to_string(),
    };
    format!("{top_level}, or leave {name} to hosted mode (`--mode hosted`)")
}

/// The `group:` option that stands for the block `header` opens:
/// `group: :test` for `group :test do`, `group: [:development, :test]` for
/// `group :development, :test do`. `None` unless the line is a `group` call
/// whose arguments are all plain symbols: a `group` with options
/// (`optional: true`), a block parameter or a string name has no one-option
/// spelling that is sure to mean the same.
fn group_option(header: &str) -> Option<String> {
    let args = header
        .trim()
        .strip_prefix("group")?
        .strip_suffix("do")?
        .trim();
    let args = args
        .strip_prefix('(')
        .and_then(|a| a.strip_suffix(')'))
        .unwrap_or(args);
    let mut groups = Vec::new();
    for arg in args.split(',') {
        let arg = arg.trim();
        let mut chars = arg.strip_prefix(':')?.chars();
        let plain = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !plain {
            return None;
        }
        groups.push(arg);
    }
    Some(match groups.as_slice() {
        [one] => format!("group: {one}"),
        many => format!("group: [{}]", many.join(", ")),
    })
}

/// Decide how to edit the Gemfile, or explain why it cannot be edited.
///
/// Deliberately conservative: only a single, top-level, statically-parseable
/// `gem "<name>" …` line qualifies for rewriting. Anything else — indented
/// (inside a `group`/`platforms`/conditional block), parenthesized,
/// continued onto the next line, conditional, or already carrying a
/// `path:`/`git:`/`github:` source — is refused rather than guessed at: a
/// wrong Gemfile rewrite executes on every `bundle` invocation. The one
/// `path:` exception is our own vendored dir for this gem (an older patch
/// uuid), which is repointed in place — see [`GemfilePlan::RewireOurs`].
fn plan_gemfile_edit(
    text: &str,
    name: &str,
    version: &str,
    rel: &str,
) -> Result<GemfilePlan, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    // (line idx, top-level?, paren-call?, quote, rest-after-name)
    let mut found: Vec<(usize, bool, bool, char, String)> = Vec::new();
    let mut unparsed_mention = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(d) = gem_declaration(trimmed, name) {
            found.push((
                i,
                trimmed.len() == line.len(),
                d.paren,
                d.quote,
                d.rest.to_string(),
            ));
        } else if gem_call_mentions_name(trimmed, name) {
            unparsed_mention = true;
        }
    }
    if found.is_empty() {
        // Gate the append behind the looser "declared at all?" probe (the
        // redirect rewriter's `declared_re` twin): a declaration the strict
        // grammar above cannot see — `gem"{name}"` with no separator,
        // `gem ("{name}")` with a space before the paren, both valid Ruby —
        // must refuse, never Append. Appending the managed block next to the
        // unseen declaration leaves the Gemfile declaring the gem TWICE, and
        // bundler hard-fails every install on the duplicate.
        if unparsed_mention {
            return Err(format!(
                "a `gem` call names \"{name}\" in a form the line grammar cannot parse; \
                 refusing to append a second declaration (bundler hard-fails on duplicates)"
            ));
        }
        // The block takes the file's line endings: an LF block in a CRLF
        // Gemfile leaves it mixed (#1821). Its declaration is one the
        // Gemfile did not have, so it is `require: false`: without the
        // option `Bundler.require` starts loading the gem at boot (#2084).
        let nl = line_endings::terminator(text);
        return Ok(GemfilePlan::Append {
            block: format!(
                "{MANAGED_OPEN}{nl}gem \"{name}\", \"{version}\", path: \"{rel}\"{REQUIRE_FALSE}{nl}{MANAGED_CLOSE}{nl}"
            ),
        });
    }
    if found.len() > 1 {
        return Err(format!(
            "`gem \"{name}\"` is declared more than once in the Gemfile"
        ));
    }
    let (idx, top_level, paren, q, rest) = found.remove(0);
    // The CR of a CRLF line is its ending, not part of the declaration: the
    // rewritten line puts it back at its end (#1821).
    let cr = if lines[idx].ends_with('\r') { "\r" } else { "" };
    let rest = rest.strip_suffix('\r').unwrap_or(&rest);
    if !top_level {
        let line_start: usize = lines[..idx].iter().map(|line| line.len() + 1).sum();
        let remedy = indented_declaration_remedy(text, line_start, name);
        return Err(format!(
            "the `gem \"{name}\"` declaration is indented (inside a group/conditional block); \
             {remedy}"
        ));
    }
    if paren {
        return Err(format!(
            "the `gem \"{name}\"` declaration uses a parenthesized call"
        ));
    }
    // Our own wiring from an older patch uuid: the `path:` value parses as
    // the socket vendor dir for exactly this gem. Repoint it in place —
    // refusing here (the source-option blocklist below) would make every
    // patch update demand a manual `vendor --revert` first. A path that
    // parses as anything else (a user fork, another gem's dir) still refuses.
    if let Some(prev_rel) = gem_line_path_value(rest) {
        if is_our_vendor_rel(prev_rel, name, version) {
            let original_line = lines[idx].to_string();
            // The fence lines are matched and recorded with their own
            // endings, so the record is the block as it stands in the file.
            let fence = |i: usize, want: &str| {
                lines
                    .get(i)
                    .is_some_and(|l| l.strip_suffix('\r').unwrap_or(l) == want)
            };
            let in_block = idx > 0 && fence(idx - 1, MANAGED_OPEN) && fence(idx + 1, MANAGED_CLOSE);
            // The rel appears exactly once (its charset excludes quotes and
            // `#`, and the code before `path:` cannot contain a `/`-bearing
            // token); swapping just the value preserves quote style and
            // trailing options verbatim.
            let body = original_line.strip_suffix('\r').unwrap_or(&original_line);
            let mut new_line = body.replacen(prev_rel, rel, 1);
            // A block line that ends at its `path:` value is the one
            // releases up to 5.1 appended: it gains the `require: false`
            // the block is now written with (#2084). A line with anything
            // after that value (an option, a comment, a modifier, a `;`)
            // was edited by hand and keeps its bytes: text added behind it
            // could land outside the call's arguments. So does a
            // declaration outside the block, which the Gemfile had before
            // the patch.
            let ends_at_path = rest
                .strip_suffix(['"', '\''])
                .is_some_and(|code| code.ends_with(prev_rel));
            if in_block && ends_at_path && keywords_after_path(rest).is_empty() {
                new_line.push_str(REQUIRE_FALSE);
            }
            new_line.push_str(cr);
            let managed_block =
                in_block.then(|| format!("{}\n{new_line}\n{}\n", lines[idx - 1], lines[idx + 1]));
            return Ok(GemfilePlan::RewireOurs {
                original_line,
                new_line,
                managed_block,
            });
        }
    }
    if let Some(reason) = rest_blocks_edit(rest) {
        return Err(format!(
            "the `gem \"{name}\"` declaration is not editable: {reason}"
        ));
    }
    // Trailing options (`require: false`, `group: :test`, …) must survive the
    // rewrite: dropping `require: false` auto-requires the gem at boot,
    // changing app behavior while vendored.
    // Positional arguments the tail keeps (`gem "x", *V`, `gem "x",
    // VERSION`, `ENV.fetch(…)`) are version constraints, superseded by the
    // exact pin exactly like quoted ones: carried after `path:` they are a
    // Ruby syntax error, and carried before it bundler sees `(= v, ~> 1)`
    // against the lock's `(= v)!` and refuses every frozen install (#847).
    let opts = gemfile::trailing_options(rest);
    let tail = split_kept_tail(&opts);
    let mut new_line = format!("gem {q}{name}{q}, {q}{version}{q}, path: {q}{rel}{q}");
    if !tail.keywords.is_empty() {
        new_line.push_str(", ");
        new_line.push_str(tail.keywords);
    }
    if !tail.comment.is_empty() {
        new_line.push(' ');
        new_line.push_str(tail.comment);
    }
    new_line.push_str(cr);
    Ok(GemfilePlan::Rewrite {
        original_line: lines[idx].to_string(),
        new_line,
    })
}

/// Refuse an [`GemfilePlan::Append`] for a gem the lock lists under
/// `DEPENDENCIES`: bundler resolved it as a DIRECT dependency, so the Gemfile
/// declares it somewhere the line grammar cannot see (`eval_gemfile`, a
/// loop, a gemspec). The managed block would declare it a second time and
/// bundler refuses every install (#482). Every other plan passes through.
/// `gemfile_text` is the Gemfile the plan was made for; the refusal reads
/// it to word its way out ([`out_of_sight_declaration_remedy`]).
fn refuse_append_of_direct_dependency(
    plan: GemfilePlan,
    gemfile_text: &str,
    lock_text: &str,
    name: &str,
) -> Result<GemfilePlan, String> {
    if matches!(plan, GemfilePlan::Append { .. })
        && crate::formats::gem::lock_lists_direct_dependency(lock_text, name)
    {
        return Err(format!(
            "Gemfile.lock lists \"{name}\" as a direct dependency, but the Gemfile declares \
             it somewhere the line grammar cannot edit (an `eval_gemfile`d file, a loop, a \
             gemspec); refusing to append a second declaration (bundler hard-fails on \
             duplicates); {}",
            out_of_sight_declaration_remedy(gemfile_text, name)
        ));
    }
    Ok(plan)
}

/// The way out of [`refuse_append_of_direct_dependency`] (#2151): a `gem`
/// line the line grammar can edit, or agent mode. Hosted mode is not named:
/// it refuses a gem declared in a gemspec, an `eval_gemfile`d file or a
/// loop for the same reason (`redirect_gem_declaration_not_visible`).
///
/// The line stands in place of a `gem` call that declares the gem out of
/// sight, never next to it: the rewrite gives the line an exact version
/// and a `path:`, and bundler refuses a Gemfile whose two declarations of
/// a gem differ. A gemspec's development dependency is no `gem` call and
/// stays.
///
/// Where the Gemfile has a `gemspec` directive, the line goes above it: a
/// gemspec development dependency on the gem merged into a line below the
/// directive is refused next ([`gemspec_merge_refusal`]). A Gemfile whose
/// directives cannot be read gets no such hint, which would not help it:
/// that refusal cannot tell either way and names hosted mode.
fn out_of_sight_declaration_remedy(gemfile_text: &str, name: &str) -> String {
    let above_gemspec = crate::formats::gem::gemspec::gemspec_directives(gemfile_text)
        .is_ok_and(|directives| !directives.is_empty());
    let place = if above_gemspec {
        " above `gemspec`"
    } else {
        ""
    };
    format!(
        "declare it with one literal `gem \"{name}\"` line{place} in the Gemfile, in place \
         of any other `gem` call that declares it, or patch {name} with `--mode agent`"
    )
}

/// Looser "declared at all?" probe — the redirect rewriter's `declared_re`
/// twin. True when a non-comment line is a `gem` call (the keyword followed
/// by anything but an identifier character) whose arguments quote the exact
/// gem name, in ANY form — including ones [`gem_declaration`]'s strict
/// grammar cannot see. Gates [`plan_gemfile_edit`]'s transitive Append plan
/// fail-closed; a false positive (the name quoted elsewhere in a `gem` call's
/// arguments) costs an honest refusal, never a wrong edit.
fn gem_call_mentions_name(trimmed: &str, name: &str) -> bool {
    let Some(rest) = trimmed.strip_prefix("gem") else {
        return false;
    };
    if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    rest.contains(&format!("\"{name}\"")) || rest.contains(&format!("'{name}'"))
}

/// A leading Ruby string literal `"…"` / `'…'` (no escape handling):
/// `(quote, contents, the text after the closing quote)`.
pub(crate) fn quoted_literal(s: &str) -> Option<(char, &str, &str)> {
    let q = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &s[1..];
    let end = rest.find(q)?;
    Some((q, &rest[..end], &rest[end + 1..]))
}

/// One `gem "<name>"` / `gem '<name>'` declaration (see [`gem_declaration_any`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GemDecl<'a> {
    pub(crate) name: &'a str,
    pub(crate) quote: char,
    /// Everything after the name's closing quote.
    pub(crate) rest: &'a str,
    /// Whether the call is parenthesized (`gem("x"…`).
    pub(crate) paren: bool,
}

/// Match `gem "<name>"` / `gem '<name>'` (or the parenthesized call form) at
/// the start of a trimmed line, for any gem name. Space OR tab after the
/// keyword — a tab-separated declaration the grammar cannot see would fall
/// through to the transitive Append plan, leaving the Gemfile declaring the
/// gem twice (bundler hard-fails on the duplicate). Never `gemspec` /
/// `gem_group`. Shared with lockfile discovery's Gemfile `source … do` block
/// reader (`vex::discover::gem`).
pub(crate) fn gem_declaration_any(trimmed: &str) -> Option<GemDecl<'_>> {
    let rest = trimmed.strip_prefix("gem")?;
    let (paren, rest) = match rest.strip_prefix([' ', '\t']) {
        Some(r) => (false, r),
        None => (true, rest.strip_prefix('(')?),
    };
    let (quote, name, rest) = quoted_literal(rest.trim_start())?;
    Some(GemDecl {
        name,
        quote,
        rest,
        paren,
    })
}

/// [`gem_declaration_any`] for exactly the gem `name`.
fn gem_declaration<'a>(trimmed: &'a str, name: &str) -> Option<GemDecl<'a>> {
    gem_declaration_any(trimmed).filter(|d| d.name == name)
}

/// The parts of a gem declaration's kept argument tail (what
/// [`gemfile::trailing_options`] returns) that survive the vendored
/// rewrite: the keyword options after any leading positional arguments,
/// and a trailing `#` comment. Each is a verbatim slice, trimmed.
struct KeptTail<'a> {
    keywords: &'a str,
    comment: &'a str,
}

/// Split the kept tail at the first keyword argument: a `key:` label, a
/// `"key":` label, a `=>` pair or a `**` double splat. Everything before it
/// (`*V`, `VERSION`, `ENV.fetch("V", "~> 1")`, a later quoted constraint) is
/// positional and dropped. Commas, `=>` and `#` only count outside strings
/// and brackets.
fn split_kept_tail(opts: &str) -> KeptTail<'_> {
    let bytes = opts.as_bytes();
    let mut quote: Option<u8> = None;
    let mut depth: i64 = 0;
    let mut arg_start = 0;
    let mut code_end = opts.len();
    let mut keyword_start: Option<usize> = None;
    let mut rocket = false;
    let mut i = 0;
    let close_arg = |start: usize, end: usize, rocket: bool, kw: &mut Option<usize>| {
        if kw.is_none() && (rocket || is_keyword_arg(opts[start..end].trim())) {
            *kw = Some(start);
        }
    };
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => quote = Some(c),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 && bytes.get(i + 1) == Some(&b'>') => rocket = true,
            b',' if depth == 0 => {
                close_arg(arg_start, i, rocket, &mut keyword_start);
                arg_start = i + 1;
                rocket = false;
            }
            b'#' if depth == 0 => {
                code_end = i;
                break;
            }
            _ => {}
        }
        i += 1;
    }
    close_arg(arg_start, code_end, rocket, &mut keyword_start);
    let code = &opts[..code_end];
    let comment = opts[code_end..].trim();
    match keyword_start {
        Some(k) => KeptTail {
            keywords: code[k..].trim(),
            comment,
        },
        None => KeptTail {
            keywords: "",
            comment,
        },
    }
}

/// True when one top-level argument is a keyword argument: a `**` double
/// splat or a `key:` / `"key":` label (not a `Const::Path`).
fn is_keyword_arg(arg: &str) -> bool {
    if arg.starts_with("**") {
        return true;
    }
    let label_end = match arg.as_bytes().first() {
        Some(q @ (b'"' | b'\'')) => arg[1..].find(*q as char).map(|e| e + 2),
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => Some(
            arg.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|e| match arg.as_bytes()[e] {
                    b'?' | b'!' => e + 1,
                    _ => e,
                })
                .unwrap_or(arg.len()),
        ),
        _ => None,
    };
    let Some(end) = label_end else {
        return false;
    };
    let after = &arg.as_bytes()[end..];
    after.first() == Some(&b':') && after.get(1) != Some(&b':')
}

/// Why the text after the gem name blocks an in-place rewrite (`None` = safe).
/// Only the code before any `#` comment counts — a comment trailing plain
/// version constraints is dropped by the rewrite (acceptable: the verbatim
/// original line lives in the ledger for revert), while one trailing kept
/// options rides along with them verbatim. Every source-selecting option is
/// blocked, not just `path:`/`git:`: bundler allows ONE source per gem, so a
/// preserved `source:`, `gitlab:` or custom `git_source` key (in any
/// spelling — the shared [`gemfile::source_option`] reader, the one hosted
/// mode refuses with) alongside the `path:` we add would fail every
/// `bundle` invocation. And so is a computed positional argument
/// ([`gemfile::inert_positionals`]): the rewrite drops the positional
/// arguments and `vendor --revert` puts the declaration back from the
/// committed ledger, which it does only for arguments that evaluate
/// nothing — so the same test decides what the revert restores
/// ([`OwnGem::rewrite_refusal`]).
fn rest_blocks_edit(rest: &str) -> Option<String> {
    if let Some(reason) = gem_line_tail_blocks_edit(rest) {
        return Some(reason);
    }
    let code = rest.split('#').next().unwrap_or("").trim();
    if code.is_empty() {
        return None;
    }
    if !gemfile::inert_positionals(rest) {
        return Some(
            "it computes a positional argument (a method call, a string interpolating one, or a \
             hash naming a source), which `vendor --revert` could not put back safely; use a \
             literal, a constant or an ENV lookup"
                .to_string(),
        );
    }
    // A `**opts` splat or hash literal is kept after `path:` (#847): a
    // source hidden in it makes bundler refuse the Gemfile loudly.
    gemfile::source_option(rest)
        .filter(|opt| !opt.dynamic)
        .map(|opt| {
            format!(
                "the declaration already carries `{}` (revert any previous vendoring first)",
                opt.spelling
            )
        })
}

/// The quoted `path:` option value on a gem line's argument tail (only the
/// code before any `#` comment counts) — the form our own rewrite emits.
/// `None` for anything else (`:path =>`, interpolation, no `path:` at all):
/// those fall through to [`rest_blocks_edit`]'s refusal, fail-closed.
fn gem_line_path_value(rest: &str) -> Option<&str> {
    let code = rest.split('#').next().unwrap_or("");
    let idx = code.find("path:")?;
    if idx > 0 && !matches!(code.as_bytes()[idx - 1], b' ' | b'\t' | b',') {
        return None;
    }
    let after = code[idx + "path:".len()..].trim_start();
    let q = after.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let value = &after[1..];
    let end = value.find(q)?;
    Some(&value[..end])
}

/// True when a `path:`/`remote:` value is OUR vendored dir for exactly this
/// gem (`.socket/vendor/gem/<any-uuid>/<name>-<version>`) — the shape
/// [`vendor_gem`] wires, and the only wiring a patch UPDATE (new uuid, same
/// purl) may rewire.
fn is_our_vendor_rel(value: &str, name: &str, version: &str) -> bool {
    parse_vendor_path(value)
        .is_some_and(|p| p.eco == "gem" && p.leaf == format!("{name}-{version}"))
}

fn apply_gemfile_plan(text: &str, plan: &GemfilePlan) -> String {
    match plan {
        GemfilePlan::Rewrite {
            original_line,
            new_line,
        }
        | GemfilePlan::RewireOurs {
            original_line,
            new_line,
            ..
        } => {
            let mut lines: Vec<&str> = text.split('\n').collect();
            if let Some(i) = lines.iter().position(|l| *l == original_line) {
                lines[i] = new_line;
            }
            lines.join("\n")
        }
        GemfilePlan::Append { block } => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(line_endings::terminator(text));
            }
            out.push_str(block);
            out
        }
    }
}

// ── Gemfile.lock editing ─────────────────────────────────────────────────────

/// The applied lock edit plus the verbatim fragments the ledger records.
struct LockEdit {
    text: String,
    /// The gem's GEM spec block as removed (4-space line + 6-space sublines);
    /// for a gem locked as platform gems, every platform's block in lock
    /// order.
    removed_spec_block: Vec<String>,
    /// The platform of each removed block, in lock order; empty when the
    /// one block is the plain `name (version)` entry.
    platforms: Vec<String>,
    /// The pre-vendor DEPENDENCIES entry (`None` = the gem was transitive and
    /// the entry was added; revert deletes it).
    old_dep_line: Option<String>,
    /// The emitted PATH section lines.
    path_section: Vec<String>,
    /// The DEPENDENCIES entry we wrote (`  <name> (= <version>)!`).
    new_dep_line: String,
    /// CHECKSUMS rewrites `(original line, bare replacement)`, one per
    /// removed block that had a registry line; empty when the lock has no
    /// CHECKSUMS section, no entry for the gem, or every entry was already
    /// bare (idempotency: our own edit is never recorded as an "original" —
    /// reverting it onto a registry-sourced lock would break frozen
    /// installs).
    checksum_rewrites: Vec<(String, String)>,
    /// The spec block was lifted from OUR OWN previous PATH section (a
    /// re-vendor to a newer patch uuid), not from GEM/specs: the lifted
    /// fragments are this backend's own prior wiring, so the caller records
    /// `original: None` and the true pre-vendor originals ride forward from
    /// the ledger entry being replaced (`persist_vendor_entry`).
    rewired_ours: bool,
    /// The already-bare CHECKSUMS lines of the gem's removed blocks.
    /// Only consulted on a re-vendor (`rewired_ours`): the checksum record
    /// must ride again or the first run's registry `sha256=` restore lines
    /// drop out of the ledger with the entry being replaced.
    checksum_bare: Vec<String>,
    /// The `  remote: ` line of the GEM section the spec block was lifted
    /// from, unless that is the lock's first GEM section (#779) and not a
    /// hosted gem's own (#2090). Revert puts the block back into that
    /// section.
    source_remote: Option<String>,
}

/// The `gemfile_lock_spec` record's `(original, new)` line arrays for
/// `edit` (see [`LOCK_WIRING_KIND`] for the positional grammar).
fn lock_record_lines(edit: &LockEdit) -> (Vec<String>, Vec<String>) {
    let mut original = edit.removed_spec_block.clone();
    original.extend(edit.source_remote.iter().cloned());
    original.extend(edit.old_dep_line.iter().cloned());
    let mut new = edit.path_section.clone();
    new.push(edit.new_dep_line.clone());
    (original, new)
}

/// Why vendored mode must not wire `name`@`version` into the Gemfile as
/// `plan` leaves it (`gemfile_after`), if it must not (#985). Bundler 2.7+
/// folds a `gemspec` development dependency on the gem into a `gem` line
/// that follows the directive. For a path gem bundler then rejects even
/// the lock it writes itself under frozen/deployment mode ("rack from
/// `<path>` to `<path>`", verified on 2.7.2 and 4.0.18), so no lock this
/// backend could write keeps vendored mode's frozen-install promise.
/// Declared before the directive, the gem keeps its own requirement and
/// installs frozen: the refusal names that remedy.
fn gemspec_merge_refusal(
    project_root: &Path,
    gemfile_after: &str,
    lock: &str,
    name: &str,
    version: &str,
) -> Option<String> {
    match crate::formats::gem::gemspec::locked_exact_requirement(
        gemfile_after,
        lock,
        name,
        version,
        &mut |dir| gemspec_listing(project_root, dir),
    ) {
        Ok(requirement) if requirement == format!("= {version}") => None,
        Ok(requirement) => Some(format!(
            "the gemspec the Gemfile's `gemspec` directive loads declares a development \
             dependency on `{name}`, so bundler 2.7+ locks the vendored gem as `{name} \
             ({requirement})!` and then rejects that lock under frozen/deployment mode (a \
             bundler limitation for path gems); move the `gem \"{name}\"` declaration above \
             `gemspec` in the Gemfile (bundler then keeps its own requirement), or use hosted \
             mode"
        )),
        Err(why) => Some(format!(
            "cannot tell whether bundler 2.7+ merges a gemspec development dependency on \
             `{name}` into the vendored requirement ({why}), so a frozen install of the \
             vendored pair is not guaranteed; use hosted mode"
        )),
    }
}

/// The `*.gemspec` files of the root-relative directory `dir` under
/// `project_root`, for [`crate::formats::gem::gemspec::locked_exact_requirement`].
fn gemspec_listing(project_root: &Path, dir: &str) -> crate::formats::gem::gemspec::GemspecListing {
    let path = project_root.join(dir);
    let entries = std::fs::read_dir(&path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let Some(file) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !crate::formats::gem::gemspec::is_gemspec_file(&file)
            || entry.file_type().is_ok_and(|t| t.is_dir())
        {
            continue;
        }
        let text = crate::utils::fs::read_regular_to_string_sync(&path.join(&file)).ok();
        out.push((file, text));
    }
    out.sort();
    Ok(out)
}

/// `text` (a Gemfile.lock as read) in the form the lock surgery reads, and
/// the line ending an edit of it is written back in (#1808): a CRLF lock is
/// folded to LF and restored as CRLF. Any other lock stays as read — a
/// mixed one has no single ending to restore, so [`gem_edits`] refuses it.
fn lock_lf_form(text: String) -> (LineEndings, String) {
    match LineEndings::of(&text) {
        LineEndings::Crlf => (LineEndings::Crlf, to_lf(&text).into_owned()),
        eol => (eol, text),
    }
}

/// Produce the pair-edited lock text (see the module doc for the canonical
/// form). Pure string surgery on exact line spans — every byte not
/// deliberately changed is preserved, which is what keeps the result
/// byte-identical to what bundler regenerates.
fn edit_lock(text: &str, name: &str, version: &str, rel: &str) -> Result<LockEdit, String> {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // 1. Lift the gem's spec block out of GEM/specs — or, on a re-vendor to
    // a newer patch uuid (same purl), out of the PATH section our previous
    // run emitted. Bundler 2.2+ writes one GEM section per rubygems source
    // (sorted by remote), so the spec may sit in any of them (#779).
    let gem_sections = gem_section_spans(&lines);
    if gem_sections.is_empty() {
        return Err("Gemfile.lock has no GEM section".to_string());
    }
    if gem_sections
        .iter()
        .any(|&(gs, ge)| !(gs..ge).any(|i| lines[i] == "  specs:"))
    {
        return Err("Gemfile.lock GEM section has no specs: stanza".to_string());
    }
    // The gem's entries: its plain `name (version)` block (the ruby
    // platform), or one block per platform when bundler locked it as
    // precompiled platform gems, which then ALL move (see the module docs).
    let found: Vec<(usize, (usize, usize), Vec<SpecBlock>)> = gem_sections
        .iter()
        .enumerate()
        .map(|(k, &span)| (k, span, gem_spec_blocks(&lines, span, name, version)))
        .filter(|(_, _, blocks)| !blocks.is_empty())
        .collect();
    // SECURITY/fail-closed: a plain entry beside platform-suffixed ones is
    // a gem locked for the ruby platform too, which no vendored prebuild
    // serves (`gem_prelude` refuses it as `platform_gem_unsupported` before
    // this point) — and lifting only one kind would leave the other behind
    // as a stale registry spec. The CHECKSUMS branch below refuses a
    // platform-suffixed sibling of a plain entry as well, but only bundler
    // ≥ 2.6 locks have a CHECKSUMS section to catch it in.
    let blocks_of = || found.iter().flat_map(|(_, _, blocks)| blocks.iter());
    if blocks_of().any(|b| b.platform.is_none()) {
        if let Some(platform) = blocks_of().find_map(|b| b.platform.as_deref()) {
            return Err(format!(
                "Gemfile.lock GEM specs has a platform-suffixed entry `{name} ({version}-{platform})` beside the plain `{name} ({version})`; a gem locked both for the ruby platform and as a platform-specific gem cannot be vendored (re-resolve the lock before vendoring)"
            ));
        }
    }
    if found.len() > 1 {
        // SECURITY/fail-closed: bundler locks one spec per gem; the same
        // entry under two sources is a lock this backend does not
        // understand, and lifting either copy would be a guess.
        return Err(format!(
            "Gemfile.lock lists `{name} ({version})` in more than one GEM section"
        ));
    }
    let mut source_remote: Option<String> = None;
    let mut rewired_ours = false;
    let (removed_spec_block, platforms): (Vec<String>, Vec<String>) = match found.into_iter().next()
    {
        Some((k, (gem_start, gem_end), blocks)) => {
            if k > 0 || hosted_gem_section(&lines[gem_start..gem_end]) {
                // Revert must find this section again; without a remote
                // line there is nothing to find it by.
                source_remote = Some(
                    lines[gem_start..gem_end]
                        .iter()
                        .find(|l| l.starts_with("  remote: "))
                        .cloned()
                        .ok_or_else(|| {
                            format!("Gemfile.lock GEM section holding `{name} ({version})` has no remote: line")
                        })?,
                );
            }
            let span = spec_blocks_span(&blocks, name, version)?;
            let platforms = blocks.into_iter().filter_map(|b| b.platform).collect();
            (lines.drain(span).collect(), platforms)
        }
        None => {
            // Re-vendor: the entry lives in the PATH section our previous
            // run emitted (remote parses as our vendored dir for exactly
            // this gem). Lift the blocks and drop the old section — step 3
            // re-emits it at the NEW uuid's sorted position. The lifted
            // lines are our own wiring, not pre-vendor originals: flagged
            // via `rewired_ours` (see the `LockEdit` field docs).
            let Some((ps, pe)) = find_our_path_section(&lines, name, version) else {
                return Err(format!(
                    "Gemfile.lock GEM specs has no entry `{name} ({version})`"
                ));
            };
            let blocks = gem_spec_blocks(&lines, (ps, pe), name, version);
            if blocks.is_empty() {
                return Err(format!(
                    "Gemfile.lock PATH section for `{name}` lost its `{name} ({version})` spec entry"
                ));
            }
            // Grammar-strict: besides the blocks, the section must be exactly
            // what vendor wrote (header, one remote, specs:, blank
            // separators), and the blocks the plain entry or platform ones,
            // never both. Anything extra — a hand edit, a merged-in second
            // spec — would be destroyed by the drain below; never guess.
            let in_block = |i: &usize| blocks.iter().any(|b| (b.start..b.end).contains(i));
            let non_block: Vec<&str> = (ps..pe)
                .filter(|i| !in_block(i))
                .map(|i| lines[i].as_str())
                .filter(|l| !l.is_empty())
                .collect();
            let mixed = blocks.iter().any(|b| b.platform.is_none())
                && blocks.iter().any(|b| b.platform.is_some());
            if mixed
                || non_block.len() != 3
                || non_block[0] != "PATH"
                || !non_block[1].starts_with("  remote: ")
                || non_block[2] != "  specs:"
            {
                return Err(format!(
                    "Gemfile.lock PATH section for `{name} ({version})` is not the shape vendor wrote; refusing to rewire it"
                ));
            }
            let block: Vec<String> = lines[spec_blocks_span(&blocks, name, version)?].to_vec();
            let platforms = blocks.into_iter().filter_map(|b| b.platform).collect();
            lines.drain(ps..pe);
            rewired_ours = true;
            (block, platforms)
        }
    };

    // 2. DEPENDENCIES: exact pin + `!` path-source marker. A transitive gem
    // (absent pre-vendor) is inserted at bundler's sorted position — it is a
    // Gemfile dependency now.
    let (dep_start, dep_end) = section_span(&lines, "DEPENDENCIES")
        .ok_or_else(|| "Gemfile.lock has no DEPENDENCIES section".to_string())?;
    let new_dep_line = format!("  {name} (= {version})!");
    let mut old_dep_line: Option<String> = None;
    let mut insert_at = dep_start + 1;
    let mut existing_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().take(dep_end).skip(dep_start + 1) {
        let Some(dep_name) = dep_entry_name(line) else {
            continue;
        };
        if dep_name == name {
            existing_idx = Some(i);
            break;
        }
        if dep_name < name {
            insert_at = i + 1;
        }
    }
    match existing_idx {
        Some(i) => {
            old_dep_line = Some(lines[i].clone());
            lines[i] = new_dep_line.clone();
        }
        None => lines.insert(insert_at, new_dep_line.clone()),
    }

    // 3. PATH section above the GEM section, at bundler's SORTED position
    // among any existing PATH sections: bundler emits path/git/plugin
    // sources sorted by identifier (source_list.rb `lock_other_sources`,
    // verified against bundler 4.0.15) — `source at `<path>`` for a path
    // source, so PATH sections order by their remote path and all sit in one
    // contiguous run (no other source's identifier can start with that
    // prefix). Splicing at invocation order instead churns the committed
    // lock on the next `bundle lock`. Non-PATH leading sections keep the
    // legacy insert-before-GEM fallback. `remote:` is the bare relative
    // path (spike claim 2).
    let mut path_section = vec![
        "PATH".to_string(),
        format!("  remote: {rel}"),
        "  specs:".to_string(),
    ];
    path_section.extend(removed_spec_block.iter().cloned());
    let gem_hdr = lines
        .iter()
        .position(|l| l.as_str() == "GEM")
        .ok_or_else(|| "Gemfile.lock lost its GEM section".to_string())?;
    let our_ident = path_source_identifier(rel);
    let mut at = gem_hdr;
    let mut i = 0;
    while i < gem_hdr {
        if lines[i].as_str() == "PATH" {
            let end = section_end(&lines, i);
            match path_section_remote(&lines[i..end]) {
                Some(existing) if path_source_identifier(existing) > our_ident => {
                    at = i;
                    break;
                }
                // Ours sorts after this section (a remote-less section is
                // grammar-degenerate; keep the legacy after-everything spot).
                _ => at = end.min(gem_hdr),
            }
            i = end;
        } else {
            i += 1;
        }
    }
    let mut insert = path_section.clone();
    insert.push(String::new()); // blank separator before the next section
    lines.splice(at..at, insert);

    // 4. CHECKSUMS (bundler ≥ 2.6 `lockfile_checksums`): a path-sourced gem
    // keeps a BARE `  <name> (<version>)` entry — bundler's own re-lock emits
    // exactly that form (spike G2), so the registry `sha256=` token must be
    // stripped here or the committed lock diverges from any regen forever
    // (spike G4: bundler silently preserves a stale token, never repairs it).
    // Absent section / absent entry are both tolerated by bundler — touched
    // by nothing. Re-found via section_span because the PATH splice above
    // shifted every index.
    let mut checksum_rewrites: Vec<(String, String)> = Vec::new();
    let mut checksum_bare: Vec<String> = Vec::new();
    if let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") {
        // The tokens of the entries that moved: `<version>`, or one
        // `<version>-<platform>` per platform block (spike G5: a native gem
        // gets one CHECKSUMS line per platform spec).
        let moved: Vec<String> = match platforms.as_slice() {
            [] => vec![version.to_string()],
            platforms => platforms
                .iter()
                .map(|platform| format!("{version}-{platform}"))
                .collect(),
        };
        let platform_prefix = format!("{version}-");
        // (line index, token) of each moved entry's line.
        let mut ours: Vec<(usize, String)> = Vec::new();
        for (i, line) in lines.iter().enumerate().take(ck_end).skip(ck_start + 1) {
            match checksum_entry(line) {
                Some((n, v)) if n == name && moved.iter().any(|token| token == v) => {
                    if ours.iter().any(|(_, token)| token == v) {
                        // SECURITY/fail-closed: duplicate entries mean the
                        // grammar assumption is wrong for this lock — editing
                        // one of them would be a guess.
                        return Err(format!(
                            "Gemfile.lock CHECKSUMS has more than one entry for `{name} ({v})`"
                        ));
                    }
                    ours.push((i, v.to_string()));
                }
                Some((n, v)) if n == name && (v == version || v.starts_with(&platform_prefix)) => {
                    // SECURITY/fail-closed: an entry for a build of this gem
                    // version that GEM specs does not lock (a
                    // platform-suffixed sibling of the plain entry, or the
                    // plain entry beside platform gems) means the lock
                    // disagrees with itself — never guess which entries
                    // bundler would collapse for a PATH spec.
                    return Err(format!(
                        "Gemfile.lock CHECKSUMS has an entry `{n} ({v})` for a build of the gem that its specs do not lock (a platform-specific or platform-suffixed sibling); the lock disagrees with itself (re-resolve it before vendoring)"
                    ));
                }
                Some(_) => {}
                // SECURITY/fail-closed: a line that names the gem but does
                // not fit the entry grammar would be left half-edited or
                // skipped silently — both wrong. Err unwinds the Gemfile.
                None if checksum_line_names_gem(line, name) => {
                    return Err(format!(
                        "Gemfile.lock CHECKSUMS entry for `{name}` is not parseable: {line:?}"
                    ));
                }
                None => {}
            }
        }
        for (i, token) in ours {
            let bare = format!("  {name} ({token})");
            if lines[i] != bare {
                checksum_rewrites.push((lines[i].clone(), bare.clone()));
                lines[i] = bare;
            } else {
                checksum_bare.push(bare);
            }
        }
    }

    Ok(LockEdit {
        text: lines.join("\n"),
        removed_spec_block,
        platforms,
        old_dep_line,
        path_section,
        new_dep_line,
        checksum_rewrites,
        rewired_ours,
        checksum_bare,
        source_remote,
    })
}

/// One spec block of a gem in a lock section: the lines `[start, end)` of
/// its 4-space entry and 6-space dependency sublines, and the platform of a
/// platform-suffixed entry (`None` for the plain `name (version)`).
struct SpecBlock {
    start: usize,
    end: usize,
    platform: Option<String>,
}

/// The spec blocks of `name`@`version` in the section `[start, end)`, in
/// lock order: its plain `name (version)` entry (the ruby platform) and its
/// platform-suffixed ones (`name (version-arm64-darwin)`). RubyGems
/// versions never contain `-`, so `version-` opens the platform.
fn gem_spec_blocks(
    lines: &[String],
    (start, end): (usize, usize),
    name: &str,
    version: &str,
) -> Vec<SpecBlock> {
    let platform_prefix = format!("{version}-");
    let mut blocks = Vec::new();
    let mut i = start + 1;
    while i < end {
        let platform = match spec_entry(&lines[i]) {
            Some((n, v)) if n == name && v == version => Some(None),
            Some((n, v)) if n == name => v
                .strip_prefix(&platform_prefix)
                .map(|platform| Some(platform.to_string())),
            _ => None,
        };
        let Some(platform) = platform else {
            i += 1;
            continue;
        };
        let mut block_end = i + 1;
        while block_end < end && lines[block_end].starts_with("      ") {
            block_end += 1;
        }
        blocks.push(SpecBlock {
            start: i,
            end: block_end,
            platform,
        });
        i = block_end;
    }
    blocks
}

/// The one line span `blocks` (a gem's spec blocks in one section,
/// non-empty) cover, which the lock edit moves as a whole. Fail-closed on
/// what bundler never writes: an entry listed twice, or the platform
/// entries apart from each other (bundler sorts a section's specs by full
/// name, so they are adjacent; revert puts the recorded blocks back as one
/// run, which would not be where separated ones came from).
fn spec_blocks_span(
    blocks: &[SpecBlock],
    name: &str,
    version: &str,
) -> Result<std::ops::Range<usize>, String> {
    for (i, block) in blocks.iter().enumerate() {
        if blocks[..i].iter().any(|b| b.platform == block.platform) {
            let token = match &block.platform {
                Some(platform) => format!("{version}-{platform}"),
                None => version.to_string(),
            };
            return Err(format!(
                "Gemfile.lock lists `{name} ({token})` more than once in one section"
            ));
        }
    }
    if blocks.windows(2).any(|pair| pair[0].end != pair[1].start) {
        return Err(format!(
            "Gemfile.lock lists the platform entries of `{name} ({version})` apart from each other, which is not the order bundler writes (re-resolve the lock before vendoring)"
        ));
    }
    Ok(blocks[0].start..blocks[blocks.len() - 1].end)
}

/// `[start, end)` of a lock section: the column-0 `header` line through (not
/// including) the next column-0 line. Blank separator lines belong to the
/// section they follow.
fn section_span(lines: &[String], header: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| l.as_str() == header)?;
    Some((start, section_end(lines, start)))
}

/// End (exclusive) of the section whose column-0 header sits at `start` —
/// the [`section_span`] rule for a known header position.
fn section_end(lines: &[String], start: usize) -> usize {
    let mut end = start + 1;
    while end < lines.len() {
        let l = &lines[end];
        if !l.is_empty() && !l.starts_with(' ') {
            break;
        }
        end += 1;
    }
    end
}

/// `[start, end)` of every GEM section, in lock order.
fn gem_section_spans(lines: &[String]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].as_str() == "GEM" {
            let end = section_end(lines, i);
            spans.push((i, end));
            i = end;
        } else {
            i += 1;
        }
    }
    spans
}

/// True when `section` (one GEM section's lines) is a hosted gem's own:
/// it has a `remote:` line and each one is a Socket gem patch registry
/// (`…/patch-registry/gem/<token>/<uuid>/`) on any origin; revert is not
/// told which patch servers the scan used. Hosted mode writes one such
/// section per patched gem, and bundler sorts it by its remote, which for
/// `https://patch.socket.dev/` is ahead of `https://rubygems.org/`. A
/// section that merges a patch registry remote with an upstream one (the
/// bundler < 2.2 lock layout) holds upstream specs too and is not one.
fn hosted_gem_section(section: &[String]) -> bool {
    let mut remotes = section
        .iter()
        .filter_map(|l| l.strip_prefix("  remote: "))
        .peekable();
    remotes.peek().is_some()
        && remotes.all(|r| {
            r.contains("/patch-registry/gem/") && crate::origin::hosted_shape_uuid(r).is_some()
        })
}

/// The GEM section a `gemfile_lock_spec` record's spec block belongs in:
/// the one carrying the recorded `remote:` line. With none recorded the
/// block came from what was the lock's first GEM section when the gem was
/// vendored, and that is the first GEM section that is not a hosted gem's
/// own: a hosted scan run since then may have put its sections ahead
/// (#2090), and a block lifted from a hosted section always records it.
fn record_gem_section(lines: &[String], source_remote: Option<&str>) -> Option<(usize, usize)> {
    let mut spans = gem_section_spans(lines).into_iter();
    match source_remote {
        None => spans.find(|&(gs, ge)| !hosted_gem_section(&lines[gs..ge])),
        Some(remote) => spans.find(|&(gs, ge)| lines[gs..ge].iter().any(|l| l == remote)),
    }
}

/// The recorded source-section `remote:` line in a `gemfile_lock_spec`
/// record's `original`, if it has one (see [`LOCK_WIRING_KIND`]).
fn record_source_remote(original_lines: &[String]) -> Option<&str> {
    original_lines
        .iter()
        .map(String::as_str)
        .find(|l| l.starts_with("  remote: "))
}

/// Bundler's lock-sort identifier for a path source — `source at `<path>``
/// (`Source::Path#to_s`, aliased as `identifier`); sections order by a
/// byte-wise comparison of these, which Rust's `str` ordering matches.
fn path_source_identifier(path: &str) -> String {
    format!("source at `{path}`")
}

/// The `  remote: ` value of the section slice starting at its header line.
fn path_section_remote(section: &[String]) -> Option<&str> {
    section.iter().find_map(|l| l.strip_prefix("  remote: "))
}

/// Find the PATH section whose `remote:` is OUR vendored dir for this gem —
/// any patch uuid (the previous run's wiring, sought during a re-vendor).
fn find_our_path_section(lines: &[String], name: &str, version: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        if lines[i].as_str() == "PATH" {
            let end = section_end(lines, i);
            if path_section_remote(&lines[i..end])
                .is_some_and(|p| is_our_vendor_rel(p, name, version))
            {
                return Some((i, end));
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// `line`'s entry text at exactly `indent` (2 or 4) spaces: non-empty and
/// not more deeply indented.
fn at_indent(line: &str, indent: usize) -> Option<&str> {
    let rest = line.strip_prefix(&"    "[..indent])?;
    (!rest.is_empty() && !rest.starts_with(' ')).then_some(rest)
}

/// Name of a 2-space DEPENDENCIES entry (`  rack (~> 3.1)` / `  rack!`).
fn dep_entry_name(line: &str) -> Option<&str> {
    let rest = at_indent(line, 2)?;
    let end = rest.find([' ', '(', '!']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Name of a 4-space spec entry (`    rack (3.2.6)`).
fn spec_entry_name(line: &str) -> Option<&str> {
    let rest = at_indent(line, 4)?;
    Some(rest.split(' ').next().unwrap_or(rest))
}

/// Parse a 4-space specs entry line: `    <name> (<token>)`, nothing after
/// the closing paren. Returns `(name, parenthesized token)` — the platform
/// suffix stays inside the token, mirroring [`checksum_entry`]'s grammar at
/// specs indentation (`    ffi (1.17.2-aarch64-linux-gnu)`).
fn spec_entry(line: &str) -> Option<(&str, &str)> {
    match split_entry(at_indent(line, 4)?)? {
        (name, ver, "") => Some((name, ver)),
        _ => None,
    }
}

/// Parse a CHECKSUMS entry line: two-space indent, `<name> (<version>)` or
/// `<name> (<version>-<platform>)`, then optional space-separated tokens
/// (`sha256=<hex>` on registry entries, nothing on path entries). Returns
/// `(name, parenthesized token)` — the platform suffix stays inside the token
/// because matching must mirror the GEM specs grammar (spike G5: native gems
/// get one CHECKSUMS line per platform spec, `ffi (1.17.2-aarch64-linux-gnu)`).
fn checksum_entry(line: &str) -> Option<(&str, &str)> {
    let (name, ver, _) = split_checksum_entry(at_indent(line, 2)?)?;
    Some((name, ver))
}

/// True when a CHECKSUMS-section line's leading token is `name` — used to
/// fail closed on lines that mention the gem but do not fit the
/// [`checksum_entry`] grammar (editing around them would be a guess).
fn checksum_line_names_gem(line: &str, name: &str) -> bool {
    line.strip_prefix("  ")
        .filter(|r| !r.starts_with(' '))
        .and_then(|r| r.split([' ', '(']).next())
        == Some(name)
}

/// True when the lock's CHECKSUMS section is coherent with a path-sourced
/// gem: no section, no entry for the gem, or exactly the bare
/// `  <name> (<version>)` form — for a gem wired as platform gems, the bare
/// `  <name> (<version>-<platform>)` form of each of `platforms`. A leftover
/// registry `sha256=` token (a lock wired by a pre-CHECKSUMS-aware
/// socket-patch) is NOT in sync — bundler silently preserves it forever
/// (spike G4), so the hot path must not declare such a lock done; only
/// revert + re-vendor can repair it. Nor is an entry for a build of the gem
/// the wired `PATH` section does not hold.
fn lock_checksum_in_sync(lock_text: &str, name: &str, version: &str, platforms: &[String]) -> bool {
    let lines: Vec<String> = lock_text.split('\n').map(str::to_string).collect();
    let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") else {
        return true;
    };
    let wired = |token: &str| match platforms {
        [] => token == version,
        platforms => token
            .strip_prefix(version)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|platform| platforms.iter().any(|p| p == platform)),
    };
    let platform_prefix = format!("{version}-");
    for line in &lines[ck_start + 1..ck_end] {
        match checksum_entry(line) {
            Some((n, v)) if n == name && (v == version || v.starts_with(&platform_prefix)) => {
                if !wired(v) || *line != format!("  {n} ({v})") {
                    return false;
                }
            }
            Some(_) => {}
            None if checksum_line_names_gem(line, name) => return false,
            None => {}
        }
    }
    true
}

// ── what a ledger record may write ───────────────────────────────────────────

/// The gem a ledger entry vendors, for checking what one of its records
/// replaces and what it puts back, right where the revert is about to
/// splice recorded text in.
///
/// The ledger is committed, so a checkout can carry any ledger; the revert
/// splices its text into the Gemfile (Ruby that every `bundle` command
/// runs) and the lock (what bundler installs from). Each record must
/// therefore be the pair edit [`vendor_gem`] makes for THIS gem, or the
/// revert fails with nothing written (every file is planned in memory
/// first). A record whose pre-vendor state is already back writes nothing
/// and is not checked, so a hand-restored Gemfile still converges.
struct OwnGem<'a> {
    entry: &'a VendorEntry,
    name: String,
    version: String,
}

impl OwnGem<'_> {
    /// Whether `value` (a `path:` or `remote:` value) is this patch's copy
    /// of the gem.
    fn is_copy(&self, value: &str) -> bool {
        parse_vendor_path(value).is_some_and(|p| {
            p.eco == "gem"
                && p.uuid == self.entry.uuid
                && p.leaf == format!("{}-{}", self.name, self.version)
        })
    }

    /// The vendored declaration of the gem on a Gemfile line: a top-level
    /// `gem "<name>", …, path: "<this patch's copy>"`.
    fn vendored_declaration<'l>(&self, line: &'l str) -> Option<GemDecl<'l>> {
        gem_declaration(line, &self.name).filter(|d| {
            !d.paren && gem_line_path_value(d.rest).is_some_and(|path| self.is_copy(path))
        })
    }

    /// The failure of the revert over `rec`, which `why`.
    fn refused(&self, rec: &WiringRecord, why: &str) -> String {
        super::state::refused_record(self.entry, rec, why)
    }

    /// Why replacing the Gemfile line `written` with `original` is not the
    /// undo of the vendored rewrite: `written` must be this patch's own
    /// `path:` declaration, and `original` ONE top-level declaration of the
    /// same gem that the rewrite replaces — no source option, nothing
    /// computed among the positional arguments it dropped
    /// ([`rest_blocks_edit`]), and the keyword options the vendored line
    /// still shows.
    fn rewrite_refusal(&self, written: &str, original: &str) -> Option<&'static str> {
        let Some(vendored) = self
            .vendored_declaration(written)
            .filter(|_| is_one_line(written, true))
        else {
            return Some(NOT_OUR_DECLARATION);
        };
        let restorable = is_one_line(original, true)
            && gem_declaration(original, &self.name).is_some_and(|d| {
                !d.paren
                    && rest_blocks_edit(d.rest).is_none()
                    && kept_keywords(d.rest) == keywords_after_path(vendored.rest)
            });
        (!restorable).then_some(
            "puts back Gemfile text that is not one plain declaration of this gem the vendored \
             line replaced",
        )
    }

    /// Why removing the Gemfile text `written` is not the undo of the
    /// managed block: the fence around this patch's own declaration.
    fn block_refusal(&self, written: &str) -> Option<&'static str> {
        let lines: Vec<&str> = written
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect();
        let ours = match lines.as_slice() {
            [MANAGED_OPEN, decl, MANAGED_CLOSE, ""] => {
                is_one_line(decl, false) && self.vendored_declaration(decl).is_some()
            }
            _ => false,
        };
        (!ours).then_some(NOT_OUR_DECLARATION)
    }

    /// Why swapping the lock lines `new` for `original` is not the undo of
    /// the lock edit: `new` is this patch's `PATH` section and dependency
    /// entry, `original` the gem's own spec block (one entry per platform,
    /// each with its dependency lines), the `remote:` of the section it
    /// came from and its dependency entry — one lock line each.
    fn lock_refusal(&self, original: &[String], new: &[String]) -> Option<&'static str> {
        let plain = |lines: &[String]| lines.iter().all(|l| is_one_line(l, false));
        let our_section = new.split_last().is_some_and(|(dep, path)| {
            path.first().is_some_and(|l| l == "PATH")
                && path
                    .get(1)
                    .and_then(|l| l.strip_prefix("  remote: "))
                    .is_some_and(|remote| self.is_copy(remote))
                && dep_entry_name(dep) == Some(self.name.as_str())
        });
        if !plain(new) || !our_section {
            return Some(
                "replaces lock lines that are not this patch's own PATH section and dependency \
                 entry",
            );
        }
        let own = |line: &String| {
            if let Some(entry) = at_indent(line, 4) {
                crate::formats::gem::parse_spec(entry).is_some_and(|spec| spec.name == self.name)
            } else if let Some(dependency) = line.strip_prefix("      ") {
                dependency
                    .split([' ', '('])
                    .next()
                    .is_some_and(is_plain_gem_token)
            } else {
                line.starts_with("  remote: ") || dep_entry_name(line) == Some(self.name.as_str())
            }
        };
        (!plain(original) || !original.iter().all(own)).then_some(
            "puts back lock lines that are not this gem's own spec block, source remote and \
             dependency entry",
        )
    }

    /// Whether `line` is the gem's own `CHECKSUMS` entry.
    fn is_checksum(&self, line: &str) -> bool {
        is_one_line(line, false) && checksum_entry(line).is_some_and(|(gem, _)| gem == self.name)
    }
}

const NOT_OUR_DECLARATION: &str =
    "replaces Gemfile text that is not this patch's own `path:` declaration";
const NOT_OUR_CHECKSUM: &str = "swaps CHECKSUMS lines that are not this gem's own entry";

/// A recorded line: no line break or other control character (a tab
/// aside), so it stays the one line it is spliced in as. `cr` allows the
/// CR of a CRLF Gemfile line, which is recorded with it.
fn is_one_line(line: &str, cr: bool) -> bool {
    let body = if cr {
        line.strip_suffix('\r').unwrap_or(line)
    } else {
        line
    };
    !body.chars().any(|c| c.is_control() && c != '\t')
}

/// The keyword options of a declaration's tail, as the vendored rewrite
/// keeps them ([`split_kept_tail`]).
fn kept_keywords(rest: &str) -> String {
    let opts = gemfile::trailing_options(rest.strip_suffix('\r').unwrap_or(rest));
    split_kept_tail(&opts).keywords.to_string()
}

/// The keyword options a vendored declaration carries after its own
/// `path:`: the ones the rewrite kept from the line it replaced.
fn keywords_after_path(rest: &str) -> String {
    let kept = kept_keywords(rest);
    gemfile::split_args(&kept)
        .and_then(|args| args.get(1).map(|(at, _)| kept[*at..].trim().to_string()))
        .unwrap_or_default()
}

// ── revert helpers ───────────────────────────────────────────────────────────

/// What restoring one wiring record found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordRevert {
    /// Restored (or would be, on a dry run) — or already in its reverted
    /// state (convergence: silent per the LIVENESS CONTRACT on
    /// [`RevertOutcome::drift_skipped`]).
    Done,
    /// What vendor wrote is gone and the pre-vendor original is not back
    /// either: genuine third-party drift, left alone in full.
    Drifted,
    /// The wired file itself no longer exists: nothing can still route
    /// through the vendored copy via it.
    FileMissing,
}

/// The Gemfile and Gemfile.lock as one revert sees them: read on first
/// use, edited in memory, and written back only by
/// [`RevertFiles::write_changed`], which [`revert_gem_opts`] skips when any
/// record drifted. So a revert never leaves the lock restored while the
/// Gemfile still names the `path:` copy, or the other way round.
struct RevertFiles<'a> {
    root: &'a Path,
    lock: Option<RevertFile>,
    gemfile: Option<RevertFile>,
}

struct RevertFile {
    /// `None`: the file does not exist.
    text: Option<String>,
    /// The bytes as read, to put back if a later write fails.
    read: Option<String>,
    /// The line ending `text` is written back in: a CRLF lock is reverted
    /// in LF form, like [`edit_lock`] edits it (#1808).
    eol: LineEndings,
    changed: bool,
}

impl<'a> RevertFiles<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            lock: None,
            gemfile: None,
        }
    }

    /// The text of `name` (`GEMFILE` or `GEMFILE_LOCK`), reading it on
    /// first use; `Ok(None)` when it does not exist.
    async fn text(&mut self, name: &str) -> Result<Option<&mut RevertFile>, String> {
        let root = self.root;
        let slot = if name == GEMFILE {
            &mut self.gemfile
        } else {
            &mut self.lock
        };
        if slot.is_none() {
            let text = match read_regular_to_string(&root.join(name)).await {
                Ok(t) => Some(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("unreadable {name}: {e}")),
            };
            let read = text.clone();
            let (eol, text) = match text {
                Some(t) if name == GEMFILE_LOCK => {
                    let (eol, t) = lock_lf_form(t);
                    (eol, Some(t))
                }
                other => (LineEndings::Lf, other),
            };
            *slot = Some(RevertFile {
                read,
                text,
                eol,
                changed: false,
            });
        }
        let file = slot.as_mut().expect("just filled");
        Ok(file.text.is_some().then_some(file))
    }

    /// Write every edited file, lock first. When the Gemfile write fails
    /// after the lock was written, the lock's bytes as read are put back so
    /// the pair is not left half reverted.
    async fn write_changed(&self) -> Result<(), String> {
        let mut written: Option<(&str, &str)> = None;
        for (name, file) in [(GEMFILE_LOCK, &self.lock), (GEMFILE, &self.gemfile)] {
            let Some(RevertFile {
                text: Some(text),
                read,
                eol,
                changed: true,
            }) = file
            else {
                continue;
            };
            let text = eol.restore(text);
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&self.root.join(name), text.as_bytes()).await
            {
                if let Some((prev, bytes)) = written {
                    let _ =
                        atomic_write_bytes_preserving_mode(&self.root.join(prev), bytes.as_bytes())
                            .await;
                }
                return Err(format!("failed to write {name}: {e}"));
            }
            if let Some(read) = read {
                written = Some((name, read));
            }
        }
        Ok(())
    }
}

impl RevertFile {
    fn text(&self) -> &str {
        self.text.as_deref().unwrap_or_default()
    }

    fn set(&mut self, text: String) {
        self.text = Some(text);
        self.changed = true;
    }
}

/// Restore one `gemfile_line` record.
async fn revert_gemfile_record(
    files: &mut RevertFiles<'_>,
    w: &WiringRecord,
    own: &OwnGem<'_>,
) -> Result<RecordRevert, String> {
    let Some(file) = files.text(GEMFILE).await? else {
        return Ok(RecordRevert::FileMissing);
    };
    let text = file.text();
    let Some(written) = w.new.as_ref().and_then(Value::as_str) else {
        return Ok(RecordRevert::Drifted);
    };
    let restored = match w.action {
        WiringAction::Rewritten => {
            let Some(original) = w.original.as_ref().and_then(Value::as_str) else {
                return Ok(RecordRevert::Drifted);
            };
            let mut lines: Vec<&str> = text.split('\n').collect();
            let Some(i) = find_wired_gemfile_line(&lines, written) else {
                // ALREADY CONVERGED: the pre-vendor line is back (a hand
                // restore, a `bundle update` regeneration, an earlier partial
                // revert) — not drift, nothing to write.
                // Either line ending: a re-checkout may have changed it.
                let original = original.strip_suffix('\r').unwrap_or(original);
                if lines
                    .iter()
                    .any(|l| l.strip_suffix('\r').unwrap_or(l) == original)
                {
                    return Ok(RecordRevert::Done);
                }
                return Ok(gemfile_left_without_our_line(text, written));
            };
            if let Some(why) = own.rewrite_refusal(written, original) {
                return Err(own.refused(w, why));
            }
            let line = restore_gemfile_line(lines[i], written, original);
            lines[i] = &line;
            lines.join("\n")
        }
        WiringAction::Added => {
            // A re-checkout may have changed the block's line endings since
            // vendor wrote it (`core.autocrlf`): look for it as written, then
            // as the file now spells its lines.
            let mut written = std::borrow::Cow::Borrowed(written);
            let mut found = text.find(&*written);
            if found.is_none() {
                written = line_endings::respell(&written, line_endings::terminator(text)).into();
                found = text.find(&*written);
            }
            let Some(at) = found else {
                // ALREADY CONVERGED: an Added block's reverted state is its
                // absence (the LIVENESS CONTRACT's "key is absent" case) —
                // unless an edited copy of it still wires the gem in.
                return Ok(gemfile_left_without_our_line(text, &written));
            };
            if let Some(why) = own.block_refusal(&written) {
                return Err(own.refused(w, why));
            }
            let mut out = String::with_capacity(text.len());
            out.push_str(&text[..at]);
            out.push_str(&text[at + written.len()..]);
            out
        }
    };
    file.set(restored);
    Ok(RecordRevert::Done)
}

/// The index of the Gemfile line carrying the `written` wiring: the exact
/// line, or else the one line whose code matches it and whose trailing
/// comment the user added, edited or removed (#988). A line whose code
/// changed too (an option added, the line reformatted) is not matched:
/// restoring the original over it would silently drop the user's edit.
/// `None` when no line, or more than one, matches.
fn find_wired_gemfile_line(lines: &[&str], written: &str) -> Option<usize> {
    if let Some(i) = lines.iter().position(|l| *l == written) {
        return Some(i);
    }
    let code = split_line_comment(written).0.trim_end();
    let mut hits = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| split_line_comment(l).0.trim_end() == code);
    let (i, _) = hits.next()?;
    hits.next().is_none().then_some(i)
}

/// What a Gemfile whose recorded wiring (`written`: the rewritten line or
/// the managed block) is no longer found verbatim means for the revert.
/// Vendor reads a Gemfile that still contains the copy path as wired, so
/// revert does too: such a Gemfile, or one that now points the gem at
/// another source, is drift and keeps the lock wired as well. A Gemfile
/// that declares the gem from the registry again (or not at all) has
/// converged, so the lock can follow it back.
fn gemfile_left_without_our_line(text: &str, written: &str) -> RecordRevert {
    let Some((name, copy)) = written.split('\n').find_map(|l| {
        let d = gem_declaration_any(l)?;
        Some((d.name, gem_line_path_value(d.rest)?))
    }) else {
        return RecordRevert::Drifted;
    };
    let repointed = text.split('\n').any(|l| {
        gem_declaration(l.trim_start(), name).is_some_and(|d| {
            gem_line_path_value(d.rest).is_some() || gemfile::source_option(d.rest).is_some()
        })
    });
    if text.contains(copy) || repointed {
        RecordRevert::Drifted
    } else {
        RecordRevert::Done
    }
}

/// The pre-vendor `original` line to put back over `live`, the wired line
/// as found. When the user changed the trailing comment vendor wrote, their
/// comment (and the spacing before it) replaces the original's, so a note
/// like `# CVE fix, do not bump` survives the revert. A CR line ending is
/// the original's, unless the live line's ending differs from the one
/// vendor wrote: a re-checkout changed the file's line endings since, and
/// the restored line follows the file (#1821).
fn restore_gemfile_line(live: &str, written: &str, original: &str) -> String {
    let (live_code, live_comment) = split_line_comment(live);
    let (_, written_comment) = split_line_comment(written);
    let ends_cr = if live.ends_with('\r') == written.ends_with('\r') {
        original.ends_with('\r')
    } else {
        live.ends_with('\r')
    };
    let cr = if ends_cr { "\r" } else { "" };
    if live == written || live_comment.trim() == written_comment.trim() {
        return format!("{}{cr}", original.strip_suffix('\r').unwrap_or(original));
    }
    let (original_code, _) = split_line_comment(original);
    let live_body = live.strip_suffix('\r').unwrap_or(live);
    let suffix = &live_body[live_code.trim_end().len()..];
    if suffix.trim().is_empty() {
        format!("{}{cr}", original_code.trim_end())
    } else {
        format!("{}{suffix}{cr}", original_code.trim_end())
    }
}

/// A Gemfile line split into its code and its trailing `#` comment (empty
/// when it has none), outside quotes; a CR line ending belongs to neither.
fn split_line_comment(line: &str) -> (&str, &str) {
    let body = line.strip_suffix('\r').unwrap_or(line);
    let code = gemfile::code_of(body).unwrap_or(body);
    (code, &body[code.len()..])
}

/// Restore one `gemfile_lock_spec` record. Drift leaves the lock alone in
/// full — a partial splice would corrupt it.
async fn revert_lock_record(
    files: &mut RevertFiles<'_>,
    w: &WiringRecord,
    own: &OwnGem<'_>,
) -> Result<RecordRevert, String> {
    let Some(original_lines) = wiring_string_array(w.original.as_ref()) else {
        return Ok(RecordRevert::Drifted);
    };
    let Some(new_lines) = wiring_string_array(w.new.as_ref()) else {
        return Ok(RecordRevert::Drifted);
    };
    let Some(file) = files.text(GEMFILE_LOCK).await? else {
        return Ok(RecordRevert::FileMissing);
    };
    let text = file.text();
    let Some(restored) = revert_lock_text(text, &original_lines, &new_lines) else {
        // ALREADY CONVERGED: our PATH section is gone and every pre-vendor
        // spec line is back in GEM/specs (a `bundle update` regeneration or
        // an earlier partial revert) — not drift, nothing to write.
        return Ok(
            if lock_record_converged(text, &original_lines, &new_lines) {
                RecordRevert::Done
            } else {
                RecordRevert::Drifted
            },
        );
    };
    if let Some(why) = own.lock_refusal(&original_lines, &new_lines) {
        return Err(own.refused(w, why));
    }
    file.set(restored);
    Ok(RecordRevert::Done)
}

/// True when the lock already holds the record's reverted state: no PATH
/// section carries vendor's `remote:` line and every spec-block line of the
/// pre-vendor original is present.
fn lock_record_converged(text: &str, original_lines: &[String], new_lines: &[String]) -> bool {
    // A record whose `new` lost its `remote:` line is malformed, never
    // converged (the tampered-ledger matrix pins it as drift).
    let Some(remote_line) = new_lines.get(1).filter(|l| l.starts_with("  remote: ")) else {
        return false;
    };
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    if find_path_section(&lines, remote_line).is_some() {
        return false;
    }
    let Some((gs, ge)) = record_gem_section(&lines, record_source_remote(original_lines)) else {
        return false;
    };
    let gem = &lines[gs..ge];
    let mut spec_block = original_lines.iter().filter(|l| l.starts_with("    "));
    let mut any = false;
    let all_present = spec_block.all(|l| {
        any = true;
        gem.contains(l)
    });
    any && all_present
}

fn wiring_string_array(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// Restore one `gemfile_lock_checksum` record: the registry CHECKSUMS line
/// (`sha256=` token and all) goes back over the bare path-form line vendor
/// wrote. Restoring is not optional polish — a bare entry left on a
/// registry-sourced gem hard-fails `BUNDLE_FROZEN=true bundle install`
/// (exit 16) and plain installs rewrite the lock to refill the token (churn);
/// the token is not recomputable offline (spike `bare-checksum-registry-gem`
/// pair). The search is confined to the CHECKSUMS section so a coincidental
/// identical line elsewhere (e.g. a DEPENDENCIES entry) is never clobbered.
/// The line vendor wrote being gone is drift — unless the registry line it
/// replaced is already back (convergence), left alone either way.
async fn revert_lock_checksum_record(
    files: &mut RevertFiles<'_>,
    w: &WiringRecord,
    own: &OwnGem<'_>,
) -> Result<RecordRevert, String> {
    // Each line vendor wrote, with the registry line it replaced: the one
    // pair of a ruby-platform gem, or (arrays) one pair per platform entry
    // of a gem vendored as platform gems, matched by their `name (token)`.
    let pairs: Vec<(String, Option<String>)> = match (w.new.as_ref(), w.original.as_ref()) {
        (Some(Value::String(written)), original) => vec![(
            written.clone(),
            original.and_then(Value::as_str).map(str::to_string),
        )],
        (Some(written @ Value::Array(_)), original) => {
            let (Some(written), Some(originals)) = (
                wiring_string_array(Some(written)),
                original.map_or(Some(Vec::new()), |o| wiring_string_array(Some(o))),
            ) else {
                return Ok(RecordRevert::Drifted);
            };
            written
                .into_iter()
                .map(|line| {
                    let entry = checksum_entry(&line);
                    let original = originals
                        .iter()
                        .find(|o| entry.is_some() && checksum_entry(o) == entry)
                        .cloned();
                    (line, original)
                })
                .collect()
        }
        _ => return Ok(RecordRevert::Drifted),
    };
    let Some(file) = files.text(GEMFILE_LOCK).await? else {
        return Ok(RecordRevert::FileMissing);
    };
    let mut lines: Vec<String> = file.text().split('\n').map(str::to_string).collect();
    let Some((ck_start, ck_end)) = section_span(&lines, "CHECKSUMS") else {
        // ALREADY CONVERGED: a lock without a CHECKSUMS section carries no
        // checksum for the gem at all, so there is no line left to restore.
        return Ok(RecordRevert::Done);
    };
    // Every pair is judged before the lock text is replaced, so one drifted
    // line leaves the others as found.
    let mut restored = false;
    for (written, original) in &pairs {
        let original = original.as_deref();
        let Some(i) = (ck_start + 1..ck_end).find(|&i| lines[i] == *written) else {
            // ALREADY CONVERGED: the registry line vendor replaced is back.
            if original.is_some_and(|orig| (ck_start + 1..ck_end).any(|i| lines[i] == orig)) {
                continue;
            }
            return Ok(RecordRevert::Drifted);
        };
        let Some(original) = original else {
            // A re-vendor rides the checksum record forward with `original: None`
            // for the caller's carry-forward to fill. When the chain has no
            // registry line to fill FROM — the pre-vendor entry was ALREADY the
            // bare path form (vendor then recorded no checksum wiring at all) —
            // there is nothing to restore: the bare line still standing IS the
            // pre-vendor state, not drift.
            continue;
        };
        if !own.is_checksum(written) || !own.is_checksum(original) {
            return Err(own.refused(w, NOT_OUR_CHECKSUM));
        }
        lines[i] = original.to_string();
        restored = true;
    }
    if restored {
        file.set(lines.join("\n"));
    }
    Ok(RecordRevert::Done)
}

/// Pure splice reversing [`edit_lock`]: drop the PATH section vendor emitted,
/// move the spec block back into GEM/specs at its sorted position, and
/// restore (or delete) the DEPENDENCIES entry. All preconditions are checked
/// BEFORE any mutation so drift never yields a half-restored lock; `None`
/// means "drifted, leave the lock alone".
fn revert_lock_text(text: &str, original_lines: &[String], new_lines: &[String]) -> Option<String> {
    let (new_dep_line, path_lines) = new_lines.split_last()?;
    let remote_line = path_lines.get(1)?;
    if !remote_line.starts_with("  remote: ") {
        return None;
    }
    let spec_block: Vec<&String> = original_lines
        .iter()
        .filter(|l| l.starts_with("    "))
        .collect();
    let source_remote = record_source_remote(original_lines);
    let old_dep_line = original_lines
        .iter()
        .find(|l| l.starts_with("  ") && !l[2..].starts_with(' ') && !l.starts_with("  remote: "));
    let our_name = spec_entry_name(spec_block.first()?)?.to_string();

    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();

    // Preconditions on the untouched lines.
    let (path_start, path_end) = find_path_section(&lines, remote_line)?;
    if !lines.iter().any(|l| l == new_dep_line) {
        return None;
    }
    {
        let (gs, ge) = record_gem_section(&lines, source_remote)?;
        (gs..ge).find(|&i| lines[i] == "  specs:")?;
    }

    // 1. Drop the PATH section (incl. its trailing blank separator).
    lines.drain(path_start..path_end);

    // 2. Spec block back into GEM/specs, sorted by entry name (bundler keeps
    // specs alphabetized; the block came out of a sorted list), in the GEM
    // section it was lifted from.
    let (gs, ge) = record_gem_section(&lines, source_remote)?;
    let specs_idx = (gs..ge).find(|&i| lines[i] == "  specs:")?;
    let mut insert_at = specs_idx + 1;
    let mut i = specs_idx + 1;
    while i < ge {
        let line = &lines[i];
        if line.is_empty() {
            break;
        }
        match spec_entry_name(line) {
            Some(n) if n > our_name.as_str() => break,
            Some(_) => {
                i += 1;
                while i < ge && lines[i].starts_with("      ") {
                    i += 1;
                }
                insert_at = i;
            }
            None => i += 1,
        }
    }
    lines.splice(
        insert_at..insert_at,
        spec_block.iter().map(|l| (*l).clone()),
    );

    // 3. DEPENDENCIES entry: restore the original line, or delete the one we
    // added for a transitive gem.
    let dep_idx = lines.iter().position(|l| l == new_dep_line)?;
    match old_dep_line {
        Some(orig) => lines[dep_idx] = orig.clone(),
        None => {
            lines.remove(dep_idx);
        }
    }

    Some(lines.join("\n"))
}

/// Find the PATH section containing exactly `remote_line` (there may be
/// several PATH sections; only ours is touched).
fn find_path_section(lines: &[String], remote_line: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(off) = lines[from..].iter().position(|l| l.as_str() == "PATH") {
        let start = from + off;
        let mut end = start + 1;
        while end < lines.len() {
            let l = &lines[end];
            if !l.is_empty() && !l.starts_with(' ') {
                break;
            }
            end += 1;
        }
        if lines[start..end].iter().any(|l| l.as_str() == remote_line) {
            return Some((start, end));
        }
        from = end;
    }
    None
}

// ── shared helpers ───────────────────────────────────────────────────────────

/// The one shared gemspec line-scanner: locate a `.{attr}` mention in `line`
/// and return what follows it (leading-whitespace-trimmed), or `None`.
///
/// `anchored` additionally requires the mention to OPEN the line as
/// `<receiver>.{attr}` with a plain-identifier receiver (`s.summary = …`,
/// `  spec.authors= …`). Anchoring makes a preceding comment marker
/// impossible, so anchored callers scan RAW lines with no comment-stripping —
/// stripping at `#` would truncate inside string literals and misjudge
/// `s.summary = "#1 Ruby web server"` as missing. A mention whose attr
/// continues as a longer identifier (`.extensions_dir`, `.authors` when
/// looking for `.author`) is never a match. Only the FIRST mention per line
/// is examined — one attribute per line is the shape `Specification#to_ruby`
/// emits. Parsing ruby for real would need a ruby.
fn attr_mention<'a>(line: &'a str, attr: &str, anchored: bool) -> Option<&'a str> {
    let needle = format!(".{attr}");
    let idx = line.find(&needle)?;
    if anchored {
        let receiver = line[..idx].trim_start();
        if receiver.is_empty()
            || !receiver
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@'))
        {
            return None;
        }
    }
    let after = &line[idx + needle.len()..];
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(after.trim_start())
}

/// Textual heuristic for `s.extensions = […]` / `spec.extensions << …` style
/// declarations (comment-stripped per line — a commented-out declaration is
/// not one; the truncation caveat in [`attr_mention`] only loses this
/// refusal's nicer error, never safety, because a match REFUSES). A miss —
/// e.g. extensions assigned through interpolation tricks — falls through,
/// which likewise only loses the nicer error.
pub(crate) fn gemspec_declares_extensions(spec_text: &str) -> bool {
    for raw in spec_text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        if let Some(after) = attr_mention(line, "extensions", false) {
            if (after.starts_with('=') && !after.starts_with("=="))
                || after.starts_with("<<")
                || after.starts_with("+=")
                || after.starts_with(".push")
                || after.starts_with(".concat")
            {
                return true;
            }
        }
    }
    false
}

/// Every RHS assigned to any of the `attrs` aliases at a line start
/// (assignments only — `==` comparisons don't count), via [`attr_mention`].
fn gemspec_attr_rhs<'a>(spec_text: &'a str, attrs: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for raw in spec_text.lines() {
        for attr in attrs {
            if let Some(after) = attr_mention(raw, attr, true) {
                if let Some(rhs) = after.strip_prefix('=') {
                    if !rhs.starts_with('=') {
                        out.push(rhs.trim());
                    }
                }
            }
        }
    }
    out
}

/// Does any line assign one of the `attrs` aliases? Pass every alias rubygems
/// accepts for the attribute (`["authors", "author"]`, `["licenses",
/// "license"]`).
fn gemspec_assigns_attr(spec_text: &str, attrs: &[&str]) -> bool {
    !gemspec_attr_rhs(spec_text, attrs).is_empty()
}

/// Textually: does this `authors` RHS collapse to NO String elements?
/// Rubygems' `authors=` writer keeps only Strings (`grep(String)`), so `[]`,
/// `nil`, `[nil]`, and empty word-arrays (`%w[]`) all yield an empty authors
/// list — the hard `authors may not be empty` error — while `[""]` keeps its
/// String and validates. Fail-open: anything not demonstrably empty passes
/// (a `[42]` would slip through, but `to_ruby` never emits one and bundler
/// still reports it — the heuristic only loses the nicer error).
fn authors_rhs_collapses_empty(rhs: &str) -> bool {
    let cleaned = rhs.replace(".freeze", "");
    let cleaned = cleaned.trim();
    let body = cleaned
        .strip_prefix("%w")
        .or_else(|| cleaned.strip_prefix("%W"))
        .unwrap_or(cleaned);
    !body
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | '(' | ')' | ','))
        .any(|tok| !tok.is_empty() && tok != "nil")
}

/// The rubygems-REQUIRED attributes a stub gemspec must assign for bundler to
/// accept it as a path source, returned as the list it is missing (empty =
/// valid). Every bundler major validates path-source gemspecs, so a stub
/// missing these bricks every later `bundle install`.
///
/// The bar is EMPIRICAL, verified against rubygems 3.3 / 3.5 / 3.6
/// (`Gem::Specification#validate`, both packaging modes, in the bundler
/// 1.17 / 2.7 / 4.0 era images):
///
/// * `summary` — hard `missing value for attribute summary` ONLY when never
///   assigned. The `summary=` writer coerces `nil`/`""` to a present value
///   (empty is at most a warning), so ANY assignment line satisfies it.
/// * `authors` — hard `authors may not be empty` when never assigned (the
///   singular `author =` alias counts) or when every assignment textually
///   collapses to no String elements ([`authors_rhs_collapses_empty`]).
///
/// A missing `licenses` is only a rubygems WARNING, deliberately not checked
/// here (callers may mention it in advisory text via
/// [`gemspec_assigns_attr`]). Fail-open by construction: only a stub that
/// demonstrably fails the bar is flagged, so a legitimate stub always passes
/// and is written byte-verbatim.
fn gemspec_missing_required_attrs(spec_text: &str) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !gemspec_assigns_attr(spec_text, &["summary"]) {
        missing.push("summary");
    }
    let author_rhs = gemspec_attr_rhs(spec_text, &["authors", "author"]);
    if author_rhs.is_empty()
        || author_rhs
            .iter()
            .all(|rhs| authors_rhs_collapses_empty(rhs))
    {
        missing.push("authors");
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::VerifyStatus;
    use crate::vendor::common::{backup_dir_for, swap_sibling_for};
    use crate::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:gem/rack@3.2.6";
    const PRISTINE: &[u8] = b"module Rack\n  VERSION = \"3.2.6\"\nend\n";
    const PATCHED: &[u8] = b"module Rack\n  SOCKET_PATCHED = true\n  VERSION = \"3.2.6\"\nend\n";

    const GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\n  s.summary = \"a modular Ruby web server interface\"\n  s.authors = [\"Rack maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    const GEMFILE_DIRECT: &str =
        "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n";
    const GEMFILE_TRANSITIVE: &str = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";

    const LOCK_DIRECT: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";
    const LOCK_TRANSITIVE: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n\nBUNDLED WITH\n   2.5.22\n";

    fn copy_rel() -> String {
        format!(".socket/vendor/gem/{UUID}/rack-3.2.6")
    }

    /// Fixture: a gem home (gems/ + specifications/ siblings), a bundler
    /// project (Gemfile + Gemfile.lock), and a blobs dir with the patched
    /// bytes. Returns (tmp, project_root, installed_dir, blobs, record).
    async fn fixture(
        gemfile: &str,
        lock: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let installed = base.join("gem_home/gems/rack-3.2.6");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/rack.rb"), PRISTINE)
            .await
            .unwrap();
        let specs = base.join("gem_home/specifications");
        tokio::fs::create_dir_all(&specs).await.unwrap();
        tokio::fs::write(specs.join("rack-3.2.6.gemspec"), GEMSPEC)
            .await
            .unwrap();

        let root = base.join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join(GEMFILE), gemfile).await.unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), lock)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE);
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = base.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "lib/rack.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, root, installed, blobs, record)
    }

    fn unwrap_done(o: VendorOutcome) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match o {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
        }
    }

    fn unwrap_refused(o: VendorOutcome) -> (&'static str, String) {
        match o {
            VendorOutcome::Refused { code, detail } => (code, detail),
            VendorOutcome::Done { result, .. } => panic!("not refused: {result:?}"),
        }
    }

    /// The download plan's gate names exactly the gems whose vendor call asks
    /// the patch service for a grant: none it refuses first (a native
    /// platform, an installed dir that is not the gem's, a non-canonical
    /// uuid), not the empty patch's no-op, and — once vendored — not the
    /// in-sync re-run.
    #[tokio::test]
    async fn service_preflight_names_exactly_the_gems_that_ask_for_a_grant() {
        use crate::vendor::test_support::{
            empty_patch, mount_no_results, plan_matches_grants, service_cfg, with_uuid, Borrowed,
            PLAN_UUID_B, PLAN_UUID_C,
        };
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let root = root.as_path();
        let server = wiremock::MockServer::start().await;
        mount_no_results(&server).await;
        let cfg = service_cfg(&server.uri(), crate::vendor::VendorSource::Service, false);
        let sources = PatchSources::blobs_only(&blobs);
        let cases = [
            (PURL, record.clone()),
            (
                "pkg:gem/rack@3.2.6?platform=x86_64-linux",
                with_uuid(&record, PLAN_UUID_B),
            ),
            (PURL, with_uuid(&record, "not-a-uuid")),
            ("pkg:gem/absent@1.0.0", with_uuid(&record, PLAN_UUID_C)),
            (PURL, empty_patch(&record, PLAN_UUID_C)),
        ];
        let installed = &installed;
        let gate = |purl: String, rec: PatchRecord| -> Borrowed<'_, bool> {
            Box::pin(async move {
                service_preflight(&purl, installed, root, &rec)
                    .await
                    .is_some()
            })
        };
        let vendor = |purl: String, rec: PatchRecord| -> Borrowed<'_, VendorOutcome> {
            let (sources, cfg) = (&sources, &cfg);
            Box::pin(async move {
                crate::vendor::test_support::vendor_gem(
                    &purl,
                    installed.as_path(),
                    root,
                    &rec,
                    sources,
                    "2026-06-09T00:00:00Z",
                    false,
                    false,
                    Some(cfg),
                )
                .await
            })
        };
        let planned = plan_matches_grants(&server, &cases, gate, vendor).await;
        assert_eq!(planned, vec![UUID.to_string()]);
        // A failed download leaves the same package eligible on retry.
        let rerun = plan_matches_grants(&server, &cases[..1], gate, vendor).await;
        assert_eq!(rerun, planned);
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        run_vendor_purl(PURL, root, blobs, installed, record, dry_run).await
    }

    /// [`run_vendor`] with a caller-chosen purl (e.g. a `?platform=` variant).
    async fn run_vendor_purl(
        purl: &str,
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            purl,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    /// Simulate the CLI caller's `persist_vendor_entry` carry-forward: fill
    /// the replacement entry's `original: None` holes from the entry being
    /// replaced, by wiring identity (file, kind, key).
    fn carry_forward_originals(prev: &VendorEntry, next: &mut VendorEntry) {
        for rec in &mut next.wiring {
            if rec.action == WiringAction::Rewritten && rec.original.is_none() {
                if let Some(p) = prev
                    .wiring
                    .iter()
                    .find(|p| p.file == rec.file && p.kind == rec.kind && p.key == rec.key)
                {
                    rec.original = p.original.clone();
                }
            }
        }
    }

    fn expected_lock_direct() -> String {
        format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            rel = copy_rel()
        )
    }

    /// #341: a `gems.rb` beside the Gemfile is the manifest bundler loads
    /// ("Multiple gemfiles ... ignoring them in favor of gems.rb"). Wiring
    /// the ignored Gemfile reported success while bundler installed the
    /// upstream gem; vendor must refuse before any write instead.
    #[tokio::test]
    async fn gems_rb_twin_is_refused_before_any_write() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("gems.rb"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join("gems.locked"), LOCK_DIRECT)
            .await
            .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("gems.rb"), "{detail}");
        for (file, want) in [
            (GEMFILE, GEMFILE_DIRECT),
            (GEMFILE_LOCK, LOCK_DIRECT),
            ("gems.rb", GEMFILE_DIRECT),
            ("gems.locked", LOCK_DIRECT),
        ] {
            assert_eq!(
                tokio::fs::read_to_string(root.join(file)).await.unwrap(),
                want
            );
        }
        assert!(!root.join(".socket/vendor").exists());
    }

    /// #390: `bundle config set --local gemfile Gemfile.next` makes bundler
    /// load `Gemfile.next` (+ `Gemfile.next.lock`); wiring `Gemfile` left the
    /// loaded manifest unpatched. Refused before any write.
    #[tokio::test]
    async fn bundle_gemfile_naming_another_manifest_is_refused() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("Gemfile.next"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join("Gemfile.next.lock"), LOCK_DIRECT)
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("Gemfile.next"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// #749: bundler 4's `bundle config set lockfile custom.lock` makes
    /// bundler read `custom.lock`, which vendored mode never wires: wiring
    /// `Gemfile.lock` would leave the lock bundler installs from untouched.
    /// Refused before any write.
    #[tokio::test]
    async fn a_bundler4_custom_lockfile_is_refused() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("custom.lock"), LOCK_DIRECT)
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_LOCKFILE: \"custom.lock\"\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("custom.lock"), "{detail}");
        assert!(
            detail.contains("bundle config unset --local lockfile"),
            "{detail}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// #1477: bundler 4's Gemfile `lockfile "custom.lock"` call makes
    /// bundler read `custom.lock` just like the setting does, so it is
    /// refused the same way, before any write.
    #[tokio::test]
    async fn a_bundler4_gemfile_lockfile_call_is_refused() {
        let gemfile = format!("lockfile \"custom.lock\"\n{GEMFILE_DIRECT}");
        let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_DIRECT).await;
        tokio::fs::write(root.join("custom.lock"), LOCK_DIRECT)
            .await
            .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_not_loaded");
        assert!(detail.contains("custom.lock"), "{detail}");
        assert!(
            detail.contains("remove the `lockfile` call from the Gemfile"),
            "{detail}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Gemfile"))
                .await
                .unwrap(),
            gemfile
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// `BUNDLE_GEMFILE` naming the project's own Gemfile beside a `gems.rb`
    /// makes bundler load the Gemfile, so vendoring wires it as usual.
    #[tokio::test]
    async fn bundle_gemfile_naming_the_gemfile_overrides_a_gems_rb_twin() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(root.join("gems.rb"), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile\"\n",
        )
        .await
        .unwrap();

        let (result, _entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("gems.rb"))
                .await
                .unwrap(),
            GEMFILE_DIRECT
        );
    }

    /// #985: on bundler 2.7+ a `gemspec` development dependency on the gem
    /// merges into a vendored `gem` line after the directive, and bundler
    /// then rejects even its own lock for the path gem under frozen mode, so
    /// vendoring refuses before any write and names the remedy. A `gem`
    /// line before the directive, or bundler < 2.7, keeps the exact pin
    /// and vendors.
    #[tokio::test]
    async fn gemspec_dev_dependency_merge_refuses_before_any_write() {
        let gemfile = "source \"https://rubygems.org\"\n\ngemspec\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n";
        let lock = LOCK_DIRECT
            .replace(
                "  puma\n  rack (~> 3.1)\n",
                "  mylib!\n  puma\n  rack (~> 3.1, >= 3)\n",
            )
            .replace("2.5.22", "2.7.2");
        let spec = "Gem::Specification.new do |s|\n  s.name = \"mylib\"\n  \
                    s.add_development_dependency \"rack\", \">= 3\"\nend\n";
        let refusal = |outcome: &VendorOutcome| match outcome {
            VendorOutcome::Refused { code, detail } => Some((*code, detail.clone())),
            _ => None,
        };

        for extra in [None, Some("other.gemspec")] {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, &lock).await;
            tokio::fs::write(root.join("mylib.gemspec"), spec)
                .await
                .unwrap();
            if let Some(extra) = extra {
                // Two gemspecs, no `name:`: what bundler loads is unknown.
                tokio::fs::write(root.join(extra), spec).await.unwrap();
            }
            let outcome = run_vendor(&root, &blobs, &installed, &record, false).await;
            let (code, detail) = refusal(&outcome).unwrap_or_else(|| panic!("{outcome:?}"));
            assert_eq!(code, "gemfile_declaration_not_editable");
            let want = if extra.is_some() {
                "cannot tell"
            } else {
                "above `gemspec`"
            };
            assert!(detail.contains(want), "{detail}");
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                lock
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
        }

        // The remedy: declared before the directive, the exact pin vendors.
        let before = "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n\ngemspec\n";
        let (_tmp, root, installed, blobs, record) = fixture(
            before,
            &lock.replace("rack (~> 3.1, >= 3)", "rack (~> 3.1)"),
        )
        .await;
        tokio::fs::write(root.join("mylib.gemspec"), spec)
            .await
            .unwrap();
        let (result, _entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(wired.contains("\n  rack (= 3.2.6)!\n"), "{wired}");

        // Bundler < 2.7 never merges.
        let (_tmp, root, installed, blobs, record) =
            fixture(gemfile, &lock.replace("2.7.2", "2.6.9")).await;
        tokio::fs::write(root.join("mylib.gemspec"), spec)
            .await
            .unwrap();
        let (result, _entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(wired.contains("\n  rack (= 3.2.6)!\n"), "{wired}");
    }

    #[tokio::test]
    async fn test_direct_dep_happy_path() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Copy patched + gemspec materialized; installed dir untouched.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            PATCHED
        );
        assert_eq!(
            tokio::fs::read_to_string(copy.join("rack.gemspec"))
                .await
                .unwrap(),
            GEMSPEC,
            "stub gemspec copied in as <name>.gemspec"
        );
        assert_eq!(
            tokio::fs::read(installed.join("lib/rack.rb"))
                .await
                .unwrap(),
            PRISTINE
        );

        // Gemfile: line rewritten in place, double quotes preserved.
        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert_eq!(
            gemfile,
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{}\"\n",
                copy_rel()
            )
        );

        // Lock: the exact bundler-canonical pair-edit form (PATH before GEM,
        // bare relative remote, spec block moved with its sublines, exact-pin
        // `!` dependency, PLATFORMS/BUNDLED WITH byte-preserved).
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(lock, expected_lock_direct());

        // Marker present in the uuid dir.
        let marker = tokio::fs::read_to_string(
            root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}")),
        )
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("\"ecosystem\": \"gem\""));

        // Ledger entry: artifact + both wiring records with verbatim text.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.ecosystem, "gem");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.wiring.len(), 2);
        let gf = &entry.wiring[0];
        assert_eq!(gf.file, GEMFILE);
        assert_eq!(gf.kind, GEMFILE_WIRING_KIND);
        assert_eq!(gf.action, WiringAction::Rewritten);
        assert_eq!(gf.key.as_deref(), Some("rack"));
        assert_eq!(
            gf.original.as_ref().unwrap(),
            &Value::String("gem \"rack\", \"~> 3.1\"".to_string())
        );
        let lk = &entry.wiring[1];
        assert_eq!(lk.file, GEMFILE_LOCK);
        assert_eq!(lk.kind, LOCK_WIRING_KIND);
        assert_eq!(lk.action, WiringAction::Rewritten);
        let orig = lk.original.as_ref().unwrap().as_array().unwrap();
        assert_eq!(
            orig,
            &vec![
                Value::String("    rack (3.2.6)".to_string()),
                Value::String("      base64 (>= 0.1.0)".to_string()),
                Value::String("  rack (~> 3.1)".to_string()),
            ],
            "spec block + old DEPENDENCIES line recorded verbatim"
        );
        let new = lk.new.as_ref().unwrap().as_array().unwrap();
        assert_eq!(
            new.last().unwrap(),
            &Value::String("  rack (= 3.2.6)!".to_string())
        );
    }

    #[tokio::test]
    async fn test_single_quote_style_preserved() {
        let gemfile = "source 'https://rubygems.org'\n\ngem 'rack', '~> 3.1'\n";
        let lock = LOCK_DIRECT
            .replace("  puma\n", "")
            .replace("    puma (6.4.2)\n      nio4r (~> 2.0)\n", "");
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, &lock).await;

        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert!(
            new_gemfile.contains(&format!("gem 'rack', '3.2.6', path: '{}'", copy_rel())),
            "single-quote style preserved: {new_gemfile}"
        );
    }

    #[tokio::test]
    async fn test_transitive_appends_managed_block_and_sorted_dep() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert_eq!(
            gemfile,
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\n{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{}\", require: false\n{MANAGED_CLOSE}\n",
                copy_rel()
            )
        );

        // DEPENDENCIES gains the pin in sorted position (after puma).
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(
            lock.contains("DEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n"),
            "sorted insert: {lock}"
        );

        let entry = entry.unwrap();
        assert_eq!(entry.wiring[0].action, WiringAction::Added);
        assert!(entry.wiring[0].original.is_none());
        // No old DEPENDENCIES line recorded → revert deletes the added one.
        let orig = entry.wiring[1]
            .original
            .as_ref()
            .unwrap()
            .as_array()
            .unwrap();
        assert!(
            orig.iter().all(|l| l.as_str().unwrap().starts_with("    ")),
            "transitive: only the spec block is recorded: {orig:?}"
        );
    }

    #[tokio::test]
    async fn test_refuses_missing_gemfile() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_file(root.join(GEMFILE)).await.unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_missing");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    #[tokio::test]
    async fn test_refuses_missing_lock() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_file(root.join(GEMFILE_LOCK))
            .await
            .unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(!root.join(".socket").exists());
    }

    /// The required-attribute heuristic ([`gemspec_missing_required_attrs`]):
    /// flag ONLY what real rubygems hard-fails on (empirically verified
    /// against rubygems 3.3/3.5/3.6, see the fn doc) — a stub rubygems
    /// tolerates must always pass, whatever its spelling.
    #[test]
    fn required_attrs_heuristic() {
        // The defective served shape: no summary, no authors.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n"
            ),
            vec!["summary", "authors"]
        );
        // A real converter/to_ruby stub: `.freeze`-d scalar + array. Valid.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |s|\n  s.summary = \"web server interface\".freeze\n  s.authors = [\"A. Person\".freeze, \"B. Person\".freeze]\nend\n"
            ),
            Vec::<&str>::new()
        );
        // Alternate spellings a valid stub may use: another block variable,
        // no space around `=`, the singular `author =` alias, %w arrays.
        assert_eq!(
            gemspec_missing_required_attrs(
                "Gem::Specification.new do |spec|\n  spec.summary=\"x\"\n  spec.author = \"A. Person\"\nend\n"
            ),
            Vec::<&str>::new()
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors = %w[alice bob]\n"),
            Vec::<&str>::new()
        );
        // A `#` inside a string literal is CONTENT, not a comment — this
        // valid stub must never be judged missing (scanning raw lines,
        // anchored to the line start, instead of comment-stripping).
        assert_eq!(
            gemspec_missing_required_attrs(
                "s.summary = \"#1 Ruby web server\".freeze\ns.authors = [\"D. #2 Person\".freeze]\n"
            ),
            Vec::<&str>::new()
        );
        // One present, one absent → only the absent one is named.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\".freeze\n"),
            vec!["authors"]
        );
        // Rubygems TOLERATES nil/empty summary (the writer coerces; empty is
        // a warning) and an empty-STRING author ([""] keeps its String), so
        // none of these flag.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"\".freeze\ns.authors = [\"\"]\n"),
            Vec::<&str>::new()
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = nil\ns.authors = [\"a\"]\n"),
            Vec::<&str>::new()
        );
        // Rubygems HARD-FAILS an authors list with no String elements
        // (`authors may not be empty`): [], nil, [nil], %w[] all flag.
        for empty_authors in ["[]", "[].freeze", "nil", "[nil]", "%w[]", "%W()"] {
            assert_eq!(
                gemspec_missing_required_attrs(&format!(
                    "s.summary = \"x\"\ns.authors = {empty_authors}\n"
                )),
                vec!["authors"],
                "authors = {empty_authors} must flag"
            );
        }
        // Commented-out assignments, `==` comparisons, and mid-line mentions
        // are not assignments.
        assert_eq!(
            gemspec_missing_required_attrs(
                "# s.summary = \"x\"\nraise if s.authors == [\"x\"]\nfoo(s.summary = \"x\")\n"
            ),
            vec!["summary", "authors"]
        );
        // Longer identifiers are not the attribute (`.authors` != `.author`).
        assert_eq!(
            gemspec_missing_required_attrs("s.summary_text = \"x\"\ns.author_email = \"x\"\n"),
            vec!["summary", "authors"]
        );
    }

    /// #2091: the remedy of an indented declaration names only ways out
    /// that work for the block it sits in, and spells the `group:` option
    /// only where one option means the same as the block.
    #[test]
    fn indented_declaration_remedy_fits_the_enclosing_block() {
        let remedy = |gemfile: &str| {
            let at = gemfile.find("gem \"rack\"").unwrap();
            let line_start = gemfile[..at].rfind('\n').map_or(0, |i| i + 1);
            indented_declaration_remedy(gemfile, line_start, "rack")
        };
        let hosted_too = ", or leave rack to hosted mode (`--mode hosted`)";
        for (gemfile, top_level) in [
            (
                "group :test do\n  gem \"rack\", \"~> 3.1\", require: false\nend\n",
                "move it to the top level with the option `group: :test`",
            ),
            // CRLF, a comment and a sibling between the header and the gem.
            (
                "group :test do\r\n  gem \"puma\"\r\n\r\n  # web\r\n  gem \"rack\"\r\nend\r\n",
                "move it to the top level with the option `group: :test`",
            ),
            (
                "group :development, :test do\n\tgem \"rack\"\nend\n",
                "move it to the top level with the option `group: [:development, :test]`",
            ),
            (
                "group(:test) do\n  gem \"rack\"\nend\n",
                "move it to the top level with the option `group: :test`",
            ),
            // No single option is sure to mean the same as these.
            (
                "group :test, optional: true do\n  gem \"rack\"\nend\n",
                "move it to the top level",
            ),
            (
                "group \"test\" do\n  gem \"rack\"\nend\n",
                "move it to the top level",
            ),
            (
                "platforms :mri do\n  gem \"rack\"\nend\n",
                "move it to the top level",
            ),
            (
                "if ENV[\"CI\"]\n  gem \"rack\"\nend\n",
                "move it to the top level",
            ),
            // Two blocks are open, however the inner one is indented.
            (
                "group :test do\nplatforms :mri do\n  gem \"rack\"\nend\nend\n",
                "move it to the top level",
            ),
            (
                "platforms :mri do\n  group :test do\n    gem \"rack\"\n  end\nend\n",
                "move it to the top level",
            ),
            // A closed block above is not the one around the gem.
            (
                "group :test do\n  gem \"puma\"\nend\n  gem \"rack\"\n",
                "write it without indentation",
            ),
        ] {
            assert_eq!(
                remedy(gemfile),
                format!("{top_level}{hosted_too}"),
                "{gemfile:?}"
            );
        }
        // Hosted mode refuses a gem inside a source-selecting block too
        // (`redirect_gem_source_option`), so it is never named there.
        for gemfile in [
            "source \"https://gems.example\" do\n  gem \"rack\"\nend\n",
            "git \"https://git.example/rack.git\" do\n  gem \"rack\"\nend\n",
            "group :test do\n  source \"https://gems.example\" do\n    gem \"rack\"\n  end\nend\n",
        ] {
            assert_eq!(
                remedy(gemfile),
                "patch rack with `--mode agent`",
                "{gemfile:?}"
            );
        }
    }

    /// #2091: a refusal that another mode does not share says so. `detail`
    /// names `--mode <m>` for exactly the modes in `modes`, so it never
    /// sends the user to a mode that refuses the gem as well.
    fn assert_names_other_modes(detail: &str, modes: &[&str]) {
        for mode in ["hosted", "agent"] {
            let named = detail.contains(&format!("`--mode {mode}`"));
            assert_eq!(
                named,
                modes.contains(&mode),
                "`--mode {mode}` named={named}: {detail}"
            );
        }
    }

    #[tokio::test]
    async fn test_refuses_native_extensions() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let spec = installed
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("specifications/rack-3.2.6.gemspec");
        tokio::fs::write(
            &spec,
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  # not this: extensions_dir = \"x\"\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "native_extensions_unsupported");
        assert!(detail.contains("native extensions"));
        assert_names_other_modes(&detail, &["hosted", "agent"]);
        assert!(!root.join(".socket").exists());
        // Neither file touched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// #2091 (review): hosted mode refuses a gem whose declaration picks
    /// its source, so the native-extension remedy names agent mode alone
    /// for it.
    #[tokio::test]
    async fn test_native_extension_remedy_skips_hosted_for_a_source_selecting_declaration() {
        for gemfile in [
            "source \"https://rubygems.org\"\n\nsource \"https://gems.example\" do\n  gem \"rack\", \"~> 3.1\"\nend\n",
            "source \"https://rubygems.org\"\n\ngem \"rack\", git: \"https://git.example/rack.git\"\n",
            "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\", :source => \"https://gems.example\"\n",
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;
            let spec = installed
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("specifications/rack-3.2.6.gemspec");
            tokio::fs::write(
                &spec,
                "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n",
            )
            .await
            .unwrap();
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert_eq!(code, "native_extensions_unsupported", "{gemfile:?}");
            assert_names_other_modes(&detail, &["agent"]);
        }
    }

    #[test]
    fn declaration_selects_source_reads_blocks_and_options() {
        for (gemfile, want) in [
            ("gem \"rack\"\n", false),
            ("gem \"rack\", \"~> 3.1\", require: false, group: :test\n", false),
            ("group :test do\n  gem \"rack\"\nend\n", false),
            // Another gem's source is not this gem's.
            ("gem \"puma\", git: \"https://git.example/puma.git\"\ngem \"rack\"\n", false),
            ("gem \"rack\" # path: \"../rack\"\n", false),
            ("gem \"rack\", path: \"../rack\"\n", true),
            ("gem \"rack\", github: \"rack/rack\"\r\n", true),
            ("gem \"rack\", :git => \"https://git.example/rack.git\"\n", true),
            ("gem \"rack\", source: \"https://gems.example\"\n", true),
            // Hosted mode refuses every source key, not only the built-in ones.
            ("gem \"rack\", gitlab: \"rack/rack\"\n", true),
            ("gem \"rack\", \"~> 3.1\", forge: \"rack/rack\"\n", true),
            ("path \"components\" do\n  gem \"rack\"\nend\n", true),
            (
                "group :test do\n  source \"https://gems.example\" do\n    gem \"rack\"\n  end\nend\n",
                true,
            ),
        ] {
            assert_eq!(declaration_selects_source(gemfile, "rack"), want, "{gemfile:?}");
        }
    }

    #[tokio::test]
    async fn test_refuses_platform_suffixed_dir() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Simulate a precompiled platform install: rack-3.2.6-x86_64-linux.
        let platform_dir = installed.parent().unwrap().join("rack-3.2.6-x86_64-linux");
        tokio::fs::rename(&installed, &platform_dir).await.unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &platform_dir, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        // Hosted mode refuses a precompiled build too, so it is not named.
        assert_names_other_modes(&detail, &["agent"]);
        assert!(!root.join(".socket").exists());
    }

    /// Fail-closed allowlist: an install dir whose name is neither the
    /// `<name>-<version>` leaf nor the legacy `gem` staging dir is refused —
    /// even though it is NOT a `<leaf>-<platform>` suffix, so a suffix-only
    /// check would admit it. Only the two legitimate dir names may pass.
    #[tokio::test]
    async fn test_refuses_unexpected_install_dir_name() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // A wholly-unexpected dir name: not `rack-3.2.6`, not `gem`, and not a
        // `rack-3.2.6-<suffix>` platform build.
        let odd_dir = installed.parent().unwrap().join("random-unrelated");
        tokio::fs::rename(&installed, &odd_dir).await.unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &odd_dir, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        assert_names_other_modes(&detail, &["agent"]);
        assert!(!root.join(".socket").exists());
    }

    /// A native `?platform=` qualifier (e.g. `x86_64-linux`) is refused as a
    /// platform-specific build EVEN when the resolved install dir is the clean
    /// portable leaf — the purl qualifier is the authoritative signal.
    #[tokio::test]
    async fn test_refuses_native_platform_qualifier() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // installed dir is the pristine `rack-3.2.6` leaf; only the purl says
        // this is a native build.
        let purl = "pkg:gem/rack@3.2.6?platform=x86_64-linux";
        let (code, detail) =
            unwrap_refused(run_vendor_purl(purl, &root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "platform_gem_unsupported");
        assert!(
            detail.contains("x86_64-linux"),
            "refusal names the offending platform: {detail}"
        );
        assert_names_other_modes(&detail, &["agent"]);
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    /// A pure-ruby gem in the legacy `gem` staging dir (still admitted, though
    /// a server download now stages at `<name>-<version>`) vendors
    /// with the purl's `?platform=ruby` (the portable default) — the staging
    /// dir name is not a platform signal.
    #[tokio::test]
    async fn test_platform_ruby_gem_from_autofetch_staging_dir_vendors() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Rename the install dir to the legacy `gem` staging leaf. The
        // sibling `specifications/rack-3.2.6.gemspec` (needed by the local
        // build) is derived from installed_dir.parent().parent(),
        // so keeping the dir under the same gem_home preserves it.
        let staged = installed.parent().unwrap().join("gem");
        tokio::fs::rename(&installed, &staged).await.unwrap();

        let purl = "pkg:gem/rack@3.2.6?platform=ruby";
        let (result, _entry, _w) =
            unwrap_done(run_vendor_purl(purl, &root, &blobs, &staged, &record, false).await);
        assert!(
            result.success,
            "pure-ruby (?platform=ruby) gem from an auto-fetch `gem` staging dir must vendor: {:?}",
            result.error
        );
        // The patched copy landed under the leaf, not the staging dir name.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            PATCHED
        );
    }

    #[tokio::test]
    async fn test_refuses_unparseable_declaration() {
        // (a) indented inside a group block
        let grouped =
            "source \"https://rubygems.org\"\n\ngroup :test do\n  gem \"rack\", \"~> 3.1\"\nend\n";
        let (_tmp, root, installed, blobs, record) = fixture(grouped, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("indented"), "{detail}");
        // #2091: both ways out are named, the first with the block's option.
        assert!(
            detail.contains("move it to the top level with the option `group: :test`"),
            "names the top-level `group:` form: {detail}"
        );
        assert_names_other_modes(&detail, &["hosted"]);
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            grouped
        );

        // (b) multi-line declaration (trailing comma continuation)
        let multiline = "source \"https://rubygems.org\"\n\ngem \"rack\",\n  \"~> 3.1\"\n";
        let (_tmp2, root2, installed2, blobs2, record2) = fixture(multiline, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root2, &blobs2, &installed2, &record2, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("continues"), "{detail}");

        // (c) already path-sourced (a previous run / a user fork)
        let pathed = "source \"https://rubygems.org\"\n\ngem \"rack\", path: \"../rack-fork\"\n";
        let (_tmp3, root3, installed3, blobs3, record3) = fixture(pathed, LOCK_DIRECT).await;
        let (code, detail) =
            unwrap_refused(run_vendor(&root3, &blobs3, &installed3, &record3, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("path:"), "{detail}");
    }

    /// #1761: a dry run raises the same declaration refusal as the wet run,
    /// so a `vendor` eject preview does not report a refused gem as planned.
    #[tokio::test]
    async fn test_dry_run_previews_declaration_refusal() {
        let grouped =
            "source \"https://rubygems.org\"\n\ngroup :test do\n  gem \"rack\", \"~> 3.1\"\nend\n";
        for dry_run in [true, false] {
            let (_tmp, root, installed, blobs, record) = fixture(grouped, LOCK_DIRECT).await;
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, dry_run).await);
            assert_eq!(
                code, "gemfile_declaration_not_editable",
                "dry_run={dry_run}"
            );
            assert!(detail.contains("indented"), "dry_run={dry_run}: {detail}");
            assert!(!root.join(".socket").exists(), "dry_run={dry_run}");
        }
    }

    /// SECURITY: a traversal uuid (tampered manifest) must be refused before
    /// any disk access.
    #[tokio::test]
    async fn test_refuses_traversal_uuid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let mut bad = record.clone();
        bad.uuid = "../../escape".to_string();

        let (code, _d) = unwrap_refused(run_vendor(&root, &blobs, &installed, &bad, false).await);
        assert_eq!(code, "unsafe_coordinates");
        assert!(!root.join(".socket").exists());
        assert!(!root.parent().unwrap().join("escape").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn test_empty_gem_specs_stanza_kept() {
        // The vendored gem is the ONLY entry: the GEM section must keep its
        // empty `specs:` stanza (that is the form bundler regenerates).
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n";
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, lock).await;

        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            new_lock,
            format!(
                "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
                rel = copy_rel()
            )
        );
    }

    #[tokio::test]
    async fn test_idempotent_rerun_in_sync() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(r2.files_patched.is_empty(), "in-sync rerun patches nothing");
        assert!(
            r2.files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "synthesized AlreadyPatched: {:?}",
            r2.files_verified
        );
        assert!(
            e2.is_none(),
            "hot path must not re-record (would clobber the originals in the ledger)"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// Wired Gemfile+lock with a deleted committed copy: the artifact (and
    /// its stub gemspec) is rebuilt, the pair stays byte-identical, no entry.
    #[tokio::test]
    async fn test_wired_missing_copy_rebuilds_artifact_only() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6"));
        assert!(copy_root.exists());

        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let (r2, e2, w2) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        // Artifact-only rebuild: a refreshed fingerprint with NO wiring of
        // its own (re-recording the live pair edit as `original` would
        // break --revert; the caller carries the first run's records).
        let e2 = e2.expect("the rebuild refreshes the ledger fingerprint");
        assert!(
            e2.wiring.is_empty(),
            "no re-recorded wiring: {:?}",
            e2.wiring
        );
        assert!(
            e2.artifact.file_inventory.is_some(),
            "rebuilt tree inventoried"
        );
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w2:?}"
        );
        assert!(
            copy_root.join("rack.gemspec").exists(),
            "stub gemspec regenerated with the rebuilt copy"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no copy created");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn test_unwind_on_lock_edit_failure() {
        // The lock lists rack@3.2.6 under two sources, which the lock edit
        // refuses to guess between: it fails AFTER the Gemfile was
        // rewritten, so vendor must unwind the Gemfile to its original
        // bytes and drop the copy.
        let lock = format!(
            "GEM\n  remote: https://gems.example.com/\n  specs:\n    rack (3.2.6)\n\n{LOCK_DIRECT}"
        );
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Gemfile.lock"));
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile unwound to its original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "lock untouched"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "half-built copy removed"
        );
    }

    /// #2075: the installed rack 3.2.6 is a version the lock doesn't
    /// resolve (it resolves 3.1.0; another project put 3.2.6 in the shared
    /// gem home). There is no entry to move into a PATH section, so the
    /// gem is refused as the skip `vendor_gem_version_not_locked`, dry run
    /// or not, with nothing written. It used to fail the lock edit.
    #[tokio::test]
    async fn version_the_lock_does_not_resolve_is_refused_untouched() {
        let lock = LOCK_DIRECT.replace("    rack (3.2.6)", "    rack (3.1.0)");
        for (lock, dry_run) in [
            (lock.clone(), false),
            (lock.clone(), true),
            (lock.replace('\n', "\r\n"), false),
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, &lock).await;
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, dry_run).await);
            assert_eq!(code, GEM_VERSION_NOT_LOCKED);
            assert!(
                detail.contains("Gemfile.lock does not resolve rack 3.2.6"),
                "{detail}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                GEMFILE_DIRECT
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                lock
            );
            assert!(!root.join(".socket/vendor").exists());
        }
    }

    #[tokio::test]
    async fn test_revert_round_trip_direct() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile byte-identical to the fixture"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock byte-identical to the fixture"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_transitive() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE,
            "managed block deleted, Gemfile byte-identical"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE,
            "spec block moved back, added DEPENDENCIES entry deleted"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// #988: a comment the user appended to the wired Gemfile line keeps the
    /// line ours. Vendor's in-sync check already reads it as wired, so revert
    /// must too: both files go back to the registry form, the user's comment
    /// survives on the restored line, and the artifact is removed.
    #[tokio::test]
    async fn revert_commented_gemfile_line_restores_both_files() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        let wired_line = format!("gem \"rack\", \"3.2.6\", path: \"{}\"", copy_rel());
        assert!(wired.contains(&format!("{wired_line}\n")), "{wired}");
        let annotated = wired.replace(
            &wired_line,
            &format!("{wired_line}  # CVE fix, do not bump"),
        );
        tokio::fs::write(root.join(GEMFILE), &annotated)
            .await
            .unwrap();

        // Vendor still reads the annotated line as wired.
        let (rerun, rerun_entry, _) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(rerun.success, "{:?}", rerun.error);
        assert!(rerun_entry.is_none(), "in sync: no new entry");

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "an annotated wired line is not drift: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT.replace(
                "gem \"rack\", \"~> 3.1\"\n",
                "gem \"rack\", \"~> 3.1\"  # CVE fix, do not bump\n"
            ),
            "registry declaration restored, the user's comment kept"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// #988: a comment vendor carried over from the original line, then
    /// edited by the user, is replaced by the user's version on revert;
    /// an untouched carried comment restores the original line verbatim.
    #[tokio::test]
    async fn revert_edited_carried_comment_keeps_the_users_comment() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\", require: false # pinned\n";
        for (edit, expected_line) in [
            (None, "gem \"rack\", \"~> 3.1\", require: false # pinned"),
            (
                Some("# pinned for CVE-2026-1"),
                "gem \"rack\", \"~> 3.1\", require: false # pinned for CVE-2026-1",
            ),
            (Some(""), "gem \"rack\", \"~> 3.1\", require: false"),
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;
            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{:?}", result.error);
            let entry = entry.unwrap();
            let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
            assert!(wired.contains("require: false # pinned\n"), "{wired}");
            if let Some(comment) = edit {
                let edited = if comment.is_empty() {
                    wired.replace(" # pinned\n", "\n")
                } else {
                    wired.replace("# pinned\n", &format!("{comment}\n"))
                };
                assert_ne!(edited, wired);
                tokio::fs::write(root.join(GEMFILE), &edited).await.unwrap();
            }

            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "{edit:?}: {:?}", outcome.error);
            assert!(
                outcome.warnings.is_empty(),
                "{edit:?}: {:?}",
                outcome.warnings
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile.replace(
                    "gem \"rack\", \"~> 3.1\", require: false # pinned",
                    expected_line
                ),
                "{edit:?}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_DIRECT,
                "{edit:?}"
            );
        }
    }

    /// #988: a CRLF Gemfile whose wired line gained a comment restores the
    /// original line's CRLF ending.
    #[tokio::test]
    async fn revert_commented_gemfile_line_keeps_crlf() {
        let gemfile = GEMFILE_DIRECT.replace('\n', "\r\n");
        let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_DIRECT).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        let wired_line = format!("gem \"rack\", \"3.2.6\", path: \"{}\"\r\n", copy_rel());
        assert!(wired.contains(&wired_line), "{wired:?}");
        let annotated = wired.replace(&wired_line, &wired_line.replace("\r\n", " # keep\r\n"));
        tokio::fs::write(root.join(GEMFILE), &annotated)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile.replace(
                "gem \"rack\", \"~> 3.1\"\r\n",
                "gem \"rack\", \"~> 3.1\" # keep\r\n"
            )
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// Whether every line break in `text` is CRLF (and no CR stands alone).
    fn all_crlf(text: &str) -> bool {
        let crlf = text.matches("\r\n").count();
        crlf > 0 && crlf == text.matches('\n').count() && crlf == text.matches('\r').count()
    }

    /// #1821: the restored line keeps the original's ending unless a
    /// re-checkout changed the wired line's ending since vendor wrote it.
    /// A ledger from before #1821 recorded a bare-LF wired line beside a
    /// CRLF original; that line, untouched, still restores CRLF.
    #[test]
    fn restore_gemfile_line_ending() {
        for (live, written, original, want) in [
            ("new", "new", "orig\r", "orig\r"),
            ("new\r", "new\r", "orig\r", "orig\r"),
            ("new", "new", "orig", "orig"),
            ("new\r", "new", "orig", "orig\r"),
            ("new", "new\r", "orig\r", "orig"),
        ] {
            assert_eq!(
                restore_gemfile_line(live, written, original),
                want,
                "{live:?} {written:?} {original:?}"
            );
        }
    }

    /// #1821: vendoring over a CRLF Gemfile keeps it CRLF, for the rewired
    /// direct declaration and for the appended managed block alike, and the
    /// revert hands the file back byte for byte.
    #[tokio::test]
    async fn vendor_keeps_a_crlf_gemfile_crlf() {
        for (gemfile, lock, expected_line) in [
            (
                GEMFILE_DIRECT,
                LOCK_DIRECT,
                format!("gem \"rack\", \"3.2.6\", path: \"{}\"\r\n", copy_rel()),
            ),
            (
                GEMFILE_TRANSITIVE,
                LOCK_TRANSITIVE,
                format!(
                    "{MANAGED_OPEN}\r\ngem \"rack\", \"3.2.6\", path: \"{}\", require: false\r\n{MANAGED_CLOSE}\r\n",
                    copy_rel()
                ),
            ),
        ] {
            let gemfile = gemfile.replace('\n', "\r\n");
            let (_tmp, root, installed, blobs, record) = fixture(&gemfile, lock).await;
            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{:?}", result.error);
            let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
            assert!(all_crlf(&wired), "mixed line endings: {wired:?}");
            assert!(wired.contains(&expected_line), "{wired:?}");

            let outcome = revert_gem(&entry.unwrap(), &root, false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
        }
    }

    /// #1821: a trailing option or comment on the rewired line keeps the
    /// CR in one place, the end of the line.
    #[test]
    fn plan_gemfile_edit_keeps_the_lines_crlf() {
        for (line, want) in [
            (
                "gem \"rack\", \"~> 3.1\"\r",
                "gem \"rack\", \"3.2.6\", path: \"p\"\r",
            ),
            (
                "gem \"rack\", \"~> 3.1\", require: false\r",
                "gem \"rack\", \"3.2.6\", path: \"p\", require: false\r",
            ),
            (
                "gem \"rack\", \"~> 3.1\", require: false # pinned\r",
                "gem \"rack\", \"3.2.6\", path: \"p\", require: false # pinned\r",
            ),
            ("gem \"rack\"\r", "gem \"rack\", \"3.2.6\", path: \"p\"\r"),
        ] {
            let text = format!("source \"https://rubygems.org\"\r\n{line}\n");
            let Ok(GemfilePlan::Rewrite { new_line, .. }) =
                plan_gemfile_edit(&text, "rack", "3.2.6", "p")
            else {
                panic!("{line:?} should rewrite");
            };
            assert_eq!(new_line, want, "{line:?}");
        }
    }

    /// #1821: re-vendoring a new patch uuid over a CRLF Gemfile's managed
    /// block still finds the fence, records the whole block as written, and
    /// a revert deletes the fence.
    #[tokio::test]
    async fn revendor_crlf_managed_block_keeps_the_fence() {
        let gemfile = GEMFILE_TRANSITIVE.replace('\n', "\r\n");
        let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "{:?}", r2.error);

        let new_block = format!(
            "{MANAGED_OPEN}\r\ngem \"rack\", \"3.2.6\", path: \".socket/vendor/gem/{UUID2}/rack-3.2.6\", require: false\r\n{MANAGED_CLOSE}\r\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!("{gemfile}{new_block}")
        );
        let mut entry2 = e2.unwrap();
        assert_eq!(entry2.wiring[0].action, WiringAction::Added);
        assert_eq!(
            entry2.wiring[0].new.as_ref().unwrap(),
            &Value::String(new_block)
        );

        carry_forward_originals(&e1.unwrap(), &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// #1821: a vendored Gemfile re-checked-out in the other line-ending
    /// style (`core.autocrlf`) reverts to the original in the style it has
    /// now, never a mix of the two.
    #[tokio::test]
    async fn revert_follows_a_recheckout_line_ending_change() {
        for (gemfile, lock) in [
            (GEMFILE_DIRECT, LOCK_DIRECT),
            (GEMFILE_TRANSITIVE, LOCK_TRANSITIVE),
        ] {
            for (vendored_nl, checkout_nl) in [("\n", "\r\n"), ("\r\n", "\n")] {
                let at_vendor = gemfile.replace('\n', vendored_nl);
                let (_tmp, root, installed, blobs, record) = fixture(&at_vendor, lock).await;
                let (result, entry, _w) =
                    unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
                assert!(result.success, "{:?}", result.error);
                let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
                let recheckout = crate::utils::line_endings::respell(&wired, checkout_nl);
                assert_ne!(recheckout, wired);
                tokio::fs::write(root.join(GEMFILE), &recheckout)
                    .await
                    .unwrap();

                let outcome = revert_gem(&entry.unwrap(), &root, false).await;
                assert!(outcome.success, "{vendored_nl:?}: {:?}", outcome.error);
                assert!(
                    outcome.warnings.is_empty(),
                    "{vendored_nl:?}: {:?}",
                    outcome.warnings
                );
                assert_eq!(
                    tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                    gemfile.replace('\n', checkout_nl),
                    "{gemfile:?} vendored with {vendored_nl:?}"
                );
            }
        }
    }

    /// #988: genuine Gemfile drift (the `path:` now points at a user fork)
    /// leaves BOTH files byte-identical and keeps the artifact. Reverting
    /// the lock alone would pair a Gemfile `path:` with a rubygems.org lock,
    /// which `bundle install --frozen` refuses. A second revert does the same.
    #[tokio::test]
    async fn revert_drifted_gemfile_line_writes_neither_file() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        let drifted = wired.replace(&copy_rel(), "../forks/rack");
        assert_ne!(drifted, wired);
        tokio::fs::write(root.join(GEMFILE), &drifted)
            .await
            .unwrap();
        let wired_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();

        for pass in 0..2 {
            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "pass {pass}: {:?}", outcome.error);
            assert!(
                outcome.drift_skipped(),
                "pass {pass}: {:?}",
                outcome.warnings
            );
            assert!(outcome.kept_artifact, "pass {pass}");
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                drifted,
                "pass {pass}: Gemfile untouched"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                wired_lock,
                "pass {pass}: no half-revert of the lock"
            );
            assert!(root.join(copy_rel()).exists(), "pass {pass}");
        }
    }

    /// The Gemfile still routes the gem through the copy, but in a form
    /// revert won't rewrite (an option added to the wired line, or a
    /// comment added inside the managed block): drift, and neither file is
    /// written, so the user's edit is never dropped and the lock never
    /// leaves the Gemfile's `path:` behind.
    #[tokio::test]
    async fn revert_still_wired_but_edited_gemfile_writes_neither_file() {
        let rack_line = format!("gem \"rack\", \"3.2.6\", path: \"{}\"", copy_rel());
        let cases = [
            (
                GEMFILE_DIRECT,
                LOCK_DIRECT,
                format!("{rack_line}, require: false"),
            ),
            (
                GEMFILE_TRANSITIVE,
                LOCK_TRANSITIVE,
                format!("{rack_line} # managed, keep"),
            ),
        ];
        for (gemfile, lock, edited_line) in cases {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, lock).await;
            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{:?}", result.error);
            let entry = entry.unwrap();
            let wired = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
            let edited = wired.replace(&rack_line, &edited_line);
            assert_ne!(edited, wired, "{edited_line}");
            tokio::fs::write(root.join(GEMFILE), &edited).await.unwrap();
            let wired_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap();

            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "{edited_line}: {:?}", outcome.error);
            assert!(
                outcome.drift_skipped(),
                "{edited_line}: {:?}",
                outcome.warnings
            );
            assert!(outcome.kept_artifact, "{edited_line}");
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                edited,
                "{edited_line}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                wired_lock,
                "{edited_line}"
            );
            assert!(root.join(copy_rel()).exists(), "{edited_line}");
        }
    }

    /// The user already put the gem back on the registry by hand, with a
    /// different constraint than the original: the Gemfile no longer routes
    /// through the copy, so that record has converged and the lock is
    /// restored to match it instead of being kept on the PATH section.
    #[tokio::test]
    async fn revert_hand_restored_gemfile_converges_and_restores_lock() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        let hand = GEMFILE_DIRECT.replace("\"~> 3.1\"", "\"~> 3.2\"  # restored");
        tokio::fs::write(root.join(GEMFILE), &hand).await.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            hand
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// A `bundle update` regenerated both files back to their pre-vendor
    /// registry form: that is CONVERGENCE (the reverted state is already on
    /// disk), not drift — revert stays silent (LIVENESS CONTRACT), leaves the
    /// files alone and still removes the artifact dir, so the entry can never
    /// wedge in the ledger forever.
    #[tokio::test]
    async fn test_revert_converged_files_are_silent_and_still_remove() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        tokio::fs::write(root.join(GEMFILE), GEMFILE_DIRECT)
            .await
            .unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), LOCK_DIRECT)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "regenerated pre-vendor files are convergence, not drift: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "uuid dir still removed"
        );
    }

    // ── bundler ≥ 2.6 CHECKSUMS (spike: gemChecksums, bundler 2.7.2) ─────────

    const PURL_318: &str = "pkg:gem/rack@3.1.8";
    const PRISTINE_318: &[u8] = b"module Rack\n  VERSION = \"3.1.8\"\nend\n";
    const PATCHED_318: &[u8] =
        b"module Rack\n  SOCKET_PATCHED = true\n  VERSION = \"3.1.8\"\nend\n";
    const GEMSPEC_318: &str = "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.1.8\"\n  s.summary = \"a modular Ruby web server interface\"\n  s.authors = [\"Rack maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    // Embedded VERBATIM from a captured before/after pair (bundler
    // 2.7.2, ruby 3.3.11, aarch64-linux; the `after` lock was written by
    // bundler itself via `bundle lock`, never by hand), verified exactly this
    // pair byte-stable under `bundle install`, `BUNDLE_FROZEN=true bundle
    // install` and a from-scratch `bundle lock`.
    const SPIKE_GEMFILE_CHECKSUMS: &str =
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"3.1.8\"\n";
    const SPIKE_RACK_SHA_LINE: &str =
        "  rack (3.1.8) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1";
    const SPIKE_LOCK_CHECKSUMS_BEFORE: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.8)\n\nCHECKSUMS\n  rack (3.1.8) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1\n\nBUNDLED WITH\n   2.7.2\n";
    const SPIKE_LOCK_CHECKSUMS_AFTER: &str = "PATH\n  remote: vendored/rack-3.1.8\n  specs:\n    rack (3.1.8)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  rack (= 3.1.8)!\n\nCHECKSUMS\n  rack (3.1.8)\n\nBUNDLED WITH\n   2.7.2\n";

    fn copy_rel_318() -> String {
        format!(".socket/vendor/gem/{UUID}/rack-3.1.8")
    }

    /// The spike `after` lock byte-for-byte, except the PATH remote points
    /// into `.socket/vendor/` instead of the spike's hand-placed `vendored/`
    /// dir — the only divergence; everything else (including the bare
    /// CHECKSUMS entry) must match bundler's own output exactly for the lock
    /// to stay byte-stable under re-lock.
    fn expected_lock_checksums() -> String {
        SPIKE_LOCK_CHECKSUMS_AFTER.replace(
            "  remote: vendored/rack-3.1.8\n",
            &format!("  remote: {}\n", copy_rel_318()),
        )
    }

    /// rack-3.1.8 twin of [`fixture`] (the CHECKSUMS spike pinned that exact
    /// version, so the oracles can embed the spike locks verbatim).
    async fn fixture_318(
        gemfile: &str,
        lock: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let installed = base.join("gem_home/gems/rack-3.1.8");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/rack.rb"), PRISTINE_318)
            .await
            .unwrap();
        let specs = base.join("gem_home/specifications");
        tokio::fs::create_dir_all(&specs).await.unwrap();
        tokio::fs::write(specs.join("rack-3.1.8.gemspec"), GEMSPEC_318)
            .await
            .unwrap();

        let root = base.join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join(GEMFILE), gemfile).await.unwrap();
        tokio::fs::write(root.join(GEMFILE_LOCK), lock)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE_318);
        let after = compute_git_sha256_from_bytes(PATCHED_318);
        let blobs = base.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED_318)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "lib/rack.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, root, installed, blobs, record)
    }

    async fn run_vendor_318(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            PURL_318,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_checksums_direct_vendor_matches_spike_pair() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Lock: bundler's own path-gem output (spike G3 pair) byte-for-byte,
        // modulo the PATH remote value.
        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(lock, expected_lock_checksums());

        // Ledger: the checksum rewrite is its own third record with the
        // verbatim registry line as original and the bare form as new.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.wiring.len(), 3);
        let ck = &entry.wiring[2];
        assert_eq!(ck.file, GEMFILE_LOCK);
        assert_eq!(ck.kind, LOCK_CHECKSUM_WIRING_KIND);
        assert_eq!(ck.action, WiringAction::Rewritten);
        assert_eq!(ck.key.as_deref(), Some("rack"));
        assert_eq!(
            ck.original.as_ref().unwrap(),
            &Value::String(SPIKE_RACK_SHA_LINE.to_string())
        );
        assert_eq!(
            ck.new.as_ref().unwrap(),
            &Value::String("  rack (3.1.8)".to_string())
        );
        // The positional gemfile_lock_spec record must NOT have absorbed the
        // checksum line (its revert parses original/new by position).
        let spec = &entry.wiring[1];
        assert!(
            !spec
                .original
                .as_ref()
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l.as_str().unwrap().contains("sha256=")),
            "checksum line must not leak into gemfile_lock_spec: {:?}",
            spec.original
        );
    }

    #[tokio::test]
    async fn test_checksums_transitive_vendor_strips_only_our_token() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let puma_sha_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n{puma_sha_line}\n{SPIKE_RACK_SHA_LINE}\n\nBUNDLED WITH\n   2.7.2\n"
        );
        let (_tmp, root, installed, blobs, record) = fixture_318(gemfile, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        // Full oracle: rack moved to PATH + sorted `!` dep + bare CHECKSUMS
        // entry; puma's checksum line is byte-untouched.
        let new_lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            new_lock,
            format!(
                "PATH\n  remote: {rel}\n  specs:\n    rack (3.1.8)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.1.8)!\n\nCHECKSUMS\n{puma_sha_line}\n  rack (3.1.8)\n\nBUNDLED WITH\n   2.7.2\n",
                rel = copy_rel_318()
            )
        );

        // Revert restores both files byte-exactly (added dep deleted, managed
        // block removed, registry checksum line back).
        let entry = entry.unwrap();
        assert_eq!(entry.wiring.len(), 3);
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock
        );
    }

    #[tokio::test]
    async fn test_checksums_revert_round_trip() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        // Byte-exact restore — the registry sha256 token is back (a bare
        // CHECKSUMS entry on a registry gem fails frozen installs, exit 16).
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_checksums_idempotent_rerun_in_sync() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        // The bare CHECKSUMS entry counts as in-sync: the rerun takes the hot
        // path and records nothing.
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(e2.is_none(), "hot path must not re-record");
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// #1808: a CRLF lock (a Git for Windows `autocrlf` checkout; bundler
    /// keeps CRLF) is edited in its own line ending — the dry run and the
    /// wet run both succeed — and a revert hands it back byte for byte.
    #[tokio::test]
    async fn crlf_lock_vendors_in_crlf_and_reverts_byte_exact() {
        let cases = [
            (GEMFILE_DIRECT, LOCK_DIRECT, Some(expected_lock_direct())),
            (GEMFILE_TRANSITIVE, LOCK_TRANSITIVE, None),
        ];
        for (gemfile, lf_lock, expected_lf) in cases {
            let crlf = lf_lock.replace('\n', "\r\n");
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, &crlf).await;

            let (dry, _, _) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, true).await);
            assert!(dry.success, "dry run: {:?}", dry.error);
            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "vendor: {:?}", result.error);
            let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap();
            assert_eq!(
                wired.matches('\n').count(),
                wired.matches("\r\n").count(),
                "every line keeps CRLF: {wired:?}"
            );
            if let Some(expected) = expected_lf {
                assert_eq!(wired, expected.replace('\n', "\r\n"));
            }
            // The ledger records bare lines, as for an LF lock.
            let entry = entry.unwrap();
            let lk = entry
                .wiring
                .iter()
                .find(|w| w.kind == LOCK_WIRING_KIND)
                .unwrap();
            assert!(
                !lk.new.as_ref().unwrap().to_string().contains("\\r"),
                "{:?}",
                lk.new
            );

            // The in-sync hot path recognises the CRLF wiring.
            let (rerun, again, _) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(rerun.success, "{:?}", rerun.error);
            assert!(again.is_none(), "hot path must not re-record");
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                wired
            );

            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(
                !outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "{:?}",
                outcome.warnings
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                crlf,
                "lock byte-identical to the CRLF fixture"
            );
        }
    }

    /// #1808: a CRLF bundler >= 2.6 lock — the CHECKSUMS rewrite and its
    /// revert keep CRLF too.
    #[tokio::test]
    async fn crlf_checksums_lock_vendors_and_reverts_byte_exact() {
        let crlf = SPIKE_LOCK_CHECKSUMS_BEFORE.replace('\n', "\r\n");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &crlf).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert!(
            wired.contains("\r\nCHECKSUMS\r\n  rack (3.1.8)\r\n"),
            "{wired:?}"
        );
        assert_eq!(wired.matches('\n').count(), wired.matches("\r\n").count());

        let (rerun, again, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(rerun.success, "{:?}", rerun.error);
        assert!(again.is_none(), "hot path must not re-record");

        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            crlf
        );
    }

    /// A lock mixing CRLF and LF has no one line ending to write the edit
    /// back in: vendor fails closed (dry run too) and writes nothing.
    #[tokio::test]
    async fn mixed_line_ending_lock_fails_closed() {
        let mixed = LOCK_DIRECT.replacen('\n', "\r\n", 3);
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, &mixed).await;
        for dry_run in [true, false] {
            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, dry_run).await);
            assert!(!result.success, "dry_run={dry_run}");
            assert!(entry.is_none());
            let err = result.error.unwrap_or_default();
            assert!(err.contains("mixes CRLF and LF"), "{err}");
        }
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            mixed
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
    }

    #[tokio::test]
    async fn test_checksums_already_bare_records_nothing() {
        // Spike `bare-checksum-registry-gem/before`: a registry-sourced lock
        // whose CHECKSUMS entry is already the bare form. Vendor must not
        // record our own target form as an "original" — reverting it later
        // would NOT be a restore (and per the spike a bare entry is exactly
        // what the path form needs anyway).
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8)");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            entry.wiring.len(),
            2,
            "already-bare entry must not produce a checksum record: {:?}",
            entry.wiring
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums(),
            "the bare line is kept verbatim"
        );
    }

    #[tokio::test]
    async fn test_checksums_absent_entry_untouched() {
        // CHECKSUMS section present but no entry for our gem: bundler
        // tolerates absent entries, so vendor touches nothing there.
        let other_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, other_line);
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            entry.unwrap().wiring.len(),
            2,
            "no checksum record for an absent entry"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums().replace(
                "  rack (3.1.8)\n\nBUNDLED",
                &format!("{other_line}\n\nBUNDLED")
            ),
            "the foreign entry is byte-untouched"
        );
    }

    #[tokio::test]
    async fn test_checksums_unparseable_entry_unwinds() {
        // A CHECKSUMS line that names our gem but breaks the entry grammar
        // (lost closing paren) fails closed AFTER the Gemfile was rewritten:
        // the pair-edit unwind must restore the Gemfile bytes.
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE
            .replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8 sha256=deadbeef");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("CHECKSUMS") && err.contains("not parseable"),
            "{err}"
        );
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS,
            "Gemfile unwound to its original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "lock untouched"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_checksums_platform_sibling_fails_closed() {
        // vendor_gem refuses platform-suffixed INSTALL dirs before the lock
        // edit, so a platform-suffixed CHECKSUMS sibling means the lock
        // disagrees with the installed tree — never guess which entries
        // bundler would collapse; fail closed and unwind.
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(
            SPIKE_RACK_SHA_LINE,
            &format!("{SPIKE_RACK_SHA_LINE}\n  rack (3.1.8-aarch64-linux) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1"),
        );
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("platform-specific"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS,
            "Gemfile unwound"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[test]
    fn test_checksums_duplicate_entries_fail_closed() {
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(
            SPIKE_RACK_SHA_LINE,
            &format!("{SPIKE_RACK_SHA_LINE}\n{SPIKE_RACK_SHA_LINE}"),
        );
        let err = match edit_lock(&lock, "rack", "3.1.8", &copy_rel_318()) {
            Err(e) => e,
            Ok(_) => panic!("duplicate CHECKSUMS entries must fail closed"),
        };
        assert!(err.contains("more than one entry"), "{err}");
    }

    #[test]
    fn test_no_checksums_lock_records_no_checksum_wiring() {
        // A lock WITHOUT a CHECKSUMS section must keep producing
        // the exact pre-CHECKSUMS output and no checksum record.
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        assert!(edit.checksum_rewrites.is_empty());
        assert_eq!(edit.text, expected_lock_direct());
    }

    #[tokio::test]
    async fn test_checksums_revert_drift_warning() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift on ONLY the checksum line (someone hand-restored
        // a token): revert must leave that line alone with a warning, never
        // clobber it, and writes nothing else either (#988: all-or-nothing).
        let drifted_line = "  rack (3.1.8) sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let wired_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let edited = wired.replace(
            "\nCHECKSUMS\n  rack (3.1.8)\n",
            &format!("\nCHECKSUMS\n{drifted_line}\n"),
        );
        assert_ne!(edited, wired, "fixture edit must hit the bare line");
        tokio::fs::write(root.join(GEMFILE_LOCK), &edited)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift_count = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(
            drift_count, 1,
            "exactly the checksum record drifts: {:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "genuine drift keeps the artifact (and the ledger entry): {:?}",
            outcome.warnings
        );
        assert!(
            root.join(copy_rel_318()).exists(),
            "the copy dir survives a drift-keep"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            edited,
            "the lock is left exactly as found, drifted checksum line included"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            wired_gemfile,
            "the Gemfile keeps its `path:` wiring alongside the unreverted lock"
        );
    }

    #[tokio::test]
    async fn test_stale_checksum_rerun_refused_with_guidance() {
        // A lock wired by a pre-CHECKSUMS-aware socket-patch: PATH wiring in
        // place but the registry sha256 token still on the CHECKSUMS line
        // (the spike's stale-checksum-v1-bug shape — bundler itself never
        // repairs it). The rerun must NOT report in-sync, and must refuse
        // with the revert+re-vendor repair path rather than silently editing
        // a lock it has no ledger entry for.
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, _e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let v1 = wired.replace(
            "\nCHECKSUMS\n  rack (3.1.8)\n",
            &format!("\nCHECKSUMS\n{SPIKE_RACK_SHA_LINE}\n"),
        );
        assert_ne!(v1, wired, "fixture edit must hit the bare line");
        tokio::fs::write(root.join(GEMFILE_LOCK), &v1)
            .await
            .unwrap();
        let gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_stale_lock_checksum");
        assert!(detail.contains("vendor --revert"), "{detail}");
        // The refusal mutates nothing.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            v1
        );
    }

    // ── multiple vendored gems: PATH sections sort like bundler's ────────────

    /// Second gem for multi-PATH tests. Its uuid sorts BEFORE rack's
    /// (`1a…` < `9f…`), so vendoring rack first is the order a naive
    /// insert-before-GEM splice would leave unsorted.
    const UUID_PUMA: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
    const PURL_PUMA: &str = "pkg:gem/puma@6.4.2";
    const PRISTINE_PUMA: &[u8] = b"module Puma\n  VERSION = \"6.4.2\"\nend\n";
    const PATCHED_PUMA: &[u8] =
        b"module Puma\n  SOCKET_PATCHED = true\n  VERSION = \"6.4.2\"\nend\n";
    const GEMSPEC_PUMA: &str = "Gem::Specification.new do |s|\n  s.name = \"puma\"\n  s.version = \"6.4.2\"\n  s.summary = \"a fast, concurrent web server\"\n  s.authors = [\"Puma maintainers\"]\n  s.require_paths = [\"lib\"]\nend\n";

    fn puma_rel() -> String {
        format!(".socket/vendor/gem/{UUID_PUMA}/puma-6.4.2")
    }

    /// Add a puma install + blob + record alongside [`fixture`]'s rack, so a
    /// test can vendor TWO gems into one project.
    async fn add_puma_fixture(installed_rack: &Path, blobs: &Path) -> (PathBuf, PatchRecord) {
        let gems = installed_rack.parent().unwrap();
        let installed = gems.join("puma-6.4.2");
        tokio::fs::create_dir_all(installed.join("lib"))
            .await
            .unwrap();
        tokio::fs::write(installed.join("lib/puma.rb"), PRISTINE_PUMA)
            .await
            .unwrap();
        let specs = gems.parent().unwrap().join("specifications");
        tokio::fs::write(specs.join("puma-6.4.2.gemspec"), GEMSPEC_PUMA)
            .await
            .unwrap();
        let before = compute_git_sha256_from_bytes(PRISTINE_PUMA);
        let after = compute_git_sha256_from_bytes(PATCHED_PUMA);
        tokio::fs::write(blobs.join(&after), PATCHED_PUMA)
            .await
            .unwrap();
        let mut files = HashMap::new();
        files.insert(
            "lib/puma.rb".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let record = PatchRecord {
            uuid: UUID_PUMA.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (installed, record)
    }

    fn expected_lock_two_path() -> String {
        format!(
            "PATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma (= 6.4.2)!\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            puma = puma_rel(),
            rack = copy_rel()
        )
    }

    /// Bundler regenerates PATH sections sorted by source identifier — by
    /// remote path, the uuid level deciding here (verified against a real
    /// bundler 4.0.15 `bundle lock` over this exact two-PATH shape). The
    /// splice must land each new section at that sorted position no matter
    /// the vendor invocation order, or the committed lock churns on the
    /// next `bundle lock`/`bundle install`.
    #[tokio::test]
    async fn test_two_path_sections_sorted_regardless_of_vendor_order() {
        for rack_first in [true, false] {
            let (_tmp, root, installed_rack, blobs, record_rack) =
                fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
            let runs: [(&str, &Path, &PatchRecord); 2] = if rack_first {
                [
                    (PURL, &installed_rack, &record_rack),
                    (PURL_PUMA, &installed_puma, &record_puma),
                ]
            } else {
                [
                    (PURL_PUMA, &installed_puma, &record_puma),
                    (PURL, &installed_rack, &record_rack),
                ]
            };
            for (purl, installed, record) in runs {
                let (result, _e, _w) = unwrap_done(
                    run_vendor_purl(purl, &root, &blobs, installed, record, false).await,
                );
                assert!(result.success, "vendor {purl} failed: {:?}", result.error);
            }
            let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap();
            assert_eq!(lock, expected_lock_two_path(), "rack_first={rack_first}");
        }
    }

    // ── re-vendor: a patch update (new uuid, same purl) ──────────────────────

    /// Re-vendor uuid; sorts BEFORE `UUID_PUMA`'s (`0e…` < `1a…`).
    const UUID2: &str = "0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b";

    /// A patch update moves the manifest to a NEW uuid for the same gem. The
    /// CLI re-vendors straight over the first run's live wiring (originals
    /// carried forward and the old uuid dir swept by the caller — no
    /// revert-first; the cargo backend pins the same design). Both pair
    /// files must be repointed in place, with `original: None` on the
    /// rewired records.
    #[tokio::test]
    async fn test_revendor_new_uuid_direct_rewires_in_place() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);

        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{new_rel}\"\n"
            ),
            "Gemfile repointed in place"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct().replace(UUID, UUID2),
            "lock repointed in place"
        );
        // New copy built; the old uuid dir is left for the caller's
        // stale-artifact sweep (the caller owns the ledger).
        assert_eq!(
            tokio::fs::read(root.join(&new_rel).join("lib/rack.rb"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(root.join(format!(".socket/vendor/gem/{UUID}")).exists());

        // The rewired records carry `original: None` — never the old-uuid
        // lines (reverting those would "restore" a dangling vendor pointer).
        let mut entry2 = e2.expect("re-vendor emits the new ledger entry");
        assert_eq!(entry2.uuid, UUID2);
        assert_eq!(entry2.wiring.len(), 2);
        for rec in &entry2.wiring {
            assert_eq!(rec.action, WiringAction::Rewritten);
            assert!(rec.original.is_none(), "{rec:?}");
        }

        // With the caller's carry-forward applied, revert restores the
        // PRE-VENDOR files byte-exactly.
        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// Transitive form: the managed block is repointed in place (never
    /// duplicated) and the record stays `Added` with the WHOLE updated block,
    /// so a later revert deletes the fence.
    #[tokio::test]
    async fn test_revendor_new_uuid_transitive_updates_managed_block() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);

        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        let new_block = format!(
            "{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{new_rel}\", require: false\n{MANAGED_CLOSE}\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!("source \"https://rubygems.org\"\n\ngem \"puma\"\n{new_block}"),
            "ONE managed block, repointed — never a duplicate declaration"
        );

        let mut entry2 = e2.unwrap();
        assert_eq!(entry2.wiring[0].action, WiringAction::Added);
        assert!(entry2.wiring[0].original.is_none());
        assert_eq!(
            entry2.wiring[0].new.as_ref().unwrap(),
            &Value::String(new_block)
        );

        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE
        );
    }

    /// The managed block as releases up to 5.1 wrote it, without
    /// `require: false` (#2084): what a project vendored by one of them
    /// carries in its Gemfile and its ledger.
    fn block_without_require(nl: &str) -> String {
        format!(
            "{MANAGED_OPEN}{nl}gem \"rack\", \"3.2.6\", path: \"{}\"{nl}{MANAGED_CLOSE}{nl}",
            copy_rel()
        )
    }

    /// Vendor the transitive fixture, then put the Gemfile and the ledger
    /// record in the state an older release left: the block without
    /// `require: false`.
    async fn vendored_by_an_older_release(
        nl: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        PatchRecord,
        VendorEntry,
        String,
    ) {
        let gemfile = GEMFILE_TRANSITIVE.replace('\n', nl);
        let (tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut entry = e1.unwrap();
        let old_block = block_without_require(nl);
        tokio::fs::write(root.join(GEMFILE), format!("{gemfile}{old_block}"))
            .await
            .unwrap();
        entry.wiring[0].new = Some(Value::String(old_block));
        (tmp, root, installed, blobs, record, entry, gemfile)
    }

    /// #2084: the declaration the managed block adds is one `Bundler.require`
    /// must not load at boot, since the gem was not in the Gemfile before.
    #[test]
    fn appended_block_declares_the_gem_require_false() {
        for nl in ["\n", "\r\n"] {
            let text = GEMFILE_TRANSITIVE.replace('\n', nl);
            let rel = copy_rel();
            let Ok(GemfilePlan::Append { block }) = plan_gemfile_edit(&text, "rack", "3.2.6", &rel)
            else {
                panic!("a gem the Gemfile does not declare is appended");
            };
            assert_eq!(
                block,
                format!(
                    "{MANAGED_OPEN}{nl}gem \"rack\", \"3.2.6\", path: \"{rel}\", require: false{nl}{MANAGED_CLOSE}{nl}"
                )
            );
        }
    }

    /// #2084: a block an older release wrote gains `require: false` when a
    /// patch update re-vendors the gem, and the record holds the block as
    /// written, so the revert still deletes it.
    #[tokio::test]
    async fn revendor_adds_require_false_to_an_older_block() {
        for nl in ["\n", "\r\n"] {
            let (_tmp, root, installed, blobs, record, entry1, gemfile) =
                vendored_by_an_older_release(nl).await;
            let mut record2 = record.clone();
            record2.uuid = UUID2.to_string();
            let (r2, e2, _) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
            assert!(r2.success, "{:?}", r2.error);

            let new_block = format!(
                "{MANAGED_OPEN}{nl}gem \"rack\", \"3.2.6\", path: \".socket/vendor/gem/{UUID2}/rack-3.2.6\", require: false{nl}{MANAGED_CLOSE}{nl}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                format!("{gemfile}{new_block}"),
                "{nl:?}"
            );
            let mut entry2 = e2.unwrap();
            assert_eq!(entry2.wiring[0].action, WiringAction::Added);
            assert_eq!(
                entry2.wiring[0].new.as_ref().unwrap(),
                &Value::String(new_block)
            );

            carry_forward_originals(&entry1, &mut entry2);
            let outcome = revert_gem(&entry2, &root, false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
        }
    }

    /// #2084: the revert still takes a block an older release wrote and
    /// recorded, the one without `require: false`.
    #[tokio::test]
    async fn revert_removes_an_older_block_without_require_false() {
        for nl in ["\n", "\r\n"] {
            let (_tmp, root, _installed, _blobs, _record, entry, gemfile) =
                vendored_by_an_older_release(nl).await;
            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_TRANSITIVE
            );
        }
    }

    /// A managed-block line someone gave options or a comment is theirs: a
    /// re-vendor repoints its `path:` and changes nothing else on it.
    #[test]
    fn revendor_keeps_an_edited_block_line_as_it_is() {
        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        for tail in [
            ", require: \"rack/lite\"",
            ", require: false",
            ", group: :web",
            " # pinned",
            " if ENV[\"CI\"]",
            " unless ENV[\"CI\"]",
            " rescue nil",
            ";",
            "; gem \"foo\"",
            " ",
        ] {
            let line = |rel: &str| format!("gem \"rack\", \"3.2.6\", path: \"{rel}\"{tail}");
            let text = format!(
                "{GEMFILE_TRANSITIVE}{MANAGED_OPEN}\n{}\n{MANAGED_CLOSE}\n",
                line(&copy_rel())
            );
            let Ok(GemfilePlan::RewireOurs {
                new_line,
                managed_block,
                ..
            }) = plan_gemfile_edit(&text, "rack", "3.2.6", &new_rel)
            else {
                panic!("our own block is rewired: {tail}");
            };
            assert_eq!(new_line, line(&new_rel), "{tail}");
            assert_eq!(
                managed_block.unwrap(),
                format!("{MANAGED_OPEN}\n{}\n{MANAGED_CLOSE}\n", line(&new_rel))
            );
        }
    }

    /// A top-level declaration we rewired (not in the managed fence) was in
    /// the Gemfile before the patch: a re-vendor never gives it
    /// `require: false`.
    #[test]
    fn revendor_never_adds_require_false_outside_the_block() {
        let new_rel = format!(".socket/vendor/gem/{UUID2}/rack-3.2.6");
        let text = format!(
            "{GEMFILE_TRANSITIVE}gem \"rack\", \"3.2.6\", path: \"{}\"\n",
            copy_rel()
        );
        let Ok(GemfilePlan::RewireOurs {
            new_line,
            managed_block,
            ..
        }) = plan_gemfile_edit(&text, "rack", "3.2.6", &new_rel)
        else {
            panic!("our own declaration is rewired");
        };
        assert_eq!(
            new_line,
            format!("gem \"rack\", \"3.2.6\", path: \"{new_rel}\"")
        );
        assert!(managed_block.is_none());
    }

    /// A re-vendor must RE-SORT: the replacement PATH section lands wherever
    /// the NEW uuid sorts among the other vendored gems' sections, not where
    /// the old one sat.
    #[tokio::test]
    async fn test_revendor_new_uuid_resorts_path_sections() {
        let (_tmp, root, installed_rack, blobs, record_rack) =
            fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
        for (purl, installed, record) in [
            (PURL, &installed_rack, &record_rack),
            (PURL_PUMA, &installed_puma, &record_puma),
        ] {
            let (result, _e, _w) =
                unwrap_done(run_vendor_purl(purl, &root, &blobs, installed, record, false).await);
            assert!(result.success, "vendor {purl} failed: {:?}", result.error);
        }

        // The patch update moves rack to a uuid sorting BEFORE puma's.
        let mut rack2 = record_rack.clone();
        rack2.uuid = UUID2.to_string();
        let (result, _e, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed_rack, &rack2, false).await);
        assert!(result.success, "re-vendor must succeed: {:?}", result.error);

        let lock = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        assert_eq!(
            lock,
            expected_lock_two_path()
                .replace(
                    &format!("PATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\n", puma = puma_rel(), rack = copy_rel()),
                    &format!("PATH\n  remote: {rack}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPATH\n  remote: {puma}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\n", puma = puma_rel(), rack = copy_rel().replace(UUID, UUID2)),
                ),
            "rack's section moved to the new uuid's sorted position"
        );
    }

    /// On a re-vendor over a CHECKSUMS lock the checksum record must ride
    /// AGAIN with `original: None`: dropped, the first run's registry
    /// `sha256=` line would vanish from the ledger with the replaced entry,
    /// and a post-update revert would leave a bare CHECKSUMS entry on a
    /// registry gem (frozen installs exit 16).
    #[tokio::test]
    async fn test_revendor_new_uuid_checksums_keeps_restore_data() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_checksums().replace(UUID, UUID2)
        );

        let mut entry2 = e2.unwrap();
        assert_eq!(entry2.wiring.len(), 3, "{:?}", entry2.wiring);
        let ck = &entry2.wiring[2];
        assert_eq!(ck.kind, LOCK_CHECKSUM_WIRING_KIND);
        assert!(ck.original.is_none(), "{:?}", ck.original);
        assert_eq!(
            ck.new.as_ref().unwrap(),
            &Value::String("  rack (3.1.8)".to_string())
        );

        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE,
            "registry sha256 line restored"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// The GEM-specs twin of `test_checksums_platform_sibling_fails_closed`:
    /// on a bundler < 2.6 lock (no CHECKSUMS section to catch it in) a
    /// platform-suffixed sibling spec must fail the lift closed — lifting
    /// only the plain entry would leave the sibling behind as a stale
    /// registry spec.
    #[test]
    fn test_gem_specs_platform_sibling_fails_closed() {
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0)\n      racc (~> 1.4)\n    nokogiri (1.16.0-arm64-darwin)\n      racc (~> 1.4)\n\nPLATFORMS\n  arm64-darwin\n  ruby\n\nDEPENDENCIES\n  nokogiri\n\nBUNDLED WITH\n   2.5.22\n";
        let rel = format!(".socket/vendor/gem/{UUID}/nokogiri-1.16.0");
        let err = match edit_lock(lock, "nokogiri", "1.16.0", &rel) {
            Err(e) => e,
            Ok(_) => panic!("a platform-suffixed GEM specs sibling must fail closed"),
        };
        assert!(err.contains("platform-suffixed"), "{err}");
    }

    /// Trailing options on the declaration (`require: false`, `group: :test`,
    /// …) must survive the rewrite: dropping `require: false` auto-requires
    /// the gem at boot, changing app behavior while vendored.
    #[tokio::test]
    async fn test_rewrite_preserves_trailing_options() {
        let gemfile =
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\", require: false\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\", path: \"{}\", require: false\n",
                copy_rel()
            ),
            "trailing options must survive the rewrite"
        );

        // Revert restores the original line (options and all) verbatim.
        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// #847: positional arguments the kept tail leads with (a splat, a
    /// constant, a method call) are version constraints the exact pin
    /// supersedes, so the rewrite drops them like quoted ones. The old
    /// `path: …, *V` rewrite left a Gemfile no `bundle` command could parse
    /// (a positional argument after a keyword one). Keyword options and a
    /// trailing comment still follow `path:`.
    #[tokio::test]
    async fn test_rewrite_drops_positional_constraints() {
        let rel = copy_rel();
        for (decl, want) in [
            (
                "gem \"rack\", *RV",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", ENV.fetch(\"RV\", \"~> 3.1\")",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", RACK_VERSION, require: false",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", require: false"),
            ),
            (
                "gem \"rack\", \"~> 3.1\", *RV, :require => false # web",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", :require => false # web"),
            ),
            (
                "gem \"rack\", RV, \"require\": false, **OPTS",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", \"require\": false, **OPTS"),
            ),
            (
                "gem \"rack\", Rack::VERSION, group: :web",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", group: :web"),
            ),
        ] {
            let gemfile = format!("source \"https://rubygems.org\"\n\nRV = [\"~> 3.1\"]\n{decl}\n");
            let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_DIRECT).await;

            let (result, entry, _w) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{decl}: {:?}", result.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                format!("source \"https://rubygems.org\"\n\nRV = [\"~> 3.1\"]\n{want}\n"),
                "{decl}: positional constraints are dropped, options kept after `path:`"
            );

            let outcome = revert_gem(&entry.unwrap(), &root, false).await;
            assert!(outcome.success, "{decl}: {:?}", outcome.error);
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile,
                "{decl}: revert restores the original line"
            );
        }
    }

    /// [`split_kept_tail`] leg by leg: commas, `=>` and `#` inside strings
    /// or brackets never split, `Const::Path` is not a `key:` label, and
    /// leading positional arguments are dropped.
    #[test]
    fn split_kept_tail_grammar() {
        for (opts, keywords, comment) in [
            ("", "", ""),
            ("require: false", "require: false", ""),
            ("*V", "", ""),
            ("*V # pinned", "", "# pinned"),
            ("ENV.fetch(\"a, b\", \"#x\")", "", ""),
            ("V, require: false", "require: false", ""),
            ("A::B, group: [:a, :b]", "group: [:a, :b]", ""),
            ("V, :require => false", ":require => false", ""),
            ("V, \"require\" => false", "\"require\" => false", ""),
            ("V, **OPTS", "**OPTS", ""),
            ("{x: 1}.fetch(:x), required?: 1", "required?: 1", ""),
        ] {
            let tail = split_kept_tail(opts);
            assert_eq!(tail.keywords, keywords, "{opts:?}");
            assert_eq!(tail.comment, comment, "{opts:?}");
        }
    }

    /// `source:` selects a registry — carried alongside the `path:` we add it
    /// is a bundler error (one source per gem), and silently dropping it
    /// would hide the user's routing. Refused like `git:`/`github:`.
    #[tokio::test]
    async fn test_refuses_source_option_declaration() {
        let gemfile =
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\", source: \"https://gems.example\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("source:"), "{detail}");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// `gem\t"rack"` (tab separator) is a valid ruby call. If the grammar
    /// cannot see it, the plan falls through to the transitive Append and the
    /// Gemfile ends up declaring rack TWICE (registry line + managed path:
    /// block) — bundler hard-fails every install until hand-repaired.
    #[tokio::test]
    async fn test_tab_separated_declaration_rewritten_not_duplicated() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem\t\"rack\", \"~> 3.1\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        assert!(
            !new_gemfile.contains(MANAGED_OPEN),
            "must rewrite in place, never append a duplicate declaration: {new_gemfile}"
        );
        assert!(
            !new_gemfile.contains("~> 3.1"),
            "registry declaration replaced: {new_gemfile}"
        );
        assert!(new_gemfile.contains(&copy_rel()), "{new_gemfile}");

        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile
        );
    }

    /// Gemfile + Gemfile.lock are USER-owned files vendor merely edits: the
    /// pair edit and every revert write must keep their permission bits (the
    /// plain atomic writer swaps in a umask-default inode — a 0600 private
    /// Gemfile silently becomes 0644; see
    /// `atomic_write_bytes_preserving_mode`). The CHECKSUMS fixture exercises
    /// all three revert writers.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_pair_edit_and_revert_preserve_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        for f in [GEMFILE, GEMFILE_LOCK] {
            tokio::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }

        let (result, entry, _w) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        for f in [GEMFILE, GEMFILE_LOCK] {
            let mode = tokio::fs::metadata(root.join(f))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f} mode reset by the vendor pair edit");
        }

        let outcome = revert_gem(&entry.unwrap(), &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        for f in [GEMFILE, GEMFILE_LOCK] {
            let mode = tokio::fs::metadata(root.join(f))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f} mode reset by revert");
        }
    }

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::VendorSource;

    /// A valid path-source stub (no native extensions; assigns the
    /// rubygems-required `summary` + `authors`, which every bundler major
    /// validates on path-source gemspecs).
    const SERVICE_STUB: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.summary = \"a modular Ruby web server interface\".freeze\n  s.authors = [\"Rack maintainers\".freeze]\n  s.licenses = [\"MIT\".freeze]\n  s.require_paths = [\"lib\".freeze]\nend\n";
    /// A stub that declares native extensions (must be refused).
    const SERVICE_STUB_NATIVE: &[u8] = b"Gem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.extensions = [\"ext/rack/extconf.rb\"]\nend\n";
    /// A DEFECTIVE stub shape: it never assigns the rubygems-required
    /// `summary` / `authors` (nor `licenses`), so bundler's path-source
    /// validation rejects it and every post-vendor `bundle install` exits 1.
    const SERVICE_STUB_INVALID: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n";

    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha512};
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    fn gem_service_cfg(uri: &str, source: VendorSource, offline: bool) -> VendorServiceConfig {
        VendorServiceConfig {
            maven_config: None,
            source,
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: uri.to_string(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    route: crate::api::client::ApiRoute::org("acme"),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none()),
            ),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            patch_server_origins: Vec::new(),
            offline,
        }
    }

    /// Build a `.gem` (uncompressed outer tar holding `data.tar.gz` +
    /// `metadata.gz`). `data_files` are the inner data.tar.gz entries at the
    /// root (no prefix dir), as a real `.gem` carries them.
    pub(super) fn make_gem(data_files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut data_tar = tar::Builder::new(Vec::new());
        for (rel, content) in data_files {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            data_tar.append_data(&mut h, rel, *content).unwrap();
        }
        let data_tar = data_tar.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&data_tar).unwrap();
        let data_gz = enc.finish().unwrap();
        // A token metadata.gz: the CLI service path never reads it (it uses the
        // served stub), but a real `.gem` always carries one.
        let mut menc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        menc.write_all(b"--- !ruby/object:Gem::Specification\nname: rack\n")
            .unwrap();
        let metadata_gz = menc.finish().unwrap();
        let mut outer = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("metadata.gz", metadata_gz.as_slice()),
            ("data.tar.gz", data_gz.as_slice()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            outer.append_data(&mut h, name, bytes).unwrap();
        }
        outer.into_inner().unwrap()
    }

    /// Mount the two-step granted flow: POST returns the `.gem` (tarball) and,
    /// when `stub` is `Some`, the `gem-stub-gemspec` second artifact; GET serves
    /// each artifact's bytes. `gem_sha512` / the stub's advertised sha512 are
    /// passed explicitly so a test can advertise a WRONG hash.
    async fn mount_gem_granted(
        server: &wiremock::MockServer,
        gem_bytes: &[u8],
        gem_sha512: &str,
        stub: Option<(&[u8], &str)>,
    ) {
        mount_gem_granted_as(server, UUID, gem_bytes, gem_sha512, stub).await;
    }

    /// [`mount_gem_granted`] for the patch `uuid`.
    async fn mount_gem_granted_as(
        server: &wiremock::MockServer,
        uuid: &str,
        gem_bytes: &[u8],
        gem_sha512: &str,
        stub: Option<(&[u8], &str)>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let gem_path = format!("/patch/gem/rack/3.2.6/tok/{uuid}/rack-3.2.6.gem");
        let gem_url = format!("{}{gem_path}", server.uri());
        let mut artifacts = vec![serde_json::json!({
            "kind": "tarball", "url": gem_url,
            "integrity": { "sha512": gem_sha512 }
        })];
        let stub_path = format!("/patch/gem/rack/3.2.6/tok/{uuid}/rack-3.2.6.gemspec");
        if let Some((stub_bytes, stub_sha512)) = stub {
            let stub_url = format!("{}{stub_path}", server.uri());
            artifacts.push(serde_json::json!({
                "kind": "gem-stub-gemspec", "url": stub_url,
                "integrity": { "sha512": stub_sha512 }
            }));
            Mock::given(method("GET"))
                .and(path(stub_path.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(stub_bytes.to_vec()))
                .mount(server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { uuid: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": artifacts
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(gem_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gem_bytes.to_vec()))
            .mount(server)
            .await;
    }

    async fn mount_gem_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .mount(server)
            .await;
    }

    /// An `installed_dir` that does NOT exist on disk but is named `<leaf>` (so
    /// the platform-gem check passes): the service path must need no local copy.
    fn missing_install(root: &Path) -> PathBuf {
        root.join("no-such-install/rack-3.2.6")
    }

    fn copy_lib(root: &Path) -> PathBuf {
        root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6/lib/rack.rb"))
    }

    fn copy_gemspec(root: &Path) -> PathBuf {
        root.join(format!(".socket/vendor/gem/{UUID}/rack-3.2.6/rack.gemspec"))
    }

    /// Service success: the prebuilt `.gem` is extracted into the copy dir, the
    /// served stub is written as `rack.gemspec` BYTE-VERBATIM (a valid stub —
    /// one assigning `summary`/`authors` — must pass the required-attribute
    /// validation untouched), the Gemfile + lock are wired, and a
    /// `vendor_prebuilt_downloaded` advisory is emitted — WITHOUT a local
    /// install (a deliberately-missing `installed_dir`).
    #[tokio::test]
    async fn service_success_extracts_gem_and_wires_lock() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (result, entry, warnings) = unwrap_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(tokio::fs::read(copy_lib(&root)).await.unwrap(), PATCHED);
        assert_eq!(
            tokio::fs::read(copy_gemspec(&root)).await.unwrap(),
            SERVICE_STUB
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
    }

    /// A gem whose `Gemfile` and lock a Bazel hub reads is committed as its
    /// archive ([`bazel`]): the pair names it by a `file:` source, a later
    /// run is in sync, a gem that went missing is written again and held
    /// to the lock, a newer patch takes the source over, and the revert
    /// puts the pair back. A `gem_checksums` entry for other bytes declines
    /// the gem once its bytes are known, with nothing written.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_gem_of_a_lock_a_bazel_hub_reads_is_committed_as_its_archive() {
        let _unset = crate::test_env::EnvGuard::unset(super::super::refusals::ALLOW_IN_BAZEL_ENV);
        let sums = "CHECKSUMS\n  puma (6.4.2) sha256=aa\n  rack (3.2.6) sha256=bb\n\nBUNDLED WITH";
        // A Bundler that a hub was built with.
        let lock = LOCK_DIRECT.replace("BUNDLED WITH", sums);
        let lock = lock.replace("   2.5.22\n", "   2.6.9\n");
        assert!(lock.ends_with("BUNDLED WITH\n   2.6.9\n"), "{lock}");
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, &lock).await;
        let module = "ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
                      ruby.bundle_fetch(name = \"b\", gemfile = \"//:Gemfile\", gemfile_lock = \
                      \"//:Gemfile.lock\"SUMS)\n";
        let write = |file: &str, text: &str| std::fs::write(root.join(file), text).unwrap();
        let read = |file: &str| std::fs::read_to_string(root.join(file)).unwrap();
        write("MODULE.bazel", &module.replace("SUMS", ""));
        write(".bazelversion", "8.8.2\n");
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sum = crate::utils::digest::sha256_hex_of(&gem);
        let server = wiremock::MockServer::start().await;
        let stub = Some((SERVICE_STUB, sri_sha512(SERVICE_STUB)));
        let stub = stub.as_ref().map(|(bytes, sri)| (*bytes, sri.as_str()));
        mount_gem_granted(&server, &gem, &sri_sha512(&gem), stub).await;
        let sources = PatchSources::blobs_only(&blobs);
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
        let run = |record: &PatchRecord, dry_run: bool, cfg: &VendorServiceConfig| {
            let (record, cfg) = (record.clone(), cfg.clone());
            let (root, sources) = (root.clone(), sources.clone());
            async move {
                let at = "2026-06-09T00:00:00Z";
                let install = missing_install(&root);
                crate::vendor::test_support::vendor_gem(
                    PURL,
                    &install,
                    &root,
                    &record,
                    &sources,
                    at,
                    dry_run,
                    false,
                    Some(&cfg),
                )
                .await
            }
        };
        let archive =
            |uuid: &str| root.join(format!(".socket/vendor/gem/{uuid}/gems/rack-3.2.6.gem"));
        let source = |uuid: &str| format!("file:.socket/vendor/gem/{uuid}/");

        // An entry of the call for the upstream gem: declined, nothing
        // written. A dry run says the same.
        let pinned = format!(
            ", gem_checksums = {{\"rack-3.2.6\": \"{}\"}}",
            "c".repeat(64)
        );
        write("MODULE.bazel", &module.replace("SUMS", &pinned));
        for dry_run in [true, false] {
            let (code, detail) = unwrap_refused(run(&record, dry_run, &cfg).await);
            assert_eq!(code, "vendor_gem_bazel_hub");
            assert!(
                detail.contains(&sum) && detail.contains("rack-3.2.6"),
                "{detail}"
            );
            assert_eq!([read(GEMFILE), read(GEMFILE_LOCK)], [GEMFILE_DIRECT, &lock]);
            assert!(!root.join(".socket").exists());
        }
        write("MODULE.bazel", &module.replace("SUMS", ""));

        // A gem that does not hold the patched file is not committed.
        let other = wiremock::MockServer::start().await;
        let unpatched = make_gem(&[("lib/rack.rb", PRISTINE)]);
        mount_gem_granted(&other, &unpatched, &sri_sha512(&unpatched), stub).await;
        let unpatched = gem_service_cfg(&other.uri(), VendorSource::Service, false);
        let (code, _) = unwrap_refused(run(&record, false, &unpatched).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(".socket").exists() && read(GEMFILE_LOCK) == lock);

        // A dry run writes nothing; the run commits the gem and names it.
        let (result, entry, _) = unwrap_done(run(&record, true, &cfg).await);
        assert!(result.success && entry.is_none() && !root.join(".socket").exists());
        let (result, entry, warnings) = unwrap_done(run(&record, false, &cfg).await);
        let first = entry.expect("an entry");
        assert!(result.success, "{:?}", result.error);
        assert_eq!(std::fs::read(archive(UUID)).unwrap(), gem);
        let rel = format!(".socket/vendor/gem/{UUID}/gems/rack-3.2.6.gem");
        assert_eq!(
            (first.artifact.path.as_str(), first.artifact.sha256.as_str()),
            (rel.as_str(), sum.as_str())
        );
        let declared = format!("gem \"rack\", \"~> 3.1\", source: \"{}\"\n", source(UUID));
        assert!(read(GEMFILE).ends_with(&declared), "{}", read(GEMFILE));
        let section = format!(
            "GEM\n  remote: {}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\n",
            source(UUID)
        );
        let wired = read(GEMFILE_LOCK);
        assert!(wired.starts_with(&section), "{wired}");
        assert!(wired.contains(&format!("  rack (~> 3.1)!\n\nCHECKSUMS\n  puma (6.4.2) sha256=aa\n  rack (3.2.6) sha256={sum}\n")), "{wired}");
        assert!(
            warnings.iter().any(|w| w.code == bazel::ADVISORY),
            "{warnings:?}"
        );
        assert!(root
            .join(format!(".socket/vendor/gem/{UUID}/.gitignore"))
            .exists());

        // In sync: nothing to record, nothing to say.
        let (result, entry, warnings) = unwrap_done(run(&record, false, &cfg).await);
        assert!(
            result.success && entry.is_none() && warnings.is_empty(),
            "{warnings:?}"
        );

        // The gem is gone: written again, with the pair as it is. One the
        // lock does not pin is not written.
        std::fs::remove_file(archive(UUID)).unwrap();
        let (_, entry, warnings) = unwrap_done(run(&record, false, &cfg).await);
        assert!(entry.is_some_and(|entry| entry.wiring.is_empty()));
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
        assert_eq!(std::fs::read(archive(UUID)).unwrap(), gem);
        assert_eq!(read(GEMFILE_LOCK), wired);
        std::fs::remove_file(archive(UUID)).unwrap();
        write(GEMFILE_LOCK, &wired.replace(&sum, &"d".repeat(64)));
        let (code, detail) = unwrap_refused(run(&record, false, &cfg).await);
        assert_eq!(code, "vendor_gem_bazel_hub");
        assert!(
            detail.contains("Gemfile.lock holds rack 3.2.6 to sha256"),
            "{detail}"
        );
        assert!(!archive(UUID).exists());
        write(GEMFILE_LOCK, &wired);
        unwrap_done(run(&record, false, &cfg).await);

        // A newer patch of the gem takes the source over, and its entry,
        // with what the caller carries forward, reverts to the first pair.
        let newer_gem = make_gem(&[("lib/rack.rb", PATCHED), ("lib/more.rb", b"more\n")]);
        let newer = PatchRecord {
            uuid: UUID2.to_string(),
            ..record.clone()
        };
        let second = wiremock::MockServer::start().await;
        mount_gem_granted_as(&second, UUID2, &newer_gem, &sri_sha512(&newer_gem), stub).await;
        let cfg2 = gem_service_cfg(&second.uri(), VendorSource::Service, false);
        let (result, entry, _) = unwrap_done(run(&newer, false, &cfg2).await);
        assert!(result.success, "{:?}", result.error);
        let mut entry = entry.expect("an entry");
        assert_eq!(std::fs::read(archive(UUID2)).unwrap(), newer_gem);
        let pair = read(GEMFILE) + &read(GEMFILE_LOCK);
        assert!(
            pair.contains(&source(UUID2)) && !pair.contains(&source(UUID)),
            "{pair}"
        );
        crate::vendor::state::carry_forward_wiring(&first, &mut entry);
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(
            outcome.success && outcome.warnings.is_empty(),
            "{outcome:?}"
        );
        assert_eq!([read(GEMFILE), read(GEMFILE_LOCK)], [GEMFILE_DIRECT, &lock]);
        assert!(!archive(UUID2).exists());
    }

    /// `service` mode + a `.gem` integrity mismatch hard-fails; nothing wired.
    #[tokio::test]
    async fn service_gem_integrity_mismatch_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let wrong = sri_sha512(b"different bytes");
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &wrong, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        // The lock is untouched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// `service` mode + a stub integrity mismatch hard-fails.
    #[tokio::test]
    async fn service_stub_integrity_mismatch_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let wrong_stub = sri_sha512(b"not the stub");
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &wrong_stub))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// `service` mode + a missing stub artifact hard-fails (old un-rebuilt row /
    /// native gem): the `.gem` is present but no `gem-stub-gemspec` is served.
    #[tokio::test]
    async fn service_stub_missing_service_mode_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, None).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    #[tokio::test]
    async fn service_stub_missing_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, None).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    /// Explicit `service` mode + a served stub
    /// that never assigns the rubygems-required `summary`/`authors` refuses
    /// with its own `vendor_prebuilt_stub_invalid` code, naming the missing
    /// attributes — writing it verbatim would make every later `bundle install`
    /// exit 1 (all bundler majors validate path-source gemspecs). No partial
    /// artifacts are left and the lock is untouched.
    #[tokio::test]
    async fn service_stub_invalid_service_mode_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary") && detail.contains("authors"),
            "the refusal must name the missing attributes: {detail}"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        // The lock is untouched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn service_stub_invalid_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    #[tokio::test]
    async fn service_stub_invalid_auto_not_installed_refuses_truthfully() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary") && detail.contains("authors"),
            "the refusal must carry the served-stub defect: {detail}"
        );
        assert!(
            detail.contains("Retry after the patch service"),
            "the refusal must advise installing the gem: {detail}"
        );
        assert!(
            !detail.contains("--vendor-source=service"),
            "circular advice (service refuses on the same defect): {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    /// Invalid served stub + explicit `service` + the gem NOT installed: the hard refusal is
    /// the same as the installed case — installation is irrelevant to
    /// `service` mode, which never falls back.
    #[tokio::test]
    async fn service_stub_invalid_service_mode_not_installed_hard_fails() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("Retry after the patch service"),
            "the service refusal names the auto/build remedy: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    /// The write choke point validates the LOCALLY-derived stub too: a
    /// corrupted `specifications/` stub missing the required attributes is an
    /// honest `gem_spec_invalid` refusal naming the file — never a vendored
    /// copy bundler will reject at install time.
    #[tokio::test]
    async fn local_stub_invalid_refuses_with_gem_spec_invalid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let spec = installed
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("specifications/rack-3.2.6.gemspec");
        tokio::fs::write(
            &spec,
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\n  s.require_paths = [\"lib\"]\nend\n",
        )
        .await
        .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("summary")
                && detail.contains("authors")
                && detail.contains("served stub gemspec for rack"),
            "the refusal names the file and the missing attributes: {detail}"
        );
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// Invalid-stub heal: a project vendored before the stub check carries
    /// the invalid served stub on disk. The idempotent hot path must not re-bless it as
    /// `already_vendored`: the on-disk stub fails the required-attribute bar,
    /// routing into the artifact-only rebuild, which rewrites a valid stub
    /// with the pair edit and the ledger entry untouched.
    #[tokio::test]
    async fn wired_copy_with_invalid_stub_is_rebuilt() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (result, entry, _) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        // Simulate the pre-fix victim: the served invalid stub on disk.
        tokio::fs::write(copy_gemspec(&root), SERVICE_STUB_INVALID)
            .await
            .unwrap();

        let (result2, entry2, warnings2) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result2.success, "{:?}", result2.error);
        let entry2 = entry2.expect("the rebuild refreshes the ledger fingerprint");
        assert!(
            entry2.wiring.is_empty(),
            "artifact-only rebuild must not re-record wiring: {:?}",
            entry2.wiring
        );
        assert!(
            warnings2
                .iter()
                .any(|w| w.code == "vendor_artifact_rebuilt"),
            "the heal must surface as a rebuild, not a silent no-op: {warnings2:?}"
        );
        assert_eq!(
            tokio::fs::read_to_string(copy_gemspec(&root))
                .await
                .unwrap(),
            GEMSPEC,
            "the invalid on-disk stub must be replaced with the valid local stub"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "the heal must not touch the Gemfile"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired,
            "the heal must not touch Gemfile.lock"
        );
    }

    /// A failed hot-path artifact rebuild must
    /// never destroy the live-wired vendored copy. Drift the committed copy
    /// (bad merge / hand edit — still buildable: the path source exists and
    /// the stub is valid), then re-run with the patch content unavailable
    /// (empty blobs dir — the offline shape: a drifted file harvests no
    /// blob): the rebuild fails, but the previous — drifted yet buildable —
    /// copy, the marker, the Gemfile, and the lock must all be left exactly
    /// as they were, never a deleted uuid dir under a still-pointing pair
    /// edit.
    #[tokio::test]
    async fn failed_rebuild_preserves_live_wired_copy() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        tokio::fs::write(copy_lib(&root), b"drifted but buildable\n")
            .await
            .unwrap();

        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();
        let (r2, e2, _) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &empty, &installed, &record, false).await,
        );
        assert!(!r2.success, "rebuild must fail without patch content");
        assert!(e2.is_none());

        // The live-wired state is untouched: copy, marker, Gemfile, lock.
        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            b"drifted but buildable\n",
            "the previous committed copy must survive a failed rebuild"
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}"))
                .exists(),
            "marker must survive"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired,
            "lock untouched"
        );
        // And the failed rebuild's swap siblings never leak into the uuid dir.
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        let mut rd = tokio::fs::read_dir(&uuid_dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(!n.contains("socket-stage"), "stage litter: {n}");
            assert!(!n.contains("socket-old"), "backup litter: {n}");
        }
    }

    /// The swap itself must never leave less recoverable state than it
    /// started with. Force the stage rename to fail (stage absent — the same
    /// io::Error surface as a Windows file lock) with a live copy in place:
    /// the old copy must be restored byte-identical, with no backup parked
    /// beside it.
    #[tokio::test]
    async fn swap_failure_restores_previous_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("rack-3.2.6");
        tokio::fs::create_dir_all(copy.join("lib")).await.unwrap();
        tokio::fs::write(copy.join("lib/rack.rb"), b"live\n")
            .await
            .unwrap();

        let stage = stage_dir_for(&copy);
        assert!(
            swap_stage_into_place(&stage, &copy).await.is_err(),
            "swapping a missing stage must fail"
        );
        assert_eq!(
            tokio::fs::read(copy.join("lib/rack.rb")).await.unwrap(),
            b"live\n",
            "the previous copy must be restored after a failed swap"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// Same destroy class, service leg: a wired-but-stale hot-path rebuild
    /// whose served `.gem` fails to extract (garbage bytes behind a correct
    /// SRI) hard-fails — and must leave the drifted-but-present copy and the
    /// live pair edit exactly as they were, not delete the uuid dir the
    /// Gemfile `path:` still points at.
    #[tokio::test]
    async fn failed_service_rebuild_preserves_live_wired_copy() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        tokio::fs::write(copy_lib(&root), b"drifted but buildable\n")
            .await
            .unwrap();

        let garbage = b"not a gem archive".to_vec();
        let sri = sri_sha512(&garbage);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &garbage, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_extract_failed");

        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            b"drifted but buildable\n",
            "the previous committed copy must survive a failed service rebuild"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired
        );
    }

    #[tokio::test]
    async fn service_unavailable_miss_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let error = crate::vendor::test_support::expect_failure(outcome);
        assert!(
            error.contains("prebuilt") || error.contains("patch service"),
            "{error}"
        );
    }
    /// A served stub that declares native extensions is refused (defense in
    /// depth — the converter should never emit one).
    #[tokio::test]
    async fn service_native_ext_stub_hard_fails() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_NATIVE);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_NATIVE, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "native_extensions_unsupported");
        assert_names_other_modes(&detail, &["hosted", "agent"]);
    }

    /// `--offline` + `--vendor-source=service` refuses without any network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &installed,
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                "http://127.0.0.1:1",
                VendorSource::Service,
                true,
            )),
        )
        .await;
        let (code, _) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_service_offline_conflict");
    }

    // ── empty-wiring guards ──────────────────────────────────────────────

    const GEMFILE_PINNED: &str =
        "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"3.2.6\"\n";
    const LOCK_PINNED: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  arm64-darwin-23\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)\n\nBUNDLED WITH\n   2.5.22\n";

    /// The empty-wiring revert guard: an entry without recoverable wiring must FAIL loudly — deleting the artifact would
    /// strand the Gemfile `path:` + lock PATH section on a dead dir. The
    /// files and the artifact stay untouched.
    #[tokio::test]
    async fn revert_refuses_empty_wiring_entry() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let mut entry = entry.expect("wired entry");
        entry.wiring = Vec::new();

        let gemfile_before = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        for dry_run in [true, false] {
            let outcome = revert_gem(&entry, &root, dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must fail loudly");
            let err = outcome.error.expect("error detail");
            assert!(err.contains("vendor_wiring_unknown"), "{err}");
            assert!(err.contains("Gemfile"), "names the files to clean: {err}");
        }
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "the artifact must NOT be deleted"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_before
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );
    }

    /// The empty-wiring refusal applies under `keep_artifact`
    /// (`--preserve-state`) TOO: a preserve-state
    /// rollback that cannot restore the wiring must not report the system
    /// restored while the pair edit still wires the vendored dir in (the
    /// patch would silently stay applied). Pins that decision.
    #[tokio::test]
    async fn preserve_state_revert_refuses_empty_wiring_entry() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let mut entry = entry.expect("wired entry");
        entry.wiring = Vec::new();

        let gemfile_before = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        for dry_run in [true, false] {
            let outcome = revert_gem_opts(
                &entry,
                &root,
                RevertOpts {
                    dry_run,
                    keep_artifact: true,
                },
            )
            .await;
            assert!(
                !outcome.success,
                "dry_run={dry_run}: must refuse under keep_artifact too"
            );
            let err = outcome.error.expect("error detail");
            assert!(err.contains("vendor_wiring_unknown"), "{err}");
        }
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "the artifact must NOT be deleted"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_before
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as `Gemfile.lock` must fail fast instead of wedging
    /// every lock reader — vendor's pair read and revert's three restore
    /// readers — forever in an `open(2)` that waits for a writer that never
    /// comes. Same `open_regular_file` guard class as the composer.lock /
    /// Cargo.lock twins. Vendor refuses loudly; revert fails without
    /// deleting the artifacts (what to restore can't be determined).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_instead_of_wedging() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        // A real vendor run first so revert has a live ledger entry.
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();

        let lock_path = root.join(GEMFILE_LOCK);
        tokio::fs::remove_file(&lock_path).await.unwrap();
        mkfifo(&lock_path);

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                run_vendor(&root, &blobs, &installed, &record, false).await,
                revert_gem(&entry, &root, false).await,
            )
        };
        let Ok((vendor_outcome, revert_outcome)) = tokio::time::timeout(deadline, all).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock_path);
            panic!("Gemfile.lock reads must fail fast on a FIFO");
        };
        let (code, detail) = unwrap_refused(vendor_outcome);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(
            detail.contains("unreadable"),
            "a squatted lock is unreadable, not missing: {detail}"
        );
        assert!(
            !revert_outcome.success,
            "revert must fail when the lock can't be read: {revert_outcome:?}"
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "failed revert must not delete the artifacts"
        );
    }

    /// A declaration the strict line grammar cannot see — `gem"rack"` with no
    /// separator, `gem ("rack")` with a space before the paren; both valid
    /// Ruby — must REFUSE, never fall through to the transitive Append plan:
    /// appending the managed block next to the unseen declaration leaves the
    /// Gemfile declaring the gem TWICE, and bundler hard-fails every install
    /// on the duplicate until hand-repaired (the redirect rewriter gates its
    /// append with the same looser `declared_re` probe).
    #[tokio::test]
    async fn unrecognized_gem_call_refuses_instead_of_duplicating() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem\"rack\", \"~> 3.1\"\n";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;

        let (code, detail) =
            unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            gemfile,
            "refusal must write nothing: {detail}"
        );

        // The space-before-paren call form (single-arg, valid Ruby) is the
        // same class: unseen by the grammar, so the plan must refuse too.
        let spaced = "source \"https://rubygems.org\"\n\ngem (\"rack\")\n";
        assert!(
            plan_gemfile_edit(spaced, "rack", "3.2.6", &copy_rel()).is_err(),
            "a space-before-paren declaration must refuse, not Append"
        );
    }

    /// #482: a DIRECT dependency declared where the line grammar cannot see
    /// it (`eval_gemfile`, a loop, a gemspec) is listed under the lock's
    /// DEPENDENCIES.
    /// Appending the managed block would declare it twice and bundler
    /// refuses every install, so the plan must refuse before any write.
    #[tokio::test]
    async fn direct_dependency_declared_out_of_sight_refuses_instead_of_appending() {
        for gemfile in [
            "source \"https://rubygems.org\"\n\ngem \"puma\"\neval_gemfile \"Gemfile.common\"\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n%w[rack].each { |g| gem g, \"~> 3.1\" }\n",
            // A gem only the gemspec declares (a development dependency).
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngemspec\n",
            "source \"https://rubygems.org\"\r\n\r\ngem \"puma\"\r\ngemspec path: \"gems/mylib\"\r\n",
            // No directive: a variable of that name, which a loop reads.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\ngemspec_file = Gem::Specification.load(\"x.gemspec\")\ngemspec_file.development_dependencies.each { |d| gem d.name }\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nspec = Gem::Specification.load(\"x.gemspec\")\n\ngemspec = spec\ngemspec.development_dependencies.each { |d| gem d.name }\n",
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_DIRECT).await;
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert_eq!(code, "gemfile_declaration_not_editable", "{gemfile}");
            assert!(detail.contains("direct dependency"), "{detail}");
            // #2151: the refusal names its way out, and no mode that
            // refuses the gem as well (hosted mode does, for this reason).
            assert!(
                detail.contains("one literal `gem \"rack\"` line"),
                "{detail}"
            );
            assert_names_other_modes(&detail, &["agent"]);
            // The line replaces a `gem` call out of sight: next to it,
            // the vendored pin would be a second, differing declaration.
            assert!(
                detail.contains("in place of any other `gem` call that declares it"),
                "{detail}"
            );
            assert_eq!(
                detail.contains("above `gemspec`"),
                gemfile.contains("\ngemspec\n") || gemfile.contains("\ngemspec path:"),
                "{detail}"
            );
            assert!(!root.join(".socket").exists());
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile,
                "refusal must write nothing: {detail}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_DIRECT
            );
        }
    }

    /// Re-vendor (new uuid) over a lock whose CHECKSUMS entry was ALREADY
    /// bare pre-vendor: the first run recorded no checksum wiring, so the
    /// re-vendor's `original: None` checksum record has nothing to
    /// carry-forward from. Revert must treat that as "nothing to restore" —
    /// the bare line still standing IS the pre-vendor state — never as
    /// drift: the pair restores byte-exactly and no
    /// `vendor_lock_entry_drifted` warning fires.
    #[tokio::test]
    async fn revendor_over_already_bare_checksum_reverts_without_drift() {
        let lock = SPIKE_LOCK_CHECKSUMS_BEFORE.replace(SPIKE_RACK_SHA_LINE, "  rack (3.1.8)");
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, &lock).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry1 = e1.unwrap();
        assert_eq!(entry1.wiring.len(), 2, "already-bare: no checksum record");

        let mut record2 = record.clone();
        record2.uuid = UUID2.to_string();
        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        let mut entry2 = e2.unwrap();

        // The caller's carry-forward finds no checksum record to fill from —
        // the record legitimately keeps `original: None`.
        carry_forward_originals(&entry1, &mut entry2);
        let ck = entry2
            .wiring
            .iter()
            .find(|w| w.kind == LOCK_CHECKSUM_WIRING_KIND)
            .expect("re-vendor rides the checksum record");
        assert!(ck.original.is_none());

        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            lock,
            "pre-vendor lock (bare CHECKSUMS entry) restored byte-exactly"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// vendor records the whole-tree file inventory (patched lib + stub
    /// gemspec) with hand-pinned plain-sha256 values.
    #[tokio::test]
    async fn vendor_records_dir_file_inventory() {
        use sha2::{Digest, Sha256};

        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_PINNED, LOCK_PINNED).await;
        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        let entry = entry.expect("wired entry");

        let inventory = entry
            .artifact
            .file_inventory
            .as_ref()
            .expect("dir-shaped entries record an inventory");
        assert_eq!(
            inventory.keys().collect::<Vec<_>>(),
            ["lib/rack.rb", "rack.gemspec"],
            "sorted keys, gemspec included"
        );
        assert_eq!(
            inventory["lib/rack.rb"],
            hex::encode(Sha256::digest(PATCHED))
        );
        assert_eq!(
            inventory["rack.gemspec"],
            hex::encode(Sha256::digest(GEMSPEC.as_bytes()))
        );
    }

    // ── refusal / failure legs ────

    /// [`run_vendor`] with an explicit service config (the service tests
    /// above inline this shape; the tests below share it).
    async fn run_vendor_service(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        cfg: &VendorServiceConfig,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_gem(
            PURL,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(cfg),
        )
        .await
    }

    /// Coordinate guards fire before any disk access: a non-gem purl and a
    /// version outside the plain gem-token charset (both embedded verbatim
    /// into ruby source + lock grammar) are `unsafe_coordinates` refusals
    /// that write nothing.
    #[tokio::test]
    async fn refuses_non_gem_purl_and_unsafe_tokens() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;

        let (code, detail) = unwrap_refused(
            run_vendor_purl(
                "pkg:npm/left-pad@1.0.0",
                &root,
                &blobs,
                &installed,
                &record,
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(detail.contains("not a gem purl"), "{detail}");

        // `+` is valid in a purl version but NOT in the plain gem token
        // charset vendor may embed into the Gemfile / lock grammar.
        let (code, detail) = unwrap_refused(
            run_vendor_purl(
                "pkg:gem/rack@3.2.6+meta",
                &root,
                &blobs,
                &installed,
                &record,
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(detail.contains("unsafe gem coordinates"), "{detail}");

        assert!(
            !root.join(".socket").exists(),
            "refusals must write nothing"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A patch record with no files is meaningless to vendor: a no-op
    /// success — no ledger entry, no copy, neither project file touched.
    #[tokio::test]
    async fn empty_record_files_is_a_noop_success() {
        let (_tmp, root, installed, blobs, mut record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        record.files.clear();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "a no-op records no ledger entry");
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert!(!root.join(".socket").exists(), "no writes at all");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// The Gemfile twin of [`fifo_lock_fails_fast_instead_of_wedging`]: a
    /// FIFO planted as the Gemfile must fail vendor's pair read fast (the
    /// `open_regular_file` guard) with the "unreadable" (not "missing")
    /// refusal, instead of wedging in `open(2)` forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_gemfile_fails_fast_instead_of_wedging() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gemfile_path = root.join(GEMFILE);
        tokio::fs::remove_file(&gemfile_path).await.unwrap();
        mkfifo(&gemfile_path);

        let deadline = std::time::Duration::from_secs(5);
        let fut = run_vendor(&root, &blobs, &installed, &record, false);
        let Ok(outcome) = tokio::time::timeout(deadline, fut).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&gemfile_path);
            panic!("Gemfile reads must fail fast on a FIFO");
        };
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "gemfile_missing");
        assert!(
            detail.contains("unreadable"),
            "a squatted Gemfile is unreadable, not missing: {detail}"
        );
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    /// Wired pair + stale copy + dry run: falls through the artifact rebuild
    /// to the verify-only preview — the copy is NOT recreated and nothing is
    /// written.
    #[tokio::test]
    async fn wired_missing_copy_dry_run_previews_without_rebuilding() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(copy_rel());
        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, true).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "dry run records nothing");
        assert!(
            !copy_root.exists(),
            "a dry run must not rebuild the missing copy"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// Wired pair + stale copy + `--offline --vendor-source=service`: the
    /// artifact-rebuild path re-checks the conflict and refuses before any
    /// network or disk write.
    #[tokio::test]
    async fn wired_missing_copy_offline_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, _, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let copy_root = root.join(copy_rel());
        crate::patch::copy_tree::remove_tree(&copy_root)
            .await
            .unwrap();

        let cfg = gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, true);
        let (code, _d) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_service_offline_conflict");
        assert!(!copy_root.exists(), "refusal must not rebuild");
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    #[tokio::test]
    async fn fresh_copy_failure_cleans_up_and_touches_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::remove_dir_all(&installed).await.unwrap();

        let (result, entry, _w) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &blobs, &installed, &record, false).await,
        );
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("patch service request failed"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "no uuid-dir husk after a failed fresh vendor"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the empty vendor levels this run created are pruned"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A marker-write failure is informational only (state.json is the
    /// ledger of record): a DIRECTORY squatting the marker path survives
    /// materialise (which only rebuilds the copy dir) and makes the atomic
    /// marker write fail — vendor still succeeds, entry recorded, with a
    /// `vendor_marker_write_failed` warning.
    #[tokio::test]
    async fn marker_write_failure_downgrades_to_warning() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let marker_path = root.join(format!(".socket/vendor/gem/{UUID}/{VENDOR_MARKER_FILE}"));
        tokio::fs::create_dir_all(&marker_path).await.unwrap();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "a marker failure must not drop the entry");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );
        // The pair edit went through normally.
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_direct()
        );
        assert_eq!(
            tokio::fs::read(copy_lib(&root)).await.unwrap(),
            PATCHED,
            "copy still materialised"
        );
    }

    /// A Gemfile atomic-write failure (read-only project root: the stage
    /// file cannot be created) unwinds the freshly-built uuid dir and
    /// reports an un-successful Done with both project files byte-untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn gemfile_write_failure_unwinds_uuid_dir() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        // Pre-create the writable uuid chain so materialise needs no write
        // under the (about to be read-only) project root itself.
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let outcome = run_vendor(&root, &blobs, &installed, &record, false).await;

        // Restore before asserting so TempDir cleanup works even on failure.
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        let (result, entry, _w) = unwrap_done(outcome);
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to write Gemfile"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(!uuid_dir.exists(), "failed pair edit unwinds the uuid dir");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    // ── service miss / failure matrix (coverage-gap legs) ─────────────────

    /// [`mount_gem_granted`], but the advertised `gem-stub-gemspec` GET
    /// returns 500 — the stub-fetch `Failed` leg.
    async fn mount_gem_granted_stub_get_fails(
        server: &wiremock::MockServer,
        gem_bytes: &[u8],
        gem_sha512: &str,
        stub_sha512: &str,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let gem_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gem");
        let gem_url = format!("{}{gem_path}", server.uri());
        let stub_path = format!("/patch/gem/rack/3.2.6/tok/{UUID}/rack-3.2.6.gemspec");
        let stub_url = format!("{}{stub_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": gem_url,
                          "integrity": { "sha512": gem_sha512 } },
                        { "kind": "gem-stub-gemspec", "url": stub_url,
                          "integrity": { "sha512": stub_sha512 } }
                    ]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(gem_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gem_bytes.to_vec()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(stub_path))
            .respond_with(ResponseTemplate::new(500))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn disabled_service_config_silently_builds_locally() {
        for cfg in [
            gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, false),
            gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, true),
        ] {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let error = crate::vendor::test_support::expect_failure(
                run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
            );
            assert!(
                error.contains("prebuilt") || error.contains("service"),
                "{error}"
            );
        }
    }
    /// `service` mode + a still-building archive (`pending_build`) refuses
    /// with the "still building" detail; nothing is written.
    #[tokio::test]
    async fn service_pending_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "pending_build").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_pending");
        assert!(detail.contains("still building"), "{detail}");
        assert!(!root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn service_pending_auto_warns_and_builds_locally() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "pending_build").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// `service` mode + a terminal miss (`not_found`) hard-fails naming the
    /// unavailability (the `auto` fallback leg is covered above).
    #[tokio::test]
    async fn service_unavailable_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let server = wiremock::MockServer::start().await;
        mount_gem_status(&server, "not_found").await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_unavailable");
        assert!(detail.contains("unavailable"), "{detail}");
        assert!(!root.join(".socket").exists());
    }

    /// `service` mode + a stub-artifact GET failure (HTTP 500) hard-fails
    /// with the "could not fetch the stub gemspec" detail.
    #[tokio::test]
    async fn stub_fetch_failure_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted_stub_get_fails(&server, &gem, &sri, &stub_sri).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(
            detail.contains("could not fetch the stub gemspec"),
            "{detail}"
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// `auto` + the same stub-fetch failure warns (`vendor_prebuilt_unavailable`)
    /// and builds locally with the local stub.
    #[tokio::test]
    async fn stub_fetch_failure_auto_warns_and_builds_locally() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted_stub_get_fails(&server, &gem, &sri, &stub_sri).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// `service` mode + a served `.gem` whose extracted layout misses the
    /// recorded file paths fails closed (`vendor_prebuilt_layout_mismatch`
    /// miss → `vendor_prebuilt_required` refusal); no husk is left.
    #[tokio::test]
    async fn service_layout_mismatch_service_mode_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("wrong/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("unexpected layout"), "{detail}");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// `auto` + the same layout mismatch warns and falls back to the local
    /// build — the wrong-layout service bytes never land in the copy.
    #[tokio::test]
    async fn service_layout_mismatch_auto_falls_back_with_warning() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("wrong/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let error = crate::vendor::test_support::expect_failure(
            run_vendor_service(&root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("prebuilt") || error.contains("service"),
            "{error}"
        );
    }
    /// A served `.gem` whose data.tar.gz carries a DIRECTORY at the stub
    /// path (`rack.gemspec/…`) makes the stub write fail — a hard
    /// `vendor_prebuilt_write_failed`, no husk.
    #[tokio::test]
    async fn service_gem_with_dir_at_stub_path_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED), ("rack.gemspec/inner.rb", b"x")]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot write the stub gemspec"), "{detail}");
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A regular FILE squatting `.socket/vendor/gem` makes the service
    /// stage's `create_dir_all` fail — a hard `vendor_prebuilt_write_failed`
    /// naming the un-creatable path; the pair is untouched.
    #[tokio::test]
    async fn service_stage_create_failure_hard_fails() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::create_dir_all(root.join(".socket/vendor"))
            .await
            .unwrap();
        tokio::fs::write(root.join(".socket/vendor/gem"), b"not a dir")
            .await
            .unwrap();
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot create"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// An invalid served stub that DOES assign `licenses` must not carry the
    /// "also omits `licenses`" advisory — the empty-note branch of the
    /// invalid-stub refusal detail.
    #[tokio::test]
    async fn invalid_stub_with_licenses_omits_licenses_advisory() {
        const STUB_INVALID_WITH_LICENSE: &[u8] = b"# -*- encoding: utf-8 -*-\n# stub: rack 3.2.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rack\".freeze\n  s.version = \"3.2.6\".freeze\n  s.licenses = [\"MIT\".freeze]\n  s.require_paths = [\"lib\".freeze]\nend\n";
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(STUB_INVALID_WITH_LICENSE);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(
            &server,
            &gem,
            &sri,
            Some((STUB_INVALID_WITH_LICENSE, &stub_sri)),
        )
        .await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(detail.contains("does not assign"), "{detail}");
        assert!(
            !detail.contains("also omits"),
            "a stub assigning licenses must not get the licenses advisory: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    #[tokio::test]
    async fn invalid_served_and_local_stub_refuses_with_honest_note() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        tokio::fs::write(
            installed
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("specifications/rack-3.2.6.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"rack\"\n  s.version = \"3.2.6\"\nend\n",
        )
        .await
        .unwrap();
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB_INVALID);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB_INVALID, &stub_sri))).await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);

        let (code, detail) =
            unwrap_refused(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_prebuilt_stub_invalid");
        assert!(
            detail.contains("Retry after the patch service publishes a corrected artifact"),
            "the served-stub defect must ride the local refusal: {detail}"
        );
        assert!(!root.join(".socket").exists());
    }

    // ── revert guard / drift / failure legs (coverage-gap) ────────────────

    /// SECURITY: a traversal uuid in a (tamperable) ledger entry must refuse
    /// the revert before any disk access — wiring and artifact untouched.
    #[tokio::test]
    async fn revert_refuses_traversal_uuid() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut entry = e1.unwrap();
        entry.uuid = "../../escape".to_string();
        let gemfile_wired = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock_wired = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("non-canonical patch uuid"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
            gemfile_wired,
            "refusal happens before any wiring restore"
        );
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_wired
        );
        assert!(
            root.join(copy_rel()).join("lib/rack.rb").is_file(),
            "artifact untouched"
        );
    }

    /// An unrecognized wiring kind (a newer ledger) warns and continues —
    /// forward compatibility: the known records still restore byte-exactly.
    /// The unknown record is a left-alone fragment, so the copy dir it may
    /// still reference is kept (the family-wide drift-keep), never deleted
    /// under a record this build cannot read.
    #[tokio::test]
    async fn revert_unrecognized_wiring_kind_warns_and_continues() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let mut entry = e1.unwrap();
        entry.wiring.push(WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: "gemfile_lock_future_thing".to_string(),
            action: WiringAction::Added,
            key: Some("rack".to_string()),
            original: None,
            new: None,
        });

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let unknown: Vec<_> = outcome
            .warnings
            .iter()
            .filter(|w| w.detail.contains("unrecognized wiring kind"))
            .collect();
        assert_eq!(unknown.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(unknown[0].code, "vendor_lock_entry_drifted");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "known records still restore"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(
            outcome.kept_artifact && root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "an unreadable record keeps the copy dir it may reference"
        );
    }

    /// Artifact removal failing at revert's END (read-only parent dir): the
    /// wiring is ALREADY restored (it runs first) and the outcome reports
    /// the removal failure instead of a false success.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_artifact_removal_failure_reports_error_after_restore() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();

        let eco = root.join(".socket/vendor/gem");
        tokio::fs::set_permissions(&eco, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let outcome = revert_gem(&entry, &root, false).await;
        tokio::fs::set_permissions(&eco, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to remove"),
            "{:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "the un-removable uuid dir is still there"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "wiring restored before the removal attempt"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    /// A deleted Gemfile is reported as missing (NotFound → nothing can
    /// route through the copy via it, so NOT a drift-keep) while the lock
    /// record still restores and the artifact is still removed.
    #[tokio::test]
    async fn revert_missing_gemfile_warns_and_restores_lock() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        tokio::fs::remove_file(root.join(GEMFILE)).await.unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.drift_skipped(), "{:?}", outcome.warnings);
        let missing = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lockfile_missing")
            .count();
        assert_eq!(missing, 1, "{:?}", outcome.warnings);
        assert!(!root.join(GEMFILE).exists(), "the missing file stays gone");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// A deleted lock reports BOTH lock-side records (spec + checksum, via
    /// NotFound) as missing — not drift — while the Gemfile still restores
    /// and the artifact is still removed.
    #[tokio::test]
    async fn revert_missing_lock_warns_and_restores_gemfile() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(entry.wiring.len(), 3);
        tokio::fs::remove_file(root.join(GEMFILE_LOCK))
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.drift_skipped(), "{:?}", outcome.warnings);
        let missing = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lockfile_missing")
            .count();
        assert_eq!(
            missing, 2,
            "both lock-side records report the missing lock: {:?}",
            outcome.warnings
        );
        assert!(!root.join(GEMFILE_LOCK).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
    }

    /// The ledger is committed, so a record can say anything. A record
    /// whose text is not the pair edit of THIS gem — Ruby put back into the
    /// Gemfile, a line of the Gemfile that vendoring did not write, lock
    /// lines beyond the gem's own — fails the revert, and neither file is
    /// written.
    #[tokio::test]
    async fn revert_refuses_records_that_are_not_this_gems_pair_edit() {
        fn gemfile_original(e: &mut VendorEntry, line: &str) {
            e.wiring[0].original = Some(Value::String(line.to_string()));
        }
        type Tamper = Box<dyn Fn(&mut VendorEntry)>;
        let ruby = |line: &'static str| -> Tamper { Box::new(move |e| gemfile_original(e, line)) };
        let cases: Vec<(&str, Tamper)> = vec![
            (
                "a method call",
                ruby("gem \"rack\", system(\"touch PWNED\").to_s"),
            ),
            ("a backtick", ruby("gem \"rack\", `touch PWNED`")),
            (
                "an interpolation",
                ruby("gem \"rack\", \"#{`touch PWNED`}\""),
            ),
            (
                "a second statement",
                ruby("gem \"rack\"; system(\"touch PWNED\")"),
            ),
            (
                "a second line",
                ruby("gem \"rack\"\nsystem(\"touch PWNED\")"),
            ),
            (
                "another source",
                ruby("gem \"rack\", git: \"https://evil.example/rack.git\""),
            ),
            (
                "a source in a hash",
                ruby("gem \"rack\", { git: \"https://evil.example/rack.git\" }"),
            ),
            (
                "an option the vendored line does not carry",
                ruby("gem \"rack\", \"~> 3.1\", require: \"evil\""),
            ),
            ("another gem", ruby("gem \"evil\"")),
            ("an indented declaration", ruby("  gem \"rack\"")),
            ("no declaration", ruby("eval(File.read(\"x\"))")),
            (
                "a Gemfile line vendoring did not write",
                Box::new(|e| {
                    e.wiring[0].new = Some(Value::String("gem \"puma\"".to_string()));
                    gemfile_original(e, "gem \"puma\"; system(\"touch PWNED\")");
                }),
            ),
            (
                "a lock section beyond the spec block",
                Box::new(|e| {
                    let lines = e.wiring[1]
                        .original
                        .as_mut()
                        .unwrap()
                        .as_array_mut()
                        .unwrap();
                    lines[0] = Value::String(
                        "    rack (3.2.6)\n\nGIT\n  remote: https://evil.example/rack.git".into(),
                    );
                }),
            ),
            (
                "another gem's spec line",
                Box::new(|e| {
                    let lines = e.wiring[1]
                        .original
                        .as_mut()
                        .unwrap()
                        .as_array_mut()
                        .unwrap();
                    lines.insert(1, Value::String("    evil (6.6.6)".into()));
                }),
            ),
            (
                "another gem's dependency entry",
                Box::new(|e| {
                    let lines = e.wiring[1]
                        .original
                        .as_mut()
                        .unwrap()
                        .as_array_mut()
                        .unwrap();
                    lines.push(Value::String("  evil".into()));
                }),
            ),
        ];
        for (label, tamper) in cases {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let (result, entry, _) =
                unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{label}: {:?}", result.error);
            let mut entry = entry.unwrap();
            tamper(&mut entry);
            let wired = (
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
            );

            for dry_run in [true, false] {
                let outcome = revert_gem(&entry, &root, dry_run).await;
                assert!(!outcome.success, "{label}");
                let error = outcome.error.unwrap_or_default();
                assert!(error.contains("ledger record"), "{label}: {error}");
                assert!(!outcome.kept_artifact, "{label}");
            }
            let after = (
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
            );
            assert_eq!(after, wired, "{label}: neither file is written");
            assert!(root.join(copy_rel()).exists(), "{label}: the copy stays");
        }
    }

    /// A record the revert would refuse to write is not in the way once the
    /// pre-vendor declaration is back by hand: nothing is left to write
    /// for it, so the lock still follows.
    #[tokio::test]
    async fn revert_converges_once_a_refused_declaration_is_restored_by_hand() {
        // What a ledger written before the rewrite refused computed
        // arguments can hold.
        let computed = "gem \"rack\", rack_version_for(:prod)";
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (_, entry, _) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        let mut entry = entry.unwrap();
        entry.wiring[0].original = Some(Value::String(computed.to_string()));
        assert!(!revert_gem(&entry, &root, false).await.success);

        let by_hand = GEMFILE_DIRECT.replace("gem \"rack\", \"~> 3.1\"", computed);
        tokio::fs::write(root.join(GEMFILE), &by_hand)
            .await
            .unwrap();
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            by_hand
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(copy_rel()).exists());
    }

    /// The rewrite drops the positional arguments and the revert puts them
    /// back from the ledger, so a declaration whose positional argument is
    /// computed is refused up front: nothing is vendored that could not be
    /// reverted.
    #[tokio::test]
    async fn computed_positional_arguments_are_refused_before_anything_is_written() {
        for declaration in [
            "gem \"rack\", rack_version_for(:prod)",
            "gem \"rack\", File.read(\"RACK_VERSION\").strip",
            "gem \"rack\", \"~> #{version_for(:rack)}\"",
        ] {
            let gemfile = GEMFILE_DIRECT.replace("gem \"rack\", \"~> 3.1\"", declaration);
            let (_tmp, root, installed, blobs, record) = fixture(&gemfile, LOCK_DIRECT).await;
            let (code, detail) =
                unwrap_refused(run_vendor(&root, &blobs, &installed, &record, false).await);
            assert_eq!(
                code, "gemfile_declaration_not_editable",
                "{declaration}: {detail}"
            );
            assert!(
                detail.contains("computes a positional argument"),
                "{declaration}: {detail}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
                gemfile
            );
            assert!(!root.join(".socket/vendor").exists(), "{declaration}");
        }
    }

    /// Malformed / hand-stripped ledger records must degrade to a drift
    /// warning — never a partial splice. Each tamper is probed with a
    /// DRY-RUN revert (no writes), so one vendored fixture serves the whole
    /// matrix; the intact entry still reverts byte-exactly afterwards.
    #[tokio::test]
    async fn revert_tampered_ledger_records_drift_instead_of_partial_splice() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(entry.wiring.len(), 3, "gemfile + lock spec + checksum");
        let wired_gemfile = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let wired_lock = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        fn t_gemfile_new_none(e: &mut VendorEntry) {
            e.wiring[0].new = None;
        }
        fn t_gemfile_original_none(e: &mut VendorEntry) {
            e.wiring[0].original = None;
        }
        fn t_lock_original_not_array(e: &mut VendorEntry) {
            e.wiring[1].original = Some(Value::Bool(true));
        }
        fn t_lock_new_remote_tampered(e: &mut VendorEntry) {
            let arr = e.wiring[1].new.as_mut().unwrap().as_array_mut().unwrap();
            arr[1] = Value::String("  broken".to_string());
        }
        fn t_checksum_new_none(e: &mut VendorEntry) {
            e.wiring[2].new = None;
        }
        type Tamper = fn(&mut VendorEntry);
        let cases: [(&str, Tamper); 5] = [
            ("gemfile record without `new`", t_gemfile_new_none),
            (
                "rewritten gemfile record without `original`",
                t_gemfile_original_none,
            ),
            (
                "lock record with non-array `original`",
                t_lock_original_not_array,
            ),
            (
                "lock record whose `new` lost its remote line",
                t_lock_new_remote_tampered,
            ),
            ("checksum record without `new`", t_checksum_new_none),
        ];
        for (label, tamper) in cases {
            let mut tampered = entry.clone();
            tamper(&mut tampered);
            let outcome = revert_gem(&tampered, &root, true).await;
            assert!(outcome.success, "{label}: {:?}", outcome.error);
            let drift = outcome
                .warnings
                .iter()
                .filter(|w| w.code == "vendor_lock_entry_drifted")
                .count();
            assert_eq!(drift, 1, "{label}: {:?}", outcome.warnings);
            assert_eq!(
                tokio::fs::read(root.join(GEMFILE)).await.unwrap(),
                wired_gemfile,
                "{label}: dry run writes nothing"
            );
            assert_eq!(
                tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
                wired_lock,
                "{label}"
            );
            assert!(root.join(copy_rel_318()).exists(), "{label}");
        }

        // The intact entry still restores everything byte-exactly.
        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
        );
    }

    /// The lock lost the `!` dep pin: the spec record's precondition fails →
    /// that record drifts and the whole revert writes nothing (#988). Before,
    /// the checksum record and the Gemfile still restored, pairing a
    /// registry Gemfile line with a lock that keeps the PATH section.
    #[tokio::test]
    async fn revert_missing_dep_pin_leaves_both_files_alone() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let wired_gemfile = tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap();
        let no_pin = wired.replace("DEPENDENCIES\n  rack (= 3.1.8)!\n", "DEPENDENCIES\n");
        assert_ne!(no_pin, wired, "fixture edit must hit the pin");
        tokio::fs::write(root.join(GEMFILE_LOCK), &no_pin)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(drift, 1, "{:?}", outcome.warnings);
        assert!(
            outcome.kept_artifact && root.join(copy_rel_318()).exists(),
            "the lock still holds the PATH section: the copy dir is kept"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            no_pin,
            "the lock is left exactly as found"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            wired_gemfile,
            "the Gemfile keeps its `path:` while the lock keeps its PATH section"
        );
    }

    /// The whole CHECKSUMS section is gone: a lock without one carries no
    /// checksum for the gem, which is a valid registry lock, so the checksum
    /// record has converged. The spec splice and Gemfile restore normally
    /// and the artifact goes (with an all-or-nothing revert, calling this
    /// drift would wedge the entry until the user re-added the section).
    #[tokio::test]
    async fn revert_checksums_section_gone_is_converged() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        let wired = tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
            .await
            .unwrap();
        let no_section = wired.replace("CHECKSUMS\n  rack (3.1.8)\n\n", "");
        assert_ne!(no_section, wired, "fixture edit must drop the section");
        tokio::fs::write(root.join(GEMFILE_LOCK), &no_section)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let drift = outcome
            .warnings
            .iter()
            .filter(|w| w.code == "vendor_lock_entry_drifted")
            .count();
        assert_eq!(drift, 0, "{:?}", outcome.warnings);
        assert!(!outcome.kept_artifact);
        assert!(!root.join(copy_rel_318()).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            SPIKE_LOCK_CHECKSUMS_BEFORE
                .replace(&format!("CHECKSUMS\n{SPIKE_RACK_SHA_LINE}\n\n"), ""),
            "spec block + dep entry restored; no CHECKSUMS resurrected"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            SPIKE_GEMFILE_CHECKSUMS
        );
    }

    /// A hand-deleted managed block (the `Added` Gemfile record's written
    /// text is gone) is already in its reverted state — convergence, not
    /// drift (LIVENESS CONTRACT: an Added record with no original is
    /// reverted once absent) — so the lock restores and the artifact is
    /// removed without a drift-keep.
    #[tokio::test]
    async fn revert_added_block_gone_is_converged() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TRANSITIVE, LOCK_TRANSITIVE).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        tokio::fs::write(root.join(GEMFILE), GEMFILE_TRANSITIVE)
            .await
            .unwrap();

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert!(!outcome.kept_artifact);
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TRANSITIVE
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TRANSITIVE
        );
    }

    /// The CHECKSUM reader's FIFO twin of
    /// [`fifo_lock_fails_fast_instead_of_wedging`]: on a CHECKSUMS-vendored
    /// project the checksum record is restored FIRST (reverse order), so a
    /// FIFO planted as the lock must fail revert fast through
    /// `revert_lock_checksum_record`'s guarded reader.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_revert_via_checksum_reader() {
        let (_tmp, root, installed, blobs, record) =
            fixture_318(SPIKE_GEMFILE_CHECKSUMS, SPIKE_LOCK_CHECKSUMS_BEFORE).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();
        assert_eq!(
            entry.wiring[2].kind, LOCK_CHECKSUM_WIRING_KIND,
            "checksum record is last → restored first"
        );

        let lock_path = root.join(GEMFILE_LOCK);
        tokio::fs::remove_file(&lock_path).await.unwrap();
        mkfifo(&lock_path);

        let deadline = std::time::Duration::from_secs(5);
        let fut = revert_gem(&entry, &root, false);
        let Ok(outcome) = tokio::time::timeout(deadline, fut).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock_path);
            panic!("the checksum revert reader must fail fast on a FIFO");
        };
        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("unreadable Gemfile.lock"),
            "{:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "failed revert must not delete the artifacts"
        );
    }

    /// Reverting one of TWO vendored gems must walk past the other's PATH
    /// section to find its own; both reverts land the fixture pair
    /// byte-exactly with zero drift.
    #[tokio::test]
    async fn multi_gem_revert_walks_past_other_path_sections() {
        let (_tmp, root, installed_rack, blobs, record_rack) =
            fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let (installed_puma, record_puma) = add_puma_fixture(&installed_rack, &blobs).await;
        let (r_rack, e_rack, _) = unwrap_done(
            run_vendor_purl(PURL, &root, &blobs, &installed_rack, &record_rack, false).await,
        );
        assert!(r_rack.success, "{:?}", r_rack.error);
        let (r_puma, e_puma, _) = unwrap_done(
            run_vendor_purl(
                PURL_PUMA,
                &root,
                &blobs,
                &installed_puma,
                &record_puma,
                false,
            )
            .await,
        );
        assert!(r_puma.success, "{:?}", r_puma.error);

        // puma's PATH section sorts FIRST, so rack's revert must walk past it.
        let rack_out = revert_gem(&e_rack.unwrap(), &root, false).await;
        assert!(rack_out.success, "{:?}", rack_out.error);
        assert!(
            !rack_out
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            rack_out.warnings
        );
        let puma_out = revert_gem(&e_puma.unwrap(), &root, false).await;
        assert!(puma_out.success, "{:?}", puma_out.error);
        assert!(
            !puma_out
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            puma_out.warnings
        );

        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
        assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
        assert!(!root
            .join(format!(".socket/vendor/gem/{UUID_PUMA}"))
            .exists());
    }

    // ── edit_lock / grammar fail-closed units (coverage-gap) ──────────────

    /// A GEM section without a `specs:` stanza is not a lock this backend
    /// understands — fail closed.
    #[test]
    fn edit_lock_missing_specs_stanza_fails_closed() {
        let lock = LOCK_DIRECT.replace("  specs:\n", "");
        assert_ne!(lock, LOCK_DIRECT);
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a specs:-less GEM section must fail closed");
        assert!(err.contains("no specs: stanza"), "{err}");
    }

    /// Re-vendor guards: our previous PATH section must carry exactly the
    /// shape vendor wrote — a missing spec entry and a hand-edited extra
    /// line each fail closed instead of being rewired around.
    #[test]
    fn edit_lock_revendor_path_section_guards_fail_closed() {
        let tail = "\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n";

        let lost = format!(
            "PATH\n  remote: {rel}\n  specs:\n    other (1.0)\n{tail}",
            rel = copy_rel()
        );
        let err = edit_lock(&lost, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a PATH section without its spec entry must fail closed");
        assert!(err.contains("lost its"), "{err}");

        let edited = format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n  hand: edit\n{tail}",
            rel = copy_rel()
        );
        let err = edit_lock(&edited, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a hand-edited PATH section must fail closed");
        assert!(err.contains("not the shape vendor wrote"), "{err}");
    }

    /// A non-PATH leading section (a GIT source — a real-world lock shape)
    /// keeps the legacy insert-before-GEM fallback: our PATH section lands
    /// between the GIT section and GEM, everything else byte-preserved.
    #[test]
    fn edit_lock_git_leading_section_keeps_insert_before_gem() {
        let git =
            "GIT\n  remote: https://example.com/dep.git\n  revision: abc123\n  specs:\n    dep (1.0)\n\n";
        let lock = format!("{git}{LOCK_DIRECT}");
        let edit = edit_lock(&lock, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.text, format!("{git}{}", expected_lock_direct()));
    }

    /// Tail-grammar rejects: text after the closing paren (or deeper indent)
    /// makes an entry unparseable — these `None`s are what route malformed
    /// lines into the fail-closed "not parseable" refusals.
    #[test]
    fn spec_and_checksum_entry_tail_grammar_rejects() {
        assert_eq!(spec_entry("    rack (3.2.6)"), Some(("rack", "3.2.6")));
        assert_eq!(spec_entry("    rack (3.2.6)x"), None);
        assert_eq!(
            checksum_entry("  rack (3.1.8) sha256=abc"),
            Some(("rack", "3.1.8"))
        );
        assert_eq!(checksum_entry("  rack (3.2.6)x"), None);
        assert_eq!(checksum_entry("   deep (1)"), None);
    }

    /// The in-sync hot path must skip OTHER gems' CHECKSUMS entries: a
    /// rerun over the transitive fixture (puma's registry sha line present)
    /// is a no-op that records nothing and rewrites nothing.
    #[tokio::test]
    async fn checksums_rerun_hot_path_skips_foreign_entries() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let puma_sha_line =
            "  puma (6.4.2) sha256=9c4f1f9d8f7c3a1b5e2d6c8a0b4f7e1d3c5a9b8e7f6d4c2a1b3e5d7c9f8a6b4c";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.1.8)\n\nPLATFORMS\n  aarch64-linux\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n{puma_sha_line}\n{SPIKE_RACK_SHA_LINE}\n\nBUNDLED WITH\n   2.7.2\n"
        );
        let (_tmp, root, installed, blobs, record) = fixture_318(gemfile, &lock).await;
        let (r1, e1, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let gemfile1 = tokio::fs::read(root.join(GEMFILE)).await.unwrap();
        let lock1 = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();

        let (r2, e2, _) =
            unwrap_done(run_vendor_318(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            e2.is_none(),
            "puma's foreign sha line must not defeat the in-sync hot path"
        );
        assert_eq!(tokio::fs::read(root.join(GEMFILE)).await.unwrap(), gemfile1);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock1
        );
    }

    /// #826: the vendored rewrite replaces the declaration's whole line, so
    /// a second `;`-joined statement on it must refuse rather than vanish;
    /// a bare trailing `;` is a complete declaration and still rewrites.
    #[test]
    fn plan_gemfile_edit_semicolon_statements() {
        let rel = copy_rel();
        for gemfile in [
            "gem \"rack\", \"~> 3.1\"; gem \"rainbow\", \"3.1.1\"\n",
            "gem \"rack\", require: false;gem \"rainbow\" # pair\n",
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("a second statement on the line must refuse");
            assert!(err.contains("another statement"), "{gemfile:?}: {err}");
        }
        for (gemfile, want) in [
            (
                "gem \"rack\", \"~> 3.1\";\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", \"~> 3.1\"; # web\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\""),
            ),
            (
                "gem \"rack\", require: false;\n",
                format!("gem \"rack\", \"3.2.6\", path: \"{rel}\", require: false"),
            ),
        ] {
            match plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel) {
                Ok(GemfilePlan::Rewrite { new_line, .. }) => {
                    assert_eq!(new_line, want, "{gemfile:?}")
                }
                Ok(_) => panic!("{gemfile:?}: expected an in-place rewrite"),
                Err(e) => panic!("{gemfile:?}: {e}"),
            }
        }
    }

    /// [`plan_gemfile_edit`]'s refusal grammar, leg by leg — a wrong Gemfile
    /// rewrite executes on every `bundle`, so each unsafe shape must name
    /// its refusal (and the `gemspec` keyword must NOT block the Append).
    #[test]
    fn plan_gemfile_edit_refusal_grammar() {
        let rel = copy_rel();

        // (`GemfilePlan` is deliberately Debug-less, so refusals are pulled
        // out via `.err()` rather than `unwrap_err`.)
        let err = plan_gemfile_edit(
            "gem \"rack\", \"~> 3.0\"\ngem \"rack\"\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .err()
        .expect("duplicate declarations must refuse");
        assert!(err.contains("more than once"), "{err}");

        let err = plan_gemfile_edit("gem(\"rack\", \"~> 3.1\")\n", "rack", "3.2.6", &rel)
            .err()
            .expect("a parenthesized call must refuse");
        assert!(err.contains("parenthesized"), "{err}");

        let err = plan_gemfile_edit("gem \"rack\" if ENV[\"CI\"]\n", "rack", "3.2.6", &rel)
            .err()
            .expect("trailing non-option tokens must refuse");
        assert!(err.contains("unexpected tokens"), "{err}");

        let err = plan_gemfile_edit(
            "gem \"rack\", \"~> 3.1\" unless ENV[\"CI\"]\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .err()
        .expect("a conditional declaration must refuse");
        assert!(err.contains("conditional"), "{err}");

        // #340: the shared tail guard also catches continuations and
        // modifiers the old substring checks missed.
        for (gemfile, want) in [
            ("gem \"rack\", platforms: [\n  :mri]\n", "continues"),
            ("gem \"rack\", :require =>\n  false\n", "continues"),
            (
                "gem \"rack\", \"~> 3.1\"\tunless ENV[\"CI\"]\n",
                "conditional",
            ),
            ("gem \"rack\", require: false rescue nil\n", "rescue"),
            ("gem \"rack\", \"~> 3.1\" if::FEATURE\n", "conditional"),
            ("gem \"rack\", \"~> 3.1\" unless::FEATURE\n", "conditional"),
            (
                "gem \"rack\", \"~> 3.1\" if:enabled == ENV[\"MODE\"].to_sym\n",
                "conditional",
            ),
            (
                "gem \"rack\", require: <<~REQUIRE_PATH.chomp\n  rack\nREQUIRE_PATH\n",
                "continues",
            ),
            (
                "gem \"rack\", require: <<'REQUIRE_PATH'\nrack\nREQUIRE_PATH\n",
                "continues",
            ),
            (
                "gem \"rack\", require: \"#{<<~REQUIRE_PATH}\".chomp\n  rack\nREQUIRE_PATH\n",
                "continues",
            ),
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("a multi-line or modified declaration must refuse");
            assert!(err.contains(want), "{gemfile:?}: {err}");
        }

        for gemfile in [
            "gem \"rack\", mypath: \"y\"\n",
            "gem \"rack\", path: File.expand_path(\"x\")\n",
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .expect("path-shaped options must refuse");
            assert!(err.contains("path:"), "{gemfile:?}: {err}");
        }

        // #652: every git source refuses, whatever its key or spelling —
        // bundler's built-in `gitlab:`, a custom `git_source(:local)`, and
        // the string-keyed `"git" =>` — since a vendored `path:` next to it
        // is a second source bundler refuses.
        for (gemfile, tok) in [
            ("gem \"rack\", gitlab: \"rack/rack\"\n", "`gitlab:`"),
            (
                "git_source(:local) { |r| \"/srv/#{r}\" }\ngem \"rack\", local: \"rack\"\n",
                "`local:`",
            ),
            ("gem \"rack\", \"git\" => \"/srv/rack\"\n", "`\"git\" =>`"),
        ] {
            let err = plan_gemfile_edit(gemfile, "rack", "3.2.6", &rel)
                .err()
                .unwrap_or_else(|| panic!("{gemfile:?}: a git source must refuse"));
            assert!(err.contains(tok), "{gemfile:?}: {err}");
        }

        for options in [
            "require: { if: \"rack\" }.values",
            "require: \"<<REQUIRE_PATH\"",
            "require: '#{<<REQUIRE_PATH}'",
            "require: \"\\#{<<REQUIRE_PATH}\"",
            "group: :unless",
        ] {
            let gemfile = format!("gem \"rack\", {options}\n");
            let plan = plan_gemfile_edit(&gemfile, "rack", "3.2.6", &rel).unwrap();
            let GemfilePlan::Rewrite { new_line, .. } = plan else {
                panic!("a one-line declaration must rewrite: {gemfile}");
            };
            assert!(new_line.ends_with(options), "{new_line}");
        }

        // `gemspec name: "rack"` opens with the keyword but continues as an
        // identifier — NOT a gem-call mention; the transitive Append stays
        // available (the identifier-continuation guard must not false-fire).
        let plan = plan_gemfile_edit(
            "source \"https://rubygems.org\"\n\ngemspec name: \"rack\"\n",
            "rack",
            "3.2.6",
            &rel,
        )
        .unwrap();
        assert!(matches!(plan, GemfilePlan::Append { .. }));
    }

    /// The Append splice on a Gemfile with NO trailing newline must insert
    /// one before the managed block — never concatenate onto the last line.
    #[tokio::test]
    async fn append_inserts_newline_before_managed_block() {
        let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"";
        let (_tmp, root, installed, blobs, record) = fixture(gemfile, LOCK_TRANSITIVE).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            format!(
                "source \"https://rubygems.org\"\n\ngem \"puma\"\n{MANAGED_OPEN}\ngem \"rack\", \"3.2.6\", path: \"{}\", require: false\n{MANAGED_CLOSE}\n",
                copy_rel()
            ),
            "a newline is inserted before the block — never line concatenation"
        );
    }

    /// [`gemspec_declares_extensions`] alternate operators and the
    /// [`gemspec_attr_rhs`] line-start `==` comparison (not an assignment).
    #[test]
    fn gemspec_heuristic_operator_variants() {
        for decl in [
            "s.extensions << \"ext/e/extconf.rb\"",
            "s.extensions += [\"ext/e/extconf.rb\"]",
            "s.extensions.push(\"ext/e/extconf.rb\")",
            "s.extensions.concat([\"ext/e/extconf.rb\"])",
        ] {
            assert!(
                gemspec_declares_extensions(&format!(
                    "Gem::Specification.new do |s|\n  {decl}\nend\n"
                )),
                "{decl} must count as declaring extensions"
            );
        }
        assert!(
            !gemspec_declares_extensions("raise if s.extensions == [\"e\"]\n"),
            "a `==` comparison is not a declaration"
        );
        assert!(
            !gemspec_declares_extensions("s.extensions_dir = \"x\"\n"),
            "a longer identifier is not the attribute"
        );
        // A line-start `==` comparison is not an assignment for the
        // required-attribute bar either.
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors == [\"a\"]\n"),
            vec!["authors"]
        );
    }

    // ── swap / prune / grammar / unwind edges ───────

    /// A parentless `copy_dir` (e.g. the filesystem root) has no directory to
    /// place a same-dir sibling in; the fallback nests the suffix under the
    /// copy dir itself instead of panicking.
    #[test]
    fn swap_sibling_for_parentless_copy_dir_nests_suffix() {
        assert_eq!(
            swap_sibling_for(Path::new("/"), ".socket-stage"),
            PathBuf::from("/.socket-stage")
        );
    }

    /// The stage rename failing with NO previous copy parked (fresh vendor,
    /// stage vanished): the swap must bubble the error without inventing a
    /// copy dir or leaving a backup behind.
    #[tokio::test]
    async fn swap_failure_without_previous_copy_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("rack-3.2.6");
        let stage = stage_dir_for(&copy);
        assert!(
            swap_stage_into_place(&stage, &copy).await.is_err(),
            "swapping a missing stage with no old copy must fail"
        );
        assert!(!copy.exists(), "no half-made copy dir");
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// The PARK rename itself failing hard (an unwritable uuid dir — the same
    /// io::Error surface as a Windows file lock on the copy): the error
    /// bubbles and the live copy is left exactly where it was.
    #[cfg(unix)]
    #[tokio::test]
    async fn swap_park_failure_bubbles_and_keeps_live_copy() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let dir = tempfile::tempdir().unwrap();
        let uuid = dir.path().join("uuid");
        let copy = uuid.join("rack-3.2.6");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("f.rb"), b"live\n")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(&stage).await.unwrap();
        tokio::fs::set_permissions(&uuid, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let swapped = swap_stage_into_place(&stage, &copy).await;

        tokio::fs::set_permissions(&uuid, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        assert!(
            swapped.is_err(),
            "parking the old copy must fail under a read-only uuid dir"
        );
        assert_eq!(
            tokio::fs::read(copy.join("f.rb")).await.unwrap(),
            b"live\n",
            "the live copy must be untouched"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// `prune_empty_vendor_levels` removes exactly the three levels a failed
    /// run may have created (`<uuid>` → `gem` → `vendor`) and never climbs
    /// higher; a parentless uuid path has no levels above it and returns.
    #[tokio::test]
    async fn prune_empty_vendor_levels_removes_three_levels_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        let uuid = keep.join("vendor/gem").join(UUID);
        tokio::fs::create_dir_all(&uuid).await.unwrap();
        prune_empty_vendor_levels(&uuid).await;
        assert!(
            !keep.join("vendor").exists(),
            "all three empty levels pruned"
        );
        assert!(
            keep.exists(),
            "the prune never climbs past the vendor level"
        );

        // A sibling entry keeps the `gem` level non-empty: the empty uuid
        // level is still pruned, but the climb stops there — another gem's
        // vendor state must never be collateral of this run's cleanup.
        let busy = dir.path().join("busy");
        let uuid_b = busy.join("vendor/gem").join(UUID);
        tokio::fs::create_dir_all(&uuid_b).await.unwrap();
        tokio::fs::write(busy.join("vendor/gem/other-gem-marker"), b"x")
            .await
            .unwrap();
        prune_empty_vendor_levels(&uuid_b).await;
        assert!(!uuid_b.exists(), "the empty uuid level is pruned");
        assert!(
            busy.join("vendor/gem/other-gem-marker").exists(),
            "a non-empty gem level stops the prune"
        );

        // Parentless uuid path: nothing above to prune, returns cleanly.
        prune_empty_vendor_levels(Path::new("")).await;
    }

    /// DEPENDENCIES entries are exactly 2-space-indented and specs entries
    /// exactly 4: blank rests and deeper (continuation) indentation are not
    /// entries.
    #[test]
    fn dep_and_spec_entry_names_reject_blank_and_deeper_indentation() {
        assert_eq!(dep_entry_name("  rack (~> 3.1)"), Some("rack"));
        assert_eq!(dep_entry_name("  "), None);
        assert_eq!(dep_entry_name("    base64 (>= 0.1.0)"), None);
        assert_eq!(spec_entry_name("    rack (3.2.6)"), Some("rack"));
        assert_eq!(spec_entry_name("    "), None);
        assert_eq!(spec_entry_name("      base64 (>= 0.1.0)"), None);
    }

    /// A ledger entry for the fixture gem, and what its records are checked
    /// against.
    fn rack_entry() -> VendorEntry {
        VendorEntry::new(
            "gem".to_string(),
            PURL.to_string(),
            UUID.to_string(),
            VendorArtifact::dir(copy_rel(), Default::default()),
            Vec::new(),
        )
    }

    fn own_rack(entry: &VendorEntry) -> OwnGem<'_> {
        OwnGem {
            entry,
            name: "rack".to_string(),
            version: "3.2.6".to_string(),
        }
    }

    /// An unreadable (present but non-regular) Gemfile fails a `gemfile_line`
    /// revert loudly — unlike a MISSING one, which is reported as
    /// `vendor_lockfile_missing` (`FileMissing`, not drift) and does not
    /// block artifact removal.
    #[tokio::test]
    async fn revert_gemfile_record_unreadable_gemfile_is_an_error() {
        // A directory squats the Gemfile path: it is readable-as-path but
        // not a regular file, so the guarded read errors with a non-NotFound
        // kind.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(GEMFILE)).unwrap();
        let w = WiringRecord {
            file: GEMFILE.to_string(),
            kind: GEMFILE_WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some("rack".to_string()),
            original: Some(Value::String("gem \"rack\", \"~> 3.1\"".to_string())),
            new: Some(Value::String(format!(
                "gem \"rack\", path: \"{}\"",
                copy_rel()
            ))),
        };
        let entry = rack_entry();
        let err = revert_gemfile_record(&mut RevertFiles::new(dir.path()), &w, &own_rack(&entry))
            .await
            .expect_err("a directory squatting the Gemfile path must error");
        assert!(err.contains("unreadable Gemfile"), "{err}");
    }

    /// A `gemfile_lock_spec` record whose `new` is not a string array is
    /// drift (`Ok(RecordRevert::Drifted)`), decided BEFORE the lock is read — proven with a
    /// lock path that would error loudly (a directory) if it were read.
    #[tokio::test]
    async fn revert_lock_record_non_array_new_is_drift_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(GEMFILE_LOCK)).unwrap();
        let w = WiringRecord {
            file: GEMFILE_LOCK.to_string(),
            kind: LOCK_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some("rack".to_string()),
            original: Some(serde_json::json!(["    rack (3.2.6)"])),
            new: Some(Value::String("not-an-array".to_string())),
        };
        let entry = rack_entry();
        let restored = revert_lock_record(&mut RevertFiles::new(dir.path()), &w, &own_rack(&entry))
            .await
            .unwrap();
        assert_eq!(
            restored,
            RecordRevert::Drifted,
            "malformed `new` wiring is drift, not an error"
        );
    }

    /// The specs-splice scan steps over a line inside GEM/specs that is not
    /// a spec entry (a stray 6-space continuation with no parent entry)
    /// instead of breaking the splice or mis-sorting the restored block.
    #[test]
    fn revert_lock_text_steps_over_non_spec_lines_in_gem_specs() {
        let rel = ".socket/vendor/gem/u/aaa-1.0.0";
        let new_lines: Vec<String> = [
            "PATH",
            &format!("  remote: {rel}") as &str,
            "  specs:",
            "    aaa (1.0.0)",
            "",
            "  aaa (= 1.0.0)!",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let original_lines: Vec<String> = ["    aaa (1.0.0)", "  aaa (~> 1.0)"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let text = format!(
            "PATH\n  remote: {rel}\n  specs:\n    aaa (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n      orphan-continuation (~> 1.0)\n    zzz (1.0)\n\nDEPENDENCIES\n  aaa (= 1.0.0)!\n  zzz\n"
        );
        let restored = revert_lock_text(&text, &original_lines, &new_lines)
            .expect("an odd-but-parseable specs section must still revert");
        assert_eq!(
            restored,
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    aaa (1.0.0)\n      orphan-continuation (~> 1.0)\n    zzz (1.0)\n\nDEPENDENCIES\n  aaa (~> 1.0)\n  zzz\n"
        );
    }

    /// An anchored attribute mention that is not an assignment at all (no
    /// `=` after the attr — `.push(…)`) yields no RHS, so a push-only
    /// `authors` still fails the required-attribute bar.
    #[test]
    fn gemspec_attr_rhs_ignores_non_assignment_mentions() {
        assert!(
            gemspec_attr_rhs("s.authors.push(\"m\")\n", &["authors", "author"]).is_empty(),
            "a method call on the attribute is not an assignment"
        );
        assert_eq!(
            gemspec_missing_required_attrs("s.summary = \"x\"\ns.authors.push(\"m\")\n"),
            vec!["authors"]
        );
    }

    #[tokio::test]
    async fn local_swap_failure_reports_move_error_and_touches_nothing() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("rack-3.2.6.socket-old"), b"husk")
            .await
            .unwrap();

        let (result, entry, _w) = crate::vendor::test_support::expect_failed(
            run_vendor(&root, &blobs, &installed, &record, false).await,
        );
        assert!(!result.success, "the swap failure must fail the vendor");
        assert!(entry.is_none(), "no ledger entry for a failed vendor");
        let err = result.error.as_deref().unwrap_or("");
        assert!(
            err.contains("cannot move the extracted .gem into place"),
            "{err}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock untouched"
        );
        assert!(
            !uuid_dir.exists(),
            "a fresh-vendor failure unwinds the uuid dir"
        );
    }

    /// The SERVICE path's swap failing the same way hard-fails under its own
    /// `vendor_prebuilt_write_failed` code, with the project untouched.
    #[tokio::test]
    async fn service_swap_failure_hard_fails_and_unwinds() {
        let (_tmp, root, _installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        let sources = PatchSources::blobs_only(&blobs);
        let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("rack-3.2.6.socket-old"), b"husk")
            .await
            .unwrap();

        let outcome = crate::vendor::test_support::vendor_gem(
            PURL,
            &missing_install(&root),
            &root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&gem_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(
            detail.contains("cannot move the extracted .gem into place"),
            "{detail}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "Gemfile untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT,
            "lock untouched"
        );
        assert!(
            !uuid_dir.exists(),
            "a fresh-vendor failure unwinds the uuid dir"
        );
    }

    /// A Gemfile.lock write failure AFTER the Gemfile edit landed (macOS
    /// user-immutable flag on the lock: the atomic rename fails EPERM while
    /// the Gemfile in the same dir writes fine) unwinds the Gemfile to its
    /// recorded original bytes — the pair is never left half-wired — and
    /// removes the freshly-built uuid dir.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn lock_write_failure_unwinds_gemfile_and_uuid_dir() {
        if unsafe { libc::geteuid() } == 0 {
            return; // uchg semantics under root differ — the trigger is not guaranteed
        }
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let lock_path = root.join(GEMFILE_LOCK);
        let set = std::process::Command::new("chflags")
            .arg("uchg")
            .arg(&lock_path)
            .status()
            .expect("run chflags uchg");
        assert!(set.success(), "chflags uchg must succeed");

        let outcome = run_vendor(&root, &blobs, &installed, &record, false).await;

        let cleared = std::process::Command::new("chflags")
            .arg("nouchg")
            .arg(&lock_path)
            .status()
            .expect("run chflags nouchg");
        assert!(cleared.success(), "chflags nouchg must succeed");

        let (result, entry, _w) = unwrap_done(outcome);
        assert!(
            !result.success,
            "the lock write failure must fail the vendor"
        );
        assert!(entry.is_none(), "no ledger entry for a failed vendor");
        let err = result.error.as_deref().unwrap_or("");
        assert!(err.contains("failed to write Gemfile.lock"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT,
            "the Gemfile edit must be unwound to the original bytes"
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock_path).await.unwrap(),
            LOCK_DIRECT,
            "the failed rename must leave the lock byte-identical"
        );
        assert!(
            !root.join(format!(".socket/vendor/gem/{UUID}")).exists(),
            "the freshly-built uuid dir is unwound"
        );
    }

    // ── source flip: the hot path decides "in sync" from the
    //    COMMITTED copy before any service call, so a service ↔ local flip
    //    between runs is a byte-identical no-op with no request. ──

    async fn flip_run(
        root: &Path,
        installed: &Path,
        blobs: &Path,
        record: &PatchRecord,
        server: &wiremock::MockServer,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        let sources = PatchSources::blobs_only(blobs);
        unwrap_done(
            crate::vendor::test_support::vendor_gem(
                PURL,
                installed,
                root,
                record,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                Some(&gem_service_cfg(
                    &server.uri(),
                    VendorSource::Service,
                    false,
                )),
            )
            .await,
        )
    }

    async fn flip_granted() -> wiremock::MockServer {
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let sri = sri_sha512(&gem);
        let stub_sri = sri_sha512(SERVICE_STUB);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(&server, &gem, &sri, Some((SERVICE_STUB, &stub_sri))).await;
        server
    }

    #[tokio::test]
    async fn flip_service_then_local_is_noop() {
        use crate::vendor::test_support as ts;
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let up = flip_granted().await;
        let (r1, e1, w1) = flip_run(&root, &installed, &blobs, &record, &up).await;
        assert!(r1.success && e1.is_some());
        assert!(ts::has_warning(&w1, "vendor_prebuilt_downloaded"));
        assert_eq!(
            tokio::fs::read(copy_gemspec(&root)).await.unwrap(),
            SERVICE_STUB
        );
        let before = ts::tree_snapshot(&root);
        let down = wiremock::MockServer::start().await;
        ts::mount_503(&down).await;
        let (r2, e2, w2) = flip_run(&root, &installed, &blobs, &record, &down).await;
        assert!(r2.success);
        assert!(e2.is_none());
        assert!(
            w2.iter().all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{w2:?}"
        );
        assert_eq!(before, ts::tree_snapshot(&root));
        assert_eq!(ts::request_count(&down).await, 0);
    }

    /// Vendored from the service (served stub gemspec), the
    /// committed copy is lost and rebuilt LOCALLY (local gemspec → different
    /// tree). The ledger the CLI persists must carry the rebuilt tree's
    /// inventory, and its carried-forward wiring must still revert cleanly.
    #[tokio::test]
    async fn wired_rebuild_refreshes_ledger_inventory() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        let server = wiremock::MockServer::start().await;
        mount_gem_granted(
            &server,
            &gem,
            &sri_sha512(&gem),
            Some((SERVICE_STUB, &sri_sha512(SERVICE_STUB))),
        )
        .await;
        let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
        let (r1, e1, _) =
            unwrap_done(run_vendor_service(&root, &blobs, &installed, &record, &cfg).await);
        assert!(r1.success, "{:?}", r1.error);
        let e1 = e1.expect("first vendor records an entry");
        assert_eq!(
            crate::vendor::check_vendored_artifact(&root, &e1, &record).await,
            crate::vendor::ArtifactHealth::Healthy
        );

        tokio::fs::remove_file(copy_lib(&root)).await.unwrap();
        let (r2, e2, w2) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{w2:?}"
        );
        assert_eq!(
            tokio::fs::read_to_string(copy_gemspec(&root))
                .await
                .unwrap(),
            GEMSPEC,
            "precondition: the local rebuild used the local stub"
        );

        let ledger = match e2 {
            Some(mut fresh) => {
                crate::vendor::carry_forward_wiring(&e1, &mut fresh);
                fresh
            }
            None => e1.clone(),
        };
        assert_eq!(
            crate::vendor::check_vendored_artifact(&root, &ledger, &record).await,
            crate::vendor::ArtifactHealth::Healthy,
            "the ledger inventory must describe the rebuilt copy"
        );
        assert_eq!(
            ledger.wiring, e1.wiring,
            "Gemfile/lock revert records preserved"
        );
        let rv = revert_gem(&ledger, &root, false).await;
        assert!(rv.success, "{:?}", rv.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_DIRECT
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_DIRECT
        );
    }

    #[tokio::test]
    async fn integrity_mismatch_hard_fails_under_auto() {
        let gem = make_gem(&[("lib/rack.rb", PATCHED)]);
        for bad_stub in [false, true] {
            let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
            let server = wiremock::MockServer::start().await;
            let (gem_sri, stub_sri) = if bad_stub {
                (sri_sha512(&gem), sri_sha512(b"not the stub"))
            } else {
                (sri_sha512(b"different bytes"), sri_sha512(SERVICE_STUB))
            };
            mount_gem_granted(&server, &gem, &gem_sri, Some((SERVICE_STUB, &stub_sri))).await;
            let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
            let outcome = run_vendor_service(&root, &blobs, &installed, &record, &cfg).await;
            let VendorOutcome::Refused { code, .. } = outcome else {
                panic!("bad_stub={bad_stub}: tampered bytes fell back: {outcome:?}");
            };
            assert_eq!(
                code, "vendor_prebuilt_integrity_mismatch",
                "bad_stub={bad_stub}"
            );
            assert!(!root.join(format!(".socket/vendor/gem/{UUID}")).exists());
            assert_eq!(
                tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                    .await
                    .unwrap(),
                LOCK_DIRECT
            );
        }
    }

    /// `--vendor-source=service` with no configured client must
    /// fail closed, never quietly build locally.
    #[tokio::test]
    async fn service_mode_without_client_refuses() {
        let (_tmp, root, installed, blobs, record) = fixture(GEMFILE_DIRECT, LOCK_DIRECT).await;
        let mut cfg = gem_service_cfg("http://127.0.0.1:1", VendorSource::Service, false);
        cfg.client = None;
        let outcome = run_vendor_service(&root, &blobs, &installed, &record, &cfg).await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("service mode without a client built locally: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(".socket").exists(), "nothing written");
    }

    // ── #775: the takeover's declaration preflight ─────────────────────

    const TAKEOVER_IDX: &str = "https://patch.socket.dev/patch-registry/gem/11111111-1111-1111-1111-111111111111/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/";

    /// A converged, CHECKSUMS-less hosted lock (restoring it needs no
    /// registry lookup, so the preflight runs offline).
    fn hosted_takeover_lock() -> String {
        format!(
            "GEM\n  remote: {TAKEOVER_IDX}\n  specs:\n    rails (7.0.0)\n\nGEM\n  remote: \
             https://rubygems.org/\n  specs:\n    puma (6.0.0)\n\nPLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  puma\n  rails (= 7.0.0)!\n\nBUNDLED WITH\n   2.4.0\n"
        )
    }

    async fn takeover_preflight(gemfile: &str) -> (Option<(&'static str, String)>, PathBuf) {
        let dir = tempfile::tempdir().unwrap().keep();
        std::fs::write(dir.join(GEMFILE), gemfile).unwrap();
        std::fs::write(dir.join(GEMFILE_LOCK), hosted_takeover_lock()).unwrap();
        let pin = crate::patch::redirect::upstream::HostedPin {
            purl: "pkg:gem/rails@7.0.0".to_string(),
            uuid: UUID.to_string(),
            files: vec![GEMFILE.to_string(), GEMFILE_LOCK.to_string()],
        };
        let opts = crate::patch::redirect::upstream::RestoreOptions {
            dry_run: false,
            offline: true,
            patch_server_origins: Vec::new(),
            bun_lockb: true,
        };
        let refusal = gem_vendor_target_preflight(&dir, "pkg:gem/rails@7.0.0", &pin, &opts).await;
        (refusal, dir)
    }

    #[tokio::test]
    async fn takeover_preflight_refuses_a_hosted_gem_inside_a_group_block() {
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n\ngroup :development do\n\
             source \"{TAKEOVER_IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        let (code, detail) = refusal.expect("an indented declaration is not editable");
        assert_eq!(code, "gemfile_declaration_not_editable");
        assert!(detail.contains("indented"), "{detail}");
        // #2091: the gem is hosted already; the remedy reads true for it.
        assert!(detail.contains("leave rails to hosted mode"), "{detail}");
        assert_names_other_modes(&detail, &["hosted"]);
        // A preflight: the hosted pair is never written, even though the
        // caller's options are a wet run.
        assert_eq!(std::fs::read_to_string(dir.join(GEMFILE)).unwrap(), gemfile);
        assert_eq!(
            std::fs::read_to_string(dir.join(GEMFILE_LOCK)).unwrap(),
            hosted_takeover_lock()
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn takeover_preflight_passes_a_top_level_hosted_gem() {
        // The hosted source block is socket-patch's own wiring: evaluated on
        // the restored Gemfile, the declaration is a plain top-level line.
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n\nsource \"{TAKEOVER_IDX}\" do\n  \
             gem \"rails\", \"7.0.0\"\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        assert_eq!(refusal, None);
        assert_eq!(std::fs::read_to_string(dir.join(GEMFILE)).unwrap(), gemfile);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn takeover_preflight_leaves_a_refused_restore_to_the_takeover() {
        // A hand-edited hosted block the restore cannot unwind: the restore
        // refuses, and the takeover reports that itself
        // (`redirect_revert_failed`), not this gate.
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\ngroup :test do\nsource \"{TAKEOVER_IDX}\" do\n  \
             gem \"rails\", \"~> 7.0\"\nend\nend\n"
        );
        let (refusal, dir) = takeover_preflight(&gemfile).await;
        assert_eq!(refusal, None);
        std::fs::remove_dir_all(dir).ok();
    }

    // ── #779: a gem outside the lock's first GEM section ──────────────────

    /// Bundler 2.2+ writes one GEM section per rubygems source, sorted by
    /// remote, so a private source can put rubygems.org second.
    const GEMFILE_TWO_SOURCES: &str = "source \"https://rubygems.org\"\n\ngem \"puma\"\ngem \"rack\", \"~> 3.1\"\n\nsource \"https://gems.example.com\" do\n  gem \"aaa-internal\"\nend\n";
    const LOCK_TWO_SOURCES: &str = "GEM\n  remote: https://gems.example.com/\n  specs:\n    aaa-internal (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  aaa-internal!\n  puma\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";

    /// Bundler's own re-lock of [`LOCK_TWO_SOURCES`] with rack path-sourced
    /// (shape verified against bundler 4.0.17 `bundle lock --local`).
    fn expected_lock_two_sources() -> String {
        format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\nGEM\n  remote: https://gems.example.com/\n  specs:\n    aaa-internal (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  aaa-internal!\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n",
            rel = copy_rel()
        )
    }

    /// #779: the spec sits in the second GEM section. It used to fail with
    /// "GEM specs has no entry" although the lock lists it.
    #[test]
    fn edit_lock_lifts_spec_from_second_gem_section() {
        let edit = edit_lock(LOCK_TWO_SOURCES, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.text, expected_lock_two_sources());
        assert!(!edit.rewired_ours);
        assert_eq!(
            edit.removed_spec_block,
            vec!["    rack (3.2.6)", "      base64 (>= 0.1.0)"]
        );
        assert_eq!(
            edit.source_remote.as_deref(),
            Some("  remote: https://rubygems.org/")
        );
    }

    /// #2075: what counts as "the lock resolves this version". A spec
    /// entry in any section does, the portable gem or a platform build of
    /// it; a dependency subline, a DEPENDENCIES or CHECKSUMS entry, another
    /// version or a gem whose name only starts the same does not.
    #[test]
    fn listed_specs_reads_spec_entries_of_every_section() {
        let lists =
            |lock: &str, name: &str, version: &str| listed_specs(lock).contains(&(name, version));
        assert!(lists(LOCK_DIRECT, "rack", "3.2.6"));
        assert!(lists(LOCK_TWO_SOURCES, "rack", "3.2.6"));
        let crlf = LOCK_DIRECT.replace('\n', "\r\n");
        assert!(lists(&crlf, "rack", "3.2.6"));
        // Our own PATH section, a user's PATH or GIT section.
        assert!(lists(&expected_lock_two_sources(), "rack", "3.2.6"));
        let git = "GIT\n  remote: https://example.com/rack.git\n  revision: abc\n  specs:\n    rack (3.2.6)\n\nGEM\n  specs:\n\nDEPENDENCIES\n  rack!\n";
        assert!(lists(git, "rack", "3.2.6"));
        // A platform build of the version is still that version.
        let platform = "GEM\n  remote: https://rubygems.org/\n  specs:\n    ffi (1.17.2-x86_64-linux-gnu)\n\nCHECKSUMS\n  rake (13.0.6) sha256=00\n";
        assert!(lists(platform, "ffi", "1.17.2"));

        assert!(!lists(LOCK_DIRECT, "rack", "3.2.5"));
        assert!(!lists(LOCK_DIRECT, "rack", "3.2"));
        assert!(!lists(LOCK_DIRECT, "rack", "3.2.60"));
        assert!(!lists(LOCK_DIRECT, "rac", "3.2.6"));
        // `nio4r (~> 2.0)` and `base64 (>= 0.1.0)` are dependency sublines.
        assert!(!lists(LOCK_DIRECT, "base64", ">= 0.1.0"));
        assert!(!lists(platform, "ffi", "1.17"));
        assert!(!lists(platform, "rake", "13.0.6"));
        assert!(!lists("", "rack", "3.2.6"));
    }

    /// #2075: the refusals name exactly the gem purls the lock doesn't
    /// resolve, qualified or not, and leave every other ecosystem alone.
    #[tokio::test]
    async fn version_not_locked_refusals_name_only_unlocked_gems() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(GEMFILE), GEMFILE_DIRECT).unwrap();
        std::fs::write(tmp.path().join(GEMFILE_LOCK), LOCK_DIRECT).unwrap();
        let purls = [
            "pkg:gem/rack@3.2.6",
            "pkg:gem/rack@2.2.8",
            "pkg:gem/rake@13.0.6?platform=ruby",
            "pkg:gem/puma@6.4.2?platform=ruby",
            "pkg:npm/rake@13.0.6",
        ];
        let refused = gem_version_not_locked_refusals(tmp.path(), &purls).await;
        let names: Vec<&str> = refused.iter().map(|(purl, _)| purl.as_str()).collect();
        assert_eq!(
            names,
            ["pkg:gem/rack@2.2.8", "pkg:gem/rake@13.0.6?platform=ruby"]
        );
        for (_, (code, detail)) in &refused {
            assert_eq!(*code, GEM_VERSION_NOT_LOCKED);
            assert!(
                detail.contains("this project doesn't lock that version"),
                "{detail}"
            );
        }
        assert!(refused[0].1 .1.contains("does not resolve rack 2.2.8"));
    }

    /// With no readable lock, or a manifest bundler doesn't load, nothing
    /// is judged here: the backend's own refusal names the real problem.
    #[tokio::test]
    async fn version_not_locked_refusals_leave_other_problems_to_the_backend() {
        let purls = ["pkg:gem/rake@13.0.6"];
        let no_lock = tempfile::tempdir().unwrap();
        std::fs::write(no_lock.path().join(GEMFILE), GEMFILE_DIRECT).unwrap();
        assert!(gem_version_not_locked_refusals(no_lock.path(), &purls)
            .await
            .is_empty());

        let gems_rb = tempfile::tempdir().unwrap();
        std::fs::write(gems_rb.path().join(GEMFILE), GEMFILE_DIRECT).unwrap();
        std::fs::write(gems_rb.path().join(GEMFILE_LOCK), LOCK_DIRECT).unwrap();
        std::fs::write(gems_rb.path().join("gems.rb"), GEMFILE_DIRECT).unwrap();
        assert!(gem_manifest_refusal(gems_rb.path()).await.is_some());
        assert!(gem_version_not_locked_refusals(gems_rb.path(), &purls)
            .await
            .is_empty());
    }

    /// The first-section case keeps its ledger shape: no source remote is
    /// recorded, so ledgers written before #779 and after it agree.
    #[test]
    fn edit_lock_first_gem_section_records_no_source_remote() {
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.source_remote, None);
        let (original, _new) = lock_record_lines(&edit);
        assert!(original.iter().all(|l| !l.starts_with("  remote: ")));
    }

    /// SECURITY/fail-closed: the same `name (version)` in two GEM sections
    /// means the lock disagrees with bundler's one-spec-per-gem model.
    /// Lifting either copy would be a guess.
    #[test]
    fn edit_lock_spec_in_two_gem_sections_fails_closed() {
        let lock = LOCK_TWO_SOURCES.replace(
            "    aaa-internal (1.0.0)\n",
            "    aaa-internal (1.0.0)\n    rack (3.2.6)\n",
        );
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a spec listed in two GEM sections must fail closed");
        assert!(err.contains("more than one GEM section"), "{err}");
    }

    /// SECURITY/fail-closed: a platform-suffixed sibling in ANOTHER GEM
    /// section is still a lock that disagrees with the install.
    #[test]
    fn edit_lock_platform_sibling_in_other_gem_section_fails_closed() {
        let lock = LOCK_TWO_SOURCES.replace(
            "    aaa-internal (1.0.0)\n",
            "    aaa-internal (1.0.0)\n    rack (3.2.6-x86_64-linux)\n",
        );
        let err = edit_lock(&lock, "rack", "3.2.6", &copy_rel())
            .err()
            .expect("a platform sibling in any GEM section must fail closed");
        assert!(err.contains("platform-suffixed"), "{err}");
    }

    /// #779 end to end: vendor a gem from the second GEM section, then
    /// revert. The lock is Bundler's canonical form while vendored, and
    /// revert puts the spec back into the section it came from, restoring
    /// the original bytes exactly.
    #[tokio::test]
    async fn second_gem_section_vendor_and_revert_round_trip() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TWO_SOURCES, LOCK_TWO_SOURCES).await;

        let (result, entry, _w) =
            unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_two_sources()
        );

        // Idempotent re-run: nothing to change.
        let lock_before = tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap();
        let (r2, _e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert_eq!(
            tokio::fs::read(root.join(GEMFILE_LOCK)).await.unwrap(),
            lock_before
        );

        let outcome = revert_gem(&entry, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE)).await.unwrap(),
            GEMFILE_TWO_SOURCES
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TWO_SOURCES,
            "revert must restore the spec into the second GEM section"
        );
    }

    /// Re-vendor to a newer patch uuid (the spec now lives in our PATH
    /// section) keeps the source section recorded by the first run, so a
    /// later revert still targets the second GEM section.
    #[test]
    fn revert_lock_text_targets_recorded_gem_section() {
        let edit = edit_lock(LOCK_TWO_SOURCES, "rack", "3.2.6", &copy_rel()).unwrap();
        let (original, new) = lock_record_lines(&edit);
        assert_eq!(
            revert_lock_text(&edit.text, &original, &new).as_deref(),
            Some(LOCK_TWO_SOURCES)
        );
        // A regenerated lock that already put rack back into its section is
        // converged, not drifted.
        assert!(lock_record_converged(LOCK_TWO_SOURCES, &original, &new));
        // The recorded section vanished (the source was dropped): drift,
        // never a guess at another section.
        let gone = edit.text.replace(
            "  remote: https://rubygems.org/\n",
            "  remote: https://mirror.example/\n",
        );
        assert_eq!(revert_lock_text(&gone, &original, &new), None);
        assert!(!lock_record_converged(
            &LOCK_TWO_SOURCES.replace("https://rubygems.org/", "https://mirror.example/"),
            &original,
            &new
        ));
    }

    /// #779 re-vendor: a superseding patch uuid lifts the spec out of our
    /// own PATH section, and the carried-forward original still names the
    /// second GEM section, so revert restores the pre-vendor bytes.
    #[tokio::test]
    async fn second_gem_section_revendor_then_revert_restores_original() {
        let (_tmp, root, installed, blobs, record) =
            fixture(GEMFILE_TWO_SOURCES, LOCK_TWO_SOURCES).await;
        let (r1, e1, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry1 = e1.unwrap();

        let mut record2 = record.clone();
        record2.uuid = "0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b".to_string();
        let (r2, e2, _) = unwrap_done(run_vendor(&root, &blobs, &installed, &record2, false).await);
        assert!(r2.success, "re-vendor must succeed: {:?}", r2.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            expected_lock_two_sources().replace(UUID, &record2.uuid)
        );

        let mut entry2 = e2.unwrap();
        carry_forward_originals(&entry1, &mut entry2);
        let outcome = revert_gem(&entry2, &root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(GEMFILE_LOCK))
                .await
                .unwrap(),
            LOCK_TWO_SOURCES
        );
    }

    // ── #2090: a hosted gem's section sorts ahead of the upstream one ─────

    /// What a hosted scan of puma does to a lock: puma's spec moves into a
    /// GEM section of its own whose remote is the patch registry at
    /// `origin`, and its DEPENDENCIES entry gains the `!` source pin.
    /// Bundler sorts that section ahead of `https://rubygems.org/`.
    fn with_puma_hosted(lock: &str, origin: &str) -> String {
        let hosted = format!(
            "GEM\n  remote: {origin}/patch-registry/gem/tok123/2fc039c8-b97d-545c-b447-879e2b468dfe/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n"
        );
        let out = lock
            .replacen(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n",
                &hosted,
                1,
            )
            .replacen("\n  puma\n", "\n  puma!\n", 1);
        assert!(
            out.contains(&hosted) && out.contains("\n  puma!\n"),
            "the fixture must move puma to a hosted section:\n{out}"
        );
        out
    }

    /// #2090: rack was vendored out of the lock's only GEM section, so its
    /// record names no section. A hosted scan of puma then put a patch
    /// registry section first. Revert must restore rack into the
    /// rubygems.org section it came from, not into puma's.
    #[test]
    fn revert_lock_text_skips_a_hosted_gem_section() {
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(edit.source_remote, None);
        let (original, new) = lock_record_lines(&edit);
        // Socket's own host, and a self-hosted or mock patch server.
        for origin in ["https://patch.socket.dev", "http://127.0.0.1:8791"] {
            let both = with_puma_hosted(&edit.text, origin);
            let want = with_puma_hosted(LOCK_DIRECT, origin);
            assert_eq!(
                revert_lock_text(&both, &original, &new).as_deref(),
                Some(want.as_str()),
                "{origin}"
            );
            // The reverted lock is the record's converged state, and the
            // corrupt one (rack in puma's section) is not.
            assert!(lock_record_converged(&want, &original, &new), "{origin}");
            let corrupt = want
                .replacen("    rack (3.2.6)\n      base64 (>= 0.1.0)\n", "", 1)
                .replacen(
                    "      nio4r (~> 2.0)\n",
                    "      nio4r (~> 2.0)\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n",
                    1,
                );
            assert!(
                !lock_record_converged(&corrupt, &original, &new),
                "{origin}"
            );
        }
    }

    /// #2090: with every upstream spec vendored or hosted, bundler still
    /// writes the rubygems.org section (empty), and revert restores into
    /// it. A lock with nothing but hosted sections has no section the
    /// block could have come from: drift, never a guess.
    #[test]
    fn revert_lock_text_never_restores_into_a_hosted_only_lock() {
        let rack_only = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.22\n";
        let edit = edit_lock(rack_only, "rack", "3.2.6", &copy_rel()).unwrap();
        let (original, new) = lock_record_lines(&edit);
        let hosted_section = "GEM\n  remote: https://patch.socket.dev/patch-registry/gem/tok123/2fc039c8-b97d-545c-b447-879e2b468dfe/\n  specs:\n    puma (6.4.2)\n\n";
        let with_hosted = |lock: &str| lock.replacen("GEM\n", &format!("{hosted_section}GEM\n"), 1);
        assert_eq!(
            revert_lock_text(&with_hosted(&edit.text), &original, &new),
            Some(with_hosted(rack_only))
        );
        let hosted_only = edit.text.replacen(
            "  remote: https://rubygems.org/\n",
            "  remote: https://patch.socket.dev/patch-registry/gem/tok123/2fc039c8-b97d-545c-b447-879e2b468dfe/\n",
            1,
        );
        assert_eq!(revert_lock_text(&hosted_only, &original, &new), None);
    }

    /// #2090: a GEM section that merges a patch registry remote with an
    /// upstream one (the bundler < 2.2 lock layout) still holds upstream
    /// specs, so it is where an unrecorded block goes back.
    #[test]
    fn revert_lock_text_keeps_a_merged_gem_section() {
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        let (original, new) = lock_record_lines(&edit);
        let merge = |lock: &str| {
            lock.replacen(
                "  remote: https://rubygems.org/\n",
                "  remote: https://patch.socket.dev/patch-registry/gem/tok123/2fc039c8-b97d-545c-b447-879e2b468dfe/\n  remote: https://rubygems.org/\n",
                1,
            )
        };
        assert_eq!(
            revert_lock_text(&merge(&edit.text), &original, &new),
            Some(merge(LOCK_DIRECT))
        );
    }

    /// #2090: only a gem patch registry marks a hosted gem's section. An
    /// upstream source whose URL merely has another Socket path shape is
    /// the user's own, and an unrecorded block goes back into it.
    #[test]
    fn revert_lock_text_keeps_a_section_that_is_not_a_gem_patch_registry() {
        let edit = edit_lock(LOCK_DIRECT, "rack", "3.2.6", &copy_rel()).unwrap();
        let (original, new) = lock_record_lines(&edit);
        let mirror = |lock: &str| {
            lock.replacen(
                "https://rubygems.org/",
                "https://mirror.example/patch/gem/2fc039c8-b97d-545c-b447-879e2b468dfe/",
                1,
            )
        };
        assert_eq!(
            revert_lock_text(&mirror(&edit.text), &original, &new),
            Some(mirror(LOCK_DIRECT))
        );
    }

    /// #2090: record and revert agree on what "no recorded section" means.
    /// A spec lifted from a hosted gem's section records that section even
    /// when it is the lock's first, so revert puts it back there and not
    /// into the first upstream section.
    #[test]
    fn edit_lock_records_a_hosted_source_section() {
        let lock = with_puma_hosted(LOCK_DIRECT, "https://patch.socket.dev");
        let hosted_remote = "  remote: https://patch.socket.dev/patch-registry/gem/tok123/2fc039c8-b97d-545c-b447-879e2b468dfe/";

        let rack = edit_lock(&lock, "rack", "3.2.6", &copy_rel()).unwrap();
        assert_eq!(
            rack.source_remote.as_deref(),
            Some("  remote: https://rubygems.org/")
        );
        let (original, new) = lock_record_lines(&rack);
        assert_eq!(
            revert_lock_text(&rack.text, &original, &new).as_deref(),
            Some(lock.as_str())
        );

        let puma_rel = copy_rel().replace("rack-3.2.6", "puma-6.4.2");
        let puma = edit_lock(&lock, "puma", "6.4.2", &puma_rel).unwrap();
        assert_eq!(puma.source_remote.as_deref(), Some(hosted_remote));
        let (original, new) = lock_record_lines(&puma);
        assert_eq!(
            revert_lock_text(&puma.text, &original, &new).as_deref(),
            Some(lock.as_str())
        );
    }

    /// A gem bundler locked as precompiled platform gems (see the module
    /// docs): vendored from the patch service's prebuilds, one tree per
    /// locked platform.
    mod platform_gems {
        use super::*;
        use crate::vendor::test_support as ts;
        use crate::vendor::{check_vendored_artifact, ArtifactHealth};

        const NOKO: &str = "pkg:gem/nokogiri@1.18.10?platform=ruby";
        const UUID_B: &str = "b0b0b0b0-0000-4000-8000-000000000002";
        const DARWIN: &str = "arm64-darwin";
        const LINUX: &str = "x86_64-linux-gnu";
        const RB: &str = "lib/nokogiri/version.rb";
        const SO: &str = "lib/nokogiri/nokogiri.so";
        const C: &str = "ext/nokogiri/xml_node.c";
        const RB_PRISTINE: &[u8] = b"module Nokogiri\n  VERSION = \"1.18.10\"\nend\n";
        const RB_PATCHED: &[u8] =
            b"module Nokogiri\n  VERSION = \"1.18.10\"\n  SOCKET_PATCHED = true\nend\n";
        const GEMFILE_NOKO: &str =
            "source \"https://rubygems.org\"\n\ngem \"nokogiri\", \"~> 1.18\"\ngem \"puma\"\n";
        const BLOCKS: &str = "    nokogiri (1.18.10-arm64-darwin)\n      racc (~> 1.4)\n    nokogiri (1.18.10-x86_64-linux-gnu)\n      racc (~> 1.4)\n";
        const TAIL: &str = "PLATFORMS\n  arm64-darwin\n  x86_64-linux-gnu\n\n";

        fn rel(uuid: &str) -> String {
            format!(".socket/vendor/gem/{uuid}/nokogiri-1.18.10")
        }

        /// A registry CHECKSUMS token (`ch` repeated to a sha256's length).
        fn sha(ch: char) -> String {
            format!(" sha256={}", ch.to_string().repeat(64))
        }

        /// A CHECKSUMS section whose two nokogiri entries end in `darwin` and
        /// `linux` (a registry token from [`sha`], or nothing for the bare
        /// form of a path gem).
        fn checksums(darwin: &str, linux: &str) -> String {
            format!(
                "CHECKSUMS\n  nokogiri (1.18.10-arm64-darwin){darwin}\n  nokogiri (1.18.10-x86_64-linux-gnu){linux}\n  puma (6.4.2){}\n  racc (1.8.1){}\n\n",
                sha('c'),
                sha('d')
            )
        }

        /// Bundler's lock of a project that takes nokogiri as precompiled
        /// platform gems, with the CHECKSUMS section of a bundler >= 2.6
        /// lock when `checksums` is one.
        fn lock(checksums: Option<&str>) -> String {
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n{BLOCKS}    puma (6.4.2)\n      nio4r (~> 2.0)\n    racc (1.8.1)\n\n{TAIL}DEPENDENCIES\n  nokogiri (~> 1.18)\n  puma\n\n{}BUNDLED WITH\n   2.5.22\n",
                checksums.unwrap_or_default()
            )
        }

        /// [`lock`] as vendoring leaves it for the copy at `rel`.
        fn vendored(rel: &str, checksums: Option<&str>) -> String {
            format!(
                "PATH\n  remote: {rel}\n  specs:\n{BLOCKS}\nGEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n    racc (1.8.1)\n\n{TAIL}DEPENDENCIES\n  nokogiri (= 1.18.10)!\n  puma\n\n{}BUNDLED WITH\n   2.5.22\n",
                checksums.unwrap_or_default()
            )
        }

        fn record(uuid: &str, files: &[(&str, &[u8], &[u8])]) -> PatchRecord {
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2026-06-09T00:00:00Z".to_string(),
                files: files
                    .iter()
                    .map(|(path, before, after)| {
                        (
                            path.to_string(),
                            PatchFileInfo {
                                before_hash: compute_git_sha256_from_bytes(before),
                                after_hash: compute_git_sha256_from_bytes(after),
                            },
                        )
                    })
                    .collect(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            }
        }

        /// A bundler project locking nokogiri with `lock`, and the patch of
        /// its `lib/nokogiri/version.rb`.
        async fn project(lock: &str) -> (tempfile::TempDir, PathBuf, PatchRecord) {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("project");
            tokio::fs::create_dir_all(&root).await.unwrap();
            tokio::fs::write(root.join(GEMFILE), GEMFILE_NOKO)
                .await
                .unwrap();
            tokio::fs::write(root.join(GEMFILE_LOCK), lock)
                .await
                .unwrap();
            (dir, root, record(UUID, &[(RB, RB_PRISTINE, RB_PATCHED)]))
        }

        /// The stub gemspec the service serves for `platform`'s prebuild.
        fn stub(platform: &str) -> Vec<u8> {
            format!(
                "# -*- encoding: utf-8 -*-\n# stub: nokogiri 1.18.10 {platform} lib\n\nGem::Specification.new do |s|\n  s.name = \"nokogiri\".freeze\n  s.version = \"1.18.10\".freeze\n  s.platform = \"{platform}\".freeze\n  s.summary = \"fixture\".freeze\n  s.authors = [\"fixture\".freeze]\n  s.require_paths = [\"lib\".freeze]\n  s.add_runtime_dependency(%q<racc>.freeze, [\"~> 1.4\".freeze])\nend\n"
            )
            .into_bytes()
        }

        /// How the gem patch's registry lists one platform gem of the
        /// version (`gemBuilds`).
        #[derive(Clone, Copy, PartialEq)]
        enum Listed {
            /// With the patch of its patched build.
            Patched,
            /// As upstream's own gem: no patched build (`patchUuid: null`).
            PassThrough,
            /// Not at all.
            Unlisted,
        }

        /// What the service answers for the reference of a platform's own
        /// patch.
        #[derive(Clone, Copy, PartialEq)]
        enum Own {
            /// A grant, with the artifacts the patch serves.
            Granted,
            /// This `status`, which is no grant, and no artifact.
            Status(&'static str),
            /// Nothing: the response leaves the patch out.
            LeftOut,
        }

        /// What the patch service has for one platform gem: how the gem
        /// patch's registry lists it, what the reference of the platform's
        /// own patch answers, and what that patch serves: the patched
        /// platform gem (its `tarball`) and the stub
        /// gemspec (`None` leaves that artifact out of the patch's
        /// reference), the sha512 that reference states for the gem when
        /// not its own, and the sha256 the registry lists for it when not
        /// its own.
        struct Served {
            platform: &'static str,
            listed: Listed,
            own: Own,
            gem: Option<Vec<u8>>,
            stub: Option<Vec<u8>>,
            gem_sha512: Option<String>,
            listed_sha256: Option<String>,
            /// The files the record of the platform's own patch names.
            files: BTreeMap<String, PatchFileInfo>,
        }

        /// The Ruby file of `platform`'s patched build. The service stamps
        /// the files of each patch with that patch's own header, so no two
        /// builds of a fix, nor a build and the gem's own patch, ship the
        /// same bytes for it.
        fn stamped(platform: &str) -> Vec<u8> {
            [
                format!("# Socket patch of the {platform} build\n").as_bytes(),
                RB_PATCHED,
            ]
            .concat()
        }

        /// The files `platform`'s own patch changes, as its record states
        /// them: the stamped Ruby file and the binary built for it.
        fn build_files(platform: &str) -> BTreeMap<String, PatchFileInfo> {
            let file = |before: &[u8], after: &[u8]| PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(before),
                after_hash: compute_git_sha256_from_bytes(after),
            };
            BTreeMap::from([
                (RB.to_string(), file(RB_PRISTINE, &stamped(platform))),
                (
                    SO.to_string(),
                    file(b"upstream's binary", platform.as_bytes()),
                ),
            ])
        }

        /// `platform`'s patched build: the patched Ruby file and the
        /// platform's own binary, with its stub.
        fn served(platform: &'static str) -> Served {
            Served {
                platform,
                listed: Listed::Patched,
                own: Own::Granted,
                gem: Some(make_gem(&[
                    (RB, &stamped(platform)),
                    (SO, platform.as_bytes()),
                ])),
                stub: Some(stub(platform)),
                gem_sha512: None,
                listed_sha256: None,
                files: build_files(platform),
            }
        }

        /// The patch of `platform`'s patched build of the fix `uuid`.
        fn build_uuid(uuid: &str, platform: &str) -> String {
            let tag = &crate::utils::digest::sha256_hex_of(platform.as_bytes())[..8];
            format!("{tag}{}", &uuid[8..])
        }

        /// A patch service answering for the gem patch `uuid` and for the
        /// patch of each patched build of `builds`, in the shape of the
        /// wire contract: the gem patch's reference lists `builds` under
        /// `gemBuilds` (`list: false` leaves the list out, a patch of the
        /// ruby gem alone), and each platform's own patch serves that
        /// platform's gem and stub. A reference request is answered for
        /// the uuids it names.
        async fn serve(
            uuid: &str,
            builds: &[Served],
            list: bool,
        ) -> (wiremock::MockServer, VendorServiceConfig) {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, ResponseTemplate};
            let server = wiremock::MockServer::start().await;
            let mut files: Vec<(String, Vec<u8>)> = Vec::new();
            let mut artifact = |kind: &str,
                                route: String,
                                bytes: &[u8],
                                sha512: Option<&String>| {
                files.push((route.clone(), bytes.to_vec()));
                serde_json::json!({
                    "kind": kind,
                    "url": format!("{}{route}", server.uri()),
                    "contentType": "application/octet-stream",
                    "sizeBytes": bytes.len(),
                    "integrity": { "sha512": sha512.cloned().unwrap_or_else(|| sri_sha512(bytes)) }
                })
            };
            let base = |uuid: &str| format!("/patch/gem/nokogiri/1.18.10/tok/{uuid}");
            let mut results = serde_json::Map::new();
            let mut gem_builds: Vec<serde_json::Value> = Vec::new();
            for build in builds {
                let platform = build.platform;
                let own = build_uuid(uuid, platform);
                let listed_sha256 = build.listed_sha256.clone().unwrap_or_else(|| {
                    crate::utils::digest::sha256_hex_of(build.gem.as_deref().unwrap_or_default())
                });
                match build.listed {
                    Listed::Unlisted => continue,
                    Listed::PassThrough => {
                        gem_builds.push(serde_json::json!({
                            "platform": platform, "gemChecksumSha256": listed_sha256,
                            "patchUuid": null
                        }));
                        continue;
                    }
                    Listed::Patched => gem_builds.push(serde_json::json!({
                        "platform": platform, "gemChecksumSha256": listed_sha256,
                        "patchUuid": own
                    })),
                }
                match build.own {
                    Own::Granted => {}
                    Own::LeftOut => continue,
                    Own::Status(status) => {
                        results.insert(
                            own,
                            serde_json::json!({ "status": status, "url": null, "artifacts": [] }),
                        );
                        continue;
                    }
                }
                let mut artifacts = Vec::new();
                if let Some(gem) = &build.gem {
                    let route = format!("{}/nokogiri-1.18.10-{platform}.gem", base(&own));
                    artifacts.push(artifact("tarball", route, gem, build.gem_sha512.as_ref()));
                }
                if let Some(stub) = &build.stub {
                    let route = format!("{}/nokogiri-1.18.10-{platform}.gemspec", base(&own));
                    artifacts.push(artifact("gem-stub-gemspec", route, stub, None));
                }
                // The record of the build's own patch, without contents.
                let view = serde_json::json!({
                    "uuid": own,
                    "purl": format!("pkg:gem/nokogiri@1.18.10?platform={platform}"),
                    "publishedAt": "2026-06-09T00:00:00Z",
                    "files": build.files,
                    "vulnerabilities": {},
                    "description": "", "license": "", "tier": "free"
                });
                Mock::given(method("GET"))
                    .and(path(format!("/v0/orgs/acme/patches/view/{own}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(view))
                    .mount(&server)
                    .await;
                results.insert(
                    own,
                    serde_json::json!({
                        "status": "granted",
                        "purl": "pkg:gem/nokogiri@1.18.10",
                        "artifacts": artifacts
                    }),
                );
            }
            gem_builds.sort_by_key(|build| build["platform"].as_str().map(str::to_string));
            let ruby_gem = make_gem(&[(RB, RB_PATCHED), (C, &b"patched C\n"[..])]);
            let route = format!("{}/nokogiri-1.18.10.gem", base(uuid));
            let mut identifiers = serde_json::json!({
                "name": "nokogiri", "version": "1.18.10",
                "gemChecksumSha256": crate::utils::digest::sha256_hex_of(&ruby_gem)
            });
            let mut index_url = format!("{}/patch-registry/gem/tok/{uuid}", server.uri());
            if list {
                identifiers["gemBuilds"] = serde_json::Value::Array(gem_builds);
                index_url.push_str("/s/4");
            }
            results.insert(
                uuid.to_string(),
                serde_json::json!({
                    "status": "granted",
                    "purl": NOKO,
                    "url": format!("{}{route}", server.uri()),
                    "artifacts": [artifact("tarball", route, &ruby_gem, None)],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": index_url,
                        "identifiers": identifiers
                    }
                }),
            );
            for (route, bytes) in files {
                Mock::given(method("GET"))
                    .and(path(route))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                    .mount(&server)
                    .await;
            }
            Mock::given(method("POST"))
                .and(path("/v0/orgs/acme/patches/package"))
                .respond_with(move |request: &wiremock::Request| {
                    let asked: serde_json::Value =
                        serde_json::from_slice(&request.body).unwrap_or_default();
                    let answered: serde_json::Map<String, serde_json::Value> = asked["uuids"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|uuid| {
                            let uuid = uuid.as_str()?;
                            Some((uuid.to_string(), results.get(uuid)?.clone()))
                        })
                        .collect();
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "results": answered }))
                })
                .mount(&server)
                .await;
            let cfg = gem_service_cfg(&server.uri(), VendorSource::Service, false);
            (server, cfg)
        }

        /// [`serve`] with the platform gems listed.
        async fn service(
            uuid: &str,
            builds: &[Served],
        ) -> (wiremock::MockServer, VendorServiceConfig) {
            serve(uuid, builds, true).await
        }

        /// The uuids each package reference request to `server` named, in
        /// the order the requests arrived.
        async fn reference_requests(server: &wiremock::MockServer) -> Vec<Vec<String>> {
            let requests = server.received_requests().await.unwrap_or_default();
            requests
                .iter()
                .filter(|request| request.method.as_str() == "POST")
                .map(|request| {
                    let asked: serde_json::Value =
                        serde_json::from_slice(&request.body).unwrap_or_default();
                    let uuids = asked["uuids"].as_array().into_iter().flatten();
                    uuids
                        .filter_map(|uuid| Some(uuid.as_str()?.to_string()))
                        .collect()
                })
                .collect()
        }

        /// The paths of the files downloaded from `server`.
        async fn downloads(server: &wiremock::MockServer) -> Vec<String> {
            let requests = server.received_requests().await.unwrap_or_default();
            requests
                .iter()
                .filter(|request| request.method.as_str() == "GET")
                .map(|request| request.url.path().to_string())
                .filter(|path| !path.starts_with("/v0/"))
                .collect()
        }

        /// What the ledger records of `platform`'s tree vendored from
        /// [`served`]'s build of the fix `uuid`.
        fn built(uuid: &str, platform: &'static str) -> GemBuildEntry {
            let build = served(platform);
            GemBuildEntry {
                platform: platform.to_string(),
                uuid: build_uuid(uuid, platform),
                gem_integrity: sri_sha512(build.gem.as_deref().unwrap()),
                gemspec_integrity: sri_sha512(build.stub.as_deref().unwrap()),
                files: build_files(platform),
            }
        }

        /// A source that is not installed (a lock-only checkout).
        fn not_installed(root: &Path) -> PathBuf {
            root.join(".socket/vendor/.uninstalled")
        }

        async fn vendor(
            root: &Path,
            installed: &Path,
            record: &PatchRecord,
            cfg: &VendorServiceConfig,
            dry_run: bool,
        ) -> VendorOutcome {
            let blobs = root.join("no-blobs");
            let sources = PatchSources::blobs_only(&blobs);
            ts::vendor_gem(
                NOKO,
                installed,
                root,
                record,
                &sources,
                "2026-06-09T00:00:00Z",
                dry_run,
                false,
                Some(cfg),
            )
            .await
        }

        async fn text(path: PathBuf) -> String {
            tokio::fs::read_to_string(path).await.unwrap()
        }

        /// Vendor the project at `root` from `cfg`'s service and persist the
        /// ledger entry the way the CLI does (carry-forward included).
        async fn vendor_and_persist(
            root: &Path,
            record: &PatchRecord,
            cfg: &VendorServiceConfig,
        ) -> VendorEntry {
            let (result, entry, _) =
                unwrap_done(vendor(root, &not_installed(root), record, cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            ts::persist(root, NOKO, entry.expect("a ledger entry")).await;
            crate::vendor::load_state(root).await.unwrap().entries[NOKO].clone()
        }

        /// The capability: every platform block moves into one PATH section,
        /// each platform gets the tree and stub of its own patch's gem, the
        /// ledger records each tree's patch and digests and (when the lock
        /// had them) every registry CHECKSUMS line, a second run is a
        /// no-op, the copy verifies, and revert restores the Gemfile and
        /// the lock byte for byte. The service is asked for two package
        /// references: the gem patch's, then both platform patches' in one
        /// request.
        #[tokio::test]
        async fn vendors_each_platform_from_its_own_patch_and_reverts_byte_for_byte() {
            let registry = checksums(&sha('a'), &sha('b'));
            for before in [None, Some(registry.as_str())] {
                let lock_before = lock(before);
                let (_tmp, root, record) = project(&lock_before).await;
                let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
                let (result, entry, warnings) =
                    unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
                assert!(result.success, "{:?}", result.error);
                let entry = entry.expect("a ledger entry");

                // One tree per platform, each with its own stub.
                let rel = rel(UUID);
                for platform in [DARWIN, LINUX] {
                    let tree = root.join(&rel).join(platform);
                    assert_eq!(
                        tokio::fs::read(tree.join(RB)).await.unwrap(),
                        stamped(platform),
                        "each tree holds its own patch's file, not the gem patch's"
                    );
                    assert_eq!(
                        tokio::fs::read(tree.join(SO)).await.unwrap(),
                        platform.as_bytes()
                    );
                    assert_eq!(
                        tokio::fs::read(tree.join("nokogiri.gemspec"))
                            .await
                            .unwrap(),
                        stub(platform)
                    );
                }
                assert!(!root.join(&rel).join("nokogiri.gemspec").exists());

                // The pair edit.
                assert_eq!(
                    text(root.join(GEMFILE)).await,
                    GEMFILE_NOKO.replace(
                        "gem \"nokogiri\", \"~> 1.18\"",
                        &format!("gem \"nokogiri\", \"1.18.10\", path: \"{rel}\"")
                    )
                );
                let bare = before.map(|_| checksums("", ""));
                assert_eq!(
                    text(root.join(GEMFILE_LOCK)).await,
                    vendored(&rel, bare.as_deref())
                );

                // The requests: the gem patch's reference says which
                // patch each locked platform's build is, the platform
                // patches' references come in ONE request, and only the
                // platform gems and their stubs are downloaded.
                assert_eq!(
                    reference_requests(&server).await,
                    [
                        vec![UUID.to_string()],
                        vec![build_uuid(UUID, DARWIN), build_uuid(UUID, LINUX)],
                    ]
                );
                let mut fetched = downloads(&server).await;
                fetched.sort();
                let file = |platform: &str, ext: &str| {
                    let own = build_uuid(UUID, platform);
                    format!(
                        "/patch/gem/nokogiri/1.18.10/tok/{own}/nokogiri-1.18.10-{platform}.{ext}"
                    )
                };
                let mut expected = vec![
                    file(DARWIN, "gem"),
                    file(DARWIN, "gemspec"),
                    file(LINUX, "gem"),
                    file(LINUX, "gemspec"),
                ];
                expected.sort();
                assert_eq!(fetched, expected);

                // The ledger entry: each tree's platform, patch and digests,
                // in lock order.
                assert_eq!(entry.gem_builds, [built(UUID, DARWIN), built(UUID, LINUX)]);
                assert_eq!(entry.uuid, UUID);
                assert_eq!(entry.artifact.path, rel);
                let inventory = entry.artifact.file_inventory.as_ref().expect("inventory");
                let inventoried: Vec<&str> = inventory.keys().map(String::as_str).collect();
                assert_eq!(
                    inventoried,
                    [
                        "arm64-darwin/lib/nokogiri/nokogiri.so",
                        "arm64-darwin/lib/nokogiri/version.rb",
                        "arm64-darwin/nokogiri.gemspec",
                        "x86_64-linux-gnu/lib/nokogiri/nokogiri.so",
                        "x86_64-linux-gnu/lib/nokogiri/version.rb",
                        "x86_64-linux-gnu/nokogiri.gemspec",
                    ]
                );
                let checksum_record = entry
                    .wiring
                    .iter()
                    .find(|w| w.kind == LOCK_CHECKSUM_WIRING_KIND);
                match before {
                    None => assert!(checksum_record.is_none(), "{checksum_record:?}"),
                    Some(_) => {
                        let rec = checksum_record.expect("a checksum record");
                        assert_eq!(
                            rec.original,
                            Some(serde_json::json!([
                                format!("  nokogiri (1.18.10-arm64-darwin){}", sha('a')),
                                format!("  nokogiri (1.18.10-x86_64-linux-gnu){}", sha('b')),
                            ]))
                        );
                        assert_eq!(
                            rec.new,
                            Some(serde_json::json!([
                                "  nokogiri (1.18.10-arm64-darwin)",
                                "  nokogiri (1.18.10-x86_64-linux-gnu)",
                            ]))
                        );
                    }
                }
                assert!(
                    warnings
                        .iter()
                        .any(|w| w.code == "vendor_prebuilt_downloaded"
                            && w.detail.contains(DARWIN)
                            && w.detail.contains(LINUX)),
                    "{warnings:?}"
                );

                // The ledger round trip through state.json.
                ts::persist(&root, NOKO, entry.clone()).await;
                let saved = crate::vendor::load_state(&root).await.unwrap().entries[NOKO].clone();
                assert_eq!(saved, entry);
                let ledger = text(root.join(".socket/vendor/state.json")).await;
                assert!(ledger.contains("\"gemBuilds\""), "{ledger}");
                assert!(ledger.contains("\"gemIntegrity\""), "{ledger}");
                assert!(ledger.contains("\"gemspecIntegrity\""), "{ledger}");

                // Verification and discovery: one vendored reference.
                assert_eq!(
                    check_vendored_artifact(&root, &saved, &record).await,
                    ArtifactHealth::Healthy
                );
                let found = crate::vex::discover::discover_patched_refs(&root).await;
                let refs: Vec<_> = found
                    .refs
                    .iter()
                    .map(|r| (r.purl.as_str(), r.uuid.as_str(), r.artifact_rel.as_deref()))
                    .collect();
                assert_eq!(
                    refs,
                    [("pkg:gem/nokogiri@1.18.10", UUID, Some(rel.as_str()))]
                );
                assert!(found.diagnostics.is_empty(), "{:?}", found.diagnostics);

                // A second run changes nothing and asks the service nothing.
                let requests = ts::request_count(&server).await;
                let snapshot = ts::tree_snapshot(&root);
                let (again, entry, warnings) =
                    unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
                assert!(again.success, "{:?}", again.error);
                assert!(entry.is_none() && warnings.is_empty(), "{warnings:?}");
                assert_eq!(ts::tree_snapshot(&root), snapshot);
                assert_eq!(ts::request_count(&server).await, requests);

                // Revert: both files byte for byte, the trees gone.
                let reverted = revert_gem(&saved, &root, false).await;
                assert!(reverted.success, "{:?}", reverted.error);
                assert!(reverted.warnings.is_empty(), "{:?}", reverted.warnings);
                assert_eq!(text(root.join(GEMFILE)).await, GEMFILE_NOKO);
                assert_eq!(text(root.join(GEMFILE_LOCK)).await, lock_before);
                assert!(!root.join(".socket/vendor/gem").exists());
            }
        }

        /// Every locked platform needs a patched build. While the gem
        /// patch's reference names none for one of them (the registry
        /// serves upstream's own gem for it, does not list it, or lists no
        /// platform gem at all), a dry run and a wet run both leave the gem
        /// alone under the benign pending code: one line that names the gem
        /// and the platforms, one request (the gem patch's reference), no
        /// download and nothing written.
        #[tokio::test]
        async fn a_locked_platform_without_a_patched_build_is_a_skip_that_downloads_nothing() {
            let listed = |platform: &'static str, listed: Listed| Served {
                listed,
                ..served(platform)
            };
            let cases: [(Vec<Served>, bool, &str); 5] = [
                (
                    vec![served(DARWIN), listed(LINUX, Listed::PassThrough)],
                    true,
                    "nokogiri@1.18.10 is not vendored: no patched build yet for x86_64-linux-gnu \
                     (arm64-darwin has one). Vendored mode needs every locked platform; `scan \
                     --mode hosted` can patch the others now.",
                ),
                (
                    vec![listed(DARWIN, Listed::Unlisted), served(LINUX)],
                    true,
                    "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin \
                     (x86_64-linux-gnu has one). Vendored mode needs every locked platform; `scan \
                     --mode hosted` can patch the others now.",
                ),
                (
                    vec![
                        listed(DARWIN, Listed::PassThrough),
                        listed(LINUX, Listed::PassThrough),
                    ],
                    true,
                    "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin and \
                     x86_64-linux-gnu. Vendored mode needs every locked platform.",
                ),
                (
                    Vec::new(),
                    true,
                    "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin and \
                     x86_64-linux-gnu. Vendored mode needs every locked platform.",
                ),
                // A patch of the ruby gem alone: its reference carries no
                // list of platform gems.
                (
                    vec![served(DARWIN), served(LINUX)],
                    false,
                    "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin and \
                     x86_64-linux-gnu. Vendored mode needs every locked platform.",
                ),
            ];
            for (builds, list, line) in cases {
                let (_tmp, root, record) = project(&lock(Some(&checksums(&sha('a'), "")))).await;
                let before = ts::tree_snapshot(&root);
                let (server, cfg) = serve(UUID, &builds, list).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                    assert!(crate::vendor::is_unserved(code));
                    assert!(crate::vendor::refusals::refusal_is_benign(code));
                    assert_eq!(detail, line);
                    assert!(!detail.contains('\n'), "one line: {detail}");
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                assert_eq!(
                    reference_requests(&server).await,
                    [vec![UUID.to_string()], vec![UUID.to_string()]],
                    "the gem patch's reference is each run's one request"
                );
                assert_eq!(downloads(&server).await, Vec::<String>::new());
            }
        }

        /// A platform the lock gains after the gem was vendored, with no
        /// patched build: the vendored copy stays in force exactly as it
        /// is, dry run or not, under the same benign code and one line
        /// that says why it was not brought up to date.
        #[tokio::test]
        async fn a_vendored_gem_whose_lock_gains_an_unpatched_platform_stays_as_it_is() {
            const JAVA: &str = "java";
            let (_tmp, root, record) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record, &cfg).await;
            // The lock names a third platform under the vendored section.
            let lock_path = root.join(GEMFILE_LOCK);
            let gained = text(lock_path.clone()).await.replace(
                "    nokogiri (1.18.10-x86_64-linux-gnu)\n",
                "    nokogiri (1.18.10-java)\n      racc (~> 1.4)\n    nokogiri (1.18.10-x86_64-linux-gnu)\n",
            );
            tokio::fs::write(&lock_path, &gained).await.unwrap();
            let before = ts::tree_snapshot(&root);
            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(JAVA)
            };
            let (server, cfg) = service(UUID, &[served(DARWIN), pass_through, served(LINUX)]).await;
            for dry_run in [true, false] {
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                );
                assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                assert_eq!(
                    detail,
                    "nokogiri@1.18.10 was not brought up to date: no patched build yet for java \
                     (arm64-darwin and x86_64-linux-gnu have one). Vendored mode needs every \
                     locked platform; its vendored copy stays in force as it is."
                );
                assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
            }
            assert_eq!(downloads(&server).await, Vec::<String>::new());
        }

        /// A copy the lock is ALREADY wired to cannot wait for a patched
        /// build when one of its trees is lost: with that platform's build
        /// gone from the registry, the rebuild is the plain miss, a
        /// failure, dry run or not, and what is left of the copy stays as
        /// it was.
        #[tokio::test]
        async fn a_wired_copy_that_cannot_be_rebuilt_fails_instead_of_skipping() {
            let (_tmp, root, record) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record, &cfg).await;
            tokio::fs::remove_dir_all(root.join(rel(UUID)).join(LINUX))
                .await
                .unwrap();
            let before = ts::tree_snapshot(&root);
            let (_server, cfg) = service(UUID, &[served(DARWIN)]).await;
            for dry_run in [true, false] {
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                );
                assert_eq!(code, "vendor_prebuilt_required", "{detail}");
                assert_eq!(
                    detail,
                    "nokogiri@1.18.10 was not brought up to date: no patched build yet for \
                     x86_64-linux-gnu (arm64-darwin has one). Vendored mode needs every locked \
                     platform; its vendored copy is missing or damaged and cannot be rebuilt \
                     until then."
                );
                assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
            }
        }

        /// `platform`'s patched build, with a patch of its own whose
        /// reference answers `status`: no grant.
        fn unserved(platform: &'static str, status: &'static str) -> Served {
            Served {
                own: Own::Status(status),
                ..served(platform)
            }
        }

        /// The references each run asks for when every locked platform is
        /// named a patch: the gem patch's, then the platform patches' in
        /// one request.
        fn both_requests(uuid: &str) -> [Vec<String>; 2] {
            [
                vec![uuid.to_string()],
                vec![build_uuid(uuid, DARWIN), build_uuid(uuid, LINUX)],
            ]
        }

        /// A patched build the gem patch names, whose own patch the
        /// service does not serve, is no build to vendor: none yet while
        /// that patch is still being built (`pending_build`), none
        /// available under any other status that is no grant. A dry run
        /// and a wet run both leave the gem alone under the benign pending
        /// code, with one line that names the platform: two requests (the
        /// gem patch's reference, the platform patches' together), no
        /// download and nothing written.
        #[tokio::test]
        async fn a_platform_patch_that_is_not_served_is_a_skip_that_downloads_nothing() {
            const NEEDS: &str = "Vendored mode needs every locked platform";
            const HOSTED: &str = "`scan --mode hosted` can patch the others now.";
            let mut cases: Vec<(Vec<Served>, String)> = vec![
                (
                    vec![served(DARWIN), unserved(LINUX, "pending_build")],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build yet for \
                         x86_64-linux-gnu (arm64-darwin has one). {NEEDS}; {HOSTED}"
                    ),
                ),
                (
                    vec![
                        unserved(DARWIN, "pending_build"),
                        unserved(LINUX, "forbidden"),
                    ],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin \
                         and none available for x86_64-linux-gnu. {NEEDS}."
                    ),
                ),
            ];
            let no_grant = [
                "forbidden",
                "not_found",
                "withdrawn",
                "build_failed",
                "a_status_of_a_later_service",
            ];
            for status in no_grant {
                cases.push((
                    vec![unserved(DARWIN, status), served(LINUX)],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build available for \
                         arm64-darwin (x86_64-linux-gnu has one). {NEEDS}; {HOSTED}"
                    ),
                ));
            }
            for (builds, line) in cases {
                let (_tmp, root, record) = project(&lock(None)).await;
                let before = ts::tree_snapshot(&root);
                let (server, cfg) = service(UUID, &builds).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                    assert!(crate::vendor::refusals::refusal_is_benign(code));
                    assert_eq!(detail, line);
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                assert_eq!(
                    reference_requests(&server).await,
                    [both_requests(UUID), both_requests(UUID)].concat(),
                    "{line}"
                );
                assert_eq!(downloads(&server).await, Vec::<String>::new(), "{line}");
            }
        }

        /// The same with a vendored copy in place, which stays in force
        /// untouched: the copy of an earlier patch when a platform patch
        /// of the newer one is not served, and this patch's own copy when
        /// the lock gains a platform whose patch is not served. The line
        /// says which.
        #[tokio::test]
        async fn an_unserved_platform_patch_leaves_a_vendored_copy_in_force() {
            const JAVA: &str = "java";
            for (status, none) in [
                ("pending_build", "no patched build yet for"),
                ("forbidden", "no patched build available for"),
            ] {
                let (_tmp, root, record_a) = project(&lock(None)).await;
                let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
                vendor_and_persist(&root, &record_a, &cfg).await;

                // A newer patch of the gem.
                let before = ts::tree_snapshot(&root);
                let record_b = PatchRecord {
                    uuid: UUID_B.to_string(),
                    ..record_a.clone()
                };
                let (server, cfg) =
                    service(UUID_B, &[served(DARWIN), unserved(LINUX, status)]).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record_b, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                    assert_eq!(
                        detail,
                        format!(
                            "nokogiri@1.18.10 was not brought up to date: {none} \
                             x86_64-linux-gnu (arm64-darwin has one). Vendored mode needs every \
                             locked platform; its vendored copy of an earlier patch stays in \
                             force as it is."
                        )
                    );
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                assert_eq!(downloads(&server).await, Vec::<String>::new());

                // The same patch, once the lock names a third platform.
                let lock_path = root.join(GEMFILE_LOCK);
                let gained = text(lock_path.clone()).await.replace(
                    "    nokogiri (1.18.10-x86_64-linux-gnu)\n",
                    "    nokogiri (1.18.10-java)\n      racc (~> 1.4)\n    nokogiri (1.18.10-x86_64-linux-gnu)\n",
                );
                tokio::fs::write(&lock_path, &gained).await.unwrap();
                let before = ts::tree_snapshot(&root);
                let builds = [served(DARWIN), unserved(JAVA, status), served(LINUX)];
                let (server, cfg) = service(UUID, &builds).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record_a, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                    assert_eq!(
                        detail,
                        format!(
                            "nokogiri@1.18.10 was not brought up to date: {none} java \
                             (arm64-darwin and x86_64-linux-gnu have one). Vendored mode needs \
                             every locked platform; its vendored copy stays in force as it is."
                        )
                    );
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                assert_eq!(downloads(&server).await, Vec::<String>::new());
            }
        }

        /// What stays a failure. A copy the lock is ALREADY wired to that
        /// lost a tree cannot wait for a platform patch that is not
        /// served: its rebuild is the plain miss, dry run or not, and so
        /// is a restore of the trees the ledger records, whose patches
        /// have nothing to wait for.
        #[tokio::test]
        async fn an_unserved_platform_patch_fails_a_wired_copy_that_must_be_rebuilt() {
            for (status, none, restore_says) in [
                ("pending_build", "yet", "is still building"),
                ("forbidden", "available", "Forbidden"),
            ] {
                let (_tmp, root, record) = project(&lock(None)).await;
                let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
                let entry = vendor_and_persist(&root, &record, &cfg).await;
                tokio::fs::remove_dir_all(root.join(rel(UUID)).join(LINUX))
                    .await
                    .unwrap();
                let before = ts::tree_snapshot(&root);
                let (_server, cfg) =
                    service(UUID, &[served(DARWIN), unserved(LINUX, status)]).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_required", "{detail}");
                    assert!(!crate::vendor::refusals::refusal_is_benign(code));
                    assert_eq!(
                        detail,
                        format!(
                            "nokogiri@1.18.10 was not brought up to date: no patched build \
                             {none} for x86_64-linux-gnu (arm64-darwin has one). Vendored mode \
                             needs every locked platform; its vendored copy is missing or \
                             damaged and cannot be rebuilt until then."
                        )
                    );
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                let failed = crate::vendor::redownload::restore(&root, &entry, &record, &cfg)
                    .await
                    .expect_err("a recorded tree whose patch is not served cannot be restored");
                assert!(failed.starts_with("vendor_prebuilt_required: "), "{failed}");
                assert!(failed.contains(restore_says), "{failed}");
                assert_eq!(ts::tree_snapshot(&root), before, "restore");
            }
        }

        /// What the skip does not cover: a response that leaves a platform
        /// patch out says nothing of that patch, and once the references
        /// are granted a download that fails is the miss it always was.
        /// Both fail, with nothing written.
        #[tokio::test]
        async fn an_unanswered_platform_patch_or_a_failed_download_is_a_failure() {
            let left_out = |platform: &'static str| Served {
                own: Own::LeftOut,
                ..served(platform)
            };
            // Left out beside one that is still being built: no skip.
            for builds in [
                vec![served(DARWIN), left_out(LINUX)],
                vec![unserved(DARWIN, "pending_build"), left_out(LINUX)],
            ] {
                let (_tmp, root, record) = project(&lock(None)).await;
                let before = ts::tree_snapshot(&root);
                let (server, cfg) = service(UUID, &builds).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "vendor_prebuilt_required", "{detail}");
                    assert!(!crate::vendor::refusals::refusal_is_benign(code));
                    assert!(detail.contains("missing a result"), "{detail}");
                    assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                }
                assert_eq!(downloads(&server).await, Vec::<String>::new());
            }

            let (_tmp, root, record) = project(&lock(None)).await;
            let before = ts::tree_snapshot(&root);
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path_regex(r"-x86_64-linux-gnu\.gem$"))
                .respond_with(wiremock::ResponseTemplate::new(404))
                .with_priority(1)
                .mount(&server)
                .await;
            for dry_run in [true, false] {
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                );
                assert_eq!(code, "vendor_prebuilt_required", "{detail}");
                assert!(
                    detail.contains(
                        "could not fetch the patched platform gem for nokogiri (x86_64-linux-gnu)"
                    ),
                    "{detail}"
                );
                assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
            }
        }

        /// A dry run that passes names the platform gems the wet run
        /// vendors, each with its own patch and the digests it was
        /// verified against, and writes nothing; the wet run names them in
        /// its entry instead. A dry run that does not pass names none.
        #[tokio::test]
        async fn a_dry_run_names_the_platform_gems_the_wet_run_vendors() {
            async fn run(
                root: &Path,
                record: &PatchRecord,
                cfg: &VendorServiceConfig,
                dry_run: bool,
                previewed: &mut Vec<GemBuildEntry>,
            ) -> VendorOutcome {
                let blobs = root.join("no-blobs");
                vendor_gem_previewing(
                    NOKO,
                    not_installed(root).as_path(),
                    root,
                    record,
                    &PatchSources::blobs_only(&blobs),
                    "2026-06-09T00:00:00Z",
                    dry_run,
                    false,
                    Some(cfg),
                    false,
                    previewed,
                )
                .await
            }
            let (_tmp, root, record) = project(&lock(None)).await;
            let before = ts::tree_snapshot(&root);

            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(LINUX)
            };
            for not_vendorable in [pass_through, unserved(LINUX, "pending_build")] {
                let (_server, cfg) = service(UUID, &[served(DARWIN), not_vendorable]).await;
                let mut previewed = Vec::new();
                let outcome = run(&root, &record, &cfg, true, &mut previewed).await;
                let (code, _) = unwrap_refused(outcome);
                assert_eq!(code, "vendor_prebuilt_platform_pending");
                assert_eq!(previewed, Vec::new());
            }

            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let mut previewed = Vec::new();
            let outcome = run(&root, &record, &cfg, true, &mut previewed).await;
            let (result, entry, warnings) = unwrap_done(outcome);
            assert!(result.success, "{:?}", result.error);
            assert!(entry.is_none() && warnings.is_empty(), "{warnings:?}");
            assert_eq!(previewed, [built(UUID, DARWIN), built(UUID, LINUX)]);
            assert_eq!(ts::tree_snapshot(&root), before);

            let mut unused = Vec::new();
            let outcome = run(&root, &record, &cfg, false, &mut unused).await;
            let (result, entry, _) = unwrap_done(outcome);
            assert!(result.success, "{:?}", result.error);
            assert_eq!(entry.expect("a ledger entry").gem_builds, previewed);
            assert_eq!(unused, Vec::new());
        }

        /// The preview of a run that holds no record of the patch: what
        /// the wet run decides before its first download, from the
        /// requests the wet run makes up to there. The gem patch's
        /// reference is the one request while a locked platform has no
        /// patched build; where every platform is named one, the platform
        /// patches' references are asked for too, in one request more. It
        /// names the patch of each locked platform's build, or refuses
        /// with the wet run's own code and line, and it downloads and
        /// writes nothing.
        #[tokio::test]
        async fn the_preview_without_a_record_makes_the_wet_runs_requests_and_no_download() {
            async fn preview(
                root: &Path,
                cfg: &VendorServiceConfig,
            ) -> Option<LockedBuildsPreview> {
                preview_locked_builds(root, NOKO, UUID, false, Some(cfg)).await
            }
            let (_tmp, root, record) = project(&lock(None)).await;
            let before = ts::tree_snapshot(&root);
            let named = |platform: &'static str| GemBuildEntry {
                gem_integrity: String::new(),
                gemspec_integrity: String::new(),
                files: BTreeMap::new(),
                ..built(UUID, platform)
            };

            // Every locked platform has a patched build whose patch is
            // served.
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            match preview(&root, &cfg).await {
                Some(LockedBuildsPreview::Vendor(builds)) => {
                    assert_eq!(builds, [named(DARWIN), named(LINUX)])
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(reference_requests(&server).await, both_requests(UUID));
            assert_eq!(downloads(&server).await, Vec::<String>::new());

            // A locked platform with no patched build, which the gem
            // patch's reference says (one request), or whose patch is not
            // served, which that patch's own reference says (the second):
            // the wet run's skip, word for word.
            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(LINUX)
            };
            for (not_vendorable, requests) in [
                (pass_through, vec![vec![UUID.to_string()]]),
                (
                    unserved(LINUX, "pending_build"),
                    both_requests(UUID).to_vec(),
                ),
                (unserved(LINUX, "forbidden"), both_requests(UUID).to_vec()),
            ] {
                let (server, cfg) = service(UUID, &[served(DARWIN), not_vendorable]).await;
                let (wet_code, wet_line) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, false).await,
                );
                let asked = reference_requests(&server).await.len();
                match preview(&root, &cfg).await {
                    Some(LockedBuildsPreview::Refused { code, detail }) => {
                        assert_eq!((code, &detail), (wet_code, &wet_line));
                        assert_eq!(code, "vendor_prebuilt_platform_pending");
                    }
                    other => panic!("{other:?}"),
                }
                assert_eq!(
                    reference_requests(&server).await[asked..],
                    requests,
                    "{wet_line}"
                );
                assert_eq!(downloads(&server).await, Vec::<String>::new());
            }

            // Offline, and for a declaration the wet run refuses before it
            // asks, nothing is asked: the answer is the wet run's refusal.
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let offline = VendorServiceConfig {
                offline: true,
                ..gem_service_cfg(&server.uri(), VendorSource::Service, false)
            };
            match preview(&root, &offline).await {
                Some(LockedBuildsPreview::Refused { code, .. }) => {
                    assert_eq!(code, "vendor_service_offline_conflict")
                }
                other => panic!("{other:?}"),
            }
            let grouped = GEMFILE_NOKO.replace(
                "gem \"nokogiri\", \"~> 1.18\"\n",
                "group :test do\n  gem \"nokogiri\", \"~> 1.18\"\nend\n",
            );
            tokio::fs::write(root.join(GEMFILE), &grouped)
                .await
                .unwrap();
            let (wet_code, wet_line) =
                unwrap_refused(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert_eq!(wet_code, "gemfile_declaration_not_editable");
            match preview(&root, &cfg).await {
                Some(LockedBuildsPreview::Refused { code, detail }) => {
                    assert_eq!((code, &detail), (wet_code, &wet_line))
                }
                other => panic!("{other:?}"),
            }
            // A gem the lockfile pins hosted is restored before it is
            // vendored: its declaration is not this preview's to judge.
            match preview_locked_builds(&root, NOKO, UUID, true, Some(&cfg)).await {
                Some(LockedBuildsPreview::Vendor(builds)) => {
                    assert_eq!(builds, [named(DARWIN), named(LINUX)])
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                reference_requests(&server).await,
                both_requests(UUID),
                "the hosted gem's are the only requests"
            );
            tokio::fs::write(root.join(GEMFILE), GEMFILE_NOKO)
                .await
                .unwrap();
            assert_eq!(ts::tree_snapshot(&root), before);

            // Not judged: a gem the lock names for the ruby platform, and
            // a lock already wired to the patch's copy.
            let ruby_gem = "pkg:gem/puma@6.4.2";
            assert!(
                preview_locked_builds(&root, ruby_gem, UUID, false, Some(&cfg))
                    .await
                    .is_none()
            );
            vendor_and_persist(&root, &record, &cfg).await;
            let asked = ts::request_count(&server).await;
            assert!(preview(&root, &cfg).await.is_none());
            assert_eq!(ts::request_count(&server).await, asked);
        }

        /// The preview words a skip as the wet run does when the Gemfile
        /// is wired to the copy of an earlier patch of the gem.
        #[tokio::test]
        async fn the_preview_without_a_record_says_which_copy_stays_in_force() {
            let (_tmp, root, record_a) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record_a, &cfg).await;
            let record_b = PatchRecord {
                uuid: UUID_B.to_string(),
                ..record_a.clone()
            };
            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(LINUX)
            };
            let (_server, cfg) = service(UUID_B, &[served(DARWIN), pass_through]).await;
            let (wet_code, wet_line) =
                unwrap_refused(vendor(&root, &not_installed(&root), &record_b, &cfg, false).await);
            assert!(
                wet_line
                    .ends_with("its vendored copy of an earlier patch stays in force as it is."),
                "{wet_line}"
            );
            match preview_locked_builds(&root, NOKO, UUID_B, false, Some(&cfg)).await {
                Some(LockedBuildsPreview::Refused { code, detail }) => {
                    assert_eq!((code, detail), (wet_code, wet_line))
                }
                other => panic!("{other:?}"),
            }
        }

        /// The line of a gem with a locked platform that has no patched
        /// build is worded in one place, and its last clause is what the
        /// gem is left with: hosted mode to run for the platforms that do
        /// have a build, a hosted pin that stays, the vendored copy of an
        /// earlier patch, or (for the caller to end) this patch's own
        /// copy. A gem the lockfile pins hosted is never told to run
        /// hosted mode, whichever platforms lack a build and however many
        /// have one.
        #[test]
        fn the_line_of_an_unpatched_platform_ends_with_what_the_gem_is_left_with() {
            const GEM: &str = "nokogiri@1.18.10";
            const NONE_YET: &str = "no patched build yet for arm64-darwin";
            const NEEDS: &str = "Vendored mode needs every locked platform";
            let yet = NoPatchedBuild {
                yet: vec![DARWIN],
                unavailable: Vec::new(),
            };
            let line = |standing: Standing, patched: &[&str]| {
                no_patched_build_detail(GEM, &yet, patched, standing)
            };
            assert_eq!(
                line(Standing::NotVendored, &[LINUX]),
                format!(
                    "{GEM} is not vendored: {NONE_YET} (x86_64-linux-gnu has one). {NEEDS}; \
                     `scan --mode hosted` can patch the others now."
                )
            );
            assert_eq!(
                line(Standing::Hosted, &[LINUX]),
                format!(
                    "{GEM} is not vendored: {NONE_YET} (x86_64-linux-gnu has one). {NEEDS}; the \
                     gem stays hosted."
                )
            );
            assert_eq!(
                line(Standing::EarlierPatch, &[LINUX]),
                format!(
                    "{GEM} was not brought up to date: {NONE_YET} (x86_64-linux-gnu has one). \
                     {NEEDS}; its vendored copy of an earlier patch stays in force as it is."
                )
            );
            // Left open for `wired_copy_not_rebuilt`, which knows whether
            // this patch's copy still stands.
            assert_eq!(
                line(Standing::Wired, &[LINUX]),
                format!(
                    "{GEM} was not brought up to date: {NONE_YET} (x86_64-linux-gnu has one). \
                     {NEEDS}"
                )
            );
            // No platform has a patched build: neither mode patches the gem.
            for standing in [Standing::NotVendored, Standing::Hosted] {
                assert_eq!(
                    line(standing, &[]),
                    format!("{GEM} is not vendored: {NONE_YET}. {NEEDS}."),
                    "{standing:?}"
                );
            }

            let unavailable = NoPatchedBuild {
                yet: Vec::new(),
                unavailable: vec![DARWIN],
            };
            let both = NoPatchedBuild {
                yet: vec![DARWIN],
                unavailable: vec!["java"],
            };
            for missing in [&yet, &unavailable, &both] {
                for patched in [&[][..], &[LINUX][..], &[LINUX, "aarch64-linux-gnu"][..]] {
                    let hosted = no_patched_build_detail(GEM, missing, patched, Standing::Hosted);
                    assert!(!hosted.contains("--mode hosted"), "{hosted}");
                    assert!(!hosted.contains("scan"), "{hosted}");
                    assert_eq!(
                        hosted.ends_with("; the gem stays hosted."),
                        !patched.is_empty(),
                        "{hosted}"
                    );
                    // The same platforms for a gem with no hosted pin.
                    let unpinned =
                        no_patched_build_detail(GEM, missing, patched, Standing::NotVendored);
                    assert_eq!(
                        unpinned.ends_with("; `scan --mode hosted` can patch the others now."),
                        !patched.is_empty(),
                        "{unpinned}"
                    );
                }
            }
        }

        /// A gem the lockfile pins hosted, as a takeover or an eject hands
        /// it to the backend (its upstream entry restored, `hosted` set):
        /// while a locked platform has no patched build, the dry run, the
        /// wet run and the preview without a record all leave it alone
        /// under the benign pending code, and the line says that the gem
        /// stays hosted. None of them names hosted mode as what to run,
        /// which is what the same gem with no hosted pin is told.
        #[tokio::test]
        async fn a_hosted_gem_with_an_unpatched_platform_is_told_that_it_stays_hosted() {
            async fn run(
                root: &Path,
                record: &PatchRecord,
                cfg: &VendorServiceConfig,
                dry_run: bool,
                hosted: bool,
            ) -> (&'static str, String) {
                let blobs = root.join("no-blobs");
                let outcome = vendor_gem_previewing(
                    NOKO,
                    not_installed(root).as_path(),
                    root,
                    record,
                    &PatchSources::blobs_only(&blobs),
                    "2026-06-09T00:00:00Z",
                    dry_run,
                    false,
                    Some(cfg),
                    hosted,
                    &mut Vec::new(),
                )
                .await;
                unwrap_refused(outcome)
            }
            const NEEDS: &str = "Vendored mode needs every locked platform";
            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(LINUX)
            };
            let cases: [(Vec<Served>, String); 3] = [
                (
                    vec![served(DARWIN), pass_through],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build yet for \
                         x86_64-linux-gnu (arm64-darwin has one). {NEEDS}; the gem stays hosted."
                    ),
                ),
                (
                    vec![unserved(DARWIN, "forbidden"), served(LINUX)],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build available for \
                         arm64-darwin (x86_64-linux-gnu has one). {NEEDS}; the gem stays hosted."
                    ),
                ),
                // No platform has a patched build: the line of any gem.
                (
                    vec![
                        unserved(DARWIN, "pending_build"),
                        unserved(LINUX, "forbidden"),
                    ],
                    format!(
                        "nokogiri@1.18.10 is not vendored: no patched build yet for arm64-darwin \
                         and none available for x86_64-linux-gnu. {NEEDS}."
                    ),
                ),
            ];
            for (builds, line) in cases {
                let (_tmp, root, record) = project(&lock(None)).await;
                let before = ts::tree_snapshot(&root);
                let (server, cfg) = service(UUID, &builds).await;
                for dry_run in [true, false] {
                    let (code, detail) = run(&root, &record, &cfg, dry_run, true).await;
                    assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                    assert_eq!(detail, line, "dry_run={dry_run}");
                    assert!(!detail.contains("--mode hosted"), "{detail}");
                }
                match preview_locked_builds(&root, NOKO, UUID, true, Some(&cfg)).await {
                    Some(LockedBuildsPreview::Refused { code, detail }) => {
                        assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                        assert_eq!(detail, line, "the preview without a record");
                    }
                    other => panic!("{other:?}"),
                }
                // With no hosted pin, the line names hosted mode exactly
                // where the hosted gem's says that it stays hosted.
                let (_, unpinned) = run(&root, &record, &cfg, true, false).await;
                assert_eq!(
                    unpinned.contains("`scan --mode hosted`"),
                    line.ends_with("the gem stays hosted."),
                    "{unpinned}"
                );
                assert_eq!(ts::tree_snapshot(&root), before);
                assert_eq!(downloads(&server).await, Vec::<String>::new());
            }
        }

        /// The layout is wired only for a lock written by a bundler it was
        /// run against: a lock that names an older one, or none, is refused
        /// by the version it needs, from the lock alone (so before a
        /// takeover too), with the service not asked and nothing written.
        #[tokio::test]
        async fn a_lock_from_a_bundler_older_than_the_layout_is_verified_on_is_refused() {
            for (bundled_with, says) in [
                ("BUNDLED WITH\n   2.2.33\n", "was written by Bundler 2.2.33"),
                ("BUNDLED WITH\n   1.17.3\n", "was written by Bundler 1.17.3"),
                ("", "does not say which Bundler wrote it"),
            ] {
                let old = lock(None).replace("BUNDLED WITH\n   2.5.22\n", bundled_with);
                let (_tmp, root, record) = project(&old).await;
                let before = ts::tree_snapshot(&root);
                let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
                for dry_run in [true, false] {
                    let (code, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(code, "platform_gem_unsupported", "{detail}");
                    assert!(detail.contains(says), "{detail}");
                    assert!(detail.contains("needs Bundler 2.3 or later"), "{detail}");
                }
                assert_eq!(ts::tree_snapshot(&root), before);
                assert_eq!(ts::request_count(&server).await, 0);
                let early = gem_platform_lock_refusals(&root, &[NOKO]).await;
                assert_eq!(early.len(), 1, "{early:?}");
                assert_eq!(early[0].1 .0, "platform_gem_unsupported");
            }
            // The floor itself, and a gem the lock does not pin as platform
            // gems, whatever bundler wrote it.
            let floor = lock(None).replace("   2.5.22\n", "   2.3.0\n");
            let (_tmp, root, record) = project(&floor).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let (result, ..) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            let locked = LockedGem {
                plain: true,
                platforms: Vec::new(),
            };
            assert!(platform_lock_refusal("rack", "3.2.6", &locked, "").is_none());
        }

        /// A plain `name (version)` entry beside the platform ones is the
        /// ruby platform, which no prebuilt tree serves: refused by name
        /// before the service is asked, with nothing written.
        #[tokio::test]
        async fn a_plain_entry_beside_the_platform_gems_is_refused() {
            let with_plain = lock(None)
                .replace(
                    "  specs:\n",
                    "  specs:\n    nokogiri (1.18.10)\n      mini_portile2 (~> 2.8.2)\n      racc (~> 1.4)\n",
                )
                .replace("  arm64-darwin\n", "  arm64-darwin\n  ruby\n");
            let (_tmp, root, record) = project(&with_plain).await;
            let before = ts::tree_snapshot(&root);
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            for dry_run in [true, false] {
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                );
                assert_eq!(code, "platform_gem_unsupported");
                assert!(
                    detail.contains("`nokogiri (1.18.10)` (the ruby platform)"),
                    "{detail}"
                );
                assert!(
                    detail.contains("`nokogiri (1.18.10-arm64-darwin)`"),
                    "{detail}"
                );
            }
            assert_eq!(ts::tree_snapshot(&root), before);
            assert_eq!(ts::request_count(&server).await, 0);
            assert!(
                service_preflight(NOKO, &not_installed(&root), &root, &record)
                    .await
                    .is_none(),
                "no download is planned for a gem the backend refuses first"
            );
            // The same refusal is the CLI's to raise before a takeover, and
            // a lock that pins platform gems alone has none.
            let early = gem_platform_lock_refusals(&root, &[NOKO, PURL]).await;
            assert_eq!(early.len(), 1, "{early:?}");
            assert_eq!(early[0].0, NOKO);
            assert_eq!(early[0].1 .0, "platform_gem_unsupported");
            assert!(early[0].1 .1.contains("(the ruby platform)"), "{early:?}");
            tokio::fs::write(root.join(GEMFILE_LOCK), lock(None))
                .await
                .unwrap();
            assert!(gem_platform_lock_refusals(&root, &[NOKO]).await.is_empty());
            // The lock edit refuses the shape on its own too.
            let err = edit_lock(&with_plain, "nokogiri", "1.18.10", &rel(UUID))
                .err()
                .expect("a plain entry beside platform ones must fail closed");
            assert!(err.contains("platform-suffixed"), "{err}");
        }

        /// A native gem locked for the ruby platform alone is still refused,
        /// whatever the service has: bundler would build it from source, and
        /// never does for a `path:` gem. The service is not asked.
        #[tokio::test]
        async fn a_native_gem_locked_only_for_the_ruby_platform_stays_refused() {
            let plain = lock(None).replace(
                BLOCKS,
                "    nokogiri (1.18.10)\n      mini_portile2 (~> 2.8.2)\n      racc (~> 1.4)\n",
            );
            let (tmp, root, record) = project(&plain).await;
            let installed = tmp
                .path()
                .join("gem_home/gems/nokogiri-1.18.10-arm64-darwin");
            tokio::fs::create_dir_all(&installed).await.unwrap();
            let before = ts::tree_snapshot(&root);
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let (code, detail) =
                unwrap_refused(vendor(&root, &installed, &record, &cfg, false).await);
            assert_eq!(code, "platform_gem_unsupported");
            assert!(detail.contains("nokogiri-1.18.10-arm64-darwin"), "{detail}");
            assert_eq!(ts::tree_snapshot(&root), before);
            assert_eq!(ts::request_count(&server).await, 0);
        }

        /// The installed copy of a platform-locked gem is a platform gem dir
        /// (`gems/nokogiri-1.18.10-arm64-darwin`): it vendors, from the
        /// platforms' patches and not from that dir. No archive download is
        /// planned and the ruby gem is never downloaded: the package
        /// reference names the platforms' patches, and their gems are all
        /// that is fetched.
        #[tokio::test]
        async fn an_installed_platform_gem_dir_vendors_from_the_platform_patches() {
            let (tmp, root, record) = project(&lock(None)).await;
            let installed = tmp
                .path()
                .join("gem_home/gems/nokogiri-1.18.10-arm64-darwin");
            tokio::fs::create_dir_all(installed.join("lib/nokogiri"))
                .await
                .unwrap();
            tokio::fs::write(installed.join(RB), RB_PRISTINE)
                .await
                .unwrap();
            assert_eq!(
                service_preflight(NOKO, &installed, &root, &record).await,
                None
            );
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let (result, entry, _) =
                unwrap_done(vendor(&root, &installed, &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            assert_eq!(
                entry.unwrap().gem_builds,
                [built(UUID, DARWIN), built(UUID, LINUX)]
            );
            let asked: Vec<String> = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .map(|request| request.url.path().to_string())
                .collect();
            assert!(
                !asked
                    .iter()
                    .any(|path| path.ends_with("/nokogiri-1.18.10.gem")),
                "the ruby gem is not downloaded: {asked:?}"
            );
            assert_eq!(
                asked.len(),
                8,
                "the gem patch's reference, the platform patches' in one request, then a \
                 platform gem, its stub and the record of its patch per platform: {asked:?}"
            );
            assert_eq!(
                tokio::fs::read(root.join(rel(UUID)).join(LINUX).join(RB))
                    .await
                    .unwrap(),
                stamped(LINUX)
            );
            assert_eq!(
                tokio::fs::read(installed.join(RB)).await.unwrap(),
                RB_PRISTINE,
                "the installed copy is not touched"
            );
        }

        /// An installed ruby-platform copy of the gem (compiled on this
        /// machine) beside a lock that pins platform gems: the extensions
        /// its gemspec declares are not the prebuilt trees', so they are no
        /// refusal.
        #[tokio::test]
        async fn a_compiled_ruby_install_beside_a_platform_lock_still_vendors() {
            let (tmp, root, record) = project(&lock(None)).await;
            let home = tmp.path().join("gem_home");
            let installed = home.join("gems/nokogiri-1.18.10");
            tokio::fs::create_dir_all(&installed).await.unwrap();
            tokio::fs::create_dir_all(home.join("specifications"))
                .await
                .unwrap();
            tokio::fs::write(
                home.join("specifications/nokogiri-1.18.10.gemspec"),
                "Gem::Specification.new do |s|\n  s.name = \"nokogiri\"\n  s.extensions = [\"ext/nokogiri/extconf.rb\"]\nend\n",
            )
            .await
            .unwrap();
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let (result, entry, _) =
                unwrap_done(vendor(&root, &installed, &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            assert_eq!(
                entry.unwrap().gem_builds,
                [built(UUID, DARWIN), built(UUID, LINUX)]
            );
        }

        /// A platform gem is verified against the integrity its own patch's
        /// reference states, like the ruby gem, AND against the sha256 the
        /// gem patch's registry lists for that platform; a patched file it
        /// ships must be the patched one, and its stub usable. Each failure
        /// refuses, naming the platform, with nothing written; a platform
        /// whose patch serves no gem or no stub is the plain miss.
        #[tokio::test]
        async fn a_tampered_or_unpatched_platform_gem_is_refused_with_nothing_written() {
            let tampered = Served {
                gem_sha512: Some(sri_sha512(b"some other bytes")),
                ..served(LINUX)
            };
            // The registry lists another gem for the platform than the one
            // the platform's patch serves.
            let not_the_listed_gem = Served {
                listed_sha256: Some("ab".repeat(32)),
                ..served(LINUX)
            };
            let no_gem = Served {
                gem: None,
                listed_sha256: Some("ab".repeat(32)),
                ..served(LINUX)
            };
            let no_stub = Served {
                stub: None,
                ..served(LINUX)
            };
            let unpatched = Served {
                gem: Some(make_gem(&[(RB, RB_PRISTINE), (SO, &b"so"[..])])),
                ..served(LINUX)
            };
            let native_stub = Served {
                stub: Some(
                    String::from_utf8(stub(LINUX))
                        .unwrap()
                        .replace(
                            "  s.require_paths",
                            "  s.extensions = [\"ext/nokogiri/extconf.rb\".freeze]\n  s.require_paths",
                        )
                        .into_bytes(),
                ),
                ..served(LINUX)
            };
            for (bad, code, says) in [
                (
                    tampered,
                    "vendor_prebuilt_integrity_mismatch",
                    "failed integrity verification",
                ),
                (
                    not_the_listed_gem,
                    "vendor_prebuilt_integrity_mismatch",
                    "is not the gem the patch registry lists for that platform",
                ),
                (
                    no_gem,
                    "vendor_prebuilt_required",
                    "served no patched platform gem",
                ),
                (
                    no_stub,
                    "vendor_prebuilt_required",
                    "served no stub gemspec",
                ),
                (
                    unpatched,
                    "vendor_prebuilt_required",
                    "does not carry the patch",
                ),
                (
                    native_stub,
                    "native_extensions_unsupported",
                    "declares native extensions",
                ),
            ] {
                let (_tmp, root, record) = project(&lock(None)).await;
                let before = ts::tree_snapshot(&root);
                let (_server, cfg) = service(UUID, &[served(DARWIN), bad]).await;
                for dry_run in [true, false] {
                    let (refused, detail) = unwrap_refused(
                        vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                    );
                    assert_eq!(refused, code, "{detail}");
                    assert!(detail.contains(says), "{detail}");
                    assert!(detail.contains(LINUX), "{detail}");
                    assert!(!crate::vendor::refusals::refusal_is_benign(refused));
                    assert_eq!(ts::tree_snapshot(&root), before, "{code} dry_run={dry_run}");
                }
            }
        }

        /// A mismatch against the registry's list, or against a platform
        /// patch's own reference, while rebuilding a copy the lock is
        /// already wired to: a hard failure that names the platform, and
        /// the existing copy, the lock and the Gemfile stay as they were.
        #[tokio::test]
        async fn a_mismatched_platform_gem_leaves_the_existing_copy_untouched() {
            let (_tmp, root, record) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record, &cfg).await;
            // A damaged tree, so the next run rebuilds the copy.
            let tree = root.join(rel(UUID)).join(LINUX);
            tokio::fs::write(tree.join(SO), b"another binary")
                .await
                .unwrap();
            let before = ts::tree_snapshot(&root);
            let against_the_list = Served {
                listed_sha256: Some("cd".repeat(32)),
                ..served(LINUX)
            };
            let against_the_reference = Served {
                gem_sha512: Some(sri_sha512(b"some other bytes")),
                ..served(LINUX)
            };
            for bad in [against_the_list, against_the_reference] {
                let (_server, cfg) = service(UUID, &[served(DARWIN), bad]).await;
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record, &cfg, false).await,
                );
                assert_eq!(code, "vendor_prebuilt_integrity_mismatch", "{detail}");
                assert!(detail.contains("nokogiri (x86_64-linux-gnu)"), "{detail}");
                assert_eq!(ts::tree_snapshot(&root), before);
            }
        }

        /// A patch of a source the platform gem never shipped (it ships the
        /// compiled extension) vendors: the prebuild carries the patched
        /// files it does ship. One rule then judges a tree wherever it is
        /// judged (the download, a re-run's in-sync test, the check): a
        /// patched file it holds is the patched one, and one it lacks is no
        /// mismatch; the ledger's inventory vouches for every byte of the
        /// tree; and with no inventory the tree must hold a patched file.
        #[tokio::test]
        async fn a_patch_of_unshipped_sources_vendors_and_verifies_by_inventory() {
            const EXTRA: &str = "lib/nokogiri/extra.rb";
            const EXTRA_PATCHED: &[u8] = b"# extra, patched\n";
            let with_extra = |platform: &'static str| {
                let mut files = build_files(platform);
                files.insert(
                    EXTRA.to_string(),
                    PatchFileInfo {
                        before_hash: compute_git_sha256_from_bytes(b"# extra\n"),
                        after_hash: compute_git_sha256_from_bytes(EXTRA_PATCHED),
                    },
                );
                Served {
                    gem: Some(make_gem(&[
                        (RB, &stamped(platform)),
                        (EXTRA, EXTRA_PATCHED),
                        (SO, platform.as_bytes()),
                    ])),
                    files,
                    ..served(platform)
                }
            };
            let (_tmp, root, _) = project(&lock(None)).await;
            let record = record(
                UUID,
                &[
                    (RB, RB_PRISTINE, RB_PATCHED),
                    (EXTRA, &b"# extra\n"[..], EXTRA_PATCHED),
                    (C, &b"pristine C\n"[..], &b"patched C\n"[..]),
                ],
            );
            let (_server, cfg) = service(UUID, &[with_extra(DARWIN), with_extra(LINUX)]).await;
            let entry = vendor_and_persist(&root, &record, &cfg).await;
            let tree = root.join(rel(UUID)).join(LINUX);
            assert!(!tree.join(C).exists());
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
            let corrupt = |reason: &str| ArtifactHealth::Corrupt {
                reason: reason.to_string(),
            };

            // No inventory says which files were vendored: the unshipped
            // source is accepted, each tree being checked against the
            // files of its own patch.
            let mut bare = entry.clone();
            bare.artifact.file_inventory = None;
            assert_eq!(
                check_vendored_artifact(&root, &bare, &record).await,
                ArtifactHealth::Healthy
            );
            // An entry synthesized from the lock names no tree, and so no
            // tree's own patch: the trees are read off the artifact and
            // checked against the gem's patch, whose stamped file is not
            // the one a platform's patch ships.
            bare.gem_builds.clear();
            assert_eq!(
                check_vendored_artifact(&root, &bare, &record).await,
                corrupt("vendor_hash_mismatch")
            );
            // A tree holding none of the patched files is vouched for by
            // the inventory; with none, nothing vouches for it.
            let unshipped = record_of(&record, &[C]);
            assert_eq!(
                check_vendored_artifact(&root, &entry, &unshipped).await,
                ArtifactHealth::Healthy
            );
            assert_eq!(
                check_vendored_artifact(&root, &bare, &unshipped).await,
                corrupt("file_not_found")
            );

            // A patched file the inventory lists and the tree no longer
            // holds was vendored and then lost. The check says so, and the
            // next run rebuilds the copy instead of calling it in sync.
            tokio::fs::remove_file(tree.join(EXTRA)).await.unwrap();
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                corrupt("vendor_inventory_mismatch")
            );
            let (result, rebuilt, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            assert!(
                warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                "{warnings:?}"
            );
            assert!(rebuilt.is_some(), "a refreshed entry");
            assert_eq!(
                tokio::fs::read(tree.join(EXTRA)).await.unwrap(),
                EXTRA_PATCHED
            );
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );

            // Drift in ONE platform's tree fails the whole copy: the binary
            // is a file of that platform's own patch.
            tokio::fs::write(tree.join(SO), b"another binary")
                .await
                .unwrap();
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                corrupt("vendor_hash_mismatch")
            );
            tokio::fs::write(tree.join(RB), RB_PRISTINE).await.unwrap();
            for entry in [&entry, &bare] {
                assert_eq!(
                    check_vendored_artifact(&root, entry, &record).await,
                    corrupt("vendor_hash_mismatch")
                );
            }

            // A platform the ledger names must be a plain directory name.
            let mut poisoned = entry.clone();
            poisoned.gem_builds[0].platform = "../x".to_string();
            assert_eq!(
                check_vendored_artifact(&root, &poisoned, &record).await,
                ArtifactHealth::Unverifiable {
                    reason: "vendor_path_unsafe".to_string()
                }
            );
        }

        /// The usual nokogiri patch touches only files no precompiled gem
        /// ships (`patches/…`, `dependencies.yml`): it lives entirely in the
        /// binaries the prebuild was rebuilt with. Such a prebuild vendors,
        /// on the strength of its download's integrity check, and is then
        /// vouched for by the ledger's inventory: the in-sync test of a
        /// re-run and the check both pass, and both catch a tampered binary.
        #[tokio::test]
        async fn a_prebuild_holding_none_of_the_patched_files_vendors_and_verifies_by_inventory() {
            let (_tmp, root, _) = project(&lock(None)).await;
            let record = record(UUID, &[(C, &b"pristine C\n"[..], &b"patched C\n"[..])]);
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let before = ts::tree_snapshot(&root);
            let (preview, ..) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, true).await);
            assert!(preview.success, "{:?}", preview.error);
            assert_eq!(ts::tree_snapshot(&root), before, "a dry run writes nothing");

            let entry = vendor_and_persist(&root, &record, &cfg).await;
            let tree = root.join(rel(UUID)).join(LINUX);
            assert!(!tree.join(C).exists(), "the prebuild ships no patched file");
            let inventory = entry.artifact.file_inventory.as_ref().expect("inventory");
            assert!(inventory.contains_key(&format!("{LINUX}/{SO}")));
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
            // A second run is in sync and asks the service nothing.
            let requests = ts::request_count(&server).await;
            let (again, rerun_entry, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(again.success, "{:?}", again.error);
            assert!(rerun_entry.is_none() && warnings.is_empty(), "{warnings:?}");
            assert_eq!(ts::request_count(&server).await, requests);

            // Without the inventory the files of each tree's own patch
            // vouch for it: the binary that patch built is in the tree.
            let mut bare = entry.clone();
            bare.artifact.file_inventory = None;
            assert_eq!(
                check_vendored_artifact(&root, &bare, &record).await,
                ArtifactHealth::Healthy
            );
            // An entry that records neither is checked against the gem's
            // patch, as before: nothing vouches for such a tree.
            for built in &mut bare.gem_builds {
                built.files.clear();
            }
            assert_eq!(
                check_vendored_artifact(&root, &bare, &record).await,
                ArtifactHealth::Corrupt {
                    reason: "file_not_found".to_string()
                }
            );

            // A tampered binary: the check reports it, and the next run
            // rebuilds the copy instead of calling it in sync.
            tokio::fs::write(tree.join(SO), b"another binary")
                .await
                .unwrap();
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Corrupt {
                    reason: "vendor_hash_mismatch".to_string()
                }
            );
            let (result, rebuilt, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            assert!(
                warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                "{warnings:?}"
            );
            assert!(rebuilt.is_some(), "a refreshed entry");
            assert_eq!(
                tokio::fs::read(tree.join(SO)).await.unwrap(),
                LINUX.as_bytes()
            );
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
        }

        /// A file planted outside every locked platform's tree (at the copy
        /// root, or as the tree of a platform the lock does not name, which
        /// bundler's glob would load once that platform is added) is one
        /// the ledger's inventory does not list. The check rejects it, and
        /// so does the in-sync test of a re-run, which rebuilds the copy.
        #[tokio::test]
        async fn a_file_planted_outside_the_locked_trees_is_not_in_sync() {
            let (_tmp, root, record) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let entry = vendor_and_persist(&root, &record, &cfg).await;
            let copy = root.join(rel(UUID));
            for planted in [
                copy.join("planted.rb"),
                copy.join("x64-mingw-ucrt").join(SO),
            ] {
                tokio::fs::create_dir_all(planted.parent().unwrap())
                    .await
                    .unwrap();
                tokio::fs::write(&planted, b"unpatched").await.unwrap();
                assert_eq!(
                    check_vendored_artifact(&root, &entry, &record).await,
                    ArtifactHealth::Corrupt {
                        reason: "vendor_inventory_mismatch".to_string()
                    }
                );
                let (result, rebuilt, warnings) =
                    unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
                assert!(result.success, "{:?}", result.error);
                assert!(
                    warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                    "{warnings:?}"
                );
                assert!(rebuilt.is_some(), "a refreshed entry");
                assert!(!planted.exists(), "the rebuild drops {planted:?}");
                assert_eq!(
                    check_vendored_artifact(&root, &entry, &record).await,
                    ArtifactHealth::Healthy
                );
            }
        }

        /// `record` with only `files`.
        fn record_of(record: &PatchRecord, files: &[&str]) -> PatchRecord {
            let mut only = record.clone();
            only.files.retain(|file, _| files.contains(&file.as_str()));
            only
        }

        /// A wired copy that lost one platform's tree is rebuilt in full by
        /// the next run (Gemfile and lock untouched), and `repair`'s restore
        /// rebuilds it from the ledger alone: each tree from the patch
        /// recorded for it, asked for in one request, with the gem patch's
        /// own reference never asked.
        #[tokio::test]
        async fn a_lost_platform_tree_is_rebuilt_by_a_rerun_and_by_restore() {
            let (_tmp, root, record) = project(&lock(Some(&checksums(&sha('a'), &sha('b'))))).await;
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let entry = vendor_and_persist(&root, &record, &cfg).await;
            let tree = root.join(rel(UUID)).join(LINUX);
            let wired = (
                text(root.join(GEMFILE)).await,
                text(root.join(GEMFILE_LOCK)).await,
            );

            tokio::fs::remove_dir_all(&tree).await.unwrap();
            let (result, rebuilt, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            assert!(
                warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                "{warnings:?}"
            );
            let rebuilt = rebuilt.expect("a refreshed entry");
            assert_eq!(
                rebuilt.gem_builds,
                [built(UUID, DARWIN), built(UUID, LINUX)]
            );
            assert!(rebuilt.wiring.is_empty(), "the first run's records ride on");
            assert_eq!(
                tokio::fs::read(tree.join(RB)).await.unwrap(),
                stamped(LINUX)
            );
            assert_eq!(
                (
                    text(root.join(GEMFILE)).await,
                    text(root.join(GEMFILE_LOCK)).await
                ),
                wired
            );

            // The uuid dir's git metadata is not part of the copy: restore
            // swaps the copy in from a stage of its own and writes the
            // metadata where the project keeps it.
            let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
            let metadata = [
                (".gitignore", "!*\n"),
                (".gitattributes", crate::vendor::npm_dir::UUID_GITATTRIBUTES),
            ];
            for (file, text_of) in metadata {
                assert_eq!(text(uuid_dir.join(file)).await, text_of, "{file}");
                tokio::fs::remove_file(uuid_dir.join(file)).await.unwrap();
            }
            tokio::fs::remove_dir_all(&tree).await.unwrap();
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Corrupt {
                    reason: "file_not_found".to_string()
                }
            );
            let asked = reference_requests(&server).await.len();
            crate::vendor::redownload::restore(&root, &entry, &record, &cfg)
                .await
                .expect("restore");
            assert_eq!(
                reference_requests(&server).await[asked..],
                [vec![build_uuid(UUID, DARWIN), build_uuid(UUID, LINUX)]],
                "one request, for the patches the ledger records"
            );
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
            for (file, text_of) in metadata {
                assert_eq!(text(uuid_dir.join(file)).await, text_of, "restore: {file}");
            }

            // An in-sync re-run puts back metadata that went missing, asks
            // the service nothing, and leaves a dry run's tree alone.
            let requests = ts::request_count(&server).await;
            for (file, _) in metadata {
                tokio::fs::remove_file(uuid_dir.join(file)).await.unwrap();
            }
            let lost = ts::tree_snapshot(&root);
            let (preview, ..) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, true).await);
            assert!(preview.success, "{:?}", preview.error);
            assert_eq!(ts::tree_snapshot(&root), lost, "a dry run writes nothing");
            let (again, entry_again, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(again.success, "{:?}", again.error);
            assert!(entry_again.is_none() && warnings.is_empty(), "{warnings:?}");
            for (file, text_of) in metadata {
                assert_eq!(text(uuid_dir.join(file)).await, text_of, "re-run: {file}");
            }
            assert_eq!(ts::request_count(&server).await, requests);
        }

        /// A restore checks each download against the digest the ledger
        /// recorded with its tree: a platform patch that serves another gem
        /// (or another stub) than the one vendored is refused, by platform,
        /// and the copy stays as it was.
        #[tokio::test]
        async fn a_restore_refuses_a_gem_or_stub_that_is_not_the_recorded_one() {
            let (_tmp, root, record) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let entry = vendor_and_persist(&root, &record, &cfg).await;
            tokio::fs::remove_dir_all(root.join(rel(UUID)).join(LINUX))
                .await
                .unwrap();
            let before = ts::tree_snapshot(&root);
            let another_gem = Served {
                gem: Some(make_gem(&[
                    (RB, &stamped(LINUX)),
                    (SO, &b"another build"[..]),
                ])),
                ..served(LINUX)
            };
            let another_stub = Served {
                stub: Some(
                    String::from_utf8(stub(LINUX))
                        .unwrap()
                        .replace("fixture", "another")
                        .into_bytes(),
                ),
                ..served(LINUX)
            };
            for (other, says) in [
                (another_gem, "is not the gem this copy was vendored from"),
                (another_stub, "is not the one this copy was vendored with"),
            ] {
                let (_server, cfg) = service(UUID, &[served(DARWIN), other]).await;
                let err = crate::vendor::redownload::restore(&root, &entry, &record, &cfg)
                    .await
                    .expect_err("a download that is not the recorded one");
                assert!(
                    err.starts_with("vendor_prebuilt_integrity_mismatch"),
                    "{err}"
                );
                assert!(err.contains(says), "{err}");
                assert!(err.contains("nokogiri (x86_64-linux-gnu)"), "{err}");
                assert_eq!(ts::tree_snapshot(&root), before);
            }
        }

        /// A ledger whose entry still has the key `gemPlatforms` (a
        /// development build wrote the platforms of the copy there, with no
        /// patch named for their trees) reads, and the key is ignored: the
        /// entry is the same one without it. Its revert needs nothing the
        /// key held: the Gemfile and the lock come back byte for byte from
        /// the originals the entry records, and the copy is removed.
        #[tokio::test]
        async fn an_entry_with_the_key_gem_platforms_reads_without_it_and_reverts() {
            let lock_before = lock(Some(&checksums(&sha('a'), &sha('b'))));
            let (_tmp, root, record) = project(&lock_before).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let current = vendor_and_persist(&root, &record, &cfg).await;

            // The ledger as such a build left it.
            let state_path = root.join(".socket/vendor/state.json");
            let mut ledger: Value = serde_json::from_str(&text(state_path.clone()).await).unwrap();
            let entry = ledger["entries"][NOKO].as_object_mut().unwrap();
            assert!(entry.remove("gemBuilds").is_some());
            entry.insert("gemPlatforms".into(), serde_json::json!([DARWIN, LINUX]));
            tokio::fs::write(&state_path, serde_json::to_vec_pretty(&ledger).unwrap())
                .await
                .unwrap();

            let read = crate::vendor::load_state(&root).await.unwrap().entries[NOKO].clone();
            let mut without_the_key = current.clone();
            without_the_key.gem_builds.clear();
            assert_eq!(read, without_the_key, "the key is ignored");
            assert_eq!(read.wiring, current.wiring, "the originals are the entry's");

            let reverted = revert_gem(&read, &root, false).await;
            assert!(reverted.success, "{:?}", reverted.error);
            assert!(reverted.warnings.is_empty(), "{:?}", reverted.warnings);
            assert_eq!(text(root.join(GEMFILE)).await, GEMFILE_NOKO);
            assert_eq!(text(root.join(GEMFILE_LOCK)).await, lock_before);
            assert!(!root.join(".socket/vendor/gem").exists());
        }

        /// A lock wired to the copy whose CHECKSUMS entry of one platform
        /// still carries a registry token is not in sync: refused with the
        /// repair path, like the plain entry's.
        #[tokio::test]
        async fn a_stale_platform_checksum_token_is_refused_on_a_rerun() {
            let (_tmp, root, record) = project(&lock(Some(&checksums(&sha('a'), &sha('b'))))).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record, &cfg).await;
            // (`\n` + two spaces: the CHECKSUMS entry, not the PATH spec.)
            let wired = text(root.join(GEMFILE_LOCK)).await;
            let stale = wired.replace(
                "\n  nokogiri (1.18.10-x86_64-linux-gnu)\n",
                &format!("\n  nokogiri (1.18.10-x86_64-linux-gnu){}\n", sha('b')),
            );
            assert_ne!(stale, wired);
            tokio::fs::write(root.join(GEMFILE_LOCK), &stale)
                .await
                .unwrap();
            let (code, _) =
                unwrap_refused(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert_eq!(code, "vendor_stale_lock_checksum");
            assert_eq!(text(root.join(GEMFILE_LOCK)).await, stale);
        }

        /// A patch update (new uuid, same gem) over a lock real bundler
        /// wrote, where only the platform it downloaded has a registry
        /// CHECKSUMS token: the blocks move to the new uuid's section, and
        /// the first run's originals — carried forward by the ledger — still
        /// restore both files byte for byte.
        #[tokio::test]
        async fn a_patch_update_rewires_the_platform_blocks_and_still_reverts() {
            let lock_before = lock(Some(&checksums(&sha('a'), "")));
            let (_tmp, root, record_a) = project(&lock_before).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let first = vendor_and_persist(&root, &record_a, &cfg).await;
            let rec = first
                .wiring
                .iter()
                .find(|w| w.kind == LOCK_CHECKSUM_WIRING_KIND)
                .expect("a checksum record");
            assert_eq!(
                rec.new,
                Some(serde_json::json!(["  nokogiri (1.18.10-arm64-darwin)"])),
                "only the rewritten entry is recorded"
            );

            let record_b = PatchRecord {
                uuid: UUID_B.to_string(),
                ..record_a.clone()
            };
            let (_server, cfg) = service(UUID_B, &[served(DARWIN), served(LINUX)]).await;
            let second = vendor_and_persist(&root, &record_b, &cfg).await;
            assert_eq!(second.uuid, UUID_B);
            assert_eq!(
                second.gem_builds,
                [built(UUID_B, DARWIN), built(UUID_B, LINUX)]
            );
            assert_eq!(
                text(root.join(GEMFILE_LOCK)).await,
                vendored(&rel(UUID_B), Some(&checksums("", "")))
            );
            assert!(text(root.join(GEMFILE)).await.contains(&rel(UUID_B)));

            let reverted = revert_gem(&second, &root, false).await;
            assert!(reverted.success, "{:?}", reverted.error);
            assert!(reverted.warnings.is_empty(), "{:?}", reverted.warnings);
            assert_eq!(text(root.join(GEMFILE)).await, GEMFILE_NOKO);
            assert_eq!(text(root.join(GEMFILE_LOCK)).await, lock_before);
            assert!(!root.join(format!(".socket/vendor/gem/{UUID_B}")).exists());
        }

        /// A newer patch of a gem already vendored, with a locked platform
        /// that has no patched build yet: the copy of the earlier patch
        /// stays wired and untouched, and the skip's one line says so.
        #[tokio::test]
        async fn a_newer_patch_with_an_unpatched_platform_keeps_the_earlier_copy() {
            let (_tmp, root, record_a) = project(&lock(None)).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            vendor_and_persist(&root, &record_a, &cfg).await;
            let before = ts::tree_snapshot(&root);
            let record_b = PatchRecord {
                uuid: UUID_B.to_string(),
                ..record_a.clone()
            };
            let pass_through = Served {
                listed: Listed::PassThrough,
                ..served(LINUX)
            };
            let (server, cfg) = service(UUID_B, &[served(DARWIN), pass_through]).await;
            for dry_run in [true, false] {
                let (code, detail) = unwrap_refused(
                    vendor(&root, &not_installed(&root), &record_b, &cfg, dry_run).await,
                );
                assert_eq!(code, "vendor_prebuilt_platform_pending", "{detail}");
                assert_eq!(
                    detail,
                    "nokogiri@1.18.10 was not brought up to date: no patched build yet for \
                     x86_64-linux-gnu (arm64-darwin has one). Vendored mode needs every locked \
                     platform; its vendored copy of an earlier patch stays in force as it is."
                );
                assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
            }
            assert_eq!(downloads(&server).await, Vec::<String>::new());
        }

        /// What git says of `path` (project-relative) in the work tree at
        /// `root`: `git <args> -- <path>`, trimmed.
        fn git(root: &Path, args: &[&str], path: &str) -> String {
            let git = crate::utils::process::resolve_tool("git").expect("git");
            let out = std::process::Command::new(git)
                .arg("-C")
                .arg(root)
                .args(args)
                .arg("--")
                .arg(path)
                .output()
                .expect("git runs");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        /// The prebuilt binaries are committable, byte for byte: a project
        /// rule that ignores them by pattern (`*.so`) is overridden by the
        /// uuid dir's own `.gitignore`, and a project filter on them (a Git
        /// LFS rule) by its `.gitattributes`, the pair every backend that
        /// commits binaries writes. A rule nothing under the uuid dir can
        /// override (one that ignores a directory above it) refuses the gem
        /// before anything is downloaded, in a dry run as in a wet one.
        #[tokio::test]
        async fn prebuilt_binaries_git_would_not_commit_are_re_included_or_refused() {
            for (rules, refused_code) in [
                ("*.so\n*.bundle\n", None),
                ("/.socket/vendor/gem/\n", Some("vendor_artifact_gitignored")),
            ] {
                let (_tmp, root, record) = project(&lock(None)).await;
                if ts::git_project(&root, rules).is_none() {
                    return; // no git, nothing to commit
                }
                tokio::fs::write(
                    root.join(".gitattributes"),
                    "*.so filter=lfs diff=lfs merge=lfs -text\n",
                )
                .await
                .unwrap();
                let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
                let uuid_dir = root.join(format!(".socket/vendor/gem/{UUID}"));
                match refused_code {
                    None => {
                        let outcome =
                            vendor(&root, &not_installed(&root), &record, &cfg, false).await;
                        let (result, entry, warnings) = unwrap_done(outcome);
                        assert!(result.success, "{:?}", result.error);
                        assert!(entry.is_some());
                        assert!(
                            !warnings.iter().any(|w| w.code.contains("gitignore")),
                            "{warnings:?}"
                        );
                        assert_eq!(text(uuid_dir.join(".gitignore")).await, "!*\n");
                        assert_eq!(
                            text(uuid_dir.join(".gitattributes")).await,
                            crate::vendor::npm_dir::UUID_GITATTRIBUTES
                        );
                        let binary = format!("{}/{DARWIN}/{SO}", rel(UUID));
                        assert_eq!(
                            crate::vendor::npm_dir::gitignored(&root, &[binary.clone()]).await,
                            None,
                            "git commits the prebuilt binary"
                        );
                        assert_eq!(
                            git(&root, &["check-attr", "filter"], &binary),
                            format!("{binary}: filter: unset"),
                            "and commits its bytes, not what the project's LFS filter makes of them"
                        );
                    }
                    Some(code) => {
                        let before = ts::tree_snapshot(&root);
                        for dry_run in [true, false] {
                            let (refused, detail) = unwrap_refused(
                                vendor(&root, &not_installed(&root), &record, &cfg, dry_run).await,
                            );
                            assert_eq!(refused, code, "dry_run={dry_run}: {detail}");
                            assert_eq!(ts::tree_snapshot(&root), before, "dry_run={dry_run}");
                        }
                        assert_eq!(
                            ts::request_count(&server).await,
                            0,
                            "refused before the service is asked for anything"
                        );
                        assert!(!root.join(".socket/vendor").exists());
                    }
                }
            }
        }

        /// A prebuild that ships a `.gitignore` of its own (its repository's,
        /// swept into the gem) would hide files from git below the uuid
        /// dir's `!*`, where no rule of the project's reaches. Each is
        /// emptied in the copy, at any depth, and reported; the ledger's
        /// inventory is of the tree as vendored, so the check passes and
        /// `repair`'s restore reproduces it. One the patch itself rewrites
        /// keeps the patch's bytes.
        #[tokio::test]
        async fn a_gitignore_a_prebuild_ships_is_emptied_in_the_copy() {
            const NESTED: &str = "lib/nokogiri/.gitignore";
            const PATCHED_IGNORE: &str = "ext/.gitignore";
            let shipping = |platform: &'static str| {
                let mut files = build_files(platform);
                files.insert(
                    PATCHED_IGNORE.to_string(),
                    PatchFileInfo {
                        before_hash: compute_git_sha256_from_bytes(b"*.o\n"),
                        after_hash: compute_git_sha256_from_bytes(b"# the patch's own\n"),
                    },
                );
                Served {
                    gem: Some(make_gem(&[
                        (RB, &stamped(platform)),
                        (SO, platform.as_bytes()),
                        (".gitignore", &b"*.so\n*.bundle\n"[..]),
                        (NESTED, &b"nokogiri.so\n"[..]),
                        (PATCHED_IGNORE, &b"# the patch's own\n"[..]),
                    ])),
                    files,
                    ..served(platform)
                }
            };
            let (_tmp, root, _) = project(&lock(None)).await;
            let record = record(
                UUID,
                &[
                    (RB, RB_PRISTINE, RB_PATCHED),
                    (PATCHED_IGNORE, &b"*.o\n"[..], &b"# the patch's own\n"[..]),
                ],
            );
            if ts::git_project(&root, "*.so\n").is_none() {
                return; // no git, nothing to commit
            }
            let (_server, cfg) = service(UUID, &[shipping(DARWIN), shipping(LINUX)]).await;
            let (result, entry, warnings) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(result.success, "{:?}", result.error);
            let neutralized: Vec<_> = warnings
                .iter()
                .filter(|w| w.code == "vendor_gem_gitignore_neutralized")
                .collect();
            assert_eq!(neutralized.len(), 1, "{warnings:?}");
            for file in [
                format!("{DARWIN}/.gitignore"),
                format!("{DARWIN}/{NESTED}"),
                format!("{LINUX}/.gitignore"),
            ] {
                assert!(neutralized[0].detail.contains(&file), "{neutralized:?}");
            }
            assert!(
                !neutralized[0].detail.contains(PATCHED_IGNORE),
                "{neutralized:?}"
            );
            ts::persist(&root, NOKO, entry.expect("a ledger entry")).await;
            let entry = crate::vendor::load_state(&root).await.unwrap().entries[NOKO].clone();

            let copy = root.join(rel(UUID));
            let emptied = |copy: &Path| {
                for platform in [DARWIN, LINUX] {
                    let tree = copy.join(platform);
                    for file in [".gitignore", NESTED] {
                        assert_eq!(std::fs::read(tree.join(file)).unwrap(), b"", "{file}");
                    }
                    assert_eq!(
                        std::fs::read(tree.join(PATCHED_IGNORE)).unwrap(),
                        b"# the patch's own\n"
                    );
                }
            };
            emptied(&copy);
            let binary = format!("{}/{LINUX}/{SO}", rel(UUID));
            assert_eq!(
                crate::vendor::npm_dir::gitignored(&root, &[binary]).await,
                None,
                "git commits the prebuilt binary"
            );
            // The inventory is of the tree as vendored: it lists the
            // emptied files, the check passes, and a second run is in sync.
            let inventory = entry.artifact.file_inventory.as_ref().expect("inventory");
            assert!(inventory.contains_key(&format!("{LINUX}/{NESTED}")));
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
            let (again, rerun_entry, _) =
                unwrap_done(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert!(again.success && rerun_entry.is_none(), "{:?}", again.error);

            // `repair`'s restore reproduces the same tree from the service.
            tokio::fs::remove_dir_all(copy.join(LINUX)).await.unwrap();
            crate::vendor::redownload::restore(&root, &entry, &record, &cfg)
                .await
                .expect("restore");
            emptied(&copy);
            assert_eq!(
                check_vendored_artifact(&root, &entry, &record).await,
                ArtifactHealth::Healthy
            );
        }

        /// A platform names a directory under the vendored dir, and the lock
        /// it is read from is committed data: one that is no plain directory
        /// name is refused before anything is asked or written.
        #[tokio::test]
        async fn an_unsafe_platform_token_is_refused() {
            let poisoned = lock(None).replace("1.18.10-x86_64-linux-gnu", "1.18.10-..");
            let (_tmp, root, record) = project(&poisoned).await;
            let before = ts::tree_snapshot(&root);
            let (server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let (code, detail) =
                unwrap_refused(vendor(&root, &not_installed(&root), &record, &cfg, false).await);
            assert_eq!(code, "unsafe_coordinates");
            assert!(detail.contains("`..`"), "{detail}");
            assert_eq!(ts::tree_snapshot(&root), before);
            assert_eq!(ts::request_count(&server).await, 0);
        }

        /// The lock edit on its own: the blocks move verbatim and in lock
        /// order (a direct and a transitive gem), revert splices them back,
        /// and shapes bundler never writes fail closed.
        #[test]
        fn the_lock_edit_moves_every_platform_block_and_fails_closed() {
            let registry = checksums(&sha('a'), &sha('b'));
            let transitive = lock(None).replace("  nokogiri (~> 1.18)\n", "");
            for before in [lock(None), lock(Some(&registry)), transitive] {
                let edit = edit_lock(&before, "nokogiri", "1.18.10", &rel(UUID)).unwrap();
                assert_eq!(edit.platforms, [DARWIN, LINUX]);
                assert_eq!(edit.removed_spec_block.join("\n") + "\n", BLOCKS);
                assert!(!edit.rewired_ours);
                let (original, new) = lock_record_lines(&edit);
                let reverted = revert_lock_text(&edit.text, &original, &new).unwrap();
                // The checksum record restores the registry tokens.
                let reverted = match reverted.split_once("CHECKSUMS\n") {
                    Some((head, entries)) => {
                        let entries = edit.checksum_rewrites.iter().fold(
                            entries.to_string(),
                            |text, (orig, bare)| {
                                text.replace(&format!("{bare}\n"), &format!("{orig}\n"))
                            },
                        );
                        format!("{head}CHECKSUMS\n{entries}")
                    }
                    None => reverted,
                };
                assert_eq!(reverted, before);

                // A patch update lifts the same blocks out of our section.
                let again = edit_lock(&edit.text, "nokogiri", "1.18.10", &rel(UUID_B)).unwrap();
                assert!(again.rewired_ours);
                assert_eq!(again.platforms, [DARWIN, LINUX]);
                assert_eq!(again.text, edit.text.replace(UUID, UUID_B));
            }

            let fails = |lock: String, why: &str| {
                let err = edit_lock(&lock, "nokogiri", "1.18.10", &rel(UUID))
                    .err()
                    .unwrap_or_else(|| panic!("must fail closed: {why}"));
                assert!(err.contains(why), "{err}");
            };
            // The platform entries apart from each other.
            fails(
                lock(None).replace(
                    "    nokogiri (1.18.10-x86_64-linux-gnu)\n      racc (~> 1.4)\n    puma (6.4.2)\n      nio4r (~> 2.0)\n",
                    "    puma (6.4.2)\n      nio4r (~> 2.0)\n    nokogiri (1.18.10-x86_64-linux-gnu)\n      racc (~> 1.4)\n",
                ),
                "apart from each other",
            );
            // One platform listed twice.
            fails(
                lock(None).replace(
                    "    puma (6.4.2)\n",
                    "    nokogiri (1.18.10-arm64-darwin)\n    puma (6.4.2)\n",
                ),
                "more than once",
            );
            // CHECKSUMS entries for builds the specs do not lock.
            fails(
                lock(Some(&registry)).replace(
                    "CHECKSUMS\n",
                    &format!("CHECKSUMS\n  nokogiri (1.18.10){}\n", sha('e')),
                ),
                "its specs do not lock",
            );
            fails(
                lock(Some(&registry)).replace(
                    "CHECKSUMS\n",
                    &format!(
                        "CHECKSUMS\n  nokogiri (1.18.10-aarch64-linux-musl){}\n",
                        sha('e')
                    ),
                ),
                "its specs do not lock",
            );
            // Our own section holding more than vendor wrote.
            let edit = edit_lock(&lock(None), "nokogiri", "1.18.10", &rel(UUID)).unwrap();
            fails(
                edit.text.replace(
                    "    nokogiri (1.18.10-arm64-darwin)\n",
                    "    nokogiri (1.18.10)\n    nokogiri (1.18.10-arm64-darwin)\n",
                ),
                "not the shape vendor wrote",
            );
        }

        /// The checksum record of a gem vendored as platform gems pairs each
        /// bare line with the registry line of the same entry: an entry that
        /// was bare before vendoring is left alone, a restored one has
        /// converged, and a missing one is drift that writes nothing.
        #[tokio::test]
        async fn the_checksum_record_restores_each_platform_line_or_none() {
            let lock_before = lock(Some(&checksums(&sha('a'), &sha('b'))));
            let (_tmp, root, record) = project(&lock_before).await;
            let (_server, cfg) = service(UUID, &[served(DARWIN), served(LINUX)]).await;
            let entry = vendor_and_persist(&root, &record, &cfg).await;
            let wired = text(root.join(GEMFILE_LOCK)).await;

            // One registry line already back (a partial hand restore).
            let partly = wired.replace(
                "  nokogiri (1.18.10-arm64-darwin)\n  nokogiri",
                &format!("  nokogiri (1.18.10-arm64-darwin){}\n  nokogiri", sha('a')),
            );
            assert_ne!(partly, wired);
            // One entry gone altogether: drift, and neither file is written.
            let drifted = wired.replace("  nokogiri (1.18.10-x86_64-linux-gnu)\n  puma", "  puma");
            assert_ne!(drifted, wired);
            let gemfile = text(root.join(GEMFILE)).await;
            tokio::fs::write(root.join(GEMFILE_LOCK), &drifted)
                .await
                .unwrap();
            let outcome = revert_gem(&entry, &root, false).await;
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "{:?}",
                outcome.warnings
            );
            assert_eq!(text(root.join(GEMFILE_LOCK)).await, drifted);
            assert_eq!(text(root.join(GEMFILE)).await, gemfile);
            assert!(root.join(rel(UUID)).is_dir(), "the copy is kept on drift");

            tokio::fs::write(root.join(GEMFILE_LOCK), &partly)
                .await
                .unwrap();
            let outcome = revert_gem(&entry, &root, false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(text(root.join(GEMFILE_LOCK)).await, lock_before);
            assert_eq!(text(root.join(GEMFILE)).await, GEMFILE_NOKO);
        }
    }
}
