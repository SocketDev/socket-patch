//! Attestation inputs for `vex`: the manifest, both `.socket/vendor`
//! ledgers, and the project's lockfiles (manifest-less VEX), merged into one
//! record view with a verification BASIS per purl.
//!
//! Sources, in record-priority order (a purl's record is the first one found
//! whose patch uuid is the one actually WIRED):
//!
//! 1. `.socket/manifest.json` (agent mode, and vendored mode's record owner);
//! 2. `.socket/vendor/redirect-state.json` `records` (hosted mode);
//! 3. `.socket/vendor/state.json` entry `record`s (vendored; always embedded
//!    by current writers, `detached` or not);
//! 4. online only: the patch API's view of the uuid (`get`'s
//!    `record_from_patch_response`, with its 401/403 → public-proxy
//!    fallback). Kept in memory — this module never writes the manifest.
//!
//! plus `vex::discover`'s lockfile references, which contribute two things:
//! patches that NO ledger or manifest records (a GitHub-app PR, an uncommitted
//! ledger), and the WIRING-LIVENESS proof for ledger entries.
//!
//! Gates, applied before (and independently of) hash verification — so
//! `--no-verify` cannot bypass them:
//!
//! * **wiring conflict** (`wiring_conflict`): lockfiles that wire ONE
//!   package to several different patches attest none of them — neither
//!   the first-found guess nor a verified-plus-skipped pair for one purl;
//! * **wired uuid wins**: when the lockfile wires a purl to patch U, a
//!   manifest/ledger record for the same package under another uuid is
//!   superseded (it describes a patch the build no longer consumes);
//! * **record match** (`record_mismatch`): the record used for a discovered
//!   reference must carry the reference's uuid AND name the same package;
//! * **record available** (`record_unavailable`): a reference with no local
//!   record under `--offline`, or whose API fetch failed / 404'd / was
//!   refused, is omitted — never attested from the `socket-patch.vendor.json`
//!   marker, which carries no hashes and is not a trust input;
//! * **liveness** (`vendor_unwired` / `redirect_unwired`): a ledger entry
//!   attests only while some lockfile/config still wires it. For a patch
//!   uuid that ANY file discovery read mentions, the discovered references
//!   alone decide (core discover rule 11): an entry an extractor rejected
//!   (inert Go replace, orphaned berry entry, reverted cargo pin, uv lock
//!   its pyproject does not confirm, shadowed maven pin, a nuget source
//!   whose lock no longer restores the id) or a section the package manager
//!   ignores is dead (a LOCKLESS cargo pin / exclusive nuget mapping is live
//!   for the ledger's exact version — core `UnlockedPin`),
//!   whatever raw text survives. Only for a uuid no read file mentions
//!   (formats no extractor reads, patch servers outside the host allowlist)
//!   does a HOSTED ledger's own recorded wiring decide — only files that
//!   PIN the resolution, never a leftover registry definition — and a hosted
//!   record whose lock entry or recorded wiring routes the uuid through a
//!   hosted-shaped url on an origin this run was not given is never
//!   attested (core `RecordLiveness::Undecided`, fail closed); a lock
//!   inventory entry resolving the purl elsewhere is dead. A VENDOR entry
//!   has no such fallback: it is live only while a discovered reference
//!   wires its package to its artifact (repair's reconstructed entries,
//!   which record no wiring, included), never because a `package.json`
//!   override or any other file its ledger names still spells the vendored
//!   dir. A reverted lockfile plus a leftover ledger or artifact must not
//!   keep attesting.
//!   A dead vendor claim falls through to a live hosted claim for the same
//!   key (hosted takeover of a vendored package). A manifest-owned purl whose REDIRECT
//!   claim is dead simply falls back to agent-mode verification (hosted mode
//!   never takes ownership away from `apply`); a dead VENDOR claim omits the
//!   purl (vendor ownership makes `apply` skip it, so no agent-mode evidence
//!   is expected).
//!
//! Bases: `Vendored` verifies the committed artifact (the ledger entry when
//! it names the wired artifact — it carries the dir-artifact file inventory —
//! else an entry synthesized from the reference); `Hosted` verifies the
//! installed copies the build CONSUMES through the hosted wiring
//! ([`crate::commands::vex_consumed`] — never a pristine sibling the build
//! does not read, such as the original Go module beside its replacement)
//! when any exist ("installed evidence wins") and otherwise, for a
//! DISCOVERED Socket-host reference with a lockfile pin, attests from the
//! pinned wiring (the in-run `scan --mode hosted --vex` evidence);
//! `Installed` is the agent-mode path.
//!
//! A gem that a Bundler lock takes from its patch registry as platform
//! builds is one hosted pin, but not one answer: the registry serves a
//! patched build for some platforms and upstream's own gem for the others.
//! The plan works out what the lock installs for each build it names
//! ([`Plan::hosted_gems`]): from the hosted run it is part of, or from the
//! lock and at most two requests per gem (the gem patch's reference, and
//! the index of the lock's registry where the lock has no `CHECKSUMS`).
//! The gem is judged as its one pin, and the document then names each
//! build ([`GemBuildView`]): a patched one under its own patch, and one on
//! upstream's gem, or of which neither is shown, as affected. The latter
//! is no failure of the run: the statement says why and what settles it,
//! and one warning names the gem (`vex_gem_build_unknown`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use futures_util::StreamExt;

use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, hold_back_debug,
    is_fallback_candidate, ApiClient, PatchApi,
};
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::hosted::engine::PinReport;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::{GemPlatformChecksum, RedirectState};
use socket_patch_core::utils::concurrent::{api_concurrency, ordered_concurrent};
use socket_patch_core::utils::purl::{purl_parts, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::{canonical_base_purl, PurlKey};
use socket_patch_core::vendor::state::{VendorArtifact, VendorEntry, VendorState};
use socket_patch_core::vex::discover::{
    vendor_ref, Discovery, LedgerLiveness, PatchedRef, RecordLiveness, WiringMode,
};
use socket_patch_core::vex::gem_builds::{
    gem_build_states, gem_index_url, locked_gem_pins, GemBuildState, GemBuildUnknown, LockedGemPin,
};
use socket_patch_core::vex::{FailedPatch, Unattested, UnattestedKind};

use crate::args::GlobalArgs;
use crate::ui::plural;

/// Omission tag: a lockfile-wired patch has no local record and none could
/// be fetched (offline, network error, 404, paid patch without a token).
pub(crate) const RECORD_UNAVAILABLE: &str = "record_unavailable";
/// Omission tag: the record found for a wired patch names another package
/// or another patch uuid than the wiring.
pub(crate) const RECORD_MISMATCH: &str = "record_mismatch";
/// Omission tag: a vendor-ledger entry whose committed artifact no lockfile
/// or config references any more.
pub(crate) const VENDOR_UNWIRED: &str = "vendor_unwired";
/// Omission tag: a hosted-redirect ledger record whose hosted patch no
/// lockfile references any more.
pub(crate) const REDIRECT_UNWIRED: &str = "redirect_unwired";
/// Omission tag: the project's lockfiles wire one package to two or more
/// DIFFERENT patches (e.g. a stale `package-lock.json` beside the
/// `npm-shrinkwrap.json`, or two package managers' locks that disagree).
/// Which one the build consumes is not decidable from the files, so no
/// candidate for that package attests.
pub(crate) const WIRING_CONFLICT: &str = "wiring_conflict";

/// Ceiling on concurrent patch-view fetches from the public proxy (one
/// GET per uuid; its view carries blob content, so it is heavy). The
/// authenticated API is asked for the view without that content, which
/// the record does not use, so there the patch API's own window applies.
const FETCH_CONCURRENCY: usize = 10;

/// The in-flight cap for the record fetch: `SOCKET_API_CONCURRENCY` applies
/// here like every other patch-API window, with [`FETCH_CONCURRENCY`] as
/// this window's own ceiling on top (a view is heavy).
fn fetch_concurrency(use_public_proxy: bool) -> usize {
    let window = api_concurrency(use_public_proxy);
    if use_public_proxy {
        window.min(FETCH_CONCURRENCY)
    } else {
        window
    }
}

/// Everything `vex` reads, loaded once by the caller (which owns the
/// corrupt-ledger hard errors).
pub(crate) struct Sources {
    /// The manifest file's contents (empty when the file is absent).
    pub manifest: PatchManifest,
    pub vendor: VendorState,
    pub redirect: Option<RedirectState>,
    pub discovery: Discovery,
    /// Embedded hosted `scan --vex` only: the uuids that run confirmed.
    /// v5 hosted mode keeps no ledger, so [`plan`] fetches their records
    /// and files them as hosted records. Empty everywhere else.
    pub hosted_uuids: Vec<String>,
    /// Embedded hosted `scan --vex` only: what that run reports for each
    /// locked build of the gems it pinned as platform builds
    /// (`engine::pin_reports`, the reports that name a gem patch). The run
    /// read the patch service's list of those builds to move the lock, so
    /// [`plan`] takes the builds from here and asks nothing. Empty
    /// everywhere else.
    pub hosted_gem_builds: Vec<PinReport>,
}

impl Sources {
    /// Nothing anywhere could name a patch: no manifest patches, no ledger
    /// entries or records, no lockfile references, no in-run hosted pins.
    pub(crate) fn is_empty(&self) -> bool {
        self.manifest.patches.is_empty()
            && self.vendor.entries.is_empty()
            && self.redirect.as_ref().is_none_or(|r| r.records.is_empty())
            && self.discovery.refs.is_empty()
            && self.hosted_uuids.is_empty()
    }
}

/// The resolved attestation inputs.
pub(crate) struct Plan {
    /// purl → record for every candidate that passed the gates (carrying
    /// the manifest file's legacy `setup` block through unchanged).
    pub view: PatchManifest,
    /// Vendored-basis entries, keyed by view purl — the verification
    /// routing for `applied_patches_with_vendor`.
    pub vendor_entries: HashMap<String, VendorEntry>,
    /// For each key of `vendor_entries`, the project files that point at
    /// its committed copy: those lockfile discovery found the vendored
    /// reference in, each from the project with `/` between its parts.
    /// Empty for an entry that is live without such a reference.
    pub vendor_pins: HashMap<String, Vec<String>>,
    /// Live hosted-basis view purls (the `(redirected)` marker and the
    /// property-7 bypass).
    pub redirected: Vec<String>,
    /// Hosted view purls that may attest from their pinned lockfile wiring
    /// when no installed tree exists.
    pub lockfile_basis: HashSet<String>,
    /// Every hosted-basis view purl (the `redirected` set) → what its hosted
    /// wiring is: the patch uuid it attests plus the discovered references
    /// (empty for a ledger-only record). Verification uses it to find the
    /// installed copy the build CONSUMES through that wiring
    /// ([`crate::commands::vex_consumed`]).
    pub hosted: BTreeMap<String, HostedWiring>,
    /// The gems of `hosted` that a Bundler lock takes from their patch
    /// registry as platform builds, by view purl: what the lock installs
    /// for each build it names ([`HostedGem`]). Such a gem is judged as the
    /// one pin it is, and the document then names its builds
    /// ([`GemBuildView`]).
    pub hosted_gems: BTreeMap<String, HostedGem>,
    /// Candidates omitted by a gate, with their routing tag.
    pub gated: Vec<FailedPatch>,
    /// Run advisories (wiring conflicts, superseded or dead records, record
    /// fetch failures): `vex` emits each as a `warnings[]` entry, so the
    /// `--json` envelope carries the detail its skip codes cannot.
    pub notes: Vec<PlanNote>,
}

/// One [`Plan`] advisory: a stable `warnings[]` code and its detail.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PlanNote {
    pub code: &'static str,
    pub detail: String,
}

/// A lockfile wires the package to different patches (`wiring_conflict`).
const NOTE_WIRING_CONFLICT: &str = "vex_wiring_conflict";
/// A recorded patch is superseded by the lockfile-wired one.
const NOTE_RECORD_SUPERSEDED: &str = "vex_record_superseded";
/// A ledger claim died although the lockfiles still mention the patch.
const NOTE_CLAIM_UNWIRED: &str = "vex_claim_unwired";
/// `--offline` forbids fetching the records the plan needs.
const NOTE_RECORD_OFFLINE: &str = "vex_record_offline";
/// The patch API has no such patch.
const NOTE_RECORD_NOT_FOUND: &str = "vex_record_not_found";
/// A record fetch failed (transport, server, paid-only, ...).
const NOTE_RECORD_FETCH_FAILED: &str = "vex_record_fetch_failed";
/// The public proxy served free patches only: the authenticated API refused
/// the credentials (`get` / `scan`'s fallback), or a token was set but its
/// org could not be resolved, so the run's client is on the proxy.
pub(crate) const NOTE_API_AUTH_FALLBACK: &str = "api_auth_fallback";

/// The run-level `--json` warning for a client whose org could not be
/// resolved (the run is on the public proxy; construction already warned on
/// stderr). A host that seeds embedded `--vex` with its client suppresses
/// the VEX plan's own `api_auth_fallback` note, so the host's envelope must
/// carry this instead (`scan` / `get` / `apply` / `vendor`).
pub(crate) fn api_auth_fallback_warning(
    client: &ApiClient,
) -> Option<crate::json_envelope::RunWarning> {
    client
        .org_unresolved()
        .map(|reason| crate::json_envelope::RunWarning {
            code: NOTE_API_AUTH_FALLBACK.to_string(),
            detail: reason.to_string(),
        })
}

/// Omission tag and note: a hosted Gradle pin is wired, but a lock file
/// records a release above its base, which that build resolves instead
/// (`vex::Unattested`).
const NOTE_LOCK_ABOVE_BASE: &str = "vex_gradle_lock_above_base";
/// Omission tag and note: an npm pin is wired, but its pnpm lock names a
/// package that bundles a copy of it, which no wiring reaches
/// (`vex::Unattested`, `UnattestedKind::BundledCopy`).
const NOTE_PNPM_BUNDLED_COPY: &str = "vex_pnpm_bundled_copy";
/// Omission tag and note: an npm pin is wired, but `deno.lock` locks the
/// same version, which `deno install` installs without the wiring
/// (`vex::Unattested`, `UnattestedKind::DenoLock`).
const NOTE_DENO_LOCK_COPY: &str = "vex_deno_lock_copy";

/// Omission tag and note: the patch is wired only in a root
/// `npm-shrinkwrap.json` with no `package-lock.json` twin, which npm >= 12
/// never reads (`vex::Unattested`).
const NOTE_NPM_SHRINKWRAP_ONLY: &str = "vex_npm_shrinkwrap_only";
/// Omission tag and note: a hosted Maven pin sits in a reactor root, where a
/// module's own `<version>` may override it (`vex::Unattested`).
const NOTE_MAVEN_REACTOR_ROOT: &str = "vex_maven_reactor_root";
/// Omission tag and note for [`UnattestedKind::MavenClassifierUnpatched`]
/// (`vex::Unattested`).
const NOTE_MAVEN_CLASSIFIER_UNPATCHED: &str = "vex_maven_classifier_unpatched";
/// Omission tag and note for [`UnattestedKind::MavenProfileUnpatched`]
/// (`vex::Unattested`).
const NOTE_MAVEN_PROFILE_UNPATCHED: &str = "vex_maven_profile_unpatched";
/// Omission tag and note for [`UnattestedKind::MavenConfigOverride`]
/// (`vex::Unattested`).
const NOTE_MAVEN_CONFIG_OVERRIDE: &str = "vex_maven_config_override";
/// Omission tag and note for [`UnattestedKind::MavenParentDeclares`]
/// (`vex::Unattested`).
const NOTE_MAVEN_PARENT_DECLARES: &str = "vex_maven_parent_declares";
/// Omission tag and note: a hosted Cargo pin beside another declaration of
/// the crate that names no Socket registry, which cargo resolves as a
/// separate, unpatched package (`vex::Unattested`).
const NOTE_CARGO_UNPINNED_DECLARATION: &str = "vex_cargo_unpinned_declaration";
/// Omission tag and note: a vendored Cargo copy beside a copy of the crate
/// from a source its `[patch]` entry does not redirect (another registry,
/// git), which cargo builds unpatched (`vex::Unattested`).
const NOTE_CARGO_PATCH_BYPASSED: &str = "vex_cargo_patch_bypassed";
/// Omission tag and note: a pnpm lock pins the patch, but a
/// `pnpm-lock.<branch>.yaml` exists, which pnpm installs from instead when
/// `gitBranchLockfile` is on; its presence withholds (`vex::Unattested`).
const NOTE_PNPM_GIT_BRANCH_LOCKFILE: &str = "vex_pnpm_git_branch_lockfile";
/// Omission tag and note: an npm-family pin's package is one the project
/// patches itself (npm / Bun / pnpm `patchedDependencies`, a yarn `patch:`
/// descriptor, a patch-package patch; `vex::Unattested`).
const NOTE_NPM_PATCHED_DEPENDENCY: &str = "vex_npm_patched_dependency";
/// Omission tag and note: a vendored sbt pin the build's local resolution
/// evidence does not verify, or under a build-wide blocker
/// (`vex::Unattested`, `UnattestedKind::SbtResolutionUnverified`).
const NOTE_SBT_RESOLUTION_UNVERIFIED: &str = "vex_sbt_resolution_unverified";
/// Omission tag and note: a vendored sbt pin's committed tree file is
/// missing or modified (`vex::Unattested`,
/// `UnattestedKind::SbtVendoredTreeMissing`).
const NOTE_SBT_VENDORED_TREE_MISSING: &str = "vex_sbt_vendored_tree_missing";
/// Omission tag and note: a NuGet Socket source's id is also locked at a
/// version other than the patched one, which that source cannot serve
/// (`vex::Unattested`).
const NOTE_NUGET_LOCK_OTHER_VERSION: &str = "vex_nuget_lock_other_version";
/// Omission tag and note: a hosted sbt pin whose bytes the build provably
/// does not use (a `dependencyOverrides` reassignment, an `onLoad` one
/// dropping the load-time verifier, or current evidence
/// resolving another version or other bytes), so the downloaded copy
/// proves nothing (`vex::Unattested`).
const NOTE_SBT_PIN_BYPASSED: &str = "vex_sbt_pin_bypassed";
/// Omission tag for a Go patch whose replace the `go.work` in effect
/// overrides, ignores or rejects (#393, #458, #531): the reason of `vex`'s
/// own go.mod gate, and the note of a discovered hosted or vendored ref the
/// governing workspace keeps from the build (`vex::Unattested`,
/// `UnattestedKind::GoWorkspaceOverride`).
pub(crate) const GO_WORKSPACE_OVERRIDE: &str = "go_workspace_override";
/// Omission tag and note: a vendored npm-family pin sits in a lock the
/// project's own configuration tells the package manager not to read (npm
/// `package-lock=false`, yarn 1 `--install.no-lockfile`, a yarn berry
/// `lockfileFilename`, pnpm `lockfile: false` with no override routing the
/// package to the artifact; `vex::Unattested`,
/// `UnattestedKind::LockNotRead`).
const NOTE_LOCK_NOT_READ: &str = "vex_lock_not_read";
/// Note, and code of the uncounted event: a platform build of a gem the
/// lockfile takes from a patch registry, of which nothing shows whether the
/// lock installs a patched build or upstream's own gem
/// ([`GemBuildState::Unknown`]). The document says `affected` of the build,
/// with why and what settles it ([`GemBuildUnshown`]): it is never attested
/// on the strength of the gem's one pin, and never left out. Not an
/// omission: the run's status and exit code are what they are without it.
pub(crate) const GEM_BUILD_UNKNOWN: &str = "vex_gem_build_unknown";

/// Largest compact-index document read for a gem's builds
/// ([`gem_index`]). The registry of a patch lists one version, a few
/// hundred bytes a line.
const MAX_GEM_INDEX_BYTES: u64 = 1024 * 1024;

/// The omission tag of an [`Unattested`](socket_patch_core::vex::Unattested)
/// ref, and the remedy its note ends with.
fn unattested_note(kind: UnattestedKind) -> (&'static str, &'static str) {
    match kind {
        UnattestedKind::LockAboveBase => (
            NOTE_LOCK_ABOVE_BASE,
            "not attested until that build resolves the patch (re-lock it, or roll the patch \
             back once upstream ships the fix)",
        ),
        UnattestedKind::BundledCopy => (
            NOTE_PNPM_BUNDLED_COPY,
            "not attested while that package bundles it; the wiring itself is intact, so \
             re-running `scan` / `vendor` does not change this (drop or upgrade the bundling \
             package)",
        ),
        UnattestedKind::DenoLock => (
            NOTE_DENO_LOCK_COPY,
            "not attested while deno.lock locks the same version; the wiring itself is \
             intact, so re-running `scan` / `vendor` does not change this (drop the entry from \
             deno.lock if Deno does not install this project's npm dependencies)",
        ),
        UnattestedKind::NpmShrinkwrapOnly => (
            NOTE_NPM_SHRINKWRAP_ONLY,
            "not attested until a package-lock.json wires it",
        ),
        UnattestedKind::MavenReactorRoot => (
            NOTE_MAVEN_REACTOR_ROOT,
            "not attested while a module of the reactor may build the unpatched version \
             (re-run `scan` once that module resolves it, or patch the reactor with `scan \
             --mode vendored`)",
        ),
        UnattestedKind::MavenClassifierUnpatched => (
            NOTE_MAVEN_CLASSIFIER_UNPATCHED,
            "not attested while that classifier copy resolves an unpatched version; the \
             wiring itself is intact, so re-running `scan` does not change this",
        ),
        UnattestedKind::MavenProfileUnpatched => (
            NOTE_MAVEN_PROFILE_UNPATCHED,
            "not attested while a profile declares it at, or its <properties> move it to, \
             another version, or its <properties> redefine a groupId / artifactId property so \
             the pin names another package or another declaration names this one; the wiring \
             itself is intact, so re-running `scan` does not change this (drop that profile \
             <version> or property or set it to the pin; `scan --mode vendored` rewrites a \
             literal profile <version>, but neither mode wires a pin a profile's <properties> \
             can move, and hosted `scan` writes no pin a profile bypasses)",
        ),
        UnattestedKind::MavenConfigOverride => (
            NOTE_MAVEN_CONFIG_OVERRIDE,
            "not attested while .mvn/maven.config redefines the property it is spelled \
             through; the wiring itself is intact, so re-running `scan` does not change this \
             (drop that -D from .mvn/maven.config, or write the pinned version literally)",
        ),
        UnattestedKind::MavenParentDeclares => (
            NOTE_MAVEN_PARENT_DECLARES,
            "not attested while a parent pom declares it with a version of its own; the \
             wiring itself is intact, so re-running `scan` does not change this (declare the \
             dependency in this pom with no <version>, or drop the <version> from the parent \
             pom's declaration)",
        ),
        UnattestedKind::CargoUnpinnedDeclaration => (
            NOTE_CARGO_UNPINNED_DECLARATION,
            "not attested while that declaration stands",
        ),
        UnattestedKind::CargoPatchBypassed => (
            NOTE_CARGO_PATCH_BYPASSED,
            "not attested while that copy can build beside the vendored one; the vendored \
             wiring itself is intact (the warning above says how to clear it)",
        ),
        UnattestedKind::PnpmGitBranchLock => (
            NOTE_PNPM_GIT_BRANCH_LOCKFILE,
            "not attested while any branch lock exists (or the members that could hold one \
             cannot be listed), whatever gitBranchLockfile says; the wiring itself is intact, \
             so re-running `scan` / `vendor` does not change this (fold the branch locks in \
             with `pnpm install --merge-git-branch-lockfiles`, turn gitBranchLockfile off and \
             delete the `pnpm-lock.<branch>.yaml` files, or make the workspace's `packages` \
             listable)",
        ),
        UnattestedKind::UserPatchedDependency => (
            NOTE_NPM_PATCHED_DEPENDENCY,
            "not attested while the project patches the package itself, even when it was \
             wired with `--allow-patch-conflicts` (fold the Socket fix into your own patch, or \
             remove your patch: the `patchedDependencies` entry, the yarn `patch:` descriptor \
             or the patch-package file, and re-run); an npm pin an earlier hosted run wrote \
             fails `npm ci` with `EPATCHFAILED` until `socket-patch rollback <uuid>` restores \
             the registry entry",
        ),
        UnattestedKind::SbtResolutionUnverified => (
            NOTE_SBT_RESOLUTION_UNVERIFIED,
            "not attested while that holds (the detail names the remedy, or that there is \
             none); the wiring itself is intact, so `vendor --check` and `scan` still treat it \
             as live",
        ),
        UnattestedKind::SbtVendoredTreeMissing => (
            NOTE_SBT_VENDORED_TREE_MISSING,
            "not attested while the committed tree differs from the pin (restore \
             `.socket/vendor/maven2` from version control, or re-run `socket-patch vendor`)",
        ),
        UnattestedKind::NugetLockOtherVersion => (
            NOTE_NUGET_LOCK_OTHER_VERSION,
            "not attested until every target framework locks only the patched version (align \
             them on it, restore, and re-run `scan` / `vendor`)",
        ),
        UnattestedKind::SbtPinBypassed => (
            NOTE_SBT_PIN_BYPASSED,
            "not attested while the build bypasses the pin, even from the copy under \
             `.socket/sbt-hosted`; the wiring itself is intact, so re-running `scan` does not \
             change this (fix the build, then run `sbt update`)",
        ),
        UnattestedKind::GoWorkspaceOverride => (
            GO_WORKSPACE_OVERRIDE,
            "not attested while the Go workspace in effect keeps it from the build; the wiring \
             itself is intact, so re-running `scan` / `vendor` does not change this",
        ),
        UnattestedKind::LockNotRead => (
            NOTE_LOCK_NOT_READ,
            "not attested while the project's configuration keeps the package manager from \
             reading that lock; the wiring itself is intact, so re-running `scan` / `vendor` \
             does not change this (drop the setting so the lock is read again)",
        ),
    }
}

/// The [`Unattested`](socket_patch_core::vex::Unattested) mark discovery
/// put on patch `uuid` for `purl`'s package, if any.
fn unattested_mark<'d>(
    discovery: &'d Discovery,
    purl: &str,
    uuid: &str,
) -> Option<&'d socket_patch_core::vex::Unattested> {
    let pkg = canonical_base_purl(purl);
    discovery
        .unattested
        .iter()
        .find(|u| u.uuid == uuid && PurlKey::same(&u.purl, &pkg))
}

/// Omit `key` for the mark `u`: its `failed[]` entry and the note naming
/// why and the remedy.
fn gate_unattested(
    key: &str,
    u: &socket_patch_core::vex::Unattested,
    gated: &mut Vec<FailedPatch>,
    notes: &mut Vec<PlanNote>,
) {
    let (code, remedy) = unattested_note(u.kind);
    gated.push(failed(key, code));
    notes.push(PlanNote {
        code,
        detail: format!(
            "{key}: patch {} is wired, but {}; {remedy}",
            u.uuid, u.detail
        ),
    });
}

/// The builds a document names in place of a gem that is one pin for
/// several platform gems.
///
/// A gem vendored as platform gems is one vendored copy, verified as one
/// against the record of the gem's patch. What an install loads from it is
/// one platform gem's tree, and each tree was built by a patch of its own,
/// which the ledger entry records ([`VendorEntry::gem_builds`]). So the
/// document names each platform gem
/// (`pkg:gem/<name>@<version>?platform=<platform>`) under its own patch,
/// with the vulnerabilities of the gem patch's record: the fix is the same
/// in every one of them. Read from the plan alone, with no request: the
/// ledger is what says which patch built which tree. An entry that names
/// no patch for its trees is attested as the gem itself.
///
/// A gem a lock takes from its patch registry as platform builds is one
/// hosted pin, judged as one. The registry serves a patched build for some
/// platforms and upstream's own gem for the others, so the pin does not
/// say that every locked build is patched ([`Plan::hosted_gems`]). The
/// document names each locked build: a patched one under its own patch,
/// like a vendored one, and every other one as `affected`
/// ([`Self::not_patched`]). That is a build on upstream's gem, which the
/// lock is known to install without the patch, and a build of which
/// neither is shown ([`GEM_BUILD_UNKNOWN`]): nothing shows that the lock
/// installs a patched build for it, so the document does not say it does,
/// and says why and what settles it. The record of every build stays in
/// the view, so that no statement names a form of the gem that also
/// stands for a build the document does not call patched.
pub(crate) struct GemBuildView {
    /// The record view with each such gem's key replaced by its builds'
    /// purls.
    view: PatchManifest,
    /// View purl of the gem → the purls of its builds that are patched.
    platform_gems: BTreeMap<String, Vec<String>>,
    /// The hosted builds that are not shown patched, each with what to do
    /// about it.
    not_patched: Vec<(String, String)>,
    /// Every build the view names in place of a gem, by purl.
    builds: BTreeMap<String, GemBuildInfo>,
}

/// One build a [`GemBuildView`] names, as the run's events describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GemBuildInfo {
    /// The gem patch's uuid: the one pin, or the one vendored copy, all
    /// the builds of the gem go by.
    pub gem_fix: String,
    /// `None` for the ruby-platform gem.
    pub platform: Option<String>,
    /// A hosted build the patch registry serves as upstream's own gem.
    pub kept_upstream: bool,
    /// A hosted build of which nothing shows what the lock installs: why,
    /// as its event says it ([`GemBuildUnshown::reason`]).
    pub unshown: Option<String>,
}

/// The action statement of a hosted gem build on upstream's gem
/// ([`GemBuildState::Upstream`]): why the lock installs it without the
/// gem's patch `gem_fix`, and what changes that.
fn upstream_build_action(platform: &str, gem_fix: &str) -> String {
    format!(
        "The patch registry has no patched build of this gem for {platform} yet and serves \
         upstream's own gem for it, so an install on that platform is without Socket patch \
         {gem_fix}. Run `socket-patch scan --mode hosted` again later: the lockfile takes the \
         patched build once it is published."
    )
}

impl GemBuildView {
    /// `None` when `plan` attests no gem vendored as platform gems and no
    /// gem a lock takes from a patch registry as platform builds.
    pub(crate) fn of(plan: &Plan) -> Option<Self> {
        let vendored: Vec<(&String, &VendorEntry, &PatchRecord)> = plan
            .vendor_entries
            .iter()
            .filter(|(_, entry)| {
                entry.ecosystem == "gem"
                    && !entry.gem_builds.is_empty()
                    && entry.gem_builds_well_formed()
            })
            .filter_map(|(key, entry)| Some((key, entry, plan.view.patches.get(key)?)))
            // The entry's trees are the builds of the entry's own patch.
            .filter(|(_, entry, record)| record.uuid == entry.uuid)
            .collect();
        let hosted: Vec<(&String, &HostedGem, &PatchRecord)> = plan
            .hosted_gems
            .iter()
            .filter_map(|(key, gem)| Some((key, gem, plan.view.patches.get(key)?)))
            // The builds are those of the patch the pin attests.
            .filter(|(_, gem, record)| record.uuid == gem.gem_fix)
            .collect();
        if vendored.is_empty() && hosted.is_empty() {
            return None;
        }
        let mut view = plan.view.clone();
        let mut platform_gems = BTreeMap::new();
        let mut not_patched = Vec::new();
        let mut builds = BTreeMap::new();
        for (key, entry, record) in vendored {
            view.patches.remove(key);
            let purls: Vec<String> = entry
                .gem_builds
                .iter()
                .map(|built| {
                    let purl = built.purl(&entry.base_purl);
                    // A purl the view already attests keeps its own record.
                    view.patches
                        .entry(purl.clone())
                        .or_insert_with(|| PatchRecord {
                            uuid: built.uuid.clone(),
                            ..record.clone()
                        });
                    builds.insert(
                        purl.clone(),
                        GemBuildInfo {
                            gem_fix: entry.uuid.clone(),
                            platform: Some(built.platform.clone()),
                            kept_upstream: false,
                            unshown: None,
                        },
                    );
                    purl
                })
                .collect();
            platform_gems.insert(key.clone(), purls);
        }
        for (key, gem, record) in hosted {
            view.patches.remove(key);
            let mut patched = Vec::new();
            for build in &gem.builds {
                // A purl the view already attests keeps its own record,
                // and the outcome of its own check.
                if view.patches.contains_key(&build.purl) {
                    continue;
                }
                let uuid = match &build.state {
                    GemBuildState::Patched { uuid } => uuid,
                    GemBuildState::Upstream | GemBuildState::Unknown(_) => &record.uuid,
                };
                view.patches.insert(
                    build.purl.clone(),
                    PatchRecord {
                        uuid: uuid.clone(),
                        ..record.clone()
                    },
                );
                let upstream = build.state == GemBuildState::Upstream;
                let unshown = build.unshown.as_ref().zip(build.platform.as_deref());
                match (&build.state, build.platform.as_deref()) {
                    (GemBuildState::Patched { .. }, _) => patched.push(build.purl.clone()),
                    (GemBuildState::Upstream, Some(platform)) => not_patched.push((
                        build.purl.clone(),
                        upstream_build_action(platform, &gem.gem_fix),
                    )),
                    (GemBuildState::Unknown(_), Some(_)) => {
                        let action = unshown.map(|(why, platform)| why.action(platform));
                        not_patched.extend(action.map(|action| (build.purl.clone(), action)));
                    }
                    // The ruby-platform gem of a patch's registry is the
                    // gem's patch, never upstream's nor unknown.
                    (GemBuildState::Upstream | GemBuildState::Unknown(_), None) => {}
                }
                builds.insert(
                    build.purl.clone(),
                    GemBuildInfo {
                        gem_fix: gem.gem_fix.clone(),
                        platform: build.platform.clone(),
                        kept_upstream: upstream,
                        unshown: unshown.map(|(why, platform)| why.reason(platform)),
                    },
                );
            }
            platform_gems.insert(key.clone(), patched);
        }
        Some(Self {
            view,
            platform_gems,
            not_patched,
            builds,
        })
    }

    /// The record view to build the document from.
    pub(crate) fn view(&self) -> &PatchManifest {
        &self.view
    }

    /// The hosted builds that are not shown patched, each with its action
    /// statement: what the document says `affected` of. A build the lock
    /// installs as upstream's own gem, and one of which nothing shows what
    /// the lock installs.
    pub(crate) fn not_patched(&self) -> &[(String, String)] {
        &self.not_patched
    }

    /// Every build the view names in place of a gem, by purl.
    pub(crate) fn builds(&self) -> &BTreeMap<String, GemBuildInfo> {
        &self.builds
    }

    /// Replace each gem of `purls` by its patched builds, in place.
    pub(crate) fn expand(&self, purls: &mut Vec<String>) {
        *purls = std::mem::take(purls)
            .into_iter()
            .flat_map(|purl| match self.platform_gems.get(&purl) {
                Some(platform_gems) => platform_gems.clone(),
                None => vec![purl],
            })
            .collect();
    }

    /// [`Self::expand`] for purls that each carry a note.
    pub(crate) fn expand_noted(&self, noted: &mut Vec<(String, String)>) {
        *noted = std::mem::take(noted)
            .into_iter()
            .flat_map(|(purl, note)| match self.platform_gems.get(&purl) {
                Some(platform_gems) => platform_gems
                    .iter()
                    .map(|purl| (purl.clone(), note.clone()))
                    .collect(),
                None => vec![(purl, note)],
            })
            .collect();
    }
}

/// One hosted-basis view purl's wiring (see [`Plan::hosted`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedWiring {
    /// The patch uuid the purl attests.
    pub uuid: String,
    /// The discovered hosted references wiring it (their `url` / pin say
    /// WHERE the build fetches from — the Go replacement module + version,
    /// the cargo registry source); empty for a ledger-only record.
    pub refs: Vec<PatchedRef>,
}

/// A gem a Bundler lock takes from its patch registry as platform builds
/// (see [`Plan::hosted_gems`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedGem {
    /// The gem patch's uuid: the one pin all the builds go by.
    pub gem_fix: String,
    /// The gem's name and version, as a person reads them.
    pub name: String,
    pub version: String,
    /// The builds the lock names, the ruby-platform gem first.
    pub builds: Vec<HostedGemBuild>,
    /// The plan worked the builds out from the lock and the patch service.
    /// Not so for the pins of the run that moved the lock, which says its
    /// builds itself.
    pub resolved: bool,
}

/// One build a lock names of a [`HostedGem`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedGemBuild {
    /// `None` for the ruby-platform gem.
    pub platform: Option<String>,
    /// What the document names the build:
    /// `pkg:gem/<name>@<version>?platform=<platform>`, or the gem's own
    /// view purl for the ruby-platform gem.
    pub purl: String,
    /// What the lock installs for it.
    pub state: GemBuildState,
    /// For a build in [`GemBuildState::Unknown`]: why nothing shows what
    /// the lock installs for it.
    pub unshown: Option<GemBuildUnshown>,
}

/// Why nothing shows whether a lock installs a patched build or upstream's
/// own gem for a platform build of a hosted gem
/// ([`GemBuildState::Unknown`]), and what settles it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GemBuildUnshown {
    /// `--offline` forbids asking the patch service for the gem's builds.
    Offline,
    /// The reference request failed; its error, safe to print.
    Request(String),
    /// The patch service gave no list of the patch's builds; why.
    NoList(String),
    /// The lock has no `CHECKSUMS` entry for the build, and the index of
    /// its registry could not be read; the error, safe to print.
    IndexUnread(String),
    /// Neither the lock's `CHECKSUMS` nor the index of its registry names
    /// an archive for the build.
    Unpinned,
    /// The list does not name the build's platform.
    Unlisted,
    /// The lock installs another archive than the list names: the list is
    /// of a later state of the registry than the one the lock names.
    Differs,
}

impl From<GemBuildUnknown> for GemBuildUnshown {
    fn from(why: GemBuildUnknown) -> Self {
        match why {
            GemBuildUnknown::Unpinned => GemBuildUnshown::Unpinned,
            GemBuildUnknown::Unlisted => GemBuildUnshown::Unlisted,
            GemBuildUnknown::Differs => GemBuildUnshown::Differs,
        }
    }
}

impl GemBuildUnshown {
    /// The reason in words, said of `them` (`it` for one build, `them`
    /// for several). `detail` adds the error of a read that failed: the
    /// run's warning carries it, the document and the events do not.
    fn why(&self, them: &str, detail: bool) -> String {
        let failed = |what: String, error: &str| match detail {
            true => format!("{what}: {error}"),
            false => what,
        };
        match self {
            GemBuildUnshown::Offline => "--offline forbids asking the patch API".to_string(),
            GemBuildUnshown::Request(error) => {
                failed("the patch API request failed".to_string(), error)
            }
            GemBuildUnshown::NoList(why) => why.clone(),
            GemBuildUnshown::IndexUnread(error) => failed(
                format!(
                    "the lockfile has no CHECKSUMS entry for {them}, and its registry's index \
                     could not be read"
                ),
                error,
            ),
            GemBuildUnshown::Unpinned => format!(
                "neither the lockfile's CHECKSUMS nor its registry's index names an archive for \
                 {them}"
            ),
            GemBuildUnshown::Unlisted => {
                format!("the patch registry does not list {them} now")
            }
            GemBuildUnshown::Differs => format!(
                "the lockfile installs another archive for {them} than the patch registry lists \
                 now"
            ),
        }
    }

    /// What to run to settle it: the request again where one failed,
    /// without `--offline` where that forbade it, and the scan that brings
    /// the lock up to date where the lock and the patch registry disagree.
    fn remedy(&self) -> &'static str {
        match self {
            GemBuildUnshown::Offline => GEM_BUILD_ONLINE,
            GemBuildUnshown::Request(_) | GemBuildUnshown::IndexUnread(_) => GEM_BUILD_RETRY,
            GemBuildUnshown::NoList(_)
            | GemBuildUnshown::Unpinned
            | GemBuildUnshown::Unlisted
            | GemBuildUnshown::Differs => GEM_BUILD_RESCAN,
        }
    }

    /// The action statement of the build for `platform`: what could not be
    /// shown, why, and what settles it. It names no patch: none is shown
    /// to be in what the lock installs.
    fn action(&self, platform: &str) -> String {
        format!(
            "It could not be shown that the lockfile installs a patched build of this gem for \
             {platform} ({}), so it is stated as affected. {}",
            self.why("it", false),
            self.remedy()
        )
    }

    /// What the uncounted [`GEM_BUILD_UNKNOWN`] event of the build for
    /// `platform` says.
    fn reason(&self, platform: &str) -> String {
        format!(
            "not shown patched for {platform}: {}",
            self.why("it", false)
        )
    }
}

impl HostedGem {
    /// The builds of the gem at the view purl `key`, each named and in
    /// the state `state` gives for its platform.
    fn of(
        key: &str,
        gem_fix: &str,
        builds: impl IntoIterator<Item = (Option<String>, GemBuildState)>,
        resolved: bool,
    ) -> Option<Self> {
        let (_, name, version) = purl_parts(key)?;
        let base = strip_purl_qualifiers(key);
        let builds = builds
            .into_iter()
            .map(|(platform, state)| HostedGemBuild {
                purl: match &platform {
                    Some(platform) => format!("{base}?platform={platform}"),
                    None => key.to_string(),
                },
                unshown: match (&state, &platform) {
                    (GemBuildState::Unknown(why), Some(_)) => Some(GemBuildUnshown::from(*why)),
                    _ => None,
                },
                platform,
                state,
            })
            .collect();
        Some(HostedGem {
            gem_fix: gem_fix.to_string(),
            name,
            version,
            builds,
            resolved,
        })
    }

    /// Whether the installed copy at `path` is evidence about the gem at
    /// the view purl `key`. A copy of a platform build the lock does not
    /// install as a patched one is not: the document never calls that
    /// build patched, and a machine of that platform holds what its lock
    /// entry names. Judged as the gem's copy, upstream's own gem there
    /// would withhold the builds the lock does install patched.
    pub(crate) fn judges(&self, key: &str, path: &std::path::Path) -> bool {
        use socket_patch_core::formats::gem::GemBuild;
        let leaf = path.file_name().and_then(|leaf| leaf.to_str());
        let Some(platform) = leaf
            .and_then(|leaf| GemBuild::of_leaf(key, leaf))
            .and_then(|build| build.platform)
        else {
            return true;
        };
        !self.builds.iter().any(|build| {
            build.platform.as_deref() == Some(platform.as_str())
                && !matches!(build.state, GemBuildState::Patched { .. })
        })
    }
}

/// How one view purl is verified.
enum Basis {
    /// The agent-mode path: installed tree / go-patches copy.
    Installed,
    /// The committed `.socket/vendor` artifact named by this entry.
    Vendored(Box<VendorEntry>),
    /// Hosted wiring: installed tree when present, else the lockfile basis
    /// when `lockfile_basis`.
    Hosted { lockfile_basis: bool },
}

/// One attestation candidate (a would-be view purl).
struct Cand {
    key: String,
    /// The patch uuid this candidate attests.
    uuid: String,
    record: Option<PatchRecord>,
    /// Other local records filed under the same key (redirect ledger /
    /// vendor entry) — used when the WIRED uuid is theirs, not the primary's.
    alts: Vec<PatchRecord>,
    manifest_owned: bool,
    /// The redirect ledger records this key.
    redirected: bool,
    vendor_entry: Option<VendorEntry>,
    /// Lockfile references wiring this candidate's package to its uuid.
    discovered: Vec<PatchedRef>,
    /// Born from a lockfile reference no local source records.
    lockfile_only: bool,
}

impl Cand {
    fn from_ref(r: &PatchedRef, vendor: &VendorState) -> Self {
        // A ledger entry for the same patch + package (e.g. an old ledger
        // without an embedded record, whose manifest record is gone) still
        // routes verification: it carries the dir-artifact file inventory.
        let vendor_entry = vendor
            .entries
            .values()
            .find(|e| e.uuid == r.uuid && PurlKey::same(&e.base_purl, &r.purl))
            .cloned();
        Cand {
            key: r.purl.clone(),
            uuid: r.uuid.clone(),
            record: None,
            alts: Vec::new(),
            manifest_owned: false,
            redirected: false,
            vendor_entry,
            discovered: vec![r.clone()],
            lockfile_only: true,
        }
    }
}

/// The run's API client, built at most once: a host command (`scan`,
/// `apply`, `vendor`) seeds it with the client it has built, so embedded
/// `--vex` reuses the run's one org resolution; standalone `vex` leaves it
/// empty and [`fetch_records`] builds it on first need.
pub(crate) use crate::args::RunApiClient;

/// Merge `sources` into a verified-input [`Plan`]. `assume_live` is the
/// in-run `scan --mode hosted --vex` confirmed set (qualifier-insensitive):
/// those ledger records were just proven wired by the run itself.
/// `api_client` is the run's client (see [`RunApiClient`]).
pub(crate) async fn plan(
    common: &GlobalArgs,
    sources: Sources,
    assume_live: &[String],
    api_client: &RunApiClient,
) -> Plan {
    // The ledgers' project: liveness and JVM wiring are judged where
    // the ledger and the discovery that gates it were read.
    let root_buf = common.project_root();
    let root = root_buf.as_path();
    let Sources {
        manifest,
        vendor,
        mut redirect,
        discovery,
        hosted_uuids,
        hosted_gem_builds,
    } = sources;
    let mut notes = Vec::new();
    // The in-run hosted pins' records, filed under the API's purl like a
    // pre-v5 hosted ledger's, later uuids winning. A uuid fetched here is
    // not asked for again below.
    let mut prefetched: HashSet<String> = HashSet::new();
    let hosted_uuids: Vec<String> = hosted_uuids
        .into_iter()
        .filter(|uuid| prefetched.insert(uuid.clone()))
        .collect();
    if !hosted_uuids.is_empty() {
        let mut fetched = fetch_records(common, api_client, &hosted_uuids, &mut notes).await;
        let state = redirect.get_or_insert_with(RedirectState::new);
        for uuid in &hosted_uuids {
            if let Some((purl, record)) = fetched.remove(uuid) {
                state.records.insert(purl, record);
            }
        }
    }
    let redirect_records: BTreeMap<String, PatchRecord> = redirect
        .as_ref()
        .map(|r| r.records.clone())
        .unwrap_or_default();
    let assumed: HashSet<&str> = assume_live
        .iter()
        .map(|p| strip_purl_qualifiers(p))
        .collect();

    let mut gated: Vec<FailedPatch> = Vec::new();
    let mut cands = build_candidates(&manifest, &vendor, redirect.as_ref());
    let conflicts = wiring_conflicts(&discovery);
    if !conflicts.is_empty() {
        // Gate every candidate for a conflicting package BEFORE anything can
        // attest it: keeping the first-found candidate would publish a
        // `not_affected` for a patch the build may not consume, next to a
        // skip for the same purl.
        let mut conflicted_keys: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        cands.retain(|c| {
            let pkg = canonical_base_purl(&c.key);
            match conflicts.iter().find(|(k, _)| PurlKey::same(k, &pkg)) {
                Some((k, _)) => {
                    conflicted_keys
                        .entry(k.as_str())
                        .or_default()
                        .push(c.key.clone());
                    false
                }
                None => true,
            }
        });
        for (pkg, wiring) in &conflicts {
            let mut keys = conflicted_keys.remove(pkg.as_str()).unwrap_or_default();
            if keys.is_empty() {
                keys.push(pkg.clone());
            }
            keys.sort();
            keys.dedup();
            for key in keys {
                gated.push(failed(&key, WIRING_CONFLICT));
            }
            notes.push(PlanNote {
                code: NOTE_WIRING_CONFLICT,
                detail: format!(
                    "{pkg}: the lockfiles wire it to different patches ({wiring}); which one the \
                     build installs cannot be told from the files, so none is attested — make \
                     the lockfiles agree (re-run `socket-patch scan` or delete the stale lock)"
                ),
            });
        }
    }
    let superseded = attach_discovered(&mut cands, &discovery, &vendor, &conflicts);
    // Wired, but a build bypasses the pin (`Unattested`: a Gradle lock
    // above the hosted base resolves the newer upstream release, a pnpm
    // bundled copy, a deno.lock copy, an npm shrinkwrap with no
    // package-lock.json twin, which npm >= 12 ignores, a pnpm lock
    // `gitBranchLockfile` bypasses, a package the project patches itself):
    // the ref keeps
    // rollback, remove, list and the ledgers' liveness working, and the
    // patch is omitted.
    // A file-scoped mark (a Go replace the workspace keeps from the build)
    // bypasses only its own file's ref: another file's live ref of the
    // same patch attests on its own basis, without the bypassed one.
    // Purls some candidate attests through a ref no mark bypasses: a
    // lockfile-only candidate left with nothing but file-scoped bypassed
    // refs of the same purl (a stale pin the workspace keeps from the
    // build) is then dropped, never both attested and reported skipped.
    let live_purls: Vec<String> = cands
        .iter()
        .filter(|c| c.discovered.iter().any(|r| !bypassed_ref(&discovery, r)))
        .map(|c| canonical_base_purl(&c.key))
        .collect();
    cands.retain_mut(|c| {
        let pkg = canonical_base_purl(&c.key);
        let marks: Vec<&Unattested> = discovery
            .unattested
            .iter()
            .filter(|u| u.uuid == c.uuid && PurlKey::same(&u.purl, &pkg))
            .collect();
        let Some(&first) = marks.first() else {
            return true;
        };
        let u = match marks.iter().find(|u| !u.kind.file_scoped()) {
            Some(u) => *u,
            None => {
                c.discovered.retain(|r| !bypassed_ref(&discovery, r));
                if !c.discovered.is_empty() {
                    return true;
                }
                if c.lockfile_only && live_purls.iter().any(|p| PurlKey::same(p, &pkg)) {
                    notes.push(PlanNote {
                        code: unattested_note(first.kind).0,
                        detail: format!(
                            "{}: patch {}'s wiring is bypassed ({}); another patch's live \
                             wiring of the same package is attested",
                            c.key, c.uuid, first.detail
                        ),
                    });
                    return false;
                }
                first
            }
        };
        gate_unattested(&c.key, u, &mut gated, &mut notes);
        false
    });
    for (key, old_uuid, wired) in &superseded {
        notes.push(PlanNote {
            code: NOTE_RECORD_SUPERSEDED,
            detail: format!(
                "{key}: the recorded patch {old_uuid} is superseded by the lockfile-wired patch \
                 {wired}; attesting only what the lockfile wires"
            ),
        });
    }

    let mut liveness = LedgerLiveness::new(root, &discovery, redirect.as_ref());
    let mut based: Vec<(Cand, Basis)> = Vec::new();
    for mut cand in cands {
        if let Some(entry) = cand
            .vendor_entry
            .as_ref()
            .filter(|e| socket_patch_core::vendor::jvm::apply::is_jvm_entry(e))
        {
            if let Err(detail) =
                socket_patch_core::vendor::jvm::apply::entry_wired_checked(root, entry)
            {
                const CODE: &str = "vendor_jvm_shape_unsupported";
                gated.push(failed(&cand.key, CODE));
                notes.push(PlanNote {
                    code: CODE,
                    detail: format!("{}: cannot establish JVM wiring: {detail}", cand.key),
                });
                continue;
            }
        }
        let mut took_over = false;
        // A JVM entry is attested from its own tree, as it is without the
        // copy of its jar that the block of a Bazel hub names.
        let of_tree = cand
            .vendor_entry
            .as_ref()
            .is_some_and(socket_patch_core::vendor::jvm::apply::is_jvm_entry);
        let basis = if let Some(vref) = cand
            .discovered
            .iter()
            .find(|r| r.mode == WiringMode::Vendored && !of_tree)
        {
            Basis::Vendored(Box::new(vendored_entry_for(&cand, vref)))
        } else if cand.discovered.iter().any(|r| r.mode == WiringMode::Hosted) {
            // Every lock wiring the patch must allow the basis. Which lock
            // the build installs from is not decidable from the files (the
            // cross-lock contest's argument), so a pinned lock never vouches
            // for one whose pin is missing.
            Basis::Hosted {
                lockfile_basis: cand.discovered.iter().all(PatchedRef::lockfile_basis_ok),
            }
        } else if let Some(entry) = &cand.vendor_entry {
            if liveness.vendor_entry(entry).await {
                Basis::Vendored(Box::new(entry.clone()))
            } else if let Some(hosted) = redirect_records.get(&cand.key).cloned() {
                // Hosted-over-vendored takeover: `scan --mode hosted` over a
                // vendored package leaves the vendor entry in place, so the
                // dead vendor claim does not end the story — the live hosted
                // claim (the redirect ledger's record, possibly another
                // uuid) is what the lockfile wires now.
                let live = assumed.contains(strip_purl_qualifiers(&cand.key))
                    || liveness.redirect_record(&cand.key, &hosted.uuid).await;
                if !live {
                    notes.extend(dead_claim_notes(
                        &discovery,
                        &cand.key,
                        &[
                            (&entry.uuid, WiringMode::Vendored, "vendor ledger"),
                            (&hosted.uuid, WiringMode::Hosted, "hosted ledger"),
                        ],
                    ));
                    gated.push(failed(&cand.key, VENDOR_UNWIRED));
                    continue;
                }
                cand.uuid = hosted.uuid.clone();
                cand.record = Some(hosted);
                cand.vendor_entry = None;
                took_over = true;
                Basis::Hosted {
                    lockfile_basis: false,
                }
            } else {
                notes.extend(dead_claim_notes(
                    &discovery,
                    &cand.key,
                    &[(&entry.uuid, WiringMode::Vendored, "vendor ledger")],
                ));
                gated.push(failed(&cand.key, VENDOR_UNWIRED));
                continue;
            }
        } else if cand.redirected {
            let verdict = if assumed.contains(strip_purl_qualifiers(&cand.key)) {
                RecordLiveness::Live
            } else {
                liveness
                    .redirect_record_verdict(&cand.key, &cand.uuid)
                    .await
            };
            if verdict.attests() {
                Basis::Hosted {
                    lockfile_basis: false,
                }
            } else if cand.manifest_owned {
                // The hosted claim is dead but the manifest still owns the
                // purl: verify it as the agent-mode patch it now is.
                Basis::Installed
            } else {
                if verdict == RecordLiveness::Undecided {
                    notes.push(foreign_origin_note(&cand.key, &cand.uuid));
                }
                notes.extend(dead_claim_notes(
                    &discovery,
                    &cand.key,
                    &[(&cand.uuid, WiringMode::Hosted, "hosted ledger")],
                ));
                gated.push(failed(&cand.key, REDIRECT_UNWIRED));
                continue;
            }
        } else {
            Basis::Installed
        };
        // The vendored basis attests the ENTRY's patch, which need not be
        // the candidate's uuid (a manifest record under another uuid keeps
        // the key; a vendored sbt pin has no ref to swap it in): its mark
        // is checked against what is actually attested.
        // Likewise the hosted-over-vendored takeover attests the redirect
        // ledger's uuid, swapped in after the early gate ran.
        let attested = match &basis {
            Basis::Vendored(entry) => Some((entry.base_purl.as_str(), entry.uuid.as_str())),
            Basis::Hosted { .. } if took_over => Some((cand.key.as_str(), cand.uuid.as_str())),
            _ => None,
        };
        if let Some(u) = attested.and_then(|(purl, uuid)| unattested_mark(&discovery, purl, uuid)) {
            gate_unattested(&cand.key, u, &mut gated, &mut notes);
            continue;
        }
        based.push((cand, basis));
    }

    let mut need_api: Vec<usize> = Vec::new();
    for (i, (cand, _)) in based.iter_mut().enumerate() {
        if cand.record.is_some() {
            continue;
        }
        let expected_pkg = expected_package(cand);
        match local_record_by_uuid(&cand.uuid, &manifest, &redirect_records, &vendor) {
            Some((found_key, record)) if PurlKey::same(&found_key, &expected_pkg) => {
                if cand.lockfile_only {
                    cand.key = found_key;
                }
                cand.record = Some(record);
            }
            // The uuid's local record is filed under another package: the
            // wiring and the record disagree about what was patched.
            Some(_) => cand.record = None,
            None => need_api.push(i),
        }
    }
    let uuids: Vec<String> = {
        let mut u: Vec<String> = need_api
            .iter()
            .map(|&i| based[i].0.uuid.clone())
            .filter(|uuid| !prefetched.contains(uuid))
            .collect();
        u.sort();
        u.dedup();
        u
    };
    let fetched = fetch_records(common, api_client, &uuids, &mut notes).await;
    let mut mismatched: HashSet<usize> = HashSet::new();
    for &i in &need_api {
        let cand = &mut based[i].0;
        match fetched.get(&cand.uuid) {
            Some((api_purl, record))
                if record.uuid == cand.uuid && PurlKey::same(api_purl, &expected_package(cand)) =>
            {
                if cand.lockfile_only {
                    cand.key = api_purl.clone();
                }
                cand.record = Some(record.clone());
            }
            Some(_) => {
                mismatched.insert(i);
            }
            None => {}
        }
    }

    let mut plan = Plan {
        view: PatchManifest {
            patches: HashMap::new(),
            setup: manifest.setup.clone(),
        },
        vendor_entries: HashMap::new(),
        vendor_pins: HashMap::new(),
        redirected: Vec::new(),
        lockfile_basis: HashSet::new(),
        hosted: BTreeMap::new(),
        hosted_gems: BTreeMap::new(),
        gated,
        notes,
    };
    // Keys two candidates resolved to (see the collision branch below).
    let mut collided: HashSet<String> = HashSet::new();
    for (i, (cand, basis)) in based.into_iter().enumerate() {
        let Some(record) = cand.record else {
            let tag = if mismatched.contains(&i) || !need_api.contains(&i) {
                RECORD_MISMATCH
            } else {
                RECORD_UNAVAILABLE
            };
            plan.gated.push(failed(&cand.key, tag));
            continue;
        };
        if collided.contains(&cand.key) || plan.view.patches.contains_key(&cand.key) {
            // Two candidates resolved to ONE purl with different records
            // (a lockfile-only candidate renamed to the key its record is
            // filed under, colliding with an existing candidate). Neither
            // guess may attest: evict the first — its view entry and every
            // basis entry — and omit both, so the purl never carries a
            // statement and a skip at once.
            if plan.view.patches.remove(&cand.key).is_some() {
                plan.vendor_entries.remove(&cand.key);
                plan.vendor_pins.remove(&cand.key);
                plan.redirected.retain(|k| *k != cand.key);
                plan.lockfile_basis.remove(&cand.key);
                plan.hosted.remove(&cand.key);
            }
            collided.insert(cand.key.clone());
            plan.gated.push(failed(&cand.key, RECORD_MISMATCH));
            continue;
        }
        match basis {
            Basis::Installed => {}
            Basis::Vendored(entry) => {
                let found = cand.discovered.iter();
                let found = found.filter(|r| r.mode == WiringMode::Vendored);
                let pins = found.map(|r| r.source_file.to_string_lossy().replace('\\', "/"));
                plan.vendor_pins.insert(cand.key.clone(), pins.collect());
                plan.vendor_entries.insert(cand.key.clone(), *entry);
            }
            Basis::Hosted { lockfile_basis } => {
                plan.redirected.push(cand.key.clone());
                if lockfile_basis {
                    plan.lockfile_basis.insert(cand.key.clone());
                }
                plan.hosted.insert(
                    cand.key.clone(),
                    HostedWiring {
                        uuid: record.uuid.clone(),
                        refs: cand
                            .discovered
                            .iter()
                            .filter(|r| r.mode == WiringMode::Hosted && r.uuid == record.uuid)
                            .cloned()
                            .collect(),
                    },
                );
            }
        }
        plan.view.patches.insert(cand.key, record);
    }
    plan.redirected.sort();
    resolve_hosted_gems(common, root, &mut plan, &hosted_gem_builds, api_client).await;
    // One skip per (purl, reason): a collision gates its key once per
    // colliding candidate.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    plan.gated
        .retain(|f| seen.insert((f.purl.clone(), f.reason.clone())));
    plan
}

fn failed(purl: &str, reason: &str) -> FailedPatch {
    FailedPatch {
        purl: purl.to_string(),
        reason: reason.to_string(),
    }
}

/// The package a candidate's record must name (canonical form).
fn expected_package(cand: &Cand) -> String {
    match (&cand.vendor_entry, cand.lockfile_only) {
        (Some(entry), false) => canonical_base_purl(&entry.base_purl),
        _ => canonical_base_purl(&cand.key),
    }
}

/// One candidate per owner key under the shared owner rule
/// ([`socket_patch_core::ledgers::Ledgers::owned`]): the manifest keys, then
/// the unclaimed vendor-ledger keys, then the redirect-ledger keys neither
/// owns, each sorted, with the losing copies' records as `alts`.
fn build_candidates(
    manifest: &PatchManifest,
    vendor: &VendorState,
    redirect: Option<&RedirectState>,
) -> Vec<Cand> {
    use socket_patch_core::ledgers::{Ledgers, Store};
    Ledgers {
        manifest: Some(manifest),
        vendor: Some(vendor),
        redirect,
    }
    .owned()
    .into_iter()
    .map(|o| Cand {
        key: o.key.to_string(),
        uuid: o.uuid.to_string(),
        record: o.record.cloned(),
        alts: o.alts.into_iter().cloned().collect(),
        manifest_owned: o.store == Store::Manifest,
        redirected: o.hosted,
        vendor_entry: o.vendor.map(|(_, e)| e.clone()),
        discovered: Vec::new(),
        lockfile_only: false,
    })
    .collect()
}

/// Packages the discovered references wire to MORE than one patch uuid
/// (any mix of modes and files), mapped to a human description of the
/// disagreeing wiring (`<uuid> (<file>), …`) for the note.
fn wiring_conflicts(discovery: &Discovery) -> BTreeMap<String, String> {
    let mut by_pkg: BTreeMap<&str, BTreeMap<&str, BTreeSet<String>>> = BTreeMap::new();
    // A ref whose file the build never reads wires nothing it installs.
    // The root go.mod is the exception: a `GOWORK=off` build from the root
    // reads it (cf. `ReplaceHost::mirrors_root_go_mod`), so a different
    // patch there still disagrees with the go.work that overrides it.
    for r in discovery
        .refs
        .iter()
        .filter(|r| r.source_file == std::path::Path::new("go.mod") || !bypassed_ref(discovery, r))
    {
        by_pkg
            .entry(r.purl.as_str())
            .or_default()
            .entry(r.uuid.as_str())
            .or_default()
            .insert(r.source_file.to_string_lossy().into_owned());
    }
    by_pkg
        .into_iter()
        .filter(|(_, uuids)| uuids.len() > 1)
        .map(|(pkg, uuids)| {
            let wiring: Vec<String> = uuids
                .into_iter()
                .map(|(uuid, files)| {
                    format!(
                        "{uuid} ({})",
                        files.into_iter().collect::<Vec<_>>().join(", ")
                    )
                })
                .collect();
            (pkg.to_string(), wiring.join(", "))
        })
        .collect()
}

/// Whether a file-scoped [`Unattested`] mark ([`UnattestedKind::file_scoped`])
/// covers `r`: the same patch and package, in the same file.
fn bypassed_ref(discovery: &Discovery, r: &PatchedRef) -> bool {
    discovery.unattested.iter().any(|u| {
        u.kind.file_scoped()
            && u.uuid == r.uuid
            && u.file == r.source_file
            && PurlKey::same(&u.purl, &canonical_base_purl(&r.purl))
    })
}

/// Attach every lockfile reference (except those of `conflicts`' packages,
/// already gated) to the candidate(s) for its package and patch; a package the lockfile wires to a patch no candidate records gets
/// a new lockfile-only candidate, and a candidate for a wired package whose
/// uuid the lockfile does NOT wire is superseded (removed). Returns
/// `(key, superseded uuid, wired uuids)` for the human notes.
fn attach_discovered(
    cands: &mut Vec<Cand>,
    discovery: &Discovery,
    vendor: &VendorState,
    conflicts: &BTreeMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut groups: BTreeMap<&str, Vec<&PatchedRef>> = BTreeMap::new();
    for r in &discovery.refs {
        if !conflicts.contains_key(&r.purl) {
            groups.entry(r.purl.as_str()).or_default().push(r);
        }
    }
    let mut new_cands: Vec<Cand> = Vec::new();
    let mut superseded_idx: Vec<usize> = Vec::new();
    let mut superseded = Vec::new();
    for (pkg, refs) in groups {
        let idxs: Vec<usize> = (0..cands.len())
            .filter(|&i| PurlKey::same(&cands[i].key, pkg))
            .collect();
        // Pass 1: the candidate already attests the wired uuid.
        let mut unmatched: Vec<&PatchedRef> = Vec::new();
        for r in &refs {
            let mut matched = false;
            for &i in &idxs {
                if cands[i].uuid == r.uuid {
                    cands[i].discovered.push((*r).clone());
                    matched = true;
                }
            }
            if !matched {
                unmatched.push(r);
            }
        }
        // Pass 2: an unconfirmed candidate holds the wired uuid's record as
        // an alternative (manifest says U1, its redirect/vendor ledger
        // record says the wired U2): the wired uuid wins.
        let mut remaining: Vec<&PatchedRef> = Vec::new();
        for r in unmatched {
            let mut matched = false;
            for &i in &idxs {
                let cand = &mut cands[i];
                if cand.uuid != r.uuid && !cand.discovered.is_empty() {
                    continue;
                }
                if cand.uuid != r.uuid {
                    let Some(alt) = cand.alts.iter().find(|a| a.uuid == r.uuid).cloned() else {
                        continue;
                    };
                    cand.uuid = alt.uuid.clone();
                    cand.record = Some(alt);
                }
                cand.discovered.push(r.clone());
                matched = true;
            }
            if !matched {
                remaining.push(r);
            }
        }
        // Wired patches nothing local records: lockfile-only candidates
        // (one per uuid; several files may wire the same patch).
        for r in remaining {
            match new_cands
                .iter_mut()
                .find(|c| c.key == r.purl && c.uuid == r.uuid)
            {
                Some(existing) => existing.discovered.push(r.clone()),
                None => new_cands.push(Cand::from_ref(r, vendor)),
            }
        }
        let wired: Vec<&str> = {
            let mut u: Vec<&str> = refs.iter().map(|r| r.uuid.as_str()).collect();
            u.sort();
            u.dedup();
            u
        };
        for &i in &idxs {
            if cands[i].discovered.is_empty() {
                superseded_idx.push(i);
                superseded.push((
                    cands[i].key.clone(),
                    cands[i].uuid.clone(),
                    wired.join(", "),
                ));
            }
        }
    }
    superseded_idx.sort_unstable();
    for i in superseded_idx.into_iter().rev() {
        cands.remove(i);
    }
    cands.extend(new_cands);
    superseded
}

/// The artifact entry a vendored reference verifies against: the ledger
/// entry when it names exactly the wired artifact (it carries the
/// dir-artifact file inventory), else one synthesized from the reference.
/// A synthesized entry has no `file_inventory` (member-only verification of
/// dir-shaped artifacts — the documented weaker basis) and no `sha256`
/// (nothing in verification asserts it; the bun mirror check recomputes the
/// canonical tarball digest).
fn vendored_entry_for(cand: &Cand, vref: &PatchedRef) -> VendorEntry {
    let wired = vref.artifact_rel.as_deref().unwrap_or_default();
    if let Some(entry) = &cand.vendor_entry {
        if entry.uuid == vref.uuid && entry.artifact.path.trim_start_matches("./") == wired {
            return entry.clone();
        }
    }
    let eco = vendor_ref(wired).map(|v| v.eco).unwrap_or_default();
    let source = vref.source_file.to_string_lossy();
    VendorEntry {
        // Bun's workspace-mirror integrity check and the vlt package-dir
        // verifier (structure rule, manifest exemption by the local blob,
        // since there is no inventory pin) key off the flavor.
        flavor: match source.as_ref() {
            "bun.lock" | "bun.lockb" => Some("bun".to_string()),
            "vlt-lock.json" => Some("vlt".to_string()),
            _ => None,
        },
        detached: true,
        ..VendorEntry::new(
            eco,
            strip_purl_qualifiers(&cand.key).to_string(),
            vref.uuid.clone(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: wired.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            Vec::new(),
        )
    }
}

/// One `vex_claim_unwired` note per dead `(uuid, mode, ledger)` claim of one
/// candidate that discovery's authority killed although the lockfiles still
/// MENTION the patch (rule 11): which files, and the extractor's own reason
/// when it gave one (a diagnostic from one of those files naming the uuid).
/// A claim whose uuid discovery does not recognize died on the ledger's own
/// evidence; its skip reason says all there is, so it gets no note.
fn dead_claim_notes(
    discovery: &Discovery,
    key: &str,
    claims: &[(&str, WiringMode, &str)],
) -> Vec<PlanNote> {
    let mut notes = Vec::new();
    for &(uuid, mode, ledger) in claims {
        let files = discovery.recognized_files(uuid, mode);
        if files.is_empty() {
            continue;
        }
        let reason = discovery
            .diagnostics
            .iter()
            .find(|d| files.contains(&d.file.as_path()) && d.detail.contains(uuid))
            .map(|d| format!(" ({}: {})", d.code, d.detail))
            .unwrap_or_default();
        let names: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
        notes.push(PlanNote {
            code: NOTE_CLAIM_UNWIRED,
            detail: format!(
                "{key}: the {ledger} records patch {uuid}, and {} still mention{} it, but not as \
                 wiring the package manager consumes for this package{reason}; not attested",
                names.join(", "),
                if names.len() == 1 { "s" } else { "" },
            ),
        });
    }
    notes
}

/// Why a hosted-ledger record whose wiring resolves from a patch server
/// this run was not given ([`RecordLiveness::Undecided`]) is not attested:
/// fail closed, and say how a staging server is admitted.
fn foreign_origin_note(key: &str, uuid: &str) -> PlanNote {
    PlanNote {
        code: NOTE_CLAIM_UNWIRED,
        detail: format!(
            "{key}: the hosted ledger records patch {uuid}, but its wiring resolves it from a \
             patch server this run was not given; pass --patch-server-url for a non-production \
             patch server; not attested"
        ),
    }
}

/// A local record for `uuid` (manifest, then redirect ledger, then vendor
/// entries) with the key it is filed under.
fn local_record_by_uuid(
    uuid: &str,
    manifest: &PatchManifest,
    redirect_records: &BTreeMap<String, PatchRecord>,
    vendor: &VendorState,
) -> Option<(String, PatchRecord)> {
    let mut manifest_hits: Vec<(&String, &PatchRecord)> = manifest
        .patches
        .iter()
        .filter(|(_, r)| r.uuid == uuid)
        .collect();
    manifest_hits.sort_by(|a, b| a.0.cmp(b.0));
    if let Some((k, r)) = manifest_hits.first() {
        return Some(((*k).clone(), (*r).clone()));
    }
    if let Some((k, r)) = redirect_records.iter().find(|(_, r)| r.uuid == uuid) {
        return Some((k.clone(), r.clone()));
    }
    let mut vendor_hits: Vec<(&String, &PatchRecord)> = vendor
        .entries
        .iter()
        .filter_map(|(k, e)| e.record.as_ref().map(|r| (k, r)))
        .filter(|(_, r)| r.uuid == uuid)
        .collect();
    vendor_hits.sort_by(|a, b| a.0.cmp(b.0));
    vendor_hits
        .first()
        .map(|(k, r)| ((*k).clone(), (*r).clone()))
}

/// The run's client: the host's, or built here once (standalone `vex`).
async fn run_client(
    common: &GlobalArgs,
    api_client: &RunApiClient,
    notes: &mut Vec<PlanNote>,
) -> ApiClient {
    let overrides = common.api_client_overrides();
    let built_here = !api_client.initialized();
    let client = api_client
        .get_or_init(|| async { get_api_client_with_overrides(overrides).await.0 })
        .await
        .clone();
    // A client built here whose org could not be resolved put the run on
    // the proxy. Its construction already warned on stderr, so only the
    // `--json` envelope needs the note (a host that seeded its client
    // reports this itself).
    if built_here && common.json {
        if let Some(reason) = client.org_unresolved() {
            notes.push(PlanNote {
                code: NOTE_API_AUTH_FALLBACK,
                detail: reason.to_string(),
            });
        }
    }
    client
}

/// Fetch the patch view for each of `uuids` (online only; empty under
/// `--offline`) with bounded concurrency and `get`'s one-shot 401/403 →
/// public-proxy fallback. Returns `uuid → (api purl, record)` for every view
/// that came back; 404s, refusals and transport errors are simply absent
/// (the caller omits those references as `record_unavailable`) and noted.
async fn fetch_records(
    common: &GlobalArgs,
    api_client: &RunApiClient,
    uuids: &[String],
    notes: &mut Vec<PlanNote>,
) -> HashMap<String, (String, PatchRecord)> {
    let mut out = HashMap::new();
    if uuids.is_empty() {
        return out;
    }
    if common.offline {
        let n = uuids.len();
        notes.push(PlanNote {
            code: NOTE_RECORD_OFFLINE,
            detail: format!(
                "{} no local record (manifest or .socket/vendor ledgers), and --offline forbids \
                 fetching {} from the patch API",
                plural(n, "lockfile-wired patch has", "lockfile-wired patches have"),
                if n == 1 { "it" } else { "them" },
            ),
        });
        return out;
    }
    let overrides = common.api_client_overrides();
    let mut client = run_client(common, api_client, notes).await;
    let mut use_public_proxy = client.uses_public_proxy();
    let mut pending: Vec<String> = uuids.to_vec();
    // Each view is a heavy response: say what the run is waiting on (a live
    // line only on a terminal, never under --json / --silent; the VEX
    // document itself goes to stdout).
    let mut status = crate::ui::StatusLine::stderr(common.json, common.silent);
    let total = uuids.len();
    let mut done = 0;
    loop {
        let mut auth_refused: Vec<String> = Vec::new();
        let mut auth_error: Option<String> = None;
        // A sliding window of views in flight, consumed in `pending` order,
        // so the reported `auth_error` and the retried `pending` list are
        // deterministic.
        {
            let client = &client;
            let mut views = std::pin::pin!(ordered_concurrent(
                pending.iter(),
                fetch_concurrency(use_public_proxy),
                // The record is built from the view's hashes and
                // advisories: its file contents are never read here.
                |uuid| async move {
                    (
                        uuid,
                        hold_back_debug(client.fetch_patch_summary(uuid)).await,
                    )
                },
            ));
            loop {
                status.progress(
                    if total == 1 {
                        "Reading the patch record"
                    } else {
                        "Reading patch records"
                    },
                    done,
                    total,
                );
                let Some((uuid, result)) = views.next().await else {
                    break;
                };
                let uuid = uuid.clone();
                done += 1;
                match result.release() {
                    Ok(Some(view)) => {
                        out.insert(
                            uuid,
                            socket_patch_core::manifest::records::record_from_patch_response(&view),
                        );
                    }
                    Ok(None) => notes.push(PlanNote {
                        code: NOTE_RECORD_NOT_FOUND,
                        detail: format!("Patch {uuid} was not found by the patch API"),
                    }),
                    Err(e) if !use_public_proxy && is_fallback_candidate(&e) => {
                        auth_error.get_or_insert_with(|| e.to_string());
                        auth_refused.push(uuid)
                    }
                    Err(e) => notes.push(PlanNote {
                        code: NOTE_RECORD_FETCH_FAILED,
                        detail: format!("Could not fetch patch {uuid}: {e}"),
                    }),
                }
            }
        }
        if auth_refused.is_empty() || use_public_proxy {
            break;
        }
        // Same stale-credential recovery (and warning text) as `get` /
        // `scan`: free patches are still served by the public proxy.
        notes.push(PlanNote {
            code: NOTE_API_AUTH_FALLBACK,
            detail: format!(
                "authenticated API returned {}; falling back to public patch API proxy (free \
                 patches only).",
                auth_error.unwrap_or_default()
            ),
        });
        client = build_proxy_fallback_client(&overrides);
        use_public_proxy = true;
        // The refused views are fetched again: not done yet.
        done = total - auth_refused.len();
        pending = auth_refused;
    }
    out
}

/// A hosted gem whose builds the plan works out.
struct PendingGem {
    /// Its view purl.
    key: String,
    /// The gem patch's uuid.
    uuid: String,
    name: String,
    version: String,
    /// The registry the lock takes the gem from.
    remote: String,
    /// The builds the lock names.
    pins: Vec<LockedGemPin>,
}

impl PendingGem {
    /// The lock's `CHECKSUMS` does not pin every platform build: what the
    /// lock installs for those is what its registry serves.
    fn needs_index(&self) -> bool {
        self.pins
            .iter()
            .any(|pin| pin.platform.is_some() && pin.sha256.is_none())
    }
}

/// What to run for a build whose state a later run can read.
const GEM_BUILD_RETRY: &str = "Run `socket-patch vex` again to attest each build.";
/// What to run for a build `--offline` kept the run from asking about.
const GEM_BUILD_ONLINE: &str = "Run `socket-patch vex` without --offline to attest each build.";
/// What to run for a build the lock and the patch registry disagree about.
const GEM_BUILD_RESCAN: &str = "Run `socket-patch scan --mode hosted` to bring the lockfile up \
    to date, then `socket-patch vex` again.";

/// The [`GEM_BUILD_UNKNOWN`] note of the gem at `key`: nothing shows what
/// the lock installs for the builds of `platforms`, for the reason `why`,
/// so the document says `affected` of them.
fn gem_build_note(key: &str, gem_fix: &str, platforms: &[&str], why: &GemBuildUnshown) -> PlanNote {
    let one = platforms.len() == 1;
    let them = if one { "it" } else { "them" };
    PlanNote {
        code: GEM_BUILD_UNKNOWN,
        detail: format!(
            "{key}: the lockfile takes its {} for {} from the registry of Socket patch {gem_fix}, \
             which serves a patched build for some platforms and upstream's own gem for the \
             others. Which it is for {} could not be told ({}), so the VEX document states \
             {them} as affected. {}",
            if one { "build" } else { "builds" },
            platforms.join(", "),
            if one { "this one" } else { "these" },
            why.why(them, true),
            why.remedy(),
        ),
    }
}

/// Work out [`Plan::hosted_gems`], and why nothing shows what the lock
/// installs for a build where nothing does.
///
/// A gem `in_run` reports (a pin of the hosted run this plan is part of)
/// takes its builds from there. Any other hosted gem is read from the lock
/// that wires it. One the lock names as its ruby-platform gem alone stays
/// the one pin it is, and nothing is asked for it. For the others the
/// patch service is asked once for the references of all their patches
/// (each lists its patch's builds), and the registry a lock names once per
/// gem, only where that lock's `CHECKSUMS` does not pin every build
/// ([`gem_index`]).
///
/// Under `--offline`, and where a request fails or the answers do not
/// settle a build, nothing is known of it: the build keeps the reason
/// ([`HostedGemBuild::unshown`]), which the document states it as
/// affected with, and a note names the gem and what to run, once per gem
/// and reason ([`GEM_BUILD_UNKNOWN`]). Nothing is gated: the run is no
/// less a success for it. The ruby-platform gem a lock names beside the
/// platform builds is the gem's patch by the lock's wiring, whatever the
/// requests say.
async fn resolve_hosted_gems(
    common: &GlobalArgs,
    root: &std::path::Path,
    plan: &mut Plan,
    in_run: &[PinReport],
    api_client: &RunApiClient,
) {
    let mut pending: Vec<PendingGem> = Vec::new();
    for (key, wiring) in &plan.hosted {
        if Ecosystem::from_purl(key) != Some(Ecosystem::Gem) {
            continue;
        }
        let reported: Vec<(Option<String>, GemBuildState)> = in_run
            .iter()
            .filter(|report| report.gem_fix.as_deref() == Some(wiring.uuid.as_str()))
            .map(|report| {
                let state = match &report.uuid {
                    Some(uuid) => GemBuildState::Patched { uuid: uuid.clone() },
                    None => GemBuildState::Upstream,
                };
                (report.platform.clone(), state)
            })
            .collect();
        if !reported.is_empty() {
            if let Some(gem) = HostedGem::of(key, &wiring.uuid, reported, false) {
                plan.hosted_gems.insert(key.clone(), gem);
            }
            continue;
        }
        let Some((_, name, version)) = purl_parts(key) else {
            continue;
        };
        // The lock that wires the gem, and the registry it names there.
        let wired = wiring
            .refs
            .iter()
            .find_map(|r| Some((r.source_file.as_path(), r.url.clone()?)));
        let Some((lock, remote)) = wired else {
            continue;
        };
        let Ok(text) = socket_patch_core::utils::fs::read_regular_to_string(&root.join(lock)).await
        else {
            continue;
        };
        let pins = locked_gem_pins(&text, &name, &version);
        if pins.iter().all(|pin| pin.platform.is_none()) {
            continue;
        }
        pending.push(PendingGem {
            key: key.clone(),
            uuid: wiring.uuid.clone(),
            name,
            version,
            remote,
            pins,
        });
    }
    if pending.is_empty() {
        return;
    }

    // What each patch's reference lists, and what each lock's registry
    // serves where the lock does not say.
    let (lists, indexes) = if common.offline {
        let unread = |_: &PendingGem| Err(GemBuildUnshown::Offline);
        let lists: Vec<_> = pending.iter().map(unread).collect();
        (lists, pending.iter().map(|_| None).collect())
    } else {
        crate::ui::busy(
            common,
            "Reading gem builds",
            read_gem_builds(common, api_client, &pending, &mut plan.notes),
        )
        .await
    };

    for ((gem, list), index) in pending.iter().zip(lists).zip(indexes) {
        let (listed, unread) = match list {
            Ok(listed) => (listed, None),
            Err(unread) => (Vec::new(), Some(unread)),
        };
        let served = index.as_ref().and_then(|read| read.as_deref().ok());
        let states = gem_build_states(&gem.version, &gem.pins, &gem.uuid, &listed, served);
        let builds = gem.pins.iter().map(|pin| pin.platform.clone()).zip(states);
        let Some(mut hosted) = HostedGem::of(&gem.key, &gem.uuid, builds, true) else {
            continue;
        };
        // What the reads say of a build beyond its state: with no list,
        // why there is none; with no index, the error of that read.
        for build in &mut hosted.builds {
            let Some(why) = build.unshown.take() else {
                continue;
            };
            build.unshown = Some(match (&unread, why, &index) {
                (Some(unread), _, _) => unread.clone(),
                (None, GemBuildUnshown::Unpinned, Some(Err(error))) => {
                    GemBuildUnshown::IndexUnread(error.clone())
                }
                (None, why, _) => why,
            });
        }
        let mut unshown: BTreeMap<&GemBuildUnshown, Vec<&str>> = BTreeMap::new();
        for build in &hosted.builds {
            if let (Some(why), Some(platform)) = (&build.unshown, build.platform.as_deref()) {
                unshown.entry(why).or_default().push(platform);
            }
        }
        for (why, platforms) in unshown {
            plan.notes
                .push(gem_build_note(&gem.key, &gem.uuid, &platforms, why));
        }
        plan.hosted_gems.insert(gem.key.clone(), hosted);
    }
}

/// The two reads [`resolve_hosted_gems`] makes for `gems`: per gem, the
/// builds its patch's reference lists (ONE request for all of them, with
/// `get`'s one-shot 401/403 → public-proxy fallback), and the index of the
/// registry its lock names, read only for a gem that has a list and whose
/// lock does not pin every build ([`PendingGem::needs_index`]).
async fn read_gem_builds(
    common: &GlobalArgs,
    api_client: &RunApiClient,
    gems: &[PendingGem],
    notes: &mut Vec<PlanNote>,
) -> (
    Vec<Result<Vec<GemPlatformChecksum>, GemBuildUnshown>>,
    Vec<Option<Result<String, String>>>,
) {
    use socket_patch_core::utils::redact::redact_urls_in;
    let mut uuids: Vec<String> = gems.iter().map(|gem| gem.uuid.clone()).collect();
    uuids.sort();
    uuids.dedup();
    let mut client = run_client(common, api_client, notes).await;
    let mut references = hold_back_debug(client.fetch_registry_references(&uuids))
        .await
        .release();
    if let Err(error) = &references {
        if !client.uses_public_proxy() && is_fallback_candidate(error) {
            // Same stale-credential recovery (and warning text) as the
            // record fetch.
            notes.push(PlanNote {
                code: NOTE_API_AUTH_FALLBACK,
                detail: format!(
                    "authenticated API returned {error}; falling back to public patch API proxy \
                     (free patches only)."
                ),
            });
            client = build_proxy_fallback_client(&common.api_client_overrides());
            references = hold_back_debug(client.fetch_registry_references(&uuids))
                .await
                .release();
        }
    }
    let lists: Vec<Result<Vec<GemPlatformChecksum>, GemBuildUnshown>> = gems
        .iter()
        .map(|gem| match &references {
            Err(error) => Err(GemBuildUnshown::Request(
                redact_urls_in(&error.to_string()).into_owned(),
            )),
            Ok(references) => {
                let reference = references.get(&gem.uuid);
                let granted = reference
                    .filter(|reference| matches!(reference.status.as_str(), "granted" | "reused"));
                granted
                    .and_then(|reference| reference.registry_override.as_ref())
                    .and_then(|registry| registry.identifiers.gem_builds.clone())
                    .ok_or_else(|| {
                        GemBuildUnshown::NoList(
                            match reference.map(|reference| reference.status.as_str()) {
                                Some("granted" | "reused") => {
                                    "the patch API lists no builds for that patch"
                                }
                                Some("withdrawn") => "the patch API says that patch is withdrawn",
                                Some("forbidden") => {
                                    "the patch API does not grant that patch to this run"
                                }
                                _ => "the patch API has no reference for that patch",
                            }
                            .to_string(),
                        )
                    })
            }
        })
        .collect();
    let client = &client;
    let indexes = ordered_concurrent(
        gems.iter().zip(&lists),
        fetch_concurrency(client.uses_public_proxy()),
        |(gem, list)| async move {
            match list.is_ok() && gem.needs_index() {
                true => Some(hold_back_debug(gem_index(client, &gem.remote, &gem.name)).await),
                false => None,
            }
        },
    )
    .collect::<Vec<_>>()
    .await;
    let indexes = indexes
        .into_iter()
        .map(|read| read.map(|held| held.release()))
        .collect();
    (lists, indexes)
}

/// The compact-index document of the registry a lock names for the gem
/// `name` ([`gem_index_url`]): the sha256 of each gem that registry
/// serves, for a lock whose `CHECKSUMS` does not say what it installs.
///
/// `remote` is the `remote:` of a lock section that lockfile discovery
/// read as hosted wiring, so it is on a patch server this run was given.
/// The document can only keep a build from being attested: a build is a
/// patched one only on the sha256 the patch service lists beside its
/// patch. The error is safe to print (the URL carries a grant token).
async fn gem_index(client: &ApiClient, remote: &str, name: &str) -> Result<String, String> {
    let url = gem_index_url(remote, name)
        .ok_or_else(|| "the lockfile names no registry URL to read it from".to_string())?;
    let bytes = PatchApi::download_artifact(client, &url, MAX_GEM_INDEX_BYTES)
        .await
        .map_err(|error| {
            socket_patch_core::utils::redact::redact_urls_in(&error.to_string()).into_owned()
        })?;
    String::from_utf8(bytes).map_err(|_| "it is not UTF-8 text".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, VulnerabilityInfo};
    use socket_patch_core::vendor::lock_inventory::LockIntegrity;
    use std::path::Path;

    const U1: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const U2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    fn record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files: [(
                "package/index.js".to_string(),
                PatchFileInfo {
                    before_hash: String::new(),
                    after_hash: "a".repeat(64),
                },
            )]
            .into_iter()
            .collect(),
            vulnerabilities: [(
                "GHSA-x".to_string(),
                VulnerabilityInfo {
                    cves: vec![],
                    summary: String::new(),
                    severity: String::new(),
                    description: String::new(),
                },
            )]
            .into_iter()
            .collect(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// A plan attesting the vendored gem `key` at [`U1`], its ledger entry
    /// shaped by `shape`.
    fn vendored_gem_plan(key: &str, shape: impl FnOnce(&mut VendorEntry)) -> Plan {
        let mut entry = VendorEntry::new(
            "gem".to_string(),
            "pkg:gem/nokogiri@1.18.10".to_string(),
            U1.to_string(),
            socket_patch_core::vendor::state::VendorArtifact {
                yarn_berry10c0: None,
                path: format!(".socket/vendor/gem/{U1}/nokogiri-1.18.10"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            Vec::new(),
        );
        shape(&mut entry);
        Plan {
            view: PatchManifest {
                patches: HashMap::from([
                    (key.to_string(), record(U1)),
                    ("pkg:npm/left-pad@1.3.0".to_string(), record(U2)),
                ]),
                setup: None,
            },
            vendor_entries: HashMap::from([(key.to_string(), entry)]),
            vendor_pins: HashMap::new(),
            redirected: Vec::new(),
            lockfile_basis: HashSet::new(),
            hosted: BTreeMap::new(),
            hosted_gems: BTreeMap::new(),
            gated: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn gem_build(platform: &str, uuid: &str) -> socket_patch_core::vendor::GemBuildEntry {
        socket_patch_core::vendor::GemBuildEntry {
            platform: platform.to_string(),
            uuid: uuid.to_string(),
            gem_integrity: String::new(),
            gemspec_integrity: String::new(),
        }
    }

    /// A gem vendored as platform gems is named per platform gem: each
    /// under the patch the ledger records for its tree, with the gem
    /// patch's vulnerabilities and files, and the gem's own key gone from
    /// the view. Every list of attested purls follows; other packages are
    /// as they were.
    #[test]
    fn a_vendored_gem_is_attested_per_platform_gem_under_its_own_patch() {
        const DARWIN: &str = "11111111-1111-4111-8111-111111111111";
        const LINUX: &str = "22222222-2222-4222-8222-222222222222";
        let key = "pkg:gem/nokogiri@1.18.10?platform=ruby";
        let plan = vendored_gem_plan(key, |entry| {
            entry.gem_builds = vec![
                gem_build("arm64-darwin", DARWIN),
                gem_build("x86_64-linux-gnu", LINUX),
            ];
        });
        let builds = GemBuildView::of(&plan).expect("a gem vendored as platform gems");
        let view = builds.view();
        let darwin = "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin";
        let linux = "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu";
        let mut keys: Vec<&str> = view.patches.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, [darwin, linux, "pkg:npm/left-pad@1.3.0"]);
        for (purl, uuid) in [(darwin, DARWIN), (linux, LINUX)] {
            let attested = &view.patches[purl];
            assert_eq!(attested.uuid, uuid);
            assert_eq!(attested.vulnerabilities, record(U1).vulnerabilities);
            assert_eq!(attested.files, record(U1).files);
        }
        assert_eq!(view.patches["pkg:npm/left-pad@1.3.0"], record(U2));

        let mut applied = vec!["pkg:npm/left-pad@1.3.0".to_string(), key.to_string()];
        builds.expand(&mut applied);
        assert_eq!(applied, ["pkg:npm/left-pad@1.3.0", darwin, linux]);
        let mut noted = vec![(key.to_string(), "why".to_string())];
        builds.expand_noted(&mut noted);
        assert_eq!(
            noted,
            [
                (darwin.to_string(), "why".to_string()),
                (linux.to_string(), "why".to_string())
            ]
        );
    }

    /// The gem itself stays the attested package where the ledger does not
    /// say which patch built which tree: an entry that names platforms
    /// only, one whose trees are another patch's than the view's record,
    /// and one that names a platform no gem platform token spells.
    #[test]
    fn a_vendored_gem_with_no_patch_named_for_its_trees_is_attested_as_the_gem() {
        let key = "pkg:gem/nokogiri@1.18.10?platform=ruby";
        let platforms_only = vendored_gem_plan(key, |entry| {
            entry.gem_platforms = vec!["arm64-darwin".to_string()];
        });
        assert!(GemBuildView::of(&platforms_only).is_none());
        let another_patch = vendored_gem_plan(key, |entry| {
            entry.uuid = U2.to_string();
            entry.gem_builds = vec![gem_build("arm64-darwin", U2)];
        });
        assert!(GemBuildView::of(&another_patch).is_none());
        let unsafe_platform = vendored_gem_plan(key, |entry| {
            entry.gem_builds = vec![gem_build("../x", U2)];
        });
        assert!(GemBuildView::of(&unsafe_platform).is_none());
    }

    fn hosted_ref(purl: &str, uuid: &str, pinned: bool) -> PatchedRef {
        PatchedRef::hosted(
            purl.to_string(),
            uuid.to_string(),
            "package-lock.json",
            None,
            pinned.then(|| LockIntegrity::Sri("sha512-x".into())),
            true,
        )
    }

    fn common(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..GlobalArgs::default()
        }
    }

    /// `SOCKET_API_CONCURRENCY=1` means one view at a time here as well.
    /// Serial: `SOCKET_*` is process-global.
    #[test]
    #[serial_test::serial]
    fn socket_api_concurrency_paces_the_record_fetch() {
        use socket_patch_core::utils::concurrent::API_CONCURRENCY_ENV;
        let orig = std::env::var(API_CONCURRENCY_ENV).ok();
        std::env::remove_var(API_CONCURRENCY_ENV);
        // The authenticated API serves the view without its file contents,
        // so the patch API's own window applies there.
        assert_eq!(fetch_concurrency(false), api_concurrency(false));
        assert!(fetch_concurrency(false) > FETCH_CONCURRENCY);
        assert_eq!(fetch_concurrency(true), 4);

        std::env::set_var(API_CONCURRENCY_ENV, "1");
        assert_eq!(fetch_concurrency(false), 1);
        assert_eq!(fetch_concurrency(true), 1);

        // The proxy's view is heavy: its window never passes this one's
        // own ceiling, however far the setting is turned up.
        std::env::set_var(API_CONCURRENCY_ENV, "32");
        assert_eq!(
            fetch_concurrency(true),
            api_concurrency(true).min(FETCH_CONCURRENCY)
        );
        assert_eq!(fetch_concurrency(false), 32);

        match orig {
            Some(v) => std::env::set_var(API_CONCURRENCY_ENV, v),
            None => std::env::remove_var(API_CONCURRENCY_ENV),
        }
    }

    /// The record fetch folds in `pending` order, not in the order the
    /// server happens to answer: the FIRST refusal in `pending` is the one
    /// reported in the fallback note, even when it answers last, and the
    /// refused uuids are retried against the proxy in that same order.
    #[tokio::test]
    #[serial_test::serial]
    async fn refused_records_fold_in_pending_order_not_completion_order() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let api = MockServer::start().await;
        let proxy = MockServer::start().await;
        // U1 is first in `pending` and answers LAST; the two refusals are
        // different statuses, so the reported one is identifiable.
        for (uuid, status, delay) in [(U1, 401, 300u64), (U2, 403, 0)] {
            Mock::given(method("GET"))
                .and(wm_path(format!("/v0/orgs/acme/patches/view/{uuid}")))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_delay(std::time::Duration::from_millis(delay)),
                )
                .mount(&api)
                .await;
            // The proxy retry serves both, so the run still ends with both
            // records: only the ORDER of the refusal report is at stake.
            Mock::given(method("GET"))
                .and(wm_path(format!("/patch/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid,
                    "purl": "pkg:npm/vexorder@1.0.0",
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "",
                    "license": "MIT",
                    "tier": "free",
                })))
                .mount(&proxy)
                .await;
        }

        let tmp = tempfile::tempdir().unwrap();
        let common = GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            json: true,
            api_url: Some(api.uri()),
            api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
            org: Some("acme".into()),
            proxy_url: Some(proxy.uri()),
            ..GlobalArgs::default()
        };
        let mut notes: Vec<PlanNote> = Vec::new();
        let out = fetch_records(
            &common,
            &RunApiClient::new(),
            &[U1.to_string(), U2.to_string()],
            &mut notes,
        )
        .await;

        let fallback = notes
            .iter()
            .find(|n| n.code == NOTE_API_AUTH_FALLBACK)
            .unwrap_or_else(|| panic!("no fallback note: {notes:?}"));
        assert!(
            fallback.detail.contains("Unauthorized") && !fallback.detail.contains("Forbidden"),
            "the first refusal in `pending` order must be the reported one: {}",
            fallback.detail
        );
        assert!(out.contains_key(U1) && out.contains_key(U2), "{out:?}");
    }

    /// Standalone `vex --json` (no host client): a token whose org cannot
    /// be resolved builds a proxy client here, the records come from the
    /// proxy, and the envelope gets one `api_auth_fallback` note. A client
    /// seeded by a host adds no note (the host reports it).
    #[tokio::test]
    #[serial_test::serial]
    async fn unresolved_org_client_built_here_notes_the_fallback_once() {
        use wiremock::matchers::{method, path as wm_path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let keys = ["SOCKET_ORG_SLUG", "SOCKET_OFFLINE", "SOCKET_NO_CONFIG"];
        let saved: Vec<(&str, Option<String>)> = keys
            .into_iter()
            .map(|k| (k, std::env::var(k).ok()))
            .collect();
        std::env::remove_var("SOCKET_ORG_SLUG");
        std::env::remove_var("SOCKET_OFFLINE");
        std::env::set_var("SOCKET_NO_CONFIG", "1");

        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/v0/organizations"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(path_regex("^/v0/orgs/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/patch/view/{U1}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": U1,
                "purl": "pkg:npm/vexorg@1.0.0",
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": {},
                "vulnerabilities": {},
                "description": "",
                "license": "MIT",
                "tier": "free",
            })))
            .mount(&mock)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let common = GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            json: true,
            silent: true,
            api_url: Some(mock.uri()),
            api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
            proxy_url: Some(mock.uri()),
            ..GlobalArgs::default()
        };
        let run_client = RunApiClient::new();
        let mut notes: Vec<PlanNote> = Vec::new();
        let out = fetch_records(&common, &run_client, &[U1.to_string()], &mut notes).await;
        // A second fetch on the same run reuses the client: no second
        // resolution (the mock's `.expect(1)`) and no second note.
        let _ = fetch_records(&common, &run_client, &[U1.to_string()], &mut notes).await;

        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }

        assert!(out.contains_key(U1), "{out:?}");
        let fallbacks: Vec<_> = notes
            .iter()
            .filter(|n| n.code == NOTE_API_AUTH_FALLBACK)
            .collect();
        assert_eq!(fallbacks.len(), 1, "{notes:?}");
        assert!(
            fallbacks[0]
                .detail
                .contains("Pass --org or set SOCKET_ORG_SLUG"),
            "{}",
            fallbacks[0].detail
        );
    }

    fn discovery(refs: Vec<PatchedRef>) -> Discovery {
        let mut d = Discovery::default();
        for r in refs {
            d.push(r);
        }
        d
    }

    #[test]
    fn a_synthesized_vendored_entry_carries_the_source_locks_flavor() {
        let vendor = VendorState::new();
        for (source, artifact, flavor) in [
            (
                "vlt-lock.json",
                format!(".socket/vendor/npm/{U1}/x-1.0.0/node_modules/x"),
                Some("vlt"),
            ),
            (
                "bun.lock",
                format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz"),
                Some("bun"),
            ),
            (
                "package-lock.json",
                format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz"),
                None,
            ),
        ] {
            let vref = vendor_ref(&artifact).unwrap();
            let r = PatchedRef::vendored("pkg:npm/x@1.0.0".into(), &vref, source, None);
            let entry = vendored_entry_for(&Cand::from_ref(&r, &vendor), &r);
            assert_eq!(entry.flavor.as_deref(), flavor, "{source}");
            assert_eq!(entry.artifact.path, artifact, "{source}");
            assert!(entry.detached && entry.artifact.file_inventory.is_none());
        }
    }

    /// The lockfile wires U2; the manifest records U1 and the redirect
    /// ledger U2 under the same key: the WIRED uuid's record wins.
    #[tokio::test]
    async fn wired_uuid_selects_the_alternative_record() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U2));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U2, true)]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        assert_eq!(plan.view.patches["pkg:npm/x@1.0.0"].uuid, U2);
        assert_eq!(plan.redirected, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(plan.lockfile_basis.contains("pkg:npm/x@1.0.0"));
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
    }

    /// Two locks wire one package to the same patch, and one of them lost
    /// the pin its rewriter always writes (an entry no Socket rewrite
    /// produced). Which lock the build installs from is not decidable from
    /// the files — the cross-lock contest's own argument — so the pinned
    /// lock does not vouch for the other: the purl stays hosted, without
    /// the lockfile basis. A ref whose format never pins withholds nothing.
    #[tokio::test]
    async fn every_hosted_ref_of_a_patch_must_allow_the_lockfile_basis() {
        let tmp = tempfile::tempdir().unwrap();
        let key = "pkg:npm/x@1.0.0";
        let in_file = |mut r: PatchedRef, file: &str| {
            r.source_file = file.into();
            r
        };
        let pinned = || hosted_ref(key, U1, true);
        let pinless = || in_file(hosted_ref(key, U1, false), "pnpm-lock.yaml");
        let never_pins = || {
            PatchedRef::hosted(
                key.to_string(),
                U1.to_string(),
                "yarn.lock",
                None,
                None,
                false,
            )
        };
        for (what, refs, basis) in [
            ("one pinned lock", vec![pinned()], true),
            (
                "a pinned and a pin-less lock",
                vec![pinned(), pinless()],
                false,
            ),
            ("one pin-less lock", vec![pinless()], false),
            (
                "a pinned lock and a format without pins",
                vec![pinned(), never_pins()],
                true,
            ),
        ] {
            let mut redirect = RedirectState::new();
            redirect.records.insert(key.into(), record(U1));
            let sources = Sources {
                manifest: PatchManifest::new(),
                vendor: VendorState::new(),
                redirect: Some(redirect),
                discovery: discovery(refs),
                hosted_uuids: Vec::new(),
                hosted_gem_builds: Vec::new(),
            };
            let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
            assert_eq!(plan.redirected, vec![key.to_string()], "{what}");
            assert_eq!(plan.lockfile_basis.contains(key), basis, "{what}");
            assert!(plan.gated.is_empty(), "{what}: {:?}", plan.gated);
        }
    }

    /// Superseded: the manifest's U1 record for a package the lockfile wires
    /// to U2 is dropped; U2 with no local record is `record_unavailable`
    /// offline.
    #[tokio::test]
    async fn superseded_manifest_record_and_offline_lockfile_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: None,
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U2, true)]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        assert!(
            plan.view.patches.is_empty(),
            "{:?}",
            plan.view.patches.keys()
        );
        assert_eq!(
            plan.gated,
            vec![failed("pkg:npm/x@1.0.0", RECORD_UNAVAILABLE)]
        );
        assert!(plan
            .notes
            .iter()
            .any(|n| n.code == NOTE_RECORD_SUPERSEDED && n.detail.contains("superseded")));
        assert!(plan
            .notes
            .iter()
            .any(|n| n.code == NOTE_RECORD_OFFLINE && n.detail.contains("--offline")));
    }

    /// A lockfile ref whose only local record (by uuid) is filed under a
    /// different package: `record_mismatch`, never attested.
    #[tokio::test]
    async fn record_for_another_package_is_a_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/other@2.0.0".into(), record(U1));
        let sources = Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U1, true)]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        assert!(plan
            .gated
            .contains(&failed("pkg:npm/x@1.0.0", RECORD_MISMATCH)));
        // And the ledger record for `other` is NOT live: discovery sees U1
        // wired — to a different package.
        assert!(plan
            .gated
            .contains(&failed("pkg:npm/other@2.0.0", REDIRECT_UNWIRED)));
        assert!(plan.view.patches.is_empty());
    }

    /// Two lockfiles wiring one package to different patches: every
    /// candidate for it is gated `wiring_conflict` exactly once, none
    /// reaches the view (no statement next to a skip), and other packages
    /// are unaffected.
    #[tokio::test]
    async fn conflicting_wiring_gates_every_candidate_once() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        manifest
            .patches
            .insert("pkg:npm/y@1.0.0".into(), record(U2));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U2));
        let mut shrinkwrap = hosted_ref("pkg:npm/x@1.0.0", U2, true);
        shrinkwrap.source_file = "npm-shrinkwrap.json".into();
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![
                hosted_ref("pkg:npm/x@1.0.0", U1, true),
                shrinkwrap,
                hosted_ref("pkg:npm/y@1.0.0", U2, true),
            ]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        assert_eq!(plan.gated, vec![failed("pkg:npm/x@1.0.0", WIRING_CONFLICT)]);
        assert!(!plan.view.patches.contains_key("pkg:npm/x@1.0.0"));
        assert!(!plan.redirected.contains(&"pkg:npm/x@1.0.0".to_string()));
        assert_eq!(plan.view.patches["pkg:npm/y@1.0.0"].uuid, U2);
        assert!(plan.notes.iter().any(|n| n.code == NOTE_WIRING_CONFLICT
            && n.detail.contains("npm-shrinkwrap.json")
            && n.detail.contains("package-lock.json")));
    }

    /// Hosted takeover of a vendored package (vendor entry U1 unwired,
    /// redirect record U2 for the same key): the candidate switches to the
    /// hosted claim instead of being gated `vendor_unwired` — but only while
    /// the hosted claim is live (here: the in-run confirmed set).
    #[tokio::test]
    async fn dead_vendor_claim_falls_through_to_a_live_hosted_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let key = "pkg:npm/x@1.0.0";
        let mut vendor = VendorState::new();
        vendor.entries.insert(
            key.into(),
            VendorEntry {
                detached: true,
                record: Some(record(U1)),
                ..VendorEntry::new(
                    "npm".into(),
                    key.into(),
                    U1.into(),
                    VendorArtifact {
                        yarn_berry10c0: None,
                        path: format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz"),
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    Vec::new(),
                )
            },
        );
        let mut redirect = RedirectState::new();
        redirect.records.insert(key.into(), record(U2));
        let mk = || Sources {
            manifest: PatchManifest::new(),
            vendor: vendor.clone(),
            redirect: Some(redirect.clone()),
            discovery: Discovery::default(),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let live = plan(
            &common(tmp.path()),
            mk(),
            &[key.to_string()],
            &RunApiClient::new(),
        )
        .await;
        assert_eq!(live.view.patches[key].uuid, U2);
        assert_eq!(live.redirected, vec![key.to_string()]);
        assert!(live.vendor_entries.is_empty());
        assert!(live.gated.is_empty(), "{:?}", live.gated);

        let dead = plan(&common(tmp.path()), mk(), &[], &RunApiClient::new()).await;
        assert!(dead.view.patches.is_empty());
        assert_eq!(dead.gated, vec![failed(key, VENDOR_UNWIRED)]);

        // The takeover attests the redirect ledger's uuid, swapped in after
        // the early mark gate ran: a mark on it still gates.
        let mut marked = mk();
        marked
            .discovery
            .unattested
            .push(socket_patch_core::vex::Unattested {
                purl: key.into(),
                uuid: U2.into(),
                file: "package-lock.json".into(),
                detail: "package-lock.json bypasses it".into(),
                kind: UnattestedKind::LockAboveBase,
            });
        let gated = plan(
            &common(tmp.path()),
            marked,
            &[key.to_string()],
            &RunApiClient::new(),
        )
        .await;
        assert!(gated.view.patches.is_empty(), "{:?}", gated.view.patches);
        assert_eq!(gated.gated, vec![failed(key, NOTE_LOCK_ABOVE_BASE)]);
    }

    /// Core discover rule 11 through the plan: a vendor ledger entry and a
    /// redirect ledger record whose patches the lockfiles MENTION only in
    /// shapes the extractors rejected are dead — `vendor_unwired` /
    /// `redirect_unwired`, with a note naming the file and the extractor's
    /// reason — although the files hold each uuid in pin position: the
    /// hosted ledger's raw-text fallback would call its record live (the
    /// unrecognized control run proves it), and the vendor ledger has no
    /// raw-text fallback at all.
    #[tokio::test]
    async fn recognized_but_rejected_uuids_are_dead_whatever_the_raw_text_says() {
        use socket_patch_core::vendor::state::{WiringAction, WiringRecord};
        use socket_patch_core::vex::{Diag, Recognized};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz");
        std::fs::write(
            root.join("yarn.lock"),
            format!("resolved \"file:./{rel}#abc\"\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            format!(
                "source = \"sparse+https://patch.socket.dev/patch-registry/cargo/tok/{U2}/index/\"\n"
            ),
        )
        .unwrap();
        let mut vendor = VendorState::new();
        vendor.entries.insert(
            "pkg:npm/x@1.0.0".into(),
            VendorEntry {
                detached: true,
                record: Some(record(U1)),
                ..VendorEntry::new(
                    "npm".into(),
                    "pkg:npm/x@1.0.0".into(),
                    U1.into(),
                    VendorArtifact {
                        yarn_berry10c0: None,
                        path: rel.clone(),
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    vec![WiringRecord {
                        file: "yarn.lock".into(),
                        kind: "yarn_lock_entry".into(),
                        action: WiringAction::Rewritten,
                        key: None,
                        original: None,
                        new: None,
                    }],
                )
            },
        );
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:cargo/y@1.0.0".into(), record(U2));
        redirect
            .edits
            .push(socket_patch_core::patch::redirect::FileEdit {
                path: "Cargo.lock".into(),
                kind: "redirect_cargo".into(),
                action: "rewritten".into(),
                key: None,
                original: None,
                new: None,
            });
        let sources = |discovery: Discovery| Sources {
            manifest: PatchManifest::new(),
            vendor: vendor.clone(),
            redirect: Some(redirect.clone()),
            discovery,
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };

        // Control — nothing recognized: the hosted ledger's own recorded
        // files decide, and its claim is live. The vendor claim is dead
        // without a discovered reference, whatever its recorded file says.
        let live = plan(
            &common(root),
            sources(Discovery::default()),
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert_eq!(live.gated, vec![failed("pkg:npm/x@1.0.0", VENDOR_UNWIRED)]);
        assert!(!live.view.patches.contains_key("pkg:npm/x@1.0.0"));
        assert_eq!(live.redirected, vec!["pkg:cargo/y@1.0.0".to_string()]);

        // The extractors rejected both mentions: dead, with the reason.
        let rejected = Discovery {
            recognized: vec![
                Recognized {
                    uuid: U2.into(),
                    mode: WiringMode::Hosted,
                    file: "Cargo.lock".into(),
                },
                Recognized {
                    uuid: U1.into(),
                    mode: WiringMode::Vendored,
                    file: "yarn.lock".into(),
                },
            ],
            diagnostics: vec![Diag {
                code: "patched_ref_invalid",
                file: "yarn.lock".into(),
                detail: format!(
                    "yarn.lock: vendored entry `x` is orphaned: nothing maps x onto {rel}"
                ),
            }],
            ..Discovery::default()
        };
        let dead = plan(&common(root), sources(rejected), &[], &RunApiClient::new()).await;
        assert!(
            dead.view.patches.is_empty(),
            "{:?}",
            dead.view.patches.keys()
        );
        assert!(dead.redirected.is_empty() && dead.hosted.is_empty());
        let mut gated = dead.gated.clone();
        gated.sort_by(|a, b| a.purl.cmp(&b.purl));
        assert_eq!(
            gated,
            vec![
                failed("pkg:cargo/y@1.0.0", REDIRECT_UNWIRED),
                failed("pkg:npm/x@1.0.0", VENDOR_UNWIRED),
            ]
        );
        assert!(
            dead.notes.iter().any(|n| n.code == NOTE_CLAIM_UNWIRED
                && n.detail.contains("yarn.lock")
                && n.detail.contains("orphaned")
                && n.detail.contains(U1)),
            "{:?}",
            dead.notes
        );
        assert!(
            dead.notes.iter().any(|n| n.detail.contains("Cargo.lock")
                && n.detail.contains("hosted ledger")
                && n.detail.contains(U2)),
            "{:?}",
            dead.notes
        );
    }

    /// Every hosted-basis view purl carries its wiring (uuid + the refs of
    /// THAT uuid) for the consumed-copy verification; other bases do not.
    #[tokio::test]
    async fn hosted_basis_purls_carry_their_wiring() {
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let sources = Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U1, true)]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        let wiring = &plan.hosted["pkg:npm/x@1.0.0"];
        assert_eq!(wiring.uuid, U1);
        assert_eq!(wiring.refs.len(), 1);
        assert_eq!(wiring.refs[0].uuid, U1);
        assert_eq!(plan.hosted.len(), plan.redirected.len());
    }

    /// #646 review: a hosted ref discovery marks unattested (a Gradle lock
    /// above the pin's base) is omitted with `vex_gradle_lock_above_base`,
    /// while the same ref without the mark attests through its wiring.
    #[tokio::test]
    async fn an_unattested_hosted_ref_is_gated() {
        const PURL: &str = "pkg:maven/com.socketfixture/victim@1.10.0";
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect.records.insert(PURL.into(), record(U1));
        let mut found = discovery(vec![hosted_ref(PURL, U1, true)]);
        found.unattested.push(socket_patch_core::vex::Unattested {
            purl: PURL.into(),
            uuid: U1.into(),
            file: "b/gradle.lockfile".into(),
            detail: "b/gradle.lockfile:1 locks it above the patched 1.10.0".into(),
            kind: UnattestedKind::LockAboveBase,
        });
        let sources = |discovery: Discovery| Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect.clone()),
            discovery,
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let gated = plan(
            &common(tmp.path()),
            sources(found),
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(gated.view.patches.is_empty() && gated.hosted.is_empty());
        assert_eq!(gated.gated, vec![failed(PURL, NOTE_LOCK_ABOVE_BASE)]);
        assert!(
            gated.notes.iter().any(|n| n.code == NOTE_LOCK_ABOVE_BASE
                && n.detail.contains("b/gradle.lockfile:1")),
            "{:?}",
            gated.notes
        );
        let live = plan(
            &common(tmp.path()),
            sources(discovery(vec![hosted_ref(PURL, U1, true)])),
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(live.gated.is_empty(), "{:?}", live.gated);
        assert!(live.hosted.contains_key(PURL));
    }

    /// Each npm-family bypass (#556 branch locks, #711 / #367 user patches)
    /// is omitted under its own tag, distinct from every other kind's.
    #[test]
    fn npm_family_unattested_kinds_have_their_own_tags() {
        let kinds = [
            UnattestedKind::LockAboveBase,
            UnattestedKind::BundledCopy,
            UnattestedKind::DenoLock,
            UnattestedKind::NpmShrinkwrapOnly,
            UnattestedKind::MavenReactorRoot,
            UnattestedKind::MavenClassifierUnpatched,
            UnattestedKind::PnpmGitBranchLock,
            UnattestedKind::UserPatchedDependency,
            UnattestedKind::LockNotRead,
        ];
        let tags: std::collections::BTreeSet<&str> =
            kinds.iter().map(|k| unattested_note(*k).0).collect();
        assert_eq!(tags.len(), kinds.len(), "{tags:?}");
        assert_eq!(
            unattested_note(UnattestedKind::LockNotRead).0,
            "vex_lock_not_read"
        );
        assert_eq!(
            unattested_note(UnattestedKind::PnpmGitBranchLock).0,
            "vex_pnpm_git_branch_lockfile"
        );
        assert_eq!(
            unattested_note(UnattestedKind::UserPatchedDependency).0,
            "vex_npm_patched_dependency"
        );
        // Review (#2010): a pre-#711 pin breaks `npm ci` (EPATCHFAILED)
        // until it is rolled back, as hosted's warning says.
        let remedy = unattested_note(UnattestedKind::UserPatchedDependency).1;
        assert!(remedy.contains("socket-patch rollback"), "{remedy}");
    }

    /// A hosted Go ref of `uuid` in `file`, and the Go workspace mark on it.
    fn go_ref(purl: &str, uuid: &str, file: &str) -> PatchedRef {
        PatchedRef::hosted(
            purl.to_string(),
            uuid.to_string(),
            file,
            None,
            Some(LockIntegrity::GoH1("h1:x".into())),
            true,
        )
    }

    fn go_bypass(purl: &str, uuid: &str, file: &str) -> socket_patch_core::vex::Unattested {
        socket_patch_core::vex::Unattested {
            purl: purl.into(),
            uuid: uuid.into(),
            file: file.into(),
            detail: format!("go builds the workspace of ../ci/go.work, never this {file}"),
            kind: UnattestedKind::GoWorkspaceOverride,
        }
    }

    /// Review finding 1: a Go workspace mark bypasses only its own file. A
    /// root go.work replace go never reads does not withhold the patch the
    /// root go.mod's mirror of it wires, which attests on its own basis;
    /// alone, the bypassed ref is omitted with `go_workspace_override`.
    #[tokio::test]
    async fn a_go_workspace_mark_withholds_only_its_own_file() {
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect.records.insert(PURL.into(), record(U1));
        let sources = |discovery: Discovery| Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect.clone()),
            discovery,
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let mut both = discovery(vec![
            go_ref(PURL, U1, "go.work"),
            go_ref(PURL, U1, "go.mod"),
        ]);
        both.unattested.push(go_bypass(PURL, U1, "go.work"));
        let live = plan(
            &common(tmp.path()),
            sources(both),
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(live.gated.is_empty(), "{:?}", live.gated);
        let wiring = &live.hosted[PURL];
        assert_eq!(wiring.refs.len(), 1, "{:?}", wiring.refs);
        assert_eq!(wiring.refs[0].source_file, Path::new("go.mod"));

        let mut alone = discovery(vec![go_ref(PURL, U1, "go.work")]);
        alone.unattested.push(go_bypass(PURL, U1, "go.work"));
        let gated = plan(
            &common(tmp.path()),
            sources(alone),
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(gated.view.patches.is_empty() && gated.hosted.is_empty());
        assert_eq!(gated.gated, vec![failed(PURL, GO_WORKSPACE_OVERRIDE)]);
    }

    /// Review finding 4: Socket's own go.work replace overriding a leftover
    /// member pin of another patch is what the build links (as `vex`'s
    /// go.mod gate holds): the overridden pin is withheld, never a wiring
    /// conflict that also withholds the go.work patch.
    #[tokio::test]
    async fn a_bypassed_leftover_pin_is_no_wiring_conflict() {
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect.records.insert(PURL.into(), record(U1));
        let mut found = discovery(vec![
            go_ref(PURL, U1, "go.work"),
            go_ref(PURL, U2, "app/go.mod"),
        ]);
        found.unattested.push(go_bypass(PURL, U2, "app/go.mod"));
        let sources = Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: found,
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(&common(tmp.path()), sources, &[], &RunApiClient::new()).await;
        assert_eq!(plan.hosted[PURL].uuid, U1);
        // Review on #2011 (round 2): the attested purl is never also
        // reported skipped for its stale, bypassed leftover pin.
        assert!(
            !plan.gated.iter().any(|f| PurlKey::same(&f.purl, PURL)),
            "{:?}",
            plan.gated
        );
    }

    /// A hosted Cargo pin beside an unpinned declaration of the crate is
    /// omitted as `vex_cargo_unpinned_declaration`, the note naming the
    /// declaration and the remedy.
    #[tokio::test]
    async fn a_cargo_pin_beside_an_unpinned_declaration_is_gated() {
        const PURL: &str = "pkg:cargo/serde@1.0.1";
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect.records.insert(PURL.into(), record(U1));
        let mut found = discovery(vec![hosted_ref(PURL, U1, true)]);
        found.unattested.push(socket_patch_core::vex::Unattested {
            purl: PURL.into(),
            uuid: U1.into(),
            file: "crates/a/Cargo.toml".into(),
            detail: "crates/a/Cargo.toml declares serde \"1\" from crates.io, not registry \
                     \"socket-patch-…\"; re-run `socket-patch scan` to pin it too"
                .into(),
            kind: UnattestedKind::CargoUnpinnedDeclaration,
        });
        let gated = plan(
            &common(tmp.path()),
            Sources {
                manifest: PatchManifest::new(),
                vendor: VendorState::new(),
                redirect: Some(redirect),
                discovery: found,
                hosted_uuids: Vec::new(),
                hosted_gem_builds: Vec::new(),
            },
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(gated.view.patches.is_empty() && gated.hosted.is_empty());
        assert_eq!(
            gated.gated,
            vec![failed(PURL, NOTE_CARGO_UNPINNED_DECLARATION)]
        );
        assert!(
            gated
                .notes
                .iter()
                .any(|n| n.code == NOTE_CARGO_UNPINNED_DECLARATION
                    && n.detail.contains("crates/a/Cargo.toml declares serde")
                    && n.detail.ends_with(
                        "re-run `socket-patch scan` to pin it too; not attested while that \
                         declaration stands"
                    )),
            "{:?}",
            gated.notes
        );
    }

    /// A vendored Cargo copy beside a copy of the crate its `[patch]`
    /// entry does not redirect is omitted as `vex_cargo_patch_bypassed`,
    /// the note naming that copy and the remedy.
    #[tokio::test]
    async fn a_vendored_cargo_copy_beside_a_bypassing_source_is_gated() {
        const PURL: &str = "pkg:cargo/serde@1.0.1";
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(PURL.into(), record(U1));
        let vref = vendor_ref(&format!(".socket/vendor/cargo/{U1}/serde-1.0.1")).unwrap();
        let mut found = discovery(vec![PatchedRef::vendored(
            PURL.into(),
            &vref,
            "Cargo.toml",
            None,
        )]);
        found.unattested.push(socket_patch_core::vex::Unattested {
            purl: PURL.into(),
            uuid: U1.into(),
            file: "crates/a/Cargo.toml".into(),
            detail: "crates/a/Cargo.toml declares serde \"1\" from registry `my-corp`".into(),
            kind: UnattestedKind::CargoPatchBypassed,
        });
        let gated = plan(
            &common(tmp.path()),
            Sources {
                manifest,
                vendor: VendorState::new(),
                redirect: None,
                discovery: found,
                hosted_uuids: Vec::new(),
                hosted_gem_builds: Vec::new(),
            },
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(gated.view.patches.is_empty() && gated.hosted.is_empty());
        assert_eq!(gated.gated, vec![failed(PURL, NOTE_CARGO_PATCH_BYPASSED)]);
        assert!(
            gated
                .notes
                .iter()
                .any(|n| n.code == NOTE_CARGO_PATCH_BYPASSED
                    && n.detail.contains("from registry `my-corp`")
                    && n.detail.contains("says how to clear it")),
            "{:?}",
            gated.notes
        );
    }

    /// The pin files of a vendored package are the files its vendored
    /// reference was found in. A second file that pins the same patch on
    /// the patch host points at no committed copy, and is none.
    #[tokio::test]
    async fn the_pins_of_a_vendored_package_are_the_files_that_point_at_its_copy() {
        const PURL: &str = "pkg:pypi/idna@3.6";
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(PURL.into(), record(U1));
        let copy = format!(".socket/vendor/pypi/{U1}/idna-3.6-py3-none-any.whl");
        let vref = vendor_ref(&copy).unwrap();
        let hosted = PatchedRef::hosted(
            PURL.to_string(),
            U1.to_string(),
            "requirements-dev.txt",
            None,
            None,
            true,
        );
        let found = discovery(vec![
            hosted,
            PatchedRef::vendored(PURL.into(), &vref, "requirements.txt", None),
        ]);
        let plan = plan(
            &common(tmp.path()),
            Sources {
                manifest,
                vendor: VendorState::new(),
                redirect: None,
                discovery: found,
                hosted_uuids: Vec::new(),
                hosted_gem_builds: Vec::new(),
            },
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
        assert_eq!(plan.vendor_entries[PURL].artifact.path, copy);
        assert_eq!(plan.vendor_pins[PURL], ["requirements.txt"]);
    }

    /// Ledger-only records with no wiring anywhere are gated, except the
    /// manifest-owned one, which falls back to agent-mode verification; an
    /// in-run confirmed purl is live by construction.
    #[tokio::test]
    async fn dead_redirect_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/owned@1.0.0".into(), record(U1));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/owned@1.0.0".into(), record(U1));
        redirect
            .records
            .insert("pkg:npm/stale@1.0.0".into(), record(U2));
        redirect
            .records
            .insert("pkg:pypi/confirmed@1.0?artifact_id=x".into(), record(U2));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: Discovery::default(),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        };
        let plan = plan(
            &common(tmp.path()),
            sources,
            &["pkg:pypi/confirmed@1.0".to_string()],
            &RunApiClient::new(),
        )
        .await;
        assert!(plan.view.patches.contains_key("pkg:npm/owned@1.0.0"));
        assert!(
            !plan.redirected.contains(&"pkg:npm/owned@1.0.0".to_string()),
            "a dead redirect claim loses the (redirected) basis"
        );
        assert_eq!(
            plan.redirected,
            vec!["pkg:pypi/confirmed@1.0?artifact_id=x".to_string()]
        );
        assert_eq!(
            plan.gated,
            vec![failed("pkg:npm/stale@1.0.0", REDIRECT_UNWIRED)]
        );
    }

    /// The bundler < 2.6 hosted rewrite leaves the pair MIXED — the
    /// Gemfile's `source "<patch registry>" do` block pins the patch, the
    /// CHECKSUMS-less lock still resolves the gem from rubygems.org until
    /// the next unfrozen `bundle install` converges it. That keeps the
    /// redirect record live under both spellings (`Gemfile`/`gems.rb`);
    /// reverting the Gemfile too kills it.
    #[tokio::test]
    async fn gemfile_source_block_keeps_a_mixed_gem_pair_live() {
        let purl = "pkg:gem/vexprobe@1.2.3";
        for (gemfile, lock) in [("Gemfile", "Gemfile.lock"), ("gems.rb", "gems.locked")] {
            for gemfile_wired in [true, false] {
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path();
                let source = if gemfile_wired {
                    format!(
                        "source \"https://patch.socket.dev/patch-registry/gem/tok/{U1}/\" do\n  \
                         gem \"vexprobe\", \"1.2.3\"\nend\n"
                    )
                } else {
                    "gem \"vexprobe\", \"1.2.3\"\n".to_string()
                };
                std::fs::write(
                    root.join(gemfile),
                    format!("source \"https://rubygems.org\"\n{source}"),
                )
                .unwrap();
                std::fs::write(
                    root.join(lock),
                    "GEM\n  remote: https://rubygems.org/\n  specs:\n    vexprobe (1.2.3)\n\n\
                     PLATFORMS\n  ruby\n\nDEPENDENCIES\n  vexprobe (= 1.2.3)\n",
                )
                .unwrap();
                let mut redirect = RedirectState::new();
                redirect.records.insert(purl.into(), record(U1));
                for file in [gemfile, lock] {
                    redirect
                        .edits
                        .push(socket_patch_core::patch::redirect::FileEdit {
                            path: file.into(),
                            kind: "redirect_gem".into(),
                            action: "rewritten".into(),
                            key: Some(purl.into()),
                            original: None,
                            new: None,
                        });
                }
                let sources = Sources {
                    manifest: PatchManifest::new(),
                    vendor: VendorState::new(),
                    redirect: Some(redirect),
                    // The lock does not mention the uuid, and the Gemfile is
                    // not a discovery input: the ledger fallback decides.
                    discovery: Discovery::default(),
                    hosted_uuids: Vec::new(),
                    hosted_gem_builds: Vec::new(),
                };
                let plan = plan(&common(root), sources, &[], &RunApiClient::new()).await;
                if gemfile_wired {
                    assert_eq!(plan.redirected, vec![purl.to_string()], "{gemfile}");
                    assert!(plan.gated.is_empty(), "{gemfile}: {:?}", plan.gated);
                } else {
                    assert!(plan.redirected.is_empty(), "{gemfile}");
                    assert_eq!(
                        plan.gated,
                        vec![failed(purl, REDIRECT_UNWIRED)],
                        "{gemfile}"
                    );
                }
            }
        }
    }

    // ── A gem a lock takes from its patch registry as platform builds ──

    const GEM: &str = "pkg:gem/nokogiri@1.18.10";
    const GEM_ARM: &str = "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin";
    const GEM_LINUX: &str = "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu";
    /// The patches of the gem's patched platform builds.
    const ARM_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const LINUX_UUID: &str = "22222222-2222-4222-8222-222222222222";
    /// Upstream's `arm64-darwin` gem, and the patched ones.
    const ARM_UPSTREAM: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    const ARM_PATCHED: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const LINUX_PATCHED: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const RUBY_PATCHED: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

    /// The registry of the gem's patch on `origin`, at the snapshot `key`.
    fn gem_registry(origin: &str, key: &str) -> String {
        format!("{origin}/patch-registry/gem/tok/{U1}/s/{key}/")
    }

    /// A lock that takes the gem's builds `tokens` (`1.18.10`,
    /// `1.18.10-arm64-darwin`, …) from `remote`, pinned as `checksums`
    /// say (no `CHECKSUMS` section without any), and the sources that read
    /// it: the lock's one hosted pin of the gem's patch [`U1`], whose
    /// record a pre-v5 ledger holds, so no record is fetched.
    fn hosted_gem_sources(
        root: &Path,
        remote: &str,
        tokens: &[&str],
        checksums: &[(&str, &str)],
    ) -> Sources {
        let mut lock = format!("GEM\n  remote: {remote}\n  specs:\n");
        for token in tokens {
            lock.push_str(&format!("    nokogiri ({token})\n"));
        }
        lock.push_str("\nDEPENDENCIES\n  nokogiri (= 1.18.10)!\n");
        if !checksums.is_empty() {
            lock.push_str("\nCHECKSUMS\n");
            for (token, sha256) in checksums {
                lock.push_str(&format!("  nokogiri ({token}) sha256={sha256}\n"));
            }
        }
        std::fs::write(root.join("Gemfile.lock"), lock).unwrap();
        let pin = checksums
            .first()
            .map(|(_, sha256)| LockIntegrity::Sha256Hex(sha256.to_string()));
        let wired = PatchedRef::hosted(
            GEM.to_string(),
            U1.to_string(),
            "Gemfile.lock",
            Some(remote),
            pin,
            !checksums.is_empty(),
        );
        let mut redirect = RedirectState::new();
        redirect.records.insert(GEM.into(), record(U1));
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U2));
        Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![wired, hosted_ref("pkg:npm/x@1.0.0", U2, true)]),
            hosted_uuids: Vec::new(),
            hosted_gem_builds: Vec::new(),
        }
    }

    /// The patch API of the gem's patch on `server`: its reference lists
    /// `builds` (platform, sha256, patch) under the snapshot `key`.
    async fn mount_gem_reference(
        server: &wiremock::MockServer,
        key: &str,
        builds: &[(&str, &str, Option<&str>)],
    ) {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, ResponseTemplate};
        let listed: Vec<serde_json::Value> = builds
            .iter()
            .map(|(platform, sha256, patch)| {
                serde_json::json!({
                    "platform": platform, "gemChecksumSha256": sha256, "patchUuid": patch,
                })
            })
            .collect();
        Mock::given(method("POST"))
            .and(wm_path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { U1: {
                    "status": "granted",
                    "purl": GEM,
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": gem_registry(&server.uri(), key),
                        "identifiers": {
                            "name": "nokogiri", "version": "1.18.10",
                            "gemChecksumSha256": RUBY_PATCHED, "gemBuilds": listed,
                        },
                    },
                }}
            })))
            .mount(server)
            .await;
    }

    /// The index of the registry at the snapshot `key` on `server`.
    async fn mount_gem_index(server: &wiremock::MockServer, key: &str, lines: &[(&str, &str)]) {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, ResponseTemplate};
        let mut body = "---\n".to_string();
        for (token, sha256) in lines {
            body.push_str(&format!("{token} racc:~> 1.4|checksum:{sha256}\n"));
        }
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/patch-registry/gem/tok/{U1}/s/{key}/info/nokogiri"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(server)
            .await;
    }

    /// A run against the patch API on `server`, authenticated.
    fn online(root: &Path, server: &wiremock::MockServer) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            api_url: Some(server.uri()),
            api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
            org: Some("acme".into()),
            ..GlobalArgs::default()
        }
    }

    /// The paths of the requests `server` received, in arrival order.
    async fn asked(server: &wiremock::MockServer) -> Vec<String> {
        let requests = server.received_requests().await.unwrap_or_default();
        requests
            .iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    /// What `plan` says of the gem's builds, by purl.
    fn gem_states(plan: &Plan) -> Vec<(&str, &GemBuildState)> {
        let gem = &plan.hosted_gems[GEM];
        assert_eq!((gem.gem_fix.as_str(), gem.resolved), (U1, true));
        gem.builds
            .iter()
            .map(|build| (build.purl.as_str(), &build.state))
            .collect()
    }

    fn patched(uuid: &str) -> GemBuildState {
        GemBuildState::Patched {
            uuid: uuid.to_string(),
        }
    }

    /// What the document made from `plan` says of the gem: the purls it
    /// attests as patched, and each purl it says `affected` of with the
    /// action statement.
    fn gem_statements(plan: &Plan) -> (Vec<String>, Vec<(String, String)>) {
        let builds = GemBuildView::of(plan).expect("a gem locked as platform builds");
        let mut applied = vec![GEM.to_string()];
        builds.expand(&mut applied);
        (applied, builds.not_patched().to_vec())
    }

    /// The action statement of a build for `platform` that is not shown
    /// patched for the reason `why`, with what to run.
    fn unshown_action(platform: &str, why: &str, remedy: &str) -> String {
        format!(
            "It could not be shown that the lockfile installs a patched build of this gem for \
             {platform} ({why}), so it is stated as affected. {remedy}"
        )
    }

    const REFERENCE: &str = "/v0/orgs/acme/patches/package";
    const ONE_PATCHED: [(&str, &str, Option<&str>); 2] = [
        ("arm64-darwin", ARM_UPSTREAM, None),
        ("x86_64-linux-gnu", LINUX_PATCHED, Some(LINUX_UUID)),
    ];
    const LOCKED: [&str; 2] = ["1.18.10-arm64-darwin", "1.18.10-x86_64-linux-gnu"];
    const PINNED: [(&str, &str); 2] = [
        ("1.18.10-arm64-darwin", ARM_UPSTREAM),
        ("1.18.10-x86_64-linux-gnu", LINUX_PATCHED),
    ];

    /// A lock whose `CHECKSUMS` pins every build is settled by ONE
    /// request, the gem patch's reference: the build on the sha256 the
    /// list gives beside a patch is that patch's, the one on the sha256 it
    /// gives beside none is upstream's gem. Nothing is omitted and nothing
    /// is noted, and the registry is not asked.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_checksummed_lock_tells_its_builds_apart_in_one_request() {
        let server = wiremock::MockServer::start().await;
        mount_gem_reference(&server, "4f", &ONE_PATCHED).await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = gem_registry(&server.uri(), "4f");
        let sources = hosted_gem_sources(tmp.path(), &remote, &LOCKED, &PINNED);
        let plan = plan(
            &online(tmp.path(), &server),
            sources,
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert_eq!(
            gem_states(&plan),
            [
                (GEM_ARM, &GemBuildState::Upstream),
                (GEM_LINUX, &patched(LINUX_UUID))
            ]
        );
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
        assert!(plan.notes.is_empty(), "{:?}", plan.notes);
        assert_eq!(asked(&server).await, [REFERENCE]);
        // The gem is still the one pin the checks judge.
        assert_eq!(plan.view.patches[GEM].uuid, U1);
        assert!(plan.redirected.contains(&GEM.to_string()));
    }

    /// A lock with no `CHECKSUMS` installs what its own registry serves:
    /// a second request reads that registry's index, and the builds are
    /// told apart by it. Two requests, and no more.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_lock_without_checksums_asks_its_own_registry_too() {
        let server = wiremock::MockServer::start().await;
        mount_gem_reference(&server, "4f", &ONE_PATCHED).await;
        mount_gem_index(&server, "4f", &PINNED).await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = gem_registry(&server.uri(), "4f");
        let sources = hosted_gem_sources(tmp.path(), &remote, &LOCKED, &[]);
        let plan = plan(
            &online(tmp.path(), &server),
            sources,
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert_eq!(
            gem_states(&plan),
            [
                (GEM_ARM, &GemBuildState::Upstream),
                (GEM_LINUX, &patched(LINUX_UUID))
            ]
        );
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
        assert_eq!(
            asked(&server).await,
            [
                REFERENCE.to_string(),
                format!("/patch-registry/gem/tok/{U1}/s/4f/info/nokogiri")
            ]
        );
    }

    /// The index of the lock's registry cannot be read: nothing shows what
    /// the lock installs, so the document says `affected` of both builds
    /// and names no patch for them. Nothing is gated, and one note names
    /// the gem, the reason (with the error of the read) and what to run.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unreadable_index_states_the_builds_of_a_lock_without_checksums_as_affected() {
        let server = wiremock::MockServer::start().await;
        mount_gem_reference(&server, "4f", &ONE_PATCHED).await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = gem_registry(&server.uri(), "4f");
        let sources = hosted_gem_sources(tmp.path(), &remote, &LOCKED, &[]);
        let plan = plan(
            &online(tmp.path(), &server),
            sources,
            &[],
            &RunApiClient::new(),
        )
        .await;
        let unpinned = GemBuildState::Unknown(GemBuildUnknown::Unpinned);
        assert_eq!(
            gem_states(&plan),
            [(GEM_ARM, &unpinned), (GEM_LINUX, &unpinned)]
        );
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
        let [note] = plan.notes.as_slice() else {
            panic!("one note for the gem: {:?}", plan.notes);
        };
        assert_eq!(note.code, GEM_BUILD_UNKNOWN);
        assert!(
            note.detail.starts_with(&format!(
                "{GEM}: the lockfile takes its builds for arm64-darwin, x86_64-linux-gnu from \
                 the registry of Socket patch {U1}"
            )) && note.detail.contains(
                "(the lockfile has no CHECKSUMS entry for them, and its registry's index could \
                 not be read: "
            ) && note.detail.ends_with(&format!(
                "), so the VEX document states them as affected. {GEM_BUILD_RETRY}"
            )),
            "{}",
            note.detail
        );
        assert!(!note.detail.contains("/tok/"), "the grant token: {note:?}");

        // The document: both builds as affected, without the error.
        let why = "the lockfile has no CHECKSUMS entry for it, and its registry's index could \
                   not be read";
        let action = |platform: &str| unshown_action(platform, why, GEM_BUILD_RETRY);
        assert_eq!(
            gem_statements(&plan),
            (
                Vec::new(),
                vec![
                    (GEM_ARM.to_string(), action("arm64-darwin")),
                    (GEM_LINUX.to_string(), action("x86_64-linux-gnu")),
                ]
            )
        );
    }

    /// The reference is of a later registry than the lock names: it lists
    /// a patched build for a platform the lock still pins upstream's gem
    /// for. That build is not attested as patched, on either way of
    /// telling what the lock installs: the document says `affected` of it,
    /// and names the patch the list gives for it nowhere. The build the
    /// lock does pin patched is attested. Nothing is gated, and the note
    /// sends the reader to the scan.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_reference_newer_than_the_lock_attests_no_build_the_lock_pins_otherwise() {
        let both = [
            ("arm64-darwin", ARM_PATCHED, Some(ARM_UUID)),
            ("x86_64-linux-gnu", LINUX_PATCHED, Some(LINUX_UUID)),
        ];
        for checksums in [true, false] {
            let server = wiremock::MockServer::start().await;
            mount_gem_reference(&server, "5a", &both).await;
            mount_gem_index(&server, "4f", &PINNED).await;
            let tmp = tempfile::tempdir().unwrap();
            let remote = gem_registry(&server.uri(), "4f");
            let pinned: &[(&str, &str)] = if checksums { &PINNED } else { &[] };
            let sources = hosted_gem_sources(tmp.path(), &remote, &LOCKED, pinned);
            let plan = plan(
                &online(tmp.path(), &server),
                sources,
                &[],
                &RunApiClient::new(),
            )
            .await;
            assert_eq!(
                gem_states(&plan),
                [
                    (GEM_ARM, &GemBuildState::Unknown(GemBuildUnknown::Differs)),
                    (GEM_LINUX, &patched(LINUX_UUID))
                ],
                "checksums: {checksums}"
            );
            assert!(plan.gated.is_empty(), "{:?}", plan.gated);
            let [note] = plan.notes.as_slice() else {
                panic!("one note for the gem: {:?}", plan.notes);
            };
            assert!(
                note.detail.contains("its build for arm64-darwin from")
                    && note.detail.contains(
                        "(the lockfile installs another archive for it than the patch registry \
                         lists now), so the VEX document states it as affected."
                    )
                    && note.detail.ends_with(GEM_BUILD_RESCAN),
                "{}",
                note.detail
            );
            let (applied, affected) = gem_statements(&plan);
            assert_eq!(applied, [GEM_LINUX], "checksums: {checksums}");
            assert_eq!(
                affected,
                [(
                    GEM_ARM.to_string(),
                    unshown_action(
                        "arm64-darwin",
                        "the lockfile installs another archive for it than the patch registry \
                         lists now",
                        GEM_BUILD_RESCAN
                    )
                )],
                "checksums: {checksums}"
            );
            assert!(!affected[0].1.contains(ARM_UUID) && !affected[0].1.contains(U1));
            assert_eq!(
                asked(&server).await.len(),
                if checksums { 1 } else { 2 },
                "checksums: {checksums}"
            );
        }
    }

    /// `--offline`: nothing is asked, so nothing says which locked build
    /// is patched. The document says `affected` of the platform builds,
    /// with one note and nothing gated; the ruby-platform gem the lock
    /// names beside them is the gem's patch by the lock's wiring alone.
    #[tokio::test]
    #[serial_test::serial]
    async fn offline_states_the_platform_builds_as_affected_and_asks_nothing() {
        let server = wiremock::MockServer::start().await;
        mount_gem_reference(&server, "4f", &ONE_PATCHED).await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = gem_registry(&server.uri(), "4f");
        let sources = hosted_gem_sources(
            tmp.path(),
            &remote,
            &["1.18.10", LOCKED[0], LOCKED[1]],
            &[("1.18.10", RUBY_PATCHED), PINNED[0], PINNED[1]],
        );
        let common = GlobalArgs {
            offline: true,
            ..online(tmp.path(), &server)
        };
        let plan = plan(&common, sources, &[], &RunApiClient::new()).await;
        let unlisted = GemBuildState::Unknown(GemBuildUnknown::Unlisted);
        assert_eq!(
            gem_states(&plan),
            [
                (GEM, &patched(U1)),
                (GEM_ARM, &unlisted),
                (GEM_LINUX, &unlisted)
            ]
        );
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
        let [note] = plan.notes.as_slice() else {
            panic!("one note for the gem: {:?}", plan.notes);
        };
        assert_eq!(
            note.detail,
            format!(
                "{GEM}: the lockfile takes its builds for arm64-darwin, x86_64-linux-gnu from \
                 the registry of Socket patch {U1}, which serves a patched build for some \
                 platforms and upstream's own gem for the others. Which it is for these could \
                 not be told (--offline forbids asking the patch API), so the VEX document \
                 states them as affected. Run `socket-patch vex` without --offline to attest \
                 each build."
            )
        );
        assert_eq!(asked(&server).await, Vec::<String>::new());

        // The document: the ruby-platform gem under the gem's patch, and
        // each platform build as affected.
        let action = |platform: &str| {
            unshown_action(
                platform,
                "--offline forbids asking the patch API",
                GEM_BUILD_ONLINE,
            )
        };
        assert_eq!(
            gem_statements(&plan),
            (
                vec![GEM.to_string()],
                vec![
                    (GEM_ARM.to_string(), action("arm64-darwin")),
                    (GEM_LINUX.to_string(), action("x86_64-linux-gnu")),
                ]
            )
        );
    }

    /// The reference request fails, or the reference carries no list: no
    /// build is attested as patched and the document says `affected` of
    /// each, the note says which it was (with the error of a failed
    /// request, which the document leaves out), nothing is gated, and the
    /// registry is not asked for an index nothing could be held against.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_failed_or_listless_reference_states_the_platform_builds_as_affected() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, ResponseTemplate};
        let no_list = serde_json::json!({ "results": { U1: {
            "status": "granted", "purl": GEM,
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": format!("https://patch.example/patch-registry/gem/tok/{U1}/"),
                "identifiers": {
                    "name": "nokogiri", "version": "1.18.10", "gemChecksumSha256": RUBY_PATCHED,
                },
            },
        }}});
        for (answer, why, stated, remedy) in [
            (
                ResponseTemplate::new(500),
                "(the patch API request failed: ",
                "the patch API request failed",
                GEM_BUILD_RETRY,
            ),
            (
                ResponseTemplate::new(200).set_body_json(no_list),
                "(the patch API lists no builds for that patch)",
                "the patch API lists no builds for that patch",
                GEM_BUILD_RESCAN,
            ),
        ] {
            let server = wiremock::MockServer::start().await;
            Mock::given(method("POST"))
                .and(wm_path(REFERENCE))
                .respond_with(answer)
                .mount(&server)
                .await;
            let tmp = tempfile::tempdir().unwrap();
            let remote = gem_registry(&server.uri(), "4f");
            // No `CHECKSUMS`: with a list, the index would be read.
            let sources = hosted_gem_sources(tmp.path(), &remote, &LOCKED, &[]);
            let plan = plan(
                &online(tmp.path(), &server),
                sources,
                &[],
                &RunApiClient::new(),
            )
            .await;
            assert!(plan.gated.is_empty(), "{why}: {:?}", plan.gated);
            let [note] = plan.notes.as_slice() else {
                panic!("one note for the gem: {:?}", plan.notes);
            };
            assert!(
                note.code == GEM_BUILD_UNKNOWN
                    && note.detail.contains(why)
                    && note.detail.ends_with(remedy),
                "{}",
                note.detail
            );
            let asked = asked(&server).await;
            assert!(
                !asked.is_empty() && asked.iter().all(|path| path == REFERENCE),
                "{asked:?}"
            );
            // The document: no build as patched, each as affected.
            let action = |platform: &str| unshown_action(platform, stated, remedy);
            assert_eq!(
                gem_statements(&plan),
                (
                    Vec::new(),
                    vec![
                        (GEM_ARM.to_string(), action("arm64-darwin")),
                        (GEM_LINUX.to_string(), action("x86_64-linux-gnu")),
                    ]
                ),
                "{why}"
            );
        }
    }

    /// A gem the lock names as its ruby-platform gem alone is the one pin
    /// it always was, and so is every other ecosystem's: no request, and
    /// nothing for the document to name in its place.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_gem_locked_as_its_ruby_gem_alone_asks_nothing() {
        let server = wiremock::MockServer::start().await;
        mount_gem_reference(&server, "4f", &ONE_PATCHED).await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = format!("{}/patch-registry/gem/tok/{U1}/", server.uri());
        let sources = hosted_gem_sources(
            tmp.path(),
            &remote,
            &["1.18.10"],
            &[("1.18.10", RUBY_PATCHED)],
        );
        let plan = plan(
            &online(tmp.path(), &server),
            sources,
            &[],
            &RunApiClient::new(),
        )
        .await;
        assert!(plan.hosted_gems.is_empty(), "{:?}", plan.hosted_gems);
        assert_eq!(plan.redirected, [GEM, "pkg:npm/x@1.0.0"]);
        assert!(plan.gated.is_empty() && plan.notes.is_empty());
        assert!(GemBuildView::of(&plan).is_none());
        assert_eq!(asked(&server).await, Vec::<String>::new());
    }

    /// The pins of the hosted run the plan is part of come with what that
    /// run reports for each locked build: the plan takes them as they are
    /// and asks nothing, whatever the lock's `CHECKSUMS` hold.
    #[tokio::test]
    #[serial_test::serial]
    async fn the_builds_a_hosted_run_reports_are_taken_without_a_request() {
        let server = wiremock::MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let remote = gem_registry(&server.uri(), "4f");
        let report = |platform: Option<&str>, uuid: Option<&str>| PinReport {
            purl: match platform {
                Some(platform) => format!("{GEM}?platform={platform}"),
                None => GEM.to_string(),
            },
            uuid: uuid.map(str::to_string),
            gem_fix: Some(U1.to_string()),
            platform: platform.map(str::to_string),
            newly_patched: uuid.is_some(),
        };
        let sources = Sources {
            hosted_gem_builds: vec![
                report(None, Some(U1)),
                report(Some("arm64-darwin"), None),
                report(Some("x86_64-linux-gnu"), Some(LINUX_UUID)),
            ],
            ..hosted_gem_sources(tmp.path(), &remote, &LOCKED, &[])
        };
        let plan = plan(
            &online(tmp.path(), &server),
            sources,
            &[GEM.to_string()],
            &RunApiClient::new(),
        )
        .await;
        let gem = &plan.hosted_gems[GEM];
        assert!(!gem.resolved, "the run says its builds itself");
        let states: Vec<(&str, &GemBuildState)> = gem
            .builds
            .iter()
            .map(|build| (build.purl.as_str(), &build.state))
            .collect();
        assert_eq!(
            states,
            [
                (GEM, &patched(U1)),
                (GEM_ARM, &GemBuildState::Upstream),
                (GEM_LINUX, &patched(LINUX_UUID))
            ]
        );
        assert!(plan.gated.is_empty() && plan.notes.is_empty());
        assert_eq!(asked(&server).await, Vec::<String>::new());
    }

    /// A plan attesting the hosted gem [`GEM`] at [`U1`], locked as the
    /// builds `builds` (platform and state).
    fn hosted_gem_plan(builds: Vec<(Option<&str>, GemBuildState)>) -> Plan {
        let builds = builds
            .into_iter()
            .map(|(platform, state)| (platform.map(str::to_string), state));
        let gem = HostedGem::of(GEM, U1, builds, true).unwrap();
        Plan {
            view: PatchManifest {
                patches: HashMap::from([
                    (GEM.to_string(), record(U1)),
                    ("pkg:npm/left-pad@1.3.0".to_string(), record(U2)),
                ]),
                setup: None,
            },
            vendor_entries: HashMap::new(),
            vendor_pins: HashMap::new(),
            redirected: vec![GEM.to_string()],
            lockfile_basis: HashSet::new(),
            hosted: BTreeMap::new(),
            hosted_gems: BTreeMap::from([(GEM.to_string(), gem)]),
            gated: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// A gem a lock takes from its patch registry as platform builds is
    /// named per locked build. A patched build goes under its own patch,
    /// with the gem patch's vulnerabilities, wherever the gem was; a build
    /// on upstream's gem, and a build nothing is known of, are in no list
    /// of attested purls and are handed over as affected, each with what
    /// to do. All three keep a record in the view, so no statement names a
    /// form of the gem that stands for an unpatched build too.
    #[test]
    fn a_hosted_gem_is_attested_per_locked_build() {
        const JAVA: &str = "pkg:gem/nokogiri@1.18.10?platform=java";
        let plan = hosted_gem_plan(vec![
            (None, patched(U1)),
            (Some("arm64-darwin"), GemBuildState::Upstream),
            (
                Some("java"),
                GemBuildState::Unknown(GemBuildUnknown::Unlisted),
            ),
            (Some("x86_64-linux-gnu"), patched(LINUX_UUID)),
        ]);
        let builds = GemBuildView::of(&plan).expect("a gem locked as platform builds");
        let view = builds.view();
        let mut keys: Vec<&str> = view.patches.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [GEM, GEM_ARM, JAVA, GEM_LINUX, "pkg:npm/left-pad@1.3.0"]
        );
        assert_eq!(view.patches[GEM].uuid, U1);
        assert_eq!(view.patches[GEM_LINUX].uuid, LINUX_UUID);
        for purl in [GEM, GEM_ARM, JAVA, GEM_LINUX] {
            assert_eq!(
                view.patches[purl].vulnerabilities,
                record(U1).vulnerabilities
            );
        }

        for mut attested in [
            vec!["pkg:npm/left-pad@1.3.0".to_string(), GEM.to_string()],
            plan.redirected.clone(),
        ] {
            let others = attested.len() - 1;
            builds.expand(&mut attested);
            assert_eq!(attested[others..], [GEM, GEM_LINUX]);
        }
        assert_eq!(
            builds.not_patched(),
            [
                (
                    GEM_ARM.to_string(),
                    format!(
                        "The patch registry has no patched build of this gem for arm64-darwin \
                         yet and serves upstream's own gem for it, so an install on that \
                         platform is without Socket patch {U1}. Run `socket-patch scan --mode \
                         hosted` again later: the lockfile takes the patched build once it is \
                         published."
                    )
                ),
                (
                    JAVA.to_string(),
                    unshown_action(
                        "java",
                        "the patch registry does not list it now",
                        GEM_BUILD_RESCAN
                    )
                ),
            ]
        );
        let described: Vec<(&str, Option<&str>, bool, Option<&str>)> = builds
            .builds()
            .iter()
            .map(|(purl, build)| {
                assert_eq!(build.gem_fix, U1);
                (
                    purl.as_str(),
                    build.platform.as_deref(),
                    build.kept_upstream,
                    build.unshown.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            described,
            [
                (GEM, None, false, None),
                (GEM_ARM, Some("arm64-darwin"), true, None),
                (
                    JAVA,
                    Some("java"),
                    false,
                    Some("not shown patched for java: the patch registry does not list it now")
                ),
                (GEM_LINUX, Some("x86_64-linux-gnu"), false, None),
            ]
        );
    }

    /// An installed copy of a platform build the lock does not install
    /// patched is no evidence about the gem: it is upstream's own gem by
    /// the lock. Every other copy is judged, the ruby-platform one and one
    /// of a platform the lock does not name included.
    #[test]
    fn the_copy_of_a_build_the_lock_installs_unpatched_is_not_judged() {
        let plan = hosted_gem_plan(vec![
            (Some("arm64-darwin"), GemBuildState::Upstream),
            (
                Some("java"),
                GemBuildState::Unknown(GemBuildUnknown::Differs),
            ),
            (Some("x86_64-linux-gnu"), patched(LINUX_UUID)),
        ]);
        let gem = &plan.hosted_gems[GEM];
        let judged = |leaf: &str| gem.judges(GEM, &Path::new("/home/gems").join(leaf));
        assert!(!judged("nokogiri-1.18.10-arm64-darwin"));
        assert!(!judged("nokogiri-1.18.10-java"));
        assert!(judged("nokogiri-1.18.10-x86_64-linux-gnu"));
        assert!(judged("nokogiri-1.18.10"));
        assert!(judged("nokogiri-1.18.10-aarch64-linux-gnu"));
        assert!(judged("nokogiri-1.18.9-arm64-darwin"));
    }
}
