//! The consumer verdict for `vex` and `apply --check` (design 7 and
//! HZ-15; revision 4, section 3): whether the Bazel build consumes a
//! patch. A statement is made only on a proof from committed files, and
//! every way a statement over-attests today ends here:
//!
//! - a hosted reference in a file no hub reads (a `pom.xml` beside
//!   `maven_install.json`) is withheld, and [`Attest::contests`] lists
//!   what each hub builds unpatched for the cross-lock contest;
//! - a patched installed tree says nothing about a build that fetches
//!   from a lock, in the governed project and in any other project of
//!   the workspace whose package a hub lock resolves;
//! - a vendored reference counts only through a lane that proves the
//!   ruleset consumes it;
//! - an in-run statement skips verification only for a patch a Bazel
//!   lane confirmed in that run ([`Attest::assume_applied`]);
//! - nothing here hashes a file or reads an installed tree, so a run
//!   that skips verification (`--no-verify`) skips none of it.
//!
//! [`Attest::consumer`] is the one entry. For a pin it re-runs what the
//! gate asked before the write (governance, literal labels, bypasses and
//! consent after the own-wiring subtraction, the lane's own proof) and
//! adds what only committed state shows: every hub lock that resolves the
//! release holds the pin, no lock of the ecosystem is unlisted, the lock
//! Bazel wrote records the pinned file as it is now, and the rows of the
//! owned index still describe the workspace.
//!
//! # The pinned digest
//!
//! A hosted pin attests only when the digest the build enforces is the
//! patch's: a lock line with the Socket URL and the upstream digest
//! builds the upstream package from the repository cache (probe Y6). The
//! comparison is made here, because a lane's `attest` is handed no grant:
//!
//! - **With the grant** (an in-run statement), every entry of the release
//!   that the hub's listing holds, in every lock file of the hub, must
//!   carry the grant's digest. A listing with no entry of the release, or
//!   an entry with no digest, anchors nothing. So a lane whose lock holds
//!   a digest lists it in its `LaneOps::inventory`, under the purl its
//!   pins name.
//! - **Without one** (offline `vex`), the pin attests only when committed
//!   state records the digest it was written with: a `pins` row of the
//!   owned index for the pin's patch, lane and file, which the lane's
//!   `attest` holds the lock to. A pin a lane finds in a native lock alone
//!   has no such record and is withheld as undetermined; whether offline
//!   `vex` may speak for one, and on what record, is the owner's to
//!   decide.
//! - Either way the entries of one release in one hub must agree: one
//!   lock file of a hub on the patched digest and another on the upstream
//!   one, or on none, is a hub that builds the upstream package on some
//!   platform.
//!
//! A vendored pin and an agent pin are not held to a locked digest: the
//! committed artifact, or the patched tree, is the evidence, and the
//! caller verifies it ([`Consumed`]). A digest their lock does hold is
//! still compared with the grant.
//!
//! # What a lane's `attest` owes
//!
//! [`Attest::consumer`] cannot ask what only a lane knows. Each lane's
//! `attest` therefore does all of these, through the helpers here:
//!
//! - [`no_bypass`] over the repositories its plan names (the spokes);
//! - [`works_after`] with the extensions that generate its hub's
//!   repositories and the pin as their specs render it: the call made
//!   here names neither, so it cannot tell a forged lock entry (a fresh
//!   digest beside repository specs from before the pin) from a refreshed
//!   one;
//! - [`version_gate`] with the ruleset floor its gate asked for
//!   (obligation 5), which is the lane's and is asked nowhere else;
//! - where a `pins` row records the pin, that the lock still holds what
//!   the row records;
//! - where it writes several files of one hub, its all-files-or-none
//!   gate again (`lock_set_partial`): this file proves every pin a
//!   lane discovers and compares the entries a listing holds, and only
//!   the lane knows which files make up the set.
//!
//! What this release cannot check yet withholds. The renderer of the
//! owned files and the hook reader have not landed, so their answers
//! arrive through [`OwnedState`]; the answer of this build
//! ([`Unrendered`]) is "not checked", and a pin whose proof rests on an
//! owned file or a hook is then withheld. A pin a declaration selects
//! (`AttestBasis::Declared`) and a pin in owned pin data
//! (`AttestBasis::OwnedPin`) are withheld in every case: no enabled lane
//! writes one, and the readers that prove the bytes behind them land with
//! those lanes. An rc flag is never evidence: a `--distdir` row provides
//! bytes a digest already pins, and a pin only an rc flag selects is not
//! attested at all.
//!
//! The `runs` rows of the index are receipts and are never read here: a
//! row cannot prove that a tool's output is still current.

use super::consent::{self, USER_PATCH_HOOK};
use super::derived::{self, ExtRef, LockUse, Proof};
use super::exec;
use super::gate::{
    self, GateCx, Roots, HOOK_MISSING, NESTED_BAZEL_ROOTS, OWNED_FILE_MISSING, OWNED_FILE_MODIFIED,
};
use super::inventory::{self, may_build, Inventory, Resolved, Unlisted};
use super::lanes::{self, Discovered};
use super::model::{
    Anchor, AttestBasis, BazelRef, BazelWorkspace, FileText, FileView, Governance, HookKind, Hub,
    HubId, Index, IndexRow, LaneCx, LaneId, LaneOps, LaneSpec, LaneTable, Mode, OwnedWrite,
    PatchRequest, Plan, PlannedWrite, Probe, Reason, Refusal, Ruleset, RunPolicy, Site,
    StaleBehaviour, VexWithhold, WithholdKind,
};
use super::owned_index::{
    self, BzlRow, FileRow, HookRow, LabelStrategy, Parsed, RcFlag, RcFlagRow, SegmentRow,
    TagEditRow, INDEX_PATH, OWNED_BUILD_PATH, OWNED_BZL_PATH, OWNED_RC_PATH, OWNED_SEGMENT_PATH,
};
use super::rc::{Chain, RepoEnv, GO_REPO_ENV};
use super::remedy;
use crate::crawlers::types::Ecosystem;
use crate::patch::redirect::Integrity;
use crate::utils::purl::purl_parts;
use crate::utils::purl_key::{canonical_base_purl, PurlKey};
use crate::vendor::lock_inventory::{LockIntegrity, LockfileEntry};

/// Every `details.token` this file names itself. The others it reports
/// are the tokens of the gate and of the consent evidence.
pub const TOKENS: &[&str] = &["stale_override", "rc_selected"];

/// The recorded wiring is for another version than the lock pins now.
pub const STALE_OVERRIDE: &str = TOKENS[0];
/// Only an rc flag selects the patched bytes.
pub const RC_SELECTED: &str = TOKENS[1];

// ── Owned state ──────────────────────────────────────────────────────

/// What a file under `.socket/bazel/` is, held against the rows that
/// render it (revision 4, 1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedFile {
    Ours,
    /// A formatter rewrote it and its model is the render's.
    Reformatted,
    Modified,
    /// Rows exist and the file does not.
    Missing,
    Foreign,
    /// Nothing compared the bytes with the rows: not known to be ours.
    Unchecked,
}

/// What a hook unit is in the user file its row names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookUnit {
    /// The unit, exactly once, as a statement Bazel evaluates.
    Present,
    Absent,
    Damaged,
    Duplicated,
    /// Nothing read the file for the unit.
    Unchecked,
}

/// The state of the owned files and of the hooks that reach them. The
/// renderer and the hook reader give these answers once they land (the
/// `owned_render::state` and `hook::state` of revision 4, 1.8); the gate's
/// obligation 15 is to be fed from the same two. Until then a build has
/// [`Unrendered`], and a test supplies the answer it wants to prove the
/// verdict over.
pub trait OwnedState {
    fn file(&self, path: &str) -> OwnedFile;
    fn hook(&self, row: &HookRow) -> HookUnit;
}

/// The owned state as a build without a renderer and a hook reader knows
/// it: a file that is gone is `Missing` (a missing user file holds no
/// unit), and every file that is there is `Unchecked`. So no statement
/// ever rests on bytes nobody compared.
pub struct Unrendered<'a>(pub &'a dyn FileView);

impl OwnedState for Unrendered<'_> {
    fn file(&self, path: &str) -> OwnedFile {
        match self.0.read(path) {
            FileText::Absent => OwnedFile::Missing,
            _ => OwnedFile::Unchecked,
        }
    }

    fn hook(&self, row: &HookRow) -> HookUnit {
        match self.0.read(&row.file) {
            FileText::Absent => HookUnit::Absent,
            _ => HookUnit::Unchecked,
        }
    }
}

// ── Candidates and verdicts ──────────────────────────────────────────

/// What a candidate statement rests on, as its caller found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis<'a> {
    /// A patched copy in an installed tree (agent mode). No committed
    /// file refers to the patch.
    Installed,
    /// A Socket-host reference that a native extractor read from the
    /// root-relative `file`.
    Hosted { file: &'a str },
    /// A `.socket/vendor/...` reference read from the root-relative
    /// `file`.
    Vendored { file: &'a str },
    /// A pin `lanes::discover` returned.
    Pin(&'a BazelRef),
}

/// One `(purl, uuid)` that `vex` or `apply --check` would speak for.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    pub purl: &'a str,
    pub uuid: &'a str,
    /// The project it was found in, relative to the Bazel root.
    pub project_rel: &'a str,
    pub basis: Basis<'a>,
    /// The digests of the patch artifact, where the caller holds the
    /// grant (an in-run statement). Every digest the hub's locks list
    /// for the release must then be the grant's. `None` (offline `vex`):
    /// a hosted pin attests only on a digest committed state records
    /// (the module docs, "The pinned digest").
    pub grant: Option<&'a Integrity>,
}

impl<'a> Candidate<'a> {
    /// The candidate of a discovered pin in the project `project_rel`,
    /// with the grant of its patch where the caller holds it.
    pub fn of_pin(pin: &'a BazelRef, project_rel: &'a str, grant: Option<&'a Integrity>) -> Self {
        Self {
            purl: &pin.purl,
            uuid: &pin.uuid,
            project_rel,
            basis: Basis::Pin(pin),
            grant,
        }
    }
}

/// A candidate the Bazel layer does not withhold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumed {
    /// No hub builds the package: the candidate is judged exactly as it
    /// is outside a Bazel workspace.
    AsToday,
    /// The Bazel build consumes the patch through a pin of `lane`, a
    /// lane of `mode`. The proof is of committed files. What the caller
    /// still verifies follows the mode, and a caller asks the three
    /// accessors below, never the variant's fields:
    ///
    /// - a hosted pin replaces the installed-tree verification: Bazel
    ///   reads no host store, so for a governed NuGet hub neither the
    ///   global packages folder nor its stale-package withholding
    ///   applies. The reference must carry a locked digest;
    /// - a vendored pin keeps its committed artifact as the sole
    ///   evidence, which the caller hashes. No tree is verified and no
    ///   locked digest is asked for;
    /// - an agent pin makes Bazel build from the patched tree (the Go
    ///   directory replace, `A-GO1`), so the caller's verification of
    ///   that tree is the evidence, as it is without Bazel.
    ByBazel {
        lane: LaneId,
        mode: Mode,
        basis: AttestBasis,
    },
}

impl Consumed {
    /// Whether the caller still verifies the installed tree: where the
    /// Bazel layer has nothing to say, and for an agent pin, whose tree
    /// is what Bazel builds from. Nothing here hashes a tree, so a caller
    /// that skipped this for an agent pin would say "patched" over bytes
    /// nobody verified.
    pub const fn verifies_installed_tree(self) -> bool {
        match self {
            Self::AsToday => true,
            Self::ByBazel { mode, .. } => matches!(mode, Mode::Agent),
        }
    }

    /// Whether the reference must carry a locked digest: for a hosted
    /// pin the Bazel build consumes (design 7, the hosted and bazel-lock
    /// rows). For every other verdict the Bazel layer asks for none, and
    /// the caller's own rule for the reference stands.
    pub const fn integrity_required(self) -> bool {
        matches!(
            self,
            Self::ByBazel {
                mode: Mode::Hosted,
                ..
            }
        )
    }

    /// Whether the committed artifact under `.socket/vendor/` is the
    /// evidence of the pin, which the caller hashes against its ledger
    /// record before it speaks: for a vendored pin the Bazel build
    /// consumes (design 7, the vendored row).
    pub const fn hashes_committed_artifact(self) -> bool {
        matches!(
            self,
            Self::ByBazel {
                mode: Mode::Vendored,
                ..
            }
        )
    }
}

/// What a verdict says of a patch that a pin or a row of the owned index
/// holds (revision 4, architecture 8.7): the `state` an audit prints, and
/// what `apply --check` fails on. Decided here, from the kind and the
/// token of a withhold, so that no caller matches on either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// The build takes the patch through a pin that passes its proof.
    Consumed,
    /// The pin is written and its one command has left no evidence yet.
    RunPending,
    /// The wiring is for another version than the lock pins now: the
    /// user bumped the package and has not run socket-patch since.
    Stale,
    /// What was written no longer stands: a pin erased or changed, an
    /// owned file missing or edited, a hook gone, a bypass, a digest
    /// nothing anchors.
    Drift,
    /// Nothing proves that the build takes the patch, and nothing says it
    /// was ever wired: no lane can tell, or no hub builds the package.
    NotConsumed,
}

impl Held {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consumed => "consumed",
            Self::RunPending => "run_pending",
            Self::Stale => "stale",
            Self::Drift => "drift",
            Self::NotConsumed => "not_consumed",
        }
    }

    /// The state a verdict of [`Attest::consumer`] is. "Cannot tell" is
    /// never drift: a withhold for an undetermined consumer says nothing
    /// about what was written. Of the stale states only the version bump
    /// is [`Self::Stale`]: a derived value or an owned file that disagrees
    /// with its record is wiring that was changed, whatever version the
    /// lock pins.
    pub fn of(verdict: &Result<Consumed, VexWithhold>) -> Self {
        let why = match verdict {
            Ok(Consumed::AsToday) => return Self::NotConsumed,
            Ok(Consumed::ByBazel { .. }) => return Self::Consumed,
            Err(why) => why,
        };
        match (why.kind, why.token) {
            (WithholdKind::ConsumerUndetermined, _) => Self::NotConsumed,
            (WithholdKind::RunPending, _) => Self::RunPending,
            (WithholdKind::DerivedStale, Some(STALE_OVERRIDE)) => Self::Stale,
            _ => Self::Drift,
        }
    }

    /// Whether `apply --check` exits non-zero for the state, for wiring a
    /// lane with the staleness behaviour `stale` wrote (owner decision
    /// O53, defaulted). Drift always does. A stale row does only where
    /// the leftover fails the build: under an inert lane the build is
    /// green on the version the user asked for, and a routine bump must
    /// not turn the check red.
    pub const fn fails_check(self, stale: StaleBehaviour) -> bool {
        match self {
            Self::Drift => true,
            Self::Stale => matches!(stale, StaleBehaviour::FailsAttributed),
            Self::Consumed | Self::RunPending | Self::NotConsumed => false,
        }
    }
}

/// An entry a hub builds with no pin that passes: it contests a native
/// reference to the same release in any project (`resolved_elsewhere`).
#[derive(Debug, Clone, Copy)]
pub struct Contest<'a> {
    pub hub: HubId,
    pub entry: &'a LockfileEntry,
}

/// What `vendor --check` verified of one vendored artifact before it asks
/// for the vendored claim.
#[derive(Debug, Clone, Copy)]
pub struct VendoredArtifact<'a> {
    /// The root-relative directory that holds it
    /// (`<project>/.socket/vendor/<eco>/<uuid>`).
    pub dir: &'a str,
    pub leaf: &'a str,
    /// Its bytes hash to the digest the pin holds. Hashing is the
    /// caller's: this layer reads no artifact.
    pub digest_is_pinned: bool,
    /// The URL the pin names. Matched and never printed: its path can
    /// hold the grant token.
    pub pin_url: &'a str,
}

fn withheld(
    kind: WithholdKind,
    token: Option<&'static str>,
    detail: impl Into<String>,
) -> VexWithhold {
    let detail = detail.into();
    VexWithhold {
        kind,
        token,
        detail,
    }
}

fn undetermined(detail: impl Into<String>) -> VexWithhold {
    withheld(WithholdKind::ConsumerUndetermined, None, detail)
}

fn no_release(purl: &str) -> VexWithhold {
    undetermined(format!("`{purl}` names no release of a package"))
}

/// A refusal of a gate obligation as the reason a statement is withheld:
/// the proof the write rested on does not hold now. The kind follows the
/// reason and the token is the refusal's.
fn of_refusal(refusal: Refusal) -> VexWithhold {
    let kind = match refusal.reason {
        Reason::PinBypassed => WithholdKind::PinBypassed,
        Reason::DeclarationInactive => WithholdKind::NotConsumed,
        Reason::OwnedFileModified | Reason::DerivedUnrepairable => WithholdKind::DerivedStale,
        Reason::SelectionUnproven => WithholdKind::SelectionUnproven,
        _ => WithholdKind::ConsumerUndetermined,
    };
    // A refusal ends by saying that nothing was written, which is not
    // what a withheld statement is about.
    let detail = refusal.detail.trim_end_matches("; nothing was written");
    withheld(kind, Some(refusal.token), detail)
}

fn unlisted_lock(unlisted: &Unlisted) -> VexWithhold {
    let detail = format!(
        "a lock Bazel may build this ecosystem from could not be listed, so what it resolves is \
         not known: {}",
        unlisted.detail
    );
    withheld(WithholdKind::ConsumerUndetermined, unlisted.token, detail)
}

/// Whether `hub` names the root-relative `file` as one of its locks.
fn reads(hub: &Hub, file: &str) -> bool {
    let named = |lock: &super::model::LockRef| lock.path.as_deref() == Some(file);
    hub.locks.iter().any(named)
}

/// Whether the version key of a tag edit is for `version` and for no
/// other: the key is the version itself, or a name and the version
/// joined by `-` or `@` (`rack-2.2.8`, `left-pad@1.3.0`), which is how
/// the rulesets key a package by its version. The whole tail of the key
/// is compared, so a key for a pre-release or a suffixed version
/// (`rack-2.2.8-rc1`, `guava-32.0.1-jre`) is not a key for the bare one,
/// and no version is found inside a longer one.
///
/// A key that says more after the version (a wheel file name, a gem
/// platform) is for no version here: no lane writes one yet, and the
/// version such a key is compared with has to carry the same suffix.
fn keyed_for(key: &str, version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    let named = |name: &str| name.len() > 1 && name.ends_with(['-', '@']);
    key == version || key.strip_suffix(version).is_some_and(named)
}

/// The package of a purl without its version, as an identity.
fn package_key(purl: &str) -> Option<PurlKey> {
    let (kind, name, _) = purl_parts(purl)?;
    Some(PurlKey::new(&format!("pkg:{kind}/{name}")))
}

/// The ecosystem, name and version a purl names. The ecosystem is read
/// from the canonical spelling: a type in another case
/// (`pkg:MAVEN/...`) is the same release to every comparison made with
/// [`PurlKey`], so it must not read as an ecosystem no ruleset builds.
/// The name and the version keep the spelling of `purl`, which is what
/// the user's own declarations are matched against.
fn release(purl: &str) -> Option<(Ecosystem, String, String)> {
    let ecosystem = Ecosystem::from_purl(&canonical_base_purl(purl))?;
    let (_, name, version) = purl_parts(purl.trim())?;
    Some((ecosystem, name, version))
}

/// A digest in the spelling two entries of one release are compared in:
/// its kind and its digests, sorted. Hex digests compare without case,
/// and a set of digests without order. An entry with no digest agrees
/// only with another that has none.
fn digest_key(digest: &LockIntegrity) -> (&'static str, Vec<String>) {
    let lower = |sum: &String| sum.to_ascii_lowercase();
    let (kind, mut sums): (&str, Vec<String>) = match digest {
        LockIntegrity::None => ("none", Vec::new()),
        LockIntegrity::Sha256Hex(sum) => ("sha256", vec![lower(sum)]),
        LockIntegrity::Sha256AnyOf(sums) => ("sha256", sums.iter().map(lower).collect()),
        LockIntegrity::Sha1Hex(sum) => ("sha1", vec![lower(sum)]),
        LockIntegrity::Sri(sri) => ("sri", sri.split_whitespace().map(String::from).collect()),
        LockIntegrity::GoH1(sum) => ("h1", vec![sum.clone()]),
        LockIntegrity::BerryChecksum(sum) => ("berry", vec![sum.clone()]),
    };
    sums.sort();
    sums.dedup();
    (kind, sums)
}

/// The pinned digest equals the grant's (design 7): `Ok` only when the
/// digest a lock holds is the patch artifact's, in the lock's own
/// rendering. A digest of another value is `DerivedStale`: it is what a
/// merge or the ruleset's own tooling leaves, and a line with the Socket
/// URL and the upstream hash builds the upstream package from the
/// repository cache (probe Y6). A lock entry with no digest anchors
/// nothing.
pub fn digest_equals_grant(pinned: &LockIntegrity, grant: &Integrity) -> Result<(), VexWithhold> {
    digest_of_grants(pinned, &[grant])
}

/// [`digest_equals_grant`] for a patch that is granted as several
/// artifacts (a wheel and an sdist of one release): `Ok` only when every
/// digest the lock holds for the release is the digest of one of them. A
/// lock entry can list one digest per artifact (`Sha256AnyOf`, an SRI
/// string with several hashes), and the build accepts any of the listed
/// ones, so each has to be an artifact of the patch. No artifact at all is
/// no grant: nothing equals it.
pub fn digest_of_grants(pinned: &LockIntegrity, grants: &[&Integrity]) -> Result<(), VexWithhold> {
    let hex = |found: &str, of: fn(&Integrity) -> &Option<String>| {
        let held = |grant: &&Integrity| {
            let of = of(grant).as_deref().filter(|of| !of.is_empty());
            of.is_some_and(|of| of.eq_ignore_ascii_case(found))
        };
        grants.iter().any(held)
    };
    let exact = |found: &str, of: fn(&Integrity) -> &Option<String>| {
        let held = |grant: &&Integrity| of(grant).as_deref() == Some(found);
        !found.is_empty() && grants.iter().any(held)
    };
    let equal = match pinned {
        LockIntegrity::None => {
            let detail = "the lock records no digest for the pinned package, so nothing the \
                          build enforces says which bytes it fetches";
            return Err(withheld(WithholdKind::IntegrityUnanchored, None, detail));
        }
        LockIntegrity::Sha256Hex(sum) => hex(sum, |grant| &grant.sha256),
        // The build accepts any digest of the set, so each must be the
        // patch's.
        LockIntegrity::Sha256AnyOf(sums) => {
            !sums.is_empty() && sums.iter().all(|sum| hex(sum, |grant| &grant.sha256))
        }
        LockIntegrity::Sha1Hex(sum) => hex(sum, |grant| &grant.sha1),
        LockIntegrity::Sri(sri) => {
            let mut hashes = sri.split_whitespace().peekable();
            hashes.peek().is_some() && hashes.all(|hash| exact(hash, |grant| &grant.sha512))
        }
        LockIntegrity::GoH1(sum) => exact(sum, |grant| &grant.dirhash_h1),
        LockIntegrity::BerryChecksum(sum) => exact(sum, |grant| &grant.yarn_berry10c0),
    };
    if equal {
        return Ok(());
    }
    let detail = "the digest the lock pins is not the digest of the patch (or the patch has none \
                  of that kind), so the build does not fetch the patched package; run \
                  `socket-patch scan` to pin it again";
    Err(withheld(WithholdKind::DerivedStale, None, detail))
}

/// Obligation 6 for a lane's `attest`, over the repositories only the
/// lane can name (`Plan::repositories`: a spoke such as
/// `npm__left-pad__1.3.0`). A lane whose plan names one passes the same
/// names here, or an `--override_repository` of the spoke would be
/// attested. [`Attest::consumer`] asks for the hub itself.
pub fn no_bypass(
    cx: &LaneCx<'_>,
    pin: &BazelRef,
    lane: LaneId,
    spokes: &[&str],
) -> Result<(), VexWithhold> {
    let Some((ecosystem, name, version)) = release(&pin.purl) else {
        return Err(no_release(&pin.purl));
    };
    let request = PatchRequest {
        ecosystem,
        name: &name,
        version: &version,
        uuid: &pin.uuid,
        project_rel: &cx.ws.root.project_rel,
    };
    gate::no_bypass(cx.ws, cx.index, cx.hub, &request, lane, spokes).map_err(of_refusal)
}

/// Obligation 5 for a lane's `attest`: the ruleset of the hub is still
/// proven to be `floor` or later, as the lane's gate asked before the
/// write. The threshold is the lane's, so nothing but its `attest` can
/// ask again; `needs` is what the lift names, such as `rules_js 1.39.1`.
pub fn version_gate(cx: &LaneCx<'_>, floor: &str, needs: &'static str) -> Result<(), VexWithhold> {
    let Some(hub) = cx.ws.hubs.get(cx.hub.0) else {
        return Err(undetermined("the pin names a hub the model does not have"));
    };
    gate::version_gate(hub, floor, needs).map_err(of_refusal)
}

/// The committed evidence that ends works-after (design 2.10): every
/// record of every input the lane wrote holds the SHA-256 of the file as
/// found, under every platform key, and each entry of the hub's
/// extensions carries the pin in its `generatedRepoSpecs`. A fresh digest
/// beside old specs is `DerivedStale` (probe L1.d); a record that is
/// behind is `RunPending`.
///
/// The forged entry is seen only by a call that names the extensions and
/// the pin: with `hub` empty and `pin` `None` the specs are not looked
/// at. [`Attest::consumer`] can make only that call, for the pin's file,
/// so each lane's `attest` makes this one with both.
///
/// Lockfile facts are no part of it and never withhold: the pin's digest
/// is enforced at fetch, and a fact that stays after a refresh proves
/// nothing either way. Where the plain build neither reads nor writes
/// the lock (`--lockfile_mode=off`), no record is evidence and none is
/// needed.
pub fn works_after(
    ws: &BazelWorkspace,
    files: &dyn FileView,
    inputs: &[&str],
    hub: &[ExtRef<'_>],
    pin: Option<&str>,
    query_hub: Option<&str>,
) -> Result<(), VexWithhold> {
    if derived::lock_use_of(&ws.flags, &ws.line) == LockUse::Unused {
        return Ok(());
    }
    let proof = Proof {
        inputs,
        hub,
        pin,
        digest_function: derived::digest_function_tracked(&ws.flags),
    };
    let cx = remedy::Cx {
        line: &ws.line,
        strict_repo_env: remedy::strict_repo_env(&ws.flags),
        facts_in_lock: false,
        query_hub,
    };
    let found = derived::evidence(&ws.module_lock, files, &proof);
    found.withhold(&ws.module_lock, &cx).map_or(Ok(()), Err)
}

// ── The rows of one pin ──────────────────────────────────────────────

/// The rows of the owned index that wire one patch through one lane. The
/// `runs` rows are left out on purpose: a receipt is no evidence.
struct Rows<'a> {
    rc: Vec<&'a RcFlagRow>,
    segment: Vec<&'a SegmentRow>,
    bzl: Vec<&'a BzlRow>,
    files: Vec<&'a FileRow>,
    tag_edits: Vec<&'a TagEditRow>,
}

impl<'a> Rows<'a> {
    fn of(index: &'a Index, pin: &BazelRef) -> Self {
        macro_rules! own {
            ($list:expr) => {
                $list
                    .iter()
                    .filter(|row| row.uuid == pin.uuid && row.lane == pin.lane.0)
                    .collect()
            };
        }
        Self {
            rc: own!(index.rc_flags),
            segment: own!(index.segment),
            bzl: own!(index.bzl),
            files: own!(index.files),
            tag_edits: own!(index.tag_edits),
        }
    }

    /// Whether a proof can rest on none of them. An rc row is not
    /// counted: under a digest or a declaration it only provides bytes
    /// that something else selects, and a pin only an rc flag selects is
    /// withheld whatever the file holds.
    fn selects_nothing(&self) -> bool {
        self.segment.is_empty()
            && self.bzl.is_empty()
            && self.files.is_empty()
            && self.tag_edits.is_empty()
    }

    /// The owned paths the selecting rows render into or name.
    fn owned_paths(&self, index: &Index) -> Vec<&'a str> {
        let mut paths: Vec<&str> = Vec::new();
        if !self.segment.is_empty() {
            paths.push(OWNED_SEGMENT_PATH);
        }
        if !self.bzl.is_empty() {
            paths.push(OWNED_BZL_PATH);
        }
        let labelled = !self.segment.is_empty() || !self.bzl.is_empty();
        if labelled && index.label_strategy == Some(LabelStrategy::Package) {
            paths.push(OWNED_BUILD_PATH);
        }
        paths.extend(self.files.iter().map(|row| row.path.as_str()));
        paths
    }
}

// ── The verdict ──────────────────────────────────────────────────────

/// A candidate with the parts of its purl.
struct Package<'a> {
    candidate: &'a Candidate<'a>,
    /// The candidate's purl in its canonical spelling, which every
    /// lookup of the release is made with.
    purl: String,
    ecosystem: Ecosystem,
    name: String,
    version: String,
}

impl Package<'_> {
    fn request(&self) -> PatchRequest<'_> {
        PatchRequest {
            ecosystem: self.ecosystem,
            name: &self.name,
            version: &self.version,
            uuid: self.candidate.uuid,
            project_rel: self.candidate.project_rel,
        }
    }
}

/// Everything the verdict is decided from, read once per Bazel root.
pub struct Attest<'a> {
    pub ws: &'a BazelWorkspace,
    pub lanes: &'a LaneTable,
    pub files: &'a dyn FileView,
    /// The root's owned index as the loader parsed it.
    pub index: &'a Index,
    /// What the root probe found beside this root, as the gate takes it.
    pub roots: Roots<'a>,
    pub owned: Box<dyn OwnedState + 'a>,
    /// What every hub lock of the root resolves.
    pub inventory: Inventory,
    /// The pins of every hub, and the hubs that cannot tell theirs.
    pub discovered: Discovered,
}

impl<'a> Attest<'a> {
    /// Lists the hub locks and discovers the pins of the root `ws` was
    /// read from, with the owned state of a build that cannot check an
    /// owned file yet ([`Unrendered`]).
    ///
    /// `roots` is the root probe's answer for the project. It is asked
    /// for here, and has no default, because the one-root answer is the
    /// open one: under [`Roots::One`] a candidate is judged as it is
    /// today where the probed roots would leave it undetermined (a
    /// Bazel root above the repository, nested roots; HZ-19). A caller
    /// passes [`Roots::One`] only when the probe found this root alone.
    pub fn read(
        ws: &'a BazelWorkspace,
        lanes: &'a LaneTable,
        files: &'a dyn FileView,
        index: &'a Index,
        roots: Roots<'a>,
    ) -> Self {
        let text = |rel: &str| files.read(rel).as_str().map(String::from);
        Self {
            ws,
            lanes,
            files,
            index,
            roots,
            owned: Box::new(Unrendered(files)),
            inventory: inventory::inventory(ws, lanes, files, index),
            discovered: lanes::discover(lanes, ws, files, index, &text),
        }
    }

    /// Whether the Bazel build consumes the patch of `candidate`, by its
    /// basis and the governance of its project (the table of design 7).
    /// Decided at plan level, from committed files alone.
    pub fn consumer(&self, candidate: &Candidate<'_>) -> Result<Consumed, VexWithhold> {
        let Some(package) = self.package(candidate)? else {
            return Ok(Consumed::AsToday);
        };
        match self.governing(&package)? {
            Governance::NotGoverned => self.not_governed(&package),
            // Inactive, ambiguous and undetermined projects are withheld
            // for the reason the gate refuses a write there.
            governed => {
                let hubs = gate::live_hubs(self.ws, governed).map_err(of_refusal)?;
                self.governed(&package, &hubs)
            }
        }
    }

    /// Whether an in-run statement (`scan --mode hosted --vex`) may take
    /// the patch for applied without verifying a tree. Where Bazel
    /// governs the project, or may, only a patch a Bazel lane confirmed
    /// in this run is: a confirmation of the native writer is about a
    /// lock the build may not read. [`Self::consumer`] still decides the
    /// statement.
    pub fn assume_applied(
        &self,
        candidate: &Candidate<'_>,
        confirmed_bazel_uuids: &[&str],
    ) -> bool {
        let governed = match self.package(candidate) {
            Ok(None) => return true,
            Ok(Some(package)) => self.governing(&package),
            Err(why) => Err(why),
        };
        matches!(governed, Ok(Governance::NotGoverned))
            || confirmed_bazel_uuids.contains(&candidate.uuid)
    }

    /// What each listed hub builds with no pin that passes its proof now.
    /// The extractor reports each as resolved elsewhere, so a native
    /// reference to the same release is contested in any project. A hub
    /// whose lock could not be listed is not here:
    /// `Inventory::cannot_enumerate` says so per ecosystem.
    ///
    /// `grant_of` is the grant the caller holds for the patch of a pin,
    /// as [`Candidate::grant`] is for one candidate: without it a hosted
    /// pin passes only on a recorded digest.
    ///
    /// A release counts as patched in a hub only when every pin of the
    /// patch that the hub's lane found passes: one requirements file of
    /// a hub on the pin and another whose pin fails is a hub that builds
    /// the upstream package on some platform. The proof of a pin holds
    /// every entry of the release in the hub to one digest, so no entry
    /// of a release that is left out here is on another digest than the
    /// pin's.
    pub fn contests<'g>(
        &self,
        grant_of: &dyn Fn(&BazelRef) -> Option<&'g Integrity>,
    ) -> Vec<Contest<'_>> {
        let same = |a: &BazelRef, b: &BazelRef| a.uuid == b.uuid && PurlKey::same(&a.purl, &b.purl);
        let mut out = Vec::new();
        for listed in &self.inventory.listed {
            let hub = listed.hub;
            let pins = self.pins_of(hub);
            let fails = |pin: &&&BazelRef| self.proof(hub, pin, grant_of(pin)).is_err();
            let failing: Vec<&BazelRef> = pins.iter().filter(fails).copied().collect();
            let patched = |pin: &&&BazelRef| !failing.iter().any(|failed| same(failed, pin));
            let patched = pins.iter().filter(patched).map(|pin| (*pin).clone());
            let patched: Vec<BazelRef> = patched.collect();
            let unpatched = self.inventory.unpatched(hub, &patched).unwrap_or_default();
            out.extend(unpatched.into_iter().map(|entry| Contest { hub, entry }));
        }
        out
    }

    /// The vendored claim (revision 4, section 3): the build of the pin
    /// needs no Socket API, because a `--distdir` row of the owned rc file
    /// provides the pinned bytes. The consumer proof never needs this;
    /// `vendor --check` does. The row names the artifact's directory, the
    /// artifact is there under the basename of the pin's URL (Bazel looks
    /// a distdir file up by that name, probe S11) with the pinned digest,
    /// the owned rc file and its hook stand, obligation 14 passes, and
    /// the downloader config leaves the URL allowed (a blocked URL skips
    /// the distdir).
    pub fn vendored_claim(
        &self,
        id: HubId,
        pin: &BazelRef,
        artifact: &VendoredArtifact<'_>,
    ) -> Result<(), VexWithhold> {
        let not = |detail: String| withheld(WithholdKind::NotConsumed, None, detail);
        let hub = self.ws.hubs.get(id.0);
        let hub = hub.ok_or_else(|| undetermined("the pin names a hub the model does not have"))?;
        let rows = Rows::of(self.index, pin);
        let provides = |row: &&RcFlagRow| row.flag == RcFlag::Distdir && row.value == artifact.dir;
        if !rows.rc.iter().any(provides) {
            return Err(not(format!(
                "no `--distdir` row of `{INDEX_PATH}` names `{}`, so nothing makes Bazel take \
                 the vendored artifact",
                artifact.dir
            )));
        }
        let path = format!("{}/{}", artifact.dir, artifact.leaf);
        if self.files.read(&path) == FileText::Absent || !artifact.digest_is_pinned {
            let detail =
                format!("`{path}` is missing or is not the artifact the pin's digest names");
            return Err(withheld(WithholdKind::DerivedStale, None, detail));
        }
        let url = artifact
            .pin_url
            .split(['?', '#'])
            .next()
            .unwrap_or_default();
        if url.rsplit('/').next() != Some(artifact.leaf) {
            return Err(not(format!(
                "`{path}` does not carry the file name of the pinned URL, and Bazel looks a \
                 distdir file up by that name"
            )));
        }
        self.owned_file(OWNED_RC_PATH)?;
        self.hooked(&[HookKind::Bazelrc], OWNED_RC_PATH)?;
        let rc: Vec<RcFlagRow> = rows.rc.iter().map(|row| (*row).clone()).collect();
        gate::rc_carriage(self.ws, &rc).map_err(of_refusal)?;
        let provider = |row: &RcFlagRow| PlannedWrite::Owned(OwnedWrite::RcFlag(row.clone()));
        let plan = Plan {
            uuid: pin.uuid.clone(),
            lane: pin.lane,
            writes: rc.iter().map(provider).collect(),
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: pin.basis,
            anchor: Anchor::Digest,
        };
        let url = Some(artifact.pin_url);
        gate::reachable(self.ws, self.files, Mode::Vendored, hub, &plan, url).map_err(of_refusal)
    }

    /// The common part of revision 4, section 3, which every pin that
    /// rests on a revision-4 class passes first. `Ok` at once for a pin
    /// with no selecting row, so a pin of a lock alone, with or without
    /// an rc provider beside it, is judged as it was in revision 3.
    ///
    /// In order: a row whose version key is not the version the hub's
    /// lock pins is stale, whatever else holds; the index file is the
    /// index held; every owned path the rows render into is ours or only
    /// reformatted; every hook the rows are reached through is present;
    /// and the rc rows beside them pass obligation 14.
    ///
    /// This is obligation 15 for one pin. The gate asks it of the whole
    /// root before a write, and in this build refuses every index that
    /// holds a revision-4 row; a statement rests only on the files its
    /// own rows name, so another pin's damaged file withholds nothing
    /// here.
    pub fn common(&self, id: HubId, pin: &BazelRef) -> Result<(), VexWithhold> {
        let rows = Rows::of(self.index, pin);
        if rows.selects_nothing() {
            return Ok(());
        }
        self.stale_override(id, pin, &rows)?;
        self.index_is_ours()?;
        for path in rows.owned_paths(self.index) {
            self.owned_file(path)?;
        }
        if !rows.segment.is_empty() {
            self.hooked(&[HookKind::ModuleFile], OWNED_SEGMENT_PATH)?;
        }
        if !rows.bzl.is_empty() {
            let either = [HookKind::ModuleFile, HookKind::WorkspaceFile];
            self.hooked(&either, OWNED_BZL_PATH)?;
        }
        let rc: Vec<RcFlagRow> = rows.rc.iter().map(|row| (*row).clone()).collect();
        gate::rc_carriage(self.ws, &rc).map_err(of_refusal)
    }

    /// The candidate with the parts of its purl. `Ok(None)` for a package
    /// of an ecosystem no ruleset builds: Bazel never governs it.
    ///
    /// The ecosystem is read from the canonical spelling of the purl. A
    /// hand-written manifest key with its type in another case is the
    /// same release to the caller and to every [`PurlKey`] comparison
    /// here, so it must not be waved through as an ecosystem Bazel does
    /// not build. A string that names no purl type at all is of no known
    /// ecosystem, and nothing is said about it.
    fn package<'c>(
        &self,
        candidate: &'c Candidate<'c>,
    ) -> Result<Option<Package<'c>>, VexWithhold> {
        let built = |ecosystem: &Ecosystem| {
            let builds = |ruleset: &Ruleset| ruleset.ecosystem() == Some(*ecosystem);
            Ruleset::ALL.iter().any(builds)
        };
        let purl = canonical_base_purl(candidate.purl);
        let typed = purl
            .strip_prefix("pkg:")
            .and_then(|rest| rest.split_once('/'));
        if !typed.is_some_and(|(kind, name)| !kind.is_empty() && !name.is_empty()) {
            let detail = format!(
                "`{}` is no package URL, so which ecosystem it is of is not known",
                candidate.purl
            );
            return Err(undetermined(detail));
        }
        if !Ecosystem::from_purl(&purl).is_some_and(|ecosystem| built(&ecosystem)) {
            return Ok(None);
        }
        let Some((ecosystem, name, version)) = release(candidate.purl) else {
            return Err(no_release(candidate.purl));
        };
        Ok(Some(Package {
            candidate,
            purl,
            ecosystem,
            name,
            version,
        }))
    }

    /// Obligations 1 and 3 as the gate asks them, over the same roots.
    fn governing(&self, package: &Package<'_>) -> Result<Governance, VexWithhold> {
        let cx = GateCx {
            roots: self.roots,
            ..GateCx::new(Mode::Hosted, self.ws, self.files, self.index)
        };
        gate::governing(&cx, &package.request()).map_err(of_refusal)
    }

    /// The agent-basis rule (design 7, row 1), for every basis: in a
    /// project no hub governs, a statement stands as it does today unless
    /// a hub lock anywhere under the root resolves the release without a
    /// pin that passes, or a lock of the ecosystem could not be listed.
    /// A `service-a/pom.xml` beside a root `maven_install.json` therefore
    /// does not attest on the strength of `~/.m2`.
    fn not_governed(&self, package: &Package<'_>) -> Result<Consumed, VexWithhold> {
        if let Basis::Pin(pin) = package.candidate.basis {
            let detail = format!(
                "no hub that Bazel evaluates reads `{}` for this project, so the pin in it is a \
                 mention and not wiring",
                pin.file
            );
            return Err(withheld(WithholdKind::NotConsumed, None, detail));
        }
        self.other_roots(package)?;
        self.every_consumer(package, &[])?;
        Ok(Consumed::AsToday)
    }

    /// Nested roots each build the project, and this inventory is of one
    /// of them. A hub of the ecosystem under another root, or a root that
    /// could not be read, leaves what Bazel builds from unknown. Roots are
    /// told apart by where the project sits under each, which the probe
    /// spells one way: two spellings of one directory are one root.
    fn other_roots(&self, package: &Package<'_>) -> Result<(), VexWithhold> {
        let Roots::Probed {
            probe: Probe::Nested(_),
            read,
        } = self.roots
        else {
            return Ok(());
        };
        let builds = |hub: &Hub| hub.ecosystem == package.ecosystem && may_build(hub);
        let open = |root: &Result<BazelWorkspace, super::model::Gap>| match root {
            Ok(ws) => ws.root.project_rel != self.ws.root.project_rel && ws.hubs.iter().any(builds),
            Err(_) => true,
        };
        if !read.iter().any(open) {
            return Ok(());
        }
        let detail = "several Bazel roots lie between the project and the repository root, and \
                      the locks another of them builds this ecosystem from were not listed";
        Err(withheld(
            WithholdKind::ConsumerUndetermined,
            Some(NESTED_BAZEL_ROOTS),
            detail,
        ))
    }

    /// The verdict of a governed project (design 7, column `Governed`):
    /// the candidate counts only through a pin a lane discovered, of the
    /// mode its basis names and in the file it was read from. Every pin
    /// of the patch that the lane of a governing hub found must then
    /// pass its proof, in whatever file: a hub that reads several lock
    /// files builds the release from each of them on some platform.
    fn governed(&self, package: &Package<'_>, hubs: &[HubId]) -> Result<Consumed, VexWithhold> {
        let mode = |id: HubId, pin: &BazelRef| {
            let ruleset = self.ws.hubs.get(id.0).map(|hub| hub.ruleset);
            let family = ruleset.and_then(|ruleset| lanes::family(self.lanes, ruleset));
            let specs = family.map_or(&[][..], |ops| ops.lanes);
            let spec = specs.iter().find(|spec| spec.id == pin.lane);
            spec.map(|spec| spec.mode)
        };
        let wanted = |id: HubId, pin: &BazelRef| match package.candidate.basis {
            // Only an agent lane makes Bazel build from a patched tree
            // (the Go directory replace, `A-GO1`).
            Basis::Installed => mode(id, pin) == Some(Mode::Agent),
            Basis::Hosted { file } => mode(id, pin) == Some(Mode::Hosted) && pin.file == file,
            Basis::Vendored { file } => mode(id, pin) == Some(Mode::Vendored) && pin.file == file,
            Basis::Pin(asked) => pin == asked,
        };
        let wanted_in = |id: &HubId| {
            let mut pins = self.pins_in(*id, package).into_iter();
            pins.find(|pin| wanted(*id, pin)).map(|pin| (*id, pin))
        };
        let Some((first_hub, first)) = hubs.iter().find_map(wanted_in) else {
            return Err(self.no_pin(package));
        };
        // A hub of the ecosystem that cannot tell its pins may build the
        // release from a lock nobody vouches for.
        if let Some(HubId(unknown)) = self.discovered.unknown_for(package.ecosystem) {
            let named = self.ws.hubs.get(unknown);
            let named = named.map_or("", |hub| hub.decl.apparent_name.as_str());
            return Err(undetermined(format!(
                "the pins of the hub `{named}` are not known, so whether every lock that builds \
                 this ecosystem holds the pin is not known"
            )));
        }
        let grant = package.candidate.grant;
        // The candidate's own pin first, so that a withheld statement
        // names what is wrong with it before what is wrong beside it.
        let spec = self.proof(first_hub, first, grant)?;
        let mut proven: Vec<HubId> = Vec::new();
        for id in hubs {
            let pins = self.pins_in(*id, package);
            if !pins.is_empty() {
                proven.push(*id);
            }
            let others = pins.into_iter();
            for pin in others.filter(|pin| !(*id == first_hub && std::ptr::eq(*pin, first))) {
                self.proof(*id, pin, grant)?;
            }
        }
        self.every_consumer(package, &proven)?;
        Ok(Consumed::ByBazel {
            lane: spec.id,
            mode: spec.mode,
            basis: first.basis,
        })
    }

    /// Why a governed candidate has no pin to count through.
    fn no_pin(&self, package: &Package<'_>) -> VexWithhold {
        let not = |detail: String| withheld(WithholdKind::NotConsumed, None, detail);
        let file = match package.candidate.basis {
            Basis::Installed => {
                return not(format!(
                    "the patch of `{}` is in an installed tree, and Bazel builds this ecosystem \
                     from the lock its ruleset reads; pin it there with `socket-patch scan --mode \
                     hosted`",
                    package.candidate.purl
                ));
            }
            Basis::Pin(pin) => {
                return not(format!(
                    "no lane finds this pin in a lock that a hub of this project reads (`{}`): \
                     it was erased, or the file is a mention and not wiring",
                    pin.file
                ));
            }
            Basis::Hosted { file } | Basis::Vendored { file } => file,
        };
        // A file a hub reads is a lock it names, or a file its lane
        // finds pins in: a hub of `go_repository` rules names no lock.
        let mut building = self.ws.hubs.iter().enumerate();
        let read = |(id, hub): (usize, &Hub)| {
            let carries = |pin: &BazelRef| pin.file == file;
            may_build(hub) && (reads(hub, file) || self.discovered.pins_of(HubId(id)).any(carries))
        };
        if building.any(read) {
            return undetermined(format!(
                "no enabled lane proves that the Bazel build consumes the pin in `{file}`"
            ));
        }
        not(format!(
            "`{file}` is a file no hub reads, so a reference in it does not reach the Bazel build"
        ))
    }

    /// Every hub lock under the root that resolves the release holds a
    /// pin of this patch that passes its proof, and no lock of the
    /// ecosystem is unlisted: the two conditions are independent (ROUTED
    /// R-114), so a lock that could not be listed withholds also where
    /// every listed one is pinned. `proven` are the hubs whose pin was
    /// just proven.
    fn every_consumer(&self, package: &Package<'_>, proven: &[HubId]) -> Result<(), VexWithhold> {
        let hubs = match self.inventory.resolves(&package.purl) {
            Resolved::No => return Ok(()),
            Resolved::CannotEnumerate(unlisted)
            | Resolved::By {
                unlisted: Some(unlisted),
                ..
            } => return Err(unlisted_lock(unlisted)),
            Resolved::By {
                hubs,
                unlisted: None,
            } => hubs,
        };
        for id in hubs.into_iter().filter(|id| !proven.contains(id)) {
            let pins = self.pins_in(id, package);
            if pins.is_empty() {
                let hub = self.ws.hubs.get(id.0);
                let (ruleset, name) = hub.map_or(("", ""), |hub| {
                    (hub.ruleset.name(), hub.decl.apparent_name.as_str())
                });
                let detail = format!(
                    "the {ruleset} hub `{name}` resolves `{}` from its lock, which holds no pin \
                     of this patch, so Bazel builds that copy unpatched",
                    package.candidate.purl
                );
                return Err(withheld(WithholdKind::NotConsumed, None, detail));
            }
            for pin in pins {
                self.proof(id, pin, package.candidate.grant)?;
            }
        }
        Ok(())
    }

    /// The pins the lane of the hub `id` found for it, whatever file
    /// carries each (discovery keeps the hub with the pin: a hub of
    /// `go_repository` rules names no lock, and its pins are in a
    /// `go.mod`), and only those of a lane of the hub's family.
    fn pins_of(&self, id: HubId) -> Vec<&BazelRef> {
        let Some(hub) = self.ws.hubs.get(id.0) else {
            return Vec::new();
        };
        let lanes = lanes::family(self.lanes, hub.ruleset).map_or(&[][..], |ops| ops.lanes);
        let own = |pin: &&BazelRef| lanes.iter().any(|spec| spec.id == pin.lane);
        self.discovered.pins_of(id).filter(own).collect()
    }

    /// [`Self::pins_of`] for the release and the patch of `package`.
    fn pins_in(&self, id: HubId, package: &Package<'_>) -> Vec<&BazelRef> {
        let uuid = package.candidate.uuid;
        let mut pins = self.pins_of(id);
        pins.retain(|pin| pin.uuid == uuid && PurlKey::same(&pin.purl, &package.purl));
        pins
    }

    /// The enabled lane that wrote `pin` for `hub`, inside its claims.
    fn lane_of(
        &self,
        hub: &Hub,
        pin: &BazelRef,
    ) -> Result<(&'static LaneOps, &'static LaneSpec), VexWithhold> {
        let lane = pin.lane.0;
        let ops = lanes::family(self.lanes, hub.ruleset);
        let spec = ops.and_then(|ops| ops.lanes.iter().find(|spec| spec.id == pin.lane));
        let (Some(ops), Some(spec)) = (ops, spec) else {
            return Err(undetermined(format!(
                "lane {lane} is no lane of {}, so nothing proves the pin",
                hub.ruleset.name()
            )));
        };
        let serving = lanes::serving(self.lanes, hub.ruleset, hub.shape, spec.mode);
        if !spec.enabled || !serving.iter().any(|served| served.id == spec.id) {
            return Err(undetermined(format!(
                "lane {lane} is not enabled for this hub in this release, so no proof says the \
                 Bazel build consumes the pin"
            )));
        }
        if !lanes::claims_admit(spec, &self.ws.line, &self.ws.system) {
            return Err(undetermined(format!(
                "lane {lane} is not proven on Bazel {} under the dependency system of this \
                 workspace",
                self.ws.line
            )));
        }
        Ok((ops, spec))
    }

    /// Everything one hub's pin is held to now: the evidence its basis
    /// and its lane's anchor require, with the owned state its rows rest
    /// on; what the gate asked before the write (literal labels, no
    /// bypass and no user patch hook after the own-wiring subtraction);
    /// the lane's own proof; a fresh record of the pin's file in
    /// `MODULE.bazel.lock`; and the pinned digest. `Ok` is the lane the
    /// pin passed through.
    ///
    /// The evidence is asked first. A pin only an rc flag selects is
    /// reported as that, and not as the bypass its own
    /// `--override_repository` line reads as while no reader can tell
    /// that line from one of the user's.
    fn proof(
        &self,
        id: HubId,
        pin: &BazelRef,
        grant: Option<&Integrity>,
    ) -> Result<&'static LaneSpec, VexWithhold> {
        let Some(hub) = self.ws.hubs.get(id.0) else {
            return Err(undetermined("the pin names a hub the model does not have"));
        };
        let (ops, spec) = self.lane_of(hub, pin)?;
        self.evidence(id, pin, spec)?;
        gate::literal(hub).map_err(of_refusal)?;
        let cx = LaneCx {
            mode: spec.mode,
            files: self.files,
            ws: self.ws,
            hub: id,
            index: self.index,
            run: RunPolicy::Never,
        };
        no_bypass(&cx, pin, spec.id, &[])?;
        self.user_patch_hook(id, pin)?;
        self.go_host_cache(hub, pin)?;
        (ops.attest)(&cx, pin)?;
        // Whatever the lane, a record of the pin's file in the lock Bazel
        // wrote must be of the file as it is now, under every platform
        // key: until then the one command has not run (works-after).
        // This call names no extension and no pin, so it never sees a
        // forged entry: the lane's `attest` makes the call that does.
        works_after(self.ws, self.files, &[pin.file.as_str()], &[], None, None)?;
        self.pinned_digest(id, pin, spec.mode, grant)?;
        Ok(spec)
    }

    /// The digest the build enforces for the release is the patch's (the
    /// module docs, "The pinned digest"). It is compared here and not by
    /// the lane, whose `attest` is handed no grant.
    ///
    /// Every entry of the release in the hub's listing counts, in every
    /// lock file the hub reads, and not the first one alone: a second
    /// entry on the upstream digest, or on none, is a build of the
    /// upstream package.
    ///
    /// Public for the hosted rewriter group, which holds a pin it has
    /// just written to the grant before it calls the patch confirmed: the
    /// rest of the proof of a pin can say "run pending" first, and a lock
    /// line with the Socket URL and the upstream digest must not pass as
    /// a write that only waits for its command.
    pub fn pinned_digest(
        &self,
        id: HubId,
        pin: &BazelRef,
        mode: Mode,
        grant: Option<&Integrity>,
    ) -> Result<(), VexWithhold> {
        self.pinned_digest_of(id, pin, mode, grant.as_slice())
    }

    /// [`Self::pinned_digest`] for a patch that is granted as several
    /// artifacts: every digest the hub's locks list for the release is
    /// the digest of one of `grants` ([`digest_of_grants`]). An entry that
    /// lists a wheel's digest and an sdist's is held to both artifacts of
    /// the patch, where one grant alone would refuse it. No grant is the
    /// `None` of [`Self::pinned_digest`].
    pub fn pinned_digest_of(
        &self,
        id: HubId,
        pin: &BazelRef,
        mode: Mode,
        grants: &[&Integrity],
    ) -> Result<(), VexWithhold> {
        let listed = self.inventory.listed.iter().filter(|of| of.hub == id);
        let entries = listed.flat_map(|of| &of.entries);
        let entries: Vec<&LockfileEntry> = entries
            .filter(|entry| PurlKey::same(&entry.purl, &pin.purl))
            .collect();
        let mut digests = entries.iter().map(|entry| digest_key(&entry.integrity));
        if let Some(first) = digests.next() {
            if digests.any(|other| other != first) {
                let detail = format!(
                    "the locks of the hub do not all pin `{}` under one digest, so one of them \
                     builds another package than the patched one; run `socket-patch scan` to \
                     pin every one of them",
                    pin.purl
                );
                return Err(withheld(WithholdKind::DerivedStale, None, detail));
            }
        }
        let hosted = mode == Mode::Hosted;
        let granted = (!grants.is_empty()).then_some(grants);
        match granted {
            Some(_) if hosted && entries.is_empty() => {
                let detail = format!(
                    "the listing of the hub's lock holds no entry of `{}`, so no digest the \
                     build enforces can be held to the digest of the patch",
                    pin.purl
                );
                Err(withheld(WithholdKind::IntegrityUnanchored, None, detail))
            }
            // A vendored or an agent pin rests on the artifact or the
            // tree, which the caller hashes: a digest its lock holds is
            // compared, and none is asked for.
            Some(grants) => entries
                .iter()
                .map(|entry| &entry.integrity)
                .filter(|digest| hosted || **digest != LockIntegrity::None)
                .try_for_each(|digest| digest_of_grants(digest, grants)),
            None if hosted && !self.recorded(pin) => Err(undetermined(format!(
                "no committed file records the digest the pin in `{}` was written with, and \
                 this run holds no grant of the patch to compare the locked digest with, so \
                 whether the lock still pins the patched package is not known",
                pin.file
            ))),
            None => Ok(()),
        }
    }

    /// Whether committed state records the digest `pin` was written with:
    /// a `pins` row of the owned index for its patch, lane and file. The
    /// lane's `attest` holds the lock to that row, which is what lets a
    /// run with no grant speak for the pin.
    fn recorded(&self, pin: &BazelRef) -> bool {
        let own = |row: &IndexRow| {
            (&row.uuid, &row.file, row.lane.as_str()) == (&pin.uuid, &pin.file, pin.lane.0)
                && PurlKey::same(&row.purl, &pin.purl)
        };
        self.index.pins.iter().any(own)
    }

    /// A pin beside the user's own patch of the package, on a hub whose
    /// hook runs the host `patch` tool: the gate allows that write under
    /// `--allow-patch-conflicts`, and the hook can then reverse the fix
    /// over the patched tarball with exit 0 (probe P4). Withheld while
    /// the user's entry exists. What socket-patch wrote itself is
    /// subtracted first, by the filter the gate uses.
    fn user_patch_hook(&self, id: HubId, pin: &BazelRef) -> Result<(), VexWithhold> {
        let Some((ecosystem, name, version)) = release(&pin.purl) else {
            return Err(no_release(&pin.purl));
        };
        let own = |site: &Site, _: Option<&str>| exec::own_site(self.index, site);
        let hooks = consent::user_patch_hooks(self.ws, &own, ecosystem, &name, &version);
        let Some(hook) = hooks.iter().find(|hook| hook.hub.is_none_or(|of| of == id)) else {
            return Ok(());
        };
        let detail = format!(
            "`{}` declares a patch of your own that covers `{name}`, on a hub that applies it \
             with the host `patch` tool, which can reverse the fix; remove your patch of the \
             package",
            hook.file
        );
        Err(withheld(
            WithholdKind::PinBypassed,
            Some(USER_PATCH_HOOK),
            detail,
        ))
    }

    /// A hosted Go pin while a tracked `--repo_env` turns a host cache of
    /// `go_repository` on: the module is then built from the host module
    /// cache, where no sum check catches an edited copy (probe G6), so no
    /// digest the build enforces anchors the pin. gazelle turns the
    /// switch on for the value `1` alone (`go_repository_cache.bzl`,
    /// `env.bzl`; read at v0.24.0 to v2.0.0-beta.2); a variable the
    /// client environment decides may be `1`.
    fn go_host_cache(&self, hub: &Hub, pin: &BazelRef) -> Result<(), VexWithhold> {
        if hub.ruleset != Ruleset::Gazelle || pin.basis == AttestBasis::LockPath {
            return Ok(());
        }
        let on = |value: &RepoEnv| match value {
            RepoEnv::Value(value) => value == "1",
            RepoEnv::Inherit => true,
            RepoEnv::Unset => false,
        };
        let switches = GO_REPO_ENV
            .iter()
            .filter(|name| name.contains("_USE_HOST_"));
        for name in switches {
            let set = |chain: &Chain| {
                self.ws
                    .flags
                    .repo_env(name, *chain)
                    .values()
                    .into_iter()
                    .any(on)
            };
            if Chain::COMMANDS.iter().any(set) {
                let detail = format!(
                    "a tracked rc file sets or may set `--repo_env={name}`, so `go_repository` \
                     builds from the host module cache, where no digest is checked; remove it"
                );
                return Err(withheld(WithholdKind::IntegrityUnanchored, None, detail));
            }
        }
        Ok(())
    }

    /// The evidence a pin's basis and its lane's anchor require (revision
    /// 4, section 3). The one place that matches on either. Every basis
    /// that can rest on a revision-4 class passes [`Self::common`] first.
    fn evidence(&self, id: HubId, pin: &BazelRef, spec: &LaneSpec) -> Result<(), VexWithhold> {
        use AttestBasis::{BazelLock, Declared, GoRule, LockPath, LockUrl, OwnedPin, Withheld};
        let lane = spec.id.0;
        let rows = Rows::of(self.index, pin);
        match (pin.basis, spec.anchor) {
            // A build that ignores the rc file (`--ignore_all_rc_files`,
            // a `--bazelrc` of its own) takes the upstream package with
            // no message (owner decision O18).
            (_, Anchor::RcSelector) => {
                let detail = format!(
                    "only an rc flag selects the patched package for lane {lane}, and a build \
                     that ignores the rc file takes the upstream one with no message"
                );
                Err(withheld(
                    WithholdKind::IntegrityUnanchored,
                    Some(RC_SELECTED),
                    detail,
                ))
            }
            (Withheld, _) => {
                let detail =
                    format!("no digest that the build enforces anchors the pin of lane {lane}");
                Err(withheld(WithholdKind::IntegrityUnanchored, None, detail))
            }
            // A pin in a lock the hub reads, anchored by the digest
            // there: the lane's own proof carries it. An rc `--distdir`
            // row adds nothing to it and its absence takes nothing away:
            // without the rc file the build fetches the same pinned bytes
            // or fails.
            (LockUrl | LockPath | BazelLock | GoRule, Anchor::Digest) => self.common(id, pin),
            (OwnedPin, _) => {
                self.common(id, pin)?;
                self.owned_pin(&rows, lane)
            }
            // A lock pin whose lane says a statement selects the bytes
            // is held to that statement too.
            (Declared, _) | (LockUrl | LockPath | BazelLock | GoRule, Anchor::Declaration) => {
                self.common(id, pin)?;
                self.declared(&rows, lane)
            }
        }
    }

    /// A pin a statement selects: a segment row, a tag edit, or the owned
    /// `.bzl` file a WORKSPACE hook loads. One of them must be on record.
    /// What the evidence table then asks (the module model complete for
    /// the extension, one override of the repository, the bytes behind
    /// its target, the statement of a tag edit, the governing WORKSPACE
    /// definition) needs the readers that land with those classes, so the
    /// statement is withheld.
    fn declared(&self, rows: &Rows<'_>, lane: &str) -> Result<(), VexWithhold> {
        if rows.segment.is_empty() && rows.tag_edits.is_empty() && rows.bzl.is_empty() {
            let detail = format!(
                "no row of `{INDEX_PATH}` records a statement that selects the patched package \
                 for lane {lane}"
            );
            return Err(withheld(WithholdKind::NotConsumed, None, detail));
        }
        Err(undetermined(format!(
            "a statement selects the patched package for lane {lane}, and this release cannot \
             prove the bytes that statement leads to"
        )))
    }

    /// A pin in owned pin data that an owned rule reads. The data file
    /// and the rule that reads it must be on record; the format of the
    /// data and the template that passes its digest to a checked download
    /// land with the first lane that writes one, so the statement is
    /// withheld.
    fn owned_pin(&self, rows: &Rows<'_>, lane: &str) -> Result<(), VexWithhold> {
        if rows.files.is_empty() || rows.bzl.is_empty() {
            let detail = format!(
                "`{INDEX_PATH}` records no pin data, or no owned rule that reads it, for lane \
                 {lane}"
            );
            return Err(withheld(WithholdKind::NotConsumed, None, detail));
        }
        Err(undetermined(format!(
            "an owned rule reads the pin of lane {lane}, and this release cannot prove that the \
             rule passes its digest to a checked download"
        )))
    }

    /// A tag edit is keyed by the version it was written for, so that it
    /// selects nothing once the lock pins another (revision 4, 2.7). Its
    /// key must be for the version of the pin's own release
    /// ([`keyed_for`]), and that version must still be one the hub's
    /// lock lists for the package: a key for another version the lock
    /// lists is the wiring of another release, and a key for a version
    /// the lock lists no more is for one the build no longer uses. Where
    /// the lock lists no version of the package at all (the pin renamed
    /// its own entry), the pin's version alone decides.
    fn stale_override(
        &self,
        id: HubId,
        pin: &BazelRef,
        rows: &Rows<'_>,
    ) -> Result<(), VexWithhold> {
        let package = package_key(&pin.purl);
        let listed = self.inventory.listed.iter().filter(|of| of.hub == id);
        let entries = listed.flat_map(|of| &of.entries);
        let same =
            |entry: &&LockfileEntry| package.is_some() && package_key(&entry.purl) == package;
        let locked: Vec<&str> = entries.filter(same).map(|e| e.version.as_str()).collect();
        let pinned = purl_parts(&pin.purl).map(|(_, _, version)| version);
        let pinned = pinned.unwrap_or_default();
        let current = locked.is_empty() || locked.contains(&pinned.as_str());
        for row in &rows.tag_edits {
            let Some(key) = row.edit.version_key.as_deref() else {
                continue;
            };
            if !current || !keyed_for(key, &pinned) {
                let now = match locked.is_empty() {
                    true => pinned.clone(),
                    false => locked.join("`, `"),
                };
                let detail = format!(
                    "the edit of `{}` in `{}` is for `{key}`, the pin is of `{pinned}` and the \
                     lock now pins `{now}`; run `socket-patch scan`",
                    row.edit.attr, row.edit.file
                );
                return Err(withheld(
                    WithholdKind::DerivedStale,
                    Some(STALE_OVERRIDE),
                    detail,
                ));
            }
        }
        Ok(())
    }

    /// The index file is the index this verdict reads rows from.
    fn index_is_ours(&self) -> Result<(), VexWithhold> {
        let stale =
            |token, detail: String| withheld(WithholdKind::DerivedStale, Some(token), detail);
        let modified = |what: &str| {
            let detail = format!(
                "`{INDEX_PATH}` {what}; restore it from version control, or run `socket-patch \
                 repair`"
            );
            stale(OWNED_FILE_MODIFIED, detail)
        };
        let bytes = match self.files.read(INDEX_PATH) {
            FileText::Bytes(bytes) => bytes,
            FileText::Unreadable => return Err(modified("exists and cannot be read")),
            FileText::Absent => {
                let detail = format!("`{INDEX_PATH}` is gone while rows of it wire this patch");
                return Err(stale(OWNED_FILE_MISSING, detail));
            }
        };
        // Row for row: an edited target or digest is still an index that
        // parses, and it is not the one these rows were read from.
        let canonical = |index: &Index| {
            let lf = Index {
                crlf: false,
                ..index.clone()
            };
            lf.render().ok()
        };
        match owned_index::parse(&bytes) {
            Parsed::Ours(found) if canonical(&found) == canonical(self.index) => Ok(()),
            Parsed::Ours(_) => Err(modified("does not hold the rows this run read")),
            _ => Err(modified("is not the index socket-patch wrote")),
        }
    }

    /// The owned file at `path` is what its rows render, or only
    /// reformatted.
    fn owned_file(&self, path: &str) -> Result<(), VexWithhold> {
        let repair = "restore it from version control, or run `socket-patch repair`";
        let (token, what) = match self.owned.file(path) {
            OwnedFile::Ours | OwnedFile::Reformatted => return Ok(()),
            OwnedFile::Modified | OwnedFile::Foreign => {
                (OWNED_FILE_MODIFIED, "is not what the index renders")
            }
            OwnedFile::Missing => (OWNED_FILE_MISSING, "is gone while the index records it"),
            OwnedFile::Unchecked => {
                return Err(undetermined(format!(
                    "this release cannot check `{path}` against the rows of `{INDEX_PATH}`, so \
                     no statement rests on it"
                )));
            }
        };
        let detail = format!("`{path}` {what}; {repair}");
        Err(withheld(WithholdKind::DerivedStale, Some(token), detail))
    }

    /// A hook of one of `kinds` is on record and its unit stands, so
    /// Bazel reads the owned file at `path`.
    fn hooked(&self, kinds: &[HookKind], path: &str) -> Result<(), VexWithhold> {
        let missing =
            |detail: String| withheld(WithholdKind::NotConsumed, Some(HOOK_MISSING), detail);
        let rows = self.index.hooks.iter();
        let rows: Vec<&HookRow> = rows.filter(|row| kinds.contains(&row.kind)).collect();
        if rows.is_empty() {
            return Err(missing(format!(
                "no hook row of `{INDEX_PATH}` records the unit that makes Bazel read `{path}`; \
                 run `socket-patch repair`"
            )));
        }
        for row in rows {
            match self.owned.hook(row) {
                HookUnit::Present => {}
                HookUnit::Unchecked => {
                    return Err(undetermined(format!(
                        "this release cannot check the unit in `{}` that makes Bazel read \
                         `{path}`, so no statement rests on it",
                        row.file
                    )));
                }
                HookUnit::Absent | HookUnit::Damaged | HookUnit::Duplicated => {
                    return Err(missing(format!(
                        "the unit that makes Bazel read `{path}` is no longer in `{}` as \
                         socket-patch wrote it; run `socket-patch repair`",
                        row.file
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;
    use crate::bazel::codes::Code;
    use crate::bazel::derived::{stale, DerivedState, Edit, FactsEdit, FactsOf, Write};
    use crate::bazel::govern::tests::{read, read_at, JS_MODULE};
    use crate::bazel::model::{
        Actor, CellClaim, ClaimSystem, Gap, HubShape, IndexRow, LockRole, StmtRef, TagEdit, TagOp,
        TextRead,
    };
    use crate::bazel::owned_index::{HookAt, IndexEdit, RunOutput, RunRow, SegmentKind, HOOK_UNIT};
    use crate::bazel::rc::testing::Files;
    use crate::utils::digest::sha256_hex_of;
    use crate::vendor::lock_inventory::SourceKind;
    use WithholdKind::{
        ConsumerUndetermined, DerivedStale, IntegrityUnanchored, NotConsumed, PinBypassed,
        RunPending,
    };

    const NINE: (&str, &str) = (".bazelversion", "9.3.2\n");
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID_B: &str = "3c1d5e7f-2b4a-4c6d-9e8f-0a1b2c3d4e5f";
    const GSON: &str = "pkg:maven/com.google.code.gson/gson@2.10.1";
    const GUAVA: &str = "pkg:maven/com.google.guava/guava@32.0.1-jre";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
    const COMPOSER: &str = "pkg:composer/a/b@1.0.0";
    const LOCK: &str = "maven_install.json";
    const PNPM: &str = "pnpm-lock.yaml";
    const MAVEN: &str = "bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
        maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
        maven.install(name = \"maven\", lock_file = \"//:maven_install.json\")\n\
        use_repo(maven, \"maven\")\n";

    macro_rules! fixture {
        ($rel:literal) => {
            include_str!(concat!("../../tests/fixtures/bazel/module_lock/", $rel))
        };
    }

    fn upstream() -> String {
        "1".repeat(64)
    }

    fn patched() -> String {
        "2".repeat(64)
    }

    // ── Toy lanes ────────────────────────────────────────────────────

    /// One package line of the toy lock.
    struct Line<'a> {
        purl: &'a str,
        /// `-`: the lock holds no digest for the package. `?`: the lane's
        /// listing leaves the line out.
        digest: &'a str,
        /// The line carries the Socket URL of the patch: what a lane of
        /// a native lock finds a pin by, with no row in the index.
        socket: bool,
        /// Something only the lane can see is wrong with the line.
        broken: bool,
    }

    /// The toy lock: one `<purl> <sha256> [socket] [broken]` per line.
    /// `// ` may stand in front of one, so that a `go.mod` can carry it.
    /// A `# ` line says what only a lane knows: `# spoke <name>` names a
    /// repository beside the hub's own that serves a package, `# ext
    /// <label> <name> <pin>` the extension that generates the hub's
    /// repositories and the pin as its specs render it, `# floor
    /// <version>` the ruleset release the lane's gate asked for, and
    /// `# opaque` makes the lane unable to tell its pins.
    fn locked(text: &str) -> Vec<Line<'_>> {
        fn line(line: &str) -> Option<Line<'_>> {
            let mut words = line.split(' ');
            let (purl, digest) = (words.next()?, words.next()?);
            let flags: Vec<&str> = words.collect();
            Some(Line {
                purl,
                digest,
                socket: flags.contains(&"socket"),
                broken: flags.contains(&"broken"),
            })
        }
        let lines = text.lines().map(|l| l.strip_prefix("// ").unwrap_or(l));
        let pins = lines.filter(|line| line.starts_with("pkg:"));
        pins.filter_map(line).collect()
    }

    fn directive<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
        let lines = text.lines().filter_map(|line| line.strip_prefix("# "));
        let named = lines.filter_map(|line| line.strip_prefix(name));
        named.map(str::trim).collect()
    }

    /// The files a toy lane reads for its hub: the hub's package locks,
    /// or, for a hub that names no lock at all (the `go_repository`
    /// rules of a `WORKSPACE`), the `go.mod` of the project. `None` when
    /// there is none to read.
    fn lock_paths(cx: &LaneCx<'_>) -> Option<Vec<String>> {
        let hub = cx.ws.hubs.get(cx.hub.0)?;
        if hub.locks.is_empty() {
            let go_mod = match cx.ws.root.project_rel.as_str() {
                "" => "go.mod".to_string(),
                project => format!("{project}/go.mod"),
            };
            return Some(vec![go_mod]);
        }
        let locks = hub.locks.iter();
        let locks = locks.filter(|lock| lock.role == LockRole::PackageLock);
        let paths: Vec<String> = locks.filter_map(|lock| lock.path.clone()).collect();
        Some(paths).filter(|paths| !paths.is_empty())
    }

    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let mut entries = Vec::new();
        for lock in lock_paths(cx)? {
            let text = read(&lock)?;
            for line in locked(&text).iter().filter(|line| line.digest != "?") {
                let (_, name, version) = purl_parts(line.purl)?;
                let integrity = match line.digest {
                    "-" => LockIntegrity::None,
                    digest => LockIntegrity::Sha256Hex(digest.to_string()),
                };
                entries.push(LockfileEntry {
                    ecosystem: Ecosystem::from_purl(line.purl)?.cli_name(),
                    name,
                    version,
                    purl: line.purl.to_string(),
                    resolved: None,
                    integrity,
                    source_kind: SourceKind::Unspecified,
                    pnpm_env: false,
                });
            }
        }
        Some(entries)
    }

    /// Every lane ID of the toy families, so that the lane a row names
    /// can be a [`LaneId`]. The first letter of an ID is its mode.
    const IDS: &[&str] = &[
        "H-TOY1", "V-TOY1", "A-TOY1", "H-DECL", "H-OWNED", "H-RCSEL", "H-WHELD", "H-DLOCK",
        "H-NET2", "H-OFF", "H-NAT1",
    ];

    fn mode_of(lane: &str) -> Mode {
        match lane.as_bytes().first() {
            Some(b'H') => Mode::Hosted,
            Some(b'V') => Mode::Vendored,
            _ => Mode::Agent,
        }
    }

    fn basis_of(lane: &str) -> AttestBasis {
        match lane {
            "H-DECL" => AttestBasis::Declared,
            "H-OWNED" => AttestBasis::OwnedPin,
            "H-RCSEL" | "H-WHELD" => AttestBasis::Withheld,
            lane if lane.starts_with("H-") => AttestBasis::LockUrl,
            _ => AttestBasis::LockPath,
        }
    }

    /// Whether the lock holds the digest `row` recorded for its package.
    fn holds(text: &str, row: &IndexRow) -> bool {
        let new = row.edits.first().map(|edit| edit.new.as_str());
        let pinned = |line: &Line<'_>| line.purl == row.purl && Some(line.digest) == new;
        locked(text).iter().any(pinned)
    }

    /// The pins of a lane that records its pins: a `pins` row of a lane
    /// of the asked mode whose digest a lock of the hub still holds. The
    /// lane a row names is taken as it stands, whatever family the hub
    /// is served by.
    fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let mut pins = Vec::new();
        for lock in lock_paths(cx)? {
            let text = read(&lock)?;
            if !directive(&text, "opaque").is_empty() {
                return None;
            }
            let rows = cx.index.pins.iter();
            for row in rows.filter(|row| row.file == lock && holds(&text, row)) {
                let lane = IDS.iter().find(|id| **id == row.lane);
                if let Some(lane) = lane.filter(|lane| mode_of(lane) == cx.mode) {
                    pins.push(pin_of(&row.purl, &row.uuid, lane, &lock));
                }
            }
        }
        Some(pins)
    }

    /// What every toy lane's `attest` does beside its own comparison, as
    /// a real lane's must: no bypass of a repository the lock names as
    /// serving the package, the works-after evidence over the extension
    /// and the pin the lock names, and the ruleset floor.
    fn lane_duties(cx: &LaneCx<'_>, pin: &BazelRef, text: &str) -> Result<(), VexWithhold> {
        no_bypass(cx, pin, pin.lane, &directive(text, "spoke"))?;
        for ext in directive(text, "ext") {
            let words: Vec<&str> = ext.split(' ').collect();
            let [label, name, rendered] = words[..] else {
                panic!("`# ext <label> <name> <pin>`: {ext}");
            };
            let ext = [ExtRef::new(label, name).expect("an extension label")];
            let inputs = [pin.file.as_str()];
            works_after(cx.ws, cx.files, &inputs, &ext, Some(rendered), None)?;
        }
        for floor in directive(text, "floor") {
            version_gate(cx, floor, "a later toy ruleset")?;
        }
        Ok(())
    }

    /// The toy consumer proof of a recorded pin: the lock holds the
    /// digest the row recorded, and the lane's duties.
    fn toy_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
        let text = cx.files.read(&pin.file);
        let text = text.as_str().unwrap_or_default();
        let own =
            |r: &&IndexRow| (&r.uuid, &r.file, &r.lane[..]) == (&pin.uuid, &pin.file, pin.lane.0);
        if !cx
            .index
            .pins
            .iter()
            .find(own)
            .is_some_and(|row| holds(text, row))
        {
            let detail = "the pinned digest is not the one the row records";
            return Err(withheld(DerivedStale, None, detail));
        }
        lane_duties(cx, pin, text)
    }

    /// The pins of a lane of a native lock, as `H-JS1` and `H-PY1` are
    /// designed: a line that carries the Socket URL, in any lock file of
    /// the hub. No row of the index records one.
    fn native_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let mut pins = Vec::new();
        for lock in lock_paths(cx)? {
            let text = read(&lock)?;
            let lines = locked(&text);
            let found = lines.iter().filter(|line| line.socket);
            let found = found.filter(|_| cx.mode == Mode::Hosted);
            pins.extend(found.map(|line| pin_of(line.purl, UUID, "H-NAT1", &lock)));
        }
        Some(pins)
    }

    /// All that a lane of a native lock can hold its pin to: it is
    /// handed no grant and has no row, so it cannot say whether the
    /// digest on the line is the patch's.
    fn native_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
        let text = cx.files.read(&pin.file);
        let text = text.as_str().unwrap_or_default();
        let lines = locked(text);
        let mut own = lines
            .iter()
            .filter(|line| line.socket && line.purl == pin.purl);
        match own.next() {
            Some(line) if !line.broken => lane_duties(cx, pin, text),
            _ => {
                let detail = "the lane's own proof of the line fails";
                Err(withheld(DerivedStale, None, detail))
            }
        }
    }

    const CLAIM: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];
    /// The claims of a lane that is proven under `WORKSPACE` as well.
    const BOTH: &[CellClaim] = &[
        CLAIM[0],
        CellClaim {
            lo: "6.6.0",
            hi: "8.8.2",
            system: ClaimSystem::Workspace,
        },
    ];

    const fn lane(id: &'static str, mode: Mode, anchor: Anchor) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIM,
            anchor,
            ..LaneSpec::stub(id, mode, &[])
        }
    }

    const fn lane_under_both(id: &'static str, mode: Mode) -> LaneSpec {
        LaneSpec {
            supported: BOTH,
            ..lane(id, mode, Anchor::Digest)
        }
    }

    const TOY: LaneOps = LaneOps {
        discover: toy_discover,
        attest: toy_attest,
        inventory: toy_inventory,
        ..LaneOps::disabled(&[
            lane("H-TOY1", Mode::Hosted, Anchor::Digest),
            lane("V-TOY1", Mode::Vendored, Anchor::Digest),
            lane("A-TOY1", Mode::Agent, Anchor::Digest),
            lane("H-DECL", Mode::Hosted, Anchor::Declaration),
            lane("H-OWNED", Mode::Hosted, Anchor::Digest),
            lane("H-RCSEL", Mode::Hosted, Anchor::RcSelector),
            // A basis nothing anchors under an anchor that says a digest
            // does: what the gate leaves when merged plans disagree.
            lane("H-WHELD", Mode::Hosted, Anchor::Digest),
            // A lock pin whose lane says a statement selects the bytes.
            lane("H-DLOCK", Mode::Hosted, Anchor::Declaration),
        ])
    };
    /// The Go family, proven under `WORKSPACE` too, where its hub is the
    /// `go_repository` rules.
    const GO: LaneOps = LaneOps {
        lanes: &[
            lane_under_both("H-TOY1", Mode::Hosted),
            lane_under_both("A-TOY1", Mode::Agent),
        ],
        ..TOY
    };
    /// The designed lane of `nuget.from_lock`, enabled for the toy proof.
    const NET: LaneOps = LaneOps {
        lanes: &[lane("H-NET2", Mode::Hosted, Anchor::Digest)],
        ..TOY
    };
    /// A family with one lane enabled and one that is not.
    const OFF: LaneOps = LaneOps {
        lanes: &[
            lane("H-TOY1", Mode::Hosted, Anchor::Digest),
            LaneSpec {
                enabled: false,
                ..lane("H-OFF", Mode::Hosted, Anchor::Digest)
            },
        ],
        ..TOY
    };
    const NATIVE: LaneOps = LaneOps {
        lanes: &[lane("H-NAT1", Mode::Hosted, Anchor::Digest)],
        discover: native_discover,
        attest: native_attest,
        ..TOY
    };
    /// A family none of whose lanes has landed: it cannot tell its pins.
    const NO_LANE: LaneOps = LaneOps::disabled(&[LaneSpec::stub("H-JS1", Mode::Hosted, &[])]);
    static TABLE: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &TOY),
        (Ruleset::RulesJs, &TOY),
        (Ruleset::RulesPython, &TOY),
        (Ruleset::Gazelle, &GO),
        (Ruleset::RulesCsharp, &NET),
    ]);
    static MAVEN_ONLY: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &TOY),
        (Ruleset::RulesJs, &NO_LANE),
    ]);
    static OFF_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OFF)]);
    static NATIVE_TABLE: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &NATIVE),
        (Ruleset::RulesPython, &NATIVE),
    ]);
    /// The Maven hub under a family that holds none of the lanes its
    /// `discover` names.
    static FOREIGN_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &NET)]);

    // ── Fixtures ─────────────────────────────────────────────────────

    fn line(purl: &str, digest: &str) -> String {
        format!("{purl} {digest}\n")
    }

    /// An index that records one pin per `(purl, uuid, lane, file)`.
    fn index_of(pins: &[(&str, &str, &str, &str)]) -> Index {
        let mut index = Index::default();
        for (purl, uuid, lane, file) in pins {
            let edit = IndexEdit {
                key: "sha256".to_string(),
                original: upstream(),
                new: patched(),
            };
            index.record_pin(IndexRow {
                uuid: uuid.to_string(),
                purl: purl.to_string(),
                lane: lane.to_string(),
                file: file.to_string(),
                edits: vec![edit],
                check: None,
            });
        }
        index
    }

    fn pin_of(purl: &str, uuid: &str, lane: &'static str, file: &str) -> BazelRef {
        BazelRef {
            lane: LaneId(lane),
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            file: file.to_string(),
            basis: basis_of(lane),
        }
    }

    fn asked<'a>(purl: &'a str, project_rel: &'a str, basis: Basis<'a>) -> Candidate<'a> {
        Candidate {
            purl,
            uuid: UUID,
            project_rel,
            basis,
            grant: None,
        }
    }

    fn hosted(file: &str) -> Basis<'_> {
        Basis::Hosted { file }
    }

    type Why = (WithholdKind, Option<&'static str>);
    type Verdict = Result<Consumed, Why>;

    fn why(withheld: VexWithhold) -> Why {
        (withheld.kind, withheld.token)
    }

    fn by(lane: &'static str) -> Verdict {
        let (mode, basis) = (mode_of(lane), basis_of(lane));
        let lane = LaneId(lane);
        Ok(Consumed::ByBazel { lane, mode, basis })
    }

    fn not(kind: WithholdKind) -> Verdict {
        Err((kind, None))
    }

    /// The owned state a test wants the verdict proven over: one answer
    /// for every owned file and one for every hook, and another answer
    /// for one owned path or for the hook of one user file where a test
    /// names it.
    #[derive(Clone, Copy)]
    struct Owned {
        file: OwnedFile,
        hook: HookUnit,
        file_at: Option<(&'static str, OwnedFile)>,
        hook_in: Option<(&'static str, HookUnit)>,
    }

    const fn owned(file: OwnedFile, hook: HookUnit) -> Owned {
        Owned {
            file,
            hook,
            file_at: None,
            hook_in: None,
        }
    }

    const SOUND: Owned = owned(OwnedFile::Ours, HookUnit::Present);

    impl OwnedState for Owned {
        fn file(&self, path: &str) -> OwnedFile {
            match self.file_at {
                Some((at, file)) if at == path => file,
                _ => self.file,
            }
        }

        fn hook(&self, row: &HookRow) -> HookUnit {
            match self.hook_in {
                Some((file, unit)) if file == row.file => unit,
                _ => self.hook,
            }
        }
    }

    /// Asks over the root that holds `files`, read for its root project,
    /// with `index` as its owned index and `owned` as its owned state
    /// (`None`: the state of this build). The root probe found this root
    /// alone.
    fn over<T>(
        files: &[(&str, &str)],
        lanes: &'static LaneTable,
        index: &Index,
        owned: Option<Owned>,
        ask: impl FnOnce(&Attest<'_>) -> T,
    ) -> T {
        over_view(files, Files::of(files), lanes, index, owned, ask)
    }

    /// [`over`] with the workspace read from `files` and every later
    /// read made of `view`, which may hold what no text can say (a file
    /// that cannot be read).
    fn over_view<T>(
        files: &[(&str, &str)],
        view: Files,
        lanes: &'static LaneTable,
        index: &Index,
        owned: Option<Owned>,
        ask: impl FnOnce(&Attest<'_>) -> T,
    ) -> T {
        let ws = read(files);
        let mut attest = Attest::read(&ws, lanes, &view, index, Roots::One);
        if let Some(owned) = owned {
            attest.owned = Box::new(owned);
        }
        ask(&attest)
    }

    fn judge(files: &[(&str, &str)], index: &Index, candidate: &Candidate<'_>) -> Verdict {
        judge_with(&TABLE, files, index, candidate)
    }

    fn judge_with(
        lanes: &'static LaneTable,
        files: &[(&str, &str)],
        index: &Index,
        candidate: &Candidate<'_>,
    ) -> Verdict {
        let verdict = |attest: &Attest<'_>| attest.consumer(candidate).map_err(why);
        over(files, lanes, index, None, verdict)
    }

    /// The reason a candidate is withheld, with its words: for the
    /// withholds that share a kind and are told apart by what they say.
    fn said(
        lanes: &'static LaneTable,
        files: &[(&str, &str)],
        index: &Index,
        candidate: &Candidate<'_>,
    ) -> (WithholdKind, String) {
        let verdict = |attest: &Attest<'_>| attest.consumer(candidate);
        let withheld = over(files, lanes, index, None, verdict);
        let withheld = withheld.expect_err("the statement is withheld");
        (withheld.kind, withheld.detail)
    }

    /// The releases each hub is contested for, with no grant in hand.
    fn contested(
        lanes: &'static LaneTable,
        files: &[(&str, &str)],
        index: &Index,
    ) -> Vec<(HubId, String)> {
        let purls = |attest: &Attest<'_>| {
            let contests = attest.contests(&|_| None);
            let found = contests.iter().map(|c| (c.hub, c.entry.purl.clone()));
            found.collect::<Vec<_>>()
        };
        over(files, lanes, index, None, purls)
    }

    /// A Maven root whose lock holds `lock`, with a `.bazelrc`.
    fn maven<'a>(lock: &'a str, rc: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            NINE,
            ("MODULE.bazel", MAVEN),
            (LOCK, lock),
            (".bazelrc", rc),
        ]
    }

    /// The gson pin of the hosted toy lane in the Maven lock, on record.
    fn gson_pinned() -> (String, Index) {
        (
            line(GSON, &patched()),
            index_of(&[(GSON, UUID, "H-TOY1", LOCK)]),
        )
    }

    /// A view that notes every path it is asked for.
    struct Spy<'a>(&'a Files, RefCell<Vec<String>>);

    impl FileView for Spy<'_> {
        fn read(&self, rel: &str) -> FileText {
            self.1.borrow_mut().push(rel.to_string());
            self.0.read(rel)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            self.1.borrow_mut().push(format!("{dir}/"));
            self.0.list(dir)
        }
    }

    /// The lock Bazel 9.3.2 wrote in probe L1 after the refresh, and the
    /// forged one: a fresh digest beside repository specs from before
    /// the pin.
    const UPDATED: &str = fixture!("stale-repair/bazel-9.3.2/updated.MODULE.bazel.lock");
    const FORGED: &str = fixture!("stale-repair/bazel-9.3.2/forged.MODULE.bazel.lock");

    /// One of those two locks with its record of `dep.lock` turned into
    /// a record of `file` under `digest`.
    fn recorded_lock(fixture: &str, file: &str, digest: &str) -> String {
        const AFTER: &str =
            "@@//dep.lock d5ff49e00557218f35cea7c897116dca4732b5c31013f1c86382ca9bdc680ac4";
        assert!(fixture.contains(AFTER), "the fixture records `dep.lock`");
        fixture.replace(AFTER, &format!("@@//{file} {digest}"))
    }

    fn tag_edit(lane: &str, key: &str) -> TagEditRow {
        TagEditRow {
            uuid: UUID.to_string(),
            lane: lane.to_string(),
            edit: TagEdit {
                file: "MODULE.bazel".to_string(),
                stmt: StmtRef {
                    callee: "maven.install".to_string(),
                    id: "maven".to_string(),
                    ordinal: 0,
                },
                attr: "artifacts".to_string(),
                op: TagOp::AddListItem,
                inserted: "\"x\", ".to_string(),
                version_key: Some(key.to_string()),
            },
            stmt_sha256_before: "e".repeat(64),
            marker: true,
        }
    }

    // ── The five over-attestation paths (F110) ───────────────────────

    /// P1: a hosted reference in a file no hub reads. A `pom.xml` pin
    /// beside an unpatched `maven_install.json` is not attested, and the
    /// hub's unpatched entry is what contests it in any project. So is a
    /// reference in a sibling lock (`package-lock.json` beside the
    /// governed `pnpm-lock.yaml`). A pin that is found and fails its
    /// proof hides nothing from the contest.
    #[test]
    fn a_reference_in_a_file_no_hub_reads_is_not_consumed() {
        let contested = |files: &[(&str, &str)], index: &Index| contested(&TABLE, files, index);
        let unpatched = line(GSON, &upstream());
        let (files, none) = (maven(&unpatched, ""), Index::default());
        let pom = asked(GSON, "", hosted("pom.xml"));
        assert_eq!(judge(&files, &none, &pom), not(NotConsumed));
        assert_eq!(
            Code::withheld(NotConsumed).as_str(),
            "vex_bazel_not_consumed"
        );
        let gson = [(HubId(0), GSON.to_string())];
        assert_eq!(contested(&files, &none), gson);

        // With the hub's lock pinned the `pom.xml` reference is still a
        // file Bazel does not read; the pin in the lock is what counts,
        // and nothing is left to contest.
        let (lock, index) = gson_pinned();
        let files = maven(&lock, "");
        let in_lock = asked(GSON, "", hosted(LOCK));
        assert_eq!(judge(&files, &index, &pom), not(NotConsumed));
        assert_eq!(judge(&files, &index, &in_lock), by("H-TOY1"));
        assert_eq!(contested(&files, &index), []);

        // The pin is found and its proof fails: an override of the hub,
        // and a record in the lock Bazel wrote from before the pin. The
        // hub's entry is contested again.
        let bypassed = maven(&lock, "common --override_repository=maven=/elsewhere\n");
        let overridden = Err((PinBypassed, Some("repo_override")));
        assert_eq!(judge(&bypassed, &index, &in_lock), overridden);
        assert_eq!(contested(&bypassed, &index), gson);
        let module_lock = recorded_lock(UPDATED, LOCK, &sha256_hex_of(b"before the pin"));
        let mut pending = maven(&lock, "");
        pending.push(("MODULE.bazel.lock", &module_lock[..]));
        assert_eq!(judge(&pending, &index, &in_lock), not(RunPending));
        assert_eq!(contested(&pending, &index), gson);

        let pnpm = line(LEFT_PAD, &patched());
        let files = [
            NINE,
            ("MODULE.bazel", JS_MODULE),
            (PNPM, &pnpm[..]),
            ("package-lock.json", "{}\n"),
        ];
        let index = index_of(&[(LEFT_PAD, UUID, "H-TOY1", PNPM)]);
        let sibling = asked(LEFT_PAD, "", hosted("package-lock.json"));
        assert_eq!(judge(&files, &index, &sibling), not(NotConsumed));
        assert_eq!(
            judge(&files, &index, &asked(LEFT_PAD, "", hosted(PNPM))),
            by("H-TOY1")
        );
    }

    /// P2: a patched installed tree. In the governed project it is never
    /// evidence, pinned lock or not. In a project no hub governs
    /// (`service-a/pom.xml` kept for an IDE beside the root
    /// `maven_install.json`) it stands only while no hub lock resolves
    /// the release without a pin that passes.
    #[test]
    fn an_installed_tree_is_no_evidence_for_a_build_that_fetches_from_a_lock() {
        let installed = |project| asked(GSON, project, Basis::Installed);
        let unpatched = line(GSON, &upstream());
        let (files, none) = (maven(&unpatched, ""), Index::default());
        assert_eq!(judge(&files, &none, &installed("")), not(NotConsumed));
        // The sub-project: Maven is not governed there, and the root
        // lock builds the release unpatched.
        assert_eq!(
            judge(&files, &none, &installed("service-a")),
            not(NotConsumed)
        );
        let pom = asked(GSON, "service-a", hosted("service-a/pom.xml"));
        assert_eq!(judge(&files, &none, &pom), not(NotConsumed));
        // A release the lock does not resolve, and an ecosystem no
        // ruleset builds, are judged as they are without Bazel.
        let guava = asked(GUAVA, "service-a", Basis::Installed);
        assert_eq!(judge(&files, &none, &guava), Ok(Consumed::AsToday));
        let composer = asked(COMPOSER, "", Basis::Installed);
        assert_eq!(judge(&files, &none, &composer), Ok(Consumed::AsToday));

        let (lock, index) = gson_pinned();
        let files = maven(&lock, "");
        assert_eq!(judge(&files, &index, &installed("")), not(NotConsumed));
        let today = judge(&files, &index, &installed("service-a"));
        assert_eq!(today, Ok(Consumed::AsToday));
        assert!(Consumed::AsToday.verifies_installed_tree());
        // The pin stops passing (an override of the hub): the sub-project
        // is withheld for the reason the pin is.
        let bypassed = maven(&lock, "common --override_repository=maven=/elsewhere\n");
        let verdict = judge(&bypassed, &index, &installed("service-a"));
        assert_eq!(verdict, Err((PinBypassed, Some("repo_override"))));
    }

    /// P3: a vendored reference counts only through an enabled vendored
    /// lane whose proof passes. A hosted lane's pin in the same file, and
    /// a table with no enabled lane, prove nothing about it.
    #[test]
    fn a_vendored_reference_counts_only_through_a_vendored_lane() {
        let lock = line(LEFT_PAD, &patched());
        let files = [NINE, ("MODULE.bazel", JS_MODULE), (PNPM, &lock[..])];
        let vendored = asked(LEFT_PAD, "", Basis::Vendored { file: PNPM });
        let undetermined = not(ConsumerUndetermined);
        assert_eq!(judge(&files, &Index::default(), &vendored), undetermined);
        let hosted_pin = index_of(&[(LEFT_PAD, UUID, "H-TOY1", PNPM)]);
        assert_eq!(judge(&files, &hosted_pin, &vendored), undetermined);
        let index = index_of(&[(LEFT_PAD, UUID, "V-TOY1", PNPM)]);
        assert_eq!(judge(&files, &index, &vendored), by("V-TOY1"));
        // Every production lane is disabled: nothing is attested.
        let production = |index: &Index, candidate: &Candidate<'_>| {
            judge_with(&lanes::PRODUCTION, &files, index, candidate)
        };
        assert_eq!(production(&index, &vendored), undetermined);
        let hosted_ref = asked(LEFT_PAD, "", hosted(PNPM));
        assert_eq!(production(&hosted_pin, &hosted_ref), undetermined);
    }

    /// P4 and P5. An in-run statement skips verification only for a patch
    /// a Bazel lane confirmed in that run. And the verdict reads no
    /// installed tree and hashes nothing, so a run that skips
    /// verification skips none of it: it is the same with a patched tree
    /// in the view and without, and the view is never asked for a path
    /// below the tree.
    #[test]
    fn the_verdict_is_decided_before_any_verification() {
        let unpatched = line(GSON, &upstream());
        let (files, none) = (maven(&unpatched, ""), Index::default());
        let (ws, view) = (read(&files), Files::of(&files));
        let attest = Attest::read(&ws, &TABLE, &view, &none, Roots::One);
        let pom = asked(GSON, "", hosted("pom.xml"));
        assert!(!attest.assume_applied(&pom, &[]));
        assert!(!attest.assume_applied(&pom, &[UUID_B]));
        assert!(attest.assume_applied(&pom, &[UUID]));
        // Not governed there, and never governed: as today.
        let sub = asked(GSON, "service-a", hosted("service-a/pom.xml"));
        assert!(attest.assume_applied(&sub, &[]));
        assert!(attest.assume_applied(&asked(COMPOSER, "", Basis::Installed), &[]));
        // A project whose governance is not known (the ruleset with no
        // hub that was read): the native writer's word is not taken.
        let signal = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";
        let unread = [NINE, ("MODULE.bazel", signal)];
        let assumed = |attest: &Attest<'_>| {
            let confirmed = attest.assume_applied(&sub, &[UUID]);
            (attest.assume_applied(&sub, &[]), confirmed)
        };
        assert_eq!(over(&unread, &TABLE, &none, None, assumed), (false, true));

        let tree = ".m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar";
        let with_tree = Files::of(&files).with(tree, FileText::Bytes(b"patched".to_vec()));
        let spy = Spy(&with_tree, RefCell::new(Vec::new()));
        let spied = Attest::read(&ws, &TABLE, &spy, &none, Roots::One);
        for project in ["", "service-a"] {
            let installed = asked(GSON, project, Basis::Installed);
            let verdict = spied.consumer(&installed).map_err(why);
            assert_eq!(verdict, not(NotConsumed), "{project}");
            assert_eq!(verdict, attest.consumer(&installed).map_err(why));
        }
        let seen = spy.1.borrow();
        assert!(seen.iter().any(|path| path == LOCK), "{seen:?}");
        assert!(!seen.iter().any(|path| path.starts_with(".m2")), "{seen:?}");
    }

    // ── What every pin is held to ────────────────────────────────────

    /// The two conditions of the agent-basis rule are independent (ROUTED
    /// R-114). A lock that could not be listed withholds although the
    /// listed lock resolves the release under a pin that passes; a dev
    /// hub under a flag that is only possible still builds; and a use of
    /// the ruleset nobody followed to a hub leaves every Maven package
    /// undetermined.
    #[test]
    fn a_lock_nobody_listed_withholds_whatever_the_listed_ones_pin() {
        let installed = asked(GSON, "service-a", Basis::Installed);
        let two = MAVEN.replace(
            "use_repo(maven, \"maven\")",
            "maven.install(name = \"other\", lock_file = \"//:other_install.json\")\n\
             use_repo(maven, \"maven\", \"other\")",
        );
        let (lock, index) = gson_pinned();
        let mut files = vec![NINE, ("MODULE.bazel", &two[..]), (LOCK, &lock[..])];
        let unlisted = |attest: &Attest<'_>| {
            assert_eq!(attest.ws.hubs.len(), 2);
            attest
                .consumer(&installed)
                .expect_err("a lock was not listed")
        };
        let unlisted = over(&files, &TABLE, &index, None, unlisted);
        assert_eq!(unlisted.kind, ConsumerUndetermined);
        assert!(
            unlisted.detail.contains("other_install.json"),
            "{unlisted:?}"
        );
        // With the second lock listed and empty, the pin of the first is
        // all there is.
        files.push(("other_install.json", ""));
        assert_eq!(judge(&files, &index, &installed), Ok(Consumed::AsToday));

        let dev = MAVEN.replacen("\"maven\")\n", "\"maven\", dev_dependency = True)\n", 1);
        let unpatched = line(GSON, &upstream());
        let files = [
            NINE,
            (".bazelrc", "common:ci --ignore_dev_dependency\n"),
            ("MODULE.bazel", &dev[..]),
            (LOCK, &unpatched[..]),
        ];
        let none = Index::default();
        assert_eq!(judge(&files, &none, &installed), not(NotConsumed));
        let at_root = asked(GSON, "", Basis::Installed);
        let dropped = Err((NotConsumed, Some("dev_dependency_dropped")));
        assert_eq!(judge(&files, &none, &at_root), dropped);

        let signal = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";
        let files = [NINE, ("MODULE.bazel", signal)];
        let unread = Err((ConsumerUndetermined, Some("label_not_literal")));
        for candidate in [installed, at_root, asked(GUAVA, "x", Basis::Installed)] {
            assert_eq!(judge(&files, &none, &candidate), unread, "{candidate:?}");
        }
    }

    /// ROUTED R-121. A hand-written pin of the ecosystem names no lock,
    /// so what it fetches cannot be listed and the pin of the hub beside
    /// it stays withheld. An override of a repository only the lane can
    /// name is a bypass. A hub of another ecosystem whose family cannot
    /// tell its pins holds nothing up, and one of the same ecosystem
    /// does. A pin is wiring only in a project a hub governs, and only
    /// through a lane of its hub's family.
    #[test]
    fn a_pin_is_held_to_every_lock_of_its_ecosystem_and_to_the_lanes_repositories() {
        let (lock, index) = gson_pinned();
        let gson = pin_of(GSON, UUID, "H-TOY1", LOCK);
        let pin = Candidate::of_pin(&gson, "", None);
        assert_eq!(judge(&maven(&lock, ""), &index, &pin), by("H-TOY1"));
        // In a project no hub governs the same pin is a mention.
        let elsewhere = Candidate::of_pin(&gson, "service-a", None);
        let mention = judge(&maven(&lock, ""), &index, &elsewhere);
        assert_eq!(mention, not(NotConsumed));
        // The family that serves the hub holds no lane of that name: the
        // pin is not one of the hub's.
        let foreign = judge_with(&FOREIGN_TABLE, &maven(&lock, ""), &index, &pin);
        assert_eq!(foreign, not(NotConsumed));

        let http_jar = "http_jar = use_repo_rule(\
            \"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_jar\")\n\
            http_jar(name = \"some_jar\", url = \"https://repo.toy.invalid/a.jar\")\n";
        let module = format!("{MAVEN}{http_jar}");
        let files = [NINE, ("MODULE.bazel", &module[..]), (LOCK, &lock[..])];
        let unlisted = Err((ConsumerUndetermined, Some("lane_not_enabled")));
        assert_eq!(judge(&files, &index, &pin), unlisted);

        // The override names a repository the hub's own name does not
        // cover. Only the lane's list makes it a bypass.
        let rc = "common --override_repository=com_google_code_gson_gson=/elsewhere\n";
        assert_eq!(judge(&maven(&lock, rc), &index, &pin), by("H-TOY1"));
        let with_spoke = format!("{lock}# spoke com_google_code_gson_gson\n");
        let bypassed = Err((PinBypassed, Some("repo_override")));
        assert_eq!(judge(&maven(&with_spoke, rc), &index, &pin), bypassed);
        assert_eq!(judge(&maven(&with_spoke, ""), &index, &pin), by("H-TOY1"));

        // An npm hub whose family cannot tell: the Maven pin stands, and
        // an npm reference is undetermined.
        let both = format!("{MAVEN}{JS_MODULE}");
        let files = [
            NINE,
            ("MODULE.bazel", &both[..]),
            (LOCK, &lock[..]),
            (PNPM, "lockfileVersion: '9.0'\n"),
        ];
        let npm = asked(LEFT_PAD, "", hosted(PNPM));
        let verdicts = |attest: &Attest<'_>| {
            let unknown = attest.discovered.unknown_for(Ecosystem::Npm);
            let unknown = unknown.map(|id| attest.ws.hubs[id.0].ruleset);
            let maven = attest.consumer(&pin).map_err(why);
            (unknown, maven, attest.consumer(&npm).map_err(why))
        };
        let found = over(&files, &MAVEN_ONLY, &index, None, verdicts);
        let cannot_tell = Some(Ruleset::RulesJs);
        assert_eq!(
            found,
            (cannot_tell, by("H-TOY1"), not(ConsumerUndetermined))
        );

        // A second Maven hub whose lane cannot tell its pins. Its lock
        // lists nothing of the release, and what it pins is not known:
        // the pin of the first hub is withheld, and stands once the
        // second can tell.
        let two = MAVEN.replace(
            "use_repo(maven, \"maven\")",
            "maven.install(name = \"other\", lock_file = \"//:other_install.json\")\n\
             use_repo(maven, \"maven\", \"other\")",
        );
        let second = |other: &'static str| {
            vec![
                NINE,
                ("MODULE.bazel", &two[..]),
                (LOCK, &lock[..]),
                ("other_install.json", other),
            ]
        };
        assert_eq!(judge(&second(""), &index, &pin), by("H-TOY1"));
        let (kind, detail) = said(&TABLE, &second("# opaque\n"), &index, &pin);
        assert_eq!(kind, ConsumerUndetermined);
        let unknown = "the pins of the hub `other` are not known";
        assert!(detail.contains(unknown), "{detail}");
    }

    /// The lane gate is re-run at discovery (L11): a pin counts only
    /// through a lane that is enabled, serves the hub's shape in its
    /// mode, and is proven on the Bazel line and the dependency system
    /// of the workspace. Each is told apart from "no pin" by what it
    /// says.
    #[test]
    fn a_pin_of_a_lane_that_is_disabled_unserved_or_unproven_is_undetermined() {
        let (lock, index) = gson_pinned();
        let in_lock = asked(GSON, "", hosted(LOCK));
        fn words(
            lanes: &'static LaneTable,
            files: &[(&str, &str)],
            index: &Index,
            of: &Candidate<'_>,
        ) -> String {
            let (kind, detail) = said(lanes, files, index, of);
            assert_eq!(kind, ConsumerUndetermined, "{detail}");
            detail
        }
        // A family with one lane enabled and one not, whose discovery
        // returns the pin of the disabled one.
        let enabled = judge_with(&OFF_TABLE, &maven(&lock, ""), &index, &in_lock);
        assert_eq!(enabled, by("H-TOY1"));
        let off = index_of(&[(GSON, UUID, "H-OFF", LOCK)]);
        let detail = words(&OFF_TABLE, &maven(&lock, ""), &off, &in_lock);
        assert!(detail.contains("lane H-OFF is not enabled"), "{detail}");

        // An agent lane's pin on a hub no agent lane serves.
        let pnpm = line(LEFT_PAD, &patched());
        let files = [NINE, ("MODULE.bazel", JS_MODULE), (PNPM, &pnpm[..])];
        let agent = index_of(&[(LEFT_PAD, UUID, "A-TOY1", PNPM)]);
        let installed = asked(LEFT_PAD, "", Basis::Installed);
        let detail = words(&TABLE, &files, &agent, &installed);
        let unserved = "lane A-TOY1 is not enabled for this hub";
        assert!(detail.contains(unserved), "{detail}");

        // A Bazel release below the lane's claim, and a dependency
        // system the lane has no claim under.
        let older = [
            (".bazelversion", "7.0.0\n"),
            ("MODULE.bazel", MAVEN),
            (LOCK, &lock[..]),
        ];
        let detail = words(&TABLE, &older, &index, &in_lock);
        assert!(detail.contains("is not proven on Bazel"), "{detail}");
        let workspace = "load(\"@rules_jvm_external//:defs.bzl\", \"maven_install\")\n\
            maven_install(name = \"maven\", maven_install_json = \"//:maven_install.json\")\n";
        let under_workspace = [
            (".bazelversion", "7.7.2\n"),
            (".bazelrc", "common --noenable_bzlmod\n"),
            ("WORKSPACE", workspace),
            (LOCK, &lock[..]),
        ];
        let detail = words(&TABLE, &under_workspace, &index, &in_lock);
        assert!(detail.contains("is not proven on Bazel"), "{detail}");
    }

    /// Discovery returns a pin whatever file carries it, and the verdict
    /// judges it through the hub whose lane found it (revision 4, section
    /// 4 item 7). The `go_repository` rules of a `WORKSPACE` name no lock
    /// and govern every Go project under the root; the pin their lane
    /// finds is in a `go.mod`.
    #[test]
    fn a_pin_in_a_file_its_hub_names_no_lock_for_is_judged_through_the_hub() {
        let workspace = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
            http_archive(\n    name = \"bazel_gazelle\",\n    \
            urls = [\"https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz\"],\n)\n\
            load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\", \"go_repository\")\n\
            go_repository(\n    name = \"com_github_pkg_errors\",\n    importpath = \"github.com/pkg/errors\",\n    \
            sum = \"h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\",\n    version = \"v0.9.1\",\n)\n\
            gazelle_dependencies()\n";
        let errors = "pkg:golang/github.com/pkg/errors@v0.9.1";
        let go_mod = format!(
            "module example.com/svc\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n// {}",
            line(errors, &patched())
        );
        let files = [
            (".bazelversion", "7.7.2\n"),
            (".bazelrc", "common --noenable_bzlmod\n"),
            ("WORKSPACE", workspace),
            ("svc/go.mod", &go_mod[..]),
        ];
        let (ws, view) = (read_at(&files, "svc"), Files::of(&files));
        let no_lock = (HubShape::GoRepository, 0);
        assert_eq!((ws.hubs[0].shape, ws.hubs[0].locks.len()), no_lock);
        let index = index_of(&[(errors, UUID, "H-TOY1", "svc/go.mod")]);
        let attest = Attest::read(&ws, &TABLE, &view, &index, Roots::One);
        let pin = pin_of(errors, UUID, "H-TOY1", "svc/go.mod");
        assert_eq!(attest.discovered.by_hub, [(HubId(0), pin.clone())]);
        let verdict = |candidate: &Candidate<'_>| attest.consumer(candidate).map_err(why);
        assert_eq!(verdict(&Candidate::of_pin(&pin, "svc", None)), by("H-TOY1"));
        let reference = asked(errors, "svc", hosted("svc/go.mod"));
        assert_eq!(verdict(&reference), by("H-TOY1"));
        // Another patch of the release has no pin there: the file is
        // still one the hub's lane reads, so nothing says the reference
        // does not reach the build. A file no lane finds a pin in is
        // one no hub reads.
        let other_patch = Candidate {
            uuid: UUID_B,
            ..reference
        };
        assert_eq!(verdict(&other_patch), not(ConsumerUndetermined));
        let stray = asked(errors, "svc", hosted("svc/tools/go.mod"));
        assert_eq!(verdict(&stray), not(NotConsumed));
    }

    /// A hub the gate would not write for (obligation 4: a lock under a
    /// file name no rewriter handles) is not attested for either, in the
    /// words of that refusal.
    #[test]
    fn a_hub_whose_lock_no_rewriter_handles_withholds_its_pin() {
        let module = JS_MODULE.replace("pnpm-lock.yaml", "locks.yaml");
        let lock = line(LEFT_PAD, &patched());
        let files = [
            NINE,
            ("MODULE.bazel", &module[..]),
            ("locks.yaml", &lock[..]),
        ];
        let index = index_of(&[(LEFT_PAD, UUID, "H-TOY1", "locks.yaml")]);
        let reference = asked(LEFT_PAD, "", hosted("locks.yaml"));
        let (kind, detail) = said(&TABLE, &files, &index, &reference);
        assert_eq!(kind, ConsumerUndetermined);
        let refused = "a file name the rewriter does not handle";
        assert!(detail.contains(refused), "{detail}");
    }

    /// A purl whose type is spelled in another case is the same release
    /// to the caller and to every comparison here, so it is not waved
    /// through as an ecosystem no ruleset builds. A string that names no
    /// purl type is of no known ecosystem.
    #[test]
    fn a_purl_type_in_another_case_is_the_same_release() {
        let (lock, index) = gson_pinned();
        let files = maven(&lock, "");
        let upper = "pkg:MAVEN/com.google.code.gson/gson@2.10.1";
        assert!(PurlKey::same(upper, GSON));
        let verdicts = |purl: &'static str| {
            let ask = |attest: &Attest<'_>| {
                let installed = asked(purl, "", Basis::Installed);
                let in_lock = asked(purl, "", hosted(LOCK));
                (
                    attest.consumer(&installed).map_err(why),
                    attest.assume_applied(&installed, &[]),
                    attest.consumer(&in_lock).map_err(why),
                )
            };
            over(&files, &TABLE, &index, None, ask)
        };
        let governed = (not(NotConsumed), false, by("H-TOY1"));
        assert_eq!(verdicts(GSON), governed);
        assert_eq!(verdicts(upper), governed);
        let qualified = "pkg:maven/com.google.code.gson/gson@2.10.1?type=jar";
        assert_eq!(verdicts(qualified), governed);
        for no_purl in ["", "pkg:", "pkg:maven", "gson@2.10.1"] {
            let unknown = not(ConsumerUndetermined);
            assert_eq!(verdicts(no_purl), (unknown, false, unknown), "{no_purl}");
        }
        // A type no ruleset builds is judged as it is without Bazel.
        let today = Ok(Consumed::AsToday);
        assert_eq!(verdicts("pkg:hex/jason@1.4.4"), (today, true, today));
        let parts = (Ecosystem::Maven, "g/a".to_string(), "1".to_string());
        assert_eq!(release(" pkg:Maven/g/a@1 "), Some(parts));
    }

    /// A user patch hook for the package on a hub that applies it with
    /// the host `patch` tool: the pin is withheld while the entry exists
    /// (probe P4). A hook for another package withholds nothing.
    #[test]
    fn a_user_patch_hook_for_the_package_withholds_its_pin() {
        let lock = line(LEFT_PAD, &patched());
        let index = index_of(&[(LEFT_PAD, UUID, "H-TOY1", PNPM)]);
        let verdict = |patches: &str| {
            let module = JS_MODULE.replace("pnpm_lock = ", &format!("{patches}pnpm_lock = "));
            let files = [NINE, ("MODULE.bazel", &module[..]), (PNPM, &lock[..])];
            judge(&files, &index, &asked(LEFT_PAD, "", hosted(PNPM)))
        };
        assert_eq!(verdict(""), by("H-TOY1"));
        let other = "patches = {\"once@2.0.0\": [\"//:once.patch\"]}, ";
        assert_eq!(verdict(other), by("H-TOY1"));
        let own = "patches = {\"left-pad@1.3.0\": [\"//:lp.patch\"]}, ";
        assert_eq!(verdict(own), Err((PinBypassed, Some("user_patch_hook"))));
        assert_eq!(
            Code::withheld(PinBypassed).as_str(),
            "vex_bazel_pin_bypassed"
        );
    }

    /// The consumer proof of a governed NuGet hub replaces the native
    /// verification of the global packages folder: Bazel never reads that
    /// store, so an `H-NET2` pin attests with the upstream package in it,
    /// and the folder is never looked at.
    #[test]
    fn an_h_net2_pin_attests_with_the_upstream_package_in_the_global_packages_folder() {
        let module = "bazel_dep(name = \"rules_csharp\", version = \"0.5.0\")\n\
            nuget = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"nuget\")\n\
            nuget.from_lock(packages_lock_json = \"//:packages.lock.json\")\n\
            use_repo(nuget, \"nuget\")\n";
        let (json, nuget_lock) = ("pkg:nuget/Newtonsoft.Json@13.0.1", "packages.lock.json");
        let lock = line(json, &patched());
        let files = [NINE, ("MODULE.bazel", module), (nuget_lock, &lock[..])];
        let ws = read(&files);
        let folder = ".nuget/packages/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg";
        let global = Files::of(&files).with(folder, FileText::Bytes(b"upstream".to_vec()));
        let spy = Spy(&global, RefCell::new(Vec::new()));
        let index = index_of(&[(json, UUID, "H-NET2", nuget_lock)]);
        let attest = Attest::read(&ws, &TABLE, &spy, &index, Roots::One);
        let reference = asked(json, "", hosted(nuget_lock));
        let verdict = attest
            .consumer(&reference)
            .expect("the consumer proof holds");
        assert_eq!(Ok(verdict), by("H-NET2"));
        assert!(!verdict.verifies_installed_tree() && verdict.integrity_required());
        let seen = spy.1.borrow();
        assert!(
            !seen.iter().any(|path| path.starts_with(".nuget")),
            "{seen:?}"
        );
        // The proof is the lock's: with the upstream digest back in it
        // the pin is gone, and the native reference proves nothing.
        let erased = line(json, &upstream());
        let files = [files[0], files[1], (nuget_lock, &erased[..])];
        assert_eq!(judge(&files, &index, &reference), not(ConsumerUndetermined));
    }

    /// What the caller still verifies follows the mode of the lane the
    /// pin passed through, and a caller asks the accessors for it. A
    /// hosted pin replaces the tree and needs a locked digest; a
    /// vendored pin rests on the committed artifact, which the caller
    /// hashes; an agent pin rests on the patched tree Bazel builds from,
    /// which the caller verifies as it does without Bazel.
    #[test]
    fn what_the_caller_still_verifies_follows_the_mode_of_the_lane() {
        let asks = |verdict: Consumed| {
            (
                verdict.verifies_installed_tree(),
                verdict.integrity_required(),
                verdict.hashes_committed_artifact(),
            )
        };
        assert_eq!(asks(Consumed::AsToday), (true, false, false));
        let grant = Integrity {
            sha256: Some(patched()),
            ..Integrity::default()
        };
        let through = |lock: &str, row: &IndexRow, basis: Basis<'_>| {
            let files = [NINE, ("MODULE.bazel", JS_MODULE), (PNPM, lock)];
            let mut index = Index::default();
            index.record_pin(row.clone());
            let candidate = Candidate {
                grant: Some(&grant),
                ..asked(LEFT_PAD, "", basis)
            };
            judge(&files, &index, &candidate)
        };
        let row = |lane: &str, digest: &str| {
            let mut rows = index_of(&[(LEFT_PAD, UUID, lane, PNPM)]).pins;
            rows[0].edits[0].new = digest.to_string();
            rows.remove(0)
        };
        let (pinned, vendored) = (line(LEFT_PAD, &patched()), Basis::Vendored { file: PNPM });
        let hosted_pin = through(&pinned, &row("H-TOY1", &patched()), hosted(PNPM));
        assert_eq!(hosted_pin, by("H-TOY1"));
        assert_eq!(hosted_pin.map(asks), Ok((false, true, false)));
        let vendored_pin = through(&pinned, &row("V-TOY1", &patched()), vendored);
        assert_eq!(vendored_pin, by("V-TOY1"));
        assert_eq!(vendored_pin.map(asks), Ok((false, false, true)));

        // A lock that holds no digest for the package: the vendored pin
        // is not held to one, and the hosted pin has nothing the build
        // enforces.
        let bare = line(LEFT_PAD, "-");
        assert_eq!(through(&bare, &row("V-TOY1", "-"), vendored), by("V-TOY1"));
        let unanchored = through(&bare, &row("H-TOY1", "-"), hosted(PNPM));
        assert_eq!(unanchored, not(IntegrityUnanchored));
        // A digest the vendored lock does hold is still compared.
        let other = line(LEFT_PAD, &upstream());
        let stale = through(&other, &row("V-TOY1", &upstream()), vendored);
        assert_eq!(stale, not(DerivedStale));
    }

    /// A hosted Go pin while a tracked `--repo_env` turns a host cache of
    /// `go_repository` on has no digest the build enforces. An agent pin
    /// (the directory replace) is what an installed tree counts through,
    /// and the caller still verifies that tree.
    #[test]
    fn a_tracked_go_host_cache_leaves_a_hosted_go_pin_unanchored() {
        let module = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
            go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
            go_deps.from_file(go_mod = \"//:go.mod\")\n\
            use_repo(go_deps, \"com_github_foo_bar\")\n";
        let bar = "pkg:golang/github.com/foo/bar@v1.0.0";
        let go_mod = format!(
            "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n// {}",
            line(bar, &patched())
        );
        let verdict = |rc: &str, lane: &str, basis: Basis<'_>| {
            let files = [
                NINE,
                (".bazelrc", rc),
                ("MODULE.bazel", module),
                ("go.mod", &go_mod[..]),
                ("go.sum", ""),
            ];
            let index = index_of(&[(bar, UUID, lane, "go.mod")]);
            judge(&files, &index, &asked(bar, "", basis))
        };
        assert_eq!(verdict("", "H-TOY1", hosted("go.mod")), by("H-TOY1"));
        let host_cache = "common --repo_env=GO_REPOSITORY_USE_HOST_MODCACHE=1\n";
        for (rc, anchored) in [
            (host_cache, false),
            (
                "common:ci --repo_env=GO_REPOSITORY_USE_HOST_CACHE=1\n",
                false,
            ),
            // The client environment decides, and it may say `1`.
            ("fetch --repo_env=GO_REPOSITORY_USE_HOST_CACHE\n", false),
            (
                "common --repo_env=GO_REPOSITORY_USE_HOST_MODCACHE=0\n",
                true,
            ),
            ("common --repo_env==GO_REPOSITORY_USE_HOST_CACHE\n", true),
        ] {
            let expected = if anchored {
                by("H-TOY1")
            } else {
                not(IntegrityUnanchored)
            };
            assert_eq!(verdict(rc, "H-TOY1", hosted("go.mod")), expected, "{rc}");
        }
        let code = Code::withheld(IntegrityUnanchored).as_str();
        assert_eq!(code, "vex_bazel_integrity_unanchored");
        // The installed tree of a governed Go project counts through an
        // agent lane's pin and through no other. Bazel builds from that
        // tree, so the caller verifies it, and no locked digest is
        // asked for.
        let agent = verdict(host_cache, "A-TOY1", Basis::Installed);
        assert_eq!(agent, by("A-TOY1"));
        let agent = agent.expect("an agent pin");
        assert!(agent.verifies_installed_tree());
        assert!(!agent.integrity_required() && !agent.hashes_committed_artifact());
        assert_eq!(verdict("", "H-TOY1", Basis::Installed), not(NotConsumed));
    }

    // ── Works-after evidence and the pinned digest ───────────────────

    /// The evidence that ends works-after, over the locks Bazel 9.3.2
    /// wrote in probe L1: the refreshed lock holds, the first lock is
    /// pending, and the forged one (a fresh digest beside repository
    /// specs from before the pin) is `vex_bazel_derived_stale`. Through
    /// the verdict the forged lock is withheld by the lane's own call,
    /// which names the extension and the pin; the call the verdict makes
    /// for every lane names neither and cannot see it.
    /// A patch granted as several artifacts: every digest a lock entry
    /// lists has to be the digest of one of them, in the entry's own
    /// kind. One grant is the case of [`digest_equals_grant`], and no
    /// grant equals nothing.
    #[test]
    fn a_listed_digest_is_held_to_the_artifacts_of_one_patch() {
        let sha256 = |sum: &str| Integrity {
            sha256: Some(sum.to_string()),
            ..Integrity::default()
        };
        let sha512 = |sri: &str| Integrity {
            sha512: Some(sri.to_string()),
            ..Integrity::default()
        };
        let (wheel, sdist) = (sha256(&"a".repeat(64)), sha256(&"B".repeat(64)));
        let any = |sums: &[&str]| {
            LockIntegrity::Sha256AnyOf(sums.iter().map(|sum| sum.to_string()).collect())
        };
        let both = any(&[&"A".repeat(64), &"b".repeat(64)]);
        let kind = |held: Result<(), VexWithhold>| held.map_err(|withheld| withheld.kind);
        assert_eq!(kind(digest_of_grants(&both, &[&wheel, &sdist])), Ok(()));
        // One artifact alone leaves a listed digest that is not its own.
        let stale = Err(WithholdKind::DerivedStale);
        assert_eq!(kind(digest_of_grants(&both, &[&wheel])), stale);
        assert_eq!(kind(digest_equals_grant(&both, &sdist)), stale);
        // A listed digest that is no artifact of the patch.
        let foreign = any(&[&"a".repeat(64), &"c".repeat(64)]);
        assert_eq!(kind(digest_of_grants(&foreign, &[&wheel, &sdist])), stale);
        assert_eq!(kind(digest_of_grants(&any(&[]), &[&wheel])), stale);
        assert_eq!(kind(digest_of_grants(&both, &[])), stale);
        // An SRI string with a hash per artifact, compared exactly.
        let (tgz, zip) = (sha512("sha512-AAA="), sha512("sha512-BBB="));
        let sri = LockIntegrity::Sri("sha512-BBB= sha512-AAA=".to_string());
        assert_eq!(kind(digest_of_grants(&sri, &[&tgz, &zip])), Ok(()));
        assert_eq!(kind(digest_of_grants(&sri, &[&tgz])), stale);
        assert_eq!(kind(digest_of_grants(&sri, &[&tgz, &wheel])), stale);
        // A kind no artifact has a digest of, and an entry with none.
        let single = LockIntegrity::Sha256Hex("a".repeat(64));
        assert_eq!(kind(digest_of_grants(&single, &[&tgz, &zip])), stale);
        assert_eq!(kind(digest_of_grants(&single, &[&zip, &wheel])), Ok(()));
        let unanchored = Err(WithholdKind::IntegrityUnanchored);
        assert_eq!(
            kind(digest_of_grants(&LockIntegrity::None, &[&wheel])),
            unanchored
        );
    }

    #[test]
    fn a_forged_lock_entry_is_derived_stale() {
        let locks = [
            ("updated", UPDATED),
            (
                "baseline",
                fixture!("stale-repair/bazel-9.3.2/baseline.MODULE.bazel.lock"),
            ),
            ("forged", FORGED),
        ];
        let toy = [ExtRef::new("//:ext.bzl", "toy").expect("an extension label")];
        let evidence = |name: &str, rc: &str| {
            let lock = locks
                .iter()
                .find(|(lock, _)| *lock == name)
                .expect("a lock");
            let files = [
                NINE,
                (".bazelrc", rc),
                (
                    "MODULE.bazel",
                    fixture!("stale-repair/bazel-9.3.2/root.MODULE.bazel"),
                ),
                ("MODULE.bazel.lock", lock.1),
                (
                    "dep.lock",
                    fixture!("stale-repair/bazel-9.3.2/dep.lock.after"),
                ),
            ];
            let (ws, view) = (read(&files), Files::of(&files));
            let pin = Some("socket-patched-a-1.0");
            let found = works_after(&ws, &view, &["dep.lock"], &toy, pin, None);
            found.map_err(|why| Code::withheld(why.kind).as_str())
        };
        assert_eq!(evidence("updated", ""), Ok(()));
        assert_eq!(evidence("baseline", ""), Err("vex_bazel_run_pending"));
        assert_eq!(evidence("forged", ""), Err("vex_bazel_derived_stale"));
        // A lock the plain build neither reads nor writes is no evidence
        // and none is needed; under a named config alone it still is.
        assert_eq!(evidence("forged", "common --lockfile_mode=off\n"), Ok(()));
        let ci = evidence("forged", "common:ci --lockfile_mode=off\n");
        assert_eq!(ci, Err("vex_bazel_derived_stale"));

        // Through the verdict, for any lane: the lock Bazel wrote records
        // the pin's file. The record of the file as it is now attests;
        // one from before the pin is pending until the command has run.
        let (lock, index) = gson_pinned();
        let judged = |lock: &str, module_lock: &str| {
            let mut files = maven(lock, "");
            files.push(("MODULE.bazel.lock", module_lock));
            judge(&files, &index, &asked(GSON, "", hosted(LOCK)))
        };
        let fresh = sha256_hex_of(lock.as_bytes());
        let refreshed = recorded_lock(UPDATED, LOCK, &fresh);
        assert_eq!(judged(&lock, &refreshed), by("H-TOY1"));
        let before = recorded_lock(UPDATED, LOCK, &sha256_hex_of(b"before the pin"));
        assert_eq!(judged(&lock, &before), not(RunPending));

        // The forged lock records the pin's file as it is now. A lane
        // that names its extension and the pin as the repository specs
        // render it withholds; with the specs of the refreshed lock the
        // same lane attests. A lane that does not make that call lets
        // the forged lock through, which is why each lane's `attest`
        // owes it.
        let named = format!("{lock}# ext //:ext.bzl toy socket-patched-a-1.0\n");
        let fresh_named = sha256_hex_of(named.as_bytes());
        let forged = recorded_lock(FORGED, LOCK, &fresh_named);
        assert_eq!(judged(&named, &forged), not(DerivedStale));
        let refreshed = recorded_lock(UPDATED, LOCK, &fresh_named);
        assert_eq!(judged(&named, &refreshed), by("H-TOY1"));
        let unnamed = recorded_lock(FORGED, LOCK, &fresh);
        assert_eq!(judged(&lock, &unnamed), by("H-TOY1"));
    }

    /// A lockfile fact for the package never withholds. The lock of
    /// probe L3 still holds the `six` fact that the pin made stale; with
    /// the requirements file recorded as it is now and the pin in the
    /// repository specs, the lane's evidence holds and the pin attests,
    /// because a fact is no part of the evidence. The same lock with the
    /// specs from before the pin is withheld, so the evidence is asked.
    #[test]
    fn a_pip_fact_for_the_package_does_not_withhold() {
        let fact = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
        let (six, requirements) = ("pkg:pypi/six@1.16.0", "requirements_lock.txt");
        let pip = ExtRef::new("//python/extensions:pip.bzl", "pip").expect("a label");
        let lock = format!(
            "{}# ext //python/extensions:pip.bzl pip {}\n",
            line(six, &patched()),
            patched()
        );
        // rules_python 2.5 records no entry for the extension in this
        // lock, only facts. One is added here in the form Bazel records
        // for an extension that reads a file: the requirements file as
        // it is now, and the pin in the specs of the wheel's repository.
        let baseline = fixture!("facts/pip-v2/baseline.MODULE.bazel.lock");
        let opening = "\"moduleExtensions\": {";
        assert!(baseline.contains(opening) && baseline.contains(fact));
        let entry = |digest: &str| {
            let input = format!("@@//{requirements} {}", sha256_hex_of(lock.as_bytes()));
            format!(
                "{opening}\"@@rules_python+//python/extensions:pip.bzl%pip\": {{\"general\": {{\
                 \"bzlTransitiveDigest\": \"AAAA\", \"usagesDigest\": \"AAAA\", \
                 \"recordedInputs\": [\"FILE:{input}\"], \"generatedRepoSpecs\": {{\
                 \"pypi_311_six\": {{\"repoRuleId\": \
                 \"@@rules_python+//python/private/pypi:whl_library.bzl%whl_library\", \
                 \"attributes\": {{\"sha256\": \"{digest}\"}}}}}}}}}},"
            )
        };
        let recorded = baseline.replacen(opening, &entry(&patched()), 1);
        let old_specs = baseline.replacen(opening, &entry(&upstream()), 1);
        let mut files = [
            NINE,
            ("MODULE.bazel", fixture!("facts/pip-v2/root.MODULE.bazel")),
            ("MODULE.bazel.lock", &recorded[..]),
            (requirements, &lock[..]),
        ];
        // The fact is in the lock, and the pin made it stale.
        let ws = read(&files);
        let (index_url, package) = ("https://pypi.org/simple", "six");
        let facts = FactsEdit {
            extension: pip,
            of: FactsOf::Pip { index_url, package },
            removed: &[fact],
            added: &[],
        };
        let edit = Edit {
            writes: &[Write::changed(requirements)],
            facts: Some(facts),
            ..Edit::default()
        };
        let stale = stale(&ws.module_lock, &edit);
        let is_fact = |state: &DerivedState| matches!(state, DerivedState::Facts { .. });
        assert!(stale.iter().any(is_fact), "{stale:?}");

        let index = index_of(&[(six, UUID, "H-TOY1", requirements)]);
        let reference = asked(six, "", hosted(requirements));
        assert_eq!(judge(&files, &index, &reference), by("H-TOY1"));
        files[2] = ("MODULE.bazel.lock", &old_specs[..]);
        assert_eq!(judge(&files, &index, &reference), not(DerivedStale));
    }

    /// Obligation 5 is re-run by the lane: its ruleset floor is its own,
    /// and a pin of a hub whose ruleset is no longer proven to reach it
    /// is withheld.
    #[test]
    fn a_ruleset_below_the_lanes_floor_withholds_its_pin() {
        let (lock, index) = gson_pinned();
        let verdict = |floor: &str| {
            let lock = format!("{lock}# floor {floor}\n");
            judge(&maven(&lock, ""), &index, &asked(GSON, "", hosted(LOCK)))
        };
        // The module file proves rules_jvm_external 6.7.
        assert_eq!(verdict("6.5"), by("H-TOY1"));
        assert_eq!(verdict("6.7"), by("H-TOY1"));
        let unproven = Err((ConsumerUndetermined, Some("ruleset_version_unproven")));
        assert_eq!(verdict("7.0"), unproven);
    }

    /// The pinned digest equals the grant's, in the lock's own rendering.
    /// A lock line with the upstream digest is what the ruleset's own
    /// tooling leaves, and with a warm repository cache it builds the
    /// upstream package (probe Y6).
    #[test]
    fn a_pinned_digest_that_is_not_the_grants_is_derived_stale() {
        let sri = format!("sha512-{}", "A".repeat(86));
        let grant = Integrity {
            sha256: Some(patched()),
            sha512: Some(sri.clone()),
            ..Integrity::default()
        };
        let kind = |pinned| digest_equals_grant(&pinned, &grant).map_err(|why| why.kind);
        assert_eq!(
            kind(LockIntegrity::Sha256Hex(patched().to_uppercase())),
            Ok(())
        );
        assert_eq!(kind(LockIntegrity::Sri(sri.clone())), Ok(()));
        for other in [
            LockIntegrity::Sha256Hex(upstream()),
            LockIntegrity::Sha256AnyOf(vec![patched(), upstream()]),
            LockIntegrity::Sri(format!("{sri} sha1-AAAA")),
            // A kind the grant has no digest of proves nothing.
            LockIntegrity::Sha1Hex("a".repeat(40)),
            LockIntegrity::GoH1("h1:AAAA".to_string()),
        ] {
            assert_eq!(kind(other.clone()), Err(DerivedStale), "{other:?}");
        }
        assert_eq!(kind(LockIntegrity::None), Err(IntegrityUnanchored));

        // Through the verdict: the digest the hub's lock lists for the
        // release is held to the grant the caller has.
        let (lock, index) = gson_pinned();
        let verdict = |grant: &Integrity| {
            let grant = Some(grant);
            let candidate = Candidate {
                grant,
                ..asked(GSON, "", hosted(LOCK))
            };
            judge(&maven(&lock, ""), &index, &candidate)
        };
        assert_eq!(verdict(&grant), by("H-TOY1"));
        let sha256 = Some("3".repeat(64));
        let other = Integrity {
            sha256,
            ..Integrity::default()
        };
        assert_eq!(verdict(&other), not(DerivedStale));
    }

    /// A lane of a native lock finds its pin by the Socket URL on the
    /// lock line and records it nowhere, and its `attest` is handed no
    /// grant. So the digest is compared here. With the grant, the line
    /// under the upstream digest (probe Y6) is stale, and a listing that
    /// holds no digest, or no entry of the release, anchors nothing.
    /// Without one nothing says which digest is the patch's, and the pin
    /// is undetermined whatever digest the line holds: it is withheld,
    /// and its hub's entry stays contested.
    #[test]
    fn a_hosted_pin_is_held_to_the_grants_digest_or_to_a_recorded_one() {
        let grant = Integrity {
            sha256: Some(patched()),
            ..Integrity::default()
        };
        let none = Index::default();
        let ask = |digest: &str, grant: Option<&Integrity>| {
            let lock = format!("{GSON} {digest} socket\n");
            let files = maven(&lock, "");
            let candidate = Candidate {
                grant,
                ..asked(GSON, "", hosted(LOCK))
            };
            let verdict = |attest: &Attest<'_>| {
                let [pin] = &attest.discovered.pins[..] else {
                    panic!("one pin: {:?}", attest.discovered);
                };
                let of_pin = Candidate::of_pin(pin, "", grant);
                let consumer = attest.consumer(&candidate).map_err(why);
                assert_eq!(attest.consumer(&of_pin).map_err(why), consumer);
                (consumer, attest.contests(&|_| grant).len())
            };
            over(&files, &NATIVE_TABLE, &none, None, verdict)
        };
        let (upstream, patched) = (upstream(), patched());
        assert_eq!(ask(&patched, Some(&grant)), (by("H-NAT1"), 0));
        assert_eq!(ask(&upstream, Some(&grant)), (not(DerivedStale), 1));
        assert_eq!(ask("-", Some(&grant)), (not(IntegrityUnanchored), 1));
        // The listing leaves the line out: nothing to compare, and
        // nothing listed to contest.
        assert_eq!(ask("?", Some(&grant)), (not(IntegrityUnanchored), 0));
        let unknown = (not(ConsumerUndetermined), 1);
        assert_eq!(ask(&upstream, None), unknown);
        assert_eq!(ask(&patched, None), unknown);

        // A pin a `pins` row records attests without a grant: the lane
        // holds the lock to the digest of the row.
        let (lock, index) = gson_pinned();
        let recorded = judge(&maven(&lock, ""), &index, &asked(GSON, "", hosted(LOCK)));
        assert_eq!(recorded, by("H-TOY1"));
    }

    /// Every entry of the release in the hub is held to the patch, and
    /// every pin of the patch the hub's lane found: not the first entry
    /// and not the pin of the candidate's file alone. A hub of
    /// rules_python reads one requirements file per platform, and one of
    /// them on the upstream digest is a build of the upstream package.
    #[test]
    fn every_entry_and_every_pin_of_the_release_in_a_hub_is_held_to_the_patch() {
        let grant = Integrity {
            sha256: Some(patched()),
            ..Integrity::default()
        };
        // Two entries of one release in one lock, in either order.
        let index = index_of(&[(GSON, UUID, "H-TOY1", LOCK)]);
        let twice = [(HubId(0), GSON.to_string()), (HubId(0), GSON.to_string())];
        for digests in [[patched(), upstream()], [upstream(), patched()]] {
            let lock = format!("{}{}", line(GSON, &digests[0]), line(GSON, &digests[1]));
            let files = maven(&lock, "");
            let reference = asked(GSON, "", hosted(LOCK));
            assert_eq!(judge(&files, &index, &reference), not(DerivedStale));
            let granted = Candidate {
                grant: Some(&grant),
                ..reference
            };
            assert_eq!(judge(&files, &index, &granted), not(DerivedStale));
            assert_eq!(contested(&TABLE, &files, &index), twice);
        }

        // One hub, two requirements files.
        let module = "bazel_dep(name = \"rules_python\", version = \"1.5.0\")\n\
            pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
            pip.parse(hub_name = \"pypi\", python_version = \"3.11\", \
            requirements_linux = \"//:requirements_linux.txt\", \
            requirements_darwin = \"//:requirements_darwin.txt\")\n\
            use_repo(pip, \"pypi\")\n";
        let six = "pkg:pypi/six@1.16.0";
        let (linux, darwin) = ("requirements_linux.txt", "requirements_darwin.txt");
        let none = Index::default();
        // The verdict of the reference in each file with the grant, the
        // one in the linux file without it, and what is contested.
        let found = |linux_line: &str, darwin_line: &str| {
            let files = [
                NINE,
                ("MODULE.bazel", module),
                (linux, linux_line),
                (darwin, darwin_line),
            ];
            let ask = |attest: &Attest<'_>| {
                assert_eq!(attest.ws.hubs.len(), 1, "{:?}", attest.ws.hubs);
                let verdict = |file: &str, grant: Option<&Integrity>| {
                    let candidate = Candidate {
                        grant,
                        ..asked(six, "", hosted(file))
                    };
                    attest.consumer(&candidate).map_err(why)
                };
                let contests = attest.contests(&|_| Some(&grant)).len();
                let granted = (verdict(linux, Some(&grant)), verdict(darwin, Some(&grant)));
                (granted, verdict(linux, None), contests)
            };
            over(&files, &NATIVE_TABLE, &none, None, ask)
        };
        let pinned = format!("{six} {} socket\n", patched());
        let both = (by("H-NAT1"), by("H-NAT1"));
        let no_record = not(ConsumerUndetermined);
        assert_eq!(found(&pinned, &pinned), (both, no_record, 0));

        // The darwin file is on the upstream digest and holds no pin at
        // all: the pin in the linux file does not speak for the hub.
        let plain = format!("{six} {}\n", upstream());
        let stale = not(DerivedStale);
        let unpinned = (stale, not(ConsumerUndetermined));
        assert_eq!(found(&pinned, &plain), (unpinned, stale, 2));
        // The darwin file names the release with no digest and no pin:
        // nothing the build enforces there is the patch's.
        let bare = format!("{six} -\n");
        assert_eq!(found(&pinned, &bare), (unpinned, stale, 2));

        // Both files hold a pin on the patched digest, and the lane's own
        // proof fails the one in the darwin file: with the grant the
        // reference in the linux file is withheld for it, and the hub is
        // contested.
        let broken = format!("{six} {} socket broken\n", patched());
        assert_eq!(found(&pinned, &broken), ((stale, stale), no_record, 2));
    }

    // ── Revision 4 ───────────────────────────────────────────────────

    fn hook(file: &str, kind: HookKind) -> HookRow {
        HookRow {
            file: file.to_string(),
            kind,
            unit: HOOK_UNIT,
            created_file: false,
            added_final_newline: false,
            inline: false,
            at: HookAt::End,
        }
    }

    fn rc_row(flag: RcFlag, value: &str, lane: &str) -> RcFlagRow {
        RcFlagRow {
            flag,
            value: value.to_string(),
            uuid: UUID.to_string(),
            lane: lane.to_string(),
        }
    }

    /// The canonical bytes of an index the tests fabricate.
    fn record(index: &Index) -> String {
        index.render().expect("rows socket-patch may record")
    }

    /// An rc provider adds nothing to a lock proof and takes nothing
    /// away: a pin with a `--distdir` row attests on the lock digest
    /// alone, with the owned rc file and its hook in place and with both
    /// deleted. A pin only an `--override_repository` row selects, with
    /// no digest, is never attested. Beside a selecting row the rc rows
    /// are held to obligation 14.
    #[test]
    fn an_rc_row_is_no_evidence_and_an_rc_selected_pin_is_withheld() {
        let hooked = "try-import %workspace%/.socket/bazel/socket.bazelrc\n";
        let verdicts = |lane: &'static str, flag: RcFlag, value: &str| {
            let lock = line(GSON, &patched());
            let mut index = index_of(&[(GSON, UUID, lane, LOCK)]);
            index.rc_flags = vec![rc_row(flag, value, lane)];
            index.hooks = vec![hook(".bazelrc", HookKind::Bazelrc)];
            let (record, pin) = (record(&index), pin_of(GSON, UUID, lane, LOCK));
            let owned_rc = format!("common --{}={value}\n", flag.as_str());
            // The owned rc file and its hook; the file deleted; the hook
            // as well.
            let mut files = maven(&lock, hooked);
            files.extend([(INDEX_PATH, &record[..]), (OWNED_RC_PATH, &owned_rc[..])]);
            let mut found = vec![judge(&files, &index, &Candidate::of_pin(&pin, "", None))];
            files.pop();
            found.push(judge(&files, &index, &Candidate::of_pin(&pin, "", None)));
            files[3] = (".bazelrc", "");
            found.push(judge(&files, &index, &Candidate::of_pin(&pin, "", None)));
            found
        };
        let dir = format!(".socket/vendor/maven/{UUID}");
        assert_eq!(
            verdicts("H-TOY1", RcFlag::Distdir, &dir),
            vec![by("H-TOY1"); 3]
        );
        // A lane with no digest: withheld as rc-selected, also where the
        // owned line reads as an override of the hub.
        let tree = "maven=%workspace%/.socket/vendor/maven/tree";
        let rc_selected = Err((IntegrityUnanchored, Some("rc_selected")));
        let found = verdicts("H-RCSEL", RcFlag::OverrideRepository, tree);
        assert_eq!(found, vec![rc_selected; 3]);

        // A pin with a selecting row passes the common part with its rc
        // rows: the user's own `--distdir` of the same directory, outside
        // the owned file, is a conflict.
        let lock = line(GSON, &patched());
        let mut index = index_of(&[(GSON, UUID, "H-TOY1", LOCK)]);
        index.rc_flags = vec![rc_row(RcFlag::Distdir, &dir, "H-TOY1")];
        index.hooks = vec![hook(".bazelrc", HookKind::Bazelrc)];
        index.tag_edits = vec![tag_edit("H-TOY1", "gson-2.10.1")];
        let (record, pin) = (record(&index), pin_of(GSON, UUID, "H-TOY1", LOCK));
        let common = |rc: &str| {
            let mut files = maven(&lock, rc);
            files.push((INDEX_PATH, &record[..]));
            let ask = |attest: &Attest<'_>| attest.common(HubId(0), &pin).map_err(why);
            over(&files, &TABLE, &index, Some(SOUND), ask)
        };
        assert_eq!(common(hooked), Ok(()));
        let users = format!("common --distdir={dir}\n{hooked}");
        let conflict = Err((PinBypassed, Some("rc_flag_conflict")));
        assert_eq!(common(&users), conflict);
    }

    /// The common part, over a fabricated index and the owned state a
    /// renderer would report. A modified segment withholds every pin with
    /// a segment row and no other pin; a reformatted one withholds
    /// nothing; a hook that is gone withholds with `hook_missing`; and a
    /// build that cannot compare the file makes no statement on it.
    #[test]
    fn owned_state_withholds_exactly_the_pins_whose_rows_rest_on_it() {
        let lock = format!("{}{}", line(GSON, &patched()), line(GUAVA, &patched()));
        let pins = [
            (GSON, UUID, "H-TOY1", LOCK),
            (GUAVA, UUID_B, "H-TOY1", LOCK),
        ];
        let mut index = index_of(&pins);
        index.label_strategy = Some(LabelStrategy::Ancestor);
        index.hooks = vec![hook("MODULE.bazel", HookKind::ModuleFile)];
        index.segment = vec![SegmentRow {
            kind: SegmentKind::OverrideRepo,
            extension: "@rules_jvm_external//:extensions.bzl".to_string(),
            name: "maven".to_string(),
            repo: "com_google_code_gson_gson".to_string(),
            target: "socket_patch_gson".to_string(),
            uuid: UUID.to_string(),
            lane: "H-TOY1".to_string(),
        }];
        let written = record(&index);
        let gson = pin_of(GSON, UUID, "H-TOY1", LOCK);
        let guava = pin_of(GUAVA, UUID_B, "H-TOY1", LOCK);
        let segment = (OWNED_SEGMENT_PATH, "\"\"\"Socket.\"\"\"\n");
        // The common part and the verdict of the gson pin, which has the
        // segment row; and whether the guava pin, which has none, stands.
        let found = |record: Option<&str>, segment_there: bool, held: &Index, state| {
            let mut files = maven(&lock, "");
            files.extend(record.map(|record| (INDEX_PATH, record)));
            files.extend(segment_there.then_some(segment));
            let ask = |attest: &Attest<'_>| {
                let other = Candidate {
                    uuid: UUID_B,
                    ..Candidate::of_pin(&guava, "", None)
                };
                let stands = attest.common(HubId(0), &guava) == Ok(())
                    && attest.consumer(&other).map_err(why) == by("H-TOY1");
                let verdict = attest.consumer(&Candidate::of_pin(&gson, "", None));
                let common = attest.common(HubId(0), &gson).map_err(why);
                (common, verdict.map_err(why), stands)
            };
            over(&files, &TABLE, held, state, ask)
        };
        let under = |file, unit| found(Some(&written), true, &index, Some(owned(file, unit)));
        for file in [OwnedFile::Ours, OwnedFile::Reformatted] {
            assert_eq!(under(file, HookUnit::Present), (Ok(()), by("H-TOY1"), true));
        }
        let (stale, off) = (DerivedStale, NotConsumed);
        for (file, unit, kind, token) in [
            (
                OwnedFile::Modified,
                HookUnit::Present,
                stale,
                "owned_file_modified",
            ),
            (
                OwnedFile::Foreign,
                HookUnit::Present,
                stale,
                "owned_file_modified",
            ),
            (
                OwnedFile::Missing,
                HookUnit::Present,
                stale,
                "owned_file_missing",
            ),
            (OwnedFile::Ours, HookUnit::Absent, off, "hook_missing"),
            (OwnedFile::Ours, HookUnit::Damaged, off, "hook_missing"),
            (OwnedFile::Ours, HookUnit::Duplicated, off, "hook_missing"),
        ] {
            let withheld = Err((kind, Some(token)));
            let expected = (withheld.map(|_: Consumed| ()), withheld, true);
            assert_eq!(under(file, unit), expected, "{file:?} {unit:?}");
        }
        // This build compares no owned file with its rows: the segment
        // pin is undetermined, and missing once the file is gone.
        let unchecked = Err((ConsumerUndetermined, None));
        let expected = (unchecked.map(|_: Consumed| ()), unchecked, true);
        assert_eq!(found(Some(&written), true, &index, None), expected);
        let gone = found(Some(&written), false, &index, None);
        assert_eq!(gone.0, Err((DerivedStale, Some("owned_file_missing"))));

        // The index itself: gone, edited, mangled, unreadable; and no
        // hook row.
        let common = |record: Option<&str>, held: &Index| found(record, true, held, Some(SOUND)).0;
        let stale = |token| Err((DerivedStale, Some(token)));
        assert_eq!(common(None, &index), stale("owned_file_missing"));
        let edited = written.replace("socket_patch_gson", "socket_patch_other");
        assert_eq!(common(Some(&edited), &index), stale("owned_file_modified"));
        let mangled = "{\"pins\": [], \"ignoreLines\": [}";
        assert_eq!(common(Some(mangled), &index), stale("owned_file_modified"));
        let files = [&maven(&lock, "")[..], &[segment]].concat();
        let unreadable = Files::of(&files).with(INDEX_PATH, FileText::Unreadable);
        let ask = |attest: &Attest<'_>| attest.common(HubId(0), &gson).map_err(why);
        let unread = over_view(&files, unreadable, &TABLE, &index, Some(SOUND), ask);
        assert_eq!(unread, stale("owned_file_modified"));
        let mut unhooked = index.clone();
        (unhooked.hooks, unhooked.label_strategy) = (Vec::new(), None);
        let no_hook = Err((NotConsumed, Some("hook_missing")));
        assert_eq!(common(Some(&record(&unhooked)), &unhooked), no_hook);

        // The owned `.bzl` file is reached through a hook of either file
        // family. With the unit of the segment standing in `MODULE.bazel`
        // and the one in `WORKSPACE` gone, only the `.bzl` row sees it.
        let mut with_bzl = index.clone();
        with_bzl
            .hooks
            .push(hook("WORKSPACE", HookKind::WorkspaceFile));
        with_bzl.bzl = vec![BzlRow {
            kind: "pinned_archive".to_string(),
            uuid: UUID.to_string(),
            lane: "H-TOY1".to_string(),
        }];
        let over_state =
            |held: &Index, state| found(Some(&record(held)), true, held, Some(state)).0;
        let workspace_unit_gone = Owned {
            hook_in: Some(("WORKSPACE", HookUnit::Absent)),
            ..SOUND
        };
        assert_eq!(over_state(&with_bzl, SOUND), Ok(()));
        assert_eq!(over_state(&with_bzl, workspace_unit_gone), no_hook);
        assert_eq!(over_state(&index, workspace_unit_gone), Ok(()));

        // Under the package label strategy the owned `BUILD.bazel` is
        // what makes the labels of the owned files resolve.
        let mut packaged = index.clone();
        packaged.label_strategy = Some(LabelStrategy::Package);
        let no_build = Owned {
            file_at: Some((OWNED_BUILD_PATH, OwnedFile::Missing)),
            ..SOUND
        };
        assert_eq!(over_state(&packaged, SOUND), Ok(()));
        let missing = stale("owned_file_missing");
        assert_eq!(over_state(&packaged, no_build), missing);
        assert_eq!(over_state(&index, no_build), Ok(()));
    }

    /// A tag edit is keyed by the version it was written for. Once the
    /// hub's lock pins another, the row is `stale_override`, whatever
    /// else holds. And a pin a statement selects, or one in owned pin
    /// data, is withheld while no lane that writes one is enabled; a
    /// `runs` row is a receipt and stands in for no statement.
    #[test]
    fn a_stale_version_key_and_an_unproven_declaration_are_withheld() {
        // The verdict of the gson pin of `lane`, and its common part,
        // over an index `fill` adds rows to, with every owned file sound.
        let found = |lock: &str, lane: &'static str, fill: &dyn Fn(&mut Index)| {
            let mut index = index_of(&[(GSON, UUID, lane, LOCK)]);
            fill(&mut index);
            let (record, pin) = (record(&index), pin_of(GSON, UUID, lane, LOCK));
            let mut files = maven(lock, "");
            files.push((INDEX_PATH, &record[..]));
            let ask = |attest: &Attest<'_>| {
                let verdict = attest.consumer(&Candidate::of_pin(&pin, "", None));
                (
                    attest.common(HubId(0), &pin).map_err(why),
                    verdict.map_err(why),
                )
            };
            over(&files, &TABLE, &index, Some(SOUND), ask)
        };
        let pinned = line(GSON, &patched());
        let keyed = |lock: &str, key: &str| {
            let fill = |index: &mut Index| index.tag_edits = vec![tag_edit("H-TOY1", key)];
            found(lock, "H-TOY1", &fill).0
        };
        for key in ["gson-2.10.1", "gson@2.10.1", "2.10.1"] {
            assert_eq!(keyed(&pinned, key), Ok(()), "{key}");
        }
        let stale = Err((DerivedStale, Some("stale_override")));
        // The key is for another version than the pin's: a shorter or a
        // longer one, a pre-release of it, a suffixed build of it, and
        // one that only ends in it.
        for key in [
            "gson-2.10",
            "gson-12.10.1",
            "gson-2.10.1-rc1",
            "gson-2.10.1-jre",
            "gson2.10.1",
            "-2.10.1",
        ] {
            assert_eq!(keyed(&pinned, key), stale, "{key}");
        }
        // The user bumped the package: the lock pins 2.11.0 now.
        let newer = "pkg:maven/com.google.code.gson/gson@2.11.0";
        let bumped = line(newer, &upstream());
        assert_eq!(keyed(&bumped, "gson-2.10.1"), stale);
        // The lock lists both versions: a key for the other one is the
        // wiring of another release, not of this pin.
        let two = format!("{pinned}{bumped}");
        assert_eq!(keyed(&two, "gson-2.10.1"), Ok(()));
        assert_eq!(keyed(&two, "gson-2.11.0"), stale);
        // The lock lists no version of the package (the pin renamed its
        // own entry): the pin's version alone decides.
        let renamed = line(GUAVA, &upstream());
        assert_eq!(keyed(&renamed, "gson-2.10.1"), Ok(()));
        assert_eq!(keyed(&renamed, "gson-2.9.0"), stale);
        assert_eq!(
            Code::withheld(DerivedStale).as_str(),
            "vex_bazel_derived_stale"
        );
        for (key, version, is_for) in [
            ("rack-2.2.8", "2.2.8", true),
            ("guava-32.0.1-jre", "32.0.1-jre", true),
            ("left-pad@1.3.0-beta.1", "1.3.0-beta.1", true),
            ("left-pad@1.3.0-beta.1", "1.3.0", false),
            ("left-pad-1.0.0-beta.1", "1.0.0", false),
            ("foo-1.0.0-rc.1", "1.0.0", false),
            ("guava-32.0.1-jre", "32.0.1", false),
            ("rack-2.2.8", "v2.2.8", false),
            ("rack-2.2.8", "2.8", false),
            ("rack-2.2.8", "", false),
            // A key that says more than the version is for no version.
            ("six-1.16.0-py2.py3-none-any.whl", "1.16.0", false),
        ] {
            assert_eq!(keyed_for(key, version), is_for, "{key} {version}");
        }

        let verdict = |lane, fill: &dyn Fn(&mut Index)| found(&pinned, lane, fill).1;
        assert_eq!(verdict("H-DECL", &|_| {}), not(NotConsumed));
        let declared =
            |index: &mut Index| index.tag_edits = vec![tag_edit("H-DECL", "gson-2.10.1")];
        assert_eq!(verdict("H-DECL", &declared), not(ConsumerUndetermined));
        // The receipt of a tool run is not a statement that selects.
        let receipt = |index: &mut Index| {
            let output = RunOutput {
                file: "MODULE.bazel.lock".to_string(),
                sha256_after: "f".repeat(64),
            };
            index.runs = vec![RunRow {
                uuid: UUID.to_string(),
                lane: "H-DECL".to_string(),
                tool: "bazel-mod-deps".to_string(),
                actor: Actor::SocketPatch,
                outputs: vec![output],
            }];
        };
        assert_eq!(verdict("H-DECL", &receipt), not(NotConsumed));
        assert_eq!(verdict("H-OWNED", &|_| {}), not(NotConsumed));
        let owned_pin = |index: &mut Index| {
            index.label_strategy = Some(LabelStrategy::Ancestor);
            index.hooks = vec![hook("MODULE.bazel", HookKind::ModuleFile)];
            index.bzl = vec![BzlRow {
                kind: "pinned_archive".to_string(),
                uuid: UUID.to_string(),
                lane: "H-OWNED".to_string(),
            }];
            index.files = vec![FileRow {
                path: ".socket/bazel/pins.json".to_string(),
                sha256: "c".repeat(64),
                uuid: UUID.to_string(),
                lane: "H-OWNED".to_string(),
            }];
        };
        assert_eq!(verdict("H-OWNED", &owned_pin), not(ConsumerUndetermined));

        // The evidence follows the basis and the anchor together. A
        // basis nothing anchors is withheld under a lane whose anchor is
        // a digest (the gate leaves that basis when merged plans
        // disagree). And a lock pin whose lane says a statement selects
        // the bytes is held to that statement: with none on record it is
        // not consumed, and with one it waits for the readers that prove
        // the bytes behind it.
        assert_eq!(verdict("H-WHELD", &|_| {}), not(IntegrityUnanchored));
        assert_eq!(verdict("H-DLOCK", &|_| {}), not(NotConsumed));
        let selecting =
            |index: &mut Index| index.tag_edits = vec![tag_edit("H-DLOCK", "gson-2.10.1")];
        assert_eq!(verdict("H-DLOCK", &selecting), not(ConsumerUndetermined));
    }

    /// The vendored claim: a `--distdir` row provides the pinned bytes,
    /// so the build needs no Socket API. It holds only with the artifact
    /// under the URL's file name and the pinned digest, the owned rc file
    /// and its hook in place, and the URL still allowed.
    #[test]
    fn the_vendored_claim_needs_the_artifact_the_hook_and_an_allowed_url() {
        let (lock, mut index) = gson_pinned();
        let dir = format!(".socket/vendor/maven/{UUID}");
        index.rc_flags = vec![rc_row(RcFlag::Distdir, &dir, "H-TOY1")];
        index.hooks = vec![hook(".bazelrc", HookKind::Bazelrc)];
        let jar = format!("{dir}/gson-2.10.1.jar");
        let gson = pin_of(GSON, UUID, "H-TOY1", LOCK);
        let artifact = VendoredArtifact {
            dir: &dir,
            leaf: "gson-2.10.1.jar",
            digest_is_pinned: true,
            pin_url: "https://patch.socket.dev/maven/tok_fixture_4f1c/gson-2.10.1.jar?x=1",
        };
        let claim_over =
            |rc: &str, owned: Owned, held: &Index, of: &VendoredArtifact<'_>, jar_there: bool| {
                let mut files = maven(&lock, rc);
                files.push(("dl.cfg", "block patch.socket.dev\n"));
                files.extend(jar_there.then_some((&jar[..], "jar")));
                let ask = |attest: &Attest<'_>| attest.vendored_claim(HubId(0), &gson, of);
                let found = over(&files, &TABLE, held, Some(owned), ask);
                let detail = found.as_ref().err().map_or("", |why| why.detail.as_str());
                assert!(!detail.contains("tok_fixture"), "{detail}");
                found.map_err(why)
            };
        let claim = |rc: &str, owned: Owned, held: &Index, of: &VendoredArtifact<'_>| {
            claim_over(rc, owned, held, of, true)
        };
        assert_eq!(claim("", SOUND, &index, &artifact), Ok(()));
        let hook_gone = owned(OwnedFile::Ours, HookUnit::Absent);
        let no_hook = Err((NotConsumed, Some("hook_missing")));
        assert_eq!(claim("", hook_gone, &index, &artifact), no_hook);
        let rc_gone = owned(OwnedFile::Missing, HookUnit::Present);
        let missing = Err((DerivedStale, Some("owned_file_missing")));
        assert_eq!(claim("", rc_gone, &index, &artifact), missing);
        // Bazel looks a distdir file up by the file name of the URL.
        let pin_url = "https://patch.socket.dev/maven/tok_fixture_4f1c/gson.jar";
        let other_name = VendoredArtifact {
            pin_url,
            ..artifact
        };
        assert_eq!(
            claim("", SOUND, &index, &other_name),
            Err((NotConsumed, None))
        );
        let wrong_bytes = VendoredArtifact {
            digest_is_pinned: false,
            ..artifact
        };
        assert_eq!(
            claim("", SOUND, &index, &wrong_bytes),
            Err((DerivedStale, None))
        );
        // The artifact is gone, whatever the caller hashed before.
        let gone = claim_over("", SOUND, &index, &artifact, false);
        assert_eq!(gone, Err((DerivedStale, None)));
        // A blocked URL skips the distdir (probe S11).
        let blocked = "common --downloader_config=dl.cfg\n";
        let config = Err((ConsumerUndetermined, Some("downloader_config")));
        assert_eq!(claim(blocked, SOUND, &index, &artifact), config);
        // The user's own `--distdir` of the directory: which line
        // provides the bytes is then not the owned file's to say.
        let users = format!("common --distdir={dir}\n");
        let conflict = Err((PinBypassed, Some("rc_flag_conflict")));
        assert_eq!(claim(&users, SOUND, &index, &artifact), conflict);
        // No row names the directory.
        let no_row = gson_pinned().1;
        assert_eq!(
            claim("", SOUND, &no_row, &artifact),
            Err((NotConsumed, None))
        );
    }

    /// What the root probe found decides before any hub does (HZ-19): a
    /// confirmed Bazel root above the repository has hubs nobody read,
    /// and of nested roots each builds the project, so the locks of the
    /// other one count although this root has none. The probe's answer
    /// is an argument of [`Attest::read`]: the one-root answer, which
    /// judges the same candidate as it is today, is never a default.
    #[test]
    fn roots_nobody_read_leave_the_consumer_undetermined() {
        let files = [NINE, ("MODULE.bazel", "module(name = \"inner\")\n")];
        let (ws, view) = (read_at(&files, "svc"), Files::of(&files));
        let none = Index::default();
        let verdict = |purl, roots: Roots<'_>| {
            let attest = Attest::read(&ws, &TABLE, &view, &none, roots);
            let candidate = asked(purl, "svc", Basis::Installed);
            attest.consumer(&candidate).map_err(why)
        };
        assert_eq!(verdict(GSON, Roots::One), Ok(Consumed::AsToday));

        let marker = PathBuf::from("/outer/MODULE.bazel");
        let confirmed = true;
        let probe = &Probe::RootOutsideBoundary { marker, confirmed };
        let read_roots: &[Result<BazelWorkspace, Gap>] = &[Ok(ws.clone())];
        let above = Roots::Probed {
            probe,
            read: read_roots,
        };
        let outside = Err((ConsumerUndetermined, Some("bazel_root_outside_repository")));
        assert_eq!(verdict(GSON, above), outside);
        assert_eq!(verdict(COMPOSER, above), Ok(Consumed::AsToday));

        // Nested: the outer root's Maven hub governs its own root
        // project only, and its lock was not listed here.
        let unpatched = line(GSON, &upstream());
        let outer = read_at(&maven(&unpatched, ""), "inner/svc");
        let probe = &Probe::Nested(vec![ws.root.clone(), outer.root.clone()]);
        let read_roots: &[Result<BazelWorkspace, Gap>] = &[Ok(ws.clone()), Ok(outer)];
        let nested = Roots::Probed {
            probe,
            read: read_roots,
        };
        let nested_roots = Err((ConsumerUndetermined, Some("nested_bazel_roots")));
        assert_eq!(verdict(GSON, nested), nested_roots);
        assert_eq!(verdict(LEFT_PAD, nested), Ok(Consumed::AsToday));
    }

    /// The state of a held patch, for every kind of withhold: cannot-tell
    /// is never drift, only the version bump is stale, and the check
    /// fails on drift always and on a stale row only where the lane's
    /// leftover fails the build (owner decision O53).
    #[test]
    fn a_verdict_is_one_state_and_only_drift_always_fails_the_check() {
        let by_bazel = Consumed::ByBazel {
            lane: LaneId("H-TOY1"),
            mode: Mode::Hosted,
            basis: AttestBasis::LockUrl,
        };
        assert_eq!(Held::of(&Ok(by_bazel)), Held::Consumed);
        assert_eq!(Held::of(&Ok(Consumed::AsToday)), Held::NotConsumed);
        for kind in WithholdKind::ALL {
            for token in [None, Some(STALE_OVERRIDE), Some(HOOK_MISSING)] {
                let state = Held::of(&Err(withheld(*kind, token, "why")));
                let expected = match (kind, token) {
                    (WithholdKind::ConsumerUndetermined, _) => Held::NotConsumed,
                    (WithholdKind::RunPending, _) => Held::RunPending,
                    (WithholdKind::DerivedStale, Some(STALE_OVERRIDE)) => Held::Stale,
                    _ => Held::Drift,
                };
                assert_eq!(state, expected, "{kind:?} {token:?}");
            }
        }
        let states = [
            (Held::Consumed, "consumed", false, false),
            (Held::RunPending, "run_pending", false, false),
            (Held::Stale, "stale", false, true),
            (Held::Drift, "drift", true, true),
            (Held::NotConsumed, "not_consumed", false, false),
        ];
        for (state, word, inert, attributed) in states {
            assert_eq!(state.as_str(), word);
            assert_eq!(state.fails_check(StaleBehaviour::Inert), inert, "{word}");
            let fails = state.fails_check(StaleBehaviour::FailsAttributed);
            assert_eq!(fails, attributed, "{word}");
        }
    }
}
