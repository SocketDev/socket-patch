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
//! owned index still describe the workspace. A lane's `attest` adds what
//! only it knows through the three helpers here: [`no_bypass`] over the
//! repositories it names, [`works_after`] with the pin as its repository
//! specs render it, and [`digest_equals_grant`].
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
    HubId, Index, LaneCx, LaneId, LaneOps, LaneSpec, LaneTable, Mode, OwnedWrite, PatchRequest,
    Plan, PlannedWrite, Probe, Reason, Refusal, Ruleset, RunPolicy, Site, VexWithhold,
    WithholdKind,
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
use crate::utils::purl_key::PurlKey;
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
    /// grant (an in-run statement). A digest the hub's lock lists for the
    /// release must then be one of them.
    pub grant: Option<&'a Integrity>,
}

impl<'a> Candidate<'a> {
    /// The candidate of a discovered pin in the project `project_rel`.
    pub fn of_pin(pin: &'a BazelRef, project_rel: &'a str) -> Self {
        Self {
            purl: &pin.purl,
            uuid: &pin.uuid,
            project_rel,
            basis: Basis::Pin(pin),
            grant: None,
        }
    }
}

/// A candidate the Bazel layer does not withhold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumed {
    /// No hub builds the package: the candidate is judged exactly as it
    /// is outside a Bazel workspace.
    AsToday,
    /// The Bazel build consumes the patch through a pin of `lane`. The
    /// proof is of committed files, and it replaces the caller's
    /// installed-tree verification: Bazel reads no host store, so for a
    /// governed NuGet hub neither the global packages folder nor its
    /// stale-package withholding applies. A vendored pin keeps its
    /// committed artifact as the evidence the caller hashes.
    ByBazel { lane: LaneId, basis: AttestBasis },
}

impl Consumed {
    /// Whether the caller still verifies the installed tree.
    pub const fn verifies_installed_tree(self) -> bool {
        matches!(self, Self::AsToday)
    }

    /// Whether the reference must carry a locked digest: always for a
    /// pin the Bazel build consumes (design 7, the bazel-lock row).
    pub const fn integrity_required(self) -> bool {
        matches!(self, Self::ByBazel { .. })
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

/// Whether `key` names `version` as a whole: `rack-2.2.8` names `2.2.8`,
/// and neither `2.2` nor `2.8`.
fn names_version(key: &str, version: &str) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '+';
    !version.is_empty()
        && key.match_indices(version).any(|(at, _)| {
            let (before, after) = (&key[..at], &key[at + version.len()..]);
            !before.ends_with(part) && !after.starts_with(part)
        })
}

/// The package of a purl without its version, as an identity.
fn package_key(purl: &str) -> Option<PurlKey> {
    let (kind, name, _) = purl_parts(purl)?;
    Some(PurlKey::new(&format!("pkg:{kind}/{name}")))
}

/// The pinned digest equals the grant's (design 7): `Ok` only when the
/// digest a lock holds is the patch artifact's, in the lock's own
/// rendering. A digest of another value is `DerivedStale`: it is what a
/// merge or the ruleset's own tooling leaves, and a line with the Socket
/// URL and the upstream hash builds the upstream package from the
/// repository cache (probe Y6). A lock entry with no digest anchors
/// nothing.
pub fn digest_equals_grant(pinned: &LockIntegrity, grant: &Integrity) -> Result<(), VexWithhold> {
    let hex = |found: &str, of: &Option<String>| {
        let of = of.as_deref().filter(|of| !of.is_empty());
        of.is_some_and(|of| of.eq_ignore_ascii_case(found))
    };
    let exact =
        |found: &str, of: &Option<String>| of.as_deref() == Some(found) && !found.is_empty();
    let equal = match pinned {
        LockIntegrity::None => {
            let detail = "the lock records no digest for the pinned package, so nothing the \
                          build enforces says which bytes it fetches";
            return Err(withheld(WithholdKind::IntegrityUnanchored, None, detail));
        }
        LockIntegrity::Sha256Hex(sum) => hex(sum, &grant.sha256),
        // The build accepts any digest of the set, so each must be the
        // patch's.
        LockIntegrity::Sha256AnyOf(sums) => {
            !sums.is_empty() && sums.iter().all(|sum| hex(sum, &grant.sha256))
        }
        LockIntegrity::Sha1Hex(sum) => hex(sum, &grant.sha1),
        LockIntegrity::Sri(sri) => {
            let mut hashes = sri.split_whitespace().peekable();
            hashes.peek().is_some() && hashes.all(|hash| exact(hash, &grant.sha512))
        }
        LockIntegrity::GoH1(sum) => exact(sum, &grant.dirhash_h1),
        LockIntegrity::BerryChecksum(sum) => exact(sum, &grant.yarn_berry10c0),
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
    let (Some(ecosystem), Some((_, name, version))) =
        (Ecosystem::from_purl(&pin.purl), purl_parts(&pin.purl))
    else {
        return Err(undetermined(format!(
            "`{}` names no release of a package",
            pin.purl
        )));
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

/// The committed evidence that ends works-after (design 2.10): every
/// record of every input the lane wrote holds the SHA-256 of the file as
/// found, under every platform key, and each entry of the hub's
/// extensions carries the pin in its `generatedRepoSpecs`. A fresh digest
/// beside old specs is `DerivedStale` (probe L1.d); a record that is
/// behind is `RunPending`.
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
    /// read from. One root, and the owned state of a build that cannot
    /// check an owned file yet ([`Unrendered`]).
    pub fn read(
        ws: &'a BazelWorkspace,
        lanes: &'a LaneTable,
        files: &'a dyn FileView,
        index: &'a Index,
    ) -> Self {
        let text = |rel: &str| files.read(rel).as_str().map(String::from);
        Self {
            ws,
            lanes,
            files,
            index,
            roots: Roots::One,
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
    pub fn contests(&self) -> Vec<Contest<'_>> {
        let mut out = Vec::new();
        for listed in &self.inventory.listed {
            let hub = listed.hub;
            let passing = |pin: &&BazelRef| self.proof(hub, pin, None).is_ok();
            let pins = self.pins_of(hub).into_iter().filter(passing);
            let pins: Vec<BazelRef> = pins.cloned().collect();
            let unpatched = self.inventory.unpatched(hub, &pins).unwrap_or_default();
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
    fn package<'c>(
        &self,
        candidate: &'c Candidate<'c>,
    ) -> Result<Option<Package<'c>>, VexWithhold> {
        let built = |ecosystem: &Ecosystem| {
            let builds = |ruleset: &Ruleset| ruleset.ecosystem() == Some(*ecosystem);
            Ruleset::ALL.iter().any(builds)
        };
        let Some(ecosystem) = Ecosystem::from_purl(candidate.purl).filter(built) else {
            return Ok(None);
        };
        let Some((_, name, version)) = purl_parts(candidate.purl) else {
            let detail = format!("`{}` names no release of a package", candidate.purl);
            return Err(undetermined(detail));
        };
        Ok(Some(Package {
            candidate,
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
    /// mode its basis names and in the file it was read from, and each
    /// such pin must pass its proof.
    fn governed(&self, package: &Package<'_>, hubs: &[HubId]) -> Result<Consumed, VexWithhold> {
        let mode = |pin: &BazelRef| {
            let mut specs = self.lanes.specs();
            specs
                .find(|(_, spec)| spec.id == pin.lane)
                .map(|(_, spec)| spec.mode)
        };
        let wanted = |pin: &BazelRef| match package.candidate.basis {
            // Only an agent lane makes Bazel build from a patched tree
            // (the Go directory replace, `A-GO1`).
            Basis::Installed => mode(pin) == Some(Mode::Agent),
            Basis::Hosted { file } => mode(pin) == Some(Mode::Hosted) && pin.file == file,
            Basis::Vendored { file } => mode(pin) == Some(Mode::Vendored) && pin.file == file,
            Basis::Pin(asked) => pin == asked,
        };
        let mut found: Vec<(HubId, &BazelRef)> = Vec::new();
        for id in hubs {
            let pins = self.pins_in(*id, package).into_iter();
            found.extend(pins.filter(|pin| wanted(pin)).map(|pin| (*id, pin)));
        }
        let Some((_, first)) = found.first().copied() else {
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
        for (id, pin) in &found {
            self.proof(*id, pin, package.candidate.grant)?;
        }
        let proven: Vec<HubId> = found.iter().map(|(id, _)| *id).collect();
        self.every_consumer(package, &proven)?;
        Ok(Consumed::ByBazel {
            lane: first.lane,
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
        let building = self.ws.hubs.iter().filter(|hub| may_build(hub));
        if building.clone().any(|hub| reads(hub, file)) {
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
        let hubs = match self.inventory.resolves(package.candidate.purl) {
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

    /// The discovered pins in a lock of the hub `id` whose lane is of the
    /// hub's family.
    fn pins_of(&self, id: HubId) -> Vec<&BazelRef> {
        let Some(hub) = self.ws.hubs.get(id.0) else {
            return Vec::new();
        };
        let lanes = lanes::family(self.lanes, hub.ruleset).map_or(&[][..], |ops| ops.lanes);
        let own =
            |pin: &&BazelRef| reads(hub, &pin.file) && lanes.iter().any(|spec| spec.id == pin.lane);
        self.discovered.pins.iter().filter(own).collect()
    }

    /// [`Self::pins_of`] for the release and the patch of `package`.
    fn pins_in(&self, id: HubId, package: &Package<'_>) -> Vec<&BazelRef> {
        let (purl, uuid) = (package.candidate.purl, package.candidate.uuid);
        let mut pins = self.pins_of(id);
        pins.retain(|pin| pin.uuid == uuid && PurlKey::same(&pin.purl, purl));
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
    /// `MODULE.bazel.lock`; and the grant's digest.
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
    ) -> Result<(), VexWithhold> {
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
        works_after(self.ws, self.files, &[pin.file.as_str()], &[], None, None)?;
        let Some(grant) = grant else {
            return Ok(());
        };
        // A listing that carries no digest leaves the comparison to the
        // lane, which knows where its lock holds one.
        let listed = self.inventory.listed.iter().filter(|of| of.hub == id);
        let mut entries = listed.flat_map(|of| &of.entries);
        let pinned = entries.find(|entry| PurlKey::same(&entry.purl, &pin.purl));
        match pinned.map(|entry| &entry.integrity) {
            None | Some(LockIntegrity::None) => Ok(()),
            Some(digest) => digest_equals_grant(digest, grant),
        }
    }

    /// A pin beside the user's own patch of the package, on a hub whose
    /// hook runs the host `patch` tool: the gate allows that write under
    /// `--allow-patch-conflicts`, and the hook can then reverse the fix
    /// over the patched tarball with exit 0 (probe P4). Withheld while
    /// the user's entry exists. What socket-patch wrote itself is
    /// subtracted first, by the filter the gate uses.
    fn user_patch_hook(&self, id: HubId, pin: &BazelRef) -> Result<(), VexWithhold> {
        let (Some(ecosystem), Some((_, name, version))) =
            (Ecosystem::from_purl(&pin.purl), purl_parts(&pin.purl))
        else {
            return Ok(());
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
    /// selects nothing once the lock pins another (revision 4, 2.7). A
    /// key that names none of the versions the hub's lock lists for the
    /// package is for a version the build no longer uses. Where the lock
    /// lists none (the pin renamed its own entry), the pin's version is
    /// the one a key must name.
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
        let mut locked: Vec<String> = entries.filter(same).map(|e| e.version.clone()).collect();
        if locked.is_empty() {
            locked.extend(purl_parts(&pin.purl).map(|(_, _, version)| version));
        }
        for row in &rows.tag_edits {
            let Some(key) = row.edit.version_key.as_deref() else {
                continue;
            };
            if !locked.iter().any(|version| names_version(key, version)) {
                let detail = format!(
                    "the edit of `{}` in `{}` is for `{key}`, and the lock now pins `{}`; run \
                     `socket-patch scan`",
                    row.edit.attr,
                    row.edit.file,
                    locked.join("`, `")
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
        Actor, CellClaim, ClaimSystem, Gap, IndexRow, LockRole, StmtRef, TagEdit, TagOp, TextRead,
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

    // ── A toy lane ───────────────────────────────────────────────────

    /// The toy lock: one `<purl> <sha256>` per line. `// ` may stand in
    /// front of one, so that a `go.mod` can carry it. A line `# spoke
    /// <name>` names a repository beside the hub's own that serves a
    /// package, which only a lane knows.
    fn locked(text: &str) -> Vec<(&str, &str)> {
        let lines = text.lines().map(|l| l.strip_prefix("// ").unwrap_or(l));
        let pins = lines.filter(|line| line.starts_with("pkg:"));
        pins.filter_map(|line| line.split_once(' ')).collect()
    }

    fn lock_path<'a>(cx: &'a LaneCx<'_>) -> Option<&'a str> {
        let mut locks = cx.ws.hubs.get(cx.hub.0)?.locks.iter();
        let lock = locks.find(|lock| lock.role == LockRole::PackageLock)?;
        lock.path.as_deref()
    }

    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let text = read(lock_path(cx)?)?;
        let entry = |(purl, digest): (&str, &str)| {
            let (_, name, version) = purl_parts(purl)?;
            Some(LockfileEntry {
                ecosystem: Ecosystem::from_purl(purl)?.cli_name(),
                name,
                version,
                purl: purl.to_string(),
                resolved: None,
                integrity: LockIntegrity::Sha256Hex(digest.to_string()),
                source_kind: SourceKind::Unspecified,
                pnpm_env: false,
            })
        };
        locked(&text).into_iter().map(entry).collect()
    }

    fn basis_of(lane: &str) -> AttestBasis {
        match lane {
            "H-DECL" => AttestBasis::Declared,
            "H-OWNED" => AttestBasis::OwnedPin,
            "H-RCSEL" => AttestBasis::Withheld,
            lane if lane.starts_with("H-") => AttestBasis::LockUrl,
            _ => AttestBasis::LockPath,
        }
    }

    /// Whether the lock holds the digest `row` recorded for its package.
    fn holds(text: &str, row: &IndexRow) -> bool {
        let new = row.edits.first().map(|edit| edit.new.as_str());
        let pinned = |(purl, digest): &(&str, &str)| *purl == row.purl && Some(*digest) == new;
        locked(text).iter().any(pinned)
    }

    /// A pin is a `pins` row of a lane of the asked mode whose digest the
    /// hub's lock still holds.
    fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let lock = lock_path(cx)?;
        let text = read(lock)?;
        let lanes = lanes::family(&TABLE, cx.ws.hubs[cx.hub.0].ruleset)?.lanes;
        let pin = |row: &IndexRow| {
            let own = |spec: &&LaneSpec| spec.id.0 == row.lane && spec.mode == cx.mode;
            Some(pin_of(
                &row.purl,
                &row.uuid,
                lanes.iter().find(own)?.id.0,
                lock,
            ))
        };
        let rows = cx.index.pins.iter();
        let rows = rows.filter(|row| row.file == lock && holds(&text, row));
        Some(rows.filter_map(pin).collect())
    }

    /// The toy consumer proof: the lock holds the digest the row
    /// recorded, and nothing bypasses a repository the lock names as
    /// serving the package.
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
        let spokes = text
            .lines()
            .filter_map(|line| line.strip_prefix("# spoke "));
        no_bypass(cx, pin, pin.lane, &spokes.collect::<Vec<&str>>())
    }

    const CLAIM: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];

    const fn lane(id: &'static str, mode: Mode, anchor: Anchor) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIM,
            anchor,
            ..LaneSpec::stub(id, mode, &[])
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
        ])
    };
    /// The designed lane of `nuget.from_lock`, enabled for the toy proof.
    const NET: LaneOps = LaneOps {
        lanes: &[lane("H-NET2", Mode::Hosted, Anchor::Digest)],
        ..TOY
    };
    /// A family none of whose lanes has landed: it cannot tell its pins.
    const NO_LANE: LaneOps = LaneOps::disabled(&[LaneSpec::stub("H-JS1", Mode::Hosted, &[])]);
    static TABLE: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &TOY),
        (Ruleset::RulesJs, &TOY),
        (Ruleset::Gazelle, &TOY),
        (Ruleset::RulesCsharp, &NET),
    ]);
    static MAVEN_ONLY: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &TOY),
        (Ruleset::RulesJs, &NO_LANE),
    ]);

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
        let (lane, basis) = (LaneId(lane), basis_of(lane));
        Ok(Consumed::ByBazel { lane, basis })
    }

    fn not(kind: WithholdKind) -> Verdict {
        Err((kind, None))
    }

    /// The owned state a test wants the verdict proven over.
    #[derive(Clone, Copy)]
    struct Owned(OwnedFile, HookUnit);
    const SOUND: Owned = Owned(OwnedFile::Ours, HookUnit::Present);

    impl OwnedState for Owned {
        fn file(&self, _: &str) -> OwnedFile {
            self.0
        }

        fn hook(&self, _: &HookRow) -> HookUnit {
            self.1
        }
    }

    /// Asks over the root that holds `files`, read for its root project,
    /// with `index` as its owned index and `owned` as its owned state
    /// (`None`: the state of this build).
    fn over<T>(
        files: &[(&str, &str)],
        lanes: &'static LaneTable,
        index: &Index,
        owned: Option<Owned>,
        ask: impl FnOnce(&Attest<'_>) -> T,
    ) -> T {
        let (ws, view) = (read(files), Files::of(files));
        let mut attest = Attest::read(&ws, lanes, &view, index);
        if let Some(owned) = owned {
            attest.owned = Box::new(owned);
        }
        ask(&attest)
    }

    fn judge(files: &[(&str, &str)], index: &Index, candidate: &Candidate<'_>) -> Verdict {
        let verdict = |attest: &Attest<'_>| attest.consumer(candidate).map_err(why);
        over(files, &TABLE, index, None, verdict)
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

    // ── The five over-attestation paths (F110) ───────────────────────

    /// P1: a hosted reference in a file no hub reads. A `pom.xml` pin
    /// beside an unpatched `maven_install.json` is not attested, and the
    /// hub's unpatched entry is what contests it in any project. So is a
    /// reference in a sibling lock (`package-lock.json` beside the
    /// governed `pnpm-lock.yaml`).
    #[test]
    fn a_reference_in_a_file_no_hub_reads_is_not_consumed() {
        let contested = |files: &[(&str, &str)], index: &Index| {
            let purls = |attest: &Attest<'_>| {
                let contests = attest.contests();
                let found = contests.iter().map(|c| (c.hub, c.entry.purl.clone()));
                found.collect::<Vec<_>>()
            };
            over(files, &TABLE, index, None, purls)
        };
        let unpatched = line(GSON, &upstream());
        let (files, none) = (maven(&unpatched, ""), Index::default());
        let pom = asked(GSON, "", hosted("pom.xml"));
        assert_eq!(judge(&files, &none, &pom), not(NotConsumed));
        assert_eq!(
            Code::withheld(NotConsumed).as_str(),
            "vex_bazel_not_consumed"
        );
        assert_eq!(contested(&files, &none), [(HubId(0), GSON.to_string())]);

        // With the hub's lock pinned the `pom.xml` reference is still a
        // file Bazel does not read; the pin in the lock is what counts,
        // and nothing is left to contest.
        let (lock, index) = gson_pinned();
        let files = maven(&lock, "");
        assert_eq!(judge(&files, &index, &pom), not(NotConsumed));
        assert_eq!(
            judge(&files, &index, &asked(GSON, "", hosted(LOCK))),
            by("H-TOY1")
        );
        assert_eq!(contested(&files, &index), []);

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
            let verdict = |attest: &Attest<'_>| attest.consumer(candidate).map_err(why);
            over(&files, &lanes::PRODUCTION, index, None, verdict)
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
        let attest = Attest::read(&ws, &TABLE, &view, &none);
        let pom = asked(GSON, "", hosted("pom.xml"));
        assert!(!attest.assume_applied(&pom, &[]));
        assert!(!attest.assume_applied(&pom, &[UUID_B]));
        assert!(attest.assume_applied(&pom, &[UUID]));
        // Not governed there, and never governed: as today.
        let sub = asked(GSON, "service-a", hosted("service-a/pom.xml"));
        assert!(attest.assume_applied(&sub, &[]));
        assert!(attest.assume_applied(&asked(COMPOSER, "", Basis::Installed), &[]));

        let tree = ".m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar";
        let with_tree = Files::of(&files).with(tree, FileText::Bytes(b"patched".to_vec()));
        let spy = Spy(&with_tree, RefCell::new(Vec::new()));
        let spied = Attest::read(&ws, &TABLE, &spy, &none);
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
    /// name is a bypass. And a hub of another ecosystem whose family
    /// cannot tell its pins holds nothing up.
    #[test]
    fn a_pin_is_held_to_every_lock_of_its_ecosystem_and_to_the_lanes_repositories() {
        let (lock, index) = gson_pinned();
        let gson = pin_of(GSON, UUID, "H-TOY1", LOCK);
        let pin = Candidate::of_pin(&gson, "");
        assert_eq!(judge(&maven(&lock, ""), &index, &pin), by("H-TOY1"));

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
        let attest = Attest::read(&ws, &TABLE, &spy, &index);
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

    /// A hosted Go pin while a tracked `--repo_env` turns a host cache of
    /// `go_repository` on has no digest the build enforces. An agent pin
    /// (the directory replace) is what an installed tree counts through.
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
        // agent lane's pin and through no other.
        assert_eq!(
            verdict(host_cache, "A-TOY1", Basis::Installed),
            by("A-TOY1")
        );
        assert_eq!(verdict("", "H-TOY1", Basis::Installed), not(NotConsumed));
    }

    // ── Works-after evidence and the grant's digest ──────────────────

    /// The evidence that ends works-after, over the locks Bazel 9.3.2
    /// wrote in probe L1: the refreshed lock holds, the first lock is
    /// pending, and the forged one (a fresh digest beside repository
    /// specs from before the pin) is `vex_bazel_derived_stale`.
    #[test]
    fn a_forged_lock_entry_is_derived_stale() {
        let locks = [
            (
                "updated",
                fixture!("stale-repair/bazel-9.3.2/updated.MODULE.bazel.lock"),
            ),
            (
                "baseline",
                fixture!("stale-repair/bazel-9.3.2/baseline.MODULE.bazel.lock"),
            ),
            (
                "forged",
                fixture!("stale-repair/bazel-9.3.2/forged.MODULE.bazel.lock"),
            ),
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
        let recorded = |digest: &str| {
            let before =
                "@@//dep.lock d5ff49e00557218f35cea7c897116dca4732b5c31013f1c86382ca9bdc680ac4";
            assert!(locks[0].1.contains(before));
            let module_lock = locks[0].1.replace(before, &format!("@@//{LOCK} {digest}"));
            let mut files = maven(&lock, "");
            files.push(("MODULE.bazel.lock", &module_lock[..]));
            judge(&files, &index, &asked(GSON, "", hosted(LOCK)))
        };
        assert_eq!(recorded(&sha256_hex_of(lock.as_bytes())), by("H-TOY1"));
        assert_eq!(recorded(&sha256_hex_of(b"before the pin")), not(RunPending));
    }

    /// A lockfile fact for the package never withholds: the lock of
    /// probe L3 still holds the `six` fact that the pin made stale, and
    /// the evidence holds, because a fact is no part of it.
    #[test]
    fn a_pip_fact_for_the_package_does_not_withhold() {
        let six = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
        let files = [
            NINE,
            ("MODULE.bazel", fixture!("facts/pip-v2/root.MODULE.bazel")),
            (
                "MODULE.bazel.lock",
                fixture!("facts/pip-v2/baseline.MODULE.bazel.lock"),
            ),
        ];
        let (ws, view) = (read(&files), Files::of(&files));
        let pip = ExtRef::new("//python/extensions:pip.bzl", "pip").expect("a label");
        let (index_url, package) = ("https://pypi.org/simple", "six");
        let facts = FactsEdit {
            extension: pip,
            of: FactsOf::Pip { index_url, package },
            removed: &[six],
            added: &[],
        };
        let edit = Edit {
            writes: &[Write::changed("requirements_lock.txt")],
            facts: Some(facts),
            ..Edit::default()
        };
        let stale = stale(&ws.module_lock, &edit);
        let fact = matches!(&stale[..], [DerivedState::Facts { .. }]);
        assert!(fact, "the fact is in the lock and may be stale: {stale:?}");
        let inputs = ["requirements_lock.txt"];
        assert_eq!(
            works_after(&ws, &view, &inputs, &[pip], Some(six), None),
            Ok(())
        );
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
    /// no digest, is never attested.
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
            let mut found = vec![judge(&files, &index, &Candidate::of_pin(&pin, ""))];
            files.pop();
            found.push(judge(&files, &index, &Candidate::of_pin(&pin, "")));
            files[3] = (".bazelrc", "");
            found.push(judge(&files, &index, &Candidate::of_pin(&pin, "")));
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
        // The common part and the verdict of the gson pin, which has the
        // segment row; and whether the guava pin, which has none, stands.
        let found = |record: Option<&str>, segment: bool, held: &Index, owned: Option<Owned>| {
            let mut files = maven(&lock, "");
            files.extend(record.map(|record| (INDEX_PATH, record)));
            files.extend(segment.then_some((OWNED_SEGMENT_PATH, "\"\"\"Socket.\"\"\"\n")));
            let ask = |attest: &Attest<'_>| {
                let other = Candidate {
                    uuid: UUID_B,
                    ..Candidate::of_pin(&guava, "")
                };
                let stands = attest.common(HubId(0), &guava) == Ok(())
                    && attest.consumer(&other).map_err(why) == by("H-TOY1");
                let verdict = attest.consumer(&Candidate::of_pin(&gson, ""));
                let common = attest.common(HubId(0), &gson).map_err(why);
                (common, verdict.map_err(why), stands)
            };
            over(&files, &TABLE, held, owned, ask)
        };
        let state = |file, unit| found(Some(&written), true, &index, Some(Owned(file, unit)));
        for file in [OwnedFile::Ours, OwnedFile::Reformatted] {
            assert_eq!(state(file, HookUnit::Present), (Ok(()), by("H-TOY1"), true));
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
            assert_eq!(state(file, unit), expected, "{file:?} {unit:?}");
        }
        // This build compares no owned file with its rows: the segment
        // pin is undetermined, and missing once the file is gone.
        let unchecked = Err((ConsumerUndetermined, None));
        let expected = (unchecked.map(|_: Consumed| ()), unchecked, true);
        assert_eq!(found(Some(&written), true, &index, None), expected);
        let gone = found(Some(&written), false, &index, None);
        assert_eq!(gone.0, Err((DerivedStale, Some("owned_file_missing"))));

        // The index itself: gone, edited, mangled; and no hook row.
        let common = |record: Option<&str>, held: &Index| found(record, true, held, Some(SOUND)).0;
        let stale = |token| Err((DerivedStale, Some(token)));
        assert_eq!(common(None, &index), stale("owned_file_missing"));
        let edited = written.replace("socket_patch_gson", "socket_patch_other");
        assert_eq!(common(Some(&edited), &index), stale("owned_file_modified"));
        let mangled = "{\"pins\": [], \"ignoreLines\": [}";
        assert_eq!(common(Some(mangled), &index), stale("owned_file_modified"));
        let mut unhooked = index.clone();
        (unhooked.hooks, unhooked.label_strategy) = (Vec::new(), None);
        let no_hook = Err((NotConsumed, Some("hook_missing")));
        assert_eq!(common(Some(&record(&unhooked)), &unhooked), no_hook);
    }

    /// A tag edit is keyed by the version it was written for. Once the
    /// hub's lock pins another, the row is `stale_override`, whatever
    /// else holds. And a pin a statement selects, or one in owned pin
    /// data, is withheld while no lane that writes one is enabled; a
    /// `runs` row is a receipt and stands in for no statement.
    #[test]
    fn a_stale_version_key_and_an_unproven_declaration_are_withheld() {
        let tag_edit = |lane: &str, key: &str| TagEditRow {
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
        };
        // The verdict of the gson pin of `lane`, and its common part,
        // over an index `fill` adds rows to, with every owned file sound.
        let found = |lock: &str, lane: &'static str, fill: &dyn Fn(&mut Index)| {
            let mut index = index_of(&[(GSON, UUID, lane, LOCK)]);
            fill(&mut index);
            let (record, pin) = (record(&index), pin_of(GSON, UUID, lane, LOCK));
            let mut files = maven(lock, "");
            files.push((INDEX_PATH, &record[..]));
            let ask = |attest: &Attest<'_>| {
                let verdict = attest.consumer(&Candidate::of_pin(&pin, ""));
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
        assert_eq!(keyed(&pinned, "gson-2.10.1"), Ok(()));
        let stale = Err((DerivedStale, Some("stale_override")));
        // The key is for a version the lock does not pin.
        assert_eq!(keyed(&pinned, "gson-2.10"), stale);
        assert_eq!(keyed(&pinned, "gson-12.10.1"), stale);
        // The user bumped the package: the lock pins 2.11.0 now.
        let bumped = line("pkg:maven/com.google.code.gson/gson@2.11.0", &upstream());
        assert_eq!(keyed(&bumped, "gson-2.10.1"), stale);
        assert_eq!(
            Code::withheld(DerivedStale).as_str(),
            "vex_bazel_derived_stale"
        );
        assert!(names_version("six-1.16.0-py2.py3-none-any.whl", "1.16.0"));
        assert!(!names_version("six-1.16.0-py2.py3-none-any.whl", "1.16"));
        assert!(!names_version("rack-2.2.8", ""));

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
        let claim = |rc: &str, owned: Owned, held: &Index, of: &VendoredArtifact<'_>| {
            let mut files = maven(&lock, rc);
            files.extend([(&jar[..], "jar"), ("dl.cfg", "block patch.socket.dev\n")]);
            let ask = |attest: &Attest<'_>| attest.vendored_claim(HubId(0), &gson, of);
            let found = over(&files, &TABLE, held, Some(owned), ask);
            let detail = found.as_ref().map_or("", |()| "").to_string()
                + found.as_ref().err().map_or("", |why| why.detail.as_str());
            assert!(!detail.contains("tok_fixture"), "{detail}");
            found.map_err(why)
        };
        assert_eq!(claim("", SOUND, &index, &artifact), Ok(()));
        let hook_gone = Owned(OwnedFile::Ours, HookUnit::Absent);
        let no_hook = Err((NotConsumed, Some("hook_missing")));
        assert_eq!(claim("", hook_gone, &index, &artifact), no_hook);
        let rc_gone = Owned(OwnedFile::Missing, HookUnit::Present);
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
        // A blocked URL skips the distdir (probe S11).
        let blocked = "common --downloader_config=dl.cfg\n";
        let config = Err((ConsumerUndetermined, Some("downloader_config")));
        assert_eq!(claim(blocked, SOUND, &index, &artifact), config);
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
    /// other one count although this root has none.
    #[test]
    fn roots_nobody_read_leave_the_consumer_undetermined() {
        let files = [NINE, ("MODULE.bazel", "module(name = \"inner\")\n")];
        let (ws, view) = (read_at(&files, "svc"), Files::of(&files));
        let none = Index::default();
        let verdict = |purl, roots: Roots<'_>| {
            let mut attest = Attest::read(&ws, &TABLE, &view, &none);
            attest.roots = roots;
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
}
