//! The Bazel extractor (design 7 and HZ-15; revision 4, sections 3 and 4):
//! `vex` speaks for a Bazel build only through a pin in a file a live hub
//! reads, on a proof from committed files.
//!
//! It is a thin layer over `bazel::attest` and adds no rule of its own,
//! and none per basis: [`Judge`] hands a candidate to `Attest::consumer`
//! and takes `Ok` or a withhold back. Two callers share it, so that a
//! reference and a record of one patch get one verdict:
//!
//! - [`extract`], the last extractor of lockfile discovery. Under a Bazel
//!   root it turns the pins `lanes::discover` finds in a lock only Bazel
//!   reads into references, and judges every reference discovery found. A
//!   reference the Bazel build does not provably consume stays a reference
//!   (`list`, `rollback` and `remove` still find the wiring) and gets an
//!   [`Unattested`] mark, which `vex` omits at plan level: nothing is
//!   hashed here, so `--no-verify` skips none of it.
//! - the CLI's gate (`bazel_gate::vex`), for a record that no file of the
//!   project wires: agent mode's manifest record, a ledger record. It
//!   builds the same [`Judge`] over what its loader read.
//!
//! # What is read, and how
//!
//! A project with no Bazel boundary file at or above it costs the
//! stat-only root probe: no file is opened and nothing is added to the
//! discovery. An in-memory project has no disk to probe and is left to the
//! in-memory engine, which reads the workspace itself. Under a root nothing
//! is read either while there is nothing to judge: no reference, and no
//! enabled lane that could have written a pin.
//!
//! The workspace model is read from the disk, through the bounded,
//! link-aware reader every caller uses (`crawlers::bazel_workspace`). The
//! files a verdict is then decided from (the hub locks, the owned index and
//! what its rows name) are the bytes of the discovery's own view, so a
//! discovery over a pending rewrite sees a lock as the rewrite leaves it
//! ([`CtxView`]).
//!
//! Those reads are not swept for Socket identities, on purpose. A sweep
//! makes discovery the authority for every patch a file mentions, and a
//! mention that no reference accounts for is contested wiring, which
//! `rollback`, `remove` and `list` refuse around. A lock only Bazel reads
//! is accounted for by its lane alone, and while that lane cannot tell its
//! pins, "cannot tell" must not read as "rejected". A pin a lane does find
//! is recognized like any other, through its reference.
//!
//! # What is not done
//!
//! A hub lock that resolves a release unpatched is not reported as
//! "resolved elsewhere". That report makes a native reference to the same
//! release contested, and the management commands refuse around contested
//! wiring: a `pom.xml` pin an earlier release wrote could no longer be
//! rolled back, and no command would clear the contest. The verdict covers
//! the case in every project of the workspace (`Attest::consumer` holds a
//! reference in a project no hub governs to every hub lock that resolves
//! the release), so the statement is withheld and the wiring stays
//! manageable.
//!
//! `Attest::contests` is the list that report would be made from. It has
//! no caller here and is kept for the hosted lanes: the first of them
//! brings the command that clears a Bazel contest (a pin in the hub's own
//! lock), and only then may a contest be reported.
//!
//! The pin of a vendored or an agent lane becomes no reference: a
//! reference names a hosted URL or a vendored artifact, and a pin carries
//! neither. The record of such a patch is judged through the pin
//! ([`Judge::record`]), and so is a vendor ledger entry that says the owned
//! index of a Bazel root wires its artifact ([`Judge::pinned`]). A pin in a
//! file outside the project is no reference of the project either: its
//! management commands must not unwind a file of another project.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use super::{DiscoverCtx, Discovery, PatchedRef, Unattested, UnattestedKind, WiringMode};
use crate::bazel::attest::{Attest, Basis, Candidate, Consumed};
use crate::bazel::exec::IndexFault;
use crate::bazel::gate::{Roots, OWNED_FILE_MODIFIED};
use crate::bazel::model::{
    BazelRef, BazelWorkspace, FileText, FileView, Gap, Governance, Index, LaneTable, Mode, Probe,
    RootRef, VexWithhold, WithholdKind,
};
use crate::bazel::owned_index::{self, Parsed, INDEX_PATH};
use crate::bazel::{govern, lanes};
use crate::crawlers::bazel_root::{RootProbe, BOUNDARY_FILES};
use crate::crawlers::bazel_workspace::{read_workspace, DiskView, MAX_FILE_BYTES};
use crate::crawlers::Ecosystem;
use crate::patch::redirect::Integrity;
use crate::utils::purl_key::{canonical_base_purl, PurlKey};
use crate::utils::repo_root::{ReadBoundary, ReadScope};
use crate::vendor::lock_inventory::{LockIntegrity, ProjectView};

/// What a caller knows of a Bazel build beyond the committed files.
#[derive(Clone, Copy)]
pub struct BazelOptions<'a> {
    /// `lanes::PRODUCTION` from every command; a test may pass a table
    /// with a toy lane, which the shipped binary cannot reach.
    pub lanes: &'a LaneTable,
    /// The grants this run holds, by patch UUID (an in-run statement):
    /// every digest a hub's lock lists for the release must then be the
    /// grant's. Without one (offline `vex`) a hosted pin attests only on a
    /// digest that committed state records.
    pub grants: &'a [(String, Integrity)],
}

impl Default for BazelOptions<'_> {
    fn default() -> Self {
        Self {
            lanes: &lanes::PRODUCTION,
            grants: &[],
        }
    }
}

/// The Bazel roots of one project as somebody read them: the discovery
/// through its own view, the CLI through its loader.
#[derive(Clone, Copy)]
pub struct Read<'a> {
    /// The root probe's answer for the project.
    pub probe: &'a Probe,
    /// What `detect` returned for each root inside the read boundary,
    /// nearest the project first, each read for the project.
    pub models: &'a [Result<BazelWorkspace, Gap>],
    /// The files and the owned index of the nearest root. `None` where no
    /// root lies inside the read boundary.
    pub nearest: Option<(&'a dyn FileView, Result<&'a Index, &'a IndexFault>)>,
}

/// The index of a root whose index file cannot be relied on: no row.
fn no_rows() -> &'static Index {
    static EMPTY: OnceLock<Index> = OnceLock::new();
    EMPTY.get_or_init(Index::default)
}

/// The detail of a withheld statement as a note prints it: the sentence,
/// and the token that names the case where it has one.
pub fn withheld_detail(withheld: &VexWithhold) -> String {
    match withheld.token {
        Some(token) => format!("{} (`{token}`)", withheld.detail),
        None => withheld.detail.clone(),
    }
}

/// The withhold of a pin whose committed artifact has no ledger record:
/// a vendored pin keeps its artifact as the sole evidence, hashed against
/// the record, so with no record nothing holds the bytes Bazel builds from
/// to the patch.
pub fn no_artifact_record() -> VexWithhold {
    let detail =
        "the Bazel build takes the patch from a committed artifact, and the vendor ledger \
                  records none for it, so the bytes cannot be held to the patch; run \
                  `socket-patch repair`";
    VexWithhold {
        kind: WithholdKind::IntegrityUnanchored,
        token: None,
        detail: detail.to_string(),
    }
}

/// `view_rel`, a path relative to the project, as a path relative to the
/// Bazel root the project lies `base` below. A `..` that climbs out of the
/// root stays in front, which is how a root-relative path names a file
/// above the root.
fn under_root(base: &str, view_rel: &str) -> String {
    let mut path: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    for segment in view_rel.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." if path.last().is_some_and(|last| *last != "..") => drop(path.pop()),
            name => path.push(name),
        }
    }
    path.join("/")
}

/// The root-relative `rel` as a path relative to the project `base` below
/// the root: the inverse of [`under_root`].
fn under_project(base: &str, rel: &str) -> String {
    let base: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    let rel: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    let shared = base.iter().zip(&rel).take_while(|(a, b)| a == b).count();
    let up = std::iter::repeat_n("..", base.len() - shared);
    up.chain(rel[shared..].iter().copied())
        .collect::<Vec<_>>()
        .join("/")
}

/// The consumer verdicts of one project (the table of design 7), decided
/// from committed files alone.
pub struct Judge<'a> {
    /// `None` where no model of the nearest root could be read.
    attest: Option<Attest<'a>>,
    probe: &'a Probe,
    models: &'a [Result<BazelWorkspace, Gap>],
    fault: Option<&'a IndexFault>,
    opts: BazelOptions<'a>,
}

impl<'a> Judge<'a> {
    /// Lists the hub locks and discovers the pins of the nearest root.
    pub fn new(read: &Read<'a>, opts: BazelOptions<'a>) -> Self {
        let model = read.models.first().and_then(|model| model.as_ref().ok());
        let roots = Roots::Probed {
            probe: read.probe,
            read: read.models,
        };
        let attest = model.zip(read.nearest).map(|(ws, (files, index))| {
            let index = index.unwrap_or_else(|_| no_rows());
            Attest::read(ws, opts.lanes, files, index, roots)
        });
        Self {
            attest,
            probe: read.probe,
            models: read.models,
            fault: read.nearest.and_then(|(_, index)| index.err()),
            opts,
        }
    }

    /// Where the project lies below the nearest root.
    fn base(&self) -> &str {
        let attest = self.attest.as_ref();
        attest.map_or("", |attest| attest.ws.root.project_rel.as_str())
    }

    /// Whether the Bazel build consumes the patch `uuid` of `purl`, for a
    /// candidate that rests on `basis`.
    pub fn consumer(
        &self,
        purl: &str,
        uuid: &str,
        basis: Basis<'_>,
    ) -> Result<Consumed, VexWithhold> {
        let Some(attest) = &self.attest else {
            return self.unread(purl);
        };
        let held = self.opts.grants.iter().find(|(of, _)| of == uuid);
        let candidate = Candidate {
            purl,
            uuid,
            project_rel: self.base(),
            basis,
            grant: held.map(|(_, grant)| grant),
        };
        let verdict = attest.consumer(&candidate);
        match self.fault {
            // The pins the index records are not known, so neither is what
            // any hub builds from them. Only "no hub builds the package"
            // stands without the index.
            Some(fault) if verdict != Ok(Consumed::AsToday) => Err(VexWithhold {
                kind: WithholdKind::ConsumerUndetermined,
                token: Some(OWNED_FILE_MODIFIED),
                detail: format!("{fault}, so the pins it records are not known"),
            }),
            _ => verdict,
        }
    }

    /// The verdict where no model of the nearest root was read: the root
    /// probe's answer decides alone. A workspace above the repository, or
    /// one whose files cannot be read, leaves every ecosystem a ruleset
    /// can build undetermined; unreadable is never "not Bazel".
    fn unread(&self, purl: &str) -> Result<Consumed, VexWithhold> {
        let Some(ecosystem) = Ecosystem::from_purl(&canonical_base_purl(purl)) else {
            return Ok(Consumed::AsToday);
        };
        let gaps = match govern::governance_over(self.probe, self.models, ecosystem) {
            Governance::NotGoverned => return Ok(Consumed::AsToday),
            Governance::Undetermined(gaps) => gaps,
            _ => Vec::new(),
        };
        let token = gaps.first().map(|gap| gap.token);
        let details: Vec<&str> = gaps.iter().map(|gap| gap.detail.as_str()).collect();
        let detail = match details.is_empty() {
            true => "the Bazel workspace of this project could not be read, so the lock Bazel \
                     builds this ecosystem from is not known"
                .to_string(),
            false => details.join("; "),
        };
        Err(VexWithhold {
            kind: WithholdKind::ConsumerUndetermined,
            token,
            detail,
        })
    }

    /// The verdict of a patch that files of the project wire: the mode and
    /// the project-relative file of each reference. One reference the
    /// build consumes carries the patch; a second one in a file no hub
    /// reads attests nothing and takes nothing away. With no reference it
    /// is [`Self::record`].
    pub fn wired(
        &self,
        purl: &str,
        uuid: &str,
        wiring: &[(WiringMode, &str)],
    ) -> Result<Consumed, VexWithhold> {
        let mut first = None;
        for (mode, file) in wiring {
            let file = under_root(self.base(), file);
            let basis = match mode {
                WiringMode::Hosted => Basis::Hosted { file: &file },
                WiringMode::Vendored => Basis::Vendored { file: &file },
            };
            match self.consumer(purl, uuid, basis) {
                Ok(consumed) => return Ok(consumed),
                Err(why) => drop(first.get_or_insert(why)),
            }
        }
        first.map_or_else(|| self.record(purl, uuid), Err)
    }

    /// The verdict of the pins discovery holds for the patch `uuid` of
    /// `purl`, whatever lane wrote them: the first one the build consumes,
    /// else the first withhold. `None` where it holds none: no file the
    /// Bazel build reads carries a pin of the patch, or no enabled lane
    /// can tell.
    ///
    /// This is the whole verdict of a vendor ledger entry whose record
    /// says the owned index of a Bazel root wires its artifact
    /// (`WiringRecord::bazel_index`): no file of the project wires it, and
    /// no installed tree stands in for a committed artifact.
    pub fn pinned(&self, purl: &str, uuid: &str) -> Option<Result<Consumed, VexWithhold>> {
        let Some(attest) = &self.attest else {
            // Nobody listed a pin. Where a ruleset may build the
            // ecosystem that is "not known", as for every other candidate.
            return self.unread(purl).err().map(Err);
        };
        let key = canonical_base_purl(purl);
        let found = attest.discovered.pins.iter();
        let own = found.filter(|pin| pin.uuid == uuid && PurlKey::same(&pin.purl, &key));
        let mut first = None;
        for pin in own {
            match self.consumer(purl, uuid, Basis::Pin(pin)) {
                Ok(consumed) => return Some(Ok(consumed)),
                Err(why) => drop(first.get_or_insert(why)),
            }
        }
        first.map(Err)
    }

    /// The verdict of a record that no file of the project wires (agent
    /// mode's manifest record, a ledger record). Where discovery holds a
    /// pin of the patch, the candidate is that pin ([`Self::pinned`]), so
    /// a pin an agent lane or a route wrote is judged as the pin it is and
    /// one patch gets one statement or one withhold. Only with no pin is
    /// it a patched installed tree, which says nothing about a build that
    /// fetches from a lock.
    pub fn record(&self, purl: &str, uuid: &str) -> Result<Consumed, VexWithhold> {
        let withheld = match self.pinned(purl, uuid) {
            Some(Ok(consumed)) => return Ok(consumed),
            Some(Err(why)) => Some(why),
            None => None,
        };
        // In a project no hub governs, a pin elsewhere under the root is no
        // wiring of the project, and the tree is judged as it is today
        // (against every hub lock that resolves the release). Where a hub
        // governs, the withhold is the pin's.
        match (withheld, self.consumer(purl, uuid, Basis::Installed)) {
            (Some(why), Err(_)) => Err(why),
            (_, verdict) => verdict,
        }
    }

    /// The pins of hosted lanes in files of the project, as the references
    /// they are: what makes a lock only Bazel reads (`maven_install.json`,
    /// a requirements file a label names) visible to every reader of
    /// discovery. The digest is the one the hub's listing holds for the
    /// release, and a reference without one never uses the lockfile basis.
    fn references(&self) -> Vec<(PatchedRef, &BazelRef)> {
        let Some(attest) = &self.attest else {
            return Vec::new();
        };
        let mode = |pin: &BazelRef| {
            let mut specs = self.opts.lanes.specs();
            specs.find_map(|(_, spec)| (spec.id == pin.lane).then_some(spec.mode))
        };
        let mut out = Vec::new();
        for (hub, pin) in &attest.discovered.by_hub {
            let file = under_project(self.base(), &pin.file);
            if file.starts_with("..") || mode(pin) != Some(Mode::Hosted) {
                continue;
            }
            let listed = attest.inventory.listed.iter().filter(|of| of.hub == *hub);
            let mut entries = listed.flat_map(|of| &of.entries);
            let entry = entries.find(|entry| PurlKey::same(&entry.purl, &pin.purl));
            let digest = entry.map(|entry| entry.integrity.clone());
            let digest = digest.filter(|digest| *digest != LockIntegrity::None);
            let (purl, uuid) = (pin.purl.clone(), pin.uuid.clone());
            out.push((
                PatchedRef::hosted(purl, uuid, &file, None, digest, true),
                pin,
            ));
        }
        out
    }
}

impl UnattestedKind {
    /// The mark of a statement the Bazel layer withholds for `kind`.
    pub fn of_withheld(kind: WithholdKind) -> Self {
        match kind {
            WithholdKind::NotConsumed => Self::BazelNotConsumed,
            WithholdKind::ConsumerUndetermined => Self::BazelConsumerUndetermined,
            WithholdKind::PinBypassed => Self::BazelPinBypassed,
            WithholdKind::DerivedStale => Self::BazelDerivedStale,
            WithholdKind::RunPending => Self::BazelRunPending,
            WithholdKind::SelectionUnproven => Self::BazelSelectionUnproven,
            WithholdKind::IntegrityUnanchored => Self::BazelIntegrityUnanchored,
        }
    }

    /// The withhold kind a mark of the Bazel layer stands for; `None` for
    /// every other mark.
    pub fn withheld(self) -> Option<WithholdKind> {
        let of = |kind: &&WithholdKind| Self::of_withheld(**kind) == self;
        WithholdKind::ALL.iter().find(of).copied()
    }
}

/// One Bazel root as a discovery reads it: the disk, behind the bounds of
/// [`DiskView`], with the bytes of the discovery's own view in front where
/// the two differ (a pending rewrite laid over the project).
struct CtxView<'a> {
    disk: &'a DiskView,
    over: HashMap<String, FileText>,
    /// The paths read since they were last held against the view.
    asked: Mutex<BTreeSet<String>>,
    settled: BTreeSet<String>,
}

impl FileView for CtxView<'_> {
    fn read(&self, rel: &str) -> FileText {
        if let Some(over) = self.over.get(rel) {
            return over.clone();
        }
        let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
        asked.insert(rel.to_string());
        self.disk.read(rel)
    }

    // A pending rewrite replaces files a lane reads by name; what a scan
    // of the packages finds is the disk's.
    fn list(&self, dir: &str) -> Option<Vec<String>> {
        self.disk.list(dir)
    }
}

impl CtxView<'_> {
    /// Holds every file read since the last call against the bytes the
    /// discovery's view has for it, and takes the view's where they
    /// differ. `true` when one did, and the verdicts are to be decided
    /// again. A view of the plain disk holds what the disk holds.
    async fn settle(&mut self, ctx: &DiscoverCtx<'_>, base: &str) -> bool {
        let asked = std::mem::take(self.asked.get_mut().unwrap_or_else(PoisonError::into_inner));
        if matches!(ctx.view, ProjectView::Disk(_)) {
            return false;
        }
        let mut changed = false;
        for rel in asked {
            if !self.settled.insert(rel.clone()) {
                continue;
            }
            // A path the view refuses or cannot read keeps the disk's
            // answer, which is bounded the same way.
            let Ok(bytes) = ctx.view.read_bytes(&under_project(base, &rel)).await else {
                continue;
            };
            let within = bytes.len() as u64 <= MAX_FILE_BYTES;
            let via = FileText::Bytes(bytes);
            if within && via != self.disk.read(&rel) {
                self.over.insert(rel, via);
                changed = true;
            }
        }
        changed
    }
}

/// What the stat-only probe found for a discovery's project, and each root
/// inside the read boundary read for the project.
struct Loaded {
    probe: Probe,
    roots: Vec<RootRef>,
    views: Vec<DiskView>,
    models: Vec<Result<BazelWorkspace, Gap>>,
}

/// `None` under no Bazel root, and for a project with no disk: nothing was
/// opened.
fn load(ctx: &DiscoverCtx<'_>) -> Option<Loaded> {
    // The boundary files of the project root are what a recording of the
    // view has to hold; the ancestors are no file of the project.
    let dir = ctx.disk_root_reading(BOUNDARY_FILES)?;
    let probe = RootProbe::new();
    // Asked without a boundary first: names are stat'ed, and "no boundary
    // file up to the top of the disk" needs no checkout to be found. A
    // project the probe cannot place is not "no root": it reports that as
    // a marker and no root, which the bounded survey reports again.
    let anywhere = probe.survey(dir, &ReadBoundary::Unbounded);
    if anywhere.roots.is_empty() && anywhere.above.is_none() {
        return None;
    }
    let from = match dir.as_os_str().is_empty() {
        true => Path::new("."),
        false => dir,
    };
    let boundary = ReadBoundary::upward(ReadScope::Workspace, from);
    let survey = probe.survey(dir, &boundary);
    if survey.roots.is_empty() && survey.above.is_none() {
        return None;
    }
    // The model is read beside the view, so a recording of the view cannot
    // vouch for this discovery.
    let _ = ctx.disk_root();
    let views: Vec<DiskView> = survey.roots.iter().map(DiskView::new).collect();
    let read = survey.roots.iter().zip(&views);
    let models = read
        .map(|(root, view)| read_workspace(root, view))
        .collect();
    Some(Loaded {
        probe: survey.probe(),
        roots: survey.roots,
        views,
        models,
    })
}

/// The owned index of the root behind `files`, as the CLI's loader reads
/// it: a root with no index file has the empty one, and a file that is
/// there and is not the index socket-patch wrote is a fault, never "no
/// rows".
fn owned_index_of(files: &dyn FileView) -> Result<Index, IndexFault> {
    match files.read(INDEX_PATH) {
        FileText::Absent => Ok(Index::default()),
        FileText::Unreadable => Err(IndexFault::Unreadable),
        FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
            Parsed::Ours(index) => Ok(index),
            Parsed::Modified(what) => Err(IndexFault::Modified(what)),
            Parsed::Foreign => Err(IndexFault::Foreign),
        },
    }
}

/// One reference and what the Bazel layer says of it.
struct Judged {
    purl: String,
    uuid: String,
    file: PathBuf,
    withheld: Option<Unattested>,
}

/// The verdicts of the references of one discovery, to be turned into
/// marks once the contests have run ([`Marks::mark`]).
#[derive(Default)]
pub(crate) struct Marks(Vec<Judged>);

impl Marks {
    /// Marks each patch that is left with no reference the Bazel build
    /// consumes, once, with the first withhold. A patch another mark
    /// already withholds keeps that reason: it names what the user can
    /// change in the file itself.
    pub(crate) fn mark(self, out: &mut Discovery) {
        let same =
            |a: &Judged, purl: &str, uuid: &str| a.uuid == uuid && PurlKey::same(&a.purl, purl);
        let left = |one: &&Judged| {
            let mut refs = out.refs.iter();
            refs.any(|r| r.source_file == one.file && same(one, &r.purl, &r.uuid))
        };
        let left: Vec<&Judged> = self.0.iter().filter(left).collect();
        let mut marks: Vec<Unattested> = Vec::new();
        for one in &left {
            let Some(mark) = &one.withheld else { continue };
            let group = || {
                left.iter()
                    .filter(|other| same(other, &one.purl, &one.uuid))
            };
            let withheld = |u: &Unattested| !u.kind.file_scoped() && same(one, &u.purl, &u.uuid);
            let marked = out.unattested.iter().chain(&marks).any(withheld);
            if group().all(|other| other.withheld.is_some()) && !marked {
                marks.push(mark.clone());
            }
        }
        out.unattested.extend(marks);
    }
}

/// How often the verdicts are decided again over bytes a view changed.
const ROUNDS: usize = 3;

/// One pass over one read of the roots: the pins that are references, and
/// the verdict of every reference.
fn pass(read: &Read<'_>, opts: BazelOptions<'_>, refs: &[PatchedRef]) -> (Vec<PatchedRef>, Marks) {
    let judge = Judge::new(read, opts);
    let judged = |r: &PatchedRef, verdict: Result<Consumed, VexWithhold>| Judged {
        purl: r.purl.clone(),
        uuid: r.uuid.clone(),
        file: r.source_file.clone(),
        withheld: verdict.err().map(|why| Unattested {
            purl: canonical_base_purl(&r.purl),
            uuid: r.uuid.clone(),
            file: r.source_file.clone(),
            detail: withheld_detail(&why),
            kind: UnattestedKind::of_withheld(why.kind),
        }),
    };
    let mut marks = Vec::new();
    for r in refs {
        let file = r.source_file.to_string_lossy();
        let verdict = judge.wired(&r.purl, &r.uuid, &[(r.mode, &file)]);
        marks.push(judged(r, verdict));
    }
    let mut found = Vec::new();
    for (r, pin) in judge.references() {
        let known = |have: &PatchedRef| {
            let same = have.uuid == r.uuid && have.source_file == r.source_file;
            same && PurlKey::same(&have.purl, &r.purl)
        };
        if !refs.iter().chain(&found).any(known) {
            marks.push(judged(
                &r,
                judge.consumer(&r.purl, &r.uuid, Basis::Pin(pin)),
            ));
            found.push(r);
        }
    }
    (found, Marks(marks))
}

/// The Bazel half of lockfile discovery (module docs). The references it
/// adds are pushed at once, so the contests weigh them like any other; the
/// marks follow the contests.
pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) -> Marks {
    let opts = ctx.bazel;
    if out.refs.is_empty() && !opts.lanes.specs().any(|(_, spec)| spec.enabled) {
        return Marks::default();
    }
    let Some(loaded) = load(ctx) else {
        return Marks::default();
    };
    let base = loaded.roots.first().map_or("", |root| &root.project_rel);
    let mut view = loaded.views.first().map(|disk| CtxView {
        disk,
        over: HashMap::new(),
        asked: Mutex::default(),
        settled: BTreeSet::new(),
    });
    let mut rounds = 0;
    let (found, marks) = loop {
        let decided = {
            let index = view.as_ref().map(|view| owned_index_of(view));
            let nearest = view.as_ref().zip(index.as_ref());
            let read = Read {
                probe: &loaded.probe,
                models: &loaded.models,
                nearest: nearest.map(|(view, index)| (view as &dyn FileView, index.as_ref())),
            };
            pass(&read, opts, &out.refs)
        };
        let Some(files) = view.as_mut() else {
            break decided;
        };
        if !files.settle(ctx, base).await {
            break decided;
        }
        rounds += 1;
        if rounds == ROUNDS {
            // A view that keeps changing what is read proves nothing: no
            // reference is added, and every one a ruleset could build is
            // withheld as a workspace that cannot be read is.
            let unread = Read {
                probe: &loaded.probe,
                models: &[],
                nearest: None,
            };
            break (Vec::new(), pass(&unread, opts, &out.refs).1);
        }
    };
    for r in found {
        out.push(r);
    }
    marks
}

#[cfg(test)]
mod tests {
    use super::super::testing::{fixture_path, ref_triples, Project};
    use super::super::{discover_patched_refs_under, discover_with_ctx, DiscoverOptions};
    use super::*;
    use crate::bazel::model::{
        AttestBasis, CellClaim, ClaimSystem, LaneCx, LaneId, LaneOps, LaneSpec, LockRole, Ruleset,
        TextRead,
    };
    use crate::bazel::owned_index::{IndexEdit, IndexRow};
    use crate::utils::purl::purl_parts;
    use crate::vendor::lock_inventory::{DiskSnapshot, LockfileEntry, SourceKind};
    use UnattestedKind::{BazelConsumerUndetermined, BazelDerivedStale, BazelNotConsumed};
    use WiringMode::{Hosted, Vendored};

    const NINE: (&str, &str) = (".bazelversion", "9.3.2\n");
    const JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";
    const MAVEN: &str = "bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
        maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
        maven.install(name = \"maven\", lock_file = \"//:maven_install.json\")\n\
        use_repo(maven, \"maven\")\n";
    const GO: &str = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
        go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
        go_deps.from_file(go_mod = \"//:go.mod\")\n\
        use_repo(go_deps, \"com_github_foo_bar\")\n";
    /// The committed redirect fixtures: a pnpm lock that pins `left-pad`
    /// and a pom that pins `slf4j-api`, each to a hosted patch.
    const PNPM_PINNED: &str = "redirect/npm/pnpm/basic/expected";
    const POM_PINNED: &str = "redirect/maven/pom/basic/expected";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
    const PNPM_PIN: &str = "22222222-2222-2222-2222-222222222222";
    const SLF4J: &str = "pkg:maven/org.slf4j/slf4j-api@1.7.36";
    const POM_PIN: &str = "77777777-7777-7777-7777-777777777777";
    const BAR: &str = "pkg:golang/github.com/foo/bar@v1.0.0";
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    // ── A toy lane ───────────────────────────────────────────────────

    /// The words of each package line of the hub's locks, with its file.
    /// The toy lock holds one `<purl> <sha256> [<lane> <uuid>] [broken]`
    /// per line, after `// ` or `# ` where a real lock carries it as a
    /// comment. A line that names a lane is that lane's pin of the patch.
    fn lines(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<(String, Vec<String>)>> {
        let hub = cx.ws.hubs.get(cx.hub.0)?;
        let locks = hub.locks.iter();
        let mut out = Vec::new();
        for lock in locks.filter(|lock| lock.role == LockRole::PackageLock) {
            let path = lock.path.clone()?;
            for line in read(&path)?.lines() {
                let line = line.trim_start_matches("// ").trim_start_matches("# ");
                if line.starts_with("pkg:") {
                    out.push((path.clone(), line.split(' ').map(String::from).collect()));
                }
            }
        }
        Some(out)
    }

    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let entry = |(_, words): (String, Vec<String>)| {
            let (_, name, version) = purl_parts(&words[0])?;
            Some(LockfileEntry {
                ecosystem: Ecosystem::from_purl(&words[0])?.cli_name(),
                name,
                version,
                purl: words[0].clone(),
                resolved: None,
                integrity: LockIntegrity::Sha256Hex(words.get(1)?.clone()),
                source_kind: SourceKind::Unspecified,
                pnpm_env: false,
            })
        };
        lines(cx, read)?.into_iter().map(entry).collect()
    }

    const LANES: [(&str, Mode, AttestBasis); 3] = [
        ("H-TOY1", Mode::Hosted, AttestBasis::LockUrl),
        ("V-TOY1", Mode::Vendored, AttestBasis::LockPath),
        ("A-TOY1", Mode::Agent, AttestBasis::LockPath),
    ];

    fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let pin = |(file, words): (String, Vec<String>)| {
            let named =
                |(id, ..): &&(&str, Mode, AttestBasis)| Some(*id) == words.get(2).map(|w| &w[..]);
            let (lane, mode, basis) = *LANES.iter().find(named)?;
            (mode == cx.mode).then(|| BazelRef {
                lane: LaneId(lane),
                purl: words[0].clone(),
                uuid: words[3].clone(),
                file,
                basis,
            })
        };
        Some(lines(cx, read)?.into_iter().filter_map(pin).collect())
    }

    fn toy_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
        let read = |rel: &str| cx.files.read(rel).as_str().map(String::from);
        let own = lines(cx, &read).into_iter().flatten();
        let mut own = own.filter(|(_, words)| words[0] == pin.purl);
        match own.any(|(_, words)| words.iter().any(|word| word == "broken")) {
            false => Ok(()),
            true => Err(VexWithhold {
                kind: WithholdKind::DerivedStale,
                token: None,
                detail: "the toy lane's own proof of the line fails".to_string(),
            }),
        }
    }

    const CLAIM: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];

    const fn lane(at: usize) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIM,
            ..LaneSpec::stub(LANES[at].0, LANES[at].1, &[])
        }
    }

    const TOY: LaneOps = LaneOps {
        discover: toy_discover,
        attest: toy_attest,
        inventory: toy_inventory,
        ..LaneOps::disabled(&[lane(0), lane(1), lane(2)])
    };
    static TABLE: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &TOY),
        (Ruleset::RulesJs, &TOY),
        (Ruleset::Gazelle, &TOY),
    ]);

    // ── Fixtures ─────────────────────────────────────────────────────

    /// A project that is its own Bazel root, in a checkout of its own.
    fn project(files: &[(&str, &str)]) -> Project {
        let project = Project::nested("ws");
        for (rel, text) in files {
            project.write(rel, text);
        }
        project
    }

    fn toy(grants: &[(String, Integrity)]) -> BazelOptions<'_> {
        BazelOptions {
            lanes: &TABLE,
            grants,
        }
    }

    fn grant(sha256: &str) -> Vec<(String, Integrity)> {
        let integrity = Integrity {
            sha256: Some(sha256.to_string()),
            ..Integrity::default()
        };
        vec![(UUID.to_string(), integrity)]
    }

    async fn discover(project: &Project, bazel: BazelOptions<'_>) -> Discovery {
        discover_patched_refs_under(project.root(), &DiscoverOptions::default(), bazel).await
    }

    fn marks(out: &Discovery) -> Vec<(&str, &str, UnattestedKind)> {
        let marks = out.unattested.iter();
        marks
            .map(|u| (u.purl.as_str(), u.uuid.as_str(), u.kind))
            .collect()
    }

    fn wired(purl: &str, uuid: &str) -> Vec<(String, String, WiringMode)> {
        vec![(purl.to_string(), uuid.to_string(), Hosted)]
    }

    /// Asks the judge of `project`, read as the extractor reads it.
    fn judged<T>(
        project: &Project,
        opts: BazelOptions<'_>,
        ask: impl FnOnce(&Judge<'_>) -> T,
    ) -> T {
        let loaded = load(&project.ctx()).expect("a Bazel root");
        let files: &dyn FileView = &loaded.views[0];
        let index = owned_index_of(files);
        let read = Read {
            probe: &loaded.probe,
            models: &loaded.models,
            nearest: Some((files, index.as_ref())),
        };
        let judge = Judge::new(&read, opts);
        ask(&judge)
    }

    // ── The extractor ────────────────────────────────────────────────

    /// The same files with and without a Bazel boundary file: outside a
    /// workspace the discovery is what it was, and under a hub that reads
    /// the lock the one thing added is the mark. The reference stays, so
    /// the management commands still find the pin.
    #[tokio::test]
    async fn only_a_bazel_workspace_brings_a_mark() {
        let project = Project::nested("ws");
        project.copy_fixture(PNPM_PINNED);
        let plain = discover(&project, BazelOptions::default()).await;
        assert_eq!(ref_triples(&plain), wired(LEFT_PAD, PNPM_PIN));
        assert_eq!(marks(&plain), []);

        project.write("MODULE.bazel", JS);
        let governed = discover(&project, BazelOptions::default()).await;
        let expected = [(LEFT_PAD, PNPM_PIN, BazelConsumerUndetermined)];
        assert_eq!(marks(&governed), expected);
        assert_eq!(governed.refs, plain.refs);
        assert_eq!(governed.diagnostics, plain.diagnostics);
        assert_eq!(governed.recognized, plain.recognized);
        assert_eq!(governed.elsewhere, plain.elsewhere);
        // The Bazel reads are not logged as files discovery read (module
        // docs). Whether one happened is another test's:
        // `a_root_with_nothing_to_judge_is_not_read`.
        assert_eq!(governed.read, plain.read);
        assert!(governed.contested.is_empty() && governed.rewirable.is_empty());
    }

    /// Over-attestation from a lock Bazel does not read: a hosted `pom.xml`
    /// pin beside a `maven_install.json` that resolves the release
    /// unpatched. It is marked in the project the hub governs and in a
    /// project below the root that no hub governs, and nowhere is it
    /// contested, so `rollback` can still undo it.
    #[tokio::test]
    async fn a_pom_pin_beside_an_unpatched_hub_lock_is_marked_and_stays_a_reference() {
        let lock = "bazel/rje_locks/probe/pin-rje7.2-bazel8.8.2-v3-sorted-2repo.json";
        let lock = std::fs::read_to_string(fixture_path(lock)).unwrap();
        let one = |out: &Discovery, said: &str| {
            let [mark] = out.unattested.as_slice() else {
                panic!("{:#?}", out.unattested);
            };
            let found = (mark.purl.as_str(), mark.uuid.as_str(), mark.kind);
            assert_eq!(found, (SLF4J, POM_PIN, BazelNotConsumed));
            assert!(mark.detail.contains(said), "{}", mark.detail);
            assert_eq!(ref_triples(out), wired(SLF4J, POM_PIN));
            let dropped = out.contested.len() + out.rewirable.len() + out.diagnostics.len();
            assert_eq!(dropped, 0, "{out:#?}");
        };
        let root = project(&[("MODULE.bazel", MAVEN), ("maven_install.json", &lock)]);
        root.copy_fixture(POM_PINNED);
        let out = discover(&root, BazelOptions::default()).await;
        one(&out, "`pom.xml` is a file no hub reads");

        let below = Project::nested("ws/service-a");
        below.write("../MODULE.bazel", MAVEN);
        below.write("../maven_install.json", &lock);
        below.copy_fixture(POM_PINNED);
        let out = discover(&below, BazelOptions::default()).await;
        one(&out, "hub `maven` resolves");

        // A release no hub lock resolves is judged as it is today.
        let pom = std::fs::read_to_string(below.root().join("pom.xml")).unwrap();
        below.write("pom.xml", pom.replace("slf4j-api", "other-api"));
        let out = discover(&below, BazelOptions::default()).await;
        assert_eq!(out.refs.len(), 1, "{out:#?}");
        assert_eq!(marks(&out), []);
    }

    /// A pin in a lock only Bazel reads becomes a reference, and is held
    /// to the digest of the patch: by the grant of an in-run statement, or
    /// offline by the row of the owned index that records it. An index
    /// somebody edited records nothing that can be relied on.
    #[tokio::test]
    async fn a_pin_in_a_lock_only_bazel_reads_is_a_reference_held_to_the_patch_digest() {
        let (patched, upstream) = ("2".repeat(64), "1".repeat(64));
        let pin = format!("{SLF4J} {patched} H-TOY1 {UUID}\n");
        let files = [NINE, ("MODULE.bazel", MAVEN), ("maven_install.json", &pin)];
        let project = project(&files);

        let out = discover(&project, toy(&[])).await;
        let [found] = out.refs.as_slice() else {
            panic!("{:#?}", out.refs);
        };
        assert_eq!(ref_triples(&out), wired(SLF4J, UUID));
        assert_eq!(found.source_file, Path::new("maven_install.json"));
        let digest = LockIntegrity::Sha256Hex(patched.clone());
        assert_eq!(found.locked_integrity, Some(digest));
        assert!(found.integrity_required && out.recognizes(UUID, Hosted));
        // Offline, nothing committed says which digest the pin was
        // written with.
        let undetermined = [(SLF4J, UUID, BazelConsumerUndetermined)];
        assert_eq!(marks(&out), undetermined);

        let out = discover(&project, toy(&grant(&patched))).await;
        assert_eq!(marks(&out), []);
        let out = discover(&project, toy(&grant(&upstream))).await;
        assert_eq!(marks(&out), [(SLF4J, UUID, BazelDerivedStale)]);

        let mut index = Index::default();
        index.record_pin(IndexRow {
            uuid: UUID.to_string(),
            purl: SLF4J.to_string(),
            lane: "H-TOY1".to_string(),
            file: "maven_install.json".to_string(),
            edits: vec![IndexEdit {
                key: "sha256".to_string(),
                original: upstream,
                new: patched.clone(),
            }],
            check: None,
        });
        let rendered = index.render().expect("a row socket-patch may record");
        project.write(INDEX_PATH, &rendered);
        assert_eq!(marks(&discover(&project, toy(&[])).await), []);

        project.write("maven_install.json", format!("{} broken\n", pin.trim_end()));
        let out = discover(&project, toy(&[])).await;
        assert_eq!(marks(&out), [(SLF4J, UUID, BazelDerivedStale)]);

        project.write("maven_install.json", &pin);
        project.write(INDEX_PATH, rendered.replacen("\"pins\"", " \"pins\"", 1));
        let out = discover(&project, toy(&grant(&patched))).await;
        assert_eq!(marks(&out), undetermined);
        let detail = &out.unattested[0].detail;
        assert!(detail.contains("(`owned_file_modified`)"), "{detail}");
    }

    /// A discovery over a pending rewrite judges the lock as the rewrite
    /// leaves it. The model is read beside the view, so a recording of the
    /// view does not vouch for a discovery under a Bazel root, and still
    /// does for one outside any.
    #[tokio::test]
    async fn a_pending_rewrite_is_judged_as_it_leaves_the_lock() {
        let (patched, upstream) = ("2".repeat(64), "1".repeat(64));
        let unpinned = format!("{SLF4J} {upstream}\n");
        let files = [
            NINE,
            ("MODULE.bazel", MAVEN),
            ("maven_install.json", &unpinned),
        ];
        let project = project(&files);
        let snapshot = DiskSnapshot::tracked(project.root());
        let pinned = format!("{SLF4J} {patched} H-TOY1 {UUID}\n");
        snapshot.overlay("maven_install.json", pinned.as_bytes());
        snapshot.begin_recording();
        let grants = grant(&patched);
        let mut ctx = DiscoverCtx::over(ProjectView::Snapshot(&snapshot), &[]);
        ctx.bazel = toy(&grants);
        let out = discover_with_ctx(ctx).await;
        assert_eq!(ref_triples(&out), wired(SLF4J, UUID));
        assert_eq!(marks(&out), []);
        assert!(snapshot.end_recording().is_none());

        let plain = Project::nested("ws");
        plain.copy_fixture(PNPM_PINNED);
        let snapshot = DiskSnapshot::tracked(plain.root());
        snapshot.begin_recording();
        let ctx = DiscoverCtx::over(ProjectView::Snapshot(&snapshot), &[]);
        let out = discover_with_ctx(ctx).await;
        assert_eq!(ref_triples(&out), wired(LEFT_PAD, PNPM_PIN));
        assert!(snapshot.end_recording().is_some());
    }

    /// Under a Bazel root with nothing to judge (no reference, and no
    /// enabled lane that could have written a pin) the extractor opens
    /// nothing: the discovery is what it is without the workspace file,
    /// and a recording of the view still vouches for it, which is what
    /// lets a command reuse one discovery and spares it the model load.
    /// One reference brings the read, and with it the recording is void.
    #[tokio::test]
    async fn a_root_with_nothing_to_judge_is_not_read() {
        let recorded = |project: &Project| {
            let root = project.root().to_path_buf();
            async move {
                let snapshot = DiskSnapshot::tracked(&root);
                snapshot.begin_recording();
                // The production options: every lane disabled.
                let ctx = DiscoverCtx::over(ProjectView::Snapshot(&snapshot), &[]);
                let out = discover_with_ctx(ctx).await;
                (out, snapshot.end_recording().is_some())
            }
        };
        let lock = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";
        let project = project(&[("package.json", "{}"), ("pnpm-lock.yaml", lock)]);
        let (plain, vouched) = recorded(&project).await;
        assert!(vouched, "no Bazel root: the recording stands");
        assert!(plain.refs.is_empty(), "{:#?}", plain.refs);

        project.write("MODULE.bazel", JS);
        let (governed, vouched) = recorded(&project).await;
        assert!(vouched, "a root with nothing to judge was read");
        assert_eq!(governed.refs, plain.refs);
        assert_eq!(governed.unattested, plain.unattested);
        assert_eq!(governed.diagnostics, plain.diagnostics);
        assert_eq!(governed.recognized, plain.recognized);
        assert_eq!(governed.elsewhere, plain.elsewhere);
        assert_eq!(governed.read, plain.read);

        // The same root with one hosted reference: there is something to
        // judge, the model is read beside the view, and the recording
        // cannot vouch for what it did not see.
        project.copy_fixture(PNPM_PINNED);
        let (pinned, vouched) = recorded(&project).await;
        assert_eq!(ref_triples(&pinned), wired(LEFT_PAD, PNPM_PIN));
        let expected = [(LEFT_PAD, PNPM_PIN, BazelConsumerUndetermined)];
        assert_eq!(marks(&pinned), expected);
        assert!(!vouched, "a recording vouched for a read beside the view");
    }

    // ── The judge ────────────────────────────────────────────────────

    /// With no lane enabled, every basis is withheld in a project a hub
    /// governs: a hosted and a vendored reference in the lock the hub
    /// reads, and a patched installed tree.
    #[test]
    fn every_basis_is_withheld_under_a_hub_no_lane_serves() {
        let project = project(&[("MODULE.bazel", JS), ("pnpm-lock.yaml", "")]);
        let kinds = judged(&project, BazelOptions::default(), |judge| {
            let lock = |mode| judge.wired(LEFT_PAD, UUID, &[(mode, "pnpm-lock.yaml")]);
            [lock(Hosted), lock(Vendored), judge.record(LEFT_PAD, UUID)]
                .map(|v| v.map_err(|w| w.kind))
        });
        let undetermined = Err(WithholdKind::ConsumerUndetermined);
        let installed = Err(WithholdKind::NotConsumed);
        assert_eq!(kinds, [undetermined, undetermined, installed]);
        // No lane can tell a pin, so discovery holds none for the patch.
        let pinned = judged(&project, BazelOptions::default(), |judge| {
            judge.pinned(LEFT_PAD, UUID)
        });
        assert_eq!(pinned, None);
        // An ecosystem no ruleset of the workspace builds is as it is
        // today.
        let cargo = judged(&project, BazelOptions::default(), |judge| {
            judge.record("pkg:cargo/serde@1.0.0", UUID)
        });
        assert_eq!(cargo, Ok(Consumed::AsToday));
    }

    /// A record that no file of the project wires is judged through the
    /// pin discovery holds for its patch: an agent lane's pin keeps the
    /// installed tree as the evidence, a vendored lane's pin the committed
    /// artifact, and a pin whose proof fails withholds as that pin, never
    /// as the installed tree it is not.
    #[test]
    fn a_record_is_judged_through_the_pin_discovery_holds_for_it() {
        let digest = "2".repeat(64);
        let record = |pin: &str, grants: &[(String, Integrity)]| {
            let go_mod = format!(
                "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n\
                 // {BAR} {digest}{pin}\n"
            );
            let files = [
                NINE,
                ("MODULE.bazel", GO),
                ("go.mod", &go_mod[..]),
                ("go.sum", ""),
            ];
            let project = project(&files);
            judged(&project, toy(grants), |judge| {
                let record = judge.record(BAR, UUID).map_err(|why| why.kind);
                // Where discovery holds a pin, the record's verdict is the
                // pin's; with none, only the record has one (the tree's).
                let pinned = judge.pinned(BAR, UUID);
                let pinned = pinned.map(|verdict| verdict.map_err(|why| why.kind));
                assert_eq!(pinned.is_some(), !pin.is_empty(), "{pin}");
                assert!(pinned.is_none_or(|pinned| pinned == record), "{pin}");
                let stray = [(Hosted, "tools/other.lock"), (Hosted, "go.mod")];
                (
                    record,
                    judge.wired(BAR, UUID, &stray).map_err(|why| why.kind),
                )
            })
        };
        assert_eq!(record("", &[]).0, Err(WithholdKind::NotConsumed));

        let agent = record(&format!(" A-TOY1 {UUID}"), &[])
            .0
            .expect("an agent pin");
        assert!(agent.verifies_installed_tree());
        assert!(!agent.hashes_committed_artifact() && !agent.integrity_required());

        let vendored = record(&format!(" V-TOY1 {UUID}"), &[])
            .0
            .expect("a vendored pin");
        assert!(vendored.hashes_committed_artifact());
        assert!(!vendored.verifies_installed_tree() && !vendored.integrity_required());
        let broken = record(&format!(" V-TOY1 {UUID} broken"), &[]).0;
        assert_eq!(broken, Err(WithholdKind::DerivedStale));

        // A hosted pin, in-run and offline. One reference the build
        // consumes carries the patch, whatever a file no hub reads says.
        let hosted = format!(" H-TOY1 {UUID}");
        let (pinned, both) = record(&hosted, &grant(&digest));
        let pinned = pinned.expect("a hosted pin under its grant");
        assert!(pinned.integrity_required() && !pinned.verifies_installed_tree());
        assert_eq!(both, Ok(pinned));
        let offline = Err(WithholdKind::ConsumerUndetermined);
        assert_eq!(
            record(&hosted, &[]),
            (offline, Err(WithholdKind::NotConsumed))
        );
    }

    /// Where no root was read, the probe's answer decides alone: a
    /// workspace somebody builds above the repository leaves every
    /// ecosystem a ruleset can build undetermined, and a stray boundary
    /// file changes nothing.
    #[test]
    fn a_workspace_above_the_repository_is_never_not_bazel() {
        let verdict = |confirmed: bool, purl: &str| {
            let marker = PathBuf::from("/above/WORKSPACE");
            let probe = Probe::RootOutsideBoundary { marker, confirmed };
            let read = Read {
                probe: &probe,
                models: &[],
                nearest: None,
            };
            let judge = Judge::new(&read, BazelOptions::default());
            let wiring = [(Hosted, "package-lock.json")];
            // Nobody listed a pin: "not known" where a ruleset may build
            // the ecosystem, and no pin at all where none can.
            let record = judge.record(purl, UUID);
            assert_eq!(judge.pinned(purl, UUID), record.clone().err().map(Err));
            (record, judge.wired(purl, UUID, &wiring))
        };
        let (record, wired) = verdict(true, LEFT_PAD);
        let why = record.expect_err("undetermined");
        assert_eq!(why.kind, WithholdKind::ConsumerUndetermined);
        assert!(
            why.detail.contains("above the repository"),
            "{}",
            why.detail
        );
        assert_eq!(wired, Err(why));
        let as_today = (Ok(Consumed::AsToday), Ok(Consumed::AsToday));
        assert_eq!(verdict(false, LEFT_PAD), as_today);
        assert_eq!(verdict(true, "pkg:composer/a/b@1.0.0"), as_today);
    }

    #[test]
    fn a_path_is_spelled_from_the_project_and_from_the_root() {
        for (base, view, root) in [
            ("", "pom.xml", "pom.xml"),
            ("svc/api", "go.mod", "svc/api/go.mod"),
            ("svc/api", "../../maven_install.json", "maven_install.json"),
            ("svc/api", "../web/yarn.lock", "svc/web/yarn.lock"),
            ("svc", "../../.bazelversion", "../.bazelversion"),
        ] {
            assert_eq!(under_root(base, view), root, "{base} + {view}");
            assert_eq!(under_project(base, root), view, "{root} from {base}");
        }
        // A reference's file is a path of this machine.
        assert_eq!(under_root("svc", "sub\\x.lock"), "svc/sub/x.lock");
    }

    /// Each withhold kind of the Bazel layer has a mark of its own, none
    /// of them scoped to one file: such a mark withholds the patch.
    #[test]
    fn every_withhold_kind_has_its_own_mark() {
        let marks: BTreeSet<UnattestedKind> = WithholdKind::ALL
            .iter()
            .map(|kind| {
                let mark = UnattestedKind::of_withheld(*kind);
                assert_eq!(mark.withheld(), Some(*kind));
                assert!(!mark.file_scoped(), "{mark:?}");
                mark
            })
            .collect();
        assert_eq!(marks.len(), WithholdKind::ALL.len());
        assert_eq!(UnattestedKind::LockNotRead.withheld(), None);
    }
}
