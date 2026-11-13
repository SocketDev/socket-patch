//! Hub locks as inventory entries: the universe `scan --prune` keeps, the
//! cross-lock contest, and the workspace-wide lookup behind the agent-basis
//! check (design HZ-15, HZ-18 and section 7). A lock that cannot be
//! enumerated answers "keep".
//!
//! Every answer here permits something only by what a lock does **not**
//! resolve: a record nothing resolves may be pruned, and a host tree may
//! be attested when no hub builds the package. So a listing must be
//! complete or absent, and three rules follow:
//!
//! - **Every hub Bazel may build from is asked** ([`may_build`]): every
//!   hub that is not proven dead or shadowed. Dropping one that is only
//!   contested, a dev dependency, another module's or imported by a spoke
//!   alone would prune a record Bazel consumes (probe B5) and attest a
//!   tree it does not build.
//! - **The lane lists the lock.** What a lock resolves is its ruleset's
//!   knowledge (which entries are fetched, which file of several is
//!   read), so the family's `LaneOps::inventory` is asked. Until a lane of
//!   the family is enabled, two views of this file stand in for the locks
//!   only Bazel reads, the first Maven and NuGet inventories:
//!   `maven_install.json` through [`rje_lock`], taken only when its
//!   content hash is reproduced, and the package lines of a
//!   `paket.<group>.bzl` as the recognizer read them.
//! - **Unreadable is not empty.** A lock label that names no file of the
//!   repository, a file name the path rule of design 2.7 refuses
//!   ([`lock_path_refused`]), a lock that is missing or cannot be read, a
//!   hub another module makes and a family with no view yet are each
//!   [`Unlisted`]: the manifest half of the prune is skipped for that
//!   ecosystem, and `vex` answers "consumer undetermined". So is a
//!   declaration nobody followed to a hub (`govern::unread_gaps`): a hub
//!   may exist whose lock was never asked for, and the ecosystem is then
//!   unlisted with no hub to name.
//!
//! What the owned index records is in use whatever a lock says
//! ([`wired`]): a pin can rename its own lock entry, and an artifact that
//! an `rcFlags` or `files` row names is one the build reads (revision 4,
//! section 5).

use std::collections::{BTreeMap, BTreeSet};

use super::govern::{self, LABEL_NOT_LITERAL};
use super::model::{
    BazelRef, BazelWorkspace, FileView, Hub, HubId, HubShape, Index, LaneCx, LaneTable, Liveness,
    LockRole, Mode, Ruleset, RulesetDetail, RunPolicy, LANE_NOT_ENABLED,
};
use super::rje_lock::{self, Format, Node};
use super::rulesets::report_only::HUB_NOT_ROOT_MODULE;
use super::rulesets::rules_csharp::LOCK_PATH;
use super::rulesets::rules_dotnet::PaketData;
use crate::crawlers::types::Ecosystem;
use crate::formats::registry;
use crate::utils::purl::{maven_purl, simple_purl};
use crate::utils::purl_key::PurlKey;
use crate::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

/// Whether Bazel may build from the hub. Two stored values prove that it
/// does not: `Dead` (no dependency system the workspace may run evaluates
/// the declaration) and `Shadowed` (another repository has the hub's
/// name). Every other value leaves a build that reads the hub's lock:
///
/// - `Undecided`: evaluated under one dependency system the workspace may
///   run and not under another, or what decides it was not read.
/// - `DevDependencyDropped`: stored as soon as `--ignore_dev_dependency`
///   is possible, and a flag under a named config (`common:ci`) is. The
///   default command still evaluates the hub.
/// - `NotRootModule`: a hub the root imports and adds tags to, which
///   another module's `install` makes. Bazel builds from it; its lock is
///   in that module, so it is never listed here ([`list`]).
/// - `NotImported`: counts imports of the hub's own name. The root may
///   import a spoke alone (`npm__left-pad__1.3.0`) and build from it.
///
/// The gate, `attest` and the consent evidence filter with this function
/// too: a hub it drops declares nothing and resolves nothing.
pub fn may_build(hub: &Hub) -> bool {
    !matches!(
        hub.liveness,
        Liveness::Dead { .. } | Liveness::Shadowed { .. }
    )
}

/// What one hub's lock resolves.
#[derive(Debug, Clone)]
pub struct Listed {
    pub hub: HubId,
    pub ecosystem: Ecosystem,
    pub entries: Vec<LockfileEntry>,
}

/// A lock Bazel may build from that could not be enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    /// The hub whose lock it is. `None` when nobody read the hub: a
    /// declaration Bazel may evaluate was not followed to one, so its
    /// lock, if it has one, was never asked for.
    pub hub: Option<HubId>,
    pub ecosystem: Ecosystem,
    /// The token of the case, where the contract has one.
    pub token: Option<&'static str>,
    /// The root-relative file at fault (the lock, or the file whose
    /// declaration was not read), `""` when no one file is.
    pub file: String,
    pub detail: String,
}

/// Whether any hub lock of the workspace resolves a package.
///
/// The agent-basis check has two conditions, and each withholds on its
/// own (design section 7): a hub lock resolves the release without a
/// confirmed pin, or a hub lock of the ecosystem cannot be enumerated.
/// `By` therefore carries both facts. A caller that finds a confirmed pin
/// in every hub of `hubs` still withholds (`vex_bazel_consumer_undetermined`)
/// while `unlisted` is `Some`: that lock may resolve the release too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// Every hub lock of the ecosystem was listed and none resolves it.
    No,
    /// These hubs build it from their locks. `unlisted` is the first lock
    /// of the ecosystem that could not be listed, which is not known not
    /// to resolve it as well.
    By {
        hubs: Vec<HubId>,
        unlisted: Option<&'a Unlisted>,
    },
    /// No listed lock resolves it, and this lock could not be listed.
    CannotEnumerate(&'a Unlisted),
}

/// The hub locks of one Bazel root.
#[derive(Debug, Clone)]
pub struct Inventory {
    pub listed: Vec<Listed>,
    pub unlisted: Vec<Unlisted>,
    /// Locks of an ecosystem a hub governs that no hub reads (a
    /// `package-lock.json` beside the governed `pnpm-lock.yaml`), by
    /// root-relative path: a reference in one attests nothing for the
    /// Bazel build, and no rewriter may take one for the hub's lock.
    pub non_consumers: Vec<String>,
    /// [`wired`] of the index the inventory was read with.
    pub wired: BTreeSet<String>,
    /// The hubs whose listed lock resolves each release, by purl identity.
    resolved: BTreeMap<PurlKey, Vec<HubId>>,
}

/// Whether the path rule of design 2.7 refuses the lock `path` of `hub`
/// (token `lock_path`): restore and discovery key on leaf names, so a
/// native lock must carry a name its ecosystem's project roots are found
/// by (`Cargo.Bazel.lock` is not one). Requirements files and the locks
/// only Bazel reads are found by their label and may have any name.
pub fn lock_path_refused(hub: &Hub, path: &str) -> bool {
    use HubShape::{MavenPinned, PaketGroup, PaketSingle, PipInstall, PipParse, PipParseWorkspace};
    let by_label = [
        PipParse,
        PipParseWorkspace,
        PipInstall,
        MavenPinned,
        PaketGroup,
        PaketSingle,
    ];
    let base = path.rsplit('/').next().unwrap_or(path);
    let tag = hub.ecosystem.cli_name();
    let native = registry::root_marker(base).is_some_and(|file| file.ecosystem == tag);
    let nuget = hub.ecosystem == Ecosystem::Nuget && base == "packages.lock.json";
    !by_label.contains(&hub.shape) && !native && !nuget
}

fn entry(ecosystem: &'static str, name: String, version: &str, purl: String) -> LockfileEntry {
    LockfileEntry {
        ecosystem,
        name,
        version: version.to_string(),
        purl,
        resolved: None,
        integrity: LockIntegrity::None,
        source_kind: SourceKind::Unspecified,
        pnpm_env: false,
    }
}

/// The Maven view: one entry per artifact a `maven_install.json` pins,
/// named `group:artifact`. A classifier or a packaging is the same
/// release. The lock must reproduce its own content hash: one that does
/// not is edited by hand or not modelled, and is not listed.
fn maven_view(text: &str) -> Result<Vec<LockfileEntry>, String> {
    let lock = rje_lock::read(text)
        .map_err(|e| format!("it is no lock rules_jvm_external reads ({e:?})"))?;
    let hash = lock.reproduced();
    hash.map_err(|e| {
        format!("its content hash is not reproduced ({e:?}), so it is not known to be read in full")
    })?;
    let bad = |what: &str| format!("`{what}` is not a Maven coordinate with a version");
    let artifact = |parts: &[&str], version: &str, whole: &str| {
        let purl = maven_purl(parts[0], parts[1], version).ok_or_else(|| bad(whole))?;
        Ok::<_, String>(entry("maven", parts[..2].join(":"), version, purl))
    };
    let mut out = Vec::new();
    if lock.format == Format::V1 {
        // `group:artifact[:packaging[:classifier]]:version`.
        let tree = lock
            .root
            .get("dependency_tree")
            .and_then(|tree| tree.get("dependencies"));
        for dependency in tree
            .and_then(Node::items)
            .ok_or_else(|| bad("dependencies"))?
        {
            let coord = dependency
                .get("coord")
                .and_then(Node::as_str)
                .ok_or_else(|| bad("coord"))?;
            let parts: Vec<&str> = coord.split(':').collect();
            if !(3..=5).contains(&parts.len()) {
                return Err(bad(coord));
            }
            out.push(artifact(&parts, parts[parts.len() - 1], coord)?);
        }
    } else {
        // `group:artifact[:packaging[:classifier]]`, the version beside it.
        let artifacts = lock.root.get("artifacts").and_then(Node::members);
        for member in artifacts.ok_or_else(|| bad("artifacts"))? {
            let key = member.key.text.as_str();
            let parts: Vec<&str> = key.split(':').collect();
            let version = member.value.get("version").and_then(Node::as_str);
            match version {
                Some(version) if (2..=4).contains(&parts.len()) => {
                    out.push(artifact(&parts, version, key)?)
                }
                _ => return Err(bad(key)),
            }
        }
    }
    Ok(out)
}

/// The view this file has of the hub's lock, for a family with no enabled
/// lane: `Ok(None)` when it has none. An error is the root-relative file
/// at fault and what is wrong with it.
fn own_view(
    hub: &Hub,
    files: &dyn FileView,
) -> Result<Option<Vec<LockfileEntry>>, (String, String)> {
    if let RulesetDetail::RulesDotnet(detail) = &hub.detail {
        let file = &detail.data_file;
        let wrong = |why: String| (file.clone(), why);
        // The NuGet view: the package lines of the generated data file.
        // A file in another format, or one the recognizer does not vouch
        // for, is at fault itself: no missing lane is the reason.
        let packages = match &detail.data {
            PaketData::Group { packages, .. } => packages,
            PaketData::Single => {
                let why = "it is the single `paket.bzl` of rules_dotnet 0.10 to 0.12, which \
                           holds every group and is not listed";
                return Err(wrong(format!("{file}: {why}")));
            }
            PaketData::Tuple => {
                let why = "it holds the tuple entries of rules_dotnet 0.8 and 0.9, which are \
                           not listed";
                return Err(wrong(format!("{file}: {why}")));
            }
            // The recognizer's reason names the file.
            PaketData::Unknown(why) => return Err(wrong(why.clone())),
        };
        let listed = packages.iter().map(|package| {
            let (id, version) = (&package.id, package.version.as_str());
            let purl = simple_purl("nuget", id, version);
            let bad = || wrong(format!("{file}: `{id}` `{version}` is no NuGet package"));
            Ok(entry("nuget", id.clone(), version, purl.ok_or_else(bad)?))
        });
        return listed.collect::<Result<_, _>>().map(Some);
    }
    if hub.shape != HubShape::MavenPinned {
        return Ok(None);
    }
    let locks = hub
        .locks
        .iter()
        .filter(|lock| lock.role == LockRole::PackageLock);
    let mut out = Vec::new();
    for path in locks.filter_map(|lock| lock.path.as_deref()) {
        let text = files.read(path);
        let text = text.as_str().unwrap_or_default();
        out.extend(maven_view(text).map_err(|why| (path.to_string(), format!("{path}: {why}")))?);
    }
    Ok(Some(out))
}

/// What the lock of the hub `cx.hub` resolves, or why that is not known.
pub fn list(cx: &LaneCx<'_>, lanes: &LaneTable) -> Result<Vec<LockfileEntry>, Unlisted> {
    let hub = &cx.ws.hubs[cx.hub.0];
    let unlisted = |token, file: &str, detail: String| Unlisted {
        hub: Some(cx.hub),
        ecosystem: hub.ecosystem,
        token,
        file: file.to_string(),
        detail,
    };
    let package_locks = || {
        let locks = hub.locks.iter();
        locks.filter(|lock| lock.role == LockRole::PackageLock)
    };
    // Another module's `install` makes the hub: the lock Bazel builds it
    // from is that module's, and no file of this repository is it.
    if hub.liveness == Liveness::NotRootModule {
        let detail = format!(
            "{}: another module declares the {} hub `{}`, so the lock it is built from is not \
             in this repository",
            hub.decl.site.file,
            hub.ruleset.name(),
            hub.decl.apparent_name
        );
        return Err(unlisted(Some(HUB_NOT_ROOT_MODULE), "", detail));
    }
    for lock in package_locks() {
        let Some(path) = lock.path.as_deref() else {
            let detail = format!(
                "the lock label `{}` is computed or names no file of this repository",
                lock.label
            );
            return Err(unlisted(Some(LABEL_NOT_LITERAL), "", detail));
        };
        if lock_path_refused(hub, path) {
            let detail = format!("{path}: no reader lists a lock of this file name");
            return Err(unlisted(Some(LOCK_PATH), path, detail));
        }
        if cx.files.read(path).as_str().is_none() {
            let detail = format!("{path}: the lock is missing, cannot be read or is not UTF-8");
            return Err(unlisted(None, path, detail));
        }
    }
    let ops = lanes.0.iter().find(|(ruleset, _)| *ruleset == hub.ruleset);
    let text = |rel: &str| cx.files.read(rel).as_str().map(String::from);
    if let Some(entries) = ops.and_then(|(_, ops)| (ops.inventory)(cx, &text)) {
        return Ok(entries);
    }
    // An enabled lane is the one view of its family's locks: where it
    // cannot list one, this file's own view is not asked in its place,
    // and the lock is at fault, not a lane that is missing.
    let enabled = ops.is_some_and(|(_, ops)| ops.lanes.iter().any(|lane| lane.enabled));
    if enabled {
        let file = package_locks().find_map(|lock| lock.path.as_deref());
        let file = file.unwrap_or_default();
        let at = match file.is_empty() {
            true => String::new(),
            false => format!("{file}: "),
        };
        let detail = format!(
            "{at}the {} lane could not list what this lock resolves",
            hub.ruleset.name()
        );
        return Err(unlisted(None, file, detail));
    }
    match own_view(hub, cx.files) {
        Ok(Some(entries)) => Ok(entries),
        Ok(None) => {
            let detail = format!(
                "no lane lists what a {} lock resolves yet",
                hub.ruleset.name()
            );
            Err(unlisted(Some(LANE_NOT_ENABLED), "", detail))
        }
        Err((file, detail)) => Err(unlisted(None, &file, detail)),
    }
}

/// The patch UUIDs the owned index records wiring for, in any row list.
/// Each is in use whatever a lock resolves: the row is the record that
/// socket-patch wired the patch into the build, and only its removal
/// through the executor ends that.
pub fn wired(index: &Index) -> BTreeSet<String> {
    let uuids = (index.pins.iter().map(|row| &row.uuid))
        .chain(index.rc_flags.iter().map(|row| &row.uuid))
        .chain(index.segment.iter().map(|row| &row.uuid))
        .chain(index.bzl.iter().map(|row| &row.uuid))
        .chain(index.files.iter().map(|row| &row.uuid))
        .chain(index.tag_edits.iter().map(|row| &row.uuid))
        .chain(index.runs.iter().map(|row| &row.uuid));
    uuids.cloned().collect()
}

/// The inventory of the root `ws` was read from: every hub Bazel may
/// build from, listed through `lanes` or reported as unlisted, and one
/// hub-less [`Unlisted`] for each ecosystem in which something Bazel may
/// evaluate was not followed to a hub (`govern::unread_gaps`, the gaps
/// that make `govern::governance` answer `Undetermined` before it looks
/// at a hub). Those follow the hubs, so [`Inventory::cannot_enumerate`]
/// names a lock where one is at fault.
///
/// A lane's listing does not depend on the mode. It is asked as agent
/// mode, the one mode that writes into no lock, and with tool runs off.
pub fn inventory(
    ws: &BazelWorkspace,
    lanes: &LaneTable,
    files: &dyn FileView,
    index: &Index,
) -> Inventory {
    let (mut listed, mut unlisted, mut siblings) = (Vec::new(), Vec::new(), Vec::new());
    let building = || ws.hubs.iter().enumerate().filter(|(_, hub)| may_build(hub));
    for (id, hub) in building() {
        let cx = LaneCx {
            mode: Mode::Agent,
            files,
            ws,
            hub: HubId(id),
            index,
            run: RunPolicy::Never,
        };
        match list(&cx, lanes) {
            Ok(entries) => listed.push(Listed {
                hub: HubId(id),
                ecosystem: hub.ecosystem,
                entries,
            }),
            Err(why) => unlisted.push(why),
        }
        if let RulesetDetail::RulesJs(detail) = &hub.detail {
            siblings.extend(detail.sibling_locks.iter().cloned());
        }
    }
    // A sibling of one hub can be the lock another hub names.
    let read = |path: &String| {
        building().any(|(_, hub)| {
            hub.locks
                .iter()
                .any(|lock| lock.path.as_ref() == Some(path))
        })
    };
    siblings.retain(|path| !read(path));
    siblings.sort();
    siblings.dedup();
    // What was not read may be a hub, or name a lock, nobody listed.
    let mut ecosystems: Vec<Ecosystem> = Vec::new();
    for ecosystem in Ruleset::ALL
        .iter()
        .filter_map(|ruleset| ruleset.ecosystem())
    {
        if !ecosystems.contains(&ecosystem) {
            ecosystems.push(ecosystem);
        }
    }
    for ecosystem in ecosystems {
        if let Some(gap) = govern::unread_gaps(ws, ecosystem).into_iter().next() {
            unlisted.push(Unlisted {
                hub: None,
                ecosystem,
                token: Some(gap.token),
                file: gap.file,
                detail: gap.detail,
            });
        }
    }
    let mut resolved: BTreeMap<PurlKey, Vec<HubId>> = BTreeMap::new();
    for hub in &listed {
        for entry in &hub.entries {
            let hubs = resolved.entry(PurlKey::new(&entry.purl)).or_default();
            if hubs.last() != Some(&hub.hub) {
                hubs.push(hub.hub);
            }
        }
    }
    Inventory {
        listed,
        unlisted,
        non_consumers: siblings,
        wired: wired(index),
        resolved,
    }
}

impl Inventory {
    /// Every entry of every listed hub lock: what the prune universe gains.
    pub fn entries(&self) -> impl Iterator<Item = &LockfileEntry> {
        self.listed.iter().flat_map(|hub| &hub.entries)
    }

    /// The first lock of `ecosystem` that could not be listed: a hub's,
    /// or, after those, one of a hub nobody read.
    pub fn cannot_enumerate(&self, ecosystem: Ecosystem) -> Option<&Unlisted> {
        self.unlisted.iter().find(|hub| hub.ecosystem == ecosystem)
    }

    /// The workspace-wide lookup of the agent-basis check: whether a hub
    /// lock anywhere under the root resolves `purl`'s name and version.
    /// A lock of the ecosystem that could not be listed is in every
    /// answer but `No` ([`Resolved`]).
    pub fn resolves(&self, purl: &str) -> Resolved<'_> {
        let unlisted = Ecosystem::from_purl(purl).and_then(|e| self.cannot_enumerate(e));
        if let Some(by) = self.resolved.get(&PurlKey::new(purl)) {
            let hubs = by.clone();
            return Resolved::By { hubs, unlisted };
        }
        unlisted.map_or(Resolved::No, Resolved::CannotEnumerate)
    }

    /// Whether the Bazel build still uses the record of `purl` with patch
    /// `uuid`, for `scan --prune` and the vendor GC. `Some(true)`: a hub
    /// lock resolves the package, or the index records wiring for the
    /// patch. `None`: cannot tell, which callers treat as "keep" (and say
    /// so). `Some(false)`: nothing Bazel reads under this root holds it.
    pub fn in_use(&self, purl: &str, uuid: &str) -> Option<bool> {
        if self.wired.contains(uuid) {
            return Some(true);
        }
        match self.resolves(purl) {
            Resolved::By { .. } => Some(true),
            Resolved::CannotEnumerate(_) => None,
            Resolved::No => Some(false),
        }
    }

    /// The entries of `hub`'s lock that none of its `pins` covers: what
    /// the hub builds unpatched. Each contests a native reference to the
    /// same release in any project (`resolved_elsewhere`). `pins` are the
    /// references `lanes::discover` found for this hub.
    ///
    /// `Err` when the hub's lock could not be listed: what it builds
    /// unpatched is then not known, which is never "nothing", and it may
    /// contest any release of its ecosystem. `Ok` and empty for a hub
    /// that is neither listed nor unlisted: Bazel does not build from it
    /// ([`may_build`]) or the root has no such hub, so it builds nothing
    /// unpatched. The answer is of this hub alone: a caller that needs
    /// every contest of an ecosystem also asks [`Self::cannot_enumerate`],
    /// which knows of a hub nobody read.
    pub fn unpatched(
        &self,
        hub: HubId,
        pins: &[BazelRef],
    ) -> Result<Vec<&LockfileEntry>, &Unlisted> {
        if let Some(why) = self.unlisted.iter().find(|u| u.hub == Some(hub)) {
            return Err(why);
        }
        let pinned: Vec<PurlKey> = pins.iter().map(|pin| PurlKey::new(&pin.purl)).collect();
        let own = self.listed.iter().filter(|listed| listed.hub == hub);
        let entries = own.flat_map(|listed| &listed.entries);
        Ok(entries
            .filter(|e| !pinned.contains(&PurlKey::new(&e.purl)))
            .collect())
    }

    /// Whether `rel` is a lock of a governed ecosystem that no hub reads.
    pub fn is_non_consumer(&self, rel: &str) -> bool {
        self.non_consumers.iter().any(|path| path == rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::govern::tests::{read, JS_MODULE, JS_WORKSPACE};
    use crate::bazel::lanes;
    use crate::bazel::model::{AttestBasis, IndexRow, LaneId, LaneOps, LaneSpec, TextRead};
    use crate::bazel::owned_index::tests::revision_4;
    use crate::bazel::rc::testing::Files;

    const V1: &str =
        include_str!("../../tests/fixtures/bazel/rje_locks/probe/pin-rje4.5-bazel5.4.1-v1.json");
    const V2: &str =
        include_str!("../../tests/fixtures/bazel/rje_locks/probe/pin-rje5.3-bazel6.6.0-v2.json");
    const V3: &str = include_str!(
        "../../tests/fixtures/bazel/rje_locks/probe/pin-rje7.2-bazel8.8.2-v3-sources.json"
    );
    const GSON: &str = "pkg:maven/com.google.code.gson/gson@2.10.1";
    const GUAVA: &str = "pkg:maven/com.google.guava/guava@32.0.1-jre";
    const MAVEN: &str = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
        maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
        maven.install(lock_file = \"//:maven_install.json\")\nuse_repo(maven, \"maven\")\n";
    const MAVEN_WS: &str = "load(\"@rules_jvm_external//:defs.bzl\", \"maven_install\")\n\
        maven_install(name = \"maven_ws\", maven_install_json = \"//ws:maven_install.json\")\n";
    const NONE: LaneTable = LaneTable(&[]);

    fn purls<'a>(entries: impl Iterator<Item = &'a LockfileEntry>) -> Vec<&'a str> {
        let mut purls: Vec<&str> = entries.map(|e| e.purl.as_str()).collect();
        purls.sort_unstable();
        purls
    }

    fn inventoried(files: &[(&str, &str)], lanes: &LaneTable) -> (BazelWorkspace, Inventory) {
        let ws = read(files);
        let inventory = inventory(&ws, lanes, &Files::of(files), &Index::default());
        (ws, inventory)
    }

    /// Resolved by these hubs, with every lock of the ecosystem listed.
    fn by(hubs: &[usize]) -> Resolved<'static> {
        Resolved::By {
            hubs: hubs.iter().map(|id| HubId(*id)).collect(),
            unlisted: None,
        }
    }

    /// The first Maven view, over the three lock formats as real
    /// rules_jvm_external releases wrote them.
    #[test]
    fn the_maven_view_lists_every_artifact_of_each_lock_format() {
        let three = [
            GSON,
            "pkg:maven/org.slf4j/slf4j-api@1.7.36",
            "pkg:maven/org.slf4j/slf4j-simple@1.7.36",
        ];
        for lock in [V1, V2] {
            assert_eq!(purls(maven_view(lock).unwrap().iter()), three);
        }
        let v3 = maven_view(V3).unwrap();
        assert_eq!(v3.len(), 10);
        let guava = v3.iter().find(|e| e.purl == GUAVA).expect("guava");
        assert_eq!(
            (guava.ecosystem, guava.name.as_str()),
            ("maven", "com.google.guava:guava")
        );
        assert_eq!(guava.version, "32.0.1-jre");
        // A lock edited by hand no longer signs itself: not listed.
        let edited = V2.replace("\"version\": \"2.10.1\"", "\"version\": \"2.10.2\"");
        assert!(maven_view(&edited).unwrap_err().contains("content hash"));
        assert!(maven_view("{}").unwrap_err().contains("no lock"));
    }

    /// ROUTED R-087: on Bazel 7.7.2 with `common:ci --noenable_workspace`
    /// the WORKSPACE hub is evaluated by some commands only. It is not
    /// dead, so its lock is in the lookup and in the prune universe
    /// beside the lock of the live MODULE.bazel hub.
    #[test]
    fn a_contested_hub_is_listed_beside_a_live_one() {
        let files = [
            (".bazelversion", "7.7.2\n"),
            (".bazelrc", "common:ci --noenable_workspace\n"),
            ("MODULE.bazel", MAVEN),
            ("WORKSPACE", MAVEN_WS),
            ("maven_install.json", V2),
            ("ws/maven_install.json", V3),
        ];
        let (ws, found) = inventoried(&files, &NONE);
        let liveness: Vec<bool> = ws
            .hubs
            .iter()
            .map(|hub| hub.liveness == Liveness::Live)
            .collect();
        assert_eq!(liveness, [true, false], "{:?}", ws.hubs[1].liveness);
        assert!(matches!(ws.hubs[1].liveness, Liveness::Undecided { .. }));
        assert!(found.unlisted.is_empty(), "{:?}", found.unlisted);
        assert_eq!(found.resolves(GSON), by(&[0, 1]));
        assert_eq!(found.resolves(GUAVA), by(&[1]));
        assert_eq!(found.entries().count(), 13);
        assert!(found.entries().any(|e| e.purl == GUAVA));
        assert_eq!(found.in_use(GUAVA, "u"), Some(true));
        let other = "pkg:maven/com.google.guava/guava@33.0.0-jre";
        assert_eq!(
            (found.resolves(other), found.in_use(other, "u")),
            (Resolved::No, Some(false))
        );

        // Proven dead (Bazel 9 never opens WORKSPACE): its lock is not read.
        let (_, nine) = inventoried(
            &[
                (".bazelversion", "9.3.2\n"),
                files[2],
                files[3],
                files[4],
                files[5],
            ],
            &NONE,
        );
        assert_eq!(nine.resolves(GUAVA), Resolved::No);
        assert_eq!(nine.listed.len(), 1);
    }

    /// Three stored liveness values are no proof that Bazel skips the
    /// hub. A dev hub under a flag that is only possible is listed from
    /// its lock. A hub another module makes is one Bazel builds from, and
    /// its lock is not here. A hub the root imports by a spoke alone is
    /// asked like any other.
    #[test]
    fn a_dev_a_foreign_and_a_spoke_only_hub_are_hubs_bazel_may_build_from() {
        let nine = (".bazelversion", "9.3.2\n");
        let dev = MAVEN.replacen("\"maven\")\n", "\"maven\", dev_dependency = True)\n", 1);
        let files = [
            nine,
            (".bazelrc", "common:ci --ignore_dev_dependency\n"),
            ("MODULE.bazel", dev.as_str()),
            ("maven_install.json", V2),
        ];
        let (ws, found) = inventoried(&files, &NONE);
        assert_eq!(ws.hubs[0].liveness, Liveness::DevDependencyDropped);
        assert!(found.unlisted.is_empty(), "{:?}", found.unlisted);
        assert_eq!(found.entries().count(), 3);
        assert!(found.entries().any(|e| e.purl == GSON));
        assert_eq!(found.resolves(GSON), by(&[0]));
        assert_eq!(found.in_use(GSON, "u"), Some(true));

        // Root tags on the hub of another module's `install`.
        let foreign = "bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            maven.artifact(name = \"maven\", group = \"junit\", artifact = \"junit\", version = \"4.13.2\")\n\
            use_repo(maven, \"maven\")\n";
        let junit = "pkg:maven/junit/junit@4.13.2";
        for lanes in [&NONE, &lanes::PRODUCTION, &LISTS_NOTHING] {
            let (ws, found) = inventoried(&[nine, ("MODULE.bazel", foreign)], lanes);
            assert_eq!(ws.hubs[0].liveness, Liveness::NotRootModule);
            let Resolved::CannotEnumerate(why) = found.resolves(junit) else {
                panic!("{:?}", found.resolves(junit));
            };
            assert_eq!(
                (why.hub, why.token, why.file.as_str()),
                (Some(HubId(0)), Some("hub_not_root_module"), "")
            );
            assert!(why.detail.contains("another module"), "{}", why.detail);
            assert_eq!(found.in_use(junit, "u"), None);
            assert!(found.listed.is_empty());
        }

        let spoke = JS_MODULE.replace(
            "use_repo(npm, \"npm\")",
            "use_repo(npm, \"npm__left-pad__1.3.0\")",
        );
        let files = [
            nine,
            ("MODULE.bazel", spoke.as_str()),
            ("pnpm-lock.yaml", "left-pad@1.3.0\n"),
        ];
        let (ws, found) = inventoried(&files, &lanes::PRODUCTION);
        assert_eq!(ws.hubs[0].liveness, Liveness::NotImported);
        let why = found.cannot_enumerate(Ecosystem::Npm).expect("unlisted");
        assert_eq!(why.hub, Some(HubId(0)));
        assert_eq!(found.in_use("pkg:npm/left-pad@1.3.0", "u"), None);
        // With a lane that lists the lock, the spoke's package is in use.
        let (_, found) = inventoried(&files, &TOY);
        assert_eq!(found.resolves("pkg:npm/left-pad@1.3.0"), by(&[0]));
        assert_eq!(found.in_use("pkg:npm/left-pad@1.3.0", "u"), Some(true));
    }

    /// A declaration nobody followed to a hub may be a hub: the ecosystem
    /// cannot be enumerated, with no hub to name. One in a file Bazel
    /// never evaluates declares nothing.
    #[test]
    fn what_was_not_followed_to_a_hub_leaves_its_ecosystem_unlisted() {
        let maven = |found: &Inventory| {
            let Resolved::CannotEnumerate(why) = found.resolves(GSON) else {
                panic!("{:?}", found.resolves(GSON));
            };
            assert_eq!(found.in_use(GSON, "u"), None);
            // Another ecosystem is not held up.
            assert_eq!(found.in_use("pkg:npm/left-pad@1.3.0", "u"), Some(false));
            assert_eq!(found.resolves("pkg:npm/left-pad@1.3.0"), Resolved::No);
            assert_eq!(found.cannot_enumerate(Ecosystem::Npm), None);
            (why.hub, why.token, why.file.clone())
        };
        // The ruleset is a dependency and no hub was read.
        let signal = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";
        let (ws, found) = inventoried(&[("MODULE.bazel", signal)], &lanes::PRODUCTION);
        assert!(ws.hubs.is_empty() && ws.signals.len() == 1);
        assert!(found.listed.is_empty());
        let none: Option<HubId> = None;
        assert_eq!(
            maven(&found),
            (none, Some("label_not_literal"), "MODULE.bazel".to_string())
        );

        // A hub whose name is computed is no hub of the model.
        let computed = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            NAME = \"maven\"\n\
            maven.install(name = NAME + \"_x\", lock_file = \"//:maven_install.json\")\n\
            use_repo(maven, \"maven_x\")\n";
        let files = [("MODULE.bazel", computed), ("maven_install.json", V2)];
        let (ws, found) = inventoried(&files, &lanes::PRODUCTION);
        assert!(ws.hubs.is_empty() && !ws.ruleset_gaps.is_empty());
        assert_eq!(
            maven(&found),
            (none, Some("label_not_literal"), "MODULE.bazel".to_string())
        );

        // The same use in a `WORKSPACE`: Bazel 6 evaluates it, and Bazel
        // 9 never opens the file.
        let archive = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
            http_archive(\n    name = \"rules_jvm_external\",\n    strip_prefix = \"rules_jvm_external-5.3\",\n    \
            url = \"https://github.com/bazelbuild/rules_jvm_external/releases/download/5.3/rules_jvm_external-5.3.tar.gz\",\n)\n";
        let six = [(".bazelversion", "6.6.0\n"), ("WORKSPACE", archive)];
        let (ws, found) = inventoried(&six, &lanes::PRODUCTION);
        assert_eq!(ws.signals.len(), 1);
        assert_eq!(
            maven(&found),
            (none, Some("label_not_literal"), "WORKSPACE".to_string())
        );
        let nine = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", ""),
            ("WORKSPACE", archive),
        ];
        let (ws, found) = inventoried(&nine, &lanes::PRODUCTION);
        assert_eq!(ws.signals.len(), 1);
        assert!(found.unlisted.is_empty(), "{:?}", found.unlisted);
        assert_eq!(
            (found.resolves(GSON), found.in_use(GSON, "u")),
            (Resolved::No, Some(false))
        );
    }

    /// The two conditions of the agent-basis check are independent: a
    /// release one hub's lock resolves may be built by another hub whose
    /// lock could not be listed. The lookup carries both, and what an
    /// unlisted hub builds unpatched is never an empty answer.
    #[test]
    fn a_resolved_release_still_names_the_lock_that_could_not_be_listed() {
        let two = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            maven.install(name = \"maven\", lock_file = \"//:maven_install.json\")\n\
            maven.install(name = \"other\", lock_file = \"//:other_install.json\")\n\
            use_repo(maven, \"maven\", \"other\")\n";
        let files = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", two),
            ("maven_install.json", V2),
        ];
        let (ws, found) = inventoried(&files, &NONE);
        assert_eq!(ws.hubs.len(), 2);
        let missing = found.cannot_enumerate(Ecosystem::Maven).expect("unlisted");
        assert_eq!(
            (missing.hub, missing.file.as_str()),
            (Some(HubId(1)), "other_install.json")
        );
        let resolved = Resolved::By {
            hubs: vec![HubId(0)],
            unlisted: Some(missing),
        };
        assert_eq!(found.resolves(GSON), resolved);
        assert_ne!(found.resolves(GSON), by(&[0]));
        assert_eq!(found.in_use(GSON, "u"), Some(true));
        assert_eq!(
            found.resolves(GUAVA),
            Resolved::CannotEnumerate(missing),
            "no listed lock resolves it"
        );
        assert_eq!(found.unpatched(HubId(0), &[]).map(|e| e.len()), Ok(3));
        assert_eq!(
            found.unpatched(HubId(1), &[]).map(|e| e.len()),
            Err(missing)
        );
    }

    /// The contest: what a hub builds unpatched is every entry no pin of
    /// its own covers.
    #[test]
    fn unpatched_entries_are_those_no_pin_of_the_hub_covers() {
        let (_, found) = inventoried(
            &[("MODULE.bazel", MAVEN), ("maven_install.json", V2)],
            &NONE,
        );
        let pin = BazelRef {
            lane: LaneId("H-MVN1"),
            purl: GSON.to_string(),
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            file: "maven_install.json".to_string(),
            basis: AttestBasis::BazelLock,
        };
        assert_eq!(found.unpatched(HubId(0), &[]).map(|e| e.len()), Ok(3));
        let left = found.unpatched(HubId(0), std::slice::from_ref(&pin));
        let left = left.expect("listed");
        assert_eq!(left.len(), 2);
        assert!(left.iter().all(|e| e.purl != GSON));
        // No such hub, and a hub Bazel never builds from, build nothing.
        assert_eq!(found.unpatched(HubId(3), &[]).map(|e| e.len()), Ok(0));
        let files = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", ""),
            ("WORKSPACE", MAVEN_WS),
            ("ws/maven_install.json", V3),
        ];
        let (ws, dead) = inventoried(&files, &NONE);
        assert!(matches!(ws.hubs[0].liveness, Liveness::Dead { .. }));
        assert!(dead.listed.is_empty() && dead.unlisted.is_empty());
        assert_eq!(dead.unpatched(HubId(0), &[]).map(|e| e.len()), Ok(0));
    }

    /// A lock that cannot be enumerated is never an empty one: the
    /// lookup says so, and the prune keeps.
    #[test]
    fn a_lock_that_cannot_be_enumerated_answers_keep() {
        let case = |files: &[(&str, &str)]| {
            let (_, found) = inventoried(files, &lanes::PRODUCTION);
            assert!(found.listed.is_empty(), "{:?}", found.listed);
            assert_eq!(found.in_use(GSON, "u"), None);
            assert!(matches!(found.resolves(GSON), Resolved::CannotEnumerate(_)));
            // Another ecosystem is not held up.
            assert_eq!(found.in_use("pkg:npm/left-pad@1.3.0", "u"), Some(false));
            let why = found
                .cannot_enumerate(Ecosystem::Maven)
                .expect("unlisted")
                .clone();
            (why.token, why.file, why.detail)
        };
        let (token, file, _) = case(&[("MODULE.bazel", MAVEN)]);
        assert_eq!((token, file.as_str()), (None, "maven_install.json"));
        let (token, _, detail) = case(&[("MODULE.bazel", MAVEN), ("maven_install.json", "{}")]);
        assert!(
            token.is_none() && detail.contains("no lock rules_jvm_external reads"),
            "{detail}"
        );
        let foreign = MAVEN.replace("//:maven_install.json", "@other//:maven_install.json");
        let (token, file, _) = case(&[("MODULE.bazel", &foreign)]);
        assert_eq!((token, file.as_str()), (Some("label_not_literal"), ""));

        // A native lock has no view until its lane lands, and a lock
        // under a name the path rule refuses is not listed by any.
        let (_, js) = inventoried(
            &[
                ("MODULE.bazel", JS_MODULE),
                ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ],
            &lanes::PRODUCTION,
        );
        let why = js.cannot_enumerate(Ecosystem::Npm).expect("unlisted");
        assert_eq!(why.token, Some("lane_not_enabled"));
        let cargo = "bazel_dep(name = \"rules_rust\", version = \"0.57.0\")\n\
            crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
            crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.Bazel.lock\", manifests = [\"//:Cargo.toml\"])\n\
            use_repo(crate, \"crates\")\n";
        let (ws, rust) = inventoried(
            &[
                ("MODULE.bazel", cargo),
                ("Cargo.Bazel.lock", "version = 3\n"),
            ],
            &TOY,
        );
        assert!(lock_path_refused(&ws.hubs[0], "Cargo.Bazel.lock"));
        assert!(!lock_path_refused(&ws.hubs[0], "third_party/Cargo.lock"));
        let why = rust.cannot_enumerate(Ecosystem::Cargo).expect("unlisted");
        assert_eq!(
            (why.token, why.file.as_str()),
            (Some("lock_path"), "Cargo.Bazel.lock")
        );
    }

    /// A toy family: one `name@version` per line of the hub's first lock.
    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let lock = cx.ws.hubs[cx.hub.0].locks.first()?.path.as_deref()?;
        let text = read(lock)?;
        let lines = text.lines().filter_map(|line| line.split_once('@'));
        Some(
            lines
                .map(|(n, v)| entry("npm", n.to_string(), v, format!("pkg:npm/{n}@{v}")))
                .collect(),
        )
    }
    const TOY_LANES: &[LaneSpec] = &[LaneSpec::stub("H-TOY1", Mode::Hosted, &[])];
    const TOY_OPS: LaneOps = LaneOps {
        inventory: toy_inventory,
        ..LaneOps::disabled(TOY_LANES)
    };
    const TOY: LaneTable =
        LaneTable(&[(Ruleset::RulesJs, &TOY_OPS), (Ruleset::RulesRust, &TOY_OPS)]);

    /// An enabled family whose lane cannot list a lock.
    const ENABLED_LANES: &[LaneSpec] = &[LaneSpec {
        enabled: true,
        ..LaneSpec::stub("H-TOY2", Mode::Hosted, &[])
    }];
    const LISTS_NOTHING_OPS: LaneOps = LaneOps::disabled(ENABLED_LANES);
    const LISTS_NOTHING: LaneTable = LaneTable(&[
        (Ruleset::RulesJvmExternal, &LISTS_NOTHING_OPS),
        (Ruleset::RulesDotnet, &LISTS_NOTHING_OPS),
    ]);

    /// An enabled lane is the one view of its family's locks. Where it
    /// cannot list one, the views of this file do not stand in for it,
    /// and the lock is named: no lane is missing.
    #[test]
    fn an_enabled_lane_that_cannot_list_is_not_replaced_by_the_own_view() {
        let files = [("MODULE.bazel", MAVEN), ("maven_install.json", V2)];
        let (_, own) = inventoried(&files, &NONE);
        assert_eq!(own.entries().count(), 3);
        // A family whose lanes are all disabled keeps the own view.
        const STUB_OPS: LaneOps = LaneOps::disabled(TOY_LANES);
        const STUB: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &STUB_OPS)]);
        assert_eq!(inventoried(&files, &STUB).1.entries().count(), 3);

        let (_, found) = inventoried(&files, &LISTS_NOTHING);
        assert_eq!(found.entries().count(), 0);
        let [why] = &found.unlisted[..] else {
            panic!("{:?}", found.unlisted);
        };
        assert_eq!(
            (why.hub, why.token, why.file.as_str()),
            (Some(HubId(0)), None, "maven_install.json")
        );
        assert_eq!(
            why.detail,
            "maven_install.json: the rules_jvm_external lane could not list what this lock resolves"
        );
        assert_eq!(found.in_use(GSON, "u"), None);
    }

    /// A sibling lock that another hub Bazel may build from names is that
    /// hub's lock, not a file no hub reads.
    #[test]
    fn a_sibling_lock_another_hub_names_is_a_consumer() {
        let nodejs = "http_archive(name = \"build_bazel_rules_nodejs\", urls = [\"https://example.com/rules_nodejs-5.8.5.tar.gz\"])\n\
            load(\"@build_bazel_rules_nodejs//:index.bzl\", \"npm_install\")\n\
            npm_install(\n    name = \"npm_legacy\",\n    package_json = \"//:package.json\",\n    \
            package_lock_json = \"//:package-lock.json\",\n)\n";
        let both = format!("{JS_WORKSPACE}{nodejs}");
        let files = [
            (".bazelversion", "6.6.0\n"),
            ("WORKSPACE", both.as_str()),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ("package-lock.json", "{}\n"),
        ];
        let (ws, found) = inventoried(&files, &NONE);
        fn package_locks(hub: &Hub) -> Vec<Option<&str>> {
            let locks = hub.locks.iter();
            let locks = locks.filter(|lock| lock.role == LockRole::PackageLock);
            locks.map(|lock| lock.path.as_deref()).collect()
        }
        let locks: Vec<Vec<Option<&str>>> = ws.hubs.iter().map(package_locks).collect();
        assert_eq!(
            locks,
            [
                vec![Some("pnpm-lock.yaml")],
                vec![Some("package-lock.json")]
            ]
        );
        assert!(ws.hubs.iter().all(may_build), "{:?}", ws.hubs);
        assert_eq!(found.non_consumers, [""; 0]);
        assert!(!found.is_non_consumer("package-lock.json"));

        // Without the second hub the file is read by no hub.
        let alone = [files[0], ("WORKSPACE", JS_WORKSPACE), files[2], files[3]];
        assert_eq!(
            inventoried(&alone, &NONE).1.non_consumers,
            ["package-lock.json"]
        );
        // So it is when the hub that names it is one Bazel never
        // evaluates: Bazel 9 opens no `WORKSPACE`.
        let legacy = format!(
            "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n{nodejs}"
        );
        let dead = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", JS_MODULE),
            ("WORKSPACE", legacy.as_str()),
            files[2],
            files[3],
        ];
        let (ws, found) = inventoried(&dead, &NONE);
        assert_eq!(ws.hubs.len(), 2, "{:?}", ws.hubs);
        assert_eq!(found.non_consumers, ["package-lock.json"]);
    }

    /// The lane's listing is the hub's inventory, and a same-ecosystem
    /// lock beside the governed one is marked as read by no hub.
    #[test]
    fn a_lane_lists_its_lock_and_a_sibling_lock_is_no_consumer() {
        let files = [
            ("MODULE.bazel", JS_MODULE),
            ("pnpm-lock.yaml", "left-pad@1.3.0\nis-odd@3.0.1\n"),
            ("package-lock.json", "{}\n"),
        ];
        let (_, found) = inventoried(&files, &TOY);
        assert_eq!(
            purls(found.entries()),
            ["pkg:npm/is-odd@3.0.1", "pkg:npm/left-pad@1.3.0"]
        );
        assert_eq!(found.resolves("pkg:npm/left-pad@1.3.0"), by(&[0]));
        assert_eq!(found.in_use("pkg:npm/left-pad@1.2.0", "u"), Some(false));
        assert_eq!(found.non_consumers, ["package-lock.json"]);
        assert!(
            found.is_non_consumer("package-lock.json") && !found.is_non_consumer("pnpm-lock.yaml")
        );
    }

    /// The NuGet view, and revision 4: a patch the index records wiring
    /// for is in use whatever the locks resolve.
    #[test]
    fn the_nuget_view_lists_a_paket_group_and_index_rows_keep_their_patches() {
        // The pair `paket2bazel` of rules_dotnet 0.22.2 writes (probe U3).
        let line = |id: &str| {
            format!(
                "            {{\"name\": \"{id}\", \"id\": \"{id}\", \"version\": \"1.0.0\", \"sha512\": \
                 \"sha512-UYYndM/8aEsn2NPPHecSroWYSo3HDOkkfkQNjT/ZOD6Bjq/KiIwiAztAkfWyVdctVooIskr8ELkRXrcKGMWyJQ==\", \
                 \"sources\": [\"https://nuget.fixture.invalid/nuget/v3/index.json\"], \"dependencies\": \
                 {{\"net8.0\": []}}, \"targeting_pack_overrides\": [], \"framework_list\": [], \"tools\": {{}}}},\n"
            )
        };
        let data = format!(
            "\"GENERATED\"\n\nload(\"@rules_dotnet//dotnet:defs.bzl\", \"nuget_repo\")\n\ndef main():\n    \
             \"main\"\n    nuget_repo(\n        name = \"paket.main\",\n        packages = [\n{}{}        ],\n    )\n",
            line("SP.Other"),
            line("SP.Victim")
        );
        let extension = "\"Generated\"\n\nload(\":paket.main.bzl\", _main = \"main\")\n\n\
            def _main_impl(module_ctx):\n    _main()\n    return module_ctx.extension_metadata(reproducible = True)\n\n\
            main_extension = module_extension(\n    implementation = _main_impl,\n)\n";
        let module = "bazel_dep(name = \"rules_dotnet\", version = \"0.22.2\")\n\
            main_extension = use_extension(\"//:paket.main_extension.bzl\", \"main_extension\")\n\
            use_repo(main_extension, \"paket.main\")\n";
        let files = [
            ("MODULE.bazel", module),
            ("paket.main.bzl", data.as_str()),
            ("paket.main_extension.bzl", extension),
        ];
        let (ws, found) = inventoried(&files, &NONE);
        assert!(
            found.unlisted.is_empty(),
            "{:?} {:?}",
            found.unlisted,
            ws.hubs
        );
        assert_eq!(
            purls(found.entries()),
            ["pkg:nuget/SP.Other@1.0.0", "pkg:nuget/SP.Victim@1.0.0"]
        );
        // NuGet compares names without case.
        assert_eq!(found.resolves("pkg:nuget/sp.victim@1.0.0"), by(&[0]));

        // Revision 4: each row list of the index keeps its patch on its
        // own, whatever the locks resolve.
        let all = revision_4();
        let pin = IndexRow {
            uuid: String::new(),
            purl: "pkg:nuget/Serilog@3.0.0".to_string(),
            lane: "H-NUG1".to_string(),
            file: "paket.main.bzl".to_string(),
            edits: Vec::new(),
            check: None,
        };
        let none = Index::default;
        let mut lists = [
            (
                "pins",
                Index {
                    pins: vec![pin],
                    ..none()
                },
            ),
            (
                "rcFlags",
                Index {
                    rc_flags: all.rc_flags,
                    ..none()
                },
            ),
            (
                "segment",
                Index {
                    segment: all.segment,
                    ..none()
                },
            ),
            (
                "bzl",
                Index {
                    bzl: all.bzl,
                    ..none()
                },
            ),
            (
                "files",
                Index {
                    files: all.files,
                    ..none()
                },
            ),
            (
                "tagEdits",
                Index {
                    tag_edits: all.tag_edits,
                    ..none()
                },
            ),
            (
                "runs",
                Index {
                    runs: all.runs,
                    ..none()
                },
            ),
        ];
        let unresolved = "pkg:nuget/Serilog@3.0.0";
        for (list, index) in &mut lists {
            // A UUID no other list of any index here holds.
            let uuid = format!("0000{list}");
            let rows = (index.pins.iter_mut().map(|row| &mut row.uuid))
                .chain(index.rc_flags.iter_mut().map(|row| &mut row.uuid))
                .chain(index.segment.iter_mut().map(|row| &mut row.uuid))
                .chain(index.bzl.iter_mut().map(|row| &mut row.uuid))
                .chain(index.files.iter_mut().map(|row| &mut row.uuid))
                .chain(index.tag_edits.iter_mut().map(|row| &mut row.uuid))
                .chain(index.runs.iter_mut().map(|row| &mut row.uuid));
            let rows: Vec<&mut String> = rows.collect();
            assert_eq!(rows.len(), 1, "{list}: one row in one list");
            for row in rows {
                row.clone_from(&uuid);
            }
            assert_eq!(wired(index), BTreeSet::from([uuid.clone()]), "{list}");
            let kept = inventory(&ws, &NONE, &Files::of(&files), index);
            assert_eq!(kept.in_use(unresolved, &uuid), Some(true), "{list}");
            assert_eq!(kept.in_use(unresolved, "another"), Some(false), "{list}");
        }
        assert_eq!(found.in_use(unresolved, "0000files"), Some(false));
    }

    /// A paket data file that is not the one format this file lists is
    /// at fault itself: the answer names it and blames no missing lane.
    #[test]
    fn a_paket_file_in_another_format_is_named_and_no_lane_is_blamed() {
        let line = "            {\"name\": \"SP.Victim\", \"id\": \"SP.Victim\", \"version\": \"1.0.0\", \"sha512\": \
             \"sha512-UYYndM/8aEsn2NPPHecSroWYSo3HDOkkfkQNjT/ZOD6Bjq/KiIwiAztAkfWyVdctVooIskr8ELkRXrcKGMWyJQ==\", \
             \"sources\": [\"https://nuget.fixture.invalid/nuget/v3/index.json\"], \"dependencies\": \
             {\"net8.0\": []}, \"targeting_pack_overrides\": [], \"framework_list\": [], \"tools\": {}},\n";
        let nuget_repo = |packages: &str| {
            format!(
                "    nuget_repo(\n        name = \"paket.main\",\n        packages = {packages}[\n{line}        ],\n    )\n"
            )
        };
        let head = "\"GENERATED\"\n\nload(\"@rules_dotnet//dotnet:defs.bzl\", \"nuget_repo\")\n\n";
        let unlisted = |files: &[(&str, &str)]| {
            let (ws, found) = inventoried(files, &NONE);
            assert_eq!(ws.hubs.len(), 1, "{:?}", ws.hubs);
            assert!(found.listed.is_empty(), "{:?}", found.listed);
            assert_eq!(found.in_use("pkg:nuget/SP.Victim@1.0.0", "u"), None);
            let why = found.cannot_enumerate(Ecosystem::Nuget).expect("unlisted");
            assert_eq!(why.hub, Some(HubId(0)));
            (why.token, why.file.clone(), why.detail.clone())
        };

        // A per-group file edited by hand: the recognizer's reason.
        let extension = "\"Generated\"\n\nload(\":paket.main.bzl\", _main = \"main\")\n\n\
            def _main_impl(module_ctx):\n    _main()\n    return module_ctx.extension_metadata(reproducible = True)\n\n\
            main_extension = module_extension(\n    implementation = _main_impl,\n)\n";
        let module = "bazel_dep(name = \"rules_dotnet\", version = \"0.22.2\")\n\
            main_extension = use_extension(\"//:paket.main_extension.bzl\", \"main_extension\")\n\
            use_repo(main_extension, \"paket.main\")\n";
        let edited = format!(
            "{head}def main():\n    \"main\"\n{}",
            nuget_repo("EXTRA + ")
        );
        let (token, file, detail) = unlisted(&[
            ("MODULE.bazel", module),
            ("paket.main.bzl", &edited),
            ("paket.main_extension.bzl", extension),
        ]);
        assert_eq!((token, file.as_str()), (None, "paket.main.bzl"));
        assert!(detail.starts_with("`paket.main.bzl` "), "{detail}");
        assert!(!detail.contains("lane"), "{detail}");

        // The single `paket.bzl` of rules_dotnet 0.10 to 0.12.
        let workspace = "load(\"@rules_dotnet//dotnet:repositories.bzl\", \"rules_dotnet_dependencies\")\n\n\
            rules_dotnet_dependencies()\n\nload(\"//paket/deps:paket.bzl\", \"paket\")\n\npaket()\n";
        let single = format!(
            "{head}def paket():\n    \"paket\"\n{}{}",
            nuget_repo(""),
            nuget_repo("").replace("paket.main", "paket.other")
        );
        let (token, file, detail) = unlisted(&[
            (".bazelversion", "6.6.0\n"),
            ("WORKSPACE", workspace),
            ("paket/deps/paket.bzl", &single),
        ]);
        assert_eq!((token, file.as_str()), (None, "paket/deps/paket.bzl"));
        assert_eq!(
            detail,
            "paket/deps/paket.bzl: it is the single `paket.bzl` of rules_dotnet 0.10 to 0.12, \
             which holds every group and is not listed"
        );

        // The tuple entries of rules_dotnet 0.8 and 0.9.
        let tuples = format!(
            "{head}def paket():\n    \"paket\"\n    nuget_repo(\n        name = \"paket.main\",\n        \
             packages = [\n            (\"Argu\", \"6.1.1\", \
             \"sha512-ed1N3RMohnxS54MYuMgPz3766hXItY3L12IrPazZ+F8CXPKkxyV+p8xVkWmE5NDnRhEvaWptRhBrXstK9DhS/w==\", \
             [\"FSharp.Core\"], []),\n        ],\n    )\n"
        );
        let (ws, found) = inventoried(
            &[
                (".bazelversion", "6.6.0\n"),
                ("WORKSPACE", workspace),
                ("paket/deps/paket.bzl", &tuples),
            ],
            &NONE,
        );
        assert_eq!(ws.hubs.len(), 1, "{:?}", ws.hubs);
        let why = found.cannot_enumerate(Ecosystem::Nuget).expect("unlisted");
        assert_eq!(
            (why.token, why.file.as_str(), why.detail.as_str()),
            (
                None,
                "paket/deps/paket.bzl",
                "paket/deps/paket.bzl: it holds the tuple entries of rules_dotnet 0.8 and 0.9, \
                 which are not listed"
            )
        );
        assert_eq!(found.in_use("pkg:nuget/Argu@6.1.1", "u"), None);

        // An enabled lane that cannot list the file names it as well.
        let (_, found) = inventoried(
            &[
                ("MODULE.bazel", module),
                ("paket.main.bzl", &edited),
                ("paket.main_extension.bzl", extension),
            ],
            &LISTS_NOTHING,
        );
        let why = found.cannot_enumerate(Ecosystem::Nuget).expect("unlisted");
        assert_eq!((why.token, why.file.as_str()), (None, "paket.main.bzl"));
    }
}
