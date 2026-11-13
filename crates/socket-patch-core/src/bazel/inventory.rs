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
//! - **Every hub Bazel may build from is asked** ([`may_build`]): a live
//!   one, and one that is evaluated under only some of the dependency
//!   systems the workspace may run. Dropping the second would prune a
//!   record Bazel consumes (probe B5) and attest a tree it does not build.
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
//!   ([`lock_path_refused`]), a lock that is missing or cannot be read and
//!   a family with no view yet are each [`Unlisted`]: the manifest half of
//!   the prune is skipped for that ecosystem, and `vex` answers "consumer
//!   undetermined".
//!
//! What the owned index records is in use whatever a lock says
//! ([`wired`]): a pin can rename its own lock entry, and an artifact that
//! an `rcFlags` or `files` row names is one the build reads (revision 4,
//! section 5).

use std::collections::{BTreeMap, BTreeSet};

use super::govern::LABEL_NOT_LITERAL;
use super::model::{
    BazelRef, BazelWorkspace, FileView, Hub, HubId, HubShape, Index, LaneCx, LaneTable, Liveness,
    LockRole, Mode, RulesetDetail, RunPolicy, LANE_NOT_ENABLED,
};
use super::rje_lock::{self, Format, Node};
use super::rulesets::rules_csharp::LOCK_PATH;
use super::rulesets::rules_dotnet::PaketData;
use crate::crawlers::types::Ecosystem;
use crate::formats::registry;
use crate::utils::purl::{maven_purl, simple_purl};
use crate::utils::purl_key::PurlKey;
use crate::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

/// Whether Bazel may build from the hub: it is live, or no single answer
/// exists (evaluated under one dependency system the workspace may run
/// and not under another, or what decides it was not read). Every other
/// liveness is proven: Bazel does not read that hub's lock.
pub fn may_build(hub: &Hub) -> bool {
    matches!(hub.liveness, Liveness::Live | Liveness::Undecided { .. })
}

/// What one hub's lock resolves.
#[derive(Debug, Clone)]
pub struct Listed {
    pub hub: HubId,
    pub ecosystem: Ecosystem,
    pub entries: Vec<LockfileEntry>,
}

/// A hub Bazel may build from whose lock could not be enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    pub hub: HubId,
    pub ecosystem: Ecosystem,
    /// The token of the case, where the contract has one.
    pub token: Option<&'static str>,
    /// The root-relative lock, `""` when no one file is at fault.
    pub file: String,
    pub detail: String,
}

/// Whether any hub lock of the workspace resolves a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// Every hub lock of the ecosystem was listed and none resolves it.
    No,
    /// These hubs build it from their locks.
    By(Vec<HubId>),
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
/// lane: `Ok(None)` when it has none.
fn own_view(
    hub: &Hub,
    files: &dyn FileView,
) -> Result<Option<Vec<LockfileEntry>>, (String, String)> {
    if let RulesetDetail::RulesDotnet(detail) = &hub.detail {
        let PaketData::Group { packages, .. } = &detail.data else {
            return Ok(None);
        };
        // The NuGet view: the package lines of the generated data file.
        let listed = packages.iter().map(|package| {
            let (id, version) = (&package.id, package.version.as_str());
            let purl = simple_purl("nuget", id, version);
            let bad = || {
                (
                    detail.data_file.clone(),
                    format!("`{id}` `{version}` is no NuGet package"),
                )
            };
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
        out.extend(maven_view(text).map_err(|why| (path.to_string(), why))?);
    }
    Ok(Some(out))
}

/// What the lock of the hub `cx.hub` resolves, or why that is not known.
pub fn list(cx: &LaneCx<'_>, lanes: &LaneTable) -> Result<Vec<LockfileEntry>, Unlisted> {
    let hub = &cx.ws.hubs[cx.hub.0];
    let unlisted = |token, file: &str, detail: String| Unlisted {
        hub: cx.hub,
        ecosystem: hub.ecosystem,
        token,
        file: file.to_string(),
        detail,
    };
    for lock in hub
        .locks
        .iter()
        .filter(|lock| lock.role == LockRole::PackageLock)
    {
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
    // An enabled lane is the one view of its family's locks.
    let enabled = ops.is_some_and(|(_, ops)| ops.lanes.iter().any(|lane| lane.enabled));
    let own = if enabled {
        Ok(None)
    } else {
        own_view(hub, cx.files)
    };
    match own {
        Ok(Some(entries)) => Ok(entries),
        Ok(None) => {
            let detail = format!(
                "no lane lists what a {} lock resolves yet",
                hub.ruleset.name()
            );
            Err(unlisted(Some(LANE_NOT_ENABLED), "", detail))
        }
        Err((file, why)) => Err(unlisted(None, &file, format!("{file}: {why}"))),
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
/// build from, listed through `lanes` or reported as unlisted.
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

    /// The first hub of `ecosystem` whose lock could not be listed.
    pub fn cannot_enumerate(&self, ecosystem: Ecosystem) -> Option<&Unlisted> {
        self.unlisted.iter().find(|hub| hub.ecosystem == ecosystem)
    }

    /// The workspace-wide lookup of the agent-basis check: whether a hub
    /// lock anywhere under the root resolves `purl`'s name and version.
    pub fn resolves(&self, purl: &str) -> Resolved<'_> {
        if let Some(by) = self.resolved.get(&PurlKey::new(purl)) {
            return Resolved::By(by.clone());
        }
        let unlisted = Ecosystem::from_purl(purl).and_then(|e| self.cannot_enumerate(e));
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
            Resolved::By(_) => Some(true),
            Resolved::CannotEnumerate(_) => None,
            Resolved::No => Some(false),
        }
    }

    /// The entries of `hub`'s lock that none of its `pins` covers: what
    /// the hub builds unpatched. Each contests a native reference to the
    /// same release in any project (`resolved_elsewhere`). `pins` are the
    /// references `lanes::discover` found for this hub.
    pub fn unpatched(&self, hub: HubId, pins: &[BazelRef]) -> Vec<&LockfileEntry> {
        let pinned: Vec<PurlKey> = pins.iter().map(|pin| PurlKey::new(&pin.purl)).collect();
        let own = self.listed.iter().filter(|listed| listed.hub == hub);
        let entries = own.flat_map(|listed| &listed.entries);
        entries
            .filter(|e| !pinned.contains(&PurlKey::new(&e.purl)))
            .collect()
    }

    /// Whether `rel` is a lock of a governed ecosystem that no hub reads.
    pub fn is_non_consumer(&self, rel: &str) -> bool {
        self.non_consumers.iter().any(|path| path == rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::govern::tests::{read, JS_MODULE};
    use crate::bazel::lanes;
    use crate::bazel::model::{AttestBasis, LaneId, LaneOps, LaneSpec, Ruleset, TextRead};
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
        assert_eq!(found.resolves(GSON), Resolved::By(vec![HubId(0), HubId(1)]));
        assert_eq!(found.resolves(GUAVA), Resolved::By(vec![HubId(1)]));
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
        assert_eq!(found.unpatched(HubId(0), &[]).len(), 3);
        let left = found.unpatched(HubId(0), std::slice::from_ref(&pin));
        assert_eq!(left.len(), 2);
        assert!(left.iter().all(|e| e.purl != GSON));
        assert!(found.unpatched(HubId(3), &[]).is_empty());
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
        let (token, ..) = case(&[("MODULE.bazel", &foreign)]);
        assert!(token.is_some());

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
        assert_eq!(
            found.resolves("pkg:npm/left-pad@1.3.0"),
            Resolved::By(vec![HubId(0)])
        );
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
        assert_eq!(
            found.resolves("pkg:nuget/sp.victim@1.0.0"),
            Resolved::By(vec![HubId(0)])
        );

        let index = revision_4();
        let wired = wired(&index);
        let rows = (index.rc_flags.iter().map(|row| &row.uuid))
            .chain(index.files.iter().map(|row| &row.uuid));
        assert!(rows.clone().count() >= 2 && rows.clone().all(|uuid| wired.contains(uuid)));
        let kept = inventory(&ws, &NONE, &Files::of(&files), &index);
        let uuid = index.files[0].uuid.as_str();
        assert_eq!(kept.in_use("pkg:nuget/Serilog@3.0.0", uuid), Some(true));
        assert_eq!(
            kept.in_use("pkg:nuget/Serilog@3.0.0", "another"),
            Some(false)
        );
    }
}
