//! `vex` under a Bazel workspace (design 7 and HZ-15; revision 4, sections
//! 3 and 4): no statement without a proof that the Bazel build consumes
//! the patch.
//!
//! A Bazel ruleset fetches a package from the lock its declaration names.
//! A patched installed tree, a pin in a file no hub reads and a vendored
//! artifact nothing proves Bazel takes each say "patched" about a build
//! that is not. Every such statement is withheld here or in the extractor
//! this file feeds, at plan level, before a file is hashed, so neither
//! `--no-verify` nor the confirmation of a native rewrite in the same run
//! brings one back.
//!
//! Two halves, one judge (`socket_patch_core::vex::discover::Judge`):
//!
//! - [`discover`] runs lockfile discovery with what this run knows beyond
//!   the committed files ([`Knowledge`]). Its Bazel extractor judges every
//!   reference a lockfile wires and marks the ones the build does not
//!   provably consume; `vex_sources::plan` omits a marked patch like any
//!   other unattested one ([`note`]).
//! - [`gate`] judges what no lockfile wires, where the extractor has
//!   nothing to mark: agent mode's manifest record (the agent basis) and a
//!   ledger record. A record whose patch discovery holds a pin for is
//!   judged as that pin. It also carries a verdict into the verification
//!   that follows ([`Verdicts`]): Bazel reads no host store, so a hosted
//!   pin it consumes is never held to an installed tree, and a vendored
//!   pin is held to its committed artifact.
//!
//! Nothing here looks at a basis, a lane or a withhold kind: the judge
//! answers `Ok` or a withhold, the code of a withhold is
//! `Code::withheld(kind)`, and what the verification does differently is
//! asked of the three accessors of the verdict. Outside a Bazel workspace
//! the gate costs the stat-only root probe and changes nothing.

use std::collections::BTreeSet;
use std::path::Path;

use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{FileView, LaneTable, Probe, VexWithhold};
use socket_patch_core::patch::redirect::Integrity;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::state::VendorEntry;
use socket_patch_core::vex::discover::{
    discover_patched_refs_under, no_artifact_record, withheld_detail, BazelOptions,
    DiscoverOptions, Discovery, Judge, PatchedRef, Read, UnattestedKind, WiringMode,
};
use socket_patch_core::vex::FailedPatch;

use super::{IndexState, Loader, RunCx};
use crate::args::GlobalArgs;
use crate::commands::vex_sources::{HostedWiring, Plan, PlanNote};

/// What a run knows of a Bazel build that no committed file holds.
#[derive(Clone)]
pub struct Knowledge {
    /// `lanes::PRODUCTION` in every run of the binary.
    pub lanes: &'static LaneTable,
    /// The grants an in-run statement holds, by patch UUID: the digests of
    /// each patch artifact a Bazel lane pinned in this run. Standalone
    /// `vex` holds none, and a hosted pin then attests only on a digest
    /// the owned index records.
    pub grants: Vec<(String, Integrity)>,
}

impl Default for Knowledge {
    fn default() -> Self {
        Self {
            lanes: &lanes::PRODUCTION,
            grants: Vec::new(),
        }
    }
}

impl Knowledge {
    fn options(&self) -> BazelOptions<'_> {
        BazelOptions {
            lanes: self.lanes,
            grants: &self.grants,
        }
    }
}

/// Lockfile discovery of `root` for a statement: `commands::discover_wiring`
/// with what the run knows of the Bazel build handed to the extractor.
pub async fn discover(common: &GlobalArgs, root: &Path, known: &Knowledge) -> Discovery {
    let opts = DiscoverOptions {
        patch_server_origins: crate::commands::hosted_unwind::patch_server_origins(common),
    };
    discover_patched_refs_under(root, &opts, known.options()).await
}

/// What every note of a withheld statement ends with. The sentence before
/// it is the Bazel layer's own and names the case and its remedy.
const WITHHELD: &str = "not attested while that holds: Bazel builds this package from the lock \
                        its ruleset reads, and the patch counts there only through a pin that \
                        the build provably consumes";

/// The omission tag and the closing words of the note for a mark of the
/// Bazel extractor: the code of the withhold kind the mark stands for.
pub fn note(kind: UnattestedKind) -> (&'static str, &'static str) {
    let withheld = kind.withheld().map(Code::withheld);
    // A mark of another extractor never reaches this function; if one
    // did, "undetermined" claims the least.
    let code = withheld.unwrap_or(Code::VexConsumerUndetermined);
    (code.as_str(), WITHHELD)
}

/// What the verification of a plan takes from the Bazel layer.
#[derive(Debug, Default)]
pub struct Verdicts {
    /// The view purls the Bazel build consumes through a hosted pin.
    hosted: BTreeSet<String>,
}

impl Verdicts {
    /// Whether the consumer proof replaces the installed-tree check of
    /// `purl`: Bazel fetches the pinned bytes itself and reads no host
    /// store (`node_modules`, the NuGet global packages folder, `~/.m2`),
    /// so a copy there, patched or not, is no evidence either way.
    pub fn replaces_installed_tree(&self, purl: &str) -> bool {
        self.hosted.contains(purl)
    }
}

/// Omits `key` from the plan for the reason the judge gave.
fn withhold(plan: &mut Plan, key: &str, uuid: &str, why: &VexWithhold) {
    let code = Code::withheld(why.kind).as_str();
    plan.view.patches.remove(key);
    plan.vendor_entries.remove(key);
    plan.hosted.remove(key);
    plan.lockfile_basis.remove(key);
    plan.redirected.retain(|purl| purl != key);
    plan.gated.push(FailedPatch {
        purl: key.to_string(),
        reason: code.to_string(),
    });
    let detail = withheld_detail(why);
    plan.notes.push(PlanNote {
        code,
        detail: format!("{key}: patch {uuid} is recorded, but {detail}; {WITHHELD}"),
    });
}

/// The consumer gate over a finished plan, before anything is verified
/// (module docs). Every entry of the plan is asked: one a lockfile wires
/// by its references, a vendored one by the files its ledger entry
/// records, and every other as a record with no reference.
pub(crate) async fn gate(common: &GlobalArgs, known: &Knowledge, plan: &mut Plan) -> Verdicts {
    let mut verdicts = Verdicts::default();
    let run = RunCx {
        read_only: true,
        offline: common.offline,
        ..RunCx::default()
    };
    let (loader, root) = (Loader::new(run), common.project_root());
    // Nothing to judge, or no Bazel root: the stat-only probe at most, and
    // no file of a workspace is read.
    if plan.view.patches.is_empty() || loader.probe(&root) == Probe::NotBazel {
        return verdicts;
    }
    // Vendored pins of records that name no artifact yet: the ledger is
    // read for them once the judge, which is not `Send`, is gone.
    let mut vendored: Vec<(String, String)> = Vec::new();
    {
        let loaded = loader.load(&root);
        let probe = loaded.probe();
        let nearest = loaded.roots().next().map(|root| {
            let index = match root.index() {
                IndexState::Ours(index) => Ok(index),
                IndexState::Faulty(fault) => Err(fault),
            };
            (root.files() as &dyn FileView, index)
        });
        let read = Read {
            probe: &probe,
            models: loaded.models(),
            nearest,
        };
        let judge = Judge::new(&read, known.options());
        let mut keys: Vec<String> = plan.view.patches.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let uuid = plan.view.patches[&key].uuid.clone();
            let file = |path: &Path| path.to_string_lossy().into_owned();
            let wiring: Vec<(WiringMode, String)> = match plan.hosted.get(&key) {
                Some(hosted) => {
                    let refs = hosted.refs.iter();
                    refs.map(|r| (r.mode, file(&r.source_file))).collect()
                }
                None => {
                    let entry = plan.vendor_entries.get(&key);
                    let files = entry.into_iter().flat_map(|entry| &entry.wiring);
                    files
                        .map(|wired| (WiringMode::Vendored, wired.file.clone()))
                        .collect()
                }
            };
            let wiring: Vec<(WiringMode, &str)> = wiring
                .iter()
                .map(|(mode, file)| (*mode, &file[..]))
                .collect();
            let consumed = match judge.wired(&key, &uuid, &wiring) {
                Ok(consumed) => consumed,
                Err(why) => {
                    withhold(plan, &key, &uuid, &why);
                    continue;
                }
            };
            // As today, or an agent lane's pin: the installed tree is
            // what Bazel builds from, and it is verified as it always is.
            if consumed.verifies_installed_tree() {
                continue;
            }
            if consumed.hashes_committed_artifact() {
                if !plan.vendor_entries.contains_key(&key) {
                    vendored.push((key, uuid));
                }
                continue;
            }
            verdicts.hosted.insert(key.clone());
            let hosted = plan.hosted.entry(key.clone());
            let hosted = hosted.or_insert_with(|| HostedWiring {
                uuid,
                refs: Vec::new(),
            });
            // The proof held the lock to the digest of the patch. A
            // reference of the project that carries none of its own does
            // not attest from the lock alone all the same.
            let pinned = |r: &PatchedRef| r.locked_integrity.is_some();
            let pinned = !consumed.integrity_required() || hosted.refs.iter().all(pinned);
            if !plan.redirected.contains(&key) {
                plan.redirected.push(key.clone());
                plan.redirected.sort();
            }
            match pinned {
                true => plan.lockfile_basis.insert(key),
                false => plan.lockfile_basis.remove(&key),
            };
        }
    }
    if vendored.is_empty() {
        return verdicts;
    }
    let ledger = socket_patch_core::vendor::load_state(&root).await.ok();
    for (key, uuid) in vendored {
        let mut entries = ledger.iter().flat_map(|ledger| ledger.entries.values());
        let own =
            |entry: &&VendorEntry| entry.uuid == uuid && PurlKey::same(&entry.base_purl, &key);
        let Some(entry) = entries.find(own).cloned() else {
            withhold(plan, &key, &uuid, &no_artifact_record());
            continue;
        };
        // The artifact is the evidence now, and the only one.
        plan.hosted.remove(&key);
        plan.lockfile_basis.remove(&key);
        plan.redirected.retain(|purl| *purl != key);
        plan.vendor_entries.insert(key, entry);
    }
    verdicts
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::path::PathBuf;

    use serde_json::json;
    use socket_patch_core::bazel::model::{
        AttestBasis, BazelRef, CellClaim, ClaimSystem, LaneCx, LaneId, LaneOps, LaneSpec, LockRole,
        Mode, Ruleset, TextRead, WithholdKind,
    };
    use socket_patch_core::bazel::owned_index::{Index, IndexEdit, IndexRow, INDEX_PATH};
    use socket_patch_core::crawlers::Ecosystem;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as git_sha256;
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use socket_patch_core::utils::purl::purl_parts;
    use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};
    use socket_patch_core::vendor::state::{
        VendorArtifact, VendorState, WiringAction, WiringRecord,
    };

    use super::*;
    use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};

    const NINE: (&str, &str) = (".bazelversion", "9.3.2\n");
    const JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";
    const GO: &str = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
        go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
        go_deps.from_file(go_mod = \"//:go.mod\")\n\
        use_repo(go_deps, \"com_github_foo_bar\")\n";
    const CSHARP: &str = "bazel_dep(name = \"rules_csharp\", version = \"0.5.0\")\n\
        nuget = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"nuget\")\n\
        nuget.from_lock(packages_lock_json = \"//:packages.lock.json\")\n\
        use_repo(nuget, \"nuget\")\n";
    const BAR: &str = "pkg:golang/github.com/foo/bar@v1.0.0";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    // ── A toy lane ───────────────────────────────────────────────────

    /// The words of each package line of the hub's locks, with its file.
    /// A toy pin is one line `<purl> <sha256> [<lane> <uuid>] [broken]`,
    /// carried where the real lock allows a line of its own: a comment of
    /// a `go.mod`, a string of an array in a JSON lock.
    fn lines(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<(String, Vec<String>)>> {
        let hub = cx.ws.hubs.get(cx.hub.0)?;
        let locks = hub.locks.iter();
        let mut out = Vec::new();
        for lock in locks.filter(|lock| lock.role == LockRole::PackageLock) {
            let path = lock.path.clone()?;
            for line in read(&path)?.lines() {
                let line = line.trim().trim_start_matches("// ");
                let line = line.trim_matches(['"', ',']);
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
    static TABLE: LaneTable = LaneTable(&[(Ruleset::Gazelle, &TOY), (Ruleset::RulesCsharp, &TOY)]);

    // ── Fixtures ─────────────────────────────────────────────────────

    /// A checkout that is its own Bazel root (or no root, with no
    /// boundary file among `files`).
    fn workspace(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("ws");
        put(&root, ".git/HEAD", "ref: refs/heads/main\n");
        for (rel, text) in files {
            put(&root, rel, text);
        }
        (tmp, root)
    }

    fn put(root: &Path, rel: &str, bytes: impl AsRef<[u8]>) {
        let file = rel
            .split('/')
            .fold(root.to_path_buf(), |at, part| at.join(part));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }

    fn common(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            offline: true,
            no_telemetry: true,
            ..GlobalArgs::default()
        }
    }

    fn patch(uuid: &str, file: &str, before: &[u8], after: &[u8]) -> PatchRecord {
        let hashes = json!({"beforeHash": git_sha256(before), "afterHash": git_sha256(after)});
        let vuln = json!({"cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d"});
        serde_json::from_value(json!({
            "uuid": uuid, "exportedAt": "2026-01-01T00:00:00Z", "files": {file: hashes},
            "vulnerabilities": {"GHSA-test-aaaa-bbbb": vuln},
            "description": "d", "license": "MIT", "tier": "free",
        }))
        .unwrap()
    }

    /// A plan that holds one record of agent mode: no file wires it.
    fn recorded(purl: &str) -> Plan {
        let mut view = PatchManifest::new();
        let record = patch(UUID, "package/x", b"before", b"after");
        view.patches.insert(purl.to_string(), record);
        Plan {
            view,
            vendor_entries: HashMap::new(),
            redirected: Vec::new(),
            lockfile_basis: HashSet::new(),
            hosted: BTreeMap::new(),
            gated: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn known(grant: Option<&str>) -> Knowledge {
        let grant = grant.map(|sha256| Integrity {
            sha256: Some(sha256.to_string()),
            ..Integrity::default()
        });
        Knowledge {
            lanes: &TABLE,
            grants: grant
                .into_iter()
                .map(|grant| (UUID.to_string(), grant))
                .collect(),
        }
    }

    fn entry(purl: &str, wired_in: &[&str]) -> VendorEntry {
        let eco = Ecosystem::from_purl(purl).unwrap().cli_name().to_string();
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: format!(".socket/vendor/{eco}/{UUID}/artifact"),
            sha256: "c".repeat(64),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        let wiring = wired_in.iter().map(|file| WiringRecord {
            file: file.to_string(),
            kind: "toy".to_string(),
            action: WiringAction::Rewritten,
            key: None,
            original: None,
            new: None,
        });
        VendorEntry::new(
            eco,
            purl.to_string(),
            UUID.to_string(),
            artifact,
            wiring.collect(),
        )
    }

    /// What the gate left of a plan: the omission code of each purl it
    /// withheld, and the purls it kept.
    fn outcome(plan: &Plan) -> (Vec<(&str, &str)>, Vec<&str>) {
        let gated = plan.gated.iter().map(|f| (&f.purl[..], &f.reason[..]));
        let mut kept: Vec<&str> = plan.view.patches.keys().map(|key| &key[..]).collect();
        kept.sort();
        (gated.collect(), kept)
    }

    // ── The gate ─────────────────────────────────────────────────────

    /// A project with no Bazel workspace around it is planned exactly as
    /// before, whatever the plan holds.
    #[tokio::test]
    async fn outside_a_bazel_workspace_the_gate_changes_nothing() {
        let (_tmp, root) = workspace(&[("go.mod", "module example.com/m\n")]);
        let mut plan = recorded(BAR);
        plan.vendor_entries
            .insert(LEFT_PAD.to_string(), entry(LEFT_PAD, &["pnpm-lock.yaml"]));
        let record = patch(UUID, "package/x", b"before", b"after");
        plan.view.patches.insert(LEFT_PAD.to_string(), record);
        let verdicts = gate(&common(&root), &Knowledge::default(), &mut plan).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR, LEFT_PAD]));
        assert!(plan.notes.is_empty() && plan.hosted.is_empty());
        assert!(plan.vendor_entries.contains_key(LEFT_PAD));
        assert!(!verdicts.replaces_installed_tree(BAR));
    }

    /// The agent basis, and the rule for a record a pin exists for: a
    /// manifest record in a project a hub governs counts only through a
    /// pin, and is judged as the pin discovery holds for its patch. Each
    /// case ends in one statement or one withhold, of the pin where there
    /// is one, never of the installed tree.
    #[tokio::test]
    async fn a_manifest_record_is_judged_through_the_pin_of_its_patch() {
        let digest = "2".repeat(64);
        let code = |kind| Code::withheld(kind).as_str();
        let judged = |pin: String, grant: Option<&'static str>, ledger: bool| {
            let digest = digest.clone();
            async move {
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
                let (tmp, root) = workspace(&files);
                if ledger {
                    let mut state = VendorState::new();
                    state.entries.insert(BAR.to_string(), entry(BAR, &[]));
                    socket_patch_core::vendor::save_state(&root, &state)
                        .await
                        .unwrap();
                }
                let mut plan = recorded(BAR);
                let grant = grant.map(|_| &digest[..]);
                let verdicts = gate(&common(&root), &known(grant), &mut plan).await;
                drop(tmp);
                (plan, verdicts)
            }
        };
        // No pin: a patched tree says nothing of a build that fetches the
        // module from its lock.
        let (plan, _) = judged(String::new(), None, false).await;
        let unconsumed = code(WithholdKind::NotConsumed);
        assert_eq!(outcome(&plan), (vec![(BAR, unconsumed)], vec![]));
        assert!(plan.notes[0]
            .detail
            .starts_with(&format!("{BAR}: patch {UUID}")));
        assert_eq!(plan.notes[0].code, unconsumed);

        // An agent lane's pin: Bazel builds from the patched tree, so the
        // plan keeps the agent basis and the tree is verified as before.
        let (plan, verdicts) = judged(format!(" A-TOY1 {UUID}"), None, false).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert!(plan.hosted.is_empty() && plan.vendor_entries.is_empty());
        assert!(!verdicts.replaces_installed_tree(BAR));

        // A vendored lane's pin: the committed artifact is the evidence,
        // hashed against its ledger record. Without a record nothing
        // holds the bytes to the patch.
        let (plan, verdicts) = judged(format!(" V-TOY1 {UUID}"), None, true).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert_eq!(plan.vendor_entries.get(BAR), Some(&entry(BAR, &[])));
        assert!(!verdicts.replaces_installed_tree(BAR));
        let (plan, _) = judged(format!(" V-TOY1 {UUID}"), None, false).await;
        let unanchored = code(WithholdKind::IntegrityUnanchored);
        assert_eq!(outcome(&plan), (vec![(BAR, unanchored)], vec![]));
        // A pin whose proof fails is withheld as that pin.
        let (plan, _) = judged(format!(" V-TOY1 {UUID} broken"), None, true).await;
        let stale = code(WithholdKind::DerivedStale);
        assert_eq!(outcome(&plan), (vec![(BAR, stale)], vec![]));

        // A hosted lane's pin in a native lock: in-run, under the grant of
        // the patch, the build consumes it and no installed tree is
        // evidence; offline nothing records the digest it was written with.
        let (plan, verdicts) = judged(format!(" H-TOY1 {UUID}"), Some("grant"), false).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert!(verdicts.replaces_installed_tree(BAR));
        assert!(plan.hosted.contains_key(BAR) && plan.lockfile_basis.contains(BAR));
        assert_eq!(plan.redirected, [BAR]);
        let (plan, _) = judged(format!(" H-TOY1 {UUID}"), None, false).await;
        let undetermined = code(WithholdKind::ConsumerUndetermined);
        assert_eq!(outcome(&plan), (vec![(BAR, undetermined)], vec![]));
    }

    /// The vendored basis with no lane to prove it: a ledger entry whose
    /// wiring is in the lock a hub reads is not a proof that Bazel takes
    /// the artifact. An entry of an ecosystem no ruleset of the workspace
    /// builds is left as it is.
    #[tokio::test]
    async fn a_vendored_entry_under_a_hub_no_lane_serves_is_withheld() {
        let (_tmp, root) = workspace(&[("MODULE.bazel", JS), ("pnpm-lock.yaml", "")]);
        let cargo = "pkg:cargo/serde@1.0.0";
        let mut plan = recorded(LEFT_PAD);
        plan.vendor_entries
            .insert(LEFT_PAD.to_string(), entry(LEFT_PAD, &["pnpm-lock.yaml"]));
        let record = patch(UUID, "package/x", b"before", b"after");
        plan.view.patches.insert(cargo.to_string(), record);
        plan.vendor_entries
            .insert(cargo.to_string(), entry(cargo, &["Cargo.toml"]));
        gate(&common(&root), &Knowledge::default(), &mut plan).await;
        let undetermined = Code::VexConsumerUndetermined.as_str();
        assert_eq!(
            outcome(&plan),
            (vec![(LEFT_PAD, undetermined)], vec![cargo])
        );
        assert!(!plan.vendor_entries.contains_key(LEFT_PAD));
        assert!(plan.vendor_entries.contains_key(cargo));
    }

    // ── The whole pipeline ───────────────────────────────────────────

    /// A hosted NuGet reference under a `nuget.from_lock` hub (the shape
    /// of `H-NET2`), with the upstream package in the global packages
    /// folder. Bazel never reads that folder, so the toy consumer proof
    /// attests from the pinned lock and the folder is not held against
    /// it. With the production lanes nothing proves the pin, and neither
    /// `--no-verify` nor an in-run confirmation brings the statement
    /// back. With no Bazel workspace the folder is the evidence again.
    #[tokio::test]
    async fn an_h_net2_shaped_reference_attests_through_the_toy_consumer_proof() {
        const NUGET: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
        const PIN: &str = "66666666-6666-6666-6666-666666666666";
        let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core");
        let fixture = core.join("tests/fixtures/redirect/nuget/packages-lock/basic/expected");
        let read = |name: &str| std::fs::read_to_string(fixture.join(name)).unwrap();
        // The folder NuGet restores into, named by the project's config.
        let folder = "<config><add key=\"globalPackagesFolder\" value=\"gpf\" /></config>";
        let config = read("nuget.config")
            .replace("<packageSources>", &format!("{folder}\n  <packageSources>"));
        let digest = "2".repeat(64);
        let toy = format!("{{\n  \"toy\": [\n    \"{NUGET} {digest} H-TOY1 {PIN}\"\n  ],");
        let lock = read("packages.lock.json").replacen('{', &toy, 1);
        let files = [
            NINE,
            ("MODULE.bazel", CSHARP),
            ("App.csproj", "<Project/>"),
            ("nuget.config", &config[..]),
            ("packages.lock.json", &lock[..]),
        ];
        let (tmp, root) = workspace(&files);
        let (upstream, patched) = (&b"upstream"[..], &b"patched"[..]);
        let nuspec = "<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>";
        put(
            &root,
            "gpf/newtonsoft.json/13.0.3/newtonsoft.json.nuspec",
            nuspec,
        );
        put(
            &root,
            "gpf/newtonsoft.json/13.0.3/lib/net6.0/Newtonsoft.Json.dll",
            upstream,
        );
        let mut manifest = PatchManifest::new();
        let record = patch(
            PIN,
            "package/lib/net6.0/Newtonsoft.Json.dll",
            upstream,
            patched,
        );
        manifest.patches.insert(NUGET.to_string(), record);
        put(
            &root,
            ".socket/manifest.json",
            serde_json::to_string(&manifest).unwrap(),
        );
        // The fabricated index: the row that records the digest the pin
        // was written with, which is what lets an offline run speak.
        let mut index = Index::default();
        index.record_pin(IndexRow {
            uuid: PIN.to_string(),
            purl: NUGET.to_string(),
            lane: "H-TOY1".to_string(),
            file: "packages.lock.json".to_string(),
            edits: vec![IndexEdit {
                key: "contentHash".to_string(),
                original: "1".repeat(64),
                new: digest.clone(),
            }],
            check: None,
        });
        put(&root, INDEX_PATH, index.render().unwrap());

        let common = common(&root);
        // `skip`: the run is told not to verify (`--no-verify`), and that
        // a rewrite of this very run confirmed the patch.
        let run = |lanes: &'static LaneTable, skip: (bool, bool), name: &str| {
            let out = tmp.path().join(name);
            let mut params = VexEmbedArgs {
                vex: Some(out),
                vex_product: Some("pkg:generic/app@1.0.0".to_string()),
                vex_no_verify: skip.0,
                ..VexEmbedArgs::default()
            }
            .to_build_params(None);
            params.bazel.lanes = lanes;
            if skip.1 {
                params.assume_applied = vec![NUGET.to_string()];
            }
            let manifest_path = common.resolved_manifest_path();
            let common = &common;
            async move { generate_vex_from_manifest_path(common, &params, &manifest_path).await }
        };
        let attested = run(&TABLE, (false, false), "toy.json").await;
        let attested = attested.unwrap_or_else(|e| panic!("{}: {:?}", e.message, e.failed));
        assert_eq!(attested.statements, 1, "{:?}", attested.failed);
        assert!(attested.failed.is_empty(), "{:?}", attested.failed);

        // The native reference is the source mapping of `nuget.config`,
        // a file the hub does not read; no lane finds a pin in the lock.
        for skip in [(false, false), (true, false), (false, true)] {
            let name = format!("production-{}-{}.json", skip.0, skip.1);
            let Err(withheld) = run(&lanes::PRODUCTION, skip, &name).await else {
                panic!("attested with no lane to prove the pin: {skip:?}");
            };
            assert_eq!(withheld.code, "no_applicable_patches");
            let reasons: Vec<&str> = withheld.failed.iter().map(|f| &f.reason[..]).collect();
            assert_eq!(reasons, [Code::VexNotConsumed.as_str()], "{skip:?}");
        }

        // The control reads the folder the project's config names, which
        // an ambient `NUGET_PACKAGES` overrides for the whole process.
        if std::env::var_os("NUGET_PACKAGES").is_some_and(|set| !set.is_empty()) {
            return;
        }
        std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
        let Err(native) = run(&TABLE, (false, false), "native.json").await else {
            panic!("attested over the upstream package in the global packages folder");
        };
        let reasons: Vec<&str> = native.failed.iter().map(|f| &f.reason[..]).collect();
        assert_eq!(reasons, ["not_applied"]);
    }
}
