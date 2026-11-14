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
//! A vendor ledger entry whose record says the owned index of a Bazel root
//! wires its artifact has no lockfile reference to be live by, so the plan
//! leaves it to the gate: it stays the evidence of a statement only on a
//! vendored pin of its patch that the build provably consumes. With a pin
//! whose proof fails the withhold is the pin's, and in every other case
//! (no pin anybody can tell, no Bazel root, a root the record does not
//! place the project under, a run on the global installs) the entry is
//! omitted as the artifact nothing wires that it then is. It is never
//! attested from the artifact alone.
//!
//! A run on the global installs (`--global`, `--global-prefix`) attests
//! another tree than the project's, which the workspace at `--cwd` does
//! not build: it asks nothing here.
//!
//! Nothing here looks at a basis, a lane or a withhold kind: the judge
//! answers `Ok` or a withhold, the code of a withhold is
//! `Code::withheld(kind)`, and what the verification does differently is
//! asked of the three accessors of the verdict. Outside a Bazel workspace
//! the gate costs the stat-only root probe and changes nothing.

use std::collections::{BTreeMap, BTreeSet};
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
use crate::commands::vex_sources::{
    HostedWiring, Plan, PlanNote, NOTE_CLAIM_UNWIRED, VENDOR_UNWIRED,
};

/// What a run knows of a Bazel build that no committed file holds.
#[derive(Clone)]
pub struct Knowledge {
    /// `lanes::PRODUCTION` in every run of the binary.
    pub lanes: &'static LaneTable,
    /// The grants an in-run statement holds, by patch UUID: the digests of
    /// each patch artifact a Bazel lane pinned in this run. Standalone
    /// `vex` holds none, and a hosted pin then attests only on a digest
    /// the owned index records.
    ///
    /// The in-run entry (`scan --mode hosted --vex`) fills it for each
    /// uuid a Bazel lane confirmed, beside its `assume_applied` filter. No
    /// lane confirms in this build, so it is empty in every run, and a
    /// pin of a native lock is withheld in the run that wrote it.
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

/// Takes `key` out of the plan, with the tag of its omission.
fn omit(plan: &mut Plan, key: &str, reason: &str) {
    plan.view.patches.remove(key);
    plan.vendor_entries.remove(key);
    plan.hosted.remove(key);
    plan.lockfile_basis.remove(key);
    plan.redirected.retain(|purl| purl != key);
    plan.gated.push(FailedPatch {
        purl: key.to_string(),
        reason: reason.to_string(),
    });
}

/// Omits `key` from the plan for the reason the judge gave.
fn withhold(plan: &mut Plan, key: &str, uuid: &str, why: &VexWithhold) {
    let code = Code::withheld(why.kind).as_str();
    omit(plan, key, code);
    let detail = withheld_detail(why);
    plan.notes.push(PlanNote {
        code,
        detail: format!("{key}: patch {uuid} is recorded, but {detail}; {WITHHELD}"),
    });
}

/// Why the Bazel layer was asked nothing about a run.
const GLOBAL_RUN: &str = "this run works on the global installs, and asks no Bazel workspace \
                          about them";
const NO_ROOT: &str = "no Bazel workspace is at or above the project now";
/// Why an entry that was asked about is not proven.
const NOT_PLACED: &str = "that record places the project elsewhere under its Bazel root than \
                          it lies now";
const NO_PIN: &str = "no file the Bazel build reads holds a pin of the patch, or no enabled \
                      lane can tell";
const OTHER_PIN: &str = "the pin of the patch that the Bazel build consumes is not one of a \
                         vendored artifact";

/// What became of the vendored entries only the Bazel layer can vouch
/// for: the ones whose ledger record says the owned index of a Bazel root
/// wires the artifact (module docs).
#[derive(Default)]
struct IndexWired {
    /// The view purls whose vendored pin the build provably consumes.
    consumed: BTreeSet<String>,
    /// Why an entry that was asked about is not among them.
    unproven: BTreeMap<String, &'static str>,
}

/// The consumer gate over a finished plan, before anything is verified
/// (module docs). Every entry of the plan is asked: one a lockfile wires
/// by its references, a vendored one by the files its ledger entry
/// records, one a Bazel root's owned index wires by the pins of its
/// patch, and every other as a record with no reference.
pub(crate) async fn gate(common: &GlobalArgs, known: &Knowledge, plan: &mut Plan) -> Verdicts {
    let mut verdicts = Verdicts::default();
    let mut wired = IndexWired::default();
    let unasked = match common.is_global() {
        true => Some(GLOBAL_RUN),
        false => ask(common, known, plan, &mut verdicts, &mut wired).await,
    };
    // An entry only the Bazel layer can vouch for, which it did not: the
    // artifact is wired by nothing that was proven, and is never the
    // evidence of a statement by itself.
    let own = |(key, entry): (&String, &VendorEntry)| {
        let unproven = entry.bazel_index().is_some() && !wired.consumed.contains(key);
        unproven.then(|| (key.clone(), entry.uuid.clone()))
    };
    let mut unproven: Vec<(String, String)> = plan.vendor_entries.iter().filter_map(own).collect();
    unproven.sort();
    for (key, uuid) in unproven {
        let why = wired.unproven.get(&key).copied().or(unasked);
        let why = why.unwrap_or(NO_PIN);
        omit(plan, &key, VENDOR_UNWIRED);
        plan.notes.push(PlanNote {
            code: NOTE_CLAIM_UNWIRED,
            detail: format!(
                "{key}: the vendor ledger records patch {uuid} with an artifact that the owned \
                 index of a Bazel root wires, but {why}; not attested"
            ),
        });
    }
    verdicts
}

/// Asks the judge about every entry of `plan`. `Some` is why nothing was
/// asked: the stat-only probe at most ran, and no file of a workspace was
/// read.
async fn ask(
    common: &GlobalArgs,
    known: &Knowledge,
    plan: &mut Plan,
    verdicts: &mut Verdicts,
    index_wired: &mut IndexWired,
) -> Option<&'static str> {
    let run = RunCx {
        read_only: true,
        offline: common.offline,
        ..RunCx::default()
    };
    let (loader, root) = (Loader::new(run), common.project_root());
    // Nothing to judge, or no Bazel root.
    if plan.view.patches.is_empty() || loader.probe(&root) == Probe::NotBazel {
        return Some(NO_ROOT);
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
        // Where the project lies under the nearest root, which a ledger
        // record of an index-wired artifact is held to.
        let base = loaded.roots().next();
        let base = base.map(|root| root.root().project_rel.clone());
        let mut keys: Vec<String> = plan.view.patches.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let uuid = plan.view.patches[&key].uuid.clone();
            // An artifact the owned index wires: the pins of the patch
            // decide alone, and only a vendored pin the build consumes
            // keeps the artifact as the evidence.
            let said = plan.vendor_entries.get(&key);
            let said = said.and_then(|entry| entry.bazel_index());
            // A record for another place under the root is followed
            // nowhere. With no root read there is no place to hold it to,
            // and the judge answers from the probe alone.
            let placed = |at: &str| base.as_deref().is_none_or(|base| base == at);
            if let Some(placed) = said.map(|said| placed(said.project_rel)) {
                let verdict = match placed {
                    true => judge.pinned(&key, &uuid),
                    false => None,
                };
                let unproven = match verdict {
                    Some(Ok(consumed)) if consumed.hashes_committed_artifact() => {
                        index_wired.consumed.insert(key);
                        continue;
                    }
                    Some(Err(why)) => {
                        withhold(plan, &key, &uuid, &why);
                        continue;
                    }
                    Some(Ok(_)) => OTHER_PIN,
                    None if placed => NO_PIN,
                    None => NOT_PLACED,
                };
                index_wired.unproven.insert(key, unproven);
                continue;
            }
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
        return None;
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
        // The pin was just proven: an entry found for it needs no second
        // word from the index its own record may name.
        index_wired.consumed.insert(key.clone());
        plan.vendor_entries.insert(key, entry);
    }
    None
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
    use crate::commands::vex::{
        generate_vex_from_manifest_path, VexEmbedArgs, VexGenError, VexWriteSummary,
    };

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

    /// The ledger entry of an artifact that the owned index of a Bazel
    /// root wires, as the vendored seam records it: the one wiring record
    /// places the project at `project_rel` under that root.
    fn index_wired(purl: &str, project_rel: &str, routed: bool) -> VendorEntry {
        let mut entry = entry(purl, &[]);
        entry.wiring = vec![WiringRecord::bazel_index(project_rel, UUID, routed)];
        entry.record = Some(patch(UUID, "package/x", b"before", b"after"));
        entry
    }

    /// The `go.mod` of the gazelle hub fixture with one toy line for
    /// [`BAR`]: its digest, then `pin` (` <lane> <uuid>[ broken]`, or
    /// nothing for a release no lane pinned). `replace` is a directive of
    /// the module file itself.
    fn go_mod(pin: &str, replace: &str) -> String {
        let digest = "2".repeat(64);
        format!(
            "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n{replace}\
             // {BAR} {digest}{pin}\n"
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
        let judged = |pin: String, grant: Option<&'static str>, ledger: Option<VendorEntry>| {
            let digest = digest.clone();
            async move {
                let go_mod = go_mod(&pin, "");
                let files = [
                    NINE,
                    ("MODULE.bazel", GO),
                    ("go.mod", &go_mod[..]),
                    ("go.sum", ""),
                ];
                let (tmp, root) = workspace(&files);
                if let Some(entry) = ledger {
                    let mut state = VendorState::new();
                    state.entries.insert(BAR.to_string(), entry);
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
        let (plan, _) = judged(String::new(), None, None).await;
        let unconsumed = code(WithholdKind::NotConsumed);
        assert_eq!(outcome(&plan), (vec![(BAR, unconsumed)], vec![]));
        assert!(plan.notes[0]
            .detail
            .starts_with(&format!("{BAR}: patch {UUID}")));
        assert_eq!(plan.notes[0].code, unconsumed);

        // An agent lane's pin: Bazel builds from the patched tree, so the
        // plan keeps the agent basis and the tree is verified as before.
        let (plan, verdicts) = judged(format!(" A-TOY1 {UUID}"), None, None).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert!(plan.hosted.is_empty() && plan.vendor_entries.is_empty());
        assert!(!verdicts.replaces_installed_tree(BAR));

        // A vendored lane's pin: the committed artifact is the evidence,
        // hashed against its ledger record. Without a record nothing
        // holds the bytes to the patch.
        let (plan, verdicts) = judged(format!(" V-TOY1 {UUID}"), None, Some(entry(BAR, &[]))).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert_eq!(plan.vendor_entries.get(BAR), Some(&entry(BAR, &[])));
        assert!(!verdicts.replaces_installed_tree(BAR));
        let (plan, _) = judged(format!(" V-TOY1 {UUID}"), None, None).await;
        let unanchored = code(WithholdKind::IntegrityUnanchored);
        assert_eq!(outcome(&plan), (vec![(BAR, unanchored)], vec![]));
        // The record the ledger holds for the pin may be one of a route
        // (an artifact the owned index wires), which the plan did not
        // file under the manifest's key: the pin that was just proven is
        // its proof, and it is not asked for a second one.
        for routed in [false, true] {
            let wired = index_wired(BAR, "", routed);
            let (plan, _) = judged(format!(" V-TOY1 {UUID}"), None, Some(wired.clone())).await;
            assert_eq!(outcome(&plan), (vec![], vec![BAR]), "{routed}");
            assert_eq!(plan.vendor_entries.get(BAR), Some(&wired));
            assert!(plan.notes.is_empty(), "{:?}", plan.notes);
        }
        // A pin whose proof fails is withheld as that pin.
        let (plan, _) = judged(
            format!(" V-TOY1 {UUID} broken"),
            None,
            Some(entry(BAR, &[])),
        )
        .await;
        let stale = code(WithholdKind::DerivedStale);
        assert_eq!(outcome(&plan), (vec![(BAR, stale)], vec![]));

        // A hosted lane's pin in a native lock: in-run, under the grant of
        // the patch, the build consumes it and no installed tree is
        // evidence; offline nothing records the digest it was written with.
        let (plan, verdicts) = judged(format!(" H-TOY1 {UUID}"), Some("grant"), None).await;
        assert_eq!(outcome(&plan), (vec![], vec![BAR]));
        assert!(verdicts.replaces_installed_tree(BAR));
        assert!(plan.hosted.contains_key(BAR) && plan.lockfile_basis.contains(BAR));
        assert_eq!(plan.redirected, [BAR]);
        let (plan, _) = judged(format!(" H-TOY1 {UUID}"), None, None).await;
        let undetermined = code(WithholdKind::ConsumerUndetermined);
        assert_eq!(outcome(&plan), (vec![(BAR, undetermined)], vec![]));
    }

    /// A run on the global installs attests another tree than the
    /// project's, which the workspace at `--cwd` does not build: the gate
    /// asks nothing, and a record that the same workspace withholds from a
    /// project run is left to the verification of the global tree.
    #[tokio::test]
    async fn a_run_on_the_global_installs_asks_nothing() {
        let go_mod = go_mod("", "");
        let files = [
            NINE,
            ("MODULE.bazel", GO),
            ("go.mod", &go_mod[..]),
            ("go.sum", ""),
        ];
        let (_tmp, root) = workspace(&files);
        let project = common(&root);
        let mut plan = recorded(BAR);
        gate(&project, &known(None), &mut plan).await;
        let unconsumed = Code::VexNotConsumed.as_str();
        assert_eq!(outcome(&plan), (vec![(BAR, unconsumed)], vec![]));

        let prefix = GlobalArgs {
            global_prefix: Some(root.join("site-packages")),
            ..common(&root)
        };
        let flag = GlobalArgs {
            global: true,
            ..common(&root)
        };
        for global in [prefix, flag] {
            for lanes in [&TABLE, &lanes::PRODUCTION] {
                let known = Knowledge {
                    lanes,
                    grants: Vec::new(),
                };
                let mut plan = recorded(BAR);
                let verdicts = gate(&global, &known, &mut plan).await;
                assert_eq!(outcome(&plan), (vec![], vec![BAR]));
                assert!(plan.notes.is_empty(), "{:?}", plan.notes);
                assert!(plan.hosted.is_empty() && plan.vendor_entries.is_empty());
                assert!(!verdicts.replaces_installed_tree(BAR));
            }
        }
    }

    /// A ledger entry whose record says the owned index of a Bazel root
    /// wires its artifact, routed or not: it stays the evidence only on a
    /// vendored pin of its patch that the build consumes. A pin whose
    /// proof fails withholds as that pin, and with no proof at all the
    /// entry is the artifact nothing wires. It is never attested from the
    /// artifact alone, whatever stops the question from being asked.
    #[tokio::test]
    async fn an_index_wired_entry_is_live_only_on_a_vendored_pin_the_build_consumes() {
        #[derive(Clone, Copy)]
        struct Case {
            /// The lane whose pin the lock holds, `""` for none.
            lane: &'static str,
            /// The toy proof of that pin fails.
            broken: bool,
            /// Where the record places the project under its root.
            at: &'static str,
            bazel: bool,
            global: bool,
        }
        let case = Case {
            lane: "",
            broken: false,
            at: "",
            bazel: true,
            global: false,
        };
        let judged = |case: Case, routed: bool| async move {
            let pin = match (case.lane, case.broken) {
                ("", _) => String::new(),
                (lane, false) => format!(" {lane} {UUID}"),
                (lane, true) => format!(" {lane} {UUID} broken"),
            };
            let go_mod = go_mod(&pin, "");
            let mut files = vec![NINE, ("go.mod", &go_mod[..]), ("go.sum", "")];
            if case.bazel {
                files.push(("MODULE.bazel", GO));
            }
            let (tmp, root) = workspace(&files);
            let mut common = common(&root);
            if case.global {
                common.global_prefix = Some(root.join("site-packages"));
            }
            let mut plan = recorded(BAR);
            plan.vendor_entries
                .insert(BAR.to_string(), index_wired(BAR, case.at, routed));
            let verdicts = gate(&common, &known(None), &mut plan).await;
            drop(tmp);
            (plan, verdicts)
        };
        for routed in [false, true] {
            // The vendored pin the build consumes: the artifact is the
            // evidence, under the entry the ledger holds.
            let vendored = Case {
                lane: "V-TOY1",
                ..case
            };
            let (plan, verdicts) = judged(vendored, routed).await;
            assert_eq!(outcome(&plan), (vec![], vec![BAR]), "{routed}");
            assert_eq!(
                plan.vendor_entries.get(BAR),
                Some(&index_wired(BAR, "", routed))
            );
            assert!(plan.notes.is_empty() && plan.hosted.is_empty());
            assert!(!verdicts.replaces_installed_tree(BAR));

            // Every way the proof is missing: the native omission of an
            // artifact nothing wires, with a note that says which it was.
            let unwired = [
                (case, "no file the Bazel build reads holds a pin"),
                (
                    Case {
                        lane: "A-TOY1",
                        ..case
                    },
                    "not one of a vendored artifact",
                ),
                (
                    Case {
                        at: "svc/api",
                        ..vendored
                    },
                    "places the project elsewhere",
                ),
                (
                    Case {
                        bazel: false,
                        ..vendored
                    },
                    "no Bazel workspace is at or above the project",
                ),
                (
                    Case {
                        global: true,
                        ..vendored
                    },
                    "works on the global installs",
                ),
            ];
            for (at, (case, said)) in unwired.into_iter().enumerate() {
                let (plan, _) = judged(case, routed).await;
                let what = format!("case {at}, routed {routed}");
                assert_eq!(
                    outcome(&plan),
                    (vec![(BAR, VENDOR_UNWIRED)], vec![]),
                    "{what}"
                );
                assert!(plan.vendor_entries.is_empty() && plan.hosted.is_empty());
                let [note] = plan.notes.as_slice() else {
                    panic!("{what}: {:?}", plan.notes);
                };
                assert_eq!(note.code, NOTE_CLAIM_UNWIRED, "{what}");
                assert!(note.detail.starts_with(&format!("{BAR}: ")), "{what}");
                assert!(note.detail.contains(said), "{what}: {}", note.detail);
            }

            // A pin whose proof fails is one withhold, of the pin.
            let broken = Case {
                broken: true,
                ..vendored
            };
            let (plan, _) = judged(broken, routed).await;
            let stale = Code::withheld(WithholdKind::DerivedStale).as_str();
            assert_eq!(outcome(&plan), (vec![(BAR, stale)], vec![]), "{routed}");
            assert!(plan.vendor_entries.is_empty());
        }
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
        // What an in-run hosted scan hands the statement beside the plan.
        #[derive(Clone, Copy, Debug, Default)]
        struct InRun {
            /// `--no-verify`.
            no_verify: bool,
            /// A rewrite of this very run confirmed the patch.
            confirmed: bool,
            /// A probe of the host found the upstream package in the
            /// global packages folder.
            stale: bool,
            /// A probe of the host found a copy it could not judge.
            unjudged: bool,
        }
        let run = |lanes: &'static LaneTable, said: InRun, name: &str| {
            let out = tmp.path().join(name);
            let mut params = VexEmbedArgs {
                vex: Some(out),
                vex_product: Some("pkg:generic/app@1.0.0".to_string()),
                vex_no_verify: said.no_verify,
                ..VexEmbedArgs::default()
            }
            .to_build_params(None);
            params.bazel.lanes = lanes;
            let named = |on: bool| on.then(|| NUGET.to_string()).into_iter().collect();
            params.assume_applied = named(said.confirmed);
            params.known_stale = named(said.stale);
            params.unjudged = named(said.unjudged);
            let manifest_path = common.resolved_manifest_path();
            let common = &common;
            async move { generate_vex_from_manifest_path(common, &params, &manifest_path).await }
        };
        let none = InRun::default();
        // The host's copy says nothing of a pin the Bazel build consumes:
        // not the upstream package the verification would find there, and
        // not what a probe of the same folder reported to the run.
        let host = [
            none,
            InRun {
                stale: true,
                ..none
            },
            InRun {
                unjudged: true,
                ..none
            },
            InRun {
                stale: true,
                confirmed: true,
                ..none
            },
        ];
        for (at, said) in host.into_iter().enumerate() {
            let attested = run(&TABLE, said, &format!("toy-{at}.json")).await;
            let attested = attested.unwrap_or_else(|e| panic!("{said:?}: {:?}", e.failed));
            assert_eq!(attested.statements, 1, "{said:?}: {:?}", attested.failed);
            assert!(
                attested.failed.is_empty(),
                "{said:?}: {:?}",
                attested.failed
            );
        }

        // The native reference is the source mapping of `nuget.config`,
        // a file the hub does not read; no lane finds a pin in the lock.
        // Nothing the run was told brings the statement back, and the
        // gate's reason is the one reported.
        let told = [
            none,
            InRun {
                no_verify: true,
                ..none
            },
            InRun {
                confirmed: true,
                ..none
            },
            InRun {
                stale: true,
                ..none
            },
            InRun {
                unjudged: true,
                ..none
            },
        ];
        for (at, said) in told.into_iter().enumerate() {
            let name = format!("production-{at}.json");
            let Err(withheld) = run(&lanes::PRODUCTION, said, &name).await else {
                panic!("attested with no lane to prove the pin: {said:?}");
            };
            assert_eq!(withheld.code, "no_applicable_patches");
            let reasons: Vec<&str> = withheld.failed.iter().map(|f| &f.reason[..]).collect();
            assert_eq!(reasons, [Code::VexNotConsumed.as_str()], "{said:?}");
        }

        // The control reads the folder the project's config names, which
        // an ambient `NUGET_PACKAGES` overrides for the whole process.
        if std::env::var_os("NUGET_PACKAGES").is_some_and(|set| !set.is_empty()) {
            return;
        }
        std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
        let Err(native) = run(&TABLE, none, "native.json").await else {
            panic!("attested over the upstream package in the global packages folder");
        };
        let reasons: Vec<&str> = native.failed.iter().map(|f| &f.reason[..]).collect();
        assert_eq!(reasons, ["not_applied"]);
        // And there a probe's finding is held against the pin, as it was.
        let stale = InRun {
            stale: true,
            confirmed: true,
            ..none
        };
        let Err(native) = run(&TABLE, stale, "native-stale.json").await else {
            panic!("attested over a copy a probe found unpatched");
        };
        let reasons: Vec<&str> = native.failed.iter().map(|f| &f.reason[..]).collect();
        assert_eq!(reasons, ["stale_install"]);
    }

    /// The pins no lockfile reference stands for, through the whole
    /// pipeline (sources, plan, gate, verification, document): a vendored
    /// lane's pin whose artifact the ledger records as wired by the owned
    /// index, with and without a manifest record and routed or not, and an
    /// agent lane's pin of a manifest record. Each is one statement on the
    /// evidence of its pin, or one omission; the production lanes prove
    /// neither, and the artifact alone never attests.
    #[tokio::test]
    async fn a_vendored_and_an_agent_pin_are_one_statement_through_the_whole_pipeline() {
        struct Fixture {
            tmp: tempfile::TempDir,
            root: PathBuf,
        }
        // `ledger`: the vendor ledger records the artifact as index-wired,
        // routed or not. `manifest`: agent mode's record of the patch.
        let fixture = |go_mod: &str, ledger: Option<bool>, manifest: bool| {
            let files = [
                NINE,
                ("MODULE.bazel", GO),
                ("go.mod", go_mod),
                ("go.sum", ""),
            ];
            let (tmp, root) = workspace(&files);
            let record = patch(UUID, "package/x", b"before", b"after");
            if manifest {
                let mut manifest = PatchManifest::new();
                manifest.patches.insert(BAR.to_string(), record);
                let text = serde_json::to_string(&manifest).unwrap();
                put(&root, ".socket/manifest.json", text);
            }
            async move {
                if let Some(routed) = ledger {
                    let wired = index_wired(BAR, "", routed);
                    put(&root, &format!("{}/x", wired.artifact.path), "after");
                    let mut state = VendorState::new();
                    state.entries.insert(BAR.to_string(), wired);
                    socket_patch_core::vendor::save_state(&root, &state)
                        .await
                        .unwrap();
                }
                Fixture { tmp, root }
            }
        };
        let run = |at: &Fixture, common: GlobalArgs, lanes: &'static LaneTable, name: &str| {
            let out = at.tmp.path().join(name);
            let mut params = VexEmbedArgs {
                vex: Some(out.clone()),
                vex_product: Some("pkg:generic/app@1.0.0".to_string()),
                ..VexEmbedArgs::default()
            }
            .to_build_params(None);
            params.bazel.lanes = lanes;
            let manifest_path = common.resolved_manifest_path();
            async move {
                let made = generate_vex_from_manifest_path(&common, &params, &manifest_path).await;
                let doc = std::fs::read(&out).ok();
                let doc = doc.map(|doc| serde_json::from_slice::<serde_json::Value>(&doc).unwrap());
                (made, doc)
            }
        };
        // The one statement of a run, as the document words it.
        let impact = |made: Result<_, VexGenError>, doc: Option<serde_json::Value>, what: &str| {
            let made: VexWriteSummary =
                made.unwrap_or_else(|e| panic!("{what}: {}: {:?}", e.message, e.failed));
            assert_eq!(made.statements, 1, "{what}: {:?}", made.failed);
            assert!(made.failed.is_empty(), "{what}: {:?}", made.failed);
            let doc = doc.unwrap_or_else(|| panic!("{what}: no document"));
            let [statement] = doc["statements"].as_array().unwrap().as_slice() else {
                panic!("{what}: {doc:#}");
            };
            statement["impact_statement"].as_str().unwrap().to_string()
        };
        let omitted =
            |made: Result<VexWriteSummary, _>, doc: Option<serde_json::Value>, what: &str| {
                let Err(e): Result<_, VexGenError> = made else {
                    panic!("{what}: attested");
                };
                assert_eq!(e.code, "no_applicable_patches", "{what}");
                assert!(doc.is_none(), "{what}: {doc:?}");
                let reasons: Vec<String> = e.failed.iter().map(|f| f.reason.clone()).collect();
                let notes: Vec<String> = e.warnings.iter().map(|w| w.code.clone()).collect();
                (reasons, notes)
            };

        // ── A vendored lane's pin ────────────────────────────────────
        let vendored = go_mod(&format!(" V-TOY1 {UUID}"), "");
        for (routed, manifest) in [(false, false), (false, true), (true, false), (true, true)] {
            let what = format!("routed {routed}, manifest record {manifest}");
            let at = fixture(&vendored, Some(routed), manifest).await;
            let (made, doc) = run(&at, common(&at.root), &TABLE, "toy.json").await;
            let said = impact(made, doc, &what);
            assert!(
                said.contains(&format!("{UUID} (vendored)")),
                "{what}: {said}"
            );

            // No enabled lane can tell the pin: the artifact is wired by
            // nothing that was proven.
            let (made, doc) = run(&at, common(&at.root), &lanes::PRODUCTION, "prod.json").await;
            let (reasons, notes) = omitted(made, doc, &what);
            assert_eq!(reasons, [VENDOR_UNWIRED], "{what}");
            assert!(
                notes.iter().any(|code| code == NOTE_CLAIM_UNWIRED),
                "{what}"
            );

            // A run on the global installs asks no workspace, so nothing
            // vouches for the artifact there.
            let global = GlobalArgs {
                global_prefix: Some(at.root.join("site-packages")),
                ..common(&at.root)
            };
            let (made, doc) = run(&at, global, &TABLE, "global.json").await;
            assert_eq!(omitted(made, doc, &what).0, [VENDOR_UNWIRED], "{what}");

            // A pin whose proof fails: one withhold, of the pin.
            let broken = go_mod(&format!(" V-TOY1 {UUID} broken"), "");
            put(&at.root, "go.mod", &broken);
            let (made, doc) = run(&at, common(&at.root), &TABLE, "broken.json").await;
            let stale = Code::withheld(WithholdKind::DerivedStale).as_str();
            assert_eq!(omitted(made, doc, &what).0, [stale], "{what}");
            put(&at.root, "go.mod", &vendored);

            // The workspace file gone: no Bazel build is there to consume
            // the pin, and no lockfile wires the artifact natively.
            std::fs::remove_file(at.root.join("MODULE.bazel")).unwrap();
            let (made, doc) = run(&at, common(&at.root), &TABLE, "native.json").await;
            assert_eq!(omitted(made, doc, &what).0, [VENDOR_UNWIRED], "{what}");
        }

        // ── An agent lane's pin of a manifest record ─────────────────
        // The Go directory replace: Bazel builds from the patched copy
        // under `.socket/go-patches`, which is verified as it always is.
        let copy = ".socket/go-patches/github.com/foo/bar@v1.0.0";
        let replace = format!("replace github.com/foo/bar v1.0.0 => ./{copy}\n");
        let agent = go_mod(&format!(" A-TOY1 {UUID}"), &replace);
        let at = fixture(&agent, None, true).await;
        put(&at.root, &format!("{copy}/x"), "after");
        put(
            &at.root,
            &format!("{copy}/go.mod"),
            "module github.com/foo/bar\n",
        );
        let (made, doc) = run(&at, common(&at.root), &TABLE, "agent.json").await;
        let said = impact(made, doc, "an agent pin");
        assert!(
            said.contains(UUID) && !said.contains("(vendored)"),
            "{said}"
        );
        // The tree is the evidence, so an unpatched copy is not attested.
        put(&at.root, &format!("{copy}/x"), "before");
        let (made, doc) = run(&at, common(&at.root), &TABLE, "agent-unpatched.json").await;
        assert_eq!(omitted(made, doc, "an unpatched copy").0, ["not_applied"]);
        put(&at.root, &format!("{copy}/x"), "after");
        // A pin whose proof fails, and no lane to tell a pin at all: one
        // withhold each, of the pin and of the tree no pin stands for.
        put(
            &at.root,
            "go.mod",
            go_mod(&format!(" A-TOY1 {UUID} broken"), &replace),
        );
        let (made, doc) = run(&at, common(&at.root), &TABLE, "agent-broken.json").await;
        let stale = Code::withheld(WithholdKind::DerivedStale).as_str();
        assert_eq!(omitted(made, doc, "a broken agent pin").0, [stale]);
        put(&at.root, "go.mod", &agent);
        let (made, doc) = run(&at, common(&at.root), &lanes::PRODUCTION, "agent-prod.json").await;
        let unconsumed = Code::VexNotConsumed.as_str();
        assert_eq!(omitted(made, doc, "no lane").0, [unconsumed]);
    }
}
