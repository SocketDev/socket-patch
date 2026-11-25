//! Vendored Maven: the router into the [`super::jvm`] backend, which plans
//! every Maven root (a single-module pom is a reactor of one), Gradle,
//! mixed, sbt and scala-cli build, plus the JVM orchestration around it
//! (upstream sourcing and verification, the committed-tree hot path) that
//! #972 moves next to the planners.
//!
//! The pre-v5 single-pom backend (a same-GAV `<repository>` in `pom.xml`
//! serving `.socket/vendor/maven/<uuid>/`) is retired. Only its revert
//! remains ([`revert_maven_opts`] over `maven_pom_repository` records), so
//! an older ledger still unwinds byte for byte; vendoring a root whose
//! ledger holds such an entry is refused (`legacy_maven_root`).

use std::path::{Path, PathBuf};

use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{
    atomic_write_artifact, atomic_write_bytes_preserving_mode, read_regular_to_bytes,
    read_regular_to_string,
};
use crate::utils::purl::{build_maven_purl, parse_maven_purl};
use crate::vendor::jvm::layout;

use super::common::{
    already_patched_result, done, failed_result, refused, synthesized_result,
    zip_bytes_match_after_hashes,
};
use super::path::vendor_uuid_dir_rel;
use super::revert::{self, KeepPolicy};
use super::service_fetch::service_archive_copy;
use super::state::{VendorArtifact, VendorEntry, WiringAction, WiringRecord};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// The project file the pre-v5 backend wired (always at the project root).
const PROJECT_POM: &str = "pom.xml";

/// The pre-v5 wiring-record discriminator. The record carries the
/// WHOLE-FILE pre/post `pom.xml` snapshot (the authoritative revert
/// record); its `key` is the repository id added, which the revert
/// ownership gate keys off.
const REPO_WIRING_KIND: &str = "maven_pom_repository";

/// The id prefix of the pre-v5 vendored `<repository>`
/// (`socket-patch-vendor-<uuid>`).
pub(crate) const VENDOR_REPO_ID_PREFIX: &str = "socket-patch-vendor-";

/// The url prefix of the pre-v5 vendored `<repository>`: the project root,
/// so the `.socket/vendor/maven/<uuid>` tree after it resolves on any
/// checkout.
pub(crate) const VENDOR_REPO_URL_PREFIX: &str = "file://${project.basedir}/";

/// Bound on a pom download from the registry — a pom is dependency metadata
/// (small XML); a multi-MB response is a mirror serving the wrong thing.
const MAX_POM_BYTES: usize = 8 * 1024 * 1024;

/// User-Agent for maven2 registry requests. Maven Central blocks/rate-limits
/// user agents containing "socket", so the CLI's own `SocketPatchCLI/x.y.z`
/// UA (`constants.rs`) gets the pom fallback download refused. These requests
/// instead identify exactly as the official Maven CLI —
/// `Apache-Maven/<maven> (Java <jdk>; <os.name> <os.version>)`, the shape
/// maven-resolver sends — pinned to fixed Maven/JDK/OS versions so the string
/// stays deterministic (no runtime probing). Only maven2 registry traffic
/// uses this; Socket API requests keep the honest UA.
#[cfg(target_os = "macos")]
const MAVEN_USER_AGENT: &str = "Apache-Maven/3.9.11 (Java 17.0.16; Mac OS X 15.5)";
#[cfg(target_os = "windows")]
const MAVEN_USER_AGENT: &str = "Apache-Maven/3.9.11 (Java 17.0.16; Windows 11 10.0)";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const MAVEN_USER_AGENT: &str = "Apache-Maven/3.9.11 (Java 17.0.16; Linux 6.8.0)";

/// Whether [`vendor_maven`] — a wet run with the service enabled — asks the
/// patch service for `record`: past every refusal and skip it raises first
/// (`not_build_root`, `legacy_maven_root`, `no_build_file`, and
/// [`jvm_prelude`]'s coordinate, ledger and sbt / scala-cli gate stops),
/// not the empty patch, and not answered by the committed-tree hot path.
/// The vendor loop's download plan consults this.
pub(crate) async fn service_preflight(
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<crate::api::client::PlannedDownload> {
    if not_build_root(project_root).is_some() || legacy_root(project_root).await {
        return None;
    }
    let shape = detect_shape(project_root);
    if shape == super::jvm::Shape::Other {
        return None;
    }
    jvm_prelude(shape, purl, project_root, record, None)
        .await
        .ok()?;
    (!record.files.is_empty()).then_some(())?;
    jvm_committed_patch(shape, purl, project_root, record)
        .await
        .is_none()
        .then_some(())?;
    // `service_archive_copy` checks the archive's members against the
    // afterHashes before writing it verbatim.
    Some(crate::api::client::PlannedDownload {
        stage: Some(super::prestage::PrestageRecipe::verify_zip(&record.files)),
        ..crate::api::client::PlannedDownload::archive(record.uuid.clone())
    })
}

/// Vendor a Maven package through the [`super::jvm`] backend: every Maven
/// root (a single-module pom is a reactor of one), Gradle build, mixed
/// root, sbt and scala-cli build gets a suffixed tree under
/// `.socket/vendor/` and the planner's wiring.
///
/// Refused, with nothing written: a project that is not its build's root
/// (`not_build_root`), a root whose ledger still holds a pre-v5
/// `<repository>` entry (`legacy_maven_root`, see [`legacy_root`]), and a
/// root with no JVM build at all (`no_build_file`).
///
/// `installed_dir` is the crawler's version dir
/// (`~/.m2/repository/<g>/<a>/<v>/`), the first place the upstream pom
/// and jar are looked for.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_maven(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    _vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    if let Some(detail) = not_build_root(project_root) {
        return refused("vendor_jvm_shape_unsupported", detail);
    }
    if legacy_root(project_root).await {
        return refused("vendor_jvm_shape_unsupported", legacy_root_detail());
    }
    let shape = detect_shape(project_root);
    // A hub of a Bazel workspace builds the jar of its own lock, whatever
    // the project's Maven or Gradle build holds: its patch is an entry of
    // its own, in the root MODULE.bazel.
    let hub = hub_verdict(project_root, purl, &record.uuid).await;
    if shape == super::jvm::Shape::Other {
        return match hub {
            Some(verdict) => {
                vendor_hub(verdict, purl, project_root, record, dry_run, service).await
            }
            None => {
                let refusal = super::jvm::no_build_file_refusal();
                let stale = stale_hub_entry(project_root, purl).await;
                refused(refusal.code, refusal.detail + &stale)
            }
        };
    }
    let outcome = vendor_maven_jvm(
        shape,
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        dry_run,
        force,
        service,
    )
    .await;
    match (hub, outcome) {
        // Beside a build that took the patch, the hub gets the jar of that
        // build's own tree. A hub that cannot be given one is the run's
        // warning ([`crate::bazel::maven::notices`]).
        (
            Some(Ok(hub)),
            VendorOutcome::Done {
                result,
                entry,
                mut warnings,
            },
        ) if result.success && !dry_run => {
            let committed = jvm_committed_patch(shape, purl, project_root, record).await;
            let jar = committed.map(|((jar, ..), _)| jar);
            // The directory must survive the commit, as the hub's own
            // vendoring requires: an entry that names a directory git
            // leaves out fails the build of every other checkout.
            let unit = hub.1.unit().unwrap_or_default();
            let ignored = super::npm_dir::ignored_root_refusal(project_root, &unit).await;
            let written = match (jar, ignored) {
                (_, Some((_, detail))) => Err(detail),
                (Some(jar), None) => write_hub(&hub, project_root, jar, true).await,
                (None, None) => Err("the vendored tree holds no jar of the patch".to_string()),
            };
            // The entry took the place of the one an earlier patch of the
            // jar had: that patch's directory is named by nothing now.
            if written.is_ok() {
                let left = drop_superseded_units(project_root).await;
                let left = left.into_iter();
                warnings.extend(left.map(|why| VendorWarning::new("cleanup_failed", why)));
            }
            warnings.extend(match written {
                // The build was in sync and the hub's part was not: said, as
                // every artifact that a run of an in-sync package writes.
                Ok(true) if entry.is_none() => {
                    let unit = hub.1.unit().unwrap_or_default();
                    let detail = format!(
                        "the copy of the patched jar that the Bazel hub builds was missing or \
                         changed, or {} did not name it: wrote {unit} and its entry there",
                        crate::bazel::maven::FILE
                    );
                    Some(VendorWarning::new("vendor_artifact_rebuilt", detail))
                }
                Ok(_) => None,
                Err(why) => {
                    let detail =
                        format!("{purl}: the Bazel hub was not given the patched jar: {why}");
                    Some(VendorWarning::new(
                        crate::bazel::maven::HUB_UNPATCHED,
                        detail,
                    ))
                }
            });
            done(result, entry, warnings)
        }
        (_, outcome) => outcome,
    }
}

/// The flavor of the ledger entry of a patch that only the hub of a Bazel
/// workspace takes: its artifact is the jar of the hub's directory, and
/// its wiring is the entry of the block in `MODULE.bazel`, which is read
/// from that file and recorded nowhere else.
pub const HUB_FLAVOR: &str = "bazel";

/// The label and the entry of a patch for the block.
type Hub = (String, crate::bazel::maven::Patch);

/// What vendored mode writes for the hub that builds the jar of `purl`
/// ([`crate::bazel::maven::vendored`]), read off the runtime.
async fn hub_verdict(
    project_root: &Path,
    purl: &str,
    uuid: &str,
) -> Option<Result<Hub, crate::bazel::maven::Declined>> {
    let (root, purl, uuid) = (
        project_root.to_path_buf(),
        purl.to_string(),
        uuid.to_string(),
    );
    crate::utils::fs::run_blocking(move || crate::bazel::maven::vendored(&root, &purl, &uuid)).await
}

/// The refusal of each of `candidates` (`(purl, uuid)`) that only a hub of
/// a Bazel workspace builds and vendored mode writes no entry for, with
/// the code a hosted run gives it and what the block holds for the jar in
/// the checkout as it is: decided before anything is downloaded, and
/// before a hosted entry is taken out. Empty in a project with a Maven,
/// Gradle, sbt or scala-cli build, where such a hub is a warning of the
/// run.
pub fn hub_refusals(
    project_root: &Path,
    candidates: &[(String, String)],
) -> Vec<(String, (&'static str, String))> {
    if detect_shape(project_root) != super::jvm::Shape::Other {
        return Vec::new();
    }
    let refused = |(purl, uuid): &(String, String)| {
        let declined = crate::bazel::maven::vendored(project_root, purl, uuid)?.err()?;
        Some((purl.clone(), declined))
    };
    candidates.iter().filter_map(refused).collect()
}

/// Whether this run judges a hub where it does not come by one through
/// the lookup: not for a user who switched the Bazel support off
/// ([`crate::bazel::off`]). With the switch no hub is a build of the
/// project: a run ejects no entry, gives no hub a copy and says nothing of
/// one. The undo, the audit and `repair` do not ask: what an earlier run
/// wrote stays theirs to see.
fn judges_hubs() -> bool {
    !crate::bazel::off()
}

/// The entries of the block in `MODULE.bazel` at the project root, for a
/// run that judges a hub by them: `None` where it judges none
/// ([`judges_hubs`]), asked before anything is read. No entry where the
/// file is not there or holds no block.
async fn judged_block(project_root: &Path) -> Option<Vec<crate::bazel::maven::Patch>> {
    use crate::bazel::maven::{entries, FILE};
    if !judges_hubs() {
        return None;
    }
    let text = read_regular_to_string(&project_root.join(FILE)).await;
    Some(text.map(|text| entries(&text)).unwrap_or_default())
}

/// Whether the hub of a Bazel workspace is the only build of the project
/// that vendored mode can patch: a hosted pin that only the block of
/// `MODULE.bazel` wires is ejected there. Elsewhere an eject leaves it,
/// and the hub's entry changes only with a run that vendors the same patch
/// for the Maven or Gradle build. The caller holds the pins of the block,
/// which are read whatever the switch says, so nothing is read here.
pub fn hub_alone(project_root: &Path) -> bool {
    judges_hubs() && detect_shape(project_root) == super::jvm::Shape::Other
}

/// Whether the block of `MODULE.bazel` at the project root holds the
/// vendored entry of the patch `uuid`: a hub builds the jar committed in
/// the directory of that patch, which a run gave it or kept for it.
pub async fn hub_wired(project_root: &Path, uuid: &str) -> bool {
    let ours = |patch: &crate::bazel::maven::Patch| patch.uuid == uuid && patch.unit().is_some();
    let block = judged_block(project_root).await;
    block.is_some_and(|block| block.iter().any(ours))
}

/// What the refusal of `purl` in a project without a JVM build ends with
/// when the block of `MODULE.bazel` still holds an entry for its jar: no
/// hub builds the jar at that version any more, so Bazel stops at the
/// entry, and the undo is what takes it out.
async fn stale_hub_entry(project_root: &Path, purl: &str) -> String {
    use crate::bazel::maven::FILE;
    let block = judged_block(project_root).await;
    match block.is_some_and(|block| block.iter().any(|patch| patch.purl() == purl)) {
        true => format!(
            "; {FILE} holds an entry for it that no pinned hub takes any more, so Bazel stops \
             there: run `socket-patch rollback {purl}`"
        ),
        false => String::new(),
    }
}

/// After a run wrote `module`, the text of `MODULE.bazel`: removes each
/// directory that vendored mode kept for the hub's jar of a patch which
/// the file no longer names and no entry of `state` records. Another entry
/// took the place of the vendored one there (a hosted one, or the one of a
/// later patch of the jar), and beside a Maven build the ledger entry of
/// the patch is that build's, so no revert removed the directory. Gives
/// what could not be removed.
pub async fn drop_unnamed_units(
    project_root: &Path,
    module: &str,
    state: &super::VendorState,
) -> Vec<String> {
    let mut left = Vec::new();
    // Every directory there, not only the ones of the patches this run
    // wrote: an entry also takes the place of an earlier patch of its jar.
    let units = project_root.join(crate::bazel::maven::UNITS);
    let mut uuids = Vec::new();
    if let Ok(mut dirs) = tokio::fs::read_dir(&units).await {
        while let Ok(Some(dir)) = dirs.next_entry().await {
            uuids.extend(dir.file_name().into_string());
        }
    }
    uuids.sort();
    for unit in uuids
        .iter()
        .filter_map(|uuid| vendor_uuid_dir_rel("maven", uuid))
    {
        let recorded = |entry: &VendorEntry| entry.artifact.path.starts_with(&unit);
        let dir = project_root.join(&unit);
        let ours = read_regular_to_bytes(&dir.join(crate::bazel::maven::REPO)).await;
        if module.contains(&unit) || state.entries.values().any(recorded) || ours.is_err() {
            continue;
        }
        let top = project_root.join(crate::constants::SOCKET_DIR);
        if let Err(e) = crate::utils::socket_dir::remove_tree_and_prune(&dir, &top).await {
            left.push(format!(
                "could not delete {unit}, which {} no longer names: {e}",
                crate::bazel::maven::FILE
            ));
        }
    }
    left
}

/// [`drop_unnamed_units`] for the checkout as a vendored run left it, read
/// from its `MODULE.bazel` and its ledger. Nothing is dropped where either
/// cannot be read.
async fn drop_superseded_units(project_root: &Path) -> Vec<String> {
    let module = read_regular_to_string(&project_root.join(crate::bazel::maven::FILE)).await;
    let state = super::state::load_state(project_root).await;
    match (module, state) {
        (Ok(module), Ok(state)) => drop_unnamed_units(project_root, &module, &state).await,
        _ => Vec::new(),
    }
}

/// Writes the directory of `hub`'s entry with `jar` and puts the entry in
/// the block, in the place of any other entry for the same jar. Gives
/// whether anything was not in place already. Without `write` nothing is
/// written, and that is what a run would change.
async fn write_hub(
    hub: &Hub,
    project_root: &Path,
    jar: Vec<u8>,
    write: bool,
) -> Result<bool, String> {
    use crate::bazel::maven::{unit_files, with_patch, FILE};
    let (label, patch) = hub;
    let module = project_root.join(FILE);
    let text = read_regular_to_string(&module)
        .await
        .map_err(|e| format!("{FILE} cannot be read: {e}"))?;
    let wired = with_patch(&text, label, patch.clone())
        .ok_or_else(|| format!("the block in {FILE} cannot be written to"))?;
    let mut changed = wired != text;
    for (rel, bytes) in unit_files(patch, jar).into_iter().flatten() {
        let path = project_root.join(&rel);
        if read_regular_to_bytes(&path)
            .await
            .is_ok_and(|held| held == bytes)
        {
            continue;
        }
        changed = true;
        if !write {
            continue;
        }
        let dir = path.parent().unwrap_or(project_root);
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        atomic_write_artifact(&path, &bytes)
            .await
            .map_err(|e| format!("cannot write {rel}: {e}"))?;
    }
    // The entry last: it names a directory that is there.
    if write && wired != text {
        atomic_write_bytes_preserving_mode(&module, wired.as_bytes())
            .await
            .map_err(|e| format!("cannot write {FILE}: {e}"))?;
    }
    Ok(changed)
}

/// Vendored mode for a patch that only a hub builds: the patched jar from
/// the patch service, or the committed one when it already carries the
/// patch, in the hub's directory, and the entry in the block. A decline is
/// the refusal, and nothing is written for it.
async fn vendor_hub(
    verdict: Result<Hub, crate::bazel::maven::Declined>,
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
    dry_run: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    let hub = match verdict {
        Ok(hub) => hub,
        Err((code, detail)) => return refused(code, detail),
    };
    let unit = vendor_uuid_dir_rel("maven", &record.uuid);
    let (Some(unit), Some(jar_rel)) = (unit, hub.1.jar()) else {
        let detail = format!("non-canonical patch uuid {:?}", record.uuid);
        return refused("unsafe_coordinates", detail);
    };
    // The directory must survive the commit the vendored workflow ends with.
    if let Some((code, detail)) = super::npm_dir::ignored_root_refusal(project_root, &unit).await {
        return refused(code, detail);
    }
    let jar_path = project_root.join(&jar_rel);
    if record.files.is_empty() {
        let nothing = synthesized_result(purl, &jar_path, Vec::new(), true, None);
        return done(nothing, None, Vec::new());
    }
    let state = match super::state::load_state(project_root).await {
        Ok(state) => state,
        Err(e) => return refused("vendor_state_unreadable", e.to_string()),
    };
    // The committed jar is taken as it is only when the ledger records its
    // bytes: one that merely carries the patch's files may hold anything
    // else, and would be recorded and wired as the vendored jar.
    let recorded = super::state::lookup_entry(&state.entries, purl)
        .filter(|entry| entry.uuid == record.uuid && entry.artifact.path == jar_rel)
        .map(|entry| entry.artifact.sha256.clone());
    let on_record = |jar: &Vec<u8>| Some(hex::encode(Sha256::digest(jar))) == recorded;
    let mut warnings = Vec::new();
    let committed = read_regular_to_bytes(&jar_path).await.ok();
    let committed =
        committed.filter(|jar| on_record(jar) && zip_bytes_match_after_hashes(jar, &record.files));
    let was_committed = committed.is_some();
    let jar = match committed {
        Some(jar) => jar,
        None if dry_run => Vec::new(),
        None => match service_archive_copy(service, record, &hub.1.artifact, ".jar", &mut warnings)
            .await
        {
            Ok(jar) => jar,
            Err(outcome) => return *outcome,
        },
    };
    let result = already_patched_result(purl, &jar_path, &record.files);
    let entry = VendorEntry {
        flavor: Some(HUB_FLAVOR.to_string()),
        ..maven_entry(hub.1.purl(), record, jar_rel, &jar, Vec::new())
    };
    match write_hub(&hub, project_root, jar, !dry_run).await {
        // In place, and on record: the run changes nothing.
        Ok(false) if was_committed => done(result, None, warnings),
        Ok(_) if dry_run => {
            let preview = super::common::preview_result(purl, &jar_path, &record.files);
            done(preview, None, warnings)
        }
        Ok(_) => done(result, Some(entry), warnings),
        Err(why) => done(failed_result(purl, &jar_path, why), None, warnings),
    }
}

/// The ledger entry for a vendored jar: `wiring` is the pom.xml record on a
/// full vendor, empty on an artifact-only rebuild (see the hot path).
fn maven_entry(
    base_purl: String,
    record: &PatchRecord,
    jar_copy_rel: String,
    jar_bytes: &[u8],
    wiring: Vec<WiringRecord>,
) -> VendorEntry {
    VendorEntry::new(
        "maven".to_string(),
        base_purl,
        record.uuid.clone(),
        VendorArtifact {
            yarn_berry10c0: None,
            // A `.jar` is a single verifiable file; record its plain sha256 for
            // tooling (harvest re-derives per-entry git hashes from the zip, so
            // the vendored copy is self-describing without a network).
            path: jar_copy_rel,
            sha256: hex::encode(Sha256::digest(jar_bytes)),
            size: Some(jar_bytes.len() as u64),
            platform_locked: None,
            file_inventory: None,
        },
        wiring,
    )
}

/// Revert a Maven vendor entry. A JVM entry goes to the planner's revert;
/// a pre-v5 entry has its `<repository>` surgically removed from
/// `pom.xml` (restoring the whole verbatim original only on the byte-identical
/// fast path — otherwise excising just our block so sibling patches and user
/// edits survive) and remove the validated uuid dir. A drifted live pom.xml —
/// our block already gone, a re-generated pom — is left alone with a
/// `vendor_lock_entry_drifted` warning.
///
/// Drift-keep: when a record was left alone and the live pom.xml STILL names
/// the uuid dir (an unrecognized or truncated record over a wired pom, a
/// hand-edited `<repository>`), the artifact is kept and `kept_artifact`
/// tells the caller to keep the ledger entry too — deleting it would strand
/// the `<repository>` at a gone path. A pom that no longer references the
/// dir has converged: the drift is warned about and the artifact removed.
pub async fn revert_maven(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_maven_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_maven`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion while the wiring restore runs unchanged.
///
/// With an entry of the patch in the block of a Bazel workspace, the edits
/// of both builds are one commit ([`crate::utils::group_commit`]): the
/// files of the Maven or Gradle build and `MODULE.bazel` are captured as
/// they are prepared and written together. A revert that is refused writes
/// none of them, and a write that fails puts the files already replaced
/// back, so the two builds never end on different versions of the jar.
/// What the edits leave unnamed (the build's tree, the hub's directory) is
/// removed after the commit, and the caller drops the ledger entry after
/// that. A run that is killed between the first replaced file and the last
/// leaves the commit's journal, which the next command that takes the
/// apply lock finishes; the undo run again then removes what no file names
/// any more.
pub async fn revert_maven_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    use crate::utils::group_commit::{self, GroupCommit};
    // Checked before anything is prepared: a block that names the directory
    // in a way the undo cannot take out fails it whole.
    let hub = match unwire_hub(entry, project_root).await {
        Ok(hub) => hub.filter(|_| !opts.dry_run),
        Err(why) => return RevertOutcome::failed(why),
    };
    // A group that is already open here (the staged revert of a hosted
    // takeover) is the commit of these edits: no second one is opened.
    let module = project_root.join(crate::bazel::maven::FILE);
    let group = (hub.is_some() && !group_commit::is_capturing(&module)).then(|| {
        let group = GroupCommit::begin(project_root);
        group.defer_removals();
        group
    });
    let unwired = hub.as_ref().map(|(_, unwired)| unwired.as_str());
    let mut outcome = revert_edits(entry, project_root, opts, unwired).await;
    if !outcome.success || opts.dry_run {
        // An open group ends here with nothing written and nothing removed.
        return outcome;
    }
    if let Some(group) = group {
        if let Err(e) = group.commit().await {
            outcome.success = false;
            outcome.error = Some(commit_failure(&e));
            return outcome;
        }
        // The tree was queued for after the commit, where a file that could
        // not be removed is not reported: the entry stays for the next undo.
        let removes = !outcome.kept_artifact && !opts.keep_artifact;
        let read = crate::utils::fs::read_regular_to_bytes_sync;
        let on_disk = |file: &str| read(&project_root.join(file)).is_ok();
        let mut tree = entry.wiring.iter();
        let left = |w: &&WiringRecord| w.kind == super::jvm::TREE_KIND && on_disk(&w.file);
        if let Some(w) = tree.find(left).filter(|_| removes) {
            outcome.success = false;
            outcome.error = Some(format!("failed to remove {}", w.file));
            return outcome;
        }
    }
    let unit = hub.map(|(unit, _)| unit);
    revert_artifacts(outcome, entry, project_root, opts, unit).await
}

/// Why the commit of [`revert_maven_opts`] failed, and what it left.
fn commit_failure(e: &std::io::Error) -> String {
    use crate::utils::group_commit::{is_pending, symlinked_target};
    if let Some(linked) = symlinked_target(e) {
        return crate::hosted::engine::symlink_refusal(linked).message;
    }
    let left = match is_pending(e) {
        true => {
            "some files were replaced and could not be put back; the commit is journaled and \
             the next socket-patch command in this project finishes it"
        }
        false => "every file is as it was",
    };
    format!(
        "could not write {} and the files of the Maven or Gradle build together: {e}; {left}",
        crate::bazel::maven::FILE
    )
}

/// The file edits of [`revert_maven_opts`]: those of the Maven or Gradle
/// build, and then `unwired`, the text of `MODULE.bazel` without the entry
/// of the patch, once they succeeded.
async fn revert_edits(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
    unwired: Option<&str>,
) -> RevertOutcome {
    // Routed only when EVERY record is a JVM kind; the JVM revert validates
    // the uuid, the coordinates and each recorded path before any disk
    // access (state.json is tamper-able).
    let mut outcome = match super::jvm::apply::is_jvm_entry(entry) {
        true => super::jvm::apply::revert(project_root, entry, opts).await,
        false => revert_repo_records(entry, project_root, opts.dry_run).await,
    };
    if let Some(unwired) = unwired.filter(|_| outcome.success) {
        if let Err(why) = write_unwired(project_root, unwired).await {
            outcome.success = false;
            outcome.error = Some(why);
        }
    }
    outcome
}

/// The records of a pre-v5 entry, each taken out of `pom.xml`.
async fn revert_repo_records(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid grammar
    // is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("maven", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let mut warnings = Vec::new();

    // One wiring record today; reverse-order iteration keeps parity with the
    // multi-record backends.
    for w in entry.wiring.iter().rev() {
        let restored = match w.kind.as_str() {
            REPO_WIRING_KIND => {
                revert_repo_record(&project_root.join(PROJECT_POM), w, &uuid_dir_rel, dry_run).await
            }
            _ => {
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
                ));
                continue;
            }
        };
        match restored {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} no longer carries the vendored <repository> {}; left alone",
                    w.file,
                    w.key_label()
                ),
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
    RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    }
}

/// What [`revert_maven_opts`] removes once its edits are in: the directory
/// of a pre-v5 entry or of a patch that only a hub took, and beside a Maven
/// or Gradle build `unit`, the directory of the hub's copy that the block
/// named. Without an entry in the block, the hub's copy of a JVM entry that
/// an interrupted undo left behind goes too: no file names it.
async fn revert_artifacts(
    mut outcome: RevertOutcome,
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
    unit: Option<String>,
) -> RevertOutcome {
    let own = vendor_uuid_dir_rel("maven", &entry.uuid);
    if !super::jvm::apply::is_jvm_entry(entry) {
        let Some(uuid_dir_rel) = own else {
            return outcome;
        };
        // Drift-keep (see the fn doc): never delete a uuid dir the live pom
        // still routes Maven at.
        let policy = KeepPolicy::OnDriftWhileReferenced(&[PROJECT_POM]);
        return revert::finish(outcome, project_root, &uuid_dir_rel, opts, policy).await;
    }
    // The hub's directory is no tree of the JVM revert.
    let made = |unit: &String| {
        project_root
            .join(unit)
            .join(crate::bazel::maven::REPO)
            .is_file()
    };
    let unit = unit.or_else(|| own.filter(made));
    let unit = unit.filter(|_| !opts.keep_artifact);
    if let Some(unit) = unit.map(|unit| project_root.join(unit)) {
        let top = project_root.join(crate::constants::SOCKET_DIR);
        if let Err(e) = crate::utils::socket_dir::remove_tree_and_prune(&unit, &top).await {
            outcome.success = false;
            outcome.error = Some(format!("failed to remove {}: {e}", unit.display()));
        }
    }
    outcome
}

/// The text of `MODULE.bazel` at the project root, `None` where there is
/// no such file. Any other failure to read it is an error: a file that
/// cannot be read may still name the directory of a vendored patch.
async fn read_module(project_root: &Path) -> Result<Option<String>, String> {
    use crate::bazel::maven::FILE;
    match read_regular_to_string(&project_root.join(FILE)).await {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{FILE} cannot be read: {e}")),
    }
}

/// What taking the vendored entry of `entry`'s patch out of the block that
/// `MODULE.bazel` at the project root holds for the hubs of a Bazel
/// workspace ([`crate::bazel::maven`]) leaves, when it holds one: the
/// directory the entry named and the text [`write_unwired`] writes. A
/// file that names that directory in any other way (a block that was
/// changed by hand), or one that cannot be read, fails the revert before
/// anything is written or removed: the build would stop at a directory
/// that is gone. Nothing is written here.
async fn unwire_hub(
    entry: &VendorEntry,
    project_root: &Path,
) -> Result<Option<(String, String)>, String> {
    use crate::bazel::maven::{without, Patch, FILE};
    let Some(unit) = vendor_uuid_dir_rel("maven", &entry.uuid) else {
        return Ok(None);
    };
    let text = match read_module(project_root).await? {
        Some(text) if text.contains(&unit) => text,
        _ => return Ok(None),
    };
    let ours = |patch: &Patch| patch.uuid == entry.uuid && patch.unit().is_some();
    let Some(unwired) = without(&text, &mut { ours }).filter(|unwired| !unwired.contains(&unit))
    else {
        return Err(format!(
            "{FILE} names {unit} outside an entry of the block socket-patch keeps there, or \
             that block was changed by hand: take what names the directory out of {FILE}, \
             then run the command again"
        ));
    };
    Ok(Some((unit, unwired)))
}

/// Writes `unwired`, the text [`unwire_hub`] gave, to `MODULE.bazel`.
async fn write_unwired(project_root: &Path, unwired: &str) -> Result<(), String> {
    use crate::bazel::maven::FILE;
    atomic_write_bytes_preserving_mode(&project_root.join(FILE), unwired.as_bytes())
        .await
        .map_err(|e| format!("cannot write {FILE}: {e}"))
}

/// After `repair` put back the jar of a patch that only a hub takes:
/// the other files of its directory, written where one is missing or is
/// not the file vendored mode writes. A directory that was lost whole is
/// no repository with its jar alone, and Bazel stops at the entry that
/// names it. Nothing for a patch whose entry the block does not hold.
pub(crate) async fn restore_hub_files(
    project_root: &Path,
    entry: &VendorEntry,
) -> Result<(), String> {
    use crate::bazel::maven::{entries, unit_files, Patch};
    let text = read_module(project_root).await?;
    let ours = |patch: &Patch| patch.uuid == entry.uuid && patch.unit().is_some();
    let patch = entries(&text.unwrap_or_default()).into_iter().find(ours);
    let files = patch.and_then(|patch| unit_files(&patch, Vec::new()));
    let Some([repo, build, _, ignore]) = files else {
        return Ok(());
    };
    for (rel, bytes) in [repo, build, ignore] {
        let path = project_root.join(&rel);
        if read_regular_to_bytes(&path)
            .await
            .is_ok_and(|held| held == bytes)
        {
            continue;
        }
        let dir = path.parent().unwrap_or(project_root);
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        atomic_write_artifact(&path, &bytes)
            .await
            .map_err(|e| format!("cannot write {rel}: {e}"))?;
    }
    Ok(())
}

/// What `vendor --check` holds the hub's copy of a patch to, for the
/// ledger entry `entry`. The directory of the patch has its entry in the
/// block of `MODULE.bazel`; a build takes that entry; the two files that
/// make the directory a repository are the ones socket-patch wrote; and
/// the jar there is, byte for byte, the vendored artifact, of which it is
/// a copy beside a Maven or Gradle build. `Ok` for a patch that has
/// neither an entry nor a directory.
pub async fn check_hub(project_root: &Path, entry: &VendorEntry) -> Result<(), String> {
    use crate::bazel::maven::{entries, pins, unit_files, Patch, FILE, REPO, STOPS};
    let Some(unit) = vendor_uuid_dir_rel("maven", &entry.uuid) else {
        return Ok(());
    };
    let text = read_module(project_root).await?.unwrap_or_default();
    let ours = |patch: &Patch| patch.uuid == entry.uuid && patch.unit().is_some();
    let Some(patch) = entries(&text).into_iter().find(ours) else {
        let made = read_regular_to_bytes(&project_root.join(&unit).join(REPO)).await;
        return match (text.contains(&unit), made.is_ok()) {
            (true, _) => Err(format!(
                "{FILE} names {unit} outside an entry of the block socket-patch keeps there, \
                 or that block was changed by hand: restore the block, or delete it and run \
                 `socket-patch vendor`"
            )),
            (false, true) => Err(format!(
                "{FILE} no longer names {unit}, so the Bazel build takes the upstream jar; \
                 re-run `socket-patch vendor`"
            )),
            (false, false) => Ok(()),
        };
    };
    // An entry that a build stops at, which the undo takes out, or one
    // that a build may pass without.
    let (root, purl) = (project_root.to_path_buf(), patch.purl());
    let read = crate::utils::fs::run_blocking(move || pins(&root, &text)).await;
    let unbuilt = |pin: crate::bazel::maven::Pin| pin.unbuilt.filter(|_| ours(&pin.patch));
    if let Some(why) = read.into_iter().flatten().find_map(unbuilt) {
        return Err(match why.ends_with(STOPS) {
            true => format!("{why}: run `socket-patch rollback {purl}`"),
            false => format!("{why}: the Bazel build may not take the patched jar"),
        });
    }
    let Some([repo, build, (jar, _), _]) = unit_files(&patch, Vec::new()) else {
        return Ok(());
    };
    for (rel, bytes) in [repo, build] {
        let held = read_regular_to_bytes(&project_root.join(&rel)).await;
        if !held.is_ok_and(|held| held == bytes) {
            return Err(format!(
                "{rel} is not the file socket-patch wrote: Bazel may build another jar than \
                 the patched one; re-run `socket-patch vendor`"
            ));
        }
    }
    let held = read_regular_to_bytes(&project_root.join(&jar)).await;
    match held.is_ok_and(|held| super::jvm::sha256_hex(&held) == entry.artifact.sha256) {
        true => Ok(()),
        false => Err(format!(
            "{jar}, which Bazel builds, is not the vendored jar of the patch; re-run \
             `socket-patch vendor`"
        )),
    }
}

// ── v5 JVM backend ─────────────────────────────────────────────────

/// The `legacy_maven_root` refusal detail (see [`legacy_root`]).
fn legacy_root_detail() -> String {
    format!(
        "reason: legacy_maven_root: pom.xml is still vendored through the pre-v5 \
         <repository> wiring; {}",
        super::common::REVERT_ALL_AND_REVENDOR
    )
}

/// The planner shape of the project root (see [`super::jvm::detect`]).
fn detect_shape(project_root: &Path) -> super::jvm::Shape {
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    super::jvm::detect(&|rel: &str| reader.read(rel), &|dir: &str| reader.list(dir))
}

/// The skip of each of `candidates` (`(purl, uuid)`) whose base version no
/// module of the Maven build at `project_root` selects (the gate
/// [`jvm_prelude`] runs, [`super::jvm::sbt_gate::MAVEN_NOT_SELECTED`]),
/// for the refusals a run decides before it downloads anything. A
/// candidate an earlier run pinned is left to the backend, which takes the
/// pin out ([`unpin_unselected`]). Empty for any other build.
pub(super) fn maven_not_selected_refusals(
    project_root: &Path,
    candidates: &[(String, String)],
) -> Vec<(String, (&'static str, String))> {
    use crate::crawlers::maven_selection::{not_selected_detail, MavenSelection, Standing};
    if detect_shape(project_root) != super::jvm::Shape::MavenReactor {
        return Vec::new();
    }
    let selection = MavenSelection::for_project(project_root);
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    candidates
        .iter()
        .filter_map(|(purl, uuid)| {
            let (g, a, v) = parse_maven_purl(purl)?;
            let Standing::NotSelected(others) = selection.standing(&g, &a, &v) else {
                return None;
            };
            let coords = super::jvm::Coords {
                group_id: &g,
                artifact_id: &a,
                version: &v,
                uuid,
            };
            let pinned = super::jvm::maven_reactor::unpin_plan(
                &|rel| reader.read(rel),
                &|dir| reader.list(dir),
                &coords,
            )
            .is_some();
            (!pinned).then(|| {
                (
                    purl.clone(),
                    (
                        super::jvm::sbt_gate::MAVEN_NOT_SELECTED,
                        not_selected_detail(&g, &a, &v, &others),
                    ),
                )
            })
        })
        .collect()
}

/// The root's ledger still holds a pre-v5 single-pom entry (a
/// `maven_pom_repository` record). Its revert restores a whole-file pom
/// snapshot, which planner edits on the same pom would make unsafe, and
/// nothing migrates it, so every Maven vendoring of the root is refused
/// until `vendor --revert` has unwound it. An unreadable ledger is left to
/// the JVM backend's own `vendor_state_unreadable` refusal.
async fn legacy_root(project_root: &Path) -> bool {
    super::state::load_state(project_root)
        .await
        .is_ok_and(|state| {
            state
                .entries
                .values()
                .any(|e| e.wiring.iter().any(|w| w.kind == REPO_WIRING_KIND))
        })
}

/// The `not_build_root` refusal detail when `project_root` is a module of a
/// Maven reactor, a project of a Gradle build or an sbt subproject of a
/// build rooted above it: vendoring
/// there would wire a build nobody runs and leave the real one unpatched
/// (#428). Ancestors are searched up to the enclosing git checkout (a
/// checkout at `project_root` itself does not stop the search: a submodule
/// can still be a module of the build above it), with the repository
/// lookup's own bounds: never into the home directory or a
/// `GIT_CEILING_DIRECTORIES` entry ([`crate::utils::repo_root`]). Like git,
/// the walk climbs the PHYSICAL parents (`project_root` canonicalized), so
/// a relative root such as `.` still has ancestors; the refusal names the
/// ancestor in the caller's own spelling of `project_root` whenever that
/// spelling reaches it ([`shown_ancestor`]).
pub(super) fn not_build_root(project_root: &Path) -> Option<String> {
    let project = super::jvm::apply::ProjectReader::new(project_root);
    let own_settings = layout::GRADLE_SETTINGS_FILES
        .iter()
        .any(|f| layout::marker_present(project_root, f));
    let own_build = layout::GRADLE_BUILD_FILES
        .iter()
        .any(|f| layout::marker_present(project_root, f));
    let canonical_root =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let ancestors = crate::utils::repo_root::ancestor_search_dirs(&canonical_root);
    let bound = crate::utils::repo_root::upward_bound(
        crate::utils::repo_root::ReadScope::Workspace,
        &canonical_root,
    );
    for ancestor in &ancestors {
        let ancestor = ancestor.as_path();
        // Above the repository root (a submodule's superproject, a
        // directory around the checkout) nothing is read: a build file
        // there may make this project a module, so it refuses.
        if let Some(bound) = bound.as_ref().filter(|b| !b.contains(ancestor)) {
            let marker = std::iter::once("pom.xml")
                .chain(layout::GRADLE_SETTINGS_FILES.iter().copied())
                .chain(["build.sbt"])
                .map(|name| ancestor.join(name))
                .find(|path| std::fs::metadata(path).is_ok());
            if let Some(marker) = marker {
                return Some(format!(
                    "reason: not_build_root: {}",
                    bound.marker_refusal(&marker)
                ));
            }
            continue;
        }
        let reader = super::jvm::apply::ProjectReader::new(ancestor);
        let rel = canonical_root
            .strip_prefix(ancestor)
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"));
        let Some(rel) = rel else { break };
        let shown = || shown_ancestor(project_root, ancestor, &canonical_root);
        if super::jvm::maven_reactor::contains_module(
            &|p| reader.read(p),
            &|d| reader.list(d),
            &format!("{rel}/pom.xml"),
        ) {
            return Some(format!(
                "reason: not_build_root: run vendor from reactor root {}",
                shown().display()
            ));
        }
        if super::jvm::sbt::nested_in_build(&|p: &str| project.read(p), &|p: &str| reader.read(p)) {
            return Some(format!(
                "reason: not_build_root: run vendor from sbt build root {}",
                shown().display()
            ));
        }
        let read_text = |p: &str| crate::gradle::dsl::decode(&reader.read(p)?);
        // Gradle reads the Groovy settings first.
        let settings = layout::GRADLE_SETTINGS_FILES
            .iter()
            .copied()
            .find(|f| reader.read(f).is_some());
        // Only a Gradle project can belong to an ancestor Gradle build.
        if let Some(settings) = settings.filter(|_| own_build || own_settings) {
            let owner = crate::gradle::graph::subproject_owner(&read_text, settings, &rel);
            // Settings that are not UTF-8 are unparseable, never "absent":
            // their includes cannot be ruled out.
            let undecodable = read_text(settings).is_none();
            // A Gradle project with no settings of its own is configured
            // by the nearest ancestor settings, whatever it includes.
            if owner.is_some() || undecodable || (own_build && !own_settings) {
                return Some(format!(
                    "reason: not_build_root: run vendor from Gradle root {}",
                    shown().display()
                ));
            }
        }
    }
    None
}

/// `ancestor` (a physical ancestor of `canonical_root`, the canonical form
/// of `project_root`) as the caller spelled it: `project_root`'s own
/// lexical ancestor the same number of levels up when that names the same
/// directory, else the canonical path without Windows' verbatim `\\?\`
/// prefix (a `.` root, or a spelling through a symlink).
fn shown_ancestor(project_root: &Path, ancestor: &Path, canonical_root: &Path) -> PathBuf {
    let levels = canonical_root
        .strip_prefix(ancestor)
        .map_or(0, |rel| rel.components().count());
    project_root
        .ancestors()
        .nth(levels)
        .filter(|logical| !logical.as_os_str().is_empty())
        .filter(|logical| std::fs::canonicalize(logical).is_ok_and(|c| c == ancestor))
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            crate::utils::pnpm_workspace::without_verbatim_prefix(ancestor.to_path_buf())
        })
}

/// Where an upstream file of a vendored GAV is looked for locally: the
/// crawler's version directory first (read directly), then every copy
/// [`locate_artifact`] finds over the cache that directory belongs to and
/// every local JVM cache of the machine.
///
/// [`locate_artifact`]: crate::crawlers::jvm_cache::locate_artifact
pub(super) struct LocalSources {
    installed_dir: Option<PathBuf>,
    roots: Vec<crate::crawlers::jvm_cache::JvmCacheRoot>,
    /// Set once an online run took a local metadata file the registry
    /// publishes no checksum for ([`acquire_jvm_artifact`]): the entry is
    /// then recorded `local_unverified`, as an offline one is.
    unverified: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LocalSources {
    /// No local copy at all (repair downloads and verifies everything).
    pub(super) fn none() -> Self {
        Self {
            installed_dir: None,
            roots: Vec::new(),
            unverified: Default::default(),
        }
    }

    /// The caches alone (never the patched GAV's own directory), for a
    /// parent's or BOM's files. Shares the [`Self::unverified`] mark.
    fn caches(&self) -> Self {
        Self {
            installed_dir: None,
            roots: self.roots.clone(),
            unverified: std::sync::Arc::clone(&self.unverified),
        }
    }

    /// Whether a file was taken from a local cache without a registry
    /// checksum to hold it to.
    fn took_unverified(&self) -> bool {
        self.unverified.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The crawler's `installed_dir` for `group_id`, its cache root and
    /// every local cache of the machine (see [`all_local_roots`]).
    ///
    /// [`all_local_roots`]: crate::crawlers::jvm_cache::all_local_roots
    fn new(project_root: &Path, installed_dir: &Path, group_id: &str) -> Self {
        use crate::crawlers::jvm_cache::{all_local_roots, JvmCacheLayout, JvmCacheRoot};
        let mut roots = Vec::new();
        if crate::crawlers::gradle_cache::is_gradle_version_dir(installed_dir) {
            if let Some(root) = installed_dir.ancestors().nth(3) {
                roots.push(JvmCacheRoot::new(
                    root.to_path_buf(),
                    JvmCacheLayout::GradleModules2,
                ));
            }
        } else if let Some(root) = installed_dir
            .ancestors()
            .nth(group_id.split('.').count() + 2)
        {
            roots.push(JvmCacheRoot::new(
                root.to_path_buf(),
                JvmCacheLayout::Maven2,
            ));
        }
        for root in all_local_roots(project_root) {
            if !roots.iter().any(|r| r.path == root.path) {
                roots.push(root);
            }
        }
        Self {
            installed_dir: Some(installed_dir.to_path_buf()),
            roots,
            unverified: Default::default(),
        }
    }

    /// The first local copy of `<a>-<v>[-<classifier>].<ext>`. A Gradle
    /// copy must hash to its hash directory, an m2 copy with a `.sha1`
    /// sidecar must match it; with `authenticated`, an m2 copy without a
    /// sidecar does not count either.
    async fn find(
        &self,
        gav: &crate::crawlers::jvm_cache::Gav,
        classifier: Option<&str>,
        ext: &str,
        authenticated: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        use crate::crawlers::jvm_cache::{locate_artifact, JvmCacheLayout};
        let (_, a, v) = gav;
        let leaf = match classifier {
            Some(c) => format!("{a}-{v}-{c}.{ext}"),
            None => format!("{a}-{v}.{ext}"),
        };
        let mut candidates: Vec<(PathBuf, JvmCacheLayout)> = Vec::new();
        if let Some(dir) = &self.installed_dir {
            candidates.push((dir.join(&leaf), JvmCacheLayout::Maven2));
        }
        for root in &self.roots {
            for path in locate_artifact(root, gav, classifier, ext) {
                if !candidates.iter().any(|(p, _)| *p == path) {
                    candidates.push((path, root.layout));
                }
            }
        }
        for (path, layout) in candidates {
            let bytes = match read_regular_to_bytes(&path).await {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("unreadable {}: {e}", path.display())),
            };
            let hash_dir = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .filter(|n| crate::crawlers::gradle_cache::is_hash_dir_name(n));
            let trusted = match (layout, hash_dir) {
                (JvmCacheLayout::GradleModules2, Some(dir)) => {
                    crate::crawlers::gradle_cache::pristine(dir, &bytes)
                }
                (JvmCacheLayout::GradleModules2, None) => false,
                _ => {
                    let sidecar = path.with_file_name(format!("{leaf}.sha1"));
                    match read_regular_to_string(&sidecar).await {
                        Ok(text) => sha1_sidecar_matches(&bytes, &text),
                        Err(_) => !authenticated,
                    }
                }
            };
            if trusted {
                return Ok(Some(bytes));
            }
        }
        // An Ivy cache keeps no `<a>-<v>.pom` beside the jar, but may hold
        // the pristine pom as `ivy-<v>.xml.original` (no checksum sidecar,
        // so it is never an authenticated copy).
        if ext == "pom" && classifier.is_none() && !authenticated {
            if let Some(dir) = &self.installed_dir {
                let (g, a, v) = gav;
                if let Some(bytes) = crate::crawlers::ivy_cache::installed_pom(dir, g, a, v) {
                    return Ok(Some(bytes));
                }
            }
        }
        Ok(None)
    }
}

/// The vendored refusals and sbt / scala-cli gate for `purl` over the
/// project at `project_root`, for a caller about to restore a hosted pin
/// upstream (a takeover or an eject) before vendoring: `Err((code,
/// detail))` when [`vendor_maven`] would stop the patch before writing
/// anything (`not_build_root`, `legacy_maven_root`, or a gate skip or
/// refusal), so the caller keeps the hosted wiring instead of ending
/// neither hosted nor vendored. `Ok` for any other project or a non-Maven
/// purl.
pub async fn jvm_gate_preflight(
    project_root: &Path,
    purl: &str,
) -> Result<(), (&'static str, String)> {
    let Some((g, a, v)) = parse_maven_purl(purl) else {
        return Ok(());
    };
    if let Some(detail) = not_build_root(project_root) {
        return Err(("vendor_jvm_shape_unsupported", detail));
    }
    if legacy_root(project_root).await {
        return Err(("vendor_jvm_shape_unsupported", legacy_root_detail()));
    }
    let shape = detect_shape(project_root);
    let selection = maven_selection(shape, project_root, None).await;
    super::jvm::sbt_gate::for_shape(shape, project_root, &g, &a, &v, selection)
        .map_err(|stop| stop.code_and_detail(purl))?;
    // Checked here too, so a hosted->vendored takeover keeps its pin
    // instead of restoring upstream and then refusing (#1061).
    match ignored_tree_root(shape, project_root).await {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// The `vendor_artifact_gitignored` refusal when git ignores a tree root
/// `shape` writes into. Each tree root owns a `!*` `.gitignore` that
/// re-includes file rules such as Java.gitignore's `*.jar` (#1061), but a
/// rule ignoring the root itself (`.socket/`) can't be undone from inside.
async fn ignored_tree_root(
    shape: super::jvm::Shape,
    project_root: &Path,
) -> Option<(&'static str, String)> {
    for tree in super::jvm::shape_trees(shape) {
        if let Some(refusal) = super::npm_dir::ignored_root_refusal(project_root, tree).await {
            return Some(refusal);
        }
    }
    None
}

/// The committed tree bytes for `record` (jar, upstream pom, module, and
/// the classifier artifacts) when the jar's patched members hash to the
/// record's `afterHash`es: a re-run then needs no jar source at all (the
/// in-sync hot path). A mixed root needs both trees in sync.
async fn jvm_committed_patch(
    shape: super::jvm::Shape,
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<(super::jvm::CommittedTree, Vec<super::jvm::ExtraArtifact>)> {
    use super::jvm::Shape;
    let (g, a, v) = parse_maven_purl(purl)?;
    let coords = super::jvm::Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &record.uuid,
    };
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    let read = |rel: &str| reader.read(rel);
    let trees: Vec<(String, String)> = match shape {
        Shape::MavenReactor => vec![(
            super::jvm::maven_reactor::tree_dir(&coords),
            coords.suffixed_version(),
        )],
        Shape::Gradle => vec![(super::jvm::gradle::tree_dir(&coords), v.to_string())],
        Shape::Mixed => vec![
            (
                super::jvm::maven_reactor::tree_dir(&coords),
                coords.suffixed_version(),
            ),
            (super::jvm::gradle::tree_dir(&coords), v.to_string()),
        ],
        Shape::Sbt => vec![(
            super::jvm::sbt::tree_dir(&coords),
            coords.suffixed_version(),
        )],
        Shape::ScalaCli => vec![(super::jvm::coursier_tree::tree_dir(&coords), v.to_string())],
        Shape::Other => return None,
    };
    for (dir, tree_version) in &trees {
        let marker: serde_json::Value =
            serde_json::from_slice(&read(&format!("{dir}/{}", layout::MARKER_FILE))?).ok()?;
        if marker.get("uuid")?.as_str()? != record.uuid {
            return None;
        }
        let files = marker.get("files")?.as_object()?;
        for ext in ["jar", "pom"] {
            files.get(&format!("{a}-{tree_version}.{ext}"))?;
        }
        for (name, file) in files {
            if name.contains('/') || name.contains('\\') || name == ".." {
                return None;
            }
            let bytes = read(&format!("{dir}/{name}"))?;
            if file.get("sha256")?.as_str()? != super::jvm::sha256_hex(&bytes) {
                return None;
            }
        }
    }
    let (committed, extras) = match shape {
        Shape::MavenReactor => (
            super::jvm::maven_reactor::committed(&read, &coords)
                .map(|(jar, pom)| (jar, pom, None))?,
            Vec::new(),
        ),
        Shape::Sbt => (super::jvm::sbt::committed(&read, &coords)?, Vec::new()),
        Shape::ScalaCli => (
            super::jvm::scala_cli::committed(&read, &coords)?,
            Vec::new(),
        ),
        _ => (
            super::jvm::gradle::committed(&read, &coords)?,
            super::jvm::gradle::committed_extras(&read, &coords)?,
        ),
    };
    (!record.files.is_empty() && zip_bytes_match_after_hashes(&committed.0, &record.files))
        .then_some((committed, extras))
}

/// What Maven selects in each module of a Maven root, read off the async
/// runtime (the walk reads a pom per artifact of the build) over the local
/// repository `repo`, or the one this process resolves against. `None` for
/// any other shape.
async fn maven_selection(
    shape: super::jvm::Shape,
    project_root: &Path,
    repo: Option<&Path>,
) -> Option<crate::crawlers::maven_selection::MavenSelection> {
    use crate::crawlers::maven_selection::MavenSelection;
    if !matches!(
        shape,
        super::jvm::Shape::MavenReactor | super::jvm::Shape::Mixed
    ) {
        return None;
    }
    let (root, repo) = (project_root.to_path_buf(), repo.map(Path::to_path_buf));
    tokio::task::spawn_blocking(move || MavenSelection::for_project_in(&root, repo.as_deref()))
        .await
        .ok()
}

/// A patch the gate skipped because no module selects its base version
/// may still be pinned by an earlier run (the build has moved on since: a
/// dependency was added or upgraded). That pin keeps forcing the version
/// Maven no longer selects, so it is taken out of the poms here and the
/// skip says so; any other outcome is returned as it is.
async fn unpin_unselected(
    outcome: VendorOutcome,
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
    dry_run: bool,
) -> VendorOutcome {
    let VendorOutcome::Refused { code, detail } = outcome else {
        return outcome;
    };
    let keep = |detail: String| VendorOutcome::Refused { code, detail };
    if code != super::jvm::sbt_gate::MAVEN_NOT_SELECTED {
        return keep(detail);
    }
    let Some((g, a, v)) = parse_maven_purl(purl) else {
        return keep(detail);
    };
    let coords = super::jvm::Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &record.uuid,
    };
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    let plan = super::jvm::maven_reactor::unpin_plan(
        &|rel| reader.read(rel),
        &|dir| reader.list(dir),
        &coords,
    );
    let Some(plan) = plan.filter(|_| reader.escaped().is_none()) else {
        return keep(detail);
    };
    let poms: Vec<&str> = plan.writes.iter().map(|w| w.rel.as_str()).collect();
    let poms = poms.join(", ");
    if dry_run {
        return keep(format!(
            "{detail}; the pin an earlier run wrote in {poms} still forces {v} and would be removed"
        ));
    }
    match super::jvm::apply::write_plan(project_root, &plan).await {
        Ok(_) => keep(format!(
            "{detail}; the pin an earlier run wrote in {poms} still forced {v} and was removed (`socket-patch vendor --revert` or `scan --mode vendored --prune` drops the vendored copy it pointed at)"
        )),
        Err(e) => keep(format!(
            "{detail}; the pin an earlier run wrote in {poms} still forces {v} and could not be removed ({e}): run `socket-patch vendor --revert`"
        )),
    }
}

/// The Maven-layout repository `installed_dir` is a version directory of
/// (`<root>/<group path>/<artifact>/<version>`), when it is one: the local
/// repository the installed copy of `purl` was found in, which holds the
/// poms of the build that resolved it.
fn maven2_root(installed_dir: &Path, purl: &str) -> Option<PathBuf> {
    let (g, a, v) = parse_maven_purl(purl)?;
    let mut dir = installed_dir;
    for part in [v.as_ref(), a.as_ref()].into_iter().chain(g.rsplit('.')) {
        if dir.file_name()?.to_str()? != part {
            return None;
        }
        dir = dir.parent()?;
    }
    dir.is_dir().then(|| dir.to_path_buf())
}

/// What [`vendor_maven_jvm`] establishes before anything else: the
/// coordinates, the ledger, and the sbt / scala-cli resolution gate's pass.
struct JvmPrelude {
    group_id: String,
    artifact_id: String,
    version: String,
    state: super::state::VendorState,
    gate_pass: super::jvm::sbt_gate::ShapePass,
}

/// Every refusal and skip [`vendor_maven_jvm`] raises before it can first
/// ask the patch service (bar the empty patch's no-op and the committed
/// tree's hot path), so its download plan ([`service_preflight`]) grants
/// nothing the vendor loop then stops short of.
async fn jvm_prelude(
    shape: super::jvm::Shape,
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
    maven_repo: Option<&Path>,
) -> Result<JvmPrelude, VendorOutcome> {
    let Some((group_id, artifact_id, version)) = parse_maven_purl(purl) else {
        return Err(refused(
            "unsafe_coordinates",
            format!("not a maven purl: {purl}"),
        ));
    };
    let (group_id, artifact_id, version) = (
        group_id.to_string(),
        artifact_id.to_string(),
        version.to_string(),
    );
    if vendor_uuid_dir_rel("maven", &record.uuid).is_none() {
        return Err(refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        ));
    }
    if !layout::safe_coordinates(&group_id, &artifact_id, &version) {
        return Err(refused(
            "unsafe_coordinates",
            format!("unsafe maven coordinates `{group_id}:{artifact_id}` @ `{version}`"),
        ));
    }
    let state = super::state::load_state(project_root)
        .await
        .map_err(|e| refused("vendor_state_unreadable", e.to_string()))?;
    // sbt / scala-cli pins are gated on the build's own resolution first.
    let selection = maven_selection(shape, project_root, maven_repo).await;
    let gate_pass = super::jvm::sbt_gate::for_shape(
        shape,
        project_root,
        &group_id,
        &artifact_id,
        &version,
        selection,
    )
    .map_err(|stop| stop.into_outcome(purl))?;
    // The tree must survive the commit the vendored workflow ends with.
    if let Some((code, detail)) = ignored_tree_root(shape, project_root).await {
        return Err(refused(code, detail));
    }
    Ok(JvmPrelude {
        group_id,
        artifact_id,
        version,
        state,
        gate_pass,
    })
}

/// Vendor into a multi-module reactor, a Gradle build or a mixed root
/// through the [`super::jvm`] backend. The jar and pom come from the
/// committed tree when it already holds this patch, otherwise from the
/// service and authenticated upstream metadata; nothing is written for a
/// refused plan.
#[allow(clippy::too_many_arguments)]
async fn vendor_maven_jvm(
    shape: super::jvm::Shape,
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    dry_run: bool,
    _force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    use super::jvm::Shape;
    let JvmPrelude {
        group_id,
        artifact_id,
        version,
        state,
        gate_pass,
    } = match jvm_prelude(
        shape,
        purl,
        project_root,
        record,
        maven2_root(installed_dir, purl).as_deref(),
    )
    .await
    {
        Ok(prelude) => prelude,
        Err(outcome) => {
            return unpin_unselected(outcome, purl, project_root, record, dry_run).await
        }
    };
    let state = Some(state);
    let gradle = matches!(shape, Shape::Gradle | Shape::Mixed);
    let display_path = project_root.join(".socket/vendor");
    if record.files.is_empty() {
        let reader = super::jvm::apply::ProjectReader::new(project_root);
        let probe_pom = format!("<project><groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId><version>{version}</version></project>");
        let patch = super::jvm::JvmPatch {
            group_id: &group_id,
            artifact_id: &artifact_id,
            version: &version,
            uuid: &record.uuid,
            jar: &[],
            upstream_pom: probe_pom.as_bytes(),
            upstream_parents: None,
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        };
        let plan = super::jvm::plan_with_selection(
            shape,
            &|rel| reader.read(rel),
            &|dir| reader.list(dir),
            &patch,
            true,
            None,
            gate_pass.maven.as_ref(),
        );
        if let Some(rel) = reader.escaped() {
            return refused(
                "vendor_jvm_shape_unsupported",
                super::jvm::apply::outside_root_detail(&rel),
            );
        }
        // A declared classifier is sourced only for a real patch.
        match plan {
            Err(e) if !e.detail.starts_with("reason: classifier_unavailable:") => {
                return refused(e.code, e.detail);
            }
            Ok(plan) if matches!(shape, Shape::MavenReactor | Shape::Mixed) => {
                let read = |rel: &str| reader.read(rel);
                let list = |dir: &str| reader.list(dir);
                if let Err(e) =
                    super::jvm::maven_reactor::refuse_unwired(&read, &list, &patch.coords(), &plan)
                {
                    return super::jvm::sbt_gate::maven_undetermined(
                        gate_pass.maven.as_ref(),
                        &plan,
                        &group_id,
                        &artifact_id,
                        &version,
                    )
                    .unwrap_or_else(|| refused(e.code, e.detail));
                }
            }
            _ => {}
        }
        return done(
            synthesized_result(purl, &display_path, Vec::new(), true, None),
            None,
            Vec::new(),
        );
    }

    let local = LocalSources::new(project_root, installed_dir, &group_id);
    let gav = (group_id.clone(), artifact_id.clone(), version.clone());
    let selection = gate_pass.maven;
    let mut warnings: Vec<VendorWarning> = gate_pass.warnings;
    let committed = jvm_committed_patch(shape, purl, project_root, record).await;
    let was_committed = committed.is_some();
    let (mut jar_bytes, mut pom_bytes, mut module_bytes, mut extras, mut result) = match committed {
        Some(((jar, pom, module), extras)) => (
            jar,
            pom,
            module,
            Some(extras),
            already_patched_result(purl, &display_path, &record.files),
        ),
        None => {
            let (jar, result) =
                match service_archive_copy(service, record, &artifact_id, ".jar", &mut warnings)
                    .await
                {
                    Ok(bytes) => (
                        bytes,
                        already_patched_result(purl, &display_path, &record.files),
                    ),
                    Err(outcome) => return *outcome,
                };
            if !result.success {
                return done(result, None, warnings);
            }
            let pom = match acquire_jvm_artifact(&local, &gav, None, "pom", service).await {
                Ok(bytes) => bytes,
                Err(detail) => {
                    return refused(
                        "vendor_jvm_upstream_unavailable",
                        format!("reason: pom_unavailable: {detail}"),
                    )
                }
            };
            let module = local.find(&gav, None, "module", false).await.ok().flatten();
            (jar, pom, module, None, result)
        }
    };

    let online = service.is_some_and(|s| !s.offline);
    // The jar is the patch service's, checked as it was served (transfer
    // integrity, the record's members at their `afterHash`), or the
    // committed one. No copy of the original is fetched to hold it to:
    // vendoring needs the patch service and this machine, not the registry.
    //
    // One comparison costs no network and protects the build. When the
    // original jar is already in the build's local repository, the members
    // the patch does not touch must be that jar's, as agent mode requires
    // before a swap. A difference means the project builds with a jar that
    // is not the one the patch was made from (an internal rebuild under the
    // same coordinates, say), and the service's jar would change more than
    // the patch. With no local copy there is nothing to compare, and
    // nothing to say. (An offline re-run compares nothing, as before.)
    if !was_committed || online {
        if let Ok(Some(resolved)) = local.find(&gav, None, "jar", false).await {
            let files = record.files.clone();
            let leaf = layout::file_name(&artifact_id, &version, None, "jar");
            // Off the async workers: a pass inflates up to the jar limits.
            let compared = tokio::task::spawn_blocking(move || {
                let verdict = verify_unpatched_jar_members(
                    (&leaf, &resolved),
                    &jar_bytes,
                    &files,
                    was_committed,
                );
                (jar_bytes, verdict)
            })
            .await;
            let Ok((bytes, verdict)) = compared else {
                return refused(
                    "vendor_prebuilt_integrity_mismatch",
                    "the comparison with the local repository's jar did not finish".to_string(),
                );
            };
            jar_bytes = bytes;
            if let Err((code, detail)) = verdict {
                return refused(code, detail);
            }
        }
    }
    if online && was_committed {
        pom_bytes = match acquire_jvm_artifact(&local, &gav, None, "pom", service).await {
            Ok(bytes) => bytes,
            Err(e) => return refused("vendor_jvm_upstream_unavailable", e),
        };
    }
    if gradle
        && (module_bytes.is_some()
            || String::from_utf8_lossy(&pom_bytes).contains("published-with-gradle-metadata"))
        && (module_bytes.is_none() || online)
    {
        module_bytes = match acquire_jvm_artifact(&local, &gav, None, "module", service).await {
            Ok(bytes) => Some(bytes),
            Err(e) => return refused("vendor_jvm_upstream_unavailable", e),
        };
    }
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    let read = |rel: &str| reader.read(rel);
    let list = |dir: &str| reader.list(dir);
    // Classifier artifacts the tree serves beside the jar (#533): every
    // declared classifier, and the sources jar when any copy is at hand.
    if gradle && (extras.is_none() || online) {
        let committed = extras.take().unwrap_or_default();
        let mut found = Vec::new();
        let declared =
            super::jvm::gradle::declared_classifiers(&read, &list, &group_id, &artifact_id);
        let mut wanted: Vec<(String, bool)> = declared.into_iter().map(|c| (c, true)).collect();
        if !wanted.iter().any(|(c, _)| c == "sources") {
            wanted.push(("sources".to_string(), false));
        }
        for (classifier, required) in wanted {
            match acquire_classifier(&local, &gav, &classifier, service).await {
                Ok(Some(bytes)) => found.push(super::jvm::ExtraArtifact {
                    classifier,
                    extension: "jar".to_string(),
                    bytes,
                }),
                // The planner refuses a declared one it is not handed (a
                // committed copy is kept below).
                Ok(None) => {}
                Err(e) if required => {
                    return refused(
                        "vendor_jvm_upstream_unavailable",
                        format!("reason: classifier_unavailable: {e}"),
                    )
                }
                Err(_) => {}
            }
        }
        // A classifier the committed tree already serves stays (the re-run
        // checked its hash against the marker): dropping it would leave an
        // unindexed file the script refuses.
        for x in committed {
            if !found.iter().any(|f| f.classifier == x.classifier) {
                found.push(x);
            }
        }
        if !found.iter().any(|x| x.classifier == "sources") {
            warnings.push(VendorWarning::new(
                super::jvm::gradle::NOTE,
                format!(
                    "reason: ide_sources_unavailable: {artifact_id}-{version}-sources.jar is in \
                     no local cache{}, so IDEs attach no sources to the vendored \
                     {group_id}:{artifact_id}:{version}",
                    if online {
                        " and the registry has none"
                    } else {
                        ""
                    }
                ),
            ));
        }
        extras = Some(found);
    }
    let extras = extras.unwrap_or_default();
    let patched: Vec<String> = record.files.keys().cloned().collect();
    // A suffixed pom is written against its upstream parents: Maven reads
    // a `${project.version}` of theirs as the suffixed version.
    let parents = if matches!(shape, Shape::MavenReactor | Shape::Mixed | Shape::Sbt) {
        match upstream_parent_chain(&pom_bytes, &local, service).await {
            Ok(chain) => Some(chain),
            // A committed tree re-planned offline keeps the pom it has: its
            // parents may be in no cache of this machine.
            Err(_) if was_committed && !online => None,
            Err(e) => {
                let suffixed = super::jvm::Coords {
                    group_id: &group_id,
                    artifact_id: &artifact_id,
                    version: &version,
                    uuid: &record.uuid,
                }
                .suffixed_version();
                return refused(
                    "vendor_jvm_upstream_unavailable",
                    format!(
                        "reason: parent_unavailable: {e}, so whether \
                         {group_id}:{artifact_id}:{suffixed} would resolve the versions \
                         {group_id}:{artifact_id}:{version} does cannot be checked{}",
                        if online {
                            ""
                        } else {
                            " (vendoring is offline: resolve the project once, or vendor online)"
                        }
                    ),
                );
            }
        }
    } else {
        None
    };
    let patch = super::jvm::JvmPatch {
        group_id: &group_id,
        artifact_id: &artifact_id,
        version: &version,
        uuid: &record.uuid,
        jar: &jar_bytes,
        upstream_pom: &pom_bytes,
        upstream_parents: parents.as_deref(),
        upstream_module: module_bytes.as_deref(),
        extra_artifacts: &extras,
        patched_members: &patched,
    };
    let prior_disabled = state.as_ref().is_some_and(|s| {
        s.entries.values().any(|e| {
            e.wiring
                .iter()
                .any(|w| super::jvm::op_of(w) == "config_none")
        })
    });
    let config_enabled = service
        .and_then(|s| s.maven_config)
        .unwrap_or(!prior_disabled);
    if !config_enabled
        && state.as_ref().is_some_and(|s| {
            s.entries.values().any(|e| {
                e.wiring.iter().any(|w| {
                    w.kind == super::jvm::CONFIG_LINE_KIND && super::jvm::op_of(w) == "config"
                })
            })
        })
    {
        return refused("vendor_jvm_shape_unsupported", "reason: maven_config_changed: revert the existing Maven wiring before selecting --maven-config=none");
    }
    let planned = match shape {
        // The pin records the gate's digest (every build source).
        Shape::Sbt => super::jvm::sbt::plan_with_digest(
            &read,
            &list,
            &patch,
            gate_pass.deps_digest.as_deref(),
        ),
        Shape::MavenReactor | Shape::Mixed => {
            let external = external_maven_poms(&read, &list, &patch, &local, service).await;
            super::jvm::plan_with_selection(
                shape,
                &read,
                &list,
                &patch,
                config_enabled,
                Some(&external),
                selection.as_ref(),
            )
        }
        _ => super::jvm::plan_with_config(shape, &read, &list, &patch, config_enabled),
    };
    if let Some(rel) = reader.escaped() {
        return refused(
            "vendor_jvm_shape_unsupported",
            super::jvm::apply::outside_root_detail(&rel),
        );
    }
    let mut plan = match planned {
        Ok(plan) => plan,
        Err(refusal) => return refused(refusal.code, refusal.detail),
    };
    if matches!(shape, Shape::MavenReactor | Shape::Mixed) {
        if let Err(refusal) =
            super::jvm::maven_reactor::refuse_unwired(&read, &list, &patch.coords(), &plan)
        {
            // Nothing names the base version to rewrite, and what the build
            // selects cannot be told: nothing is pinned on a guess.
            return super::jvm::sbt_gate::maven_undetermined(
                selection.as_ref(),
                &plan,
                &group_id,
                &artifact_id,
                &version,
            )
            .unwrap_or_else(|| refused(refusal.code, refusal.detail));
        }
    }
    if gradle
        && reader
            .read(super::jvm::gradle::VERIFICATION_REL)
            .is_some_and(|b| super::jvm::gradle::verifies_metadata(&String::from_utf8_lossy(&b)))
    {
        // An in-sync run can reuse the already recorded metadata edits offline.
        let previous = state.as_ref().and_then(|s| {
            s.entries.values().find(|e| {
                e.uuid == record.uuid
                    && e.base_purl == build_maven_purl(&group_id, &artifact_id, &version)
            })
        });
        let metadata_records: Vec<_> = previous
            .into_iter()
            .flat_map(|e| &e.wiring)
            .filter(|w| {
                w.kind == super::jvm::VERIFICATION_FRAGMENT_KIND
                    && w.key.as_deref().is_some_and(|k| k.starts_with("metadata:"))
            })
            .cloned()
            .collect();
        let text = reader
            .read(super::jvm::gradle::VERIFICATION_REL)
            .unwrap_or_default();
        let reusable = !online
            && !metadata_records.is_empty()
            && metadata_records.iter().all(|w| {
                super::jvm::gradle::metadata_record_present(&String::from_utf8_lossy(&text), w)
            });
        if reusable {
            plan.records.extend(metadata_records);
            plan.warnings.retain(|w| {
                !w.detail
                    .starts_with("reason: verification_parent_chain_unhandled:")
            });
        } else {
            let mut metadata = vec![super::jvm::gradle::MetadataArtifact {
                group: group_id.clone(),
                artifact: artifact_id.clone(),
                version: version.clone(),
                extension: "pom",
                bytes: pom_bytes.clone(),
            }];
            if let Some(module) = &module_bytes {
                metadata.push(super::jvm::gradle::MetadataArtifact {
                    group: group_id.clone(),
                    artifact: artifact_id.clone(),
                    version: version.clone(),
                    extension: "module",
                    bytes: module.clone(),
                });
            }
            // Gradle verifies both the parent's standalone model and the
            // child's effective imports, which can select different BOM versions.
            for propagate_properties in [false, true] {
                if let Err(e) = collect_gradle_metadata(
                    &pom_bytes,
                    &local,
                    service,
                    &mut metadata,
                    0,
                    &std::collections::BTreeMap::new(),
                    propagate_properties,
                )
                .await
                {
                    return refused(
                        "vendor_jvm_upstream_unavailable",
                        format!("reason: verification_metadata_unavailable: {e}"),
                    );
                }
            }
            if let Err(e) =
                super::jvm::gradle::add_verification_metadata(&read, &mut plan, &metadata)
            {
                return refused(e.code, e.detail);
            }
        }
    }
    let previous = state.as_ref().and_then(|s| {
        s.entries.values().find(|e| {
            e.uuid == record.uuid
                && e.base_purl == build_maven_purl(&group_id, &artifact_id, &version)
        })
    });
    let prior_verified = previous.is_some_and(|e| !super::jvm::apply::upstream_unverified(e));
    let registry_verified =
        (online && !local.took_unverified()) || (was_committed && prior_verified);
    plan.records.push(WiringRecord {file: plan.jar_rel.clone(), kind: super::jvm::UPSTREAM_KIND.into(), action: WiringAction::Added, key: Some("upstream".into()), original: None, new: Some(serde_json::json!({"op": if registry_verified {"registry_verified"} else {"local_unverified"}}))});
    warnings.extend(
        plan.warnings
            .iter()
            .map(|w| VendorWarning::new(w.code, w.detail.clone())),
    );
    let jar_path = project_root.join(&plan.jar_rel);
    result.package_path = jar_path.display().to_string();
    // Anything else in the tree fails the build and `vendor --check`
    // (#656), so it is drift a re-vendor sweeps.
    let indexed: std::collections::BTreeSet<String> = plan
        .tree_files
        .iter()
        .map(|(rel, _)| rel.clone())
        .chain(plan.writes.iter().filter(|w| w.tree).map(|w| w.rel.clone()))
        .collect();
    // A file the committed ledger still records is not a stray: this sweep
    // runs before the commit, so deleting it here would outlive a refused
    // or rolled-back write. A patch update's dropped files go after the
    // commit, through `sweep_replaced_tree`.
    let recorded: std::collections::BTreeSet<String> = state
        .iter()
        .flat_map(|s| s.entries.values())
        .filter(|e| super::jvm::apply::is_jvm_entry(e))
        .flat_map(super::jvm::apply::recorded_tree_files)
        .collect();
    let unindexed = match super::jvm::apply::unindexed_tree_entries(project_root, &indexed)
        .map(|found| {
            found
                .into_iter()
                .filter(|s| !recorded.contains(&s.rel))
                .collect::<Vec<_>>()
        })
        .and_then(|found| super::jvm::apply::refuse_linked(&found).map(|()| found))
    {
        Ok(found) => found,
        Err(e) => return done(failed_result(purl, &jar_path, e), None, warnings),
    };
    if plan.writes.is_empty()
        && unindexed.is_empty()
        && (previous.is_none() || registry_verified == prior_verified)
    {
        // Notes describe what a vendoring did; an in-sync run did nothing.
        warnings.retain(|w| w.code != super::jvm::gradle::NOTE);
        return done(
            already_patched_result(purl, &jar_path, &record.files),
            None,
            warnings,
        );
    }
    if dry_run {
        return done(
            super::common::preview_result(purl, &jar_path, &record.files),
            None,
            warnings,
        );
    }
    // Before any wiring is written, so a stray that cannot go leaves
    // nothing half-done.
    if let Err(e) = super::jvm::apply::sweep_unindexed(&unindexed).await {
        return done(failed_result(purl, &jar_path, e), None, warnings);
    }
    let mut wiring = match super::jvm::apply::write_plan(project_root, &plan).await {
        Ok(records) => records,
        Err(e) => return done(failed_result(purl, &jar_path, e), None, warnings),
    };
    // Shared fragments another JVM entry wrote, and the pristine originals
    // of a patch update, come from the ledger.
    if let Some(state) = &state {
        super::jvm::apply::inherit_peer_records(&mut wiring, state.entries.values());
    }
    let mut entry = maven_entry(
        build_maven_purl(&group_id, &artifact_id, &version),
        record,
        plan.jar_rel.clone(),
        &jar_bytes,
        wiring,
    );
    entry.ecosystem = layout::LEDGER_ECOSYSTEM.to_string();
    done(result, Some(entry), warnings)
}

/// A classifier jar of `gav`: an authenticated local copy, else (online) a
/// registry download checked against its upstream checksum. `Ok(None)` when
/// it exists nowhere (offline: in no local cache; online: the registry
/// does not publish it).
async fn acquire_classifier(
    local: &LocalSources,
    gav: &crate::crawlers::jvm_cache::Gav,
    classifier: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<Option<Vec<u8>>, String> {
    let (g, a, v) = gav;
    let leaf = layout::file_name(a, v, Some(classifier), "jar");
    let local_copy = local.find(gav, Some(classifier), "jar", true).await?;
    let online = service.is_some_and(|s| !s.offline);
    let bytes = match local_copy {
        Some(bytes) => bytes,
        None if online => {
            let url = layout::registry_url(g, a, v, Some(classifier), "jar");
            match fetch_registry_bytes(&url, super::registry_fetch::MAX_DOWNLOAD_BYTES).await {
                Ok(bytes) => bytes,
                Err(e) if e.contains("HTTP 404") => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        None => {
            return Err(format!(
                "{leaf} is in no local cache with a verifiable checksum and vendoring is offline"
            ))
        }
    };
    verify_jvm_upstream(&bytes, g, a, v, &format!("{classifier}.jar"), service).await?;
    Ok(Some(bytes))
}

/// The patched jar (the service's on a first vendoring, the committed one
/// on a re-run) against `resolved`, the jar `(leaf, bytes)` the build
/// resolves from its local repository: outside the record `files` and
/// signature files, every member a JVM would load must be the same in both
/// ([`crate::patch::jar_members`], whose limits also bound the read). For a
/// jar the service signed again, the manifest may differ as that signing
/// leaves it: digest lines changed or added, and sections added for
/// entries it did not list ([`crate::patch::jar_manifest`]). A local jar
/// that cannot be read gives nothing to compare with. `Err` is the
/// refusal's `(code, detail)`.
fn verify_unpatched_jar_members(
    resolved: (&str, &[u8]),
    patched: &[u8],
    files: &std::collections::HashMap<String, crate::manifest::schema::PatchFileInfo>,
    committed: bool,
) -> Result<(), (&'static str, String)> {
    use crate::patch::jar_members::{difference_outside_patch, Digests, JarError};
    let whose = if committed {
        "the committed jar"
    } else {
        "the patch service's jar"
    };
    // A jar past a limit is too large, whichever read met the limit; it is
    // never reported as a jar that differs.
    let unread = |e: JarError| match e {
        JarError::TooLarge(why) => (
            super::verify::ARTIFACT_TOO_LARGE,
            format!("{whose} cannot be checked: {why}"),
        ),
        JarError::Unreadable(why) => (
            "vendor_prebuilt_integrity_mismatch",
            format!("{whose} cannot be read: {why}"),
        ),
    };
    let candidate = Digests::of_bytes(patched).map_err(unread)?;
    let Ok(original) = Digests::of_bytes(resolved.1) else {
        return Ok(());
    };
    let difference =
        difference_outside_patch((resolved.1, &original), (patched, &candidate), files)
            .map_err(unread)?;
    if !difference.is_empty() {
        return Err((
            "vendor_prebuilt_integrity_mismatch",
            format!(
                "{whose} differs from {}, the jar this build resolves from its local \
                 repository, outside the patched members: {}. The build uses a jar that is not \
                 the one the patch was made from, so the vendored jar would change more than \
                 the patch",
                resolved.0,
                difference.describe()
            ),
        ));
    }
    Ok(())
}

/// What the registry's sidecars say of an upstream file.
enum UpstreamCheck {
    /// They match its bytes (or vendoring is offline and none is asked).
    Verified,
    /// The registry gave no checksum for it: why.
    Unpublished(String),
}

/// Check registry sidecars independently of any checksum in the local
/// cache. `ext` is the leaf's tail after `<a>-<v>` (`jar`, `pom`, a
/// classifier's `tests.jar` is spelled `-tests.jar` there).
async fn verify_jvm_upstream(
    bytes: &[u8],
    g: &str,
    a: &str,
    v: &str,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<(), String> {
    match check_jvm_upstream(bytes, g, a, v, ext, service).await? {
        UpstreamCheck::Verified => Ok(()),
        UpstreamCheck::Unpublished(why) => Err(why),
    }
}

/// [`verify_jvm_upstream`] telling a file the registry has no checksum for
/// (it does not serve the file, or cannot be reached) from one whose bytes
/// differ from the checksum it publishes, which is the `Err`.
async fn check_jvm_upstream(
    bytes: &[u8],
    g: &str,
    a: &str,
    v: &str,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<UpstreamCheck, String> {
    if service.is_none_or(|s| s.offline) {
        return Ok(UpstreamCheck::Verified);
    }
    // `tests.jar` is the `tests` classifier's jar.
    let tail = match ext.split_once('.') {
        Some((classifier, ext)) => format!("-{classifier}.{ext}"),
        None => format!(".{ext}"),
    };
    let url = format!(
        "{}/{}/{a}-{v}{tail}",
        layout::registry_base(),
        layout::version_dir(g, a, v)
    );
    check_published_checksum(bytes, &url, &format!("{g}:{a}:{v}{tail}")).await
}

/// `bytes` against the checksum the registry publishes beside the file at
/// `url` (`.sha512`, else `.sha1`). `what` names the file in the mismatch.
async fn check_published_checksum(
    bytes: &[u8],
    url: &str,
    what: &str,
) -> Result<UpstreamCheck, String> {
    use sha2::Digest;
    let (checksum, actual) = match fetch_pom_bytes(&format!("{url}.sha512")).await {
        Ok(sum) => (sum, hex::encode(sha2::Sha512::digest(bytes))),
        Err(_) => match fetch_pom_bytes(&format!("{url}.sha1")).await {
            Ok(sum) => (sum, sha1_hex(bytes)),
            Err(why) => return Ok(UpstreamCheck::Unpublished(why)),
        },
    };
    let expected = std::str::from_utf8(&checksum)
        .map_err(|_| "upstream checksum is not UTF-8")?
        .split_whitespace()
        .next()
        .ok_or("upstream checksum is empty")?;
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(format!("upstream checksum mismatch for {what}"));
    }
    Ok(UpstreamCheck::Verified)
}

/// The file `leaf` of `g:a:v` as the registry serves it, taken only when
/// its bytes match the checksum the registry publishes beside it. `Err`
/// says which of the two was missing.
pub(crate) async fn verified_registry_file(
    g: &str,
    a: &str,
    v: &str,
    leaf: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "{}/{}/{leaf}",
        layout::registry_base(),
        layout::version_dir(g, a, v)
    );
    let upstream = fetch_registry_bytes(&url, super::registry_fetch::MAX_DOWNLOAD_BYTES).await;
    let bytes = upstream.map_err(|e| format!("the registry did not serve it ({e})"))?;
    match check_published_checksum(&bytes, &url, &format!("{g}:{a}:{v} ({leaf})")).await {
        Ok(UpstreamCheck::Verified) => Ok(bytes),
        Ok(UpstreamCheck::Unpublished(why)) => {
            Err(format!("the registry publishes no checksum for it ({why})"))
        }
        Err(why) => Err(format!(
            "the download does not match the registry's checksum ({why})"
        )),
    }
}

/// One upstream file of `gav` (`classifier`, `ext`): a local copy (see
/// [`LocalSources::find`]), else a registry download when the service is
/// online; online, the bytes are checked against the registry's checksum
/// either way. A local pom or module the registry has no checksum for is
/// still the file the build resolved (a parent or BOM from a corporate
/// repository is on no public registry): it is used, and the run is marked
/// [`LocalSources::took_unverified`]. Bytes that differ from a published
/// checksum are refused.
pub(super) async fn acquire_jvm_artifact(
    local: &LocalSources,
    gav: &crate::crawlers::jvm_cache::Gav,
    classifier: Option<&str>,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<u8>, String> {
    let (g, a, v) = gav;
    let leaf = layout::file_name(a, v, classifier, ext);
    let (bytes, cached) = match local.find(gav, classifier, ext, false).await? {
        Some(bytes) => (bytes, true),
        None if service.is_some_and(|s| !s.offline) => {
            let bytes = fetch_registry_bytes(
                &layout::registry_url(g, a, v, classifier, ext),
                if ext == "jar" {
                    super::registry_fetch::MAX_DOWNLOAD_BYTES
                } else {
                    MAX_POM_BYTES as u64
                },
            )
            .await?;
            (bytes, false)
        }
        None => {
            return Err(format!(
                "upstream {g}:{a}:{v}{} unavailable: in no local cache",
                &leaf[a.len() + v.len() + 1..]
            ))
        }
    };
    let tail = match classifier {
        Some(c) => format!("{c}.{ext}"),
        None => ext.to_string(),
    };
    match check_jvm_upstream(&bytes, g, a, v, &tail, service).await? {
        UpstreamCheck::Verified => {}
        UpstreamCheck::Unpublished(_) if cached && matches!(ext, "pom" | "module") => local
            .unverified
            .store(true, std::sync::atomic::Ordering::Relaxed),
        UpstreamCheck::Unpublished(why) => return Err(why),
    }
    Ok(bytes)
}

/// [`acquire_jvm_artifact`] of a metadata file from `dir` alone (or the
/// registry), for callers with no local caches.
pub(super) async fn acquire_jvm_metadata(
    dir: &Path,
    g: &str,
    a: &str,
    v: &str,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<u8>, String> {
    let local = LocalSources {
        installed_dir: Some(dir.to_path_buf()),
        ..LocalSources::none()
    };
    acquire_jvm_artifact(
        &local,
        &(g.to_string(), a.to_string(), v.to_string()),
        None,
        ext,
        service,
    )
    .await
}

/// Collect effective parent/BOM metadata. Descendant properties override parent
/// import versions, but do not leak into a separately imported BOM's own model.
async fn collect_gradle_metadata(
    bytes: &[u8],
    local: &LocalSources,
    service: Option<&VendorServiceConfig>,
    out: &mut Vec<super::jvm::gradle::MetadataArtifact>,
    depth: usize,
    descendant: &std::collections::BTreeMap<String, String>,
    propagate_properties: bool,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    use super::jvm::maven_reactor::metadata_model;
    if depth > 32 || out.len() > 128 {
        return Err("upstream metadata graph exceeds the depth or size limit".into());
    }
    let empty = std::collections::BTreeMap::new();
    let model = metadata_model(bytes, &empty, descendant, false)?;
    let mut properties = empty;
    if let Some((g, a, v)) = model.parent {
        let parent = acquire_upstream_metadata(local, &g, &a, &v, "pom", service).await?;
        let child_properties = model
            .properties
            .into_iter()
            .filter(|(key, _)| {
                propagate_properties
                    && !matches!(
                        key.as_str(),
                        "project.groupId" | "project.artifactId" | "project.version"
                    )
            })
            .collect();
        properties = Box::pin(collect_gradle_metadata(
            &parent,
            local,
            service,
            out,
            depth + 1,
            &child_properties,
            propagate_properties,
        ))
        .await?;
        collect_metadata_artifacts(local, &g, &a, &v, parent, service, out).await?;
    }
    let model = metadata_model(bytes, &properties, descendant, true)?;
    for (g, a, v) in model.imports {
        if out
            .iter()
            .any(|m| m.group == g && m.artifact == a && m.version == v && m.extension == "pom")
        {
            continue;
        }
        let bom = acquire_upstream_metadata(local, &g, &a, &v, "pom", service).await?;
        Box::pin(collect_gradle_metadata(
            &bom,
            local,
            service,
            out,
            depth + 1,
            &std::collections::BTreeMap::new(),
            propagate_properties,
        ))
        .await?;
        collect_metadata_artifacts(local, &g, &a, &v, bom, service, out).await?;
    }
    Ok(model.properties)
}

/// The poms outside the checkout (external parents, imported BOMs) the
/// reactor planner weighs a pin against (#488): the copy a local cache
/// holds, which is the one the build reads whatever a registry says of it
/// (a corporate parent is on no public registry), else the registry's;
/// one that neither has is recorded unavailable, and the planner then
/// leaves that root unpinned.
async fn external_maven_poms(
    read: super::jvm::ReadFn<'_>,
    list: super::jvm::ListFn<'_>,
    patch: &super::jvm::JvmPatch<'_>,
    local: &LocalSources,
    service: Option<&VendorServiceConfig>,
) -> super::jvm::maven_reactor::ExternalPoms {
    // These poms only decide a pin: nothing of them is vendored, so they
    // do not make the entry's upstream files unverified.
    let caches = LocalSources {
        roots: local.roots.clone(),
        ..LocalSources::none()
    };
    let mut known = super::jvm::maven_reactor::ExternalPoms::new();
    loop {
        let need = super::jvm::maven_reactor::external_poms_needed(read, list, patch, &known);
        if need.is_empty() {
            return known;
        }
        for gav in need {
            let bytes = match caches.find(&gav, None, "pom", false).await {
                Ok(Some(bytes)) => Some(bytes),
                _ => acquire_jvm_artifact(&caches, &gav, None, "pom", service)
                    .await
                    .ok(),
            };
            known.insert(gav, bytes);
        }
    }
}

/// The upstream poms of `pom`'s parent chain, nearest first and complete
/// ([`super::jvm::JvmPatch::upstream_parents`]), read like any upstream
/// metadata. The error names the parent that could not be read.
pub(super) async fn upstream_parent_chain(
    pom: &[u8],
    local: &LocalSources,
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<Vec<u8>>, String> {
    /// A parent chain is a handful of poms; this bounds a cyclic one.
    const MAX_PARENTS: usize = 16;
    let mut chain: Vec<Vec<u8>> = Vec::new();
    loop {
        let child = chain.last().map_or(pom, Vec::as_slice);
        let Some((g, a, v)) = super::jvm::maven_reactor::parent_gav(child)
            .map_err(|e| format!("a pom of its parent chain cannot be followed ({e})"))?
        else {
            return Ok(chain);
        };
        if chain.len() >= MAX_PARENTS {
            return Err(format!(
                "its parent poms nest deeper than {MAX_PARENTS} (at {g}:{a}:{v})"
            ));
        }
        let parent = acquire_upstream_metadata(local, &g, &a, &v, "pom", service)
            .await
            .map_err(|e| format!("its parent pom {g}:{a}:{v} cannot be read ({e})"))?;
        chain.push(parent);
    }
}

/// A parent's or BOM's metadata file: the local caches only (never the
/// patched GAV's own directory), else the registry.
async fn acquire_upstream_metadata(
    local: &LocalSources,
    g: &str,
    a: &str,
    v: &str,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<u8>, String> {
    acquire_jvm_artifact(
        &local.caches(),
        &(g.to_string(), a.to_string(), v.to_string()),
        None,
        ext,
        service,
    )
    .await
}

async fn collect_metadata_artifacts(
    local: &LocalSources,
    g: &str,
    a: &str,
    v: &str,
    pom: Vec<u8>,
    service: Option<&VendorServiceConfig>,
    out: &mut Vec<super::jvm::gradle::MetadataArtifact>,
) -> Result<(), String> {
    if out
        .iter()
        .any(|m| m.group == g && m.artifact == a && m.version == v)
    {
        return Ok(());
    }
    let module = if String::from_utf8_lossy(&pom).contains("published-with-gradle-metadata") {
        Some(acquire_upstream_metadata(local, g, a, v, "module", service).await?)
    } else {
        None
    };
    for (extension, bytes) in [("pom", Some(pom)), ("module", module)] {
        if let Some(bytes) = bytes {
            out.push(super::jvm::gradle::MetadataArtifact {
                group: g.into(),
                artifact: a.into(),
                version: v.into(),
                extension,
                bytes,
            });
        }
    }
    Ok(())
}

/// Bounded HTTP GET of a pom from the maven2 registry.
async fn fetch_pom_bytes(url: &str) -> Result<Vec<u8>, String> {
    fetch_registry_bytes(url, MAX_POM_BYTES as u64).await
}

/// Bounded HTTP GET from a Maven registry. Errors quote the URL redacted
/// (a mirror's userinfo, reqwest's own error text included).
pub(crate) async fn fetch_registry_bytes(url: &str, cap: u64) -> Result<Vec<u8>, String> {
    fetch_registry_bytes_unredacted(url, cap)
        .await
        .map_err(|e| crate::utils::redact::redact_urls_in(&e).into_owned())
}

async fn fetch_registry_bytes_unredacted(url: &str, cap: u64) -> Result<Vec<u8>, String> {
    let client = super::registry_fetch::registry_client_builder(MAVEN_USER_AGENT)
        .build()
        .map_err(|e| format!("build http client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    // Enforce the cap on the declared Content-Length AND on the streamed
    // bytes (the shared reader every other registry download uses): a
    // mirror serving a huge body is refused mid-stream instead of being
    // buffered whole before the size check.
    crate::utils::http::read_capped(resp, cap, "Maven artifact")
        .await
        .map_err(|e| format!("{url}: {e}"))
}

/// Write the jar + pom + their `.sha1` sidecars into the maven2 leaf dir,
/// creating it. Errors are strings.
pub(super) async fn write_maven_artifact(
    leaf_dir: &Path,
    jar_leaf: &str,
    jar_bytes: &[u8],
    pom_leaf: &str,
    pom_bytes: &[u8],
) -> Result<(), String> {
    tokio::fs::create_dir_all(leaf_dir)
        .await
        .map_err(|e| format!("cannot create {}: {e}", leaf_dir.display()))?;
    for (leaf, bytes) in [(jar_leaf, jar_bytes), (pom_leaf, pom_bytes)] {
        let path = leaf_dir.join(leaf);
        atomic_write_artifact(&path, bytes)
            .await
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let sha1_path = leaf_dir.join(format!("{leaf}.sha1"));
        atomic_write_artifact(&sha1_path, sha1_hex(bytes).as_bytes())
            .await
            .map_err(|e| format!("cannot write {}: {e}", sha1_path.display()))?;
    }
    Ok(())
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

/// Whether a `.sha1` sidecar's text names `jar`'s sha1 the way maven-resolver
/// reads a checksum file: the first token of the first non-empty line,
/// case-insensitive (`sha1sum`'s `<hex>  <file>` form included). Pure; the
/// caller reads both files. (The vendor backend's own in-sync checks compare
/// the trimmed text exactly, the shape it writes.)
pub(crate) fn sha1_sidecar_matches(jar: &[u8], recorded: &str) -> bool {
    let token = recorded
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_default();
    token.eq_ignore_ascii_case(&sha1_hex(jar))
}

/// The `<repository>` element served from the committed maven2 repo. The URL
/// uses `${project.basedir}` so it resolves relative to the pom on any checkout;
/// `checksumPolicy=fail` makes Maven hard-fail on a jar/pom that doesn't match
/// its `.sha1` sidecar; `<snapshots>` is disabled (the vendored GAV is a fixed
/// release).
fn repository_block(repo_id: &str, uuid_dir_rel: &str) -> String {
    format!(
        "    <repository>\n\
         \x20     <id>{repo_id}</id>\n\
         \x20     <url>{VENDOR_REPO_URL_PREFIX}{uuid_dir_rel}</url>\n\
         \x20     <releases>\n\
         \x20       <enabled>true</enabled>\n\
         \x20       <checksumPolicy>fail</checksumPolicy>\n\
         \x20     </releases>\n\
         \x20     <snapshots>\n\
         \x20       <enabled>false</enabled>\n\
         \x20     </snapshots>\n\
         \x20   </repository>\n"
    )
}

/// Revert our `<repository>` wiring from `pom.xml`. `Ok(true)` = reverted (or
/// would be on dry run) / already gone; `Ok(false)` = drifted (the live pom no
/// longer carries our repository block), left alone; `Err` = a real I/O failure.
///
/// FRAGMENT-LEVEL: the whole-file `w.original` snapshot is only restored on the
/// provably-safe fast path where the live pom is still byte-identical to what we
/// wrote (`w.new`) — nothing has changed since vendoring. Otherwise — a sibling
/// patch added another `<repository>` into the same `<repositories>`, or the
/// user hand-edited the pom AFTER vendoring — we surgically excise ONLY the
/// exact `<repository>` block we authored ([`repository_block`] renders it
/// deterministically, so we reproduce it verbatim from the repo id + uuid dir)
/// and leave every other byte (sibling wiring, user edits) intact. If we
/// created the `<repositories>` section and excising our block leaves it empty,
/// the now-empty section is removed too. A pom that no longer carries our exact
/// block is third-party state, left alone with a drift warning.
async fn revert_repo_record(
    pom_xml_path: &Path,
    w: &WiringRecord,
    uuid_dir_rel: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(repo_id) = w.key.as_deref() else {
        return Ok(false);
    };
    let Some(Value::String(original)) = &w.original else {
        return Ok(false);
    };
    let new = match &w.new {
        Some(Value::String(new)) => Some(new),
        _ => None,
    };
    let live = match read_regular_to_string(pom_xml_path).await {
        Ok(live) => live,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The pom is gone (deleted by the user) — nothing to restore.
            return Ok(true);
        }
        Err(e) => return Err(format!("unreadable {}: {e}", pom_xml_path.display())),
    };

    // (a) Byte-identical to what we wrote → the whole-file restore is provably
    //     safe (nothing changed since vendoring). This also cheaply covers the
    //     lone-patch common case. The ledger is committed, so its snapshots
    //     are not trusted to say what the pom was: the restore is only taken
    //     when they differ by nothing but our `<repository>` element.
    if new.is_some_and(|n| &live == n && only_adds_our_repository(original, n, uuid_dir_rel)) {
        if dry_run {
            return Ok(true);
        }
        atomic_write_bytes_preserving_mode(pom_xml_path, original.as_bytes())
            .await
            .map_err(|e| format!("failed to restore {}: {e}", pom_xml_path.display()))?;
        return Ok(true);
    }

    // (b) The file diverged (a sibling vendor added another <repository>, or the
    //     user edited elsewhere) but our exact block is still present → excise
    //     ONLY our block, reproduced verbatim from the deterministic renderer.
    let block = repository_block(repo_id, uuid_dir_rel);
    if !live.contains(&block) {
        // (c) Our exact block is gone (already reverted, or edited) → drift,
        //     leave the file alone.
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    let excised = strip_empty_repositories(&live.replacen(&block, "", 1));
    atomic_write_bytes_preserving_mode(pom_xml_path, excised.as_bytes())
        .await
        .map_err(|e| {
            format!(
                "failed to excise the vendored <repository> from {}: {e}",
                pom_xml_path.display()
            )
        })?;
    Ok(true)
}

/// Whether the pom snapshot `new` is `original` with nothing but lines of a
/// `<repository>` element for this patch's vendored repo added (and the
/// `<repositories>` section around it): what the pre-v5 backend wrote. The
/// whole-file restore puts `original` back, so this is what makes it the
/// undo of that edit and nothing more — a ledger whose snapshots differ in
/// any other way (a dependency, a plugin, another repository) is not
/// followed, and the element is excised instead.
fn only_adds_our_repository(original: &str, new: &str, uuid_dir_rel: &str) -> bool {
    let between = |line: &str, tag: &str| {
        line.strip_prefix(&format!("<{tag}>"))
            .and_then(|rest| rest.strip_suffix(&format!("</{tag}>")))
            .map(str::to_string)
    };
    let kept: Vec<&str> = original.lines().collect();
    let mut next = 0;
    let mut ours = false;
    for line in new.lines() {
        if kept.get(next) == Some(&line) {
            next += 1;
            continue;
        }
        let line = line.trim();
        let element = matches!(
            line,
            "<repositories>"
                | "</repositories>"
                | "<repository>"
                | "</repository>"
                | "<releases>"
                | "</releases>"
                | "<snapshots>"
                | "</snapshots>"
        ) || between(line, "id").is_some_and(|id| !id.contains(['<', '>']))
            || between(line, "enabled").is_some_and(|v| matches!(v.as_str(), "true" | "false"))
            || between(line, "checksumPolicy").is_some_and(|v| !v.contains(['<', '>']));
        let url = between(line, "url")
            .is_some_and(|url| url == format!("{VENDOR_REPO_URL_PREFIX}{uuid_dir_rel}"));
        ours |= url;
        if !element && !url {
            return false;
        }
    }
    next == kept.len() && ours
}

/// After excising our `<repository>`, drop a `<repositories>` section left with
/// no children (the section the pre-v5 backend created for the first vendored
/// package, rendered as `  <repositories>\n` + blocks + `  </repositories>\n`
/// just before `</project>`), byte for byte; a section that still holds a
/// sibling `<repository>` is untouched (its inner bytes are non-whitespace).
fn strip_empty_repositories(pom: &str) -> String {
    let open = "  <repositories>\n";
    let close = "  </repositories>\n";
    let Some(open_at) = pom.find(open) else {
        return pom.to_string();
    };
    let inner_start = open_at + open.len();
    let Some(rel_close) = pom[inner_start..].find(close) else {
        return pom.to_string();
    };
    let inner = &pom[inner_start..inner_start + rel_close];
    if !inner.trim().is_empty() {
        // A sibling <repository> still lives here — keep the section.
        return pom.to_string();
    }
    let close_end = inner_start + rel_close + close.len();
    let mut out = String::with_capacity(pom.len());
    out.push_str(&pom[..open_at]);
    out.push_str(&pom[close_end..]);
    out
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::path::PathBuf;

    use std::collections::HashMap;

    use super::*;

    /// A reactor `pom.xml` above the repository root is never read: the
    /// project may be one of its modules, so vendoring refuses.
    #[test]
    fn a_build_above_the_repository_refuses_unread() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = std::fs::canonicalize(tmp.path()).unwrap();
        let app = outer.join("repo");
        std::fs::create_dir_all(app.join(".git")).unwrap();
        std::fs::write(app.join("pom.xml"), "<project/>").unwrap();
        std::fs::write(
            outer.join("pom.xml"),
            "<project><modules><module>other</module></modules></project>",
        )
        .unwrap();
        let why = not_build_root(&app).unwrap();
        assert!(why.contains("outside the repository"), "{why}");
    }
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::ApplyResult;
    use crate::vendor::jvm::layout::is_path_safe;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";
    const PRISTINE: &[u8] =
        b"Apache Commons Text\nCopyright 2014-2022 The Apache Software Foundation\n";
    const PATCHED: &[u8] =
        b"Apache Commons Text\n// SOCKET-PATCH-MARKER\nCopyright 2014-2022 The Apache Software Foundation\n";
    /// The real upstream pom, carrying a transitive dependency — proof that
    /// vendoring copies it verbatim (never a minimal stand-in).
    const UPSTREAM_POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
        <groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
        <version>1.10.0</version>\
        <dependencies><dependency><groupId>org.apache.commons</groupId>\
        <artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency></dependencies>\
        </project>";
    /// The file inside the jar the marker patch targets.
    const JAR_FILE: &str = "META-INF/NOTICE.txt";

    fn leaf_rel() -> String {
        format!(".socket/vendor/maven/{UUID}/org/apache/commons/commons-text/1.10.0")
    }

    fn jar_rel() -> String {
        format!("{}/commons-text-1.10.0.jar", leaf_rel())
    }

    /// Build a jar (plain zip) with a MANIFEST + the NOTICE.txt patch target.
    fn make_jar(notice: &[u8]) -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        let files: &[(&str, &[u8])] = &[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            (JAR_FILE, notice),
            (
                "org/apache/commons/text/StringSubstitutor.class",
                b"\xca\xfe\xba\xbe-fake-class",
            ),
        ];
        for (name, bytes) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// A minimal project pom.xml at the root (single-module, no <modules>).
    fn project_pom() -> &'static str {
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
         \x20 <modelVersion>4.0.0</modelVersion>\n\
         \x20 <groupId>com.example</groupId>\n\
         \x20 <artifactId>app</artifactId>\n\
         \x20 <version>1.0.0</version>\n\
         \x20 <dependencies>\n\
         \x20   <dependency>\n\
         \x20     <groupId>org.apache.commons</groupId>\n\
         \x20     <artifactId>commons-text</artifactId>\n\
         \x20     <version>1.10.0</version>\n\
         \x20   </dependency>\n\
         \x20 </dependencies>\n\
         </project>\n"
    }

    async fn fixture(
        pom_xml: Option<&str>,
        with_local_jar: bool,
        with_local_pom: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // The crawler's version dir: ~/.m2/repository/<g>/<a>/<v>/ carrying the
        // cached jar + pom (NOT extracted files).
        let installed = root.join("m2/org/apache/commons/commons-text/1.10.0");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        if with_local_jar {
            tokio::fs::write(
                installed.join("commons-text-1.10.0.jar"),
                make_jar(PRISTINE),
            )
            .await
            .unwrap();
        }
        if with_local_pom {
            tokio::fs::write(installed.join("commons-text-1.10.0.pom"), UPSTREAM_POM)
                .await
                .unwrap();
        }

        // Blob store carrying the patched NOTICE.txt.
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        if let Some(pom) = pom_xml {
            tokio::fs::write(root.join(PROJECT_POM), pom).await.unwrap();
        }

        let mut files = HashMap::new();
        files.insert(
            JAR_FILE.to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(PRISTINE),
                after_hash: after,
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-vend-maven-real".to_string(),
            crate::manifest::schema::VulnerabilityInfo {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, blobs, installed, record)
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

    /// The JVM shapes' plan entry asks for a grant exactly when the JVM
    /// backend would: never for a Gradle subproject (`not_build_root`) nor
    /// for an sbt build the resolution gate skips, both of which stop
    /// before the service is asked; a Gradle root does ask. A granted
    /// download the loop then skips is a leaked server-side build.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_service_preflight_matches_what_the_backend_asks_for() {
        use crate::vendor::test_support::{granted_uuids, mount_no_results, service_cfg};
        let server = wiremock::MockServer::start().await;
        mount_no_results(&server).await;
        let cfg = service_cfg(&server.uri(), crate::vendor::VendorSource::Service, false);

        let (sub_dir, blobs, installed, record) = fixture(None, true, true).await;
        std::fs::create_dir_all(sub_dir.path().join(".git")).unwrap();
        std::fs::write(sub_dir.path().join("settings.gradle"), "include 'app'\n").unwrap();
        let subproject = sub_dir.path().join("app");
        std::fs::create_dir_all(&subproject).unwrap();
        std::fs::write(subproject.join("build.gradle"), "plugins { id 'java' }\n").unwrap();

        let (sbt_dir, ..) = fixture(None, true, true).await;
        std::fs::create_dir_all(sbt_dir.path().join("project")).unwrap();
        std::fs::write(
            sbt_dir.path().join("build.sbt"),
            "scalaVersion := \"2.13.12\"\n",
        )
        .unwrap();
        std::fs::write(
            sbt_dir.path().join("project/build.properties"),
            "sbt.version=1.9.7\n",
        )
        .unwrap();

        let (gradle_dir, ..) = fixture(None, true, true).await;
        std::fs::write(
            gradle_dir.path().join("build.gradle"),
            "plugins { id 'java' }\n",
        )
        .unwrap();

        let sources = PatchSources::blobs_only(&blobs);
        for (project, asks) in [
            (subproject.as_path(), false),
            (sbt_dir.path(), false),
            (gradle_dir.path(), true),
        ] {
            let planned = service_preflight(PURL, project, &record).await.is_some();
            let before = granted_uuids(&server).await.len();
            let _ = crate::vendor::test_support::vendor_maven(
                PURL,
                installed.as_path(),
                project,
                &record,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                Some(&cfg),
            )
            .await;
            let asked = granted_uuids(&server).await.len() > before;
            assert_eq!(asked, asks, "{}: the backend's own ask", project.display());
            assert_eq!(planned, asked, "{}: plan vs backend", project.display());
        }
    }

    /// The download plan's gate names exactly the artifacts whose vendor call
    /// asks the patch service for a grant: not a non-canonical uuid, not the
    /// empty patch's no-op, and — once vendored — not the in-sync re-run; a
    /// second patch uuid for the same artifact asks again.
    #[tokio::test]
    #[serial_test::serial]
    async fn service_preflight_names_exactly_the_artifacts_that_ask_for_a_grant() {
        use crate::vendor::test_support::{
            empty_patch, mount_no_results, plan_matches_grants, service_cfg, with_uuid, Borrowed,
            PLAN_UUID_B, PLAN_UUID_C,
        };
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_no_results(&server).await;
        let cfg = service_cfg(&server.uri(), crate::vendor::VendorSource::Service, false);
        let sources = PatchSources::blobs_only(&blobs);
        let cases = [
            (PURL, record.clone()),
            (PURL, with_uuid(&record, "not-a-uuid")),
            (PURL, empty_patch(&record, PLAN_UUID_B)),
            (
                "pkg:maven/org..bad/commons-text@1.10.0",
                with_uuid(&record, PLAN_UUID_B),
            ),
            (PURL, with_uuid(&record, PLAN_UUID_C)),
        ];
        let gate = |purl: String, rec: PatchRecord| -> Borrowed<'_, bool> {
            Box::pin(async move { service_preflight(&purl, root, &rec).await.is_some() })
        };
        let vendor = |purl: String, rec: PatchRecord| -> Borrowed<'_, VendorOutcome> {
            let (installed, sources, cfg) = (&installed, &sources, &cfg);
            Box::pin(async move {
                crate::vendor::test_support::vendor_maven(
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
        assert_eq!(planned, vec![UUID.to_string(), PLAN_UUID_C.to_string()]);
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_maven(
            PURL,
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

    fn read_jar_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).ok()?;
        let mut f = archive.by_name(name).ok()?;
        let mut out = Vec::new();
        f.read_to_end(&mut out).ok()?;
        Some(out)
    }

    /// A build that declares another version of the artifact itself does
    /// not select the patch's base version, whatever its local repository
    /// holds: the patch is a skip decided before any download. A build
    /// that declares the base version is none.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_version_the_build_does_not_select_is_skipped_before_any_download() {
        let declaring = |version: &str| {
            format!(
                "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
                 <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <dependencies>\n    \
                 <dependency>\n      <groupId>org.apache.commons</groupId>\n      \
                 <artifactId>commons-text</artifactId>\n      <version>{version}</version>\n    \
                 </dependency>\n  </dependencies>\n</project>\n"
            )
        };
        let (dir, blobs, installed, record) = fixture(Some(&declaring("1.11.0")), true, true).await;
        let root = dir.path();
        let refusals = maven_not_selected_refusals(root, &[(PURL.to_string(), UUID.to_string())]);
        let [(purl, (code, detail))] = refusals.as_slice() else {
            panic!("{refusals:?}");
        };
        assert_eq!(
            (purl.as_str(), *code),
            (PURL, "vendor_maven_version_not_selected")
        );
        assert!(
            detail.contains("Maven selects org.apache.commons:commons-text 1.11.0")
                && detail.contains("not 1.10.0"),
            "{detail}"
        );
        assert!(crate::vendor::refusals::refusal_is_benign(code));
        // The backend stops at the same gate, and writes nothing.
        let (code, _) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_maven_version_not_selected");
        assert!(service_preflight(PURL, root, &record).await.is_none());
        assert!(!root.join(".socket").exists());
        assert_eq!(
            std::fs::read_to_string(root.join(PROJECT_POM)).unwrap(),
            declaring("1.11.0")
        );

        std::fs::write(root.join(PROJECT_POM), declaring("1.10.0")).unwrap();
        assert!(
            maven_not_selected_refusals(root, &[(PURL.to_string(), UUID.to_string())]).is_empty()
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn missing_reactor_module_is_refused_without_writes() {
        let multimodule = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <groupId>com.example</groupId>\n\
             \x20 <artifactId>agg</artifactId>\n\
             \x20 <version>1.0.0</version>\n\
             \x20 <packaging>pom</packaging>\n\
             \x20 <modules>\n\
             \x20   <module>child</module>\n\
             \x20 </modules>\n\
             </project>\n";
        let (dir, blobs, installed, record) = fixture(Some(multimodule), true, true).await;
        let root = dir.path();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");
    }

    /// #716: a commented-out `<modules>` is not a reactor's; the pom is
    /// planned as a single module.
    #[tokio::test]
    #[serial_test::serial]
    async fn commented_modules_do_not_refuse() {
        let commented = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <groupId>com.example</groupId>\n\
             \x20 <artifactId>app</artifactId>\n\
             \x20 <version>1.0.0</version>\n\
             \x20 <!-- <modules><module>old</module></modules> -->\n\
             \x20 <dependencies>\n\
             \x20   <dependency>\n\
             \x20     <groupId>org.apache.commons</groupId>\n\
             \x20     <artifactId>commons-text</artifactId>\n\
             \x20     <version>1.10.0</version>\n\
             \x20   </dependency>\n\
             \x20 </dependencies>\n\
             </project>\n";
        let (dir, blobs, installed, record) = fixture(Some(commented), true, true).await;
        let root = dir.path();
        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(
            result.success,
            "commented <modules> must not refuse: {:?}",
            result.error
        );
        assert_eq!(entry.unwrap().ecosystem, layout::LEDGER_ECOSYSTEM);
        let pom = std::fs::read_to_string(root.join(PROJECT_POM)).unwrap();
        assert!(pom.contains("<module>old</module></modules> -->"), "{pom}");
        assert!(pom.contains("1.10.0-socket."), "{pom}");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn vendors_gradle_only_project_by_default() {
        // build.gradle but no pom.xml → gradle-only.
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        tokio::fs::write(root.join("build.gradle"), b"plugins { id 'java' }\n")
            .await
            .unwrap();
        let (result, entry, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(entry.unwrap().ecosystem, layout::LEDGER_ECOSYSTEM);
        assert!(root.join(".socket/vendor/gradle-index.tsv").is_file());
    }

    /// The JVM shapes #1061 names, each as a fresh project: a single-module
    /// pom, a multi-module reactor and a Gradle-only build.
    async fn jvm_shape_fixture(shape: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        match shape {
            "pom" => fixture(Some(project_pom()), true, true).await,
            "reactor" => reactor_fixture(true).await,
            _ => {
                let fx = fixture(None, true, true).await;
                std::fs::write(fx.0.path().join("build.gradle"), "plugins { id 'java' }\n")
                    .unwrap();
                fx
            }
        }
    }

    /// Every file under `.socket/` (relative, `/`-separated).
    fn socket_files(root: &Path) -> Vec<String> {
        crate::vendor::test_support::tree_snapshot(root)
            .into_keys()
            .filter(|rel| rel.starts_with(".socket/"))
            .collect()
    }

    /// #1061 (and #620): GitHub's stock Java.gitignore ignores `*.jar`.
    /// Vendoring a Maven, reactor or Gradle project must still leave every
    /// written tree file committable (the tree roots re-include them), and
    /// revert removes the re-include it created.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_jar_ignore_rule_is_overridden_by_the_tree_gitignore() {
        use crate::vendor::test_support::{git_project, JAVA_GITIGNORE};
        for shape in ["pom", "reactor", "gradle"] {
            let (dir, blobs, installed, record) = jvm_shape_fixture(shape).await;
            let root = dir.path();
            if git_project(root, JAVA_GITIGNORE).is_none() {
                return;
            }
            let (result, entry, _) =
                unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
            assert!(result.success, "{shape}: {:?}", result.error);
            let entry = entry.expect("ledger entry");
            assert!(entry.artifact.path.ends_with(".jar"), "{shape}");
            let written = socket_files(root);
            assert!(
                written.contains(&entry.artifact.path),
                "{shape}: {written:?}"
            );
            assert_eq!(
                crate::vendor::npm_dir::gitignored(root, &written).await,
                None,
                "{shape}: git commits every vendored file"
            );

            let reverted = revert_maven(&entry, root, false).await;
            assert!(reverted.success, "{shape}: {reverted:?}");
            let left = socket_files(root)
                .into_iter()
                .filter(|rel| rel.ends_with(".gitignore"))
                .collect::<Vec<_>>();
            assert!(left.is_empty(), "{shape}: revert leaves {left:?}");
        }
    }

    /// #1061: a rule that ignores the vendor tree itself (`.socket/`) can't
    /// be overridden from inside it, so every JVM shape refuses
    /// `vendor_artifact_gitignored` before writing, dry run included.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_jvm_tree_directory_ignore_rule_refuses_before_any_write() {
        use crate::vendor::test_support::git_project;
        for shape in ["pom", "reactor", "gradle"] {
            for rule in [".socket/", ".socket/vendor/"] {
                for dry_run in [false, true] {
                    let (dir, blobs, installed, record) = jvm_shape_fixture(shape).await;
                    let root = dir.path();
                    if git_project(root, &format!("{rule}\n")).is_none() {
                        return;
                    }
                    let before = crate::vendor::test_support::tree_snapshot(root);
                    let (code, detail) = unwrap_refused(
                        run_vendor(root, &blobs, &installed, &record, dry_run).await,
                    );
                    assert_eq!(
                        code, "vendor_artifact_gitignored",
                        "{shape} {rule}: {detail}"
                    );
                    assert!(detail.contains(rule), "{shape} {rule}: {detail}");
                    assert_eq!(
                        crate::vendor::test_support::tree_snapshot(root),
                        before,
                        "{shape} {rule}: nothing written"
                    );
                    // The takeover gate refuses too, before any restore.
                    assert_eq!(
                        jvm_gate_preflight(root, PURL).await.map_err(|(c, _)| c),
                        Err("vendor_artifact_gitignored"),
                        "{shape} {rule}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn refuses_unsafe_coordinates() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut bad = record.clone();
        bad.uuid = "../../escape".to_string();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &bad, false).await);
        assert_eq!(code, "unsafe_coordinates");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");

        // A traversal in the coordinate group is refused too.
        let sources = PatchSources::blobs_only(&blobs);
        let (code, _d) = unwrap_refused(
            crate::vendor::test_support::vendor_maven(
                "pkg:maven/../evil/x@1.0.0",
                &installed,
                root,
                &record,
                &sources,
                "t",
                false,
                false,
                None,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn dry_run_writes_nothing() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no artifact created");
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.detail.starts_with("reason: maven_mirror_of_all: ")),
            "dry run predicts the wrapper-less warnings: {warnings:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revert_restores_pom_byte_identical() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let entry = legacy_vendor(root, &record).await;
        assert_ne!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before,
            "vendor rewired pom.xml"
        );

        let outcome = revert_maven(&entry, root, false).await;
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
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before,
            "pom.xml restored byte-identically"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "uuid dir removed"
        );
    }

    /// The ledger is committed, so the pom snapshot it records is not
    /// trusted to say what the pom was: one that differs from the vendored
    /// pom by more than our `<repository>` is never written. The element is
    /// excised from the live pom instead.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_never_writes_a_pom_snapshot_that_is_not_the_pom_minus_our_repository() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let mut entry = legacy_vendor(root, &record).await;
        let evil = pom_before.replace(
            "</project>",
            "  <build><plugins><plugin><artifactId>exec-maven-plugin</artifactId></plugin></plugins></build>\n</project>",
        );
        assert_ne!(evil, pom_before);
        entry.wiring[0].original = Some(Value::String(evil));

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            pom_before,
            "our repository is excised; the ledger's text is not written"
        );
    }

    #[test]
    fn a_pom_snapshot_pair_differs_only_by_our_repository() {
        let rel = format!(".socket/vendor/maven/{UUID}");
        let original = "<project>\n  <modelVersion>4.0.0</modelVersion>\n</project>\n";
        let block = repository_block("socket-patch-vendor-x", &rel);
        let new = original.replace(
            "</project>",
            &format!("  <repositories>\n{block}  </repositories>\n</project>"),
        );
        assert!(only_adds_our_repository(original, &new, &rel));
        // In a section the pom already had.
        let sectioned = "<project>\n  <repositories>\n  </repositories>\n</project>\n";
        let wired = sectioned.replace("  </repositories>", &format!("{block}  </repositories>"));
        assert!(only_adds_our_repository(sectioned, &wired, &rel));

        for (what, original, new) in [
            (
                "nothing of ours added",
                original.to_string(),
                original.to_string(),
            ),
            (
                "a line dropped",
                original.to_string(),
                new.replace("  <modelVersion>4.0.0</modelVersion>\n", ""),
            ),
            (
                "a line the original has and the pom does not",
                original.replace("</project>", "  <build />\n</project>"),
                new.clone(),
            ),
            (
                "another repository",
                original.to_string(),
                new.replace(&rel, ".socket/vendor/maven/other"),
            ),
            (
                "a plugin among the added lines",
                original.to_string(),
                new.replace("</project>", "  <build />\n</project>"),
            ),
        ] {
            assert!(!only_adds_our_repository(&original, &new, &rel), "{what}");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revert_drift_leaves_pom_alone() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let entry = legacy_vendor(root, &record).await;

        // Third-party drift: the user regenerated pom.xml without our repo.
        tokio::fs::write(root.join(PROJECT_POM), project_pom())
            .await
            .unwrap();
        let drifted = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            drifted,
            "drifted pom.xml left alone"
        );
        assert!(!outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "a converged pom names nothing under .socket/vendor: the uuid dir is removed"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revert_excises_only_our_block_preserving_sibling() {
        // Vendor creates the <repositories> section with OUR block. Then a
        // sibling vendor run inserts ANOTHER <repository> into that same
        // section (simulated by inserting before </repositories>). Reverting
        // us must excise ONLY our block and keep the sibling's wiring intact —
        // a whole-file restore would wipe it.
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let entry = legacy_vendor(root, &record).await;

        // A sibling patch's <repository> lands in the section we created.
        let wired = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let sibling = "    <repository>\n      <id>socket-patch-vendor-SIBLING</id>\n      <url>file://${project.basedir}/.socket/vendor/maven/SIBLING</url>\n    </repository>\n";
        let with_sibling = wired.replacen(
            "  </repositories>\n",
            &format!("{sibling}  </repositories>\n"),
            1,
        );
        assert_ne!(with_sibling, wired, "sibling block inserted");
        tokio::fs::write(root.join(PROJECT_POM), &with_sibling)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our block is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            !after.contains(&format!("socket-patch-vendor-{UUID}")),
            "our <repository> excised"
        );
        assert!(
            after.contains("socket-patch-vendor-SIBLING"),
            "sibling <repository> preserved: {after}"
        );
        // The section stays (a sibling still lives in it).
        assert_eq!(after.matches("<repositories>").count(), 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revert_preserves_user_edit_made_after_vendoring() {
        // The user edits the pom AFTER vendoring (adds a <properties> block).
        // Revert must remove our <repository> (and the section we created) yet
        // keep the user's edit — the whole-file restore would have discarded it.
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let entry = legacy_vendor(root, &record).await;

        let wired = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let user_edit = "  <properties>\n    <maven.compiler.release>17</maven.compiler.release>\n  </properties>\n";
        let edited = wired.replacen("</project>", &format!("{user_edit}</project>"), 1);
        tokio::fs::write(root.join(PROJECT_POM), &edited)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our block is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            !after.contains("socket-patch-vendor"),
            "our <repository> excised"
        );
        assert!(
            !after.contains("<repositories>"),
            "the section we created is removed once empty: {after}"
        );
        assert!(
            after.contains("<maven.compiler.release>17</maven.compiler.release>"),
            "user edit after vendoring preserved: {after}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revert_warns_when_our_block_already_gone() {
        // The user regenerated the pom, dropping our block but keeping a
        // hand-written <repositories>. Our exact block is absent → drift, and
        // we must NOT touch their section.
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let entry = legacy_vendor(root, &record).await;

        let regenerated = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <repositories>\n\
             \x20   <repository><id>corp</id><url>https://corp/repo</url></repository>\n\
             \x20 </repositories>\n\
             </project>\n";
        tokio::fs::write(root.join(PROJECT_POM), regenerated)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "our block gone → drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            regenerated,
            "the user's regenerated pom is left alone"
        );
        assert!(!outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "a regenerated pom names nothing under .socket/vendor: the uuid dir is removed"
        );
    }

    #[test]
    #[serial_test::serial]
    fn strip_empty_repositories_removes_created_section_only() {
        // A section left empty after excision is removed.
        let empty = "<project>\n  <repositories>\n  </repositories>\n</project>\n";
        assert_eq!(
            strip_empty_repositories(empty),
            "<project>\n</project>\n",
            "empty created section removed"
        );
        // A section still holding a sibling is kept verbatim.
        let with_sibling =
            "<project>\n  <repositories>\n    <repository><id>corp</id></repository>\n  </repositories>\n</project>\n";
        assert_eq!(
            strip_empty_repositories(with_sibling),
            with_sibling,
            "non-empty section untouched"
        );
    }

    #[test]
    #[serial_test::serial]
    fn group_id_path_and_safety() {
        assert_eq!(
            layout::group_path("org.apache.commons"),
            "org/apache/commons"
        );
        let is_safe_group_id = |g| is_path_safe(g, "a", "1");
        assert!(is_safe_group_id("org.apache.commons"));
        assert!(!is_safe_group_id(""));
        assert!(!is_safe_group_id(".org"));
        assert!(!is_safe_group_id("org."));
        assert!(!is_safe_group_id("a..b"));
        assert!(!is_safe_group_id("a/b"));
        assert!(!is_safe_group_id("a:b"));
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_preserves_pom_xml_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_path = root.join(PROJECT_POM);

        async fn mode_of(p: &Path) -> u32 {
            tokio::fs::metadata(p).await.unwrap().permissions().mode() & 0o7777
        }

        // Byte-identical fast path (whole-file restore).
        let entry = legacy_vendor(root, &record).await;
        tokio::fs::set_permissions(&pom_path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            mode_of(&pom_path).await,
            0o600,
            "whole-file restore must not reset the pom.xml mode"
        );

        // Re-vendor, drift with a user edit, revert → the excise path writes too.
        let entry = legacy_vendor(root, &record).await;
        let wired = tokio::fs::read_to_string(&pom_path).await.unwrap();
        let edited = wired.replacen(
            "</project>",
            "  <properties>\n  </properties>\n</project>",
            1,
        );
        tokio::fs::write(&pom_path, &edited).await.unwrap();
        tokio::fs::set_permissions(&pom_path, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            mode_of(&pom_path).await,
            0o640,
            "the excise path must not reset the pom.xml mode"
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

    /// Await `fut` under the FIFO-wedge deadline. On timeout, connect a writer
    /// to `fifo` so the blocked `open(2)` in the runtime's blocking pool is
    /// released (letting the test FAIL instead of hanging the whole suite),
    /// then panic with `what`.
    #[cfg(unix)]
    async fn expect_fast<T>(
        fut: impl std::future::Future<Output = T>,
        fifo: &Path,
        what: &str,
    ) -> T {
        let deadline = std::time::Duration::from_secs(5);
        match tokio::time::timeout(deadline, fut).await {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::OpenOptions::new().write(true).open(fifo);
                panic!("{what}");
            }
        }
    }

    /// A FIFO planted as the project `pom.xml` reads as no build file (the
    /// planner reads regular files only) instead of wedging every vendor
    /// run forever.
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn fifo_project_pom_fails_fast_in_vendor() {
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        let pom_path = root.join(PROJECT_POM);
        mkfifo(&pom_path);

        let outcome = expect_fast(
            run_vendor(root, &blobs, &installed, &record, false),
            &pom_path,
            "vendor must fail fast on a FIFO pom.xml, not wedge",
        )
        .await;
        let (code, detail) = unwrap_refused(outcome);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(detail.starts_with("reason: no_build_file: "), "{detail}");
    }

    /// Maven Central blocks/rate-limits user agents containing "socket" —
    /// the maven2 registry client must identify as the official Maven CLI,
    /// never as `SocketPatchCLI/…`.
    #[test]
    #[serial_test::serial]
    fn maven_user_agent_is_the_maven_cli_shape() {
        assert!(
            MAVEN_USER_AGENT.starts_with("Apache-Maven/"),
            "maven2 registry UA must lead with the Maven CLI product token: {MAVEN_USER_AGENT}"
        );
        assert!(
            !MAVEN_USER_AGENT.to_ascii_lowercase().contains("socket"),
            "a UA containing \"socket\" is blocked by Maven Central: {MAVEN_USER_AGENT}"
        );
    }

    /// The Maven-CLI UA must actually go out on the wire: the mock only
    /// serves the pom when the request carries `MAVEN_USER_AGENT`, so a
    /// regression back to `SocketPatchCLI/…` misses the matcher and fails
    /// the fetch.
    #[tokio::test]
    #[serial_test::serial]
    async fn pom_fetch_sends_the_maven_cli_user_agent() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pom_route = "/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.pom";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(pom_route))
            .and(header("user-agent", MAVEN_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(UPSTREAM_POM.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let bytes = fetch_pom_bytes(&format!("{}{pom_route}", server.uri()))
            .await
            .expect("pom fetch under the Maven CLI UA succeeds");
        assert_eq!(bytes, UPSTREAM_POM);
    }

    /// A FIFO planted as `pom.xml` must fail the revert fast and loudly —
    /// keeping the uuid dir for a retry — instead of wedging `--revert`
    /// forever.
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn fifo_project_pom_fails_fast_in_revert() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let entry = legacy_vendor(root, &record).await;

        let pom_path = root.join(PROJECT_POM);
        tokio::fs::remove_file(&pom_path).await.unwrap();
        mkfifo(&pom_path);

        let outcome = expect_fast(
            revert_maven(&entry, root, false),
            &pom_path,
            "revert must fail fast on a FIFO pom.xml, not wedge",
        )
        .await;
        assert!(
            !outcome.success,
            "an unreadable pom.xml must fail the revert"
        );
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("unreadable")),
            "error names the unreadable pom.xml: {:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact must survive a failed revert for the retry"
        );
    }

    // ── coverage: refusal and edge arms ──────────────────────────────────────

    use crate::test_env::EnvGuard;

    fn service_cfg(
        api_url: Option<&str>,
        source: crate::vendor::VendorSource,
        offline: bool,
    ) -> VendorServiceConfig {
        use crate::api::client::{ApiClient, ApiClientOptions};
        VendorServiceConfig {
            maven_config: None,
            source,
            client: api_url.map(|uri| {
                ApiClient::new(ApiClientOptions {
                    api_url: uri.to_string(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    route: crate::api::client::ApiRoute::org("acme"),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none())
            }),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            patch_server_origins: Vec::new(),
            offline,
        }
    }

    async fn run_vendor_with_service(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        cfg: &VendorServiceConfig,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        crate::vendor::test_support::vendor_maven(
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

    /// A purl from another ecosystem entirely fails `parse_maven_purl` and is
    /// refused before any coordinate/uuid processing.
    #[tokio::test]
    #[serial_test::serial]
    async fn refuses_non_maven_purl() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let (code, detail) = unwrap_refused(
            crate::vendor::test_support::vendor_maven(
                "pkg:npm/leftpad@1.0.0",
                &installed,
                root,
                &record,
                &sources,
                "t",
                false,
                false,
                None,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(
            detail.contains("not a maven purl"),
            "refusal names the parse failure: {detail}"
        );
        assert!(!root.join(".socket").exists(), "refusal writes nothing");
    }

    /// No pom.xml and no Gradle, sbt or scala-cli build: the planner's
    /// `no_build_file` refusal, with nothing written and no service call
    /// planned.
    #[tokio::test]
    #[serial_test::serial]
    async fn refuses_a_root_with_no_build_file() {
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        let (code, detail) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(detail.starts_with("reason: no_build_file: "), "{detail}");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");
        assert!(service_preflight(PURL, root, &record).await.is_none());
    }

    /// Revert fail-closed on a non-canonical uuid in the (tamper-able)
    /// state.json entry — refused before any disk access.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_refuses_non_canonical_uuid() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut entry = legacy_vendor(root, &record).await;
        entry.uuid = "../../escape".to_string();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(!outcome.success, "a tampered uuid must refuse the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("non-canonical")),
            "error names the fail-closed gate: {:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the real artifact must be untouched by the refused revert"
        );
        let pom_xml = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            pom_xml.contains(&format!("socket-patch-vendor-{UUID}")),
            "pom.xml untouched by the refused revert"
        );
    }

    /// An unrecognized wiring kind (forward-compat / tampered state.json) is
    /// warned about and left alone; the live pom still names the uuid dir,
    /// so the artifact is drift-kept (deleting it would strand the
    /// `<repository>` at a gone path).
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_unrecognized_wiring_kind_warns_and_keeps_the_referenced_artifact() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut entry = legacy_vendor(root, &record).await;
        entry.wiring[0].kind = "bogus".to_string();
        let wired = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("unrecognized wiring kind")),
            "the unknown kind is surfaced: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            wired,
            "the unrecognized wiring is left in place"
        );
        assert!(outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "the keep is surfaced: {:?}",
            outcome.warnings
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact the live pom still names is kept"
        );
    }

    /// A wiring record missing its `key` (tampered/truncated state.json) is
    /// tolerated as drift — `<unknown>` in the warning, pom.xml untouched;
    /// the still-wired pom keeps the artifact.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_tolerates_wiring_key_missing() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut entry = legacy_vendor(root, &record).await;
        entry.wiring[0].key = None;
        let wired = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("<unknown>")),
            "a key-less record drifts with <unknown>: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            wired,
            "pom.xml untouched when the record is unusable"
        );
        assert!(outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "the keep is surfaced: {:?}",
            outcome.warnings
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact the live pom still names is kept"
        );
    }

    /// A wiring record whose `original` is not a string is tolerated as drift;
    /// pom.xml is untouched and, still wired, keeps the artifact.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_tolerates_wiring_original_missing() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut entry = legacy_vendor(root, &record).await;
        entry.wiring[0].original = None;
        let wired = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "an original-less record drifts: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            wired,
            "pom.xml untouched when the record is unusable"
        );
        assert!(outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "the keep is surfaced: {:?}",
            outcome.warnings
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact the live pom still names is kept"
        );
    }

    /// A wiring record whose `new` snapshot is missing skips the byte-identical
    /// fast path but still excises our block surgically.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_missing_new_snapshot_excises_block() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut entry = legacy_vendor(root, &record).await;
        entry.wiring[0].new = None;

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our block is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            !after.contains(&format!("socket-patch-vendor-{UUID}")),
            "our <repository> excised without the new snapshot: {after}"
        );
        assert!(
            !after.contains("<repositories>"),
            "the section we created is removed once empty: {after}"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact is removed"
        );
    }

    /// pom.xml deleted by the user before revert: nothing to restore, the
    /// revert proceeds cleanly and still removes the artifact.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_with_pom_deleted_still_removes_artifact() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let entry = legacy_vendor(root, &record).await;
        tokio::fs::remove_file(root.join(PROJECT_POM))
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "a deleted pom is not drift: {:?}",
            outcome.warnings
        );
        assert!(
            !root.join(PROJECT_POM).exists(),
            "the revert must not resurrect the deleted pom.xml"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "the artifact is removed"
        );
    }

    /// A remove_tree failure during revert reports success=false with the uuid
    /// dir path — and the pom restore has ALREADY happened when the deletion
    /// fails (partial-revert semantics, pinned deliberately).
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_remove_tree_failure_reported() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();
        let entry = legacy_vendor(root, &record).await;

        // A read-only parent blocks the final rmdir of the uuid dir (unlinking
        // an entry needs write on its parent; the uuid dir's parent is the
        // maven dir).
        let maven_dir = root.join(".socket/vendor/maven");
        tokio::fs::set_permissions(&maven_dir, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        // Skip when the environment ignores modes (running as root).
        if std::fs::write(maven_dir.join(".probe"), b"x").is_ok() {
            let _ = std::fs::remove_file(maven_dir.join(".probe"));
            tokio::fs::set_permissions(&maven_dir, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();
            return;
        }
        let outcome = revert_maven(&entry, root, false).await;
        tokio::fs::set_permissions(&maven_dir, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(!outcome.success, "a failed deletion must fail the revert");
        let uuid_dir = root.join(format!(".socket/vendor/maven/{UUID}"));
        assert!(
            outcome.error.as_deref().is_some_and(
                |e| e.contains("failed to remove") && e.contains(&*uuid_dir.to_string_lossy())
            ),
            "error names the undeletable uuid dir: {:?}",
            outcome.error
        );
        assert!(uuid_dir.exists(), "the uuid dir survives for a retry");
        // Partial-revert semantics: the wiring restore ran BEFORE the deletion.
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before,
            "pom.xml was already restored when the deletion failed"
        );
    }

    /// --vendor-source=service + --offline is a fail-closed conflict, refused
    /// before any write.
    #[tokio::test]
    #[serial_test::serial]
    async fn service_mode_offline_refuses_before_any_write() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let cfg = service_cfg(
            None,
            crate::vendor::VendorSource::Service,
            /*offline=*/ true,
        );
        let (code, _d) =
            unwrap_refused(run_vendor_with_service(root, &blobs, &installed, &record, &cfg).await);
        assert_eq!(code, "vendor_service_offline_conflict");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");
        let pom_xml = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(!pom_xml.contains("socket-patch-vendor"));
    }

    /// fetch_pom_bytes rejects a non-2xx response with the status in the error.
    #[tokio::test]
    #[serial_test::serial]
    async fn fetch_pom_bytes_rejects_http_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pom_route = "/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.pom";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(pom_route))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = fetch_pom_bytes(&format!("{}{pom_route}", server.uri()))
            .await
            .unwrap_err();
        assert!(err.contains("HTTP 404"), "{err}");
    }

    /// fetch_pom_bytes rejects a body over MAX_POM_BYTES (a mirror serving the
    /// wrong thing) with the cap in the error.
    #[tokio::test]
    #[serial_test::serial]
    async fn fetch_pom_bytes_rejects_oversize_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let pom_route = "/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.pom";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(pom_route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; MAX_POM_BYTES + 1]))
            .mount(&server)
            .await;
        let err = fetch_pom_bytes(&format!("{}{pom_route}", server.uri()))
            .await
            .unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    /// Dry-run revert on the byte-identical fast path: reports success, warns
    /// nothing, and touches neither pom.xml nor the artifact.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_dry_run_touches_nothing_on_fast_path() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let entry = legacy_vendor(root, &record).await;
        let wired = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, /*dry_run=*/ true).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "a clean dry-run revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            wired,
            "dry run must not touch pom.xml"
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "dry run must not delete the artifact"
        );
    }

    /// Dry-run revert on the diverged (excise) path: likewise touches nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn revert_dry_run_touches_nothing_on_excise_path() {
        let (dir, _, _, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let entry = legacy_vendor(root, &record).await;

        // A user edit after vendoring forces the excise path.
        let wired = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let edited = wired.replacen(
            "</project>",
            "  <properties>\n  </properties>\n</project>",
            1,
        );
        tokio::fs::write(root.join(PROJECT_POM), &edited)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, /*dry_run=*/ true).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "our block is still present — not drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            edited,
            "dry run must not excise"
        );
        assert!(
            root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "dry run must not delete the artifact"
        );
    }

    /// strip_empty_repositories early returns: missing open marker, and open
    /// marker with a differently-rendered close — both leave the pom unchanged.
    #[test]
    #[serial_test::serial]
    fn strip_empty_repositories_missing_markers_left_unchanged() {
        // No two-space open marker at all.
        let no_open = "<project>\n</project>\n";
        assert_eq!(strip_empty_repositories(no_open), no_open);
        // Open marker present, but the close is rendered differently (no
        // leading two-space + newline form) → not our section, untouched.
        let no_close = "<project>\n  <repositories>\n    <repository/></repositories></project>";
        assert_eq!(strip_empty_repositories(no_close), no_close);
    }

    /// Mount a granted service response serving `body` as the prebuilt jar.
    async fn mount_granted_jar(body: &[u8]) -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let sri = crate::vendor::npm_pack::PackedTarball::from_bytes(body).integrity;
        let serve_path = "/patch/maven/commons-text/1.10.0/tok/uuid/commons-text-1.10.0.jar";
        let server = MockServer::start().await;
        let serve_url = format!("{}{serve_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": { "sha512": sri } }]
                }}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(serve_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;
        server
    }

    /// A served jar that passes the SRI floor but whose patched
    /// member does NOT carry the record's afterHash must never be accepted.
    /// Under `service` it is a refusal with nothing written.
    #[tokio::test]
    #[serial_test::serial]
    async fn service_jar_failing_after_hashes_refused_under_service() {
        let server = mount_granted_jar(&make_jar(PRISTINE)).await;
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let cfg = service_cfg(
            Some(&server.uri()),
            crate::vendor::VendorSource::Service,
            false,
        );
        let outcome = run_vendor_with_service(root, &blobs, &installed, &record, &cfg).await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("an unpatched service jar was accepted: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(".socket").exists(), "nothing written");
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            project_pom()
        );
    }

    /// Under `auto`: the bad served jar falls back (loudly) to the
    /// local rebuild, so the committed jar really carries the patch and a
    /// re-run is in sync (no perpetual rebuild).
    #[tokio::test]
    #[serial_test::serial]
    async fn service_jar_failing_after_hashes_never_uses_local_jar() {
        let server = mount_granted_jar(&make_jar(PRISTINE)).await;
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let cfg = service_cfg(
            Some(&server.uri()),
            crate::vendor::VendorSource::Service,
            false,
        );
        let error = crate::vendor::test_support::expect_failure(
            run_vendor_with_service(root, &blobs, &installed, &record, &cfg).await,
        );
        assert!(
            error.contains("does not carry the patched files"),
            "{error}"
        );
        assert!(!root.join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            project_pom()
        );
    }

    /// `--vendor-source=service` with no configured client must
    /// fail closed, never quietly build locally.
    #[tokio::test]
    #[serial_test::serial]
    async fn service_mode_without_client_refuses() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let cfg = service_cfg(None, crate::vendor::VendorSource::Service, false);
        let outcome = run_vendor_with_service(root, &blobs, &installed, &record, &cfg).await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("service mode without a client built locally: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root.join(".socket").exists(), "nothing written");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_upstream_checksums_are_independent_of_cache_sidecars() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let _reg = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
        let cfg = service_cfg(None, crate::vendor::VendorSource::Service, false);
        let bytes = b"upstream";
        let route = "/org/example/foo/1/foo-1.jar";
        Mock::given(method("GET"))
            .and(path(format!("{route}.sha512")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(hex::encode(sha2::Sha512::digest(bytes))),
            )
            .mount(&server)
            .await;
        assert!(
            verify_jvm_upstream(bytes, "org.example", "foo", "1", "jar", Some(&cfg))
                .await
                .is_ok()
        );
        assert!(
            verify_jvm_upstream(b"corrupt", "org.example", "foo", "1", "jar", Some(&cfg))
                .await
                .unwrap_err()
                .contains("checksum mismatch")
        );
        server.reset().await;
        Mock::given(method("GET"))
            .and(path(format!("{route}.sha1")))
            .respond_with(ResponseTemplate::new(200).set_body_string(sha1_hex(bytes)))
            .mount(&server)
            .await;
        assert!(
            verify_jvm_upstream(bytes, "org.example", "foo", "1", "jar", Some(&cfg))
                .await
                .is_ok()
        );
        server.reset().await;
        assert!(
            verify_jvm_upstream(bytes, "org.example", "foo", "1", "jar", Some(&cfg))
                .await
                .is_err()
        );
        let mut offline = cfg;
        offline.offline = true;
        assert!(
            verify_jvm_upstream(bytes, "org.example", "foo", "1", "jar", Some(&offline))
                .await
                .is_ok()
        );
    }

    // ── JVM backend glue ──

    const REACTOR_ROOT: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
        <groupId>t</groupId>\n  <artifactId>root</artifactId>\n  <version>1</version>\n  \
        <packaging>pom</packaging>\n  <modules>\n    <module>a</module>\n  </modules>\n</project>\n";

    fn reactor_module() -> String {
        "<project>\n  <parent>\n    <groupId>t</groupId>\n    <artifactId>root</artifactId>\n    \
         <version>1</version>\n  </parent>\n  <artifactId>a</artifactId>\n  <dependencies>\n    \
         <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
         <version>1.10.0</version></dependency>\n  </dependencies>\n</project>\n"
            .to_string()
    }

    async fn reactor_fixture(
        with_local_jar: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let fx = fixture(Some(REACTOR_ROOT), with_local_jar, true).await;
        let a = fx.0.path().join("a");
        tokio::fs::create_dir_all(&a).await.unwrap();
        tokio::fs::write(a.join("pom.xml"), reactor_module())
            .await
            .unwrap();
        fx
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn corrupt_jvm_ledger_refuses_without_losing_revert_records() {
        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(root.join(".socket/vendor/state.json"), "{corrupt").unwrap();
        let (code, _) = unwrap_refused(run_jvm(root, &blobs, &installed, &record, None).await);
        assert_eq!(code, "vendor_state_unreadable");
        assert_eq!(
            std::fs::read_to_string(root.join("pom.xml")).unwrap(),
            REACTOR_ROOT
        );
        assert_eq!(
            std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap(),
            "{corrupt"
        );
        assert!(!root.join(".socket/vendor/maven2").exists());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn empty_jvm_patch_still_validates_the_reactor_layout() {
        let (dir, blobs, installed, mut record) = reactor_fixture(true).await;
        record.files.clear();
        std::fs::remove_file(dir.path().join("a/pom.xml")).unwrap();
        let (code, detail) =
            unwrap_refused(run_jvm(dir.path(), &blobs, &installed, &record, None).await);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(detail.contains("module"), "{detail}");
        assert!(!dir.path().join(".socket").exists());
    }

    async fn run_jvm(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        service: Option<&VendorServiceConfig>,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        let fixture = if service.is_none() {
            Some(
                crate::vendor::test_support::service_fixture::Fixture::new(
                    PURL,
                    installed.into(),
                    record,
                    &sources,
                )
                .await,
            )
        } else {
            None
        };
        vendor_maven_jvm(
            super::super::jvm::Shape::MavenReactor,
            PURL,
            installed,
            root,
            record,
            &sources,
            false,
            false,
            service.or_else(|| fixture.as_ref().map(|f| &f.cfg)),
        )
        .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_redownload_restores_missing_tree_and_preserves_project_wiring() {
        for gradle in [false, true] {
            let (dir, blobs, installed, record) = reactor_fixture(true).await;
            let root = dir.path();
            let shape = if gradle {
                tokio::fs::remove_file(root.join("pom.xml")).await.unwrap();
                tokio::fs::write(
                    root.join("settings.gradle"),
                    "rootProject.name = 'fixture'\n",
                )
                .await
                .unwrap();
                tokio::fs::write(root.join("build.gradle"), "plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.apache.commons:commons-text:1.10.0' }\n").await.unwrap();
                super::super::jvm::Shape::Gradle
            } else {
                super::super::jvm::Shape::MavenReactor
            };
            let sources = PatchSources::blobs_only(&blobs);
            let service = crate::vendor::test_support::service_fixture::Fixture::new(
                PURL,
                installed.as_path().into(),
                &record,
                &sources,
            )
            .await;
            let (result, entry, _) = unwrap_done(
                vendor_maven_jvm(
                    shape,
                    PURL,
                    &installed,
                    root,
                    &record,
                    &sources,
                    false,
                    false,
                    Some(&service.cfg),
                )
                .await,
            );
            assert!(result.success, "gradle={gradle}: {:?}", result.error);
            let entry = entry.unwrap();
            crate::vendor::test_support::persist(root, PURL, entry.clone()).await;
            let snapshot = crate::vendor::test_support::tree_snapshot(root);
            let jar = root.join(&entry.artifact.path);
            tokio::fs::remove_dir_all(jar.parent().unwrap())
                .await
                .unwrap();
            crate::vendor::redownload::restore(root, &entry, &record, &service.cfg)
                .await
                .unwrap();
            assert_eq!(
                crate::vendor::test_support::tree_snapshot(root),
                snapshot,
                "gradle={gradle}"
            );
            assert_eq!(
                crate::vendor::check_vendored_artifact(root, &entry, &record).await,
                crate::vendor::ArtifactHealth::Healthy
            );
        }
    }

    /// A re-run over a committed tree that holds this patch needs no jar
    /// source: no cached jar, and `--vendor-source=service --offline`.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_rerun_is_in_sync_without_any_jar_source() {
        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let (result, entry, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success, "{result:?}");
        let entry = entry.expect("ledger entry");
        assert!(super::super::jvm::apply::is_jvm_entry(&entry));
        tokio::fs::remove_file(installed.join("commons-text-1.10.0.jar"))
            .await
            .unwrap();
        tokio::fs::remove_file(installed.join("commons-text-1.10.0.pom"))
            .await
            .unwrap();
        let cfg = crate::vendor::test_support::service_cfg(
            "http://127.0.0.1:9",
            crate::vendor::VendorSource::Service,
            true,
        );
        let (result, again, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, Some(&cfg)).await);
        assert!(result.success && again.is_none(), "{result:?}");
        assert!(
            jvm_committed_patch(super::super::jvm::Shape::MavenReactor, PURL, root, &record)
                .await
                .is_some(),
            "the service prefetch plan skips an in-sync JVM entry"
        );
        // A tampered committed jar is not in sync: the jar source is needed.
        let jar = root.join(&entry.artifact.path);
        tokio::fs::write(&jar, make_jar(PRISTINE)).await.unwrap();
        let (code, detail) = unwrap_refused(run_jvm(root, &blobs, &installed, &record, None).await);
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("patch service request failed"), "{detail}");
    }

    /// A jar over the limits of the reader jars used to share with Python
    /// wheels (10,000 entries, 64 MiB inflated) vendors, verifies (what
    /// `vex` and `vendor --check` ask), passes an online re-run's comparison
    /// with upstream, and is repaired.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_jar_over_the_wheel_reader_limits_vendors_verifies_and_repairs() {
        use crate::patch::jar_members::testing::big_jar;
        use crate::vendor::{check_vendored_artifact, ArtifactHealth};

        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let upstream = big_jar(10_001, 65 * 1024 * 1024, &[(JAR_FILE, PRISTINE)]);
        assert!(crate::vendor::verify::read_zip_bytes_to_map(&upstream).is_err());
        tokio::fs::write(installed.join("commons-text-1.10.0.jar"), &upstream)
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&blobs);
        let service = crate::vendor::test_support::service_fixture::Fixture::new(
            PURL,
            installed.as_path().into(),
            &record,
            &sources,
        )
        .await;

        let (result, entry, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, Some(&service.cfg)).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("ledger entry");
        crate::vendor::test_support::persist(root, PURL, entry.clone()).await;
        let jar = root.join(&entry.artifact.path);
        let committed = std::fs::read(&jar).unwrap();
        assert_eq!(
            crate::patch::jar_members::Digests::of_bytes(&committed)
                .unwrap()
                .len(),
            10_002
        );

        assert_eq!(
            crate::vendor::verify::verify_vendored_patch_record(root, &entry, &record).await,
            Ok(())
        );
        assert_eq!(
            check_vendored_artifact(root, &entry, &record).await,
            ArtifactHealth::Healthy
        );

        // Online, the committed jar is held to upstream outside the patch.
        let (again, _, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, Some(&service.cfg)).await);
        assert!(again.success, "{:?}", again.error);

        let snapshot = crate::vendor::test_support::tree_snapshot(root);
        tokio::fs::remove_dir_all(jar.parent().unwrap())
            .await
            .unwrap();
        crate::vendor::redownload::restore(root, &entry, &record, &service.cfg)
            .await
            .unwrap();
        assert_eq!(crate::vendor::test_support::tree_snapshot(root), snapshot);
        assert_eq!(
            check_vendored_artifact(root, &entry, &record).await,
            ArtifactHealth::Healthy
        );
    }

    /// A committed jar whose patched member is past the jar limits is
    /// reported as too large, not as unreadable, and is repair's to put
    /// back: the jar the ledger records was within them.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_committed_jar_past_the_jar_limits_is_too_large() {
        use crate::vendor::{check_vendored_artifact, ArtifactHealth};

        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let (result, entry, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("ledger entry");
        // The member the check must inflate is 65 MiB of zeros, deflated to
        // a few kilobytes: over what a jar that small may inflate to.
        let mut bomb = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        bomb.start_file(JAR_FILE, opts).unwrap();
        std::io::copy(&mut std::io::repeat(0).take(65 * 1024 * 1024), &mut bomb).unwrap();
        std::fs::write(
            root.join(&entry.artifact.path),
            bomb.finish().unwrap().into_inner(),
        )
        .unwrap();
        assert_eq!(
            crate::vendor::verify::verify_vendored_patch_record(root, &entry, &record).await,
            Err("vendor_artifact_too_large".to_string())
        );
        assert_eq!(
            check_vendored_artifact(root, &entry, &record).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_artifact_too_large".to_string()
            }
        );
        // The recorded jar is within the limits: repair puts it back.
        crate::vendor::test_support::persist(root, PURL, entry.clone()).await;
        let sources = PatchSources::blobs_only(&blobs);
        let service = crate::vendor::test_support::service_fixture::Fixture::new(
            PURL,
            installed.as_path().into(),
            &record,
            &sources,
        )
        .await;
        crate::vendor::redownload::restore(root, &entry, &record, &service.cfg)
            .await
            .unwrap();
        assert_eq!(
            check_vendored_artifact(root, &entry, &record).await,
            ArtifactHealth::Healthy
        );
    }

    /// Vendoring needs the patch service and this machine, not the
    /// registry: no upstream jar is fetched to compare with, and none is
    /// missed. The one comparison is with the jar the build already
    /// resolves from its local repository. With none there, the service's
    /// jar is committed, whatever it holds beside the patch, and nothing is
    /// said. With one that matches outside the patch (the original, or the
    /// jar agent mode patched there) it is committed. With one that
    /// differs it is refused, naming the members, and nothing is written.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_first_vendoring_compares_with_the_local_jar_and_asks_the_registry_for_none() {
        use crate::patch::jar_members::testing::jar_with_modes;
        const MANIFEST: (&str, &[u8], Option<u32>) =
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", None);
        const NOTICE: (&str, &[u8], Option<u32>) = (JAR_FILE, PATCHED, None);
        const CLASS: &str = "org/apache/commons/text/StringSubstitutor.class";
        const CODE: (&str, &[u8], Option<u32>) = (CLASS, b"\xca\xfe\xba\xbe-fake-class", None);
        const ADDED: &str = "org/apache/commons/text/Added.class";
        let honest = make_jar(PATCHED);
        let another_base =
            jar_with_modes(&[MANIFEST, NOTICE, (CLASS, b"another release's class", None)]);
        let with_signatures = jar_with_modes(&[
            ("META-INF/", b"", None),
            MANIFEST,
            ("META-INF/APACHE.SF", b"signature", None),
            ("META-INF/APACHE.RSA", b"signature", None),
            (JAR_FILE, PRISTINE, None),
            ("org/apache/commons/text/", b"", None),
            CODE,
        ]);
        // (the service's jar, the jar in the local repository, the refusal)
        let cases: Vec<(Vec<u8>, Option<Vec<u8>>, Option<String>)> = vec![
            (honest.clone(), None, None),
            (another_base.clone(), None, None),
            (honest.clone(), Some(make_jar(PRISTINE)), None),
            // Directory entries and signature files may differ.
            (honest.clone(), Some(with_signatures), None),
            // The jar agent mode patched there, with the `.sha1` it wrote.
            (honest.clone(), Some(honest.clone()), None),
            (
                another_base,
                Some(make_jar(PRISTINE)),
                Some(format!("1 changed (`{CLASS}`)")),
            ),
            (
                jar_with_modes(&[MANIFEST, NOTICE, CODE, (ADDED, b"\xca\xfe\xba\xbe", None)]),
                Some(make_jar(PRISTINE)),
                Some(format!("1 added (`{ADDED}`)")),
            ),
            (
                // A symlink-mode entry is not a regular file to a zip
                // reader, and is a class to the JVM.
                jar_with_modes(&[MANIFEST, NOTICE, CODE, (ADDED, b"target", Some(0o120777))]),
                Some(make_jar(PRISTINE)),
                Some(format!("1 added (`{ADDED}`)")),
            ),
            (
                jar_with_modes(&[MANIFEST, NOTICE]),
                Some(make_jar(PRISTINE)),
                Some(format!("1 missing (`{CLASS}`)")),
            ),
        ];
        for (served, local_jar, refusal) in cases {
            let (dir, blobs, installed, record) = reactor_fixture(false).await;
            let root = dir.path();
            if let Some(local_jar) = &local_jar {
                let jar = installed.join("commons-text-1.10.0.jar");
                tokio::fs::write(&jar, local_jar).await.unwrap();
                tokio::fs::write(jar.with_extension("jar.sha1"), sha1_hex(local_jar))
                    .await
                    .unwrap();
            }
            // The service answers; every registry route is a 404.
            let server = mount_granted_jar(&served).await;
            let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
            let cfg = service_cfg(
                Some(&server.uri()),
                crate::vendor::VendorSource::Service,
                false,
            );
            let before = crate::vendor::test_support::tree_snapshot(root);
            let outcome = run_jvm(root, &blobs, &installed, &record, Some(&cfg)).await;
            let asked_for_a_jar = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| r.url.path().starts_with("/org/") && r.url.path().contains(".jar"));
            assert!(!asked_for_a_jar, "no jar is asked of the registry");
            match refusal {
                Some(difference) => {
                    let (code, detail) = unwrap_refused(outcome);
                    assert_eq!(code, "vendor_prebuilt_integrity_mismatch", "{difference}");
                    assert_eq!(
                        detail,
                        format!(
                            "the patch service's jar differs from commons-text-1.10.0.jar, the \
                             jar this build resolves from its local repository, outside the \
                             patched members: {difference}. The build uses a jar that is not \
                             the one the patch was made from, so the vendored jar would change \
                             more than the patch"
                        )
                    );
                    assert_eq!(
                        crate::vendor::test_support::tree_snapshot(root),
                        before,
                        "{difference}: nothing is written"
                    );
                    assert!(!root.join(".socket").exists(), "{difference}");
                }
                None => {
                    let (result, entry, warnings) = unwrap_done(outcome);
                    assert!(result.success && entry.is_some(), "{:?}", result.error);
                    assert!(
                        !warnings
                            .iter()
                            .any(|w| w.code == "vendor_jvm_upstream_unverified"),
                        "nothing is said of a comparison that was not made: {warnings:?}"
                    );
                    // A re-run over the committed tree needs no jar either.
                    crate::vendor::test_support::persist(root, PURL, entry.unwrap()).await;
                    let (again, _, _) =
                        unwrap_done(run_jvm(root, &blobs, &installed, &record, Some(&cfg)).await);
                    assert!(again.success, "{:?}", again.error);
                }
            }
        }
    }

    /// The vendored comparison accepts a jar the patch service re-signed
    /// (its signature files, and the manifest digests of the member the
    /// patch changes) and refuses any other manifest change.
    #[test]
    fn a_resigned_provider_jar_is_upstream_outside_the_patch() {
        use crate::patch::jar_manifest::fixture::{edited, record as resigned, SERVED, UPSTREAM};
        let files = resigned();
        for committed in [false, true] {
            assert_eq!(
                verify_unpatched_jar_members(("lib-1.0.jar", UPSTREAM), SERVED, &files, committed),
                Ok(())
            );
        }
        let tampered = edited(|m| m.replace("Implementation-Title: ", "Implementation-Title: x"));
        let (code, detail) =
            verify_unpatched_jar_members(("lib-1.0.jar", UPSTREAM), &tampered, &files, false)
                .unwrap_err();
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(
            detail.contains("1 changed (`META-INF/MANIFEST.MF`)")
                && detail.contains("its main attributes differ"),
            "{detail}"
        );
    }

    /// commons-text as log4j-core is published: a sibling's version comes
    /// from the parent's management, written `${project.version}`.
    const CHILD_OF_PARENT_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
        <parent><groupId>org.apache.commons</groupId><artifactId>commons-parent</artifactId>\
        <version>54</version></parent><artifactId>commons-text</artifactId>\
        <version>1.10.0</version><dependencies><dependency><groupId>org.apache.commons</groupId>\
        <artifactId>commons-lang3</artifactId></dependency></dependencies></project>";
    const PARENT_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
        <groupId>org.apache.commons</groupId><artifactId>commons-parent</artifactId>\
        <version>54</version><packaging>pom</packaging><dependencyManagement><dependencies>\
        <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
        <version>${project.version}</version></dependency></dependencies></dependencyManagement>\
        </project>";

    /// The reactor fixture with [`CHILD_OF_PARENT_POM`] as the cached
    /// upstream pom; `parent` puts [`PARENT_POM`] in the same repository.
    async fn inheriting_fixture(
        parent: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let fx = reactor_fixture(true).await;
        std::fs::write(fx.2.join("commons-text-1.10.0.pom"), CHILD_OF_PARENT_POM).unwrap();
        if parent {
            let dir = fx.0.path().join("m2/org/apache/commons/commons-parent/54");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("commons-parent-54.pom"), PARENT_POM).unwrap();
        }
        fx
    }

    fn upstream_status(entry: &VendorEntry) -> &str {
        entry
            .wiring
            .iter()
            .find(|w| w.kind == super::super::jvm::UPSTREAM_KIND)
            .map(super::super::jvm::op_of)
            .unwrap_or_default()
    }

    /// VJ-D1 end to end: the parent's `${project.version}` would read the
    /// suffixed version in the vendored pom, so the sibling it manages is
    /// declared there at the base version. VJ-D2: the parent is in the
    /// local repository and on no registry (the fixture's serves the
    /// artifact alone), which is every corporate parent; it is used, and
    /// the entry says its upstream files were not all registry-verified.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_parent_naming_the_poms_version_is_vendored_at_the_base_version() {
        let (dir, blobs, installed, record) = inheriting_fixture(true).await;
        let root = dir.path();
        let (result, entry, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success, "{result:?}");
        let entry = entry.expect("ledger entry");
        let jar = root.join(&entry.artifact.path);
        let pom = std::fs::read_to_string(jar.with_extension("pom")).unwrap();
        assert!(pom.contains("socket-patch:inherited:begin"), "{pom}");
        assert!(
            pom.contains("<artifactId>commons-lang3</artifactId><version>1.10.0</version>"),
            "{pom}"
        );
        assert!(!pom.contains("${project.version}"), "{pom}");
        assert_eq!(upstream_status(&entry), "local_unverified");
        crate::vendor::test_support::persist(root, PURL, entry.clone()).await;
        // In sync on a re-run, online or offline with the parent gone from
        // every cache (a fresh checkout), and under `--check` either way.
        let (_, again, _) = unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(again.is_none(), "an in-sync re-run records nothing");
        let m2 = root.join("m2");
        super::super::jvm::apply::check_entry(root, &entry, Some(&m2)).expect("with the parent");
        std::fs::remove_dir_all(m2.join("org/apache/commons/commons-parent")).unwrap();
        super::super::jvm::apply::check_entry(root, &entry, Some(&m2)).expect("without it");
        let offline = crate::vendor::test_support::service_cfg(
            "http://127.0.0.1:9",
            crate::vendor::VendorSource::Service,
            true,
        );
        let (result, again, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, Some(&offline)).await);
        assert!(result.success && again.is_none(), "{result:?}");
        assert_eq!(
            std::fs::read_to_string(jar.with_extension("pom")).unwrap(),
            pom
        );
    }

    /// Without the parent the suffixed pom cannot be checked, and a pom
    /// that may resolve `commons-lang3:1.10.0-socket.<hex8>` is not written.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unreadable_parent_refuses_a_first_vendoring() {
        let (dir, blobs, installed, record) = inheriting_fixture(false).await;
        let root = dir.path();
        let (code, detail) = unwrap_refused(run_jvm(root, &blobs, &installed, &record, None).await);
        assert_eq!(code, "vendor_jvm_upstream_unavailable");
        assert!(
            detail.starts_with("reason: parent_unavailable: ")
                && detail.contains("org.apache.commons:commons-parent:54"),
            "{detail}"
        );
        assert!(!root.join(".socket").exists(), "nothing written");
    }

    /// VJ-D2: a root's parent from a corporate repository is in the local
    /// repository and on no public registry. The pin is weighed against
    /// the local copy, as Maven reads it: before, the registry's 404 for
    /// its checksum made the pom "in no local Maven repository", the root
    /// stayed unpinned and a transitive-only patch was refused.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_parent_on_no_registry_is_read_from_the_local_repository() {
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        std::fs::write(
            root.join("pom.xml"),
            "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
             <groupId>com.corp</groupId>\n    <artifactId>corp-parent</artifactId>\n    \
             <version>1</version>\n    <relativePath/>\n  </parent>\n  <artifactId>app</artifactId>\n  \
             <dependencies>\n    <dependency>\n      <groupId>com.corp</groupId>\n      \
             <artifactId>uses-commons-text</artifactId>\n      <version>1</version>\n    \
             </dependency>\n  </dependencies>\n</project>\n",
        )
        .unwrap();
        let corp = root.join("m2/com/corp/corp-parent/1");
        std::fs::create_dir_all(&corp).unwrap();
        std::fs::write(
            corp.join("corp-parent-1.pom"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.corp</groupId>\
             <artifactId>corp-parent</artifactId><version>1</version><packaging>pom</packaging>\
             </project>",
        )
        .unwrap();
        // The pom of what brings commons-text in: the pin is written only
        // because Maven selects 1.10.0 through it.
        let uses = root.join("m2/com/corp/uses-commons-text/1");
        std::fs::create_dir_all(&uses).unwrap();
        std::fs::write(
            uses.join("uses-commons-text-1.pom"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.corp</groupId>\
             <artifactId>uses-commons-text</artifactId><version>1</version><dependencies>\
             <dependency><groupId>org.apache.commons</groupId>\
             <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        // What commons-text depends on, as a resolved project holds it:
        // with a pom missing, the build is not known to select 1.10.0.
        let lang3 = root.join("m2/org/apache/commons/commons-lang3/3.12.0");
        std::fs::create_dir_all(&lang3).unwrap();
        std::fs::write(
            lang3.join("commons-lang3-3.12.0.pom"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.apache.commons</groupId>\
             <artifactId>commons-lang3</artifactId><version>3.12.0</version></project>",
        )
        .unwrap();
        let (result, entry, warnings) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success, "{result:?}");
        assert!(
            !warnings
                .iter()
                .any(|w| w.detail.contains("management_unresolved")),
            "{warnings:?}"
        );
        let pom = std::fs::read_to_string(root.join("pom.xml")).unwrap();
        assert!(
            pom.contains("<version>1.10.0-socket.9f6b2c4e</version>"),
            "{pom}"
        );
        // The corporate pom only decided the pin; nothing of it is vendored.
        assert_eq!(upstream_status(&entry.unwrap()), "registry_verified");
    }

    /// A file the index does not list in the vendored tree (a Finder
    /// `.DS_Store`, a stray directory) fails the Gradle build and
    /// `vendor --check` (#656), so a re-run is not in sync: a dry run
    /// previews the re-vendor and a real one sweeps the strays.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_rerun_sweeps_unindexed_tree_files() {
        for gradle in [false, true] {
            let (dir, blobs, installed, record) = reactor_fixture(true).await;
            let root = dir.path();
            let shape = if gradle {
                tokio::fs::remove_file(root.join("pom.xml")).await.unwrap();
                tokio::fs::write(
                    root.join("settings.gradle"),
                    "rootProject.name = 'fixture'\n",
                )
                .await
                .unwrap();
                tokio::fs::write(root.join("build.gradle"), "plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.apache.commons:commons-text:1.10.0' }\n").await.unwrap();
                super::super::jvm::Shape::Gradle
            } else {
                super::super::jvm::Shape::MavenReactor
            };
            let sources = PatchSources::blobs_only(&blobs);
            let service = crate::vendor::test_support::service_fixture::Fixture::new(
                PURL,
                installed.as_path().into(),
                &record,
                &sources,
            )
            .await;
            let run = |dry_run| {
                vendor_maven_jvm(
                    shape,
                    PURL,
                    &installed,
                    root,
                    &record,
                    &sources,
                    dry_run,
                    false,
                    Some(&service.cfg),
                )
            };
            let (result, entry, _) = unwrap_done(run(false).await);
            assert!(result.success, "gradle={gradle}: {:?}", result.error);
            let entry = entry.unwrap();
            crate::vendor::test_support::persist(root, PURL, entry.clone()).await;
            let (_, again, _) = unwrap_done(run(false).await);
            assert!(
                again.is_none(),
                "gradle={gradle}: a clean re-run is in sync"
            );

            let tree = root.join(&entry.artifact.path);
            let tree = tree.parent().unwrap();
            let ds_store = tree.join(".DS_Store");
            let stray_dir = tree.join("backup");
            tokio::fs::write(&ds_store, b"\0\0\0\x01Bud1")
                .await
                .unwrap();
            tokio::fs::create_dir_all(&stray_dir).await.unwrap();
            tokio::fs::write(stray_dir.join("old.jar"), b"x")
                .await
                .unwrap();
            let check = super::super::jvm::apply::check_entry(root, &entry, None).unwrap_err();
            assert!(check.contains("unindexed vendored file"), "{check}");

            let (preview, none, _) = unwrap_done(run(true).await);
            assert!(none.is_none() && preview.success, "gradle={gradle}");
            assert!(
                preview
                    .files_verified
                    .iter()
                    .all(|f| f.status == crate::patch::apply::VerifyStatus::Ready),
                "gradle={gradle}: the dry run previews a re-vendor: {preview:?}"
            );
            assert!(
                ds_store.exists() && stray_dir.exists(),
                "dry run writes nothing"
            );

            let (result, swept, _) = unwrap_done(run(false).await);
            assert!(result.success, "gradle={gradle}: {:?}", result.error);
            let swept = swept.expect("the re-run is not in sync");
            assert!(!ds_store.exists(), "gradle={gradle}: .DS_Store swept");
            assert!(
                !stray_dir.exists(),
                "gradle={gradle}: stray directory swept"
            );
            assert!(root.join(&entry.artifact.path).is_file(), "the jar stays");
            crate::vendor::test_support::persist(root, PURL, swept.clone()).await;
            super::super::jvm::apply::check_entry(root, &swept, None)
                .unwrap_or_else(|e| panic!("gradle={gradle}: {e}"));
            let (_, again, _) = unwrap_done(run(false).await);
            assert!(again.is_none(), "gradle={gradle}: in sync after the sweep");
        }
    }

    /// A tree file the committed ledger records but the new plan drops is
    /// not a stray: the pre-commit sweep would delete it even when the
    /// write is then refused or rolled back, leaving the restored ledger
    /// and index naming a missing file. It goes only after a commit,
    /// through `sweep_replaced_tree`.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_rerun_keeps_tree_files_the_ledger_records() {
        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let (result, entry, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success, "{result:?}");
        let mut entry = entry.unwrap();
        let tree = std::path::Path::new(&entry.artifact.path)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let name = entry
            .artifact
            .path
            .rsplit('/')
            .next()
            .unwrap()
            .replace(".jar", "-dropped.jar");
        let dropped = format!("{tree}/{name}");
        tokio::fs::write(root.join(&dropped), b"OLD CLASSIFIER")
            .await
            .unwrap();
        entry.wiring.push(WiringRecord {
            file: dropped.clone(),
            kind: super::super::jvm::TREE_KIND.into(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: Some(serde_json::Value::String(super::super::jvm::sha256_hex(
                b"OLD CLASSIFIER",
            ))),
        });
        crate::vendor::test_support::persist(root, PURL, entry).await;
        let (result, again, _) =
            unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(result.success && again.is_none(), "in sync: {result:?}");
        assert!(root.join(&dropped).is_file(), "a recorded file is kept");
        // A file nothing records is still swept.
        tokio::fs::write(root.join(&tree).join(".DS_Store"), b"x")
            .await
            .unwrap();
        let (_, swept, _) = unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        assert!(swept.is_some() && !root.join(&tree).join(".DS_Store").exists());
        assert!(root.join(&dropped).is_file(), "still kept");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_revert_honours_keep_artifact_and_restores_the_poms() {
        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let (_, entry, _) = unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        let entry = entry.unwrap();
        let out = revert_maven_opts(
            &entry,
            root,
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(
            out.success && !out.kept_artifact && out.warnings.is_empty(),
            "{out:?}"
        );
        assert!(
            root.join(&entry.artifact.path).is_file(),
            "--preserve-state keeps the jar"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("pom.xml")).unwrap(),
            REACTOR_ROOT
        );
        assert_eq!(
            std::fs::read_to_string(root.join("a/pom.xml")).unwrap(),
            reactor_module()
        );
        assert!(!root.join(".mvn").exists());
    }

    /// A forged JVM entry (tamper-able state.json) is refused before any
    /// disk access.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_revert_refuses_forged_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        tokio::fs::create_dir_all(root.join("src")).await.unwrap();
        tokio::fs::write(root.join("src/Main.java"), "class Main {}\n")
            .await
            .unwrap();
        let tree = |file: &str| WiringRecord {
            file: file.to_string(),
            kind: super::super::jvm::TREE_KIND.to_string(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: Some(Value::String(hex::encode(Sha256::digest(
                b"class Main {}\n",
            )))),
        };
        let forged = |uuid: &str, file: &str| VendorEntry {
            uuid: uuid.to_string(),
            wiring: vec![tree(file)],
            ..maven_entry(
                PURL.to_string(),
                &PatchRecord {
                    uuid: UUID.to_string(),
                    ..fixture_record()
                },
                String::new(),
                b"",
                Vec::new(),
            )
        };
        for entry in [
            forged("../../../NOT-A-UUID", "src/Main.java"),
            forged(UUID, "src/Main.java"),
        ] {
            let out = revert_maven_opts(&entry, root, RevertOpts::new(false)).await;
            assert!(!out.success, "{out:?}");
        }
        assert!(root.join("src/Main.java").is_file());
    }

    /// A module of an ancestor Maven reactor is refused `not_build_root`
    /// by both [`vendor_maven`] and [`jvm_gate_preflight`], so a hosted
    /// pin is kept rather than restored before a refusal that writes
    /// nothing; the reactor root itself passes the preflight.
    #[tokio::test]
    #[serial_test::serial]
    async fn maven_reactor_module_refuses_not_build_root_in_preflight() {
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(
            root.join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0</version><packaging>pom</packaging>\
             <modules><module>app</module></modules></project>\n",
        )
        .unwrap();
        let module = root.join("app");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(
            module.join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0</version></parent>\
             <artifactId>app</artifactId><dependencies><dependency>\
             <groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
             <version>1.10.0</version></dependency></dependencies></project>\n",
        )
        .unwrap();
        let before = crate::vendor::test_support::tree_snapshot(root);
        let (code, detail) = jvm_gate_preflight(&module, PURL).await.unwrap_err();
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(
            detail.starts_with("reason: not_build_root: run vendor from reactor root "),
            "{detail}"
        );
        let (code, vendor_detail) =
            unwrap_refused(run_vendor(&module, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert_eq!(vendor_detail, detail);
        assert_eq!(crate::vendor::test_support::tree_snapshot(root), before);
        assert!(service_preflight(PURL, &module, &record).await.is_none());
        assert!(jvm_gate_preflight(root, PURL).await.is_ok());
    }

    /// #428: vendoring from a project of a Gradle build rooted above it
    /// (a literal or relocated include, includes that cannot be read, or a
    /// project with no settings of its own) refuses with `not_build_root`
    /// and writes nothing; a separate build below the root does not.
    #[tokio::test]
    #[serial_test::serial]
    async fn gradle_subproject_refuses_not_build_root_and_writes_nothing() {
        for (settings, body, project, own) in [
            (
                "settings.gradle",
                "include 'app'\n",
                "app",
                vec![("build.gradle", "plugins { id 'java' }\n")],
            ),
            (
                "settings.gradle.kts",
                "include(\":lib\")\nproject(\":lib\").projectDir = file(\"modules/lib\")\n",
                "modules/lib",
                vec![
                    ("build.gradle.kts", "plugins { java }\n"),
                    ("settings.gradle.kts", ""),
                ],
            ),
            (
                "settings.gradle",
                "include computedName\n",
                "app",
                vec![("settings.gradle", ""), ("build.gradle", "")],
            ),
            (
                "settings.gradle",
                "rootProject.name = 'x'\n",
                "tool",
                vec![("build.gradle", "")],
            ),
        ] {
            let (dir, blobs, installed, record) = fixture(None, true, true).await;
            let root = dir.path();
            std::fs::create_dir_all(root.join(".git")).unwrap();
            std::fs::write(root.join(settings), body).unwrap();
            let project = root.join(project);
            std::fs::create_dir_all(&project).unwrap();
            for (name, text) in &own {
                std::fs::write(project.join(name), text).unwrap();
            }
            let before = crate::vendor::test_support::tree_snapshot(root);
            let (code, detail) =
                unwrap_refused(run_vendor(&project, &blobs, &installed, &record, false).await);
            assert_eq!(code, "vendor_jvm_shape_unsupported", "{body}");
            assert!(
                detail.starts_with("reason: not_build_root: run vendor from Gradle root "),
                "{body}: {detail}"
            );
            assert_eq!(
                crate::vendor::test_support::tree_snapshot(root),
                before,
                "{body}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("settings.gradle"), "include 'app'\n").unwrap();
        std::fs::create_dir_all(root.join("tools/gen")).unwrap();
        std::fs::write(root.join("tools/gen/settings.gradle"), "").unwrap();
        std::fs::write(root.join("tools/gen/build.gradle"), "").unwrap();
        assert_eq!(not_build_root(&root.join("tools/gen")), None);
        assert_eq!(not_build_root(root), None);
        // Root settings that are not UTF-8 (a Latin-1 `©`) cannot rule out
        // an include: a project with settings of its own still refuses.
        std::fs::write(
            root.join("settings.gradle"),
            b"// \xa9 2026\ninclude 'tools:gen'\n",
        )
        .unwrap();
        let detail = not_build_root(&root.join("tools/gen")).unwrap();
        assert!(
            detail.starts_with("reason: not_build_root: run vendor from Gradle root "),
            "{detail}"
        );
    }

    /// The build-root walk climbs physical parents, so a RELATIVE project
    /// root still finds the build above it (the old lexical
    /// `project_root.ancestors()` saw no real ancestor of `.`), and the
    /// refusal names that root the way the caller spelled the project:
    /// not the canonical `/private/var/…` (macOS) or `\\?\C:\…` (Windows).
    #[cfg(unix)]
    #[test]
    fn not_build_root_walks_a_relative_root_and_names_the_callers_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("settings.gradle"), "include 'tools:gen'\n").unwrap();
        std::fs::create_dir_all(root.join("tools/gen")).unwrap();
        std::fs::write(root.join("tools/gen/build.gradle"), "").unwrap();
        let want = |shown: &Path| {
            Some(format!(
                "reason: not_build_root: run vendor from Gradle root {}",
                shown.display()
            ))
        };
        assert_eq!(not_build_root(&root.join("tools/gen")), want(root));

        // The same project reached by a path relative to the working
        // directory: up to `/`, then down.
        let cwd = std::env::current_dir().unwrap();
        let mut rel_root = PathBuf::new();
        for c in cwd.components() {
            if matches!(c, std::path::Component::Normal(_)) {
                rel_root.push("..");
            }
        }
        rel_root.push(root.strip_prefix("/").unwrap());
        assert!(rel_root.is_relative());
        assert_eq!(not_build_root(&rel_root.join("tools/gen")), want(&rel_root));
    }

    fn fixture_record() -> PatchRecord {
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_refuses_a_module_symlinked_outside_the_checkout() {
        let (dir, blobs, installed, record) = fixture(Some(REACTOR_ROOT), true, true).await;
        let root = dir.path();
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::write(outside.path().join("pom.xml"), reactor_module())
            .await
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("a")).unwrap();
        let (code, detail) = unwrap_refused(run_jvm(root, &blobs, &installed, &record, None).await);
        assert_eq!(code, "vendor_jvm_shape_unsupported");
        assert!(
            detail.starts_with("reason: build_file_outside_root: a "),
            "{detail}"
        );
        assert_eq!(
            std::fs::read_to_string(outside.path().join("pom.xml")).unwrap(),
            reactor_module()
        );
    }

    /// A ledger of JVM entries is not a legacy root.
    #[tokio::test]
    #[serial_test::serial]
    async fn jvm_entries_are_not_a_legacy_root() {
        let (dir, blobs, installed, record) = reactor_fixture(true).await;
        let root = dir.path();
        let (_, entry, _) = unwrap_done(run_jvm(root, &blobs, &installed, &record, None).await);
        crate::vendor::test_support::persist(root, PURL, entry.unwrap()).await;
        assert!(!legacy_root(root).await);
        assert_eq!(detect_shape(root), super::super::jvm::Shape::MavenReactor);
    }

    // ── #973: single-module poms through the planner ──

    /// A pre-v5 single-pom vendoring of `record` over the project pom, as
    /// the retired backend left it: the `.socket/vendor/maven/<uuid>` maven2
    /// tree, a `<repositories>` section before `</project>` and the
    /// `maven_pom_repository` ledger record (not persisted).
    async fn legacy_vendor(root: &Path, record: &PatchRecord) -> VendorEntry {
        let original = std::fs::read_to_string(root.join(PROJECT_POM)).unwrap();
        let jar = make_jar(PATCHED);
        write_maven_artifact(
            &root.join(leaf_rel()),
            "commons-text-1.10.0.jar",
            &jar,
            "commons-text-1.10.0.pom",
            UPSTREAM_POM,
        )
        .await
        .unwrap();
        let repo_id = format!("{VENDOR_REPO_ID_PREFIX}{}", record.uuid);
        let at = original.rfind("</project>").unwrap();
        let wired = format!(
            "{}  <repositories>\n{}  </repositories>\n{}",
            &original[..at],
            repository_block(&repo_id, &format!(".socket/vendor/maven/{}", record.uuid)),
            &original[at..]
        );
        std::fs::write(root.join(PROJECT_POM), &wired).unwrap();
        maven_entry(
            PURL.to_string(),
            record,
            jar_rel(),
            &jar,
            vec![WiringRecord {
                file: PROJECT_POM.to_string(),
                kind: REPO_WIRING_KIND.to_string(),
                action: WiringAction::Added,
                key: Some(repo_id),
                original: Some(Value::String(original)),
                new: Some(Value::String(wired)),
            }],
        )
    }

    /// A lone single-module pom is a reactor of one: a `jvm` entry with a
    /// suffixed pin, `.mvn/maven.config` and the `maven2` tree, the
    /// wrapper-less warnings, an in-sync re-run that writes nothing, and a
    /// byte-exact revert (LF and CRLF poms).
    #[tokio::test]
    #[serial_test::serial]
    async fn single_module_pom_vendors_through_the_planner() {
        for crlf in [false, true] {
            let pom = if crlf {
                project_pom().replace('\n', "\r\n")
            } else {
                project_pom().to_string()
            };
            let (dir, blobs, installed, record) = fixture(Some(&pom), true, true).await;
            let root = dir.path();
            let before = crate::vendor::test_support::tree_snapshot(root);
            assert!(service_preflight(PURL, root, &record).await.is_some());

            let (result, entry, warnings) =
                unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
            assert!(result.success, "crlf={crlf}: {:?}", result.error);
            let entry = entry.expect("ledger entry");
            assert_eq!(entry.ecosystem, layout::LEDGER_ECOSYSTEM);
            assert!(super::super::jvm::apply::is_jvm_entry(&entry));
            assert!(
                entry.artifact.path.starts_with(
                    ".socket/vendor/maven2/org/apache/commons/commons-text/1.10.0-socket."
                ),
                "{}",
                entry.artifact.path
            );
            let jar = std::fs::read(root.join(&entry.artifact.path)).unwrap();
            assert_eq!(read_jar_entry(&jar, JAR_FILE).as_deref(), Some(PATCHED));
            let wired = std::fs::read_to_string(root.join(PROJECT_POM)).unwrap();
            assert!(wired.contains("<version>1.10.0-socket."), "{wired}");
            assert!(!wired.contains(VENDOR_REPO_URL_PREFIX), "{wired}");
            assert!(root.join(".mvn/maven.config").is_file());
            assert!(!root.join(".socket/vendor/maven").exists());
            // No Maven Wrapper: both wrapper-less warnings.
            for reason in ["maven_f_outside_root", "maven_mirror_of_all"] {
                assert!(
                    warnings
                        .iter()
                        .any(|w| w.code == super::super::jvm::gradle::DEGRADED
                            && w.detail.starts_with(&format!("reason: {reason}: "))),
                    "crlf={crlf}: {reason}: {warnings:?}"
                );
            }
            assert!(
                !warnings
                    .iter()
                    .any(|w| w.code == "vendor_maven_local_cache_shadow"),
                "{warnings:?}"
            );
            crate::vendor::test_support::persist(root, PURL, entry.clone()).await;

            let snapshot = crate::vendor::test_support::tree_snapshot(root);
            let (result, again, _) =
                unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
            assert!(result.success && again.is_none(), "crlf={crlf}: {result:?}");
            assert_eq!(crate::vendor::test_support::tree_snapshot(root), snapshot);
            assert!(service_preflight(PURL, root, &record).await.is_none());

            let out = revert_maven(&entry, root, false).await;
            assert!(
                out.success && out.warnings.is_empty(),
                "crlf={crlf}: {out:?}"
            );
            assert_eq!(
                std::fs::read(root.join(PROJECT_POM)).unwrap(),
                pom.as_bytes()
            );
            assert!(!root.join(".mvn").exists());
            let mut after = crate::vendor::test_support::tree_snapshot(root);
            after.remove(".socket/vendor/state.json");
            assert_eq!(after, before, "crlf={crlf}");
        }
    }

    /// A root whose ledger holds a pre-v5 `maven_pom_repository` entry is
    /// refused whole (`legacy_maven_root`), single or beside a Gradle
    /// build, with nothing written and no service call or hosted restore
    /// planned. After `vendor --revert` it vendors through the planner.
    #[tokio::test]
    #[serial_test::serial]
    async fn legacy_maven_root_is_refused_until_reverted() {
        for mixed in [false, true] {
            let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
            let root = dir.path();
            if mixed {
                std::fs::write(root.join("settings.gradle"), "rootProject.name = 'app'\n").unwrap();
            }
            let legacy = legacy_vendor(root, &record).await;
            crate::vendor::test_support::persist(root, PURL, legacy.clone()).await;
            let before = crate::vendor::test_support::tree_snapshot(root);

            let (code, detail) =
                unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
            assert_eq!(code, "vendor_jvm_shape_unsupported", "mixed={mixed}");
            assert!(
                detail.starts_with("reason: legacy_maven_root: ")
                    && detail.contains("socket-patch vendor --revert"),
                "mixed={mixed}: {detail}"
            );
            // A second patch uuid is refused the same way.
            let other = PatchRecord {
                uuid: crate::vendor::test_support::PLAN_UUID_B.to_string(),
                ..record.clone()
            };
            let (code, _) =
                unwrap_refused(run_vendor(root, &blobs, &installed, &other, false).await);
            assert_eq!(code, "vendor_jvm_shape_unsupported");
            assert_eq!(
                crate::vendor::test_support::tree_snapshot(root),
                before,
                "mixed={mixed}"
            );
            assert!(service_preflight(PURL, root, &other).await.is_none());
            let (code, detail) = jvm_gate_preflight(root, PURL).await.unwrap_err();
            assert_eq!(code, "vendor_jvm_shape_unsupported");
            assert!(
                detail.starts_with("reason: legacy_maven_root: "),
                "{detail}"
            );

            // `vendor --revert`: the pom comes back byte for byte, the
            // ledger empties, and vendoring then plans the root.
            let out = revert_maven(&legacy, root, false).await;
            assert!(out.success && out.warnings.is_empty(), "{out:?}");
            assert_eq!(
                std::fs::read_to_string(root.join(PROJECT_POM)).unwrap(),
                project_pom()
            );
            assert!(!root.join(".socket/vendor/maven").exists());
            super::super::state::save_state(root, &super::super::state::VendorState::new())
                .await
                .unwrap();
            let (result, entry, _) =
                unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
            assert!(result.success, "mixed={mixed}: {:?}", result.error);
            assert_eq!(entry.unwrap().ecosystem, layout::LEDGER_ECOSYSTEM);
            assert!(std::fs::read_to_string(root.join(PROJECT_POM))
                .unwrap()
                .contains("1.10.0-socket."));
        }
    }

    /// Offline sourcing (#533, #511): a Gradle copy counts only in the hash
    /// directory its bytes name, an m2 copy only when its `.sha1` sidecar
    /// matches (or, unauthenticated, when it has none), and the crawler's
    /// Gradle version directory makes its whole `files-2.1` tree a source.
    #[tokio::test]
    async fn local_sources_trust_only_verifiable_copies() {
        use crate::crawlers::jvm_cache::{JvmCacheLayout, JvmCacheRoot};
        let sha1 = |b: &[u8]| {
            use sha1::Digest as _;
            hex::encode(sha1::Sha1::digest(b))
        };
        let dir = tempfile::tempdir().unwrap();
        let gav: crate::crawlers::jvm_cache::Gav = ("com.x".into(), "lib".into(), "1.0".into());
        let only = |path: PathBuf, layout| LocalSources {
            roots: vec![JvmCacheRoot::new(path, layout)],
            ..LocalSources::none()
        };

        let files21 = dir.path().join("gradle/caches/modules-2/files-2.1");
        let version = files21.join("com.x/lib/1.0");
        let put = |rel: PathBuf, bytes: &[u8]| {
            std::fs::create_dir_all(rel.parent().unwrap()).unwrap();
            std::fs::write(rel, bytes).unwrap();
        };
        put(version.join(sha1(b"POM")).join("lib-1.0.pom"), b"POM");
        put(
            version.join(sha1(b"other")).join("lib-1.0.jar"),
            b"TAMPERED",
        );
        put(
            version.join(sha1(b"SRC")).join("lib-1.0-sources.jar"),
            b"SRC",
        );
        let gradle = only(files21.clone(), JvmCacheLayout::GradleModules2);
        assert_eq!(
            gradle.find(&gav, None, "pom", true).await.unwrap(),
            Some(b"POM".to_vec())
        );
        assert_eq!(gradle.find(&gav, None, "jar", false).await.unwrap(), None);
        // From the crawler's version dir: the root is its files-2.1 tree.
        let crawled = LocalSources::new(dir.path(), &version, "com.x");
        assert!(crawled.roots.iter().any(|r| r.path == files21));
        assert_eq!(
            crawled
                .find(&gav, Some("sources"), "jar", true)
                .await
                .unwrap(),
            Some(b"SRC".to_vec())
        );

        let m2 = dir.path().join("m2");
        let leaf = m2.join("com/x/lib/1.0");
        put(leaf.join("lib-1.0.pom"), b"POM");
        put(leaf.join("lib-1.0.pom.sha1"), sha1(b"POM").as_bytes());
        put(leaf.join("lib-1.0.jar"), b"JAR");
        put(leaf.join("lib-1.0.jar.sha1"), sha1(b"other").as_bytes());
        put(leaf.join("lib-1.0-tests.jar"), b"TESTS");
        let maven = only(m2.clone(), JvmCacheLayout::Maven2);
        assert_eq!(
            maven.find(&gav, None, "pom", true).await.unwrap(),
            Some(b"POM".to_vec())
        );
        assert_eq!(maven.find(&gav, None, "jar", false).await.unwrap(), None);
        assert_eq!(
            maven.find(&gav, Some("tests"), "jar", true).await.unwrap(),
            None
        );
        assert_eq!(
            maven.find(&gav, Some("tests"), "jar", false).await.unwrap(),
            Some(b"TESTS".to_vec())
        );
        // The crawler's own m2 dir is read directly, under the same rules.
        let crawled = LocalSources::new(dir.path(), &leaf, "com.x");
        assert!(crawled.roots.iter().any(|r| r.path == m2));
        assert_eq!(
            crawled
                .find(&gav, Some("tests"), "jar", true)
                .await
                .unwrap(),
            None
        );
        assert_eq!(crawled.find(&gav, None, "jar", false).await.unwrap(), None);
    }
    /// The undo of a patch takes its vendored entry out of the block of
    /// `MODULE.bazel` and then removes the directory the entry named. A
    /// file that names the directory in a block changed by hand, or
    /// outside the block, fails the undo before anything is removed: Bazel
    /// would stop at a directory that is gone. A dry run and
    /// `--preserve-state` keep the directory.
    #[tokio::test]
    async fn the_revert_takes_the_hub_entry_out_before_its_directory() {
        use crate::bazel::maven::{with_patch, Patch, FILE};
        let uuid = "0e77a000-0000-4000-8000-0000000000a1";
        let module = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n";
        let patch = Patch {
            group: "g".to_string(),
            artifact: "a".to_string(),
            version: "1".to_string(),
            uuid: uuid.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let (unit, jar) = (patch.unit().unwrap(), patch.jar().unwrap());
        let wired = with_patch(module, "@rules_jvm_external//:extensions.bzl", patch).unwrap();
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: jar.clone(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        let purl = "pkg:maven/g/a@1".to_string();
        let entry = VendorEntry::new("maven".into(), purl, uuid.into(), artifact, Vec::new());
        let (keep, dry) = (
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
            RevertOpts::new(true),
        );
        let edited = wired.replace("# Do not change", "# Do change");
        let named = format!("# the jar of {unit}\n{wired}");
        for (text, opts, undone, left) in [
            (&edited, RevertOpts::new(false), false, (&edited, true)),
            (&named, RevertOpts::new(false), false, (&named, true)),
            (&wired, dry, true, (&wired, true)),
            (&wired, keep, true, (&module.to_string(), true)),
            (
                &wired,
                RevertOpts::new(false),
                true,
                (&module.to_string(), false),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            std::fs::create_dir_all(root.join(&unit).join("file")).unwrap();
            std::fs::write(root.join(&jar), b"jar").unwrap();
            std::fs::write(root.join(FILE), text).unwrap();
            let outcome = revert_maven_opts(&entry, root, opts).await;
            assert_eq!(outcome.success, undone, "{:?}", outcome.error);
            let held = std::fs::read_to_string(root.join(FILE)).unwrap();
            assert_eq!((&held, root.join(&jar).exists()), left, "{opts:?}");
            if !undone {
                let why = outcome.error.unwrap_or_default();
                assert!(
                    why.contains("changed by hand") && why.contains(&unit),
                    "{why}"
                );
            }
        }
        // Without the file, or without the directory's name in it, the
        // undo is the one it was.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(unwire_hub(&entry, tmp.path()).await, Ok(None));
        std::fs::write(tmp.path().join(FILE), module).unwrap();
        assert_eq!(unwire_hub(&entry, tmp.path()).await, Ok(None));
    }

    /// A `MODULE.bazel` that is there but cannot be read (here, not UTF-8)
    /// may still name the directory of the hub's jar: the undo, the check
    /// and the repair fail on it instead of taking it for a file that is
    /// not there, and the directory stays.
    #[tokio::test]
    async fn an_unreadable_module_file_is_no_missing_one() {
        use crate::bazel::maven::{with_patch, Patch, FILE};
        let uuid = "0e77a000-0000-4000-8000-0000000000a1";
        let module = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n";
        let patch = Patch {
            group: "g".to_string(),
            artifact: "a".to_string(),
            version: "1".to_string(),
            uuid: uuid.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let (unit, jar) = (patch.unit().unwrap(), patch.jar().unwrap());
        let wired = with_patch(module, "@rules_jvm_external//:extensions.bzl", patch).unwrap();
        let mut unreadable = wired.into_bytes();
        unreadable.extend_from_slice(b"# \xff\n");
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: jar.clone(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        let purl = "pkg:maven/g/a@1".to_string();
        let mut entry = VendorEntry::new("maven".into(), purl, uuid.into(), artifact, Vec::new());
        entry.flavor = Some(HUB_FLAVOR.to_string());
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(&unit).join("file")).unwrap();
        std::fs::write(root.join(&jar), b"jar").unwrap();
        std::fs::write(root.join(FILE), &unreadable).unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(!outcome.success, "{outcome:?}");
        let why = outcome.error.unwrap_or_default();
        assert!(
            why.contains(FILE) && why.contains("cannot be read"),
            "{why}"
        );
        assert!(root.join(&jar).exists());
        assert_eq!(std::fs::read(root.join(FILE)).unwrap(), unreadable);

        let why = check_hub(root, &entry).await.unwrap_err();
        assert!(why.contains("cannot be read"), "{why}");
        let why = restore_hub_files(root, &entry).await.unwrap_err();
        assert!(why.contains("cannot be read"), "{why}");
        assert!(!root.join(&unit).join(crate::bazel::maven::REPO).exists());
    }

    /// The block keeps the entry of the patch when the JVM revert it goes
    /// with is refused: the directory it names stays, so the entry must
    /// too, and a later undo still finds and removes both.
    #[tokio::test]
    async fn a_refused_jvm_revert_leaves_the_hub_entry() {
        use crate::bazel::maven::{with_patch, Patch, FILE};
        let uuid = "0e77a000-0000-4000-8000-0000000000a1";
        let module = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n";
        let patch = Patch {
            group: "g".to_string(),
            artifact: "a".to_string(),
            version: "1".to_string(),
            uuid: uuid.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let (unit, jar) = (patch.unit().unwrap(), patch.jar().unwrap());
        let wired = with_patch(module, "@rules_jvm_external//:extensions.bzl", patch).unwrap();
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: jar.clone(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        // A tree record at a path vendoring never writes: the JVM revert
        // refuses it before touching the disk.
        let tree = WiringRecord {
            file: "elsewhere/a.jar".to_string(),
            kind: super::super::jvm::TREE_KIND.to_string(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: None,
        };
        let purl = "pkg:maven/g/a@1".to_string();
        let entry = VendorEntry::new("jvm".into(), purl, uuid.into(), artifact, vec![tree]);
        assert!(super::super::jvm::apply::is_jvm_entry(&entry));
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(&unit).join("file")).unwrap();
        std::fs::write(root.join(&jar), b"jar").unwrap();
        std::fs::write(root.join(FILE), &wired).unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("refusing revert")),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read_to_string(root.join(FILE)).unwrap(), wired);
        assert!(root.join(&jar).exists());
        assert!(unwire_hub(&entry, root).await.unwrap().is_some());
    }

    /// The undo of a patch that a Maven build and a hub both take edits the
    /// files of both, and removes the build's tree only once every edit is
    /// in. A `MODULE.bazel` that cannot be replaced (its directory takes no
    /// new file) fails the undo with the tree, the block and the hub's
    /// directory as they were: the tree does not go first. So does one
    /// that is a symbolic link, which the commit would replace. And an
    /// undo that was interrupted after its edits is finished by the next
    /// one, which removes the tree and the hub's directory that no file
    /// names.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_undo_that_cannot_write_module_bazel_removes_nothing() {
        use crate::bazel::maven::{with_patch, Patch, FILE, REPO};
        use std::os::unix::fs::PermissionsExt;
        let uuid = "0e77a000-0000-4000-8000-0000000000a1";
        let module = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n";
        let patch = Patch {
            group: "g".to_string(),
            artifact: "a".to_string(),
            version: "1".to_string(),
            uuid: uuid.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let (unit, jar) = (patch.unit().unwrap(), patch.jar().unwrap());
        let wired = with_patch(module, "@rules_jvm_external//:extensions.bzl", patch).unwrap();
        // The tree of the Maven build, as its ledger entry records it.
        let tree = ".socket/vendor/maven2/g/a/1-socket.0e77a000/a-1-socket.0e77a000.jar";
        let record = WiringRecord {
            file: tree.to_string(),
            kind: super::super::jvm::TREE_KIND.to_string(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: Some(Value::String(hex::encode(Sha256::digest(b"JAR")))),
        };
        let artifact = VendorArtifact {
            yarn_berry10c0: None,
            path: tree.to_string(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        };
        let purl = "pkg:maven/g/a@1".to_string();
        let entry = VendorEntry::new("jvm".into(), purl, uuid.into(), artifact, vec![record]);
        assert!(super::super::jvm::apply::is_jvm_entry(&entry));
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (rel, bytes) in [
            (tree, &b"JAR"[..]),
            (&jar, b"jar"),
            (&format!("{unit}/{REPO}"), b"# a repository\n"),
            (FILE, wired.as_bytes()),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let mode =
            |mode| std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode)).unwrap();
        mode(0o555);
        if std::fs::write(root.join("probe"), b"").is_ok() {
            eprintln!("skipping: permission bits not enforced (running as root?)");
            return mode(0o755);
        }
        let outcome = revert_maven(&entry, root, false).await;
        mode(0o755);
        assert!(!outcome.success, "{outcome:?}");
        let why = outcome.error.unwrap_or_default();
        assert!(root.join(tree).exists(), "the tree went first: {why}");
        assert_eq!(std::fs::read(root.join(tree)).unwrap(), b"JAR", "{why}");
        assert_eq!(std::fs::read_to_string(root.join(FILE)).unwrap(), wired);
        assert!(root.join(&jar).exists(), "{why}");
        assert!(
            why.contains(FILE) && why.ends_with("every file is as it was"),
            "{why}"
        );

        // A `MODULE.bazel` that is a symbolic link: the commit would put a
        // file in the place of the link, and is refused before any write.
        let real = root.join("real.MODULE.bazel");
        std::fs::rename(root.join(FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, root.join(FILE)).unwrap();
        let outcome = revert_maven(&entry, root, false).await;
        let why = outcome.error.unwrap_or_default();
        assert!(!outcome.success && why.contains("symbolic link"), "{why}");
        assert!(
            root.join(tree).exists() && root.join(&jar).exists(),
            "{why}"
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), wired);
        assert!(root.join(FILE).is_symlink(), "{why}");
        std::fs::remove_file(root.join(FILE)).unwrap();

        // The edits are in and the run ended there: the block names no
        // directory, and the tree and the hub's directory are still there.
        std::fs::write(root.join(FILE), module).unwrap();
        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{outcome:?}");
        assert_eq!(std::fs::read_to_string(root.join(FILE)).unwrap(), module);
        let left = [tree, unit.as_str()].map(|rel| root.join(rel).exists());
        assert_eq!(left, [false, false], "{outcome:?}");
    }

    /// A hosted run that put its entry in the place of a vendored one
    /// removes the directory of the hub's jar that `MODULE.bazel` no longer
    /// names, where no revert did: beside a Maven build, whose ledger entry
    /// stays. A directory that the file still names, one that holds the
    /// artifact of a ledger entry, and one that socket-patch did not make a
    /// repository stay.
    #[tokio::test]
    async fn a_hosted_run_drops_the_hub_directory_that_nothing_names() {
        let uuid = "0e77a000-0000-4000-8000-0000000000a1".to_string();
        let unit = format!(".socket/vendor/maven/{uuid}");
        let recorded = |path: String| {
            let artifact = VendorArtifact {
                yarn_berry10c0: None,
                path,
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            };
            let purl = "pkg:maven/g/a@1".to_string();
            let entry =
                VendorEntry::new("jvm".into(), purl.clone(), uuid.clone(), artifact, vec![]);
            let mut state = crate::vendor::VendorState::default();
            state.entries.insert(purl, entry);
            state
        };
        let beside = recorded(".socket/vendor/maven2/g/a/1-socket.0e77a000/a.jar".to_string());
        let alone = recorded(format!("{unit}/file/a-1.jar"));
        for (module, state, made, stays) in [
            (String::new(), &beside, true, false),
            (format!("path = \"{unit}\""), &beside, true, true),
            (String::new(), &alone, true, true),
            (String::new(), &beside, false, true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join(&unit);
            std::fs::create_dir_all(dir.join("file")).unwrap();
            std::fs::write(dir.join("file/a-1.jar"), b"jar").unwrap();
            if made {
                std::fs::write(dir.join(crate::bazel::maven::REPO), b"# a repository\n").unwrap();
            }
            let left = drop_unnamed_units(tmp.path(), &module, state).await;
            assert_eq!(left, Vec::<String>::new(), "{module:?} {made}");
            assert_eq!(dir.exists(), stays, "{module:?} {made}");
            let vendor = tmp.path().join(".socket/vendor");
            assert_eq!(vendor.exists(), stays, "{module:?} {made}");
        }
    }

    /// A rule of the checkout that ignores the directory of the hub's jar
    /// is the refusal every vendored artifact has, before anything is
    /// written: the commit would leave the jar out.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_hub_directory_that_git_ignores_is_refused() {
        use crate::vendor::test_support::{git_project, tree_snapshot};
        let (dir, _, _, record) = fixture(None, true, true).await;
        let root = dir.path();
        if git_project(root, ".socket/vendor/\n").is_none() {
            return;
        }
        let [group, artifact, version] =
            ["org.apache.commons", "commons-text", "1.10.0"].map(str::to_string);
        let patch = crate::bazel::maven::Patch {
            group,
            artifact,
            version,
            uuid: UUID.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let before = tree_snapshot(root);
        let hub = Ok((String::new(), patch));
        let refused = vendor_hub(hub, PURL, root, &record, false, None).await;
        let (code, detail) = unwrap_refused(refused);
        assert_eq!(code, "vendor_artifact_gitignored", "{detail}");
        let unit = format!(".socket/vendor/maven/{UUID}");
        assert!(detail.contains(&unit), "{detail}");
        assert_eq!(tree_snapshot(root), before);
    }
}
