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

use crate::constants::SOCKET_DIR;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{
    atomic_write_artifact, atomic_write_bytes_preserving_mode, read_regular_to_bytes,
    read_regular_to_string,
};
use crate::utils::purl::{build_maven_purl, parse_maven_purl};
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::{
    already_patched_result, any_live_file_references, done, failed_result, refused,
    synthesized_result, zip_bytes_match_after_hashes,
};
use super::path::vendor_uuid_dir_rel;
use super::service_fetch::{service_archive_copy, ServiceCopy};
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

/// The maven2 registry base for the (fallback) pom download, overridable with
/// `SOCKET_MAVEN_REGISTRY` (the private-mirror / test escape hatch). Default is
/// Maven Central's maven2 endpoint.
pub(crate) fn maven_registry_base() -> String {
    std::env::var("SOCKET_MAVEN_REGISTRY")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://repo1.maven.org/maven2".to_string())
}

/// Convert a dotted Maven groupId to its maven2 path segment
/// (`org.apache.commons` → `org/apache/commons`). Local twin of the private
/// `maven_crawler::group_id_to_path`; the coordinate has already passed
/// [`super::jvm::safe_coordinates`] before this runs.
fn group_id_to_path(group_id: &str) -> String {
    group_id.replace('.', "/")
}

/// Whether [`vendor_maven`] — a wet run with the service enabled — asks the
/// patch service for `record`: past every refusal it raises first and not
/// answered by the in-sync hot path. The vendor loop's download plan
/// consults this.
pub(crate) async fn service_preflight(
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
) -> Option<crate::api::client::PlannedDownload> {
    let (g, a, v) = parse_maven_purl(purl)?;
    vendor_uuid_dir_rel("maven", &record.uuid)?;
    (super::jvm::safe_coordinates(&g, &a, &v) && !record.files.is_empty()).then_some(())?;
    if not_build_root(project_root).is_some() || legacy_root(project_root).await {
        return None;
    }
    let shape = detect_shape(project_root);
    if shape == super::jvm::Shape::Other {
        return None;
    }
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
        return refused("vendor_jvm_shape_unsupported", LEGACY_ROOT_DETAIL);
    }
    let shape = detect_shape(project_root);
    if shape == super::jvm::Shape::Other {
        let refusal = super::jvm::no_build_file_refusal();
        return refused(refusal.code, refusal.detail);
    }
    vendor_maven_jvm(
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
    .await
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
    VendorEntry {
        ecosystem: "maven".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
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
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    }
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
pub async fn revert_maven_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // Routed only when EVERY record is a JVM kind; the JVM revert validates
    // the uuid, the coordinates and each recorded path before any disk
    // access (state.json is tamper-able).
    if super::jvm::apply::is_jvm_entry(entry) {
        return super::jvm::apply::revert(project_root, entry, opts).await;
    }
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid grammar
    // is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("maven", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
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
                    w.key.as_deref().unwrap_or("<unknown>")
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

    let mut outcome = RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    };
    if dry_run {
        return outcome;
    }
    // Drift-keep (see the fn doc): never delete a uuid dir the live pom
    // still routes Maven at.
    if outcome.drift_skipped()
        && any_live_file_references(project_root, &[PROJECT_POM], &uuid_dir_rel).await
    {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }
    // `--preserve-state` (`keep_artifact`): the artifact dir stays behind
    // (and the caller keeps the ledger entry), so only the deletion is
    // skipped.
    if keep_artifact {
        return outcome;
    }
    // The last maven entry leaves `.socket/vendor/maven/` (and
    // `.socket/vendor/`) empty: the shared helper prunes them so a
    // reverted project carries no vendor residue (non-recursive:
    // siblings keep them).
    if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
        outcome.success = false;
        outcome.error = Some(format!("failed to remove {}: {e}", uuid_dir.display()));
    }
    outcome
}

// ── v5 JVM backend ─────────────────────────────────────────────────

/// The `legacy_maven_root` refusal detail (see [`legacy_root`]).
const LEGACY_ROOT_DETAIL: &str = "reason: legacy_maven_root: pom.xml is still vendored through \
     the pre-v5 <repository> wiring; run `socket-patch vendor --revert` and vendor again";

/// The planner shape of the project root (see [`super::jvm::detect`]).
fn detect_shape(project_root: &Path) -> super::jvm::Shape {
    let reader = super::jvm::apply::ProjectReader::new(project_root);
    super::jvm::detect(&|rel: &str| reader.read(rel))
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
    let own_settings = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .any(|f| project_root.join(f).is_file());
    let own_build = ["build.gradle", "build.gradle.kts"]
        .iter()
        .any(|f| project_root.join(f).is_file());
    let canonical_root =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let ancestors = crate::utils::repo_root::ancestor_search_dirs(&canonical_root);
    for ancestor in &ancestors {
        let ancestor = ancestor.as_path();
        let reader = super::jvm::apply::ProjectReader::new(ancestor);
        let rel = canonical_root
            .strip_prefix(ancestor)
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"));
        let Some(rel) = rel else { break };
        let shown = || shown_ancestor(project_root, ancestor, &canonical_root);
        if super::jvm::maven_reactor::contains_module(
            &|p| reader.read(p),
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
        let settings = ["settings.gradle", "settings.gradle.kts"]
            .into_iter()
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
}

impl LocalSources {
    /// No local copy at all (repair downloads and verifies everything).
    pub(super) fn none() -> Self {
        Self {
            installed_dir: None,
            roots: Vec::new(),
        }
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

/// The vendored sbt / scala-cli gate for `purl` over the project at
/// `project_root`, for a caller about to restore a hosted pin upstream (a
/// takeover or an eject) before vendoring: `Err((code, detail))` when the
/// gate would stop the patch (a skip or a refusal), so the caller keeps the
/// hosted wiring instead of ending neither hosted nor vendored. `Ok` for
/// any other project shape or a non-Maven purl.
pub async fn jvm_gate_preflight(
    project_root: &Path,
    purl: &str,
) -> Result<(), (&'static str, String)> {
    let Some((g, a, v)) = parse_maven_purl(purl) else {
        return Ok(());
    };
    if legacy_root(project_root).await {
        return Err((
            "vendor_jvm_shape_unsupported",
            LEGACY_ROOT_DETAIL.to_string(),
        ));
    }
    let shape = detect_shape(project_root);
    super::jvm::sbt_gate::for_shape(shape, project_root, &g, &a, &v)
        .map(|_| ())
        .map_err(|stop| stop.code_and_detail(purl))
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
            serde_json::from_slice(&read(&format!("{dir}/socket-patch.vendor.json"))?).ok()?;
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
    let Some((group_id, artifact_id, version)) = parse_maven_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a maven purl: {purl}"));
    };
    let (group_id, artifact_id, version) = (
        group_id.to_string(),
        artifact_id.to_string(),
        version.to_string(),
    );
    if vendor_uuid_dir_rel("maven", &record.uuid).is_none() {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    }
    if !super::jvm::safe_coordinates(&group_id, &artifact_id, &version) {
        return refused(
            "unsafe_coordinates",
            format!("unsafe maven coordinates `{group_id}:{artifact_id}` @ `{version}`"),
        );
    }
    let state = match super::state::load_state(project_root).await {
        Ok(state) => Some(state),
        Err(e) => return refused("vendor_state_unreadable", e.to_string()),
    };
    let gradle = matches!(shape, Shape::Gradle | Shape::Mixed);
    let display_path = project_root.join(".socket/vendor");
    // sbt / scala-cli pins are gated on the build's own resolution first.
    let gate =
        super::jvm::sbt_gate::for_shape(shape, project_root, &group_id, &artifact_id, &version);
    let gate_pass = match gate.map_err(|stop| stop.into_outcome(purl)) {
        Ok(pass) => pass,
        Err(outcome) => return outcome,
    };
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
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        };
        let plan = super::jvm::plan(
            shape,
            &|rel| reader.read(rel),
            &|dir| reader.list(dir),
            &patch,
        );
        if let Some(rel) = reader.escaped() {
            return refused(
                "vendor_jvm_shape_unsupported",
                super::jvm::apply::outside_root_detail(&rel),
            );
        }
        // A declared classifier is sourced only for a real patch.
        if let Err(e) = plan {
            if !e.detail.starts_with("reason: classifier_unavailable:") {
                return refused(e.code, e.detail);
            }
        }
        return done(
            synthesized_result(purl, &display_path, Vec::new(), true, None),
            None,
            Vec::new(),
        );
    }

    let local = LocalSources::new(project_root, installed_dir, &group_id);
    let gav = (group_id.clone(), artifact_id.clone(), version.clone());
    let mut warnings: Vec<VendorWarning> = gate_pass.warnings;
    let committed = jvm_committed_patch(shape, purl, project_root, record).await;
    let was_committed = committed.is_some();
    let (jar_bytes, mut pom_bytes, mut module_bytes, mut extras, mut result) = match committed {
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
                    ServiceCopy::Used(bytes) => (
                        bytes,
                        already_patched_result(purl, &display_path, &record.files),
                    ),
                    ServiceCopy::HardFail(outcome) => return *outcome,
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
    if online && was_committed {
        let upstream = match acquire_jvm_artifact(&local, &gav, None, "jar", service).await {
            Ok(bytes) => bytes,
            Err(e) => return refused("vendor_jvm_upstream_unavailable", e),
        };
        if let Err(e) = verify_unpatched_jar_members(&upstream, &jar_bytes, record) {
            return refused("vendor_prebuilt_integrity_mismatch", e);
        }
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
    let patch = super::jvm::JvmPatch {
        group_id: &group_id,
        artifact_id: &artifact_id,
        version: &version,
        uuid: &record.uuid,
        jar: &jar_bytes,
        upstream_pom: &pom_bytes,
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
        Shape::Sbt => {
            super::jvm::sbt::plan_with_digest(&read, &patch, gate_pass.deps_digest.as_deref())
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
    let registry_verified = online || (was_committed && prior_verified);
    plan.records.push(WiringRecord {file: plan.jar_rel.clone(), kind: super::jvm::UPSTREAM_KIND.into(), action: WiringAction::Added, key: Some("upstream".into()), original: None, new: Some(serde_json::json!({"op": if registry_verified {"registry_verified"} else {"local_unverified"}}))});
    warnings.extend(
        plan.warnings
            .iter()
            .map(|w| VendorWarning::new(w.code, w.detail.clone())),
    );
    let jar_path = project_root.join(&plan.jar_rel);
    result.package_path = jar_path.display().to_string();
    if plan.writes.is_empty() && (previous.is_none() || registry_verified == prior_verified) {
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
    entry.ecosystem = "jvm".to_string();
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
    let leaf = format!("{a}-{v}-{classifier}.jar");
    let local_copy = local.find(gav, Some(classifier), "jar", true).await?;
    let online = service.is_some_and(|s| !s.offline);
    let bytes = match local_copy {
        Some(bytes) => bytes,
        None if online => {
            let url = format!(
                "{}/{}/{a}/{v}/{leaf}",
                maven_registry_base(),
                group_id_to_path(g)
            );
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

/// Verify upstream cache/registry bytes against checksums fetched independently over TLS.
fn verify_unpatched_jar_members(
    upstream: &[u8],
    patched: &[u8],
    record: &PatchRecord,
) -> Result<(), String> {
    let mut original = super::verify::read_zip_bytes_to_map(upstream)?;
    let mut committed = super::verify::read_zip_bytes_to_map(patched)?;
    let retain = |name: &String, _: &mut Vec<u8>| {
        !record.files.contains_key(name) && !super::jvm::is_signature(name)
    };
    original.retain(retain);
    committed.retain(retain);
    if original != committed {
        return Err(
            "committed jar's unpatched members differ from the verified upstream jar".into(),
        );
    }
    Ok(())
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
    if service.is_none_or(|s| s.offline) {
        return Ok(());
    }
    use sha2::Digest;
    // `tests.jar` is the `tests` classifier's jar.
    let tail = match ext.split_once('.') {
        Some((classifier, ext)) => format!("-{classifier}.{ext}"),
        None => format!(".{ext}"),
    };
    let url = format!(
        "{}/{gpath}/{a}/{v}/{a}-{v}{tail}",
        maven_registry_base(),
        gpath = group_id_to_path(g)
    );
    let (checksum, actual) = match fetch_pom_bytes(&format!("{url}.sha512")).await {
        Ok(sum) => (sum, hex::encode(sha2::Sha512::digest(bytes))),
        Err(_) => (
            fetch_pom_bytes(&format!("{url}.sha1")).await?,
            sha1_hex(bytes),
        ),
    };
    let expected = std::str::from_utf8(&checksum)
        .map_err(|_| "upstream checksum is not UTF-8")?
        .split_whitespace()
        .next()
        .ok_or("upstream checksum is empty")?;
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(format!("upstream checksum mismatch for {g}:{a}:{v}{tail}"));
    }
    Ok(())
}

/// One upstream file of `gav` (`classifier`, `ext`): a local copy (see
/// [`LocalSources::find`]), else a registry download when the service is
/// online; online, the bytes are checked against the registry's checksum
/// either way.
pub(super) async fn acquire_jvm_artifact(
    local: &LocalSources,
    gav: &crate::crawlers::jvm_cache::Gav,
    classifier: Option<&str>,
    ext: &str,
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<u8>, String> {
    let (g, a, v) = gav;
    let leaf = match classifier {
        Some(c) => format!("{a}-{v}-{c}.{ext}"),
        None => format!("{a}-{v}.{ext}"),
    };
    let bytes = match local.find(gav, classifier, ext, false).await? {
        Some(bytes) => bytes,
        None if service.is_some_and(|s| !s.offline) => {
            fetch_registry_bytes(
                &format!(
                    "{}/{}/{a}/{v}/{leaf}",
                    maven_registry_base(),
                    group_id_to_path(g)
                ),
                if ext == "jar" {
                    super::registry_fetch::MAX_DOWNLOAD_BYTES
                } else {
                    MAX_POM_BYTES as u64
                },
            )
            .await?
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
    verify_jvm_upstream(&bytes, g, a, v, &tail, service).await?;
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
        roots: Vec::new(),
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
    let roots = LocalSources {
        installed_dir: None,
        roots: local.roots.clone(),
    };
    acquire_jvm_artifact(
        &roots,
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

pub(crate) async fn fetch_registry_bytes(url: &str, cap: u64) -> Result<Vec<u8>, String> {
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
    //     lone-patch common case.
    if new.is_some_and(|n| &live == n) {
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
    use crate::crawlers::maven_crawler::is_safe_maven_coordinate;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::ApplyResult;

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
        assert_eq!(entry.unwrap().ecosystem, "jvm");
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
        assert_eq!(entry.unwrap().ecosystem, "jvm");
        assert!(root.join(".socket/vendor/gradle-index.tsv").is_file());
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
        assert_eq!(group_id_to_path("org.apache.commons"), "org/apache/commons");
        let is_safe_group_id = |g| is_safe_maven_coordinate(g, "a", "1");
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

    /// Save/restore guard for env-var tests (same shape as the maven crawler's
    /// tests); every user must also be `#[serial_test::serial]`.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

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
                    use_public_proxy: false,
                    org_slug: Some("acme".into()),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none())
            }),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
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
        let _reg = EnvGuard::set("SOCKET_MAVEN_REGISTRY", &server.uri());
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
            assert_eq!(entry.ecosystem, "jvm");
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
            assert_eq!(entry.unwrap().ecosystem, "jvm");
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
            installed_dir: None,
            roots: vec![JvmCacheRoot::new(path, layout)],
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
}
