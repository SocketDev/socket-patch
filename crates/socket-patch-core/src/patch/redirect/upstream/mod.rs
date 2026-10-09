//! Hosted → upstream restore: the v5 unwind of a hosted redirect.
//!
//! v5 hosted mode keeps no ledger (`scan`/`get --mode hosted` write only
//! lockfile edits), so an unwind cannot replay recorded fragments. Instead,
//! for every hosted pin the lockfiles carry (`vex::discover`'s hosted refs:
//! purl + patch uuid + the files wiring it), this module rewrites the lock
//! entry back to the DEFAULT UPSTREAM registry entry for `name@version`,
//! re-resolving whatever the entry pins (tarball URL, integrity, checksum)
//! from the public registry: the npm registry's version document, the
//! crates.io sparse index, the Go module proxy, and so on.
//!
//! Where that is impossible — a format whose entry carries fields only the
//! package manager can compute, an offline run, a registry that does not
//! answer, a binary `bun.lockb` outside a vendor takeover
//! ([`RestoreOptions::bun_lockb`]) — the pin is REFUSED with a message naming
//! the remedy (`git checkout -- <lockfile>`). A refusal is all-or-nothing
//! per pin: a pin refused in one of its files is restored in none of them,
//! so no pin is ever left half hosted.
//!
//! Nothing reaches disk until every pin resolved (the staged view below),
//! and a dry run resolves everything exactly like a wet run — network
//! lookups included — and skips only the flush.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::vex::discover::{Discovery, PatchedRef, WiringMode};

mod bun_lockb;
pub(super) mod cargo;
mod client;
mod composer;
mod gem;
mod golang;
mod gradle;
mod maven;
mod npm;
mod nuget;
mod pypi;
mod pypi_locks;
mod sbt;
mod uv;
mod vlt;

pub(crate) use client::UpstreamClient;
pub(crate) use uv::{respell_lock_specifier, LockRequirementArray};

use super::staged::{flush_staged, read_rel, Staged, StagedBytes};

/// One hosted pin to restore: a `(purl, patch uuid)` pair and the
/// root-relative files lockfile discovery found it wired in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedPin {
    /// Canonical base purl (no qualifiers), as discovery spells it.
    pub purl: String,
    /// The hosted patch uuid.
    pub uuid: String,
    /// Root-relative files that wire this pin, sorted and deduplicated.
    pub files: Vec<String>,
}

impl HostedPin {
    /// Group a discovery's HOSTED refs into pins, one per `(purl, uuid)`.
    pub fn from_refs<'a>(refs: impl IntoIterator<Item = &'a PatchedRef>) -> Vec<HostedPin> {
        let mut grouped: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for r in refs {
            if r.mode != WiringMode::Hosted {
                continue;
            }
            grouped
                .entry((r.purl.clone(), r.uuid.clone()))
                .or_default()
                .insert(r.source_file.to_string_lossy().replace('\\', "/"));
        }
        grouped
            .into_iter()
            .map(|((purl, uuid), files)| HostedPin {
                purl,
                uuid,
                files: files.into_iter().collect(),
            })
            .collect()
    }

    /// Every hosted pin a discovery holds: its refs, plus the refs it
    /// withholds from attestation only because an unreachable unpatched
    /// copy installs beside them ([`Discovery::shadowed`], #828) — that
    /// wiring is still one package version's pin, so it is restorable.
    pub fn all(discovery: &Discovery) -> Vec<HostedPin> {
        Self::from_refs(discovery.refs.iter().chain(&discovery.shadowed))
    }

    /// THE "is this patch pinned" answer: the attributable hosted pins
    /// lockfile discovery reads through `view` (the disk, a snapshot of it
    /// overlaid with a pending rewrite, or an in-memory project), with
    /// `origins` counting as patch servers besides Socket's own. The
    /// forward rewrite's confirmation, the rollout's recorded view (disk
    /// and in memory) and the management commands' [`HostedInventory`] all
    /// read pins through discovery, so none of them can call a uuid pinned
    /// that another one calls unpinned or contested.
    pub async fn discover(
        view: crate::vendor::lock_inventory::ProjectView<'_>,
        origins: &[String],
    ) -> Vec<HostedPin> {
        let opts = crate::vex::DiscoverOptions {
            patch_server_origins: origins.to_vec(),
        };
        Self::all(&crate::vex::discover::discover_patched_refs_view(view, &opts).await)
    }

    /// `(name, version)` of the purl, percent-decoded.
    pub(crate) fn name_version(&self) -> Option<(String, String)> {
        let (_, name, version) = crate::utils::purl::purl_parts(&self.purl)?;
        Some((name, version))
    }
}

/// Hosted wiring the lockfiles mention that is NOT an attributable pin: a
/// Socket-hosted patch identity discovery recognized in `files` but could
/// not tie to one package version (a lock another lock contradicts, a
/// malformed or unattributable reference, a lockless registry pin). It is
/// still hosted state — management commands must refuse around it, never
/// read it as "no hosted patches".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestedWiring {
    /// The hosted patch uuid the files name.
    pub uuid: String,
    /// Root-relative files naming it, sorted and deduplicated.
    pub files: Vec<String>,
    /// Discovery's own findings for those files (`code: detail`), if any.
    pub details: Vec<String>,
    /// The ecosystems (`cargo`, `nuget`) of a LOCKLESS pin among this
    /// wiring: a registry pin no lockfile records a version for. Nothing
    /// the lockfiles hold can attribute it, so its remedy is to create the
    /// lockfile, not to reconcile one.
    pub lockless: BTreeSet<String>,
}

/// The project's hosted state as raw wiring: the attributable pins (what
/// restores and ejects act on) and the contested wiring (what they must
/// refuse around). VEX eligibility is a separate judgment over the same
/// discovery; this inventory keeps everything the lockfiles wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedInventory {
    pub pins: Vec<HostedPin>,
    pub contested: Vec<ContestedWiring>,
}

impl HostedInventory {
    pub fn of(discovery: &Discovery) -> Self {
        let pins = HostedPin::all(discovery);
        let norm = |p: &Path| p.to_string_lossy().replace('\\', "/");
        let pinned: BTreeSet<&str> = pins.iter().map(|p| p.uuid.as_str()).collect();
        // A hosted URL also carries its grant token as a uuid-shaped
        // segment, so an unpinned recognized uuid in a file that DOES carry
        // pins is contested only when discovery flagged that file.
        let pinned_files: BTreeSet<&str> = pins
            .iter()
            .flat_map(|p| p.files.iter().map(String::as_str))
            .collect();
        let flagged_files: BTreeSet<String> = discovery
            .diagnostics
            .iter()
            .filter(|d| {
                matches!(
                    d.code,
                    crate::vex::discover::DIAG_REF_INVALID
                        | crate::vex::discover::DIAG_REF_UNATTRIBUTABLE
                )
            })
            .map(|d| norm(&d.file))
            .collect();
        // The grant tokens of the attributable pins' own hosted URLs. The
        // sweep recognizes every uuid-shaped segment of a hosted URL, so a
        // file that repeats an attributed pin's URL names its token too:
        // the paired `pyproject.toml` `[tool.uv.sources]` entry of a
        // `uv.lock` pin (no pin file itself), or a `vlt-lock.json` whose pins
        // are refs but withheld from the lock basis (a flagged pin file).
        // Without a ledger that token is NOT unattributed hosted wiring: it
        // is excused in a file that also names the pin's own patch uuid.
        let pin_tokens: BTreeMap<String, BTreeSet<&str>> = {
            let mut tokens: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
            // A lockless pin's index url carries its token the same way.
            let urls = discovery
                .refs
                .iter()
                .chain(&discovery.shadowed)
                .filter(|r| r.mode == WiringMode::Hosted)
                .filter_map(|r| Some((r.url.as_deref()?, r.uuid.as_str())))
                .chain(
                    discovery
                        .unlocked_pins
                        .iter()
                        .filter_map(|p| Some((p.index_url.as_deref()?, p.uuid.as_str()))),
                );
            for (url, uuid) in urls {
                for token in url_uuid_segments(url) {
                    if token != uuid {
                        tokens.entry(token).or_default().insert(uuid);
                    }
                }
            }
            tokens
        };
        let hosted_in_file: BTreeSet<(String, &str)> = discovery
            .recognized
            .iter()
            .filter(|r| r.mode == WiringMode::Hosted)
            .map(|r| (norm(&r.file), r.uuid.as_str()))
            .collect();
        let is_pin_token = |uuid: &str, file: &str| {
            pin_tokens.get(uuid).is_some_and(|patches| {
                patches
                    .iter()
                    .any(|patch| hosted_in_file.contains(&(file.to_string(), *patch)))
            })
        };
        let mut contested: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut lockless: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for r in &discovery.recognized {
            let file = norm(&r.file);
            if r.mode == WiringMode::Hosted
                && !pinned.contains(r.uuid.as_str())
                && !is_pin_token(&r.uuid, &file)
                && (!pinned_files.contains(file.as_str()) || flagged_files.contains(&file))
            {
                contested
                    .entry(r.uuid.clone())
                    .or_default()
                    .insert(norm(&r.file));
            }
        }
        for pin in &discovery.unlocked_pins {
            if !pinned.contains(pin.uuid.as_str()) {
                contested
                    .entry(pin.uuid.clone())
                    .or_default()
                    .insert(norm(&pin.file));
                lockless
                    .entry(pin.uuid.clone())
                    .or_default()
                    .insert(pin.ecosystem.clone());
            }
        }
        let contested = contested
            .into_iter()
            .map(|(uuid, files)| {
                let details = discovery
                    .diagnostics
                    .iter()
                    .filter(|d| files.contains(&norm(&d.file)))
                    .map(|d| format!("{}: {}", d.code, d.detail))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                ContestedWiring {
                    lockless: lockless.remove(&uuid).unwrap_or_default(),
                    uuid,
                    files: files.into_iter().collect(),
                    details,
                }
            })
            .collect();
        HostedInventory { pins, contested }
    }

    /// Whether the lockfiles wire any hosted patch at all.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty() && self.contested.is_empty()
    }

    /// The refusal a management command raises while contested wiring
    /// exists: which files, why, and the remedy. `None` when uncontested.
    pub fn contested_refusal(&self) -> Option<String> {
        if self.contested.is_empty() {
            return None;
        }
        let files: BTreeSet<&str> = self
            .contested
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        let files: Vec<&str> = files.into_iter().collect();
        let details: Vec<&str> = self
            .contested
            .iter()
            .flat_map(|c| c.details.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let lockless: BTreeSet<&str> = self
            .contested
            .iter()
            .flat_map(|c| c.lockless.iter().map(String::as_str))
            .collect();
        let all_lockless = self.contested.iter().all(|c| !c.lockless.is_empty());
        // Files, not uuids: a hosted URL also carries its grant token as a
        // uuid-shaped segment, so the recognized set over-names patches.
        let mut msg = format!(
            "{} wire(s) Socket-hosted patches that cannot be attributed to one package \
             version ({}), so socket-patch cannot manage them safely",
            files.join(", "),
            if all_lockless {
                "no lockfile records which version the pin resolves"
            } else if lockless.is_empty() {
                "the lockfiles disagree, or the reference is malformed"
            } else {
                "the lockfiles disagree, the reference is malformed, or no lockfile records \
                 the pinned version"
            }
        );
        if !details.is_empty() {
            msg.push_str(&format!(" ({})", details.join("; ")));
        }
        // A lockless pin is attributed once its lockfile exists: re-running
        // the hosted scan alone would only write the same pin again.
        let mut remedies: Vec<String> = Vec::new();
        if !all_lockless {
            remedies.push(
                "reconcile the lockfiles (re-run `socket-patch scan --mode hosted`)".to_string(),
            );
        }
        for eco in &lockless {
            match *eco {
                "nuget" => remedies.push(
                    "create packages.lock.json (`dotnet restore --use-lock-file`)".to_string(),
                ),
                "cargo" => {
                    remedies.push("create Cargo.lock (`cargo generate-lockfile`)".to_string())
                }
                _ => {}
            }
        }
        remedies.push(format!(
            "restore them from version control (`git checkout -- {}`)",
            files.join(" ")
        ));
        msg.push_str(&format!("; {}", remedies.join(" or ")));
        Some(msg)
    }
}

/// The origins (`scheme://host[:port]`) of the patch servers `deps` are
/// served from — their artifact and registry index urls, a `sparse+` /
/// `registry+` kind prefix dropped — sorted and deduplicated. Passed as
/// discovery's extra origins, they let it recognize the pins a run writes
/// for them when the server is not the configured one.
pub fn dep_origins<'a>(deps: impl IntoIterator<Item = &'a super::DepOverride>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for dep in deps {
        let index = dep.registry_override.as_ref().map(|r| r.index_url.as_str());
        for url in std::iter::once(dep.artifact_url.as_str()).chain(index) {
            out.extend(dep_origins_of_url(url));
        }
    }
    out.into_iter().collect()
}

/// `scheme://host[:port]` of `url` (a `kind+` scheme prefix dropped, the
/// default port omitted), or `None` when it does not parse.
fn dep_origins_of_url(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, _) = url.split_once("://")?;
    let text = match scheme.rsplit_once('+') {
        Some((kind, _)) => &url[kind.len() + 1..],
        None => url,
    };
    let parsed = reqwest::Url::parse(text).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
}

/// [`dep_origins`] less the ones discovery already counts: Socket's own
/// patch server and `configured` (the operator's `--patch-server-url`). An
/// empty answer means a discovery over `configured` already recognizes
/// every pin these deps could have.
pub fn foreign_dep_origins<'a>(
    deps: impl IntoIterator<Item = &'a super::DepOverride>,
    configured: &[String],
) -> Vec<String> {
    dep_origins(deps)
        .into_iter()
        .filter(|origin| {
            let known = std::iter::once(format!("https://{}", super::SOCKET_PATCH_SERVER_HOST))
                .chain(configured.iter().cloned());
            !known
                .into_iter()
                .any(|k| dep_origins_of_url(&k).as_deref() == Some(origin.as_str()))
        })
        .collect()
}

/// The canonical-uuid path segments of a hosted URL discovery already
/// accepted (`\/` unescaped; a wholly percent-encoded URL decoded first;
/// each segment percent-decoded after splitting).
fn url_uuid_segments(url: &str) -> Vec<String> {
    use crate::patch::path_safety::is_canonical_uuid;
    use crate::utils::purl::percent_decode_purl_component;
    let unescaped = url.trim().replace("\\/", "/");
    let lower = unescaped.to_ascii_lowercase();
    let decoded = if lower.starts_with("https%3a%2f%2f") || lower.starts_with("http%3a%2f%2f") {
        percent_decode_purl_component(&unescaped).into_owned()
    } else {
        unescaped
    };
    let path = decoded.split(['?', '#']).next().unwrap_or_default();
    path.split('/')
        .map(|s| percent_decode_purl_component(s).into_owned())
        .filter(|s| is_canonical_uuid(s))
        .collect()
}

/// Knobs for [`restore_upstream`].
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// Resolve everything, write nothing.
    pub dry_run: bool,
    /// No network: every pin whose restore needs a registry lookup is
    /// refused with the checkout remedy.
    pub offline: bool,
    /// Extra patch-server origins whose URLs count as hosted (the
    /// operator's `--patch-server-url`), exactly as discovery takes them.
    pub patch_server_origins: Vec<String>,
    /// Restore hosted pins in a binary `bun.lockb` by rebuilding the npm
    /// registry record (see `bun_lockb`). Off, they are refused with the
    /// checkout remedy. The rebuild is exact for a lock the hosted rewrite
    /// wrote (a promoted format-1 lock is demoted back; a lock whose
    /// workspace dependency behaviors it normalized is refused), but only a
    /// vendor takeover — which re-records the rebuilt record as its own
    /// pre-vendor original — opts in; `rollback` keeps refusing.
    pub bun_lockb: bool,
}

/// What happened to one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// Every file wiring the pin now resolves the upstream registry entry
    /// (or would, on a dry run).
    Restored,
    /// Nothing was changed for this pin. The message names the remedy.
    Refused(String),
}

/// One pin's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinResult {
    pub purl: String,
    pub uuid: String,
    pub status: PinStatus,
    /// The files that wired the pin.
    pub files: Vec<String>,
}

/// What [`restore_upstream`] did.
#[derive(Debug, Default)]
pub struct RestoreOutcome {
    /// One entry per input pin, in input order.
    pub pins: Vec<PinResult>,
    /// Root-relative files rewritten or removed (or that would be, on a
    /// dry run), sorted.
    pub reverted_files: Vec<String>,
    /// Advisory `(code, detail)` pairs.
    pub warnings: Vec<(&'static str, String)>,
    /// The new text of each root-relative text file the restore rewrote (or
    /// would, on a dry run); `None` for a file it removed. Lets a caller
    /// evaluate the restored project before anything is written.
    pub staged_text: BTreeMap<String, Option<String>>,
    /// A write failure after every pin resolved: some files may have
    /// landed. `None` on a clean flush (and always on a dry run).
    pub flush_error: Option<String>,
}

impl RestoreOutcome {
    pub fn restored(&self) -> impl Iterator<Item = &PinResult> {
        self.pins.iter().filter(|p| p.status == PinStatus::Restored)
    }

    pub fn refused(&self) -> impl Iterator<Item = (&PinResult, &str)> {
        self.pins.iter().filter_map(|p| match &p.status {
            PinStatus::Refused(why) => Some((p, why.as_str())),
            PinStatus::Restored => None,
        })
    }
}

/// The remedy every refusal names: restore the file from version control.
/// For a Bun lock it also names `bun install --force`: Bun's hoisted linker
/// keeps the installed patched copy when the restored entry is the registry
/// copy of the same `name@version`, so a plain `bun install` after the
/// checkout reports no changes (#764).
pub fn checkout_remedy(files: &[String]) -> String {
    if files.is_empty() {
        return "restore the lockfile from version control (`git checkout -- <lockfile>`)"
            .to_string();
    }
    use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
    let bun = files.iter().any(|f| {
        let name = f.rsplit(['/', '\\']).next().unwrap_or(f);
        name == BUN_LOCK || name == BUN_LOCKB
    });
    format!(
        "restore it from version control instead (`git checkout -- {}`){}",
        files.join(" "),
        if bun {
            ", then run `bun install --force` (a plain `bun install` keeps the patched copy)"
        } else {
            ""
        }
    )
}

/// The staged project view the restorers work over: reads fall through to
/// disk, writes stay in memory until [`restore_upstream`] flushes them.
pub(crate) struct View<'a> {
    root: &'a Path,
    staged: Staged,
    /// Original on-disk text of every file read, so a write that restores
    /// the exact original bytes is not reported as a change.
    originals: BTreeMap<String, Option<String>>,
    /// Binary files (bun.lockb): staged bytes and their on-disk originals.
    staged_bytes: StagedBytes,
    original_bytes: BTreeMap<String, Option<Vec<u8>>>,
}

impl<'a> View<'a> {
    fn new(root: &'a Path) -> Self {
        View {
            root,
            staged: Staged::new(),
            originals: BTreeMap::new(),
            staged_bytes: StagedBytes::new(),
            original_bytes: BTreeMap::new(),
        }
    }

    /// The current (staged) bytes of the binary file `rel`; `Ok(None)` when
    /// absent. FIFO-guarded like [`Self::read`].
    pub(crate) async fn read_bytes(&mut self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        if let Some(pending) = self.staged_bytes.get(rel) {
            return Ok(Some(pending.clone()));
        }
        if let Some(original) = self.original_bytes.get(rel) {
            return Ok(original.clone());
        }
        let bytes = match crate::utils::fs::read_regular_to_bytes(&self.root.join(rel)).await {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("read {rel}: {e}")),
        };
        self.original_bytes.insert(rel.to_string(), bytes.clone());
        Ok(bytes)
    }

    pub(crate) fn write_bytes(&mut self, rel: &str, content: Vec<u8>) {
        self.staged_bytes.insert(rel.to_string(), content);
    }

    /// Binary files whose staged bytes differ from what was read from disk.
    fn changed_bytes(&self) -> StagedBytes {
        self.staged_bytes
            .iter()
            .filter(|(rel, pending)| {
                self.original_bytes.get(*rel).and_then(Option::as_ref) != Some(*pending)
            })
            .map(|(rel, pending)| (rel.clone(), pending.clone()))
            .collect()
    }

    pub(crate) fn root(&self) -> &Path {
        self.root
    }

    /// The current (staged) text of `rel`; `Ok(None)` when absent.
    pub(crate) async fn read(&mut self, rel: &str) -> Result<Option<String>, String> {
        if let Some(pending) = self.staged.get(rel) {
            return Ok(pending.clone());
        }
        if let Some(original) = self.originals.get(rel) {
            return Ok(original.clone());
        }
        let text = read_rel(self.root, rel).await?;
        self.originals.insert(rel.to_string(), text.clone());
        Ok(text)
    }

    pub(crate) fn write(&mut self, rel: &str, content: String) {
        self.staged.insert(rel.to_string(), Some(content));
    }

    pub(crate) fn remove(&mut self, rel: &str) {
        self.staged.insert(rel.to_string(), None);
    }

    /// Files whose staged state differs from what was read from disk.
    fn changed(&self) -> Staged {
        self.staged
            .iter()
            .filter(|(rel, pending)| self.originals.get(*rel) != Some(*pending))
            .map(|(rel, pending)| (rel.clone(), pending.clone()))
            .collect()
    }
}

/// Per-format restore result, merged across formats by the driver.
#[derive(Debug, Default)]
pub(crate) struct FormatResult {
    /// Pins (by uuid) this format refused, with the reason (the driver
    /// appends the remedy).
    pub refused: BTreeMap<String, String>,
    /// Pins (by uuid) this format found wired and restored in the view.
    pub handled: BTreeSet<String>,
    pub warnings: Vec<(&'static str, String)>,
}

impl FormatResult {
    pub(crate) fn refuse(&mut self, uuid: &str, why: impl Into<String>) {
        self.refused
            .entry(uuid.to_string())
            .or_insert_with(|| why.into());
    }

    fn merge(&mut self, other: FormatResult) {
        for (uuid, why) in other.refused {
            self.refused.entry(uuid).or_insert(why);
        }
        self.handled.extend(other.handled);
        self.warnings.extend(other.warnings);
    }
}

/// Shared context handed to every format restorer.
pub(crate) struct Ctx<'a> {
    pub client: &'a UpstreamClient,
    pub origins: &'a [String],
    /// [`RestoreOptions::bun_lockb`].
    pub bun_lockb: bool,
}

impl Ctx<'_> {
    /// The hosted patch uuid `url` names, under the same host allowlist
    /// discovery applies.
    pub(crate) fn hosted_uuid(&self, url: &str) -> Option<String> {
        super::hosted_patch_uuid(url, self.origins)
    }
}

/// The lock formats a pin's files belong to. One restorer per format sees
/// every in-scope pin wired in that format's files at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Format {
    NpmLock,
    YarnLock,
    PnpmLock,
    BunLock,
    /// Binary bun.lockb (restored only under [`RestoreOptions::bun_lockb`]).
    BunLockb,
    Cargo,
    Golang,
    Gem,
    Composer,
    PipfileLock,
    PoetryLock,
    PdmLock,
    Requirements,
    /// Hatch direct references (`pyproject.toml`, `hatch.toml`).
    Hatch,
    /// uv.lock, PEP 723 script locks and PEP 751 pylock files (the uv
    /// restorer also edits their paired `pyproject.toml` / script).
    PythonLock,
    VltLock,
    Maven,
    /// The hosted Gradle index (the restorer edits the settings, lock and
    /// verification files it implies).
    Gradle,
    /// The generated `socket-patch.sbt`.
    Sbt,
    NuGet,
    Unsupported,
}

fn format_of(rel: &str) -> Format {
    let leaf = rel.rsplit('/').next().unwrap_or(rel);
    match leaf {
        "package-lock.json" | "npm-shrinkwrap.json" => Format::NpmLock,
        "yarn.lock" => Format::YarnLock,
        "pnpm-lock.yaml" | "shrinkwrap.yaml" => Format::PnpmLock,
        "bun.lock" => Format::BunLock,
        "bun.lockb" => Format::BunLockb,
        "Cargo.toml" | "Cargo.lock" | "config.toml" | "config" => Format::Cargo,
        "go.mod" | "go.sum" | "go.work" => Format::Golang,
        "Gemfile.lock" | "gems.locked" | "Gemfile" | "gems.rb" => Format::Gem,
        "composer.lock" => Format::Composer,
        "Pipfile.lock" => Format::PipfileLock,
        "poetry.lock" => Format::PoetryLock,
        "pdm.lock" => Format::PdmLock,
        "pyproject.toml" | "hatch.toml" => Format::Hatch,
        leaf if crate::utils::python_lock::is_python_lock_name(leaf) => Format::PythonLock,
        // The root requirements.txt and the `-r` includes discovery walks.
        leaf if leaf.ends_with(".txt") => Format::Requirements,
        "vlt-lock.json" => Format::VltLock,
        "pom.xml" => Format::Maven,
        "hosted-index.tsv" => Format::Gradle,
        crate::formats::sbt::owned_file::HOSTED_FILE if !rel.contains('/') => Format::Sbt,
        "nuget.config" | "NuGet.config" | "NuGet.Config" | "packages.lock.json" => Format::NuGet,
        _ => Format::Unsupported,
    }
}

/// Restore every pin in `pins` to its default upstream registry entry.
/// See the module docs for the contract.
pub async fn restore_upstream(
    root: &Path,
    pins: &[HostedPin],
    opts: &RestoreOptions,
) -> RestoreOutcome {
    let client = UpstreamClient::new(opts.offline);
    let ctx = Ctx {
        client: &client,
        origins: &opts.patch_server_origins,
        bun_lockb: opts.bun_lockb,
    };

    // Pins refused so far (uuid → reason). Each pass restores the pins not
    // yet refused over a FRESH view; a pass that refuses a new pin is rerun
    // without it, so the final view restores exactly the surviving set.
    let mut refused: BTreeMap<String, String> = BTreeMap::new();
    let (view, result) = loop {
        let active: Vec<&HostedPin> = pins
            .iter()
            .filter(|p| !refused.contains_key(&p.uuid))
            .collect();
        let mut view = View::new(root);
        let result = restore_pass(&mut view, &active, &ctx).await;
        let mut grew = false;
        for (uuid, why) in &result.refused {
            if !refused.contains_key(uuid) {
                refused.insert(uuid.clone(), why.clone());
                grew = true;
            }
        }
        // A pin no restorer claimed has wiring nothing here can unwind.
        for pin in &active {
            if !result.handled.contains(&pin.uuid) && !refused.contains_key(&pin.uuid) {
                refused.insert(
                    pin.uuid.clone(),
                    format!(
                        "no hosted wiring for {} was found in {} that socket-patch can \
                         restore to the upstream registry entry",
                        pin.purl,
                        if pin.files.is_empty() {
                            "the lockfiles".to_string()
                        } else {
                            pin.files.join(", ")
                        }
                    ),
                );
                grew = true;
            }
        }
        if !grew {
            break (view, result);
        }
    };

    let changed = view.changed();
    let changed_bytes = view.changed_bytes();
    let reverted_files: BTreeSet<String> = changed
        .keys()
        .chain(changed_bytes.keys())
        .cloned()
        .collect();
    let flush_error = if opts.dry_run || (changed.is_empty() && changed_bytes.is_empty()) {
        None
    } else {
        flush_staged(root, &changed, &changed_bytes).await.err()
    };

    let pins_out = pins
        .iter()
        .map(|pin| PinResult {
            purl: pin.purl.clone(),
            uuid: pin.uuid.clone(),
            status: match refused.get(&pin.uuid) {
                Some(why) => PinStatus::Refused(format!(
                    "cannot restore {} to its upstream registry entry: {why}; {}",
                    pin.purl,
                    checkout_remedy(&pin.files)
                )),
                None => PinStatus::Restored,
            },
            files: pin.files.clone(),
        })
        .collect();

    RestoreOutcome {
        pins: pins_out,
        reverted_files: reverted_files.into_iter().collect(),
        warnings: result.warnings,
        staged_text: changed,
        flush_error,
    }
}

/// One restore pass over `view` for the `active` pins.
async fn restore_pass(view: &mut View<'_>, active: &[&HostedPin], ctx: &Ctx<'_>) -> FormatResult {
    let mut by_format: BTreeMap<Format, (Vec<&HostedPin>, BTreeSet<String>)> = BTreeMap::new();
    for pin in active {
        for file in &pin.files {
            let slot = by_format.entry(format_of(file)).or_default();
            if !slot.0.iter().any(|p| p.uuid == pin.uuid) {
                slot.0.push(pin);
            }
            slot.1.insert(file.clone());
        }
    }
    let mut out = FormatResult::default();
    for (format, (pins, files)) in by_format {
        let files: Vec<String> = files.into_iter().collect();
        let result = match format {
            Format::NpmLock => npm::restore_npm_locks(view, &pins, &files, ctx).await,
            Format::YarnLock => npm::restore_yarn_locks(view, &pins, &files, ctx).await,
            Format::PnpmLock => npm::restore_pnpm_locks(view, &pins, &files, ctx).await,
            Format::BunLock => npm::restore_bun_locks(view, &pins, &files, ctx).await,
            Format::BunLockb if ctx.bun_lockb => bun_lockb::restore(view, &pins, &files, ctx).await,
            Format::Cargo => cargo::restore(view, &pins, &files, ctx).await,
            Format::Golang => golang::restore(view, &pins, &files, ctx).await,
            Format::Gem => gem::restore(view, &pins, &files, ctx).await,
            Format::Composer => composer::restore(view, &pins, &files, ctx).await,
            Format::PipfileLock => pypi::restore_pipfile_lock(view, &pins, &files, ctx).await,
            Format::PoetryLock => pypi_locks::restore_poetry(view, &pins, &files, ctx).await,
            Format::PdmLock => pypi_locks::restore_pdm(view, &pins, &files, ctx).await,
            Format::Requirements => pypi::restore_requirements(view, &pins, &files, ctx).await,
            Format::Hatch => pypi::restore_hatch(view, &pins, &files, ctx).await,
            Format::PythonLock => uv::restore(view, &pins, &files, ctx).await,
            Format::VltLock => vlt::restore(view, &pins, &files, ctx).await,
            Format::Maven => maven::restore(view, &pins, &files, ctx).await,
            Format::Gradle => gradle::restore(view, &pins, &files, ctx).await,
            Format::Sbt => sbt::restore(view, &pins, &files, ctx).await,
            Format::NuGet => nuget::restore(view, &pins, &files, ctx).await,
            Format::Unsupported | Format::BunLockb => {
                let mut r = FormatResult::default();
                for pin in &pins {
                    let unsupported: Vec<&str> = pin
                        .files
                        .iter()
                        .filter(|f| format_of(f) == format)
                        .map(String::as_str)
                        .collect();
                    let why = if format == Format::BunLockb {
                        format!(
                            "{} is a binary lock whose rebuilt registry record is not \
                             byte-exact for every lock, so it is not restored here",
                            unsupported.join(", ")
                        )
                    } else {
                        format!(
                            "socket-patch cannot re-derive the upstream entry in {}",
                            unsupported.join(", ")
                        )
                    };
                    r.refuse(&pin.uuid, why);
                }
                r
            }
        };
        out.merge(result);
    }
    // The npm-family side settings a hosted run may have written, once no
    // npm-family lock entry needs them any more.
    npm::cleanup_side_config(view, ctx, &mut out).await;
    out
}

#[cfg(test)]
mod tests {
    use super::checkout_remedy;

    #[test]
    fn bun_lock_remedies_name_the_forced_reinstall() {
        for file in ["bun.lockb", "bun.lock", "packages/app/bun.lockb"] {
            let remedy = checkout_remedy(&[file.to_string()]);
            assert!(remedy.contains(&format!("`git checkout -- {file}`")), "{remedy}");
            assert!(remedy.ends_with(
                ", then run `bun install --force` (a plain `bun install` keeps the patched copy)"
            ), "{remedy}");
        }
        for file in ["yarn.lock", "package-lock.json", "bun.lock.bak"] {
            assert_eq!(
                checkout_remedy(&[file.to_string()]),
                format!("restore it from version control instead (`git checkout -- {file}`)")
            );
        }
    }
}
