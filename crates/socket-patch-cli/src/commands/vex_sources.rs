//! Attestation inputs for `vex`: the manifest, both `.socket/vendor`
//! ledgers, and the project's lockfiles (manifest-less VEX), merged into one
//! record view with a verification BASIS per purl.
//!
//! Sources, in record-priority order (a purl's record is the first one found
//! whose patch uuid is the one actually WIRED):
//!
//! 1. `.socket/manifest.json` (agent mode, and vendored mode's record owner);
//! 2. `.socket/vendor/redirect-state.json` `records` (hosted mode);
//! 3. `.socket/vendor/state.json` entry `record`s (vendored; always embedded
//!    by current writers, `detached` or not);
//! 4. online only: the patch API's view of the uuid (`get`'s
//!    `record_from_patch_response`, with its 401/403 → public-proxy
//!    fallback). Kept in memory — this module never writes the manifest.
//!
//! plus `vex::discover`'s lockfile references, which contribute two things:
//! patches that NO ledger or manifest records (a depscan PR, an uncommitted
//! ledger), and the WIRING-LIVENESS proof for ledger entries.
//!
//! Gates, applied before (and independently of) hash verification — so
//! `--no-verify` cannot bypass them:
//!
//! * **wiring conflict** (`wiring_conflict`): lockfiles that wire ONE
//!   package to several different patches attest none of them — neither
//!   the first-found guess nor a verified-plus-skipped pair for one purl;
//! * **wired uuid wins**: when the lockfile wires a purl to patch U, a
//!   manifest/ledger record for the same package under another uuid is
//!   superseded (it describes a patch the build no longer consumes);
//! * **record match** (`record_mismatch`): the record used for a discovered
//!   reference must carry the reference's uuid AND name the same package;
//! * **record available** (`record_unavailable`): a reference with no local
//!   record under `--offline`, or whose API fetch failed / 404'd / was
//!   refused, is omitted — never attested from the `socket-patch.vendor.json`
//!   marker, which carries no hashes and is not a trust input;
//! * **liveness** (`vendor_unwired` / `redirect_unwired`): a ledger entry
//!   attests only while some lockfile/config still wires it. For a patch
//!   uuid that ANY file discovery read mentions, the discovered references
//!   alone decide (core discover rule 11): an entry an extractor rejected
//!   (inert Go replace, orphaned berry entry, reverted cargo pin, uv lock
//!   its pyproject does not confirm, shadowed maven pin, a nuget source
//!   whose lock no longer restores the id) or a section the package manager
//!   ignores is dead (a LOCKLESS cargo pin / exclusive nuget mapping is live
//!   for the ledger's exact version — core `UnlockedPin`),
//!   whatever raw text survives. Only for a uuid no read file mentions
//!   (formats no extractor reads, patch servers outside the host allowlist)
//!   does the ledger's own recorded wiring decide — only files that PIN the
//!   resolution, never a leftover registry definition; a vendor entry
//!   recording no wiring (repair's reconstruction) probes its ecosystem's
//!   root locks; a lock inventory entry resolving the purl elsewhere is
//!   dead. A reverted lockfile plus a leftover ledger or artifact must not
//!   keep attesting.
//!   A dead vendor claim falls through to a live hosted claim for the same
//!   key (hosted takeover of a vendored package). A manifest-owned purl whose REDIRECT
//!   claim is dead simply falls back to agent-mode verification (hosted mode
//!   never takes ownership away from `apply`); a dead VENDOR claim omits the
//!   purl (vendor ownership makes `apply` skip it, so no agent-mode evidence
//!   is expected).
//!
//! Bases: `Vendored` verifies the committed artifact (the ledger entry when
//! it names the wired artifact — it carries the dir-artifact file inventory —
//! else an entry synthesized from the reference); `Hosted` verifies the
//! installed copies the build CONSUMES through the hosted wiring
//! ([`crate::commands::vex_consumed`] — never a pristine sibling the build
//! does not read, such as the original Go module beside its replacement)
//! when any exist ("installed evidence wins") and otherwise, for a
//! DISCOVERED Socket-host reference with a lockfile pin, attests from the
//! pinned wiring (the in-run `scan --mode hosted --vex` evidence);
//! `Installed` is the pre-existing agent-mode path.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::RedirectState;
use socket_patch_core::utils::composer_version::composer_purls_equivalent;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vendor::state::{lookup_entry_kv, VendorArtifact, VendorEntry, VendorState};
use socket_patch_core::vex::discover::{
    canonical_base_purl, vendor_ref, Discovery, LedgerLiveness, PatchedRef, WiringMode,
};
use socket_patch_core::vex::FailedPatch;

use crate::args::GlobalArgs;
use crate::ui::plural;

/// Omission tag: a lockfile-wired patch has no local record and none could
/// be fetched (offline, network error, 404, paid patch without a token).
pub(crate) const RECORD_UNAVAILABLE: &str = "record_unavailable";
/// Omission tag: the record found for a wired patch names another package
/// or another patch uuid than the wiring.
pub(crate) const RECORD_MISMATCH: &str = "record_mismatch";
/// Omission tag: a vendor-ledger entry whose committed artifact no lockfile
/// or config references any more.
pub(crate) const VENDOR_UNWIRED: &str = "vendor_unwired";
/// Omission tag: a hosted-redirect ledger record whose hosted patch no
/// lockfile references any more.
pub(crate) const REDIRECT_UNWIRED: &str = "redirect_unwired";
/// Omission tag: the project's lockfiles wire one package to two or more
/// DIFFERENT patches (e.g. a stale `package-lock.json` beside the
/// `npm-shrinkwrap.json`, or two package managers' locks that disagree).
/// Which one the build consumes is not decidable from the files, so no
/// candidate for that package attests.
pub(crate) const WIRING_CONFLICT: &str = "wiring_conflict";

/// Bound on concurrent patch-view fetches (one GET per uuid; the view
/// carries blob content, so it is heavy) — the batch fallback's limit.
const FETCH_CONCURRENCY: usize = 10;

/// Everything `vex` reads, loaded once by the caller (which owns the
/// corrupt-ledger hard errors).
pub(crate) struct Sources {
    /// The manifest file's contents (empty when the file is absent).
    pub manifest: PatchManifest,
    pub vendor: VendorState,
    pub redirect: Option<RedirectState>,
    pub discovery: Discovery,
}

impl Sources {
    /// Nothing anywhere could name a patch: no manifest patches, no ledger
    /// entries or records, no lockfile references.
    pub(crate) fn is_empty(&self) -> bool {
        self.manifest.patches.is_empty()
            && self.vendor.entries.is_empty()
            && self.redirect.as_ref().is_none_or(|r| r.records.is_empty())
            && self.discovery.refs.is_empty()
    }
}

/// The resolved attestation inputs.
pub(crate) struct Plan {
    /// purl → record for every candidate that passed the gates (with the
    /// manifest file's `setup` block, which property 7 reads).
    pub view: PatchManifest,
    /// Vendored-basis entries, keyed by view purl — the verification
    /// routing for `applied_patches_with_vendor`.
    pub vendor_entries: HashMap<String, VendorEntry>,
    /// Live hosted-basis view purls (the `(redirected)` marker and the
    /// property-7 bypass).
    pub redirected: Vec<String>,
    /// Hosted view purls that may attest from their pinned lockfile wiring
    /// when no installed tree exists.
    pub lockfile_basis: HashSet<String>,
    /// Every hosted-basis view purl (the `redirected` set) → what its hosted
    /// wiring is: the patch uuid it attests plus the discovered references
    /// (empty for a ledger-only record). Verification uses it to find the
    /// installed copy the build CONSUMES through that wiring
    /// ([`crate::commands::vex_consumed`]).
    pub hosted: BTreeMap<String, HostedWiring>,
    /// Candidates omitted by a gate, with their routing tag.
    pub gated: Vec<FailedPatch>,
    /// Run advisories (wiring conflicts, superseded or dead records, record
    /// fetch failures): `vex` emits each as a `warnings[]` entry, so the
    /// `--json` envelope carries the detail its skip codes cannot.
    pub notes: Vec<PlanNote>,
}

/// One [`Plan`] advisory: a stable `warnings[]` code and its detail.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PlanNote {
    pub code: &'static str,
    pub detail: String,
}

/// A lockfile wires the package to different patches (`wiring_conflict`).
pub(crate) const NOTE_WIRING_CONFLICT: &str = "vex_wiring_conflict";
/// A recorded patch is superseded by the lockfile-wired one.
pub(crate) const NOTE_RECORD_SUPERSEDED: &str = "vex_record_superseded";
/// A ledger claim died although the lockfiles still mention the patch.
pub(crate) const NOTE_CLAIM_UNWIRED: &str = "vex_claim_unwired";
/// `--offline` forbids fetching the records the plan needs.
pub(crate) const NOTE_RECORD_OFFLINE: &str = "vex_record_offline";
/// The patch API has no such patch.
pub(crate) const NOTE_RECORD_NOT_FOUND: &str = "vex_record_not_found";
/// A record fetch failed (transport, server, paid-only, ...).
pub(crate) const NOTE_RECORD_FETCH_FAILED: &str = "vex_record_fetch_failed";
/// The authenticated API refused the credentials; the public proxy served
/// the retry (free patches only) — `get` / `scan`'s fallback.
pub(crate) const NOTE_API_AUTH_FALLBACK: &str = "api_auth_fallback";

fn note(code: &'static str, detail: String) -> PlanNote {
    PlanNote { code, detail }
}

/// One hosted-basis view purl's wiring (see [`Plan::hosted`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedWiring {
    /// The patch uuid the purl attests.
    pub uuid: String,
    /// The discovered hosted references wiring it (their `url` / pin say
    /// WHERE the build fetches from — the Go replacement module + version,
    /// the cargo registry source); empty for a ledger-only record.
    pub refs: Vec<PatchedRef>,
}

/// How one view purl is verified.
enum Basis {
    /// The pre-existing agent-mode path: installed tree / go-patches copy.
    Installed,
    /// The committed `.socket/vendor` artifact named by this entry.
    Vendored(Box<VendorEntry>),
    /// Hosted wiring: installed tree when present, else the lockfile basis
    /// when `lockfile_basis`.
    Hosted { lockfile_basis: bool },
}

/// One attestation candidate (a would-be view purl).
struct Cand {
    key: String,
    /// The patch uuid this candidate attests.
    uuid: String,
    record: Option<PatchRecord>,
    /// Other local records filed under the same key (redirect ledger /
    /// vendor entry) — used when the WIRED uuid is theirs, not the primary's.
    alts: Vec<PatchRecord>,
    manifest_owned: bool,
    /// The redirect ledger records this key.
    redirected: bool,
    vendor_entry: Option<VendorEntry>,
    /// Lockfile references wiring this candidate's package to its uuid.
    discovered: Vec<PatchedRef>,
    /// Born from a lockfile reference no local source records.
    lockfile_only: bool,
}

impl Cand {
    fn from_ref(r: &PatchedRef, vendor: &VendorState) -> Self {
        // A ledger entry for the same patch + package (e.g. an old ledger
        // without an embedded record, whose manifest record is gone) still
        // routes verification: it carries the dir-artifact file inventory.
        let vendor_entry = vendor
            .entries
            .values()
            .find(|e| e.uuid == r.uuid && same_package(&canonical_base_purl(&e.base_purl), &r.purl))
            .cloned();
        Cand {
            key: r.purl.clone(),
            uuid: r.uuid.clone(),
            record: None,
            alts: Vec::new(),
            manifest_owned: false,
            redirected: false,
            vendor_entry,
            discovered: vec![r.clone()],
            lockfile_only: true,
        }
    }
}

/// Merge `sources` into a verified-input [`Plan`]. `assume_live` is the
/// in-run `scan --mode hosted --vex` confirmed set (qualifier-insensitive):
/// those ledger records were just proven wired by the run itself.
pub(crate) async fn plan(common: &GlobalArgs, sources: Sources, assume_live: &[String]) -> Plan {
    let root = common.cwd.as_path();
    let Sources {
        manifest,
        vendor,
        redirect,
        discovery,
    } = sources;
    let redirect_records: BTreeMap<String, PatchRecord> = redirect
        .as_ref()
        .map(|r| r.records.clone())
        .unwrap_or_default();
    let assumed: HashSet<&str> = assume_live
        .iter()
        .map(|p| strip_purl_qualifiers(p))
        .collect();

    let mut notes = Vec::new();
    let mut gated: Vec<FailedPatch> = Vec::new();
    let mut cands = build_candidates(&manifest, &vendor, &redirect_records);
    let conflicts = wiring_conflicts(&discovery);
    if !conflicts.is_empty() {
        // Gate every candidate for a conflicting package BEFORE anything can
        // attest it: keeping the first-found candidate would publish a
        // `not_affected` for a patch the build may not consume, next to a
        // skip for the same purl.
        let mut conflicted_keys: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        cands.retain(|c| {
            let pkg = canonical_base_purl(&c.key);
            match conflicts.iter().find(|(k, _)| same_package(k, &pkg)) {
                Some((k, _)) => {
                    conflicted_keys
                        .entry(k.as_str())
                        .or_default()
                        .push(c.key.clone());
                    false
                }
                None => true,
            }
        });
        for (pkg, wiring) in &conflicts {
            let mut keys = conflicted_keys.remove(pkg.as_str()).unwrap_or_default();
            if keys.is_empty() {
                keys.push(pkg.clone());
            }
            keys.sort();
            keys.dedup();
            for key in keys {
                gated.push(failed(&key, WIRING_CONFLICT));
            }
            notes.push(note(
                NOTE_WIRING_CONFLICT,
                format!(
                    "{pkg}: the lockfiles wire it to different patches ({wiring}); which one the \
                     build installs cannot be told from the files, so none is attested — make \
                     the lockfiles agree (re-run `socket-patch scan` or delete the stale lock)"
                ),
            ));
        }
    }
    let superseded = attach_discovered(&mut cands, &discovery, &vendor, &conflicts);
    for (key, old_uuid, wired) in &superseded {
        notes.push(note(
            NOTE_RECORD_SUPERSEDED,
            format!(
                "{key}: the recorded patch {old_uuid} is superseded by the lockfile-wired patch \
                 {wired}; attesting only what the lockfile wires"
            ),
        ));
    }

    // ── bases + liveness ────────────────────────────────────────────────
    let mut liveness = LedgerLiveness::new(root, &discovery, redirect.as_ref());
    let mut based: Vec<(Cand, Basis)> = Vec::new();
    for mut cand in cands {
        let basis = if let Some(vref) = cand
            .discovered
            .iter()
            .find(|r| r.mode == WiringMode::Vendored)
        {
            Basis::Vendored(Box::new(vendored_entry_for(&cand, vref)))
        } else if cand.discovered.iter().any(|r| r.mode == WiringMode::Hosted) {
            Basis::Hosted {
                lockfile_basis: cand.discovered.iter().any(PatchedRef::lockfile_basis_ok),
            }
        } else if let Some(entry) = &cand.vendor_entry {
            if liveness.vendor_entry(entry).await {
                Basis::Vendored(Box::new(entry.clone()))
            } else if let Some(hosted) = redirect_records.get(&cand.key).cloned() {
                // Hosted-over-vendored takeover: `scan --mode hosted` over a
                // vendored package leaves the vendor entry in place, so the
                // dead vendor claim does not end the story — the live hosted
                // claim (the redirect ledger's record, possibly another
                // uuid) is what the lockfile wires now.
                let live = assumed.contains(strip_purl_qualifiers(&cand.key))
                    || liveness.redirect_record(&cand.key, &hosted.uuid).await;
                if !live {
                    notes.extend(dead_claim_notes(
                        &discovery,
                        &cand.key,
                        &[
                            (&entry.uuid, WiringMode::Vendored, "vendor ledger"),
                            (&hosted.uuid, WiringMode::Hosted, "redirect ledger"),
                        ],
                    ));
                    gated.push(failed(&cand.key, VENDOR_UNWIRED));
                    continue;
                }
                cand.uuid = hosted.uuid.clone();
                cand.record = Some(hosted);
                cand.vendor_entry = None;
                Basis::Hosted {
                    lockfile_basis: false,
                }
            } else {
                notes.extend(dead_claim_notes(
                    &discovery,
                    &cand.key,
                    &[(&entry.uuid, WiringMode::Vendored, "vendor ledger")],
                ));
                gated.push(failed(&cand.key, VENDOR_UNWIRED));
                continue;
            }
        } else if cand.redirected {
            let live = assumed.contains(strip_purl_qualifiers(&cand.key))
                || liveness.redirect_record(&cand.key, &cand.uuid).await;
            if live {
                Basis::Hosted {
                    lockfile_basis: false,
                }
            } else if cand.manifest_owned {
                // The hosted claim is dead but the manifest still owns the
                // purl: verify it as the agent-mode patch it now is.
                Basis::Installed
            } else {
                notes.extend(dead_claim_notes(
                    &discovery,
                    &cand.key,
                    &[(&cand.uuid, WiringMode::Hosted, "redirect ledger")],
                ));
                gated.push(failed(&cand.key, REDIRECT_UNWIRED));
                continue;
            }
        } else {
            Basis::Installed
        };
        based.push((cand, basis));
    }

    // ── record resolution ───────────────────────────────────────────────
    let mut need_api: Vec<usize> = Vec::new();
    for (i, (cand, _)) in based.iter_mut().enumerate() {
        if cand.record.is_some() {
            continue;
        }
        let expected_pkg = expected_package(cand);
        match local_record_by_uuid(&cand.uuid, &manifest, &redirect_records, &vendor) {
            Some((found_key, record))
                if same_package(&canonical_base_purl(&found_key), &expected_pkg) =>
            {
                if cand.lockfile_only {
                    cand.key = found_key;
                }
                cand.record = Some(record);
            }
            // The uuid's local record is filed under another package: the
            // wiring and the record disagree about what was patched.
            Some(_) => cand.record = None,
            None => need_api.push(i),
        }
    }
    let uuids: Vec<String> = {
        let mut u: Vec<String> = need_api.iter().map(|&i| based[i].0.uuid.clone()).collect();
        u.sort();
        u.dedup();
        u
    };
    let fetched = fetch_records(common, &uuids, &mut notes).await;
    let mut mismatched: HashSet<usize> = HashSet::new();
    for &i in &need_api {
        let cand = &mut based[i].0;
        match fetched.get(&cand.uuid) {
            Some((api_purl, record))
                if record.uuid == cand.uuid
                    && same_package(&canonical_base_purl(api_purl), &expected_package(cand)) =>
            {
                if cand.lockfile_only {
                    cand.key = api_purl.clone();
                }
                cand.record = Some(record.clone());
            }
            Some(_) => {
                mismatched.insert(i);
            }
            None => {}
        }
    }

    // ── assemble ────────────────────────────────────────────────────────
    let mut plan = Plan {
        view: PatchManifest {
            patches: HashMap::new(),
            setup: manifest.setup.clone(),
        },
        vendor_entries: HashMap::new(),
        redirected: Vec::new(),
        lockfile_basis: HashSet::new(),
        hosted: BTreeMap::new(),
        gated,
        notes,
    };
    // Keys two candidates resolved to (see the collision branch below).
    let mut collided: HashSet<String> = HashSet::new();
    for (i, (cand, basis)) in based.into_iter().enumerate() {
        let Some(record) = cand.record else {
            let tag = if mismatched.contains(&i) || !need_api.contains(&i) {
                RECORD_MISMATCH
            } else {
                RECORD_UNAVAILABLE
            };
            plan.gated.push(failed(&cand.key, tag));
            continue;
        };
        if collided.contains(&cand.key) || plan.view.patches.contains_key(&cand.key) {
            // Two candidates resolved to ONE purl with different records
            // (a lockfile-only candidate renamed to the key its record is
            // filed under, colliding with an existing candidate). Neither
            // guess may attest: evict the first — its view entry and every
            // basis entry — and omit both, so the purl never carries a
            // statement and a skip at once.
            if plan.view.patches.remove(&cand.key).is_some() {
                plan.vendor_entries.remove(&cand.key);
                plan.redirected.retain(|k| *k != cand.key);
                plan.lockfile_basis.remove(&cand.key);
                plan.hosted.remove(&cand.key);
            }
            collided.insert(cand.key.clone());
            plan.gated.push(failed(&cand.key, RECORD_MISMATCH));
            continue;
        }
        match basis {
            Basis::Installed => {}
            Basis::Vendored(entry) => {
                plan.vendor_entries.insert(cand.key.clone(), *entry);
            }
            Basis::Hosted { lockfile_basis } => {
                plan.redirected.push(cand.key.clone());
                if lockfile_basis {
                    plan.lockfile_basis.insert(cand.key.clone());
                }
                plan.hosted.insert(
                    cand.key.clone(),
                    HostedWiring {
                        uuid: record.uuid.clone(),
                        refs: cand
                            .discovered
                            .iter()
                            .filter(|r| r.mode == WiringMode::Hosted && r.uuid == record.uuid)
                            .cloned()
                            .collect(),
                    },
                );
            }
        }
        plan.view.patches.insert(cand.key, record);
    }
    plan.redirected.sort();
    // One skip per (purl, reason): a collision gates its key once per
    // colliding candidate.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    plan.gated
        .retain(|f| seen.insert((f.purl.clone(), f.reason.clone())));
    plan
}

fn failed(purl: &str, reason: &str) -> FailedPatch {
    FailedPatch {
        purl: purl.to_string(),
        reason: reason.to_string(),
    }
}

/// Whether two [`canonical_base_purl`] spellings name one package release:
/// equal, or composer spellings of the same release (a lock's `@3.0.2`, a
/// patch purl's padded `@3.0.2.0`).
fn same_package(a: &str, b: &str) -> bool {
    a == b || composer_purls_equivalent(a, b)
}

/// The package a candidate's record must name (canonical form).
fn expected_package(cand: &Cand) -> String {
    match (&cand.vendor_entry, cand.lockfile_only) {
        (Some(entry), false) => canonical_base_purl(&entry.base_purl),
        _ => canonical_base_purl(&cand.key),
    }
}

/// One candidate per manifest key, then per unclaimed vendor-ledger key,
/// then per unclaimed redirect-ledger key — the pre-existing collision rule
/// (the manifest owns a key it records; ledgers fill the rest), in sorted
/// order so the output is deterministic.
fn build_candidates(
    manifest: &PatchManifest,
    vendor: &VendorState,
    redirect_records: &BTreeMap<String, PatchRecord>,
) -> Vec<Cand> {
    let mut cands = Vec::new();
    let mut claimed_entries: HashSet<&str> = HashSet::new();
    let mut manifest_keys: Vec<&String> = manifest.patches.keys().collect();
    manifest_keys.sort();
    for key in manifest_keys {
        let record = &manifest.patches[key];
        let entry = lookup_entry_kv(&vendor.entries, key);
        let mut alts = Vec::new();
        if let Some((entry_key, e)) = entry {
            claimed_entries.insert(entry_key.as_str());
            alts.extend(e.record.clone());
        }
        alts.extend(redirect_records.get(key).cloned());
        cands.push(Cand {
            key: key.clone(),
            uuid: record.uuid.clone(),
            record: Some(record.clone()),
            alts,
            manifest_owned: true,
            redirected: redirect_records.contains_key(key),
            vendor_entry: entry.map(|(_, e)| e.clone()),
            discovered: Vec::new(),
            lockfile_only: false,
        });
    }
    let mut vendor_keys: Vec<&String> = vendor.entries.keys().collect();
    vendor_keys.sort();
    for key in vendor_keys {
        if claimed_entries.contains(key.as_str()) || manifest.patches.contains_key(key) {
            continue;
        }
        let entry = &vendor.entries[key];
        cands.push(Cand {
            key: key.clone(),
            uuid: entry.uuid.clone(),
            record: entry.record.clone(),
            alts: redirect_records.get(key).cloned().into_iter().collect(),
            manifest_owned: false,
            redirected: redirect_records.contains_key(key),
            vendor_entry: Some(entry.clone()),
            discovered: Vec::new(),
            lockfile_only: false,
        });
    }
    for (purl, record) in redirect_records {
        if cands.iter().any(|c| c.key == *purl) {
            continue;
        }
        cands.push(Cand {
            key: purl.clone(),
            uuid: record.uuid.clone(),
            record: Some(record.clone()),
            alts: Vec::new(),
            manifest_owned: false,
            redirected: true,
            vendor_entry: None,
            discovered: Vec::new(),
            lockfile_only: false,
        });
    }
    cands
}

/// Packages the discovered references wire to MORE than one patch uuid
/// (any mix of modes and files), mapped to a human description of the
/// disagreeing wiring (`<uuid> (<file>), …`) for the note.
fn wiring_conflicts(discovery: &Discovery) -> BTreeMap<String, String> {
    let mut by_pkg: BTreeMap<&str, BTreeMap<&str, BTreeSet<String>>> = BTreeMap::new();
    for r in &discovery.refs {
        by_pkg
            .entry(r.purl.as_str())
            .or_default()
            .entry(r.uuid.as_str())
            .or_default()
            .insert(r.source_file.to_string_lossy().into_owned());
    }
    by_pkg
        .into_iter()
        .filter(|(_, uuids)| uuids.len() > 1)
        .map(|(pkg, uuids)| {
            let wiring: Vec<String> = uuids
                .into_iter()
                .map(|(uuid, files)| {
                    format!(
                        "{uuid} ({})",
                        files.into_iter().collect::<Vec<_>>().join(", ")
                    )
                })
                .collect();
            (pkg.to_string(), wiring.join(", "))
        })
        .collect()
}

/// Attach every lockfile reference (except those of `conflicts`' packages,
/// already gated) to the candidate(s) for its package and patch; a package the lockfile wires to a patch no candidate records gets
/// a new lockfile-only candidate, and a candidate for a wired package whose
/// uuid the lockfile does NOT wire is superseded (removed). Returns
/// `(key, superseded uuid, wired uuids)` for the human notes.
fn attach_discovered(
    cands: &mut Vec<Cand>,
    discovery: &Discovery,
    vendor: &VendorState,
    conflicts: &BTreeMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut groups: BTreeMap<&str, Vec<&PatchedRef>> = BTreeMap::new();
    for r in &discovery.refs {
        if !conflicts.contains_key(&r.purl) {
            groups.entry(r.purl.as_str()).or_default().push(r);
        }
    }
    let mut new_cands: Vec<Cand> = Vec::new();
    let mut superseded_idx: Vec<usize> = Vec::new();
    let mut superseded = Vec::new();
    for (pkg, refs) in groups {
        let idxs: Vec<usize> = (0..cands.len())
            .filter(|&i| same_package(&canonical_base_purl(&cands[i].key), pkg))
            .collect();
        // Pass 1: the candidate already attests the wired uuid.
        let mut unmatched: Vec<&PatchedRef> = Vec::new();
        for r in &refs {
            let mut matched = false;
            for &i in &idxs {
                if cands[i].uuid == r.uuid {
                    cands[i].discovered.push((*r).clone());
                    matched = true;
                }
            }
            if !matched {
                unmatched.push(r);
            }
        }
        // Pass 2: an unconfirmed candidate holds the wired uuid's record as
        // an alternative (manifest says U1, its redirect/vendor ledger
        // record says the wired U2): the wired uuid wins.
        let mut remaining: Vec<&PatchedRef> = Vec::new();
        for r in unmatched {
            let mut matched = false;
            for &i in &idxs {
                let cand = &mut cands[i];
                if cand.uuid != r.uuid && !cand.discovered.is_empty() {
                    continue;
                }
                if cand.uuid != r.uuid {
                    let Some(alt) = cand.alts.iter().find(|a| a.uuid == r.uuid).cloned() else {
                        continue;
                    };
                    cand.uuid = alt.uuid.clone();
                    cand.record = Some(alt);
                }
                cand.discovered.push(r.clone());
                matched = true;
            }
            if !matched {
                remaining.push(r);
            }
        }
        // Wired patches nothing local records: lockfile-only candidates
        // (one per uuid; several files may wire the same patch).
        for r in remaining {
            match new_cands
                .iter_mut()
                .find(|c| c.key == r.purl && c.uuid == r.uuid)
            {
                Some(existing) => existing.discovered.push(r.clone()),
                None => new_cands.push(Cand::from_ref(r, vendor)),
            }
        }
        let wired: Vec<&str> = {
            let mut u: Vec<&str> = refs.iter().map(|r| r.uuid.as_str()).collect();
            u.sort();
            u.dedup();
            u
        };
        for &i in &idxs {
            if cands[i].discovered.is_empty() {
                superseded_idx.push(i);
                superseded.push((
                    cands[i].key.clone(),
                    cands[i].uuid.clone(),
                    wired.join(", "),
                ));
            }
        }
    }
    superseded_idx.sort_unstable();
    for i in superseded_idx.into_iter().rev() {
        cands.remove(i);
    }
    cands.extend(new_cands);
    superseded
}

/// The artifact entry a vendored reference verifies against: the ledger
/// entry when it names exactly the wired artifact (it carries the
/// dir-artifact file inventory), else one synthesized from the reference.
/// A synthesized entry has no `file_inventory` (member-only verification of
/// dir-shaped artifacts — the documented weaker basis) and no `sha256`
/// (nothing in verification asserts it; the bun mirror check recomputes the
/// canonical tarball digest).
fn vendored_entry_for(cand: &Cand, vref: &PatchedRef) -> VendorEntry {
    let wired = vref.artifact_rel.as_deref().unwrap_or_default();
    if let Some(entry) = &cand.vendor_entry {
        if entry.uuid == vref.uuid && entry.artifact.path.trim_start_matches("./") == wired {
            return entry.clone();
        }
    }
    let eco = vendor_ref(wired).map(|v| v.eco).unwrap_or_default();
    let source = vref.source_file.to_string_lossy();
    VendorEntry {
        ecosystem: eco,
        base_purl: strip_purl_qualifiers(&cand.key).to_string(),
        uuid: vref.uuid.clone(),
        artifact: VendorArtifact {
            path: wired.to_string(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        },
        wiring: Vec::new(),
        lock: None,
        took_over_go_patches: false,
        // Bun's workspace-mirror integrity check keys off the flavor.
        flavor: (source == "bun.lock" || source == "bun.lockb").then(|| "bun".to_string()),
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
        detached: true,
        record: None,
    }
}

/// [`recognized_dead_note`] for each dead `(uuid, mode, ledger)` claim of
/// one candidate.
fn dead_claim_notes(
    discovery: &Discovery,
    key: &str,
    claims: &[(&str, WiringMode, &str)],
) -> Vec<PlanNote> {
    claims
        .iter()
        .filter_map(|(uuid, mode, ledger)| {
            recognized_dead_note(discovery, key, uuid, *mode, ledger)
        })
        .map(|detail| note(NOTE_CLAIM_UNWIRED, detail))
        .collect()
}

/// The human note for a ledger claim discovery's authority killed although
/// the lockfiles still MENTION the patch (rule 11): which files, and the
/// extractor's own reason when it gave one (a diagnostic from one of those
/// files naming the uuid). `None` when discovery does not recognize the
/// uuid — the claim then died on the ledger's own evidence, and the skip
/// reason says all there is.
fn recognized_dead_note(
    discovery: &Discovery,
    key: &str,
    uuid: &str,
    mode: WiringMode,
    ledger: &str,
) -> Option<String> {
    let files = discovery.recognized_files(uuid, mode);
    if files.is_empty() {
        return None;
    }
    let reason = discovery
        .diagnostics
        .iter()
        .find(|d| files.contains(&d.file.as_path()) && d.detail.contains(uuid))
        .map(|d| format!(" ({}: {})", d.code, d.detail))
        .unwrap_or_default();
    let names: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
    Some(format!(
        "{key}: the {ledger} records patch {uuid}, and {} still mention{} it, but not as \
         wiring the package manager consumes for this package{reason}; not attested",
        names.join(", "),
        if names.len() == 1 { "s" } else { "" },
    ))
}

/// A local record for `uuid` (manifest, then redirect ledger, then vendor
/// entries) with the key it is filed under.
fn local_record_by_uuid(
    uuid: &str,
    manifest: &PatchManifest,
    redirect_records: &BTreeMap<String, PatchRecord>,
    vendor: &VendorState,
) -> Option<(String, PatchRecord)> {
    let mut manifest_hits: Vec<(&String, &PatchRecord)> = manifest
        .patches
        .iter()
        .filter(|(_, r)| r.uuid == uuid)
        .collect();
    manifest_hits.sort_by(|a, b| a.0.cmp(b.0));
    if let Some((k, r)) = manifest_hits.first() {
        return Some(((*k).clone(), (*r).clone()));
    }
    if let Some((k, r)) = redirect_records.iter().find(|(_, r)| r.uuid == uuid) {
        return Some((k.clone(), r.clone()));
    }
    let mut vendor_hits: Vec<(&String, &PatchRecord)> = vendor
        .entries
        .iter()
        .filter_map(|(k, e)| e.record.as_ref().map(|r| (k, r)))
        .filter(|(_, r)| r.uuid == uuid)
        .collect();
    vendor_hits.sort_by(|a, b| a.0.cmp(b.0));
    vendor_hits
        .first()
        .map(|(k, r)| ((*k).clone(), (*r).clone()))
}

/// Fetch the patch view for each of `uuids` (online only; empty under
/// `--offline`) with bounded concurrency and `get`'s one-shot 401/403 →
/// public-proxy fallback. Returns `uuid → (api purl, record)` for every view
/// that came back; 404s, refusals and transport errors are simply absent
/// (the caller omits those references as `record_unavailable`) and noted.
async fn fetch_records(
    common: &GlobalArgs,
    uuids: &[String],
    notes: &mut Vec<PlanNote>,
) -> HashMap<String, (String, PatchRecord)> {
    let mut out = HashMap::new();
    if uuids.is_empty() {
        return out;
    }
    if common.offline {
        let n = uuids.len();
        notes.push(note(
            NOTE_RECORD_OFFLINE,
            format!(
                "{} no local record (manifest or .socket/vendor ledgers), and --offline forbids \
                 fetching {} from the patch API",
                plural(n, "lockfile-wired patch has", "lockfile-wired patches have"),
                if n == 1 { "it" } else { "them" },
            ),
        ));
        return out;
    }
    let overrides = common.api_client_overrides();
    let (mut client, mut use_public_proxy) = get_api_client_with_overrides(overrides.clone()).await;
    let mut pending: Vec<String> = uuids.to_vec();
    // Each view is a heavy response: say what the run is waiting on (a live
    // line only on a terminal, never under --json / --silent; the VEX
    // document itself goes to stdout).
    let mut status = crate::ui::StatusLine::stderr(common.json, common.silent);
    let total = uuids.len();
    let mut done = 0;
    loop {
        let mut auth_refused: Vec<String> = Vec::new();
        let mut auth_error: Option<String> = None;
        for chunk in pending.chunks(FETCH_CONCURRENCY) {
            status.set(format!(
                "Fetching {}... ({done}/{total})",
                if total == 1 {
                    "the patch record"
                } else {
                    "patch records"
                }
            ));
            let mut set = tokio::task::JoinSet::new();
            for uuid in chunk {
                let client = client.clone();
                let uuid = uuid.clone();
                set.spawn(async move {
                    let result = client.fetch_patch(&uuid).await;
                    (uuid, result)
                });
            }
            while let Some(joined) = set.join_next().await {
                let Ok((uuid, result)) = joined else {
                    continue;
                };
                done += 1;
                match result {
                    Ok(Some(view)) => {
                        out.insert(
                            uuid,
                            crate::commands::get::record_from_patch_response(&view),
                        );
                    }
                    Ok(None) => notes.push(note(
                        NOTE_RECORD_NOT_FOUND,
                        format!("Patch {uuid} was not found by the patch API"),
                    )),
                    Err(e) if !use_public_proxy && is_fallback_candidate(&e) => {
                        auth_error.get_or_insert_with(|| e.to_string());
                        auth_refused.push(uuid)
                    }
                    Err(e) => notes.push(note(
                        NOTE_RECORD_FETCH_FAILED,
                        format!("Could not fetch patch {uuid}: {e}"),
                    )),
                }
            }
        }
        if auth_refused.is_empty() || use_public_proxy {
            break;
        }
        // Same stale-credential recovery (and warning text) as `get` /
        // `scan`: free patches are still served by the public proxy.
        notes.push(note(
            NOTE_API_AUTH_FALLBACK,
            format!(
                "authenticated API returned {}; falling back to public patch API proxy (free \
                 patches only).",
                auth_error.unwrap_or_default()
            ),
        ));
        client = build_proxy_fallback_client(&overrides);
        use_public_proxy = true;
        // The refused views are fetched again: not done yet.
        done = total - auth_refused.len();
        pending = auth_refused;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, VulnerabilityInfo};
    use socket_patch_core::vendor::lock_inventory::LockIntegrity;
    use std::path::Path;

    const U1: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const U2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    fn record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files: [(
                "package/index.js".to_string(),
                PatchFileInfo {
                    before_hash: String::new(),
                    after_hash: "a".repeat(64),
                },
            )]
            .into_iter()
            .collect(),
            vulnerabilities: [(
                "GHSA-x".to_string(),
                VulnerabilityInfo {
                    cves: vec![],
                    summary: String::new(),
                    severity: String::new(),
                    description: String::new(),
                },
            )]
            .into_iter()
            .collect(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn hosted_ref(purl: &str, uuid: &str, pinned: bool) -> PatchedRef {
        PatchedRef::hosted(
            purl.to_string(),
            uuid.to_string(),
            "package-lock.json",
            None,
            pinned.then(|| LockIntegrity::Sri("sha512-x".into())),
            true,
        )
    }

    fn common(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..GlobalArgs::default()
        }
    }

    fn discovery(refs: Vec<PatchedRef>) -> Discovery {
        let mut d = Discovery::default();
        for r in refs {
            d.push(r);
        }
        d
    }

    /// The lockfile wires U2; the manifest records U1 and the redirect
    /// ledger U2 under the same key: the WIRED uuid's record wins.
    #[tokio::test]
    async fn wired_uuid_selects_the_alternative_record() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U2));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U2, true)]),
        };
        let plan = plan(&common(tmp.path()), sources, &[]).await;
        assert_eq!(plan.view.patches["pkg:npm/x@1.0.0"].uuid, U2);
        assert_eq!(plan.redirected, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(plan.lockfile_basis.contains("pkg:npm/x@1.0.0"));
        assert!(plan.gated.is_empty(), "{:?}", plan.gated);
    }

    /// Superseded: the manifest's U1 record for a package the lockfile wires
    /// to U2 is dropped; U2 with no local record is `record_unavailable`
    /// offline.
    #[tokio::test]
    async fn superseded_manifest_record_and_offline_lockfile_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: None,
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U2, true)]),
        };
        let plan = plan(&common(tmp.path()), sources, &[]).await;
        assert!(
            plan.view.patches.is_empty(),
            "{:?}",
            plan.view.patches.keys()
        );
        assert_eq!(
            plan.gated,
            vec![failed("pkg:npm/x@1.0.0", RECORD_UNAVAILABLE)]
        );
        assert!(plan
            .notes
            .iter()
            .any(|n| n.code == NOTE_RECORD_SUPERSEDED && n.detail.contains("superseded")));
        assert!(plan
            .notes
            .iter()
            .any(|n| n.code == NOTE_RECORD_OFFLINE && n.detail.contains("--offline")));
    }

    /// A lockfile ref whose only local record (by uuid) is filed under a
    /// different package: `record_mismatch`, never attested.
    #[tokio::test]
    async fn record_for_another_package_is_a_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/other@2.0.0".into(), record(U1));
        let sources = Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U1, true)]),
        };
        let plan = plan(&common(tmp.path()), sources, &[]).await;
        assert!(plan
            .gated
            .contains(&failed("pkg:npm/x@1.0.0", RECORD_MISMATCH)));
        // And the ledger record for `other` is NOT live: discovery sees U1
        // wired — to a different package.
        assert!(plan
            .gated
            .contains(&failed("pkg:npm/other@2.0.0", REDIRECT_UNWIRED)));
        assert!(plan.view.patches.is_empty());
    }

    /// Two lockfiles wiring one package to different patches: every
    /// candidate for it is gated `wiring_conflict` exactly once, none
    /// reaches the view (no statement next to a skip), and other packages
    /// are unaffected.
    #[tokio::test]
    async fn conflicting_wiring_gates_every_candidate_once() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        manifest
            .patches
            .insert("pkg:npm/y@1.0.0".into(), record(U2));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U2));
        let mut shrinkwrap = hosted_ref("pkg:npm/x@1.0.0", U2, true);
        shrinkwrap.source_file = "npm-shrinkwrap.json".into();
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![
                hosted_ref("pkg:npm/x@1.0.0", U1, true),
                shrinkwrap,
                hosted_ref("pkg:npm/y@1.0.0", U2, true),
            ]),
        };
        let plan = plan(&common(tmp.path()), sources, &[]).await;
        assert_eq!(plan.gated, vec![failed("pkg:npm/x@1.0.0", WIRING_CONFLICT)]);
        assert!(!plan.view.patches.contains_key("pkg:npm/x@1.0.0"));
        assert!(!plan.redirected.contains(&"pkg:npm/x@1.0.0".to_string()));
        assert_eq!(plan.view.patches["pkg:npm/y@1.0.0"].uuid, U2);
        assert!(plan.notes.iter().any(|n| n.code == NOTE_WIRING_CONFLICT
            && n.detail.contains("npm-shrinkwrap.json")
            && n.detail.contains("package-lock.json")));
    }

    /// Hosted takeover of a vendored package (vendor entry U1 unwired,
    /// redirect record U2 for the same key): the candidate switches to the
    /// hosted claim instead of being gated `vendor_unwired` — but only while
    /// the hosted claim is live (here: the in-run confirmed set).
    #[tokio::test]
    async fn dead_vendor_claim_falls_through_to_a_live_hosted_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let key = "pkg:npm/x@1.0.0";
        let mut vendor = VendorState::new();
        vendor.entries.insert(
            key.into(),
            VendorEntry {
                ecosystem: "npm".into(),
                base_purl: key.into(),
                uuid: U1.into(),
                artifact: VendorArtifact {
                    path: format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring: Vec::new(),
                lock: None,
                took_over_go_patches: false,
                flavor: None,
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
                detached: true,
                record: Some(record(U1)),
            },
        );
        let mut redirect = RedirectState::new();
        redirect.records.insert(key.into(), record(U2));
        let mk = || Sources {
            manifest: PatchManifest::new(),
            vendor: vendor.clone(),
            redirect: Some(redirect.clone()),
            discovery: Discovery::default(),
        };
        let live = plan(&common(tmp.path()), mk(), &[key.to_string()]).await;
        assert_eq!(live.view.patches[key].uuid, U2);
        assert_eq!(live.redirected, vec![key.to_string()]);
        assert!(live.vendor_entries.is_empty());
        assert!(live.gated.is_empty(), "{:?}", live.gated);

        let dead = plan(&common(tmp.path()), mk(), &[]).await;
        assert!(dead.view.patches.is_empty());
        assert_eq!(dead.gated, vec![failed(key, VENDOR_UNWIRED)]);
    }

    /// Core discover rule 11 through the plan: a vendor ledger entry and a
    /// redirect ledger record whose patches the lockfiles MENTION only in
    /// shapes the extractors rejected are dead — `vendor_unwired` /
    /// `redirect_unwired`, with a note naming the file and the extractor's
    /// reason — although the raw-text fallbacks would call both live (the
    /// files hold each uuid in pin position; the unrecognized control run
    /// proves it). Before, exactly this re-derivation from raw text attested
    /// an orphaned berry entry and a reverted cargo pin.
    #[tokio::test]
    async fn recognized_but_rejected_uuids_are_dead_whatever_the_raw_text_says() {
        use socket_patch_core::vendor::state::{WiringAction, WiringRecord};
        use socket_patch_core::vex::{Diag, Recognized};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{U1}/x-1.0.0.tgz");
        std::fs::write(
            root.join("yarn.lock"),
            format!("resolved \"file:./{rel}#abc\"\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            format!(
                "source = \"sparse+https://patch.socket.dev/patch-registry/cargo/tok/{U2}/index/\"\n"
            ),
        )
        .unwrap();
        let mut vendor = VendorState::new();
        vendor.entries.insert(
            "pkg:npm/x@1.0.0".into(),
            VendorEntry {
                ecosystem: "npm".into(),
                base_purl: "pkg:npm/x@1.0.0".into(),
                uuid: U1.into(),
                artifact: VendorArtifact {
                    path: rel.clone(),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring: vec![WiringRecord {
                    file: "yarn.lock".into(),
                    kind: "yarn_lock_entry".into(),
                    action: WiringAction::Rewritten,
                    key: None,
                    original: None,
                    new: None,
                }],
                lock: None,
                took_over_go_patches: false,
                flavor: None,
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
                detached: true,
                record: Some(record(U1)),
            },
        );
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:cargo/y@1.0.0".into(), record(U2));
        redirect
            .edits
            .push(socket_patch_core::patch::redirect::FileEdit {
                path: "Cargo.lock".into(),
                kind: "redirect_cargo".into(),
                action: "rewritten".into(),
                key: None,
                original: None,
                new: None,
            });
        let sources = |discovery: Discovery| Sources {
            manifest: PatchManifest::new(),
            vendor: vendor.clone(),
            redirect: Some(redirect.clone()),
            discovery,
        };

        // Control — nothing recognized: the ledgers' own recorded files
        // decide, and both claims are live.
        let live = plan(&common(root), sources(Discovery::default()), &[]).await;
        assert!(live.gated.is_empty(), "{:?}", live.gated);
        assert!(live.view.patches.contains_key("pkg:npm/x@1.0.0"));
        assert_eq!(live.redirected, vec!["pkg:cargo/y@1.0.0".to_string()]);

        // The extractors rejected both mentions: dead, with the reason.
        let rejected = Discovery {
            recognized: vec![
                Recognized {
                    uuid: U2.into(),
                    mode: WiringMode::Hosted,
                    file: "Cargo.lock".into(),
                },
                Recognized {
                    uuid: U1.into(),
                    mode: WiringMode::Vendored,
                    file: "yarn.lock".into(),
                },
            ],
            diagnostics: vec![Diag {
                code: "patched_ref_invalid",
                file: "yarn.lock".into(),
                detail: format!(
                    "yarn.lock: vendored entry `x` is orphaned: nothing maps x onto {rel}"
                ),
            }],
            ..Discovery::default()
        };
        let dead = plan(&common(root), sources(rejected), &[]).await;
        assert!(
            dead.view.patches.is_empty(),
            "{:?}",
            dead.view.patches.keys()
        );
        assert!(dead.redirected.is_empty() && dead.hosted.is_empty());
        let mut gated = dead.gated.clone();
        gated.sort_by(|a, b| a.purl.cmp(&b.purl));
        assert_eq!(
            gated,
            vec![
                failed("pkg:cargo/y@1.0.0", REDIRECT_UNWIRED),
                failed("pkg:npm/x@1.0.0", VENDOR_UNWIRED),
            ]
        );
        assert!(
            dead.notes.iter().any(|n| n.code == NOTE_CLAIM_UNWIRED
                && n.detail.contains("yarn.lock")
                && n.detail.contains("orphaned")
                && n.detail.contains(U1)),
            "{:?}",
            dead.notes
        );
        assert!(
            dead.notes.iter().any(|n| n.detail.contains("Cargo.lock")
                && n.detail.contains("redirect ledger")
                && n.detail.contains(U2)),
            "{:?}",
            dead.notes
        );
    }

    /// Every hosted-basis view purl carries its wiring (uuid + the refs of
    /// THAT uuid) for the consumed-copy verification; other bases do not.
    #[tokio::test]
    async fn hosted_basis_purls_carry_their_wiring() {
        let tmp = tempfile::tempdir().unwrap();
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/x@1.0.0".into(), record(U1));
        let sources = Sources {
            manifest: PatchManifest::new(),
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: discovery(vec![hosted_ref("pkg:npm/x@1.0.0", U1, true)]),
        };
        let plan = plan(&common(tmp.path()), sources, &[]).await;
        let wiring = &plan.hosted["pkg:npm/x@1.0.0"];
        assert_eq!(wiring.uuid, U1);
        assert_eq!(wiring.refs.len(), 1);
        assert_eq!(wiring.refs[0].uuid, U1);
        assert_eq!(plan.hosted.len(), plan.redirected.len());
    }

    /// Ledger-only records with no wiring anywhere are gated, except the
    /// manifest-owned one, which falls back to agent-mode verification; an
    /// in-run confirmed purl is live by construction.
    #[tokio::test]
    async fn dead_redirect_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/owned@1.0.0".into(), record(U1));
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/owned@1.0.0".into(), record(U1));
        redirect
            .records
            .insert("pkg:npm/stale@1.0.0".into(), record(U2));
        redirect
            .records
            .insert("pkg:pypi/confirmed@1.0?artifact_id=x".into(), record(U2));
        let sources = Sources {
            manifest,
            vendor: VendorState::new(),
            redirect: Some(redirect),
            discovery: Discovery::default(),
        };
        let plan = plan(
            &common(tmp.path()),
            sources,
            &["pkg:pypi/confirmed@1.0".to_string()],
        )
        .await;
        assert!(plan.view.patches.contains_key("pkg:npm/owned@1.0.0"));
        assert!(
            !plan.redirected.contains(&"pkg:npm/owned@1.0.0".to_string()),
            "a dead redirect claim loses the (redirected) basis"
        );
        assert_eq!(
            plan.redirected,
            vec!["pkg:pypi/confirmed@1.0?artifact_id=x".to_string()]
        );
        assert_eq!(
            plan.gated,
            vec![failed("pkg:npm/stale@1.0.0", REDIRECT_UNWIRED)]
        );
    }

    /// REGRESSION: the bundler < 2.6 hosted rewrite leaves the pair MIXED —
    /// the Gemfile's `source "<patch registry>" do` block pins the patch, the
    /// CHECKSUMS-less lock still resolves the gem from rubygems.org until
    /// the next unfrozen `bundle install` converges it. The lock inventory
    /// reads `Gemfile.lock`'s registry url and used to call the redirect
    /// record dead (while the identical `gems.rb` / `gems.locked` pair was
    /// live, the inventory not reading `gems.locked`). Reverting the
    /// Gemfile too kills it under both spellings.
    #[tokio::test]
    async fn gemfile_source_block_keeps_a_mixed_gem_pair_live() {
        let purl = "pkg:gem/vexprobe@1.2.3";
        for (gemfile, lock) in [("Gemfile", "Gemfile.lock"), ("gems.rb", "gems.locked")] {
            for gemfile_wired in [true, false] {
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path();
                let source = if gemfile_wired {
                    format!(
                        "source \"https://patch.socket.dev/patch-registry/gem/tok/{U1}/\" do\n  \
                         gem \"vexprobe\", \"1.2.3\"\nend\n"
                    )
                } else {
                    "gem \"vexprobe\", \"1.2.3\"\n".to_string()
                };
                std::fs::write(
                    root.join(gemfile),
                    format!("source \"https://rubygems.org\"\n{source}"),
                )
                .unwrap();
                std::fs::write(
                    root.join(lock),
                    "GEM\n  remote: https://rubygems.org/\n  specs:\n    vexprobe (1.2.3)\n\n\
                     PLATFORMS\n  ruby\n\nDEPENDENCIES\n  vexprobe (= 1.2.3)\n",
                )
                .unwrap();
                let mut redirect = RedirectState::new();
                redirect.records.insert(purl.into(), record(U1));
                for file in [gemfile, lock] {
                    redirect
                        .edits
                        .push(socket_patch_core::patch::redirect::FileEdit {
                            path: file.into(),
                            kind: "redirect_gem".into(),
                            action: "rewritten".into(),
                            key: Some(purl.into()),
                            original: None,
                            new: None,
                        });
                }
                let sources = Sources {
                    manifest: PatchManifest::new(),
                    vendor: VendorState::new(),
                    redirect: Some(redirect),
                    // The lock does not mention the uuid, and the Gemfile is
                    // not a discovery input: the ledger fallback decides.
                    discovery: Discovery::default(),
                };
                let plan = plan(&common(root), sources, &[]).await;
                if gemfile_wired {
                    assert_eq!(plan.redirected, vec![purl.to_string()], "{gemfile}");
                    assert!(plan.gated.is_empty(), "{gemfile}: {:?}", plan.gated);
                } else {
                    assert!(plan.redirected.is_empty(), "{gemfile}");
                    assert_eq!(
                        plan.gated,
                        vec![failed(purl, REDIRECT_UNWIRED)],
                        "{gemfile}"
                    );
                }
            }
        }
    }
}
