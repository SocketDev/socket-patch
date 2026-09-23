use clap::Args;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::{RedirectState, REDIRECT_STATE_REL};
use socket_patch_core::telemetry::track_patch_listed;
use socket_patch_core::vendor::state::{VendorEntry, VENDOR_STATE_REL};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile,
};

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

/// Where a listed record lives. Declaration order is the tie-break order
/// when one purl appears in several stores: coexistence is real state (e.g.
/// an agent-applied patch alongside live hosted wiring), so every copy is
/// shown, labeled apart.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    /// A `.socket/manifest.json` entry (agent mode).
    Manifest,
    /// A hosted redirect-ledger record: `scan --mode hosted` records its
    /// patches ONLY in `.socket/vendor/redirect-state.json` and never
    /// writes the manifest — without these, a purely hosted-wired project
    /// listed as `manifest_not_found` while its patches were demonstrably
    /// live.
    Hosted,
    /// A vendor-ledger record: vendored mode is manifest-free, so every
    /// `scan`/`get --mode vendored` patch lives ONLY in
    /// `.socket/vendor/state.json`, as a `detached` entry's embedded record
    /// (the hosted rule again — a vendored-only project lists and exits 0).
    Vendored,
}

/// The `(mode, ledger)` label pair for a ledger-sourced record — the shared
/// constant labels, never a ledger's own opaque `mode` string (see
/// `HOSTED_MODE_LABEL`'s docs) — or `None` for a manifest entry. Shared by
/// the JSON `details` and the human `Mode:` line.
fn ledger_label(source: Source) -> Option<(&'static str, &'static str)> {
    match source {
        Source::Manifest => None,
        Source::Hosted => Some((crate::commands::HOSTED_MODE_LABEL, REDIRECT_STATE_REL)),
        Source::Vendored => Some((crate::commands::VENDORED_MODE_LABEL, VENDOR_STATE_REL)),
    }
}

/// One listable patch record with its provenance.
struct ListEntry<'a> {
    purl: &'a str,
    record: &'a PatchRecord,
    source: Source,
}

/// Every listable record from all three stores, in a stable order: by
/// PURL, then manifest < hosted < vendored when one purl appears in more
/// than one. The record maps (`HashMap` manifest and vendor ledger /
/// `BTreeMap` redirect ledger) never impose an order shared consumers could
/// diff, so the sort here is the contract. Only vendor entries that carry
/// an embedded record fold in — a legacy manifest-tracked entry has no
/// record of its own (the manifest's IS the record) and would otherwise
/// double-list its purl.
fn combined_entries<'a>(
    manifest: Option<&'a PatchManifest>,
    redirect: Option<&'a RedirectState>,
    vendor: Option<&'a std::collections::HashMap<String, VendorEntry>>,
) -> Vec<ListEntry<'a>> {
    let mut entries: Vec<ListEntry<'a>> = Vec::new();
    if let Some(manifest) = manifest {
        entries.extend(manifest.patches.iter().map(|(purl, record)| ListEntry {
            purl,
            record,
            source: Source::Manifest,
        }));
    }
    if let Some(redirect) = redirect {
        entries.extend(redirect.records.iter().map(|(purl, record)| ListEntry {
            purl,
            record,
            source: Source::Hosted,
        }));
    }
    if let Some(vendor) = vendor {
        entries.extend(vendor.iter().filter_map(|(purl, entry)| {
            let record = entry.record.as_ref().filter(|_| entry.detached)?;
            Some(ListEntry {
                purl,
                record,
                source: Source::Vendored,
            })
        }));
    }
    entries.sort_by(|a, b| a.purl.cmp(b.purl).then(a.source.cmp(&b.source)));
    entries
}

/// Build the `list --json` envelope: one `Discovered` event per entry, with
/// the rich metadata (vulnerabilities, tier, license, description,
/// exportedAt) under `details` per the per-command extension convention.
/// Ledger records additionally carry `details.mode` (the constants
/// [`crate::commands::HOSTED_MODE_LABEL`] /
/// [`crate::commands::VENDORED_MODE_LABEL`]) and `details.ledger` naming
/// the ledger they came from (additive keys, absent on manifest entries),
/// so consumers can tell the stores apart.
///
/// Events are emitted in the entries' given order — [`combined_entries`]
/// owns the by-PURL event sort; this builder sorts each event's
/// vulnerabilities (by advisory ID) and files (by path). `HashMap`
/// iteration is otherwise nondeterministic, so without these sorts the
/// vuln/file ordering would change run-to-run — breaking consumers that
/// diff this output in CI logs. Mirrors the stable-ordering guarantee
/// `get` already provides for its vulnerability lists.
///
/// Shared by `run` and the unit tests so the tests exercise the exact code
/// path `list --json` uses, rather than a hand-copied duplicate.
fn build_list_envelope(entries: &[ListEntry<'_>]) -> Envelope {
    let mut env = Envelope::new(Command::List);

    for entry in entries {
        let patch = entry.record;
        let mut file_paths: Vec<_> = patch.files.keys().cloned().collect();
        file_paths.sort();
        let files = file_paths
            .into_iter()
            .map(|path| PatchEventFile {
                path,
                verified: false,
                applied_via: None,
            })
            .collect();

        let mut vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
        vuln_entries.sort_by(|a, b| a.0.cmp(b.0));
        let vulnerabilities: Vec<_> = vuln_entries
            .iter()
            .map(|(id, vuln)| {
                serde_json::json!({
                    "id": id,
                    "cves": vuln.cves,
                    "summary": vuln.summary,
                    "severity": vuln.severity,
                    "description": vuln.description,
                })
            })
            .collect();

        let mut details = serde_json::json!({
            "exportedAt": patch.exported_at,
            "tier": patch.tier,
            "license": patch.license,
            "description": patch.description,
            "vulnerabilities": vulnerabilities,
        });
        if let Some((mode, ledger)) = ledger_label(entry.source) {
            details["mode"] = serde_json::json!(mode);
            details["ledger"] = serde_json::json!(ledger);
        }

        env.record(
            PatchEvent::new(PatchAction::Discovered, entry.purl.to_string())
                .with_uuid(patch.uuid.clone())
                .with_files(files)
                .with_details(details),
        );
    }

    env
}

/// Emit the top-level envelope for `list` in error states. Used for the
/// "manifest not found" and "manifest unreadable" paths so they share
/// the same JSON shape as a successful list.
fn emit_error(args: &ListArgs, code: &str, message: String) {
    if args.common.json {
        let mut env = Envelope::new(Command::List);
        env.mark_error(EnvelopeError::new(code, message));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
    }
}

pub async fn run(args: ListArgs) -> i32 {
    apply_env_toggles(&args.common);
    let manifest_path = args.common.resolved_manifest_path();

    // `read_manifest` is the single source of truth for the three error
    // states: `Ok(None)` (file absent), `Err(InvalidData)` (present but
    // unparseable), and any other `Err` (genuine I/O failure). We deliberately
    // do NOT stat the path first: a `metadata` pre-check is both redundant and
    // wrong — it reports *any* stat failure (e.g. an unreadable parent dir) as
    // `manifest_not_found`, masking real I/O errors that owe a
    // `manifest_unreadable`, and it opens a TOCTOU window where a file removed
    // between the stat and the read lands in the wrong error arm.
    let manifest = match read_manifest(&manifest_path).await {
        Ok(manifest) => manifest,
        Err(e) => {
            // A manifest that exists but is unparseable (bad JSON or a
            // schema violation) surfaces as `ErrorKind::InvalidData` — the
            // contract's `manifest_invalid`. Everything else is a genuine
            // I/O failure (`manifest_unreadable`). Conflating the two would
            // tell a consumer to retry on a corrupt file, or to give up on a
            // transient I/O error. See CLI_CONTRACT.md error-code table.
            // Hosted-ledger records never mask either: a present-but-broken
            // manifest is an error state, not a hosted-only project.
            let code = if e.kind() == std::io::ErrorKind::InvalidData {
                "manifest_invalid"
            } else {
                "manifest_unreadable"
            };
            emit_error(&args, code, e.to_string());
            return 1;
        }
    };

    // Hosted-mode patches live ONLY in the redirect ledger and vendored-mode
    // patches ONLY in the vendor ledger, so `list` consults both alongside
    // the manifest — leniently (a malformed ledger degrades to "nothing to
    // consult", surfaced on stderr unless --silent; the write paths
    // hard-error on it instead), and always from the SAME project as the
    // manifest (`project_root` steps out of the manifest's `.socket/`):
    // with `--manifest-path` pointing at another project, reading the LOCAL
    // cwd's ledgers would interleave two projects' patch state (and a local
    // ledger could suppress the flagged project's manifest_not_found).
    let project_root = args.common.project_root();
    let redirect_state =
        crate::commands::load_redirect_state_lenient(&project_root, args.common.silent).await;
    let vendor_state =
        crate::commands::load_vendor_state_lenient(&project_root, args.common.silent).await;

    // `combined_entries` folds only ledger RECORDS in (an edits-only
    // redirect ledger — post-takeover residue / a degraded record-fetch-
    // failed run — and a record-less legacy vendor entry assert no
    // patches), so entry emptiness is the whole exit predicate.
    let entries = combined_entries(
        manifest.as_ref(),
        redirect_state.as_ref(),
        vendor_state.as_ref().map(|s| &s.entries),
    );
    if manifest.is_none() && entries.is_empty() {
        // No manifest AND no ledger records: nothing is listable anywhere —
        // the classic missing-manifest error. `read_manifest` returns
        // `Ok(None)` only when the file does not exist (its documented
        // contract), so this is `manifest_not_found`, NOT `manifest_invalid`
        // (which means the file is present but corrupt). See CLI_CONTRACT.md
        // error-code table.
        emit_error(
            &args,
            "manifest_not_found",
            format!("Manifest not found at {}", manifest_path.display()),
        );
        return 1;
    }

    // Records found (either store) ⇒ a successful list, exit 0 — including
    // the purely hosted-wired project that used to hard-fail here.
    //
    // Telemetry: `patch_listed`'s `patches_count` predates the hosted
    // folding and its consumers read it as "manifest patches", so it keeps
    // counting the manifest ONLY (0 on a hosted-only project) — folding the
    // listed entries in would silently redefine the metric and double-count
    // purls present in both stores. Hosted visibility, if wanted, belongs
    // in a new dedicated field.
    let manifest_patch_count = manifest.as_ref().map_or(0, |m| m.patches.len());
    let (api_token, org_slug) = args.common.telemetry_credentials();
    track_patch_listed(
        manifest_patch_count,
        api_token.as_deref(),
        org_slug.as_deref(),
    )
    .await;

    if args.common.json {
        println!("{}", build_list_envelope(&entries).to_pretty_json());
    } else if args.common.silent {
        // `--silent` is "errors only" (CLI_CONTRACT.md): suppress the
        // entire human-readable listing, mirroring `get`/`repair`.
        // The exit code still distinguishes the manifest states.
    } else if entries.is_empty() {
        println!("No patches found in manifest.");
    } else {
        println!("Found {} patch(es):\n", entries.len());
        for entry in &entries {
            let patch = entry.record;
            println!("Package: {}", entry.purl);
            println!("  UUID: {}", patch.uuid);
            if let Some((mode, ledger)) = ledger_label(entry.source) {
                // Same labeling rule as the JSON details: the record comes
                // from a ledger, not the manifest — hosted installs resolve
                // the package to the hosted patch server, vendored ones to
                // the committed `.socket/vendor/` artifact; no manifest
                // entry exists or is needed.
                println!("  Mode: {mode} (recorded in {ledger})");
            }
            println!("  Tier: {}", patch.tier);
            println!("  License: {}", patch.license);
            println!("  Exported: {}", patch.exported_at);

            if !patch.description.is_empty() {
                println!("  Description: {}", patch.description);
            }

            // Sort vulnerabilities by advisory ID for stable output.
            let mut vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
            vuln_entries.sort_by(|a, b| a.0.cmp(b.0));
            if !vuln_entries.is_empty() {
                println!("  Vulnerabilities ({}):", vuln_entries.len());
                for (id, vuln) in &vuln_entries {
                    let cve_list = if vuln.cves.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", vuln.cves.join(", "))
                    };
                    println!("    - {id}{cve_list}");
                    println!("      Severity: {}", vuln.severity);
                    println!("      Summary: {}", vuln.summary);
                }
            }

            // Sort patched files by path for stable output.
            let mut file_list: Vec<_> = patch.files.keys().collect();
            file_list.sort();
            if !file_list.is_empty() {
                println!("  Files patched ({}):", file_list.len());
                for file_path in &file_list {
                    println!("    - {file_path}");
                }
            }

            println!();
        }
    }

    0
}

#[cfg(test)]
mod tests {
    //! Inline tests for `list` JSON output. Pin the new envelope shape
    //! so downstream consumers (PR bots, dashboards) can rely on it.
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

    /// Envelope for a manifest-only listing (no redirect ledger) — the shape
    /// most tests below need; the hosted tests call `combined_entries`
    /// directly with a `RedirectState`.
    fn manifest_envelope(manifest: &PatchManifest) -> Envelope {
        build_list_envelope(&combined_entries(Some(manifest), None, None))
    }

    fn sample_manifest() -> PatchManifest {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: "a".repeat(64),
            },
        );

        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-xyz-1234".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2024-12345".to_string()],
                summary: "Prototype Pollution".to_string(),
                severity: "high".to_string(),
                description: "Some description".to_string(),
            },
        );

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            PatchRecord {
                uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: "Fixes prototype pollution".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        PatchManifest {
            patches,
            setup: None,
        }
    }

    /// A manifest with several patches, each carrying multiple
    /// vulnerabilities and files, all inserted in deliberately
    /// non-alphabetical order. Used to pin the stable sort order the
    /// envelope must impose regardless of HashMap iteration.
    fn multi_entry_manifest() -> PatchManifest {
        fn record(uuid: &str, vuln_ids: &[&str], file_paths: &[&str]) -> PatchRecord {
            let mut files = HashMap::new();
            for fp in file_paths {
                files.insert(
                    fp.to_string(),
                    PatchFileInfo {
                        before_hash: "b".repeat(64),
                        after_hash: "a".repeat(64),
                    },
                );
            }
            let mut vulns = HashMap::new();
            for id in vuln_ids {
                vulns.insert(
                    id.to_string(),
                    VulnerabilityInfo {
                        cves: vec![],
                        summary: "s".to_string(),
                        severity: "high".to_string(),
                        description: "d".to_string(),
                    },
                );
            }
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: "desc".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            }
        }

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/zeta@1.0.0".to_string(),
            record(
                "uuid-z",
                &["GHSA-zzzz-2222-3333", "GHSA-aaaa-2222-3333"],
                &["z/b.js", "z/a.js"],
            ),
        );
        patches.insert(
            "pkg:npm/alpha@1.0.0".to_string(),
            record("uuid-a", &["GHSA-mmmm-2222-3333"], &["a/zz.js", "a/aa.js"]),
        );
        patches.insert(
            "pkg:npm/mid@1.0.0".to_string(),
            record("uuid-m", &["GHSA-cccc-2222-3333"], &["m/x.js"]),
        );
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn list_emits_discovered_event_per_patch() {
        let env = manifest_envelope(&sample_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["command"], "list");
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        let events = v["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], "discovered");
        assert_eq!(events[0]["purl"], "pkg:npm/minimist@1.2.2");
        assert_eq!(events[0]["uuid"], "11111111-1111-4111-8111-111111111111");
    }

    #[test]
    fn list_event_carries_vulnerability_details() {
        let env = manifest_envelope(&sample_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let event = &v["events"][0];
        assert_eq!(event["details"]["tier"], "free");
        assert_eq!(event["details"]["license"], "MIT");
        let vulns = event["details"]["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "GHSA-xyz-1234");
        assert_eq!(vulns[0]["severity"], "high");
        assert_eq!(vulns[0]["cves"][0], "CVE-2024-12345");
    }

    #[test]
    fn empty_manifest_emits_empty_events() {
        let env = manifest_envelope(&PatchManifest::new());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
        assert_eq!(v["summary"]["discovered"], 0);
    }

    // -- Regression: stable ordering -------------------------------------
    // `HashMap` iteration order is randomized per run, so without explicit
    // sorting the events / vulnerabilities / files arrays would shuffle
    // between invocations. These pin the sorted contract so consumers can
    // diff `list --json` output in CI logs.

    #[test]
    fn events_are_sorted_by_purl() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let purls: Vec<&str> = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["purl"].as_str().unwrap())
            .collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/alpha@1.0.0",
                "pkg:npm/mid@1.0.0",
                "pkg:npm/zeta@1.0.0",
            ]
        );
    }

    #[test]
    fn vulnerabilities_are_sorted_by_id() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        // The zeta entry carries two advisories inserted out of order.
        let zeta = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["purl"] == "pkg:npm/zeta@1.0.0")
            .unwrap();
        let ids: Vec<&str> = zeta["details"]["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vuln| vuln["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["GHSA-aaaa-2222-3333", "GHSA-zzzz-2222-3333"]);
    }

    #[test]
    fn files_are_sorted_by_path() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let zeta = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["purl"] == "pkg:npm/zeta@1.0.0")
            .unwrap();
        let paths: Vec<&str> = zeta["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["z/a.js", "z/b.js"]);
    }

    /// Hosted redirect-ledger records fold into the envelope labeled apart
    /// from manifest entries: `details.mode` / `details.ledger` ride the
    /// hosted events ONLY (additive keys), and the global purl sort holds
    /// with the manifest entry first when one purl appears in both stores.
    #[test]
    fn hosted_ledger_records_are_labeled_and_interleaved() {
        let manifest = sample_manifest();
        let mut redirect = RedirectState::new();
        let mut hosted_record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        hosted_record.uuid = "22222222-2222-4222-8222-222222222222".to_string();
        // Same purl as the manifest entry (coexistence) + a distinct one.
        redirect
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), hosted_record.clone());
        redirect
            .records
            .insert("pkg:npm/aaa-hosted@1.0.0".to_string(), hosted_record);

        let env = build_list_envelope(&combined_entries(
            Some(&manifest),
            Some(&redirect),
            None,
        ));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["summary"]["discovered"], 3);
        let events = v["events"].as_array().unwrap();
        let listed: Vec<(&str, bool)> = events
            .iter()
            .map(|e| {
                (
                    e["purl"].as_str().unwrap(),
                    e["details"]["mode"] == "hosted",
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("pkg:npm/aaa-hosted@1.0.0", true),
                ("pkg:npm/minimist@1.2.2", false),
                ("pkg:npm/minimist@1.2.2", true),
            ],
            "purl-sorted, manifest before hosted on a tie: {v}"
        );
        assert!(
            events[1]["details"].get("mode").is_none()
                && events[1]["details"].get("ledger").is_none(),
            "manifest entries must NOT carry the hosted labels: {v}"
        );
        assert_eq!(
            events[0]["details"]["ledger"],
            ".socket/vendor/redirect-state.json"
        );
    }

    /// A hosted-only listing (no manifest at all) — the shape a purely
    /// hosted-wired project produces.
    #[test]
    fn hosted_only_entries_build_a_success_envelope() {
        let manifest = sample_manifest();
        let mut redirect = RedirectState::new();
        redirect.records.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            manifest.patches["pkg:npm/minimist@1.2.2"].clone(),
        );
        let env = build_list_envelope(&combined_entries(None, Some(&redirect), None));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        assert_eq!(v["events"][0]["details"]["mode"], "hosted");
    }

    /// A vendor-ledger entry: `detached` with the embedded record when
    /// `record` is given (the manifest-free vendored posture), a legacy
    /// manifest-tracked entry (no record of its own) otherwise. Built from
    /// the on-disk JSON shape so the fixture follows the ledger schema.
    fn vendor_entry(purl: &str, record: Option<PatchRecord>) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "basePurl": purl,
            "uuid": record
                .as_ref()
                .map_or("legacy-uuid", |r| r.uuid.as_str()),
            "artifact": { "path": ".socket/vendor/npm/x/pkg.tgz" },
            "wiring": [],
            "detached": record.is_some(),
            "record": record,
        }))
        .expect("vendor entry fixture deserializes")
    }

    /// Vendor-ledger records fold in labeled `vendored` with their ledger,
    /// sort after the hosted record on a purl tie, and a legacy
    /// manifest-tracked entry (no embedded record) never double-lists its
    /// manifest purl. A vendored-only listing is a success envelope — the
    /// hosted-only rule applied to the manifest-free vendored mode.
    #[test]
    fn vendored_ledger_records_are_labeled_and_sorted_last() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let mut redirect = RedirectState::new();
        redirect
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), record.clone());
        let mut detached = record.clone();
        detached.uuid = "44444444-4444-4444-8444-444444444444".to_string();
        let mut vendor = HashMap::new();
        vendor.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            vendor_entry("pkg:npm/minimist@1.2.2", Some(detached)),
        );
        vendor.insert(
            "pkg:npm/zzz-vendored@1.0.0".to_string(),
            vendor_entry("pkg:npm/zzz-vendored@1.0.0", Some(record)),
        );
        // Legacy manifest-tracked vendoring: the manifest holds the record.
        vendor.insert(
            "pkg:npm/minimist@1.2.2#legacy".to_string(),
            vendor_entry("pkg:npm/minimist@1.2.2", None),
        );

        let env = build_list_envelope(&combined_entries(
            Some(&manifest),
            Some(&redirect),
            Some(&vendor),
        ));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let listed: Vec<(&str, &str)> = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["purl"].as_str().unwrap(),
                    e["details"]["mode"].as_str().unwrap_or("manifest"),
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("pkg:npm/minimist@1.2.2", "manifest"),
                ("pkg:npm/minimist@1.2.2", "hosted"),
                ("pkg:npm/minimist@1.2.2", "vendored"),
                ("pkg:npm/zzz-vendored@1.0.0", "vendored"),
            ],
            "purl-sorted, manifest < hosted < vendored on a tie, record-less              entries skipped: {v}"
        );
        let events = v["events"].as_array().unwrap();
        assert_eq!(
            events[2]["details"]["ledger"], ".socket/vendor/state.json",
            "{v}"
        );
        assert_eq!(
            events[2]["uuid"], "44444444-4444-4444-8444-444444444444",
            "the ledger's embedded record is the one listed: {v}"
        );

        let only = build_list_envelope(&combined_entries(None, None, Some(&vendor)));
        let v: serde_json::Value = serde_json::from_str(&only.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success", "{v}");
        assert_eq!(v["summary"]["discovered"], 2, "{v}");
    }

    #[test]
    fn ordering_is_deterministic_across_builds() {
        // Two independent builds of the same manifest must be byte-identical.
        let manifest = multi_entry_manifest();
        let a = manifest_envelope(&manifest).to_pretty_json();
        let b = manifest_envelope(&manifest).to_pretty_json();
        assert_eq!(a, b);
    }
}
