use clap::Args;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::upstream::HostedPin;
use socket_patch_core::patch::redirect::RedirectState;
use socket_patch_core::telemetry::track_patch_listed;
use socket_patch_core::vendor::state::{VendorState, VENDOR_STATE_REL};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile, RunWarning,
};

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

// Where a listed record lives (see `socket_patch_core::ledgers`): the
// manifest (agent mode); the hosted redirect ledger, where `scan --mode
// hosted` recorded its patches; or the vendor ledger, where vendored mode
// keeps every `scan`/`get --mode vendored` patch as a `detached` entry's
// embedded record (a standalone `vendor` entry's fallback copy lists too
// once no manifest entry covers it — the checkout `vex` attests from it).
use socket_patch_core::ledgers::Store as Source;

/// The display order of one purl's copies: manifest, hosted, vendored.
fn display_rank(source: Source) -> u8 {
    match source {
        Source::Manifest => 0,
        Source::Hosted => 1,
        Source::Vendored => 2,
    }
}

/// The `(mode, ledger)` label pair for a vendor-ledger record — the shared
/// constant label, never a ledger's own opaque `mode` string (see
/// `HOSTED_MODE_LABEL`'s docs) — or `None` for a manifest entry or a hosted
/// pin (which has no ledger; see [`ListEntry::lockfiles`]). Shared by the
/// JSON `details` and the human `Mode:` line.
fn ledger_label(source: Source) -> Option<(&'static str, &'static str)> {
    match source {
        Source::Manifest | Source::Hosted => None,
        Source::Vendored => Some((crate::commands::VENDORED_MODE_LABEL, VENDOR_STATE_REL)),
    }
}

/// One listable patch record with its provenance.
struct ListEntry<'a> {
    purl: &'a str,
    record: &'a PatchRecord,
    source: Source,
    /// The lockfiles wiring a hosted pin (empty for the other sources).
    lockfiles: &'a [String],
}

/// A hosted pin as `list` shows it: the lockfiles wiring it, and its
/// record — from a pre-v5 redirect ledger when one still describes this
/// exact pin (read for migration only), else just the uuid (the details
/// live on the API; `vex` fetches them).
pub(crate) struct HostedListing {
    pub purl: String,
    pub record: PatchRecord,
    pub lockfiles: Vec<String>,
}

impl HostedListing {
    /// One listing per hosted pin in `pins`, detailed from `legacy` where
    /// it records the same purl and uuid.
    pub(crate) fn from_pins(pins: &[HostedPin], legacy: Option<&RedirectState>) -> Vec<Self> {
        let canon = |p: &str| {
            socket_patch_core::utils::purl::normalize_purl(
                socket_patch_core::utils::purl::strip_purl_qualifiers(p),
            )
            .into_owned()
        };
        pins.iter()
            .map(|pin| {
                let record = legacy
                    .and_then(|l| {
                        l.records
                            .iter()
                            .find(|(k, r)| canon(k) == canon(&pin.purl) && r.uuid == pin.uuid)
                            .map(|(_, r)| r.clone())
                    })
                    .unwrap_or_else(|| PatchRecord {
                        uuid: pin.uuid.clone(),
                        exported_at: String::new(),
                        files: Default::default(),
                        vulnerabilities: Default::default(),
                        description: String::new(),
                        license: String::new(),
                        tier: String::new(),
                    });
                HostedListing {
                    purl: pin.purl.clone(),
                    record,
                    lockfiles: pin.files.clone(),
                }
            })
            .collect()
    }
}

/// Every listable record, in a stable order: by PURL, then
/// [`display_rank`] when one purl appears in more than one store. The
/// manifest and the vendor ledger go through the shared owner rule
/// ([`socket_patch_core::ledgers::Ledgers::listed`]: coexisting copies are
/// real state, shown labeled apart; a claimed fallback copy and a legacy
/// entry with no embedded record never list); every hosted pin lists as
/// its own copy (the lockfiles are the only hosted record). The record
/// maps never impose an order shared consumers could diff, so the sort
/// here is the contract.
fn combined_entries<'a>(
    manifest: Option<&'a PatchManifest>,
    hosted: &'a [HostedListing],
    vendor: Option<&'a VendorState>,
) -> Vec<ListEntry<'a>> {
    let ledgers = socket_patch_core::ledgers::Ledgers {
        manifest,
        vendor,
        redirect: None,
    };
    let mut entries: Vec<ListEntry<'a>> = ledgers
        .listed()
        .into_iter()
        .map(|l| ListEntry {
            purl: l.key,
            record: l.record,
            source: l.store,
            lockfiles: &[],
        })
        .collect();
    entries.extend(hosted.iter().map(|h| ListEntry {
        purl: &h.purl,
        record: &h.record,
        source: Source::Hosted,
        lockfiles: &h.lockfiles,
    }));
    entries.sort_by(|a, b| {
        a.purl
            .cmp(b.purl)
            .then(display_rank(a.source).cmp(&display_rank(b.source)))
    });
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
/// vulnerabilities (by advisory ID) and files (by path) so the output is
/// stable across runs (`HashMap` iteration is not).
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
        if entry.source == Source::Hosted {
            details["mode"] = serde_json::json!(crate::commands::HOSTED_MODE_LABEL);
            details["lockfiles"] = serde_json::json!(entry.lockfiles);
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
/// the same JSON shape as a successful list. `warnings` gathered before
/// the error (a corrupt redirect ledger) ride the error envelope too, so a
/// JSON consumer sees them on every exit path.
fn emit_error(args: &ListArgs, code: &str, message: String, warnings: Vec<RunWarning>) {
    if args.common.json {
        let mut env = Envelope::new(Command::List);
        env.mark_error(EnvelopeError::new(code, message));
        env.warnings = warnings;
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
    }
}

/// Manifest/ledger text is free-form (API-sourced descriptions): drop
/// control characters that would rewrite the terminal (ESC, a stray
/// `\r`), keeping newlines and tabs, and normalize `\r\n`.
fn sanitize(s: &str) -> String {
    s.replace("\r\n", "\n")
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

/// `"{indent}{label}: {value}"`, or `None` when the value is blank (no
/// dangling `License: ` line). Continuation lines of a multi-line value
/// are indented two past the label so they stay inside the entry.
fn field(indent: &str, label: &str, value: &str) -> Option<String> {
    let value = sanitize(value);
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let continuation = format!("\n{indent}  ");
    let body = value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join(&continuation);
    Some(format!("{indent}{label}: {body}"))
}

/// One entry of the human listing (no trailing newline).
fn format_entry(entry: &ListEntry<'_>, color: bool) -> String {
    let patch = entry.record;
    let mut lines = vec![format!("Package: {}", sanitize(entry.purl))];
    lines.extend(field("  ", "UUID", &patch.uuid));
    if let Some((mode, ledger)) = ledger_label(entry.source) {
        // Same labeling rule as the JSON details.
        lines.push(format!("  Mode: {mode} (recorded in {ledger})"));
    }
    if entry.source == Source::Hosted {
        lines.push(format!(
            "  Mode: {} (wired in {})",
            crate::commands::HOSTED_MODE_LABEL,
            sanitize(&entry.lockfiles.join(", "))
        ));
    }
    lines.extend(field("  ", "Tier", &patch.tier));
    lines.extend(field("  ", "License", &patch.license));
    lines.extend(field("  ", "Exported", &patch.exported_at));
    lines.extend(field("  ", "Description", &patch.description));

    let mut vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
    vuln_entries.sort_by(|a, b| a.0.cmp(b.0));
    if !vuln_entries.is_empty() {
        lines.push(format!("  Vulnerabilities ({}):", vuln_entries.len()));
        for (id, vuln) in &vuln_entries {
            let cve_list = if vuln.cves.is_empty() {
                String::new()
            } else {
                format!(" ({})", sanitize(&vuln.cves.join(", ")))
            };
            lines.push(format!("    - {}{cve_list}", sanitize(id)));
            // Upper-cased like scan's table, and colored by tier on a
            // color terminal.
            let severity = sanitize(vuln.severity.trim()).to_uppercase();
            if !severity.is_empty() {
                lines.push(format!(
                    "      Severity: {}",
                    crate::ui::severity(&severity, color)
                ));
            }
            lines.extend(field("      ", "Summary", &vuln.summary));
        }
    }

    let mut file_list: Vec<_> = patch.files.keys().collect();
    file_list.sort();
    if !file_list.is_empty() {
        lines.push(format!("  Files patched ({}):", file_list.len()));
        for file_path in &file_list {
            lines.push(format!("    - {}", sanitize(file_path)));
        }
    }
    lines.join("\n")
}

/// The human line for a project with nothing to list (an empty manifest, or
/// no manifest and no ledger records at all).
const NO_PATCHES: &str = "No patches in this project. Run `socket-patch scan`.";

/// The whole human listing for stdout: a count header, then the entries
/// separated by one blank line (none after the last).
fn format_listing(entries: &[ListEntry<'_>], color: bool) -> String {
    if entries.is_empty() {
        return NO_PATCHES.to_string();
    }
    let mut out = format!(
        "Found {}:\n\n",
        crate::ui::plural(entries.len(), "patch", "patches")
    );
    let blocks: Vec<String> = entries.iter().map(|e| format_entry(e, color)).collect();
    out.push_str(&blocks.join("\n\n"));
    out
}

pub async fn run(args: ListArgs) -> i32 {
    apply_env_toggles(&args.common);
    let manifest_path = args.common.resolved_manifest_path();

    // `read_manifest` is the single source of truth for the three error
    // states: `Ok(None)` (file absent), `Err(InvalidData)` (present but
    // unparseable), and any other `Err` (genuine I/O failure). No stat
    // pre-check: it would report any stat failure as `manifest_not_found`
    // and open a TOCTOU window.
    // One load of the three stores, all from the SAME project as the
    // manifest (see below); each keeps list's own posture.
    let ctx = crate::commands::context::ProjectContext::new(&args.common);
    let loaded = ctx.loaded().await;
    let manifest = match &loaded.manifest {
        Ok(manifest) => manifest.as_ref(),
        Err(e) => {
            // `InvalidData` (bad JSON or schema) is the contract's
            // `manifest_invalid`; everything else is `manifest_unreadable`
            // (see CLI_CONTRACT.md error-code table). Ledger records never
            // mask either: a present-but-broken manifest is an error state.
            let code = if e.kind() == std::io::ErrorKind::InvalidData {
                "manifest_invalid"
            } else {
                "manifest_unreadable"
            };
            emit_error(
                &args,
                code,
                crate::ui::manifest_error_message(&manifest_path, e),
                Vec::new(),
            );
            return 1;
        }
    };

    // Hosted-mode patches live ONLY in the lockfiles (v5 keeps no hosted
    // ledger) and vendored-mode patches ONLY in the vendor ledger, so
    // `list` consults both alongside the manifest — always from the SAME
    // project as the manifest (`project_root` steps out of the manifest's
    // `.socket/`): with `--manifest-path` pointing at another project,
    // reading the LOCAL cwd's state would interleave two projects' patches.
    //
    // A pre-v5 redirect ledger is read (never written) only to detail the
    // hosted pins it still describes; a malformed one degrades to "nothing
    // to consult", surfaced on stderr unless --silent, or in the envelope's
    // `warnings[]` under --json.
    let mut warnings: Vec<RunWarning> = Vec::new();
    let legacy_redirect = match &loaded.redirect {
        Ok(state) => state.as_ref(),
        Err(corrupt) => {
            if args.common.json {
                warnings.push(RunWarning {
                    code: "redirect_ledger_corrupt".to_string(),
                    detail: corrupt.to_string(),
                });
            } else if !args.common.silent {
                eprintln!("Warning: {corrupt}");
            }
            None
        }
    };
    let inventory = crate::commands::hosted_inventory(&args.common, &ctx.root).await;
    let hosted = HostedListing::from_pins(&inventory.pins, legacy_redirect);
    // Contested hosted wiring cannot be listed as patches, but it is hosted
    // state: surface it (stderr / `warnings[]`), never hide it.
    let contested = inventory.contested_refusal();
    if let Some(detail) = &contested {
        if args.common.json {
            warnings.push(RunWarning {
                code: "hosted_wiring_contested".to_string(),
                detail: detail.clone(),
            });
        } else if !args.common.silent {
            eprintln!("Warning: {}", crate::ui::sentence_case(detail));
        }
    }
    let vendor_state = crate::commands::vendor_state_lenient(&loaded.vendor, args.common.silent);

    // `combined_entries` folds only real records in (a record-less legacy
    // vendor entry asserts no patch), so entry emptiness is the whole exit
    // predicate.
    let entries = combined_entries(manifest, &hosted, vendor_state);
    if manifest.is_none() && entries.is_empty() {
        if let Some(detail) = contested {
            emit_error(&args, "hosted_wiring_contested", detail, warnings);
            return 1;
        }
    }

    // A successful list, exit 0, with or without records. No manifest
    // and no ledger record is just an empty project (normal for hosted
    // mode, which writes no manifest); only an unreadable or invalid
    // manifest or contested hosted wiring fails.
    //
    // Telemetry: `patch_listed`'s `patches_count` means "manifest patches"
    // to its consumers, so it counts the manifest ONLY (0 on a ledger-only
    // project) rather than the listed entries.
    let manifest_patch_count = manifest.map_or(0, |m| m.patches.len());
    let (api_token, org_slug) = args.common.telemetry_credentials();
    track_patch_listed(
        manifest_patch_count,
        api_token.as_deref(),
        org_slug.as_deref(),
    )
    .await;

    if args.common.json {
        let mut env = build_list_envelope(&entries);
        env.warnings = warnings;
        println!("{}", env.to_pretty_json());
    } else if args.common.silent {
        // `--silent` is "errors only" (CLI_CONTRACT.md).
    } else {
        println!("{}", format_listing(&entries, crate::ui::stdout_color()));
    }

    0
}

#[cfg(test)]
mod tests {
    //! Inline tests for `list` output. Pin the envelope shape so downstream
    //! consumers (PR bots, dashboards) can rely on it.
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use socket_patch_core::vendor::state::VendorEntry;
    use std::collections::HashMap;

    /// Envelope for a manifest-only listing (no hosted pins, no vendor
    /// ledger) — the shape most tests below need.
    fn manifest_envelope(manifest: &PatchManifest) -> Envelope {
        build_list_envelope(&combined_entries(Some(manifest), &[], None))
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

    // -- Stable ordering -------------------------------------------------
    // Pin the sorted events / vulnerabilities / files contract so consumers
    // can diff `list --json` output.

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

    fn hosted(purl: &str, record: PatchRecord) -> HostedListing {
        HostedListing {
            purl: purl.to_string(),
            record,
            lockfiles: vec!["package-lock.json".to_string()],
        }
    }

    /// Hosted pins fold into the envelope labeled apart from manifest
    /// entries: `details.mode` / `details.lockfiles` ride the hosted events
    /// ONLY (additive keys), and the global purl sort holds with the
    /// manifest entry first when one purl appears in both stores.
    #[test]
    fn hosted_pins_are_labeled_and_interleaved() {
        let manifest = sample_manifest();
        let mut hosted_record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        hosted_record.uuid = "22222222-2222-4222-8222-222222222222".to_string();
        // Same purl as the manifest entry (coexistence) + a distinct one.
        let pins = vec![
            hosted("pkg:npm/minimist@1.2.2", hosted_record.clone()),
            hosted("pkg:npm/aaa-hosted@1.0.0", hosted_record),
        ];

        let env = build_list_envelope(&combined_entries(Some(&manifest), &pins, None));
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
            events[0]["details"]["lockfiles"],
            serde_json::json!(["package-lock.json"])
        );
        assert!(
            events[0]["details"].get("ledger").is_none(),
            "a hosted pin names no ledger: {v}"
        );
    }

    /// A pre-v5 redirect ledger details only the pins it records with the
    /// same uuid; any other pin lists with its uuid alone.
    #[test]
    fn legacy_ledger_details_only_matching_pins() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let mut legacy = RedirectState::new();
        legacy
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), record.clone());
        let pin = |purl: &str, uuid: &str| HostedPin {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            files: vec!["yarn.lock".to_string()],
        };
        let listings = HostedListing::from_pins(
            &[
                pin("pkg:npm/minimist@1.2.2", &record.uuid),
                pin(
                    "pkg:npm/other@1.0.0",
                    "33333333-3333-4333-8333-333333333333",
                ),
            ],
            Some(&legacy),
        );
        assert_eq!(listings[0].record, record);
        assert_eq!(
            listings[1].record.uuid,
            "33333333-3333-4333-8333-333333333333"
        );
        assert!(listings[1].record.vulnerabilities.is_empty());
        assert_eq!(listings[1].lockfiles, vec!["yarn.lock".to_string()]);
    }

    /// A hosted-only listing (no manifest at all) — the shape a purely
    /// hosted-wired project produces.
    #[test]
    fn hosted_only_entries_build_a_success_envelope() {
        let manifest = sample_manifest();
        let pins = vec![hosted(
            "pkg:npm/minimist@1.2.2",
            manifest.patches["pkg:npm/minimist@1.2.2"].clone(),
        )];
        let env = build_list_envelope(&combined_entries(None, &pins, None));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        assert_eq!(v["events"][0]["details"]["mode"], "hosted");
    }

    /// A vendor-ledger entry: `detached` with the embedded record when
    /// `record` is given (the manifest-free vendored posture), a legacy
    /// manifest-tracked entry (no record of its own) otherwise. Built from
    /// the on-disk JSON shape so the fixture follows the ledger schema.
    fn as_state(entries: &HashMap<String, VendorEntry>) -> VendorState {
        VendorState {
            entries: entries.clone(),
            ..VendorState::new()
        }
    }

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
        let pins = vec![hosted("pkg:npm/minimist@1.2.2", record.clone())];
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
            &pins,
            Some(&as_state(&vendor)),
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

        let only = build_list_envelope(&combined_entries(None, &[], Some(&as_state(&vendor))));
        let v: serde_json::Value = serde_json::from_str(&only.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success", "{v}");
        assert_eq!(v["summary"]["discovered"], 2, "{v}");
    }

    /// The ledger entry the manifest-driven standalone `vendor` writes: NOT
    /// detached, with the record embedded as a fallback copy.
    fn standalone_vendor_entry(base_purl: &str, record: PatchRecord) -> VendorEntry {
        let mut entry = vendor_entry(base_purl, Some(record));
        entry.detached = false;
        entry
    }

    /// A standalone `vendor` entry's embedded fallback record lists exactly
    /// when `vex` would attest from it — no manifest entry covers the entry
    /// (by ledger key or base purl). With no manifest at all it lists
    /// labeled `vendored`, so a manifest-less checkout never reads "no
    /// patches" while its VEX document attests the patch; while the manifest
    /// covers it, the manifest's record IS its record (no double listing).
    #[test]
    fn standalone_vendor_fallback_record_lists_only_when_the_manifest_does_not_cover_it() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let mut other = record.clone();
        other.uuid = "55555555-5555-4555-8555-555555555555".to_string();
        let mut vendor = HashMap::new();
        // Covered by the manifest's exact key.
        vendor.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            standalone_vendor_entry("pkg:npm/minimist@1.2.2", record.clone()),
        );
        // Covered through its base purl (a qualified ledger key).
        vendor.insert(
            "pkg:npm/minimist@1.2.2?variant=x".to_string(),
            standalone_vendor_entry("pkg:npm/minimist@1.2.2", record.clone()),
        );
        // Dropped from the manifest while the ledger still holds it.
        vendor.insert(
            "pkg:npm/left-pad@1.3.0".to_string(),
            standalone_vendor_entry("pkg:npm/left-pad@1.3.0", other),
        );

        let listed = |entries: &[ListEntry<'_>]| -> Vec<(String, String, String)> {
            let env = build_list_envelope(entries);
            let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
            v["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["purl"].as_str().unwrap().to_string(),
                        e["details"]["mode"]
                            .as_str()
                            .unwrap_or("manifest")
                            .to_string(),
                        e["uuid"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        };

        assert_eq!(
            listed(&combined_entries(
                Some(&manifest),
                &[],
                Some(&as_state(&vendor))
            )),
            vec![
                (
                    "pkg:npm/left-pad@1.3.0".to_string(),
                    "vendored".to_string(),
                    "55555555-5555-4555-8555-555555555555".to_string(),
                ),
                (
                    "pkg:npm/minimist@1.2.2".to_string(),
                    "manifest".to_string(),
                    "11111111-1111-4111-8111-111111111111".to_string(),
                ),
            ],
            "covered fallback copies stay behind the manifest record; the uncovered one lists"
        );

        // No manifest at all: every fallback copy stands on its own.
        let only = listed(&combined_entries(None, &[], Some(&as_state(&vendor))));
        assert_eq!(only.len(), 3, "{only:?}");
        assert!(
            only.iter().all(|(_, mode, _)| mode == "vendored"),
            "{only:?}"
        );
    }

    #[test]
    fn ordering_is_deterministic_across_builds() {
        // Two independent builds of the same manifest must be byte-identical.
        let manifest = multi_entry_manifest();
        let a = manifest_envelope(&manifest).to_pretty_json();
        let b = manifest_envelope(&manifest).to_pretty_json();
        assert_eq!(a, b);
    }

    fn record_with(description: &str, license: &str, severity: &str, summary: &str) -> PatchRecord {
        let mut rec = sample_manifest().patches["pkg:npm/minimist@1.2.2"].clone();
        rec.description = description.to_string();
        rec.license = license.to_string();
        let vuln = rec.vulnerabilities.get_mut("GHSA-xyz-1234").unwrap();
        vuln.severity = severity.to_string();
        vuln.summary = summary.to_string();
        rec
    }

    fn entry<'a>(purl: &'a str, record: &'a PatchRecord) -> ListEntry<'a> {
        ListEntry {
            purl,
            record,
            source: Source::Manifest,
            lockfiles: &[],
        }
    }

    #[test]
    fn format_entry_exact_layout() {
        let rec = record_with("Some fix", "MIT", "high", "Prototype Pollution");
        assert_eq!(
            format_entry(&entry("pkg:npm/minimist@1.2.2", &rec), false),
            "Package: pkg:npm/minimist@1.2.2\n\
             \x20 UUID: 11111111-1111-4111-8111-111111111111\n\
             \x20 Tier: free\n\
             \x20 License: MIT\n\
             \x20 Exported: 2024-01-01T00:00:00Z\n\
             \x20 Description: Some fix\n\
             \x20 Vulnerabilities (1):\n\
             \x20   - GHSA-xyz-1234 (CVE-2024-12345)\n\
             \x20     Severity: HIGH\n\
             \x20     Summary: Prototype Pollution\n\
             \x20 Files patched (1):\n\
             \x20   - package/index.js"
        );
    }

    #[test]
    fn format_entry_indents_multiline_and_skips_blank_fields() {
        let rec = record_with("Multi\r\nline  \ndescription", "", "", "");
        let out = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(
            out.contains("  Description: Multi\n    line\n    description\n"),
            "{out}"
        );
        for gone in ["License:", "Severity:", "Summary:"] {
            assert!(!out.contains(gone), "blank {gone} must be skipped: {out}");
        }
        assert!(
            !out.lines().any(|l| l.ends_with(' ')),
            "no trailing spaces: {out:?}"
        );
    }

    #[test]
    fn format_entry_strips_terminal_control_sequences() {
        let rec = record_with("evil\x1b[2J\x07 text\rmore", "MIT", "low", "s\x1b]0;t\x07");
        let out = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(
            !out.contains('\x1b') && !out.contains('\x07') && !out.contains('\r'),
            "{out:?}"
        );
        assert!(out.contains("  Description: evil[2J textmore"), "{out}");
    }

    #[test]
    fn format_entry_colors_severity_only_when_asked() {
        let rec = record_with("d", "MIT", "critical", "s");
        let plain = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(!plain.contains('\x1b'));
        let colored = format_entry(&entry("pkg:npm/x@1", &rec), true);
        assert!(
            colored.contains("Severity: \x1b[91mCRITICAL\x1b[0m"),
            "{colored:?}"
        );
    }

    #[test]
    fn format_entry_multibyte_passes_through() {
        let rec = record_with("修复 — é", "MIT", "medium", "漏洞");
        let out = format_entry(&entry("pkg:npm/日本@1", &rec), false);
        assert!(out.starts_with("Package: pkg:npm/日本@1\n"), "{out}");
        assert!(out.contains("  Description: 修复 — é\n"), "{out}");
        assert!(out.contains("      Summary: 漏洞\n"), "{out}");
    }

    #[test]
    fn format_listing_counts_and_separates_entries() {
        assert_eq!(format_listing(&[], false), NO_PATCHES);
        let manifest = sample_manifest();
        let one = combined_entries(Some(&manifest), &[], None);
        let out = format_listing(&one, false);
        assert!(out.starts_with("Found 1 patch:\n\nPackage: "), "{out}");
        assert!(!out.ends_with('\n'), "no trailing blank line: {out:?}");

        let multi = multi_entry_manifest();
        let many = combined_entries(Some(&multi), &[], None);
        let out = format_listing(&many, false);
        assert!(
            out.starts_with(&format!("Found {} patches:\n\n", many.len())),
            "{out}"
        );
        // Exactly one blank line between entries, none doubled.
        assert_eq!(out.matches("\n\nPackage: ").count(), many.len());
        assert!(!out.contains("\n\n\n"), "{out:?}");
    }
}
