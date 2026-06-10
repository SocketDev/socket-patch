use clap::Args;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::telemetry::track_patch_listed;

use crate::args::GlobalArgs;
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile,
};

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

/// Build the `list --json` envelope: one `Discovered` event per manifest
/// entry, with the rich metadata (vulnerabilities, tier, license,
/// description, exportedAt) under `details` per the per-command extension
/// convention.
///
/// Patches, vulnerabilities, and files are each emitted in a stable sorted
/// order (by PURL / advisory ID / path). `HashMap` iteration is otherwise
/// nondeterministic, so without this the event/vuln/file ordering would
/// change run-to-run — breaking consumers that diff this output in CI logs.
/// Mirrors the stable-ordering guarantee `get` already provides for its
/// vulnerability lists.
///
/// Shared by `run` and the unit tests so the tests exercise the exact code
/// path `list --json` uses, rather than a hand-copied duplicate.
fn build_list_envelope(manifest: &PatchManifest) -> Envelope {
    let mut env = Envelope::new(Command::List);

    let mut patch_entries: Vec<_> = manifest.patches.iter().collect();
    patch_entries.sort_by(|a, b| a.0.cmp(b.0));

    for (purl, patch) in patch_entries {
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

        let details = serde_json::json!({
            "exportedAt": patch.exported_at,
            "tier": patch.tier,
            "license": patch.license,
            "description": patch.description,
            "vulnerabilities": vulnerabilities,
        });

        env.record(
            PatchEvent::new(PatchAction::Discovered, purl.clone())
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
    let manifest_path = args.common.resolved_manifest_path();

    // `read_manifest` is the single source of truth for the three error
    // states: `Ok(None)` (file absent), `Err(InvalidData)` (present but
    // unparseable), and any other `Err` (genuine I/O failure). We deliberately
    // do NOT stat the path first: a `metadata` pre-check is both redundant and
    // wrong — it reports *any* stat failure (e.g. an unreadable parent dir) as
    // `manifest_not_found`, masking real I/O errors that owe a
    // `manifest_unreadable`, and it opens a TOCTOU window where a file removed
    // between the stat and the read lands in the wrong error arm.
    match read_manifest(&manifest_path).await {
        Ok(Some(manifest)) => {
            // Sort by PURL so both the JSON envelope and the human-readable
            // table list packages in a stable order across runs.
            let mut patch_entries: Vec<_> = manifest.patches.iter().collect();
            patch_entries.sort_by(|a, b| a.0.cmp(b.0));
            let patches_count = patch_entries.len();
            track_patch_listed(
                patches_count,
                args.common.api_token.as_deref(),
                args.common.org.as_deref(),
            )
            .await;

            if args.common.json {
                println!("{}", build_list_envelope(&manifest).to_pretty_json());
            } else if patch_entries.is_empty() {
                println!("No patches found in manifest.");
            } else {
                println!("Found {} patch(es):\n", patch_entries.len());
                for (purl, patch) in &patch_entries {
                    println!("Package: {purl}");
                    println!("  UUID: {}", patch.uuid);
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
        Ok(None) => {
            // `read_manifest` returns `Ok(None)` only when the file does not
            // exist (its documented contract), so this is the missing-manifest
            // path — `manifest_not_found`, NOT `manifest_invalid` (which means
            // the file is present but corrupt). See CLI_CONTRACT.md error-code
            // table.
            emit_error(
                &args,
                "manifest_not_found",
                format!("Manifest not found at {}", manifest_path.display()),
            );
            1
        }
        Err(e) => {
            // A manifest that exists but is unparseable (bad JSON or a
            // schema violation) surfaces as `ErrorKind::InvalidData` — the
            // contract's `manifest_invalid`. Everything else is a genuine
            // I/O failure (`manifest_unreadable`). Conflating the two would
            // tell a consumer to retry on a corrupt file, or to give up on a
            // transient I/O error. See CLI_CONTRACT.md error-code table.
            let code = if e.kind() == std::io::ErrorKind::InvalidData {
                "manifest_invalid"
            } else {
                "manifest_unreadable"
            };
            emit_error(&args, code, e.to_string());
            1
        }
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for `list` JSON output. Pin the new envelope shape
    //! so downstream consumers (PR bots, dashboards) can rely on it.
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

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
        let env = build_list_envelope(&sample_manifest());
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
        let env = build_list_envelope(&sample_manifest());
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
        let env = build_list_envelope(&PatchManifest::new());
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
        let env = build_list_envelope(&multi_entry_manifest());
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
        let env = build_list_envelope(&multi_entry_manifest());
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
        let env = build_list_envelope(&multi_entry_manifest());
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

    #[test]
    fn ordering_is_deterministic_across_builds() {
        // Two independent builds of the same manifest must be byte-identical.
        let manifest = multi_entry_manifest();
        let a = build_list_envelope(&manifest).to_pretty_json();
        let b = build_list_envelope(&manifest).to_pretty_json();
        assert_eq!(a, b);
    }
}
