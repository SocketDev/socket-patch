use clap::Args;
use socket_patch_core::manifest::operations::read_manifest;
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

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        emit_error(
            &args,
            "manifest_not_found",
            format!("Manifest not found at {}", manifest_path.display()),
        );
        return 1;
    }

    match read_manifest(&manifest_path).await {
        Ok(Some(manifest)) => {
            let patch_entries: Vec<_> = manifest.patches.iter().collect();
            let patches_count = patch_entries.len();
            track_patch_listed(
                patches_count,
                args.common.api_token.as_deref(),
                args.common.org.as_deref(),
            )
            .await;

            if args.common.json {
                let mut env = Envelope::new(Command::List);
                for (purl, patch) in &patch_entries {
                    // `list` emits one `Discovered` event per manifest
                    // entry. The rich metadata (vulnerabilities, tier,
                    // license, description, exportedAt) lives under
                    // `details` per the per-command extension convention.
                    let files = patch
                        .files
                        .keys()
                        .map(|p| PatchEventFile {
                            path: p.clone(),
                            verified: false,
                            applied_via: None,
                        })
                        .collect();
                    let details = serde_json::json!({
                        "exportedAt": patch.exported_at,
                        "tier": patch.tier,
                        "license": patch.license,
                        "description": patch.description,
                        "vulnerabilities": patch.vulnerabilities.iter().map(|(id, vuln)| {
                            serde_json::json!({
                                "id": id,
                                "cves": vuln.cves,
                                "summary": vuln.summary,
                                "severity": vuln.severity,
                                "description": vuln.description,
                            })
                        }).collect::<Vec<_>>(),
                    });
                    env.record(
                        PatchEvent::new(PatchAction::Discovered, (*purl).clone())
                            .with_uuid(patch.uuid.clone())
                            .with_files(files)
                            .with_details(details),
                    );
                }
                println!("{}", env.to_pretty_json());
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

                    let vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
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

                    let file_list: Vec<_> = patch.files.keys().collect();
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
            emit_error(&args, "manifest_invalid", "Invalid manifest".to_string());
            1
        }
        Err(e) => {
            emit_error(&args, "manifest_unreadable", e.to_string());
            1
        }
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for `list` JSON output. Pin the new envelope shape
    //! so downstream consumers (PR bots, dashboards) can rely on it.
    use super::*;
    use socket_patch_core::manifest::schema::{
        PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
    };
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

        PatchManifest { patches }
    }

    /// Build the envelope the same way `run` would for the given manifest.
    /// Keeps the test free of binary-spawn overhead while still pinning
    /// the exact event shape `list --json` produces.
    fn build_envelope(manifest: &PatchManifest) -> Envelope {
        let mut env = Envelope::new(Command::List);
        for (purl, patch) in &manifest.patches {
            let files = patch
                .files
                .keys()
                .map(|p| PatchEventFile {
                    path: p.clone(),
                    verified: false,
                    applied_via: None,
                })
                .collect();
            let details = serde_json::json!({
                "exportedAt": patch.exported_at,
                "tier": patch.tier,
                "license": patch.license,
                "description": patch.description,
                "vulnerabilities": patch.vulnerabilities.iter().map(|(id, vuln)| {
                    serde_json::json!({
                        "id": id,
                        "cves": vuln.cves,
                        "summary": vuln.summary,
                        "severity": vuln.severity,
                        "description": vuln.description,
                    })
                }).collect::<Vec<_>>(),
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

    #[test]
    fn list_emits_discovered_event_per_patch() {
        let env = build_envelope(&sample_manifest());
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
        let env = build_envelope(&sample_manifest());
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
        let env = build_envelope(&PatchManifest::new());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
        assert_eq!(v["summary"]["discovered"], 0);
    }
}
