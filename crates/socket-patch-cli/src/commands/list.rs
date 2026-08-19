use clap::Args;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::{RedirectState, REDIRECT_STATE_REL};
use socket_patch_core::telemetry::track_patch_listed;
use socket_patch_core::utils::socket_cli_config;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile,
};

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

/// One listable patch record with its provenance: a `.socket/manifest.json`
/// entry (agent/vendored modes) or a hosted redirect-ledger record
/// (`scan --mode hosted` records its patches ONLY in
/// `.socket/vendor/redirect-state.json` and never writes the manifest —
/// without the ledger records, a purely hosted-wired project listed as
/// `manifest_not_found` while its patches were demonstrably live).
struct ListEntry<'a> {
    purl: &'a str,
    record: &'a PatchRecord,
    /// `true` when the record comes from the hosted redirect ledger.
    hosted: bool,
}

/// Every listable record from both stores, in a stable order: by PURL, the
/// manifest entry before the hosted-ledger record when one purl appears in
/// BOTH (coexistence is real state — e.g. an agent-applied patch alongside
/// live hosted wiring — so both are shown, labeled apart). The record maps
/// (`HashMap` manifest / `BTreeMap` ledger) never impose an order shared
/// consumers could diff, so the sort here is the contract.
fn combined_entries<'a>(
    manifest: Option<&'a PatchManifest>,
    redirect: Option<&'a RedirectState>,
) -> Vec<ListEntry<'a>> {
    let mut entries: Vec<ListEntry<'a>> = Vec::new();
    if let Some(manifest) = manifest {
        entries.extend(manifest.patches.iter().map(|(purl, record)| ListEntry {
            purl,
            record,
            hosted: false,
        }));
    }
    if let Some(redirect) = redirect {
        entries.extend(redirect.records.iter().map(|(purl, record)| ListEntry {
            purl,
            record,
            hosted: true,
        }));
    }
    entries.sort_by(|a, b| a.purl.cmp(b.purl).then(a.hosted.cmp(&b.hosted)));
    entries
}

/// Build the `list --json` envelope: one `Discovered` event per entry, with
/// the rich metadata (vulnerabilities, tier, license, description,
/// exportedAt) under `details` per the per-command extension convention.
/// Hosted-ledger records additionally carry `details.mode: "hosted"` and
/// `details.ledger` naming the redirect ledger (additive keys, absent on
/// manifest entries), so consumers can tell the stores apart.
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
        if entry.hosted {
            // The label is the constant "hosted" (the mode's documented
            // name), not the ledger's own opaque `mode` string — pre-rename
            // ledgers carry `"redirect"`, and a consumer dispatching on
            // this key must not have to know that history.
            details["mode"] = serde_json::json!("hosted");
            details["ledger"] = serde_json::json!(REDIRECT_STATE_REL);
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

/// Resolve the credentials the `patch_listed` telemetry event is attributed
/// to: `--api-token` / `--org` (clap already folds in `SOCKET_API_TOKEN` /
/// `SOCKET_ORG_SLUG` and their promoted `SOCKET_CLI_*` aliases), then the
/// socket-cli `config.json` written by `socket login`.
///
/// The config layer is part of the contract for both settings ("Persisted
/// configuration" in CLI_CONTRACT.md), and
/// `telemetry::resolve_telemetry_endpoint` only uses the org-scoped
/// `/v0/orgs/<slug>/telemetry` endpoint when BOTH a token and a slug reach
/// it. Passing the raw flag values here skipped the config layer, so a
/// caller authenticated by `socket login` alone had every `list` reported
/// anonymously to the public patch proxy — while `apply`/`repair`/`remove`/
/// `rollback` (which take theirs from `get_api_client_with_overrides`)
/// reported to that caller's org. With an on-prem `apiBaseUrl` that also
/// broke the "telemetry can never target a different host than the client"
/// property, sending the event off to `patches-api.socket.dev` instead.
///
/// The API client is deliberately NOT built to get these: `list` is a purely
/// local read, and constructing one would add the org-slug auto-resolve
/// round-trip and the "No SOCKET_API_TOKEN set" advisory to a command that
/// needs neither. Only the two credential lookups are mirrored — including
/// the `SOCKET_NO_API_TOKEN` veto over *ambient* tokens (`main` scrubs the
/// env var for the flag layer; core applies the same veto to the config
/// layer) and the `--debug` echo naming the resolution source.
pub(crate) fn telemetry_credentials(common: &GlobalArgs) -> (Option<String>, Option<String>) {
    let api_token = common
        .api_token
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            if socket_cli_config::no_api_token_veto() {
                return None;
            }
            socket_cli_config::load()
                .and_then(|c| c.api_token.clone())
                .inspect(|_| {
                    if common.debug {
                        eprintln!(
                            "[socket-patch debug] api token: from socket-cli config \
                             (`socket login`)"
                        );
                    }
                })
        });
    let org_slug = common.org.clone().filter(|s| !s.is_empty()).or_else(|| {
        socket_cli_config::load()
            .and_then(|c| c.default_org.clone())
            .inspect(|slug| {
                if common.debug {
                    eprintln!("[socket-patch debug] org slug: `{slug}` from socket-cli config");
                }
            })
    });
    (api_token, org_slug)
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

    // Hosted-mode patches live ONLY in the redirect ledger, so `list`
    // consults it alongside the manifest. This is a read-only consult: a
    // malformed ledger degrades to "nothing to consult" with the corruption
    // surfaced on stderr (the hosted write path hard-errors on it instead —
    // see `load_redirect_state`'s contract), never a hard failure here.
    let redirect_state =
        match socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd).await {
            Ok(state) => state,
            Err(corrupt) => {
                eprintln!("Warning: {corrupt}");
                None
            }
        };
    // An edits-only ledger (post-takeover residue / a degraded
    // record-fetch-failed run) asserts no patches — only `records` count.
    let has_hosted_records = redirect_state
        .as_ref()
        .is_some_and(|state| !state.records.is_empty());

    if manifest.is_none() && !has_hosted_records {
        // No manifest AND no hosted records: nothing is listable anywhere —
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
    let entries = combined_entries(manifest.as_ref(), redirect_state.as_ref());
    let (api_token, org_slug) = telemetry_credentials(&args.common);
    track_patch_listed(entries.len(), api_token.as_deref(), org_slug.as_deref()).await;

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
            if entry.hosted {
                // Same labeling rule as the JSON details: the record comes
                // from the hosted redirect ledger — installs resolve this
                // package to the hosted patch server; no manifest entry
                // exists or is needed.
                println!("  Mode: hosted (recorded in {REDIRECT_STATE_REL})");
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
        let manifest = sample_manifest();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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
        let manifest = sample_manifest();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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
        let manifest = PatchManifest::new();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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
        let manifest = multi_entry_manifest();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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
        let manifest = multi_entry_manifest();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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
        let manifest = multi_entry_manifest();
        let env = build_list_envelope(&combined_entries(Some(&manifest), None));
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

    // -- Telemetry credential resolution ---------------------------------
    // The socket-cli `config.json` layer is exercised end-to-end (it is read
    // once per process, so it needs a subprocess) by
    // `tests/cli_config_fallback.rs::list_telemetry_follows_socket_cli_login`.
    // These pin the two layers above it, which need no fixture.

    /// Explicit values — the flag, or the env var clap folds into the same
    /// field — are used verbatim, never overridden by a lower layer.
    #[test]
    fn telemetry_credentials_prefer_explicit_values() {
        let common = GlobalArgs {
            api_token: Some("sktsec_flag_api".to_string()),
            org: Some("flag-org".to_string()),
            ..GlobalArgs::default()
        };
        assert_eq!(
            telemetry_credentials(&common),
            (
                Some("sktsec_flag_api".to_string()),
                Some("flag-org".to_string())
            )
        );
    }

    /// Empty means "unset" repo-wide, so an empty value must never be
    /// forwarded: `Some("")` would build a malformed `/v0/orgs//telemetry`
    /// URL and an empty `Bearer ` header.
    #[test]
    fn telemetry_credentials_treat_empty_as_unset() {
        let common = GlobalArgs {
            api_token: Some(String::new()),
            org: Some(String::new()),
            ..GlobalArgs::default()
        };
        let (api_token, org_slug) = telemetry_credentials(&common);
        assert_ne!(api_token.as_deref(), Some(""));
        assert_ne!(org_slug.as_deref(), Some(""));
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

        let env = build_list_envelope(&combined_entries(Some(&manifest), Some(&redirect)));
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
        let env = build_list_envelope(&combined_entries(None, Some(&redirect)));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        assert_eq!(v["events"][0]["details"]["mode"], "hosted");
    }

    #[test]
    fn ordering_is_deterministic_across_builds() {
        // Two independent builds of the same manifest must be byte-identical.
        let manifest = multi_entry_manifest();
        let a = build_list_envelope(&combined_entries(Some(&manifest), None)).to_pretty_json();
        let b = build_list_envelope(&combined_entries(Some(&manifest), None)).to_pretty_json();
        assert_eq!(a, b);
    }
}
