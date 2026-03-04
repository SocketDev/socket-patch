use clap::Args;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::manifest::operations::read_manifest;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ListArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Path to patch manifest file
    #[arg(short = 'm', long = "manifest-path", default_value = DEFAULT_PATCH_MANIFEST_PATH)]
    pub manifest_path: String,

    /// Output as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub async fn run(args: ListArgs) -> i32 {
    let manifest_path = if Path::new(&args.manifest_path).is_absolute() {
        PathBuf::from(&args.manifest_path)
    } else {
        args.cwd.join(&args.manifest_path)
    };

    // Check if manifest exists
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.json {
            println!(
                "{}",
                serde_json::json!({
                    "error": "Manifest not found",
                    "path": manifest_path.display().to_string()
                })
            );
        } else {
            eprintln!("Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    match read_manifest(&manifest_path).await {
        Ok(Some(manifest)) => {
            let patch_entries: Vec<_> = manifest.patches.iter().collect();

            if patch_entries.is_empty() {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "patches": [] })).unwrap());
                } else {
                    println!("No patches found in manifest.");
                }
                return 0;
            }

            if args.json {
                let json_output = serde_json::json!({
                    "patches": patch_entries.iter().map(|(purl, patch)| {
                        serde_json::json!({
                            "purl": purl,
                            "uuid": patch.uuid,
                            "exportedAt": patch.exported_at,
                            "tier": patch.tier,
                            "license": patch.license,
                            "description": patch.description,
                            "files": patch.files.keys().collect::<Vec<_>>(),
                            "vulnerabilities": patch.vulnerabilities.iter().map(|(id, vuln)| {
                                serde_json::json!({
                                    "id": id,
                                    "cves": vuln.cves,
                                    "summary": vuln.summary,
                                    "severity": vuln.severity,
                                    "description": vuln.description,
                                })
                            }).collect::<Vec<_>>(),
                        })
                    }).collect::<Vec<_>>()
                });
                println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
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
            if args.json {
                println!("{}", serde_json::json!({ "error": "Invalid manifest" }));
            } else {
                eprintln!("Error: Invalid manifest at {}", manifest_path.display());
            }
            1
        }
        Err(e) => {
            if args.json {
                println!("{}", serde_json::json!({ "error": e.to_string() }));
            } else {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}
