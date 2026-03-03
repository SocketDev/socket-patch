use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo};

/// Result of manifest recovery operation.
#[derive(Debug, Clone)]
pub struct RecoveryResult {
    pub manifest: PatchManifest,
    pub repair_needed: bool,
    pub invalid_patches: Vec<String>,
    pub recovered_patches: Vec<String>,
    pub discarded_patches: Vec<String>,
}

/// Patch data returned from an external source (e.g., database).
#[derive(Debug, Clone)]
pub struct PatchData {
    pub uuid: String,
    pub purl: String,
    pub published_at: String,
    pub files: HashMap<String, PatchDataFileInfo>,
    pub vulnerabilities: HashMap<String, PatchDataVulnerability>,
    pub description: String,
    pub license: String,
    pub tier: String,
}

/// File info from external patch data (hashes are optional).
#[derive(Debug, Clone)]
pub struct PatchDataFileInfo {
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
}

/// Vulnerability info from external patch data.
#[derive(Debug, Clone)]
pub struct PatchDataVulnerability {
    pub cves: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub description: String,
}

/// Events emitted during recovery.
#[derive(Debug, Clone)]
pub enum RecoveryEvent {
    CorruptedManifest,
    InvalidPatch {
        purl: String,
        uuid: Option<String>,
    },
    RecoveredPatch {
        purl: String,
        uuid: String,
    },
    DiscardedPatchNotFound {
        purl: String,
        uuid: String,
    },
    DiscardedPatchPurlMismatch {
        purl: String,
        uuid: String,
        db_purl: String,
    },
    DiscardedPatchNoUuid {
        purl: String,
    },
    RecoveryError {
        purl: String,
        uuid: String,
        error: String,
    },
}

/// Type alias for the refetch callback.
/// Takes (uuid, optional purl) and returns a future resolving to Option<PatchData>.
pub type RefetchPatchFn = Box<
    dyn Fn(String, Option<String>) -> Pin<Box<dyn Future<Output = Result<Option<PatchData>, String>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for the recovery event callback.
pub type OnRecoveryEventFn = Box<dyn Fn(RecoveryEvent) + Send + Sync>;

/// Options for manifest recovery.
pub struct RecoveryOptions {
    /// Optional function to refetch patch data from external source (e.g., database).
    /// Should return patch data or None if not found.
    pub refetch_patch: Option<RefetchPatchFn>,

    /// Optional callback for logging recovery events.
    pub on_recovery_event: Option<OnRecoveryEventFn>,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            refetch_patch: None,
            on_recovery_event: None,
        }
    }
}

/// Recover and validate manifest with automatic repair of invalid patches.
///
/// This function attempts to parse and validate a manifest. If the manifest
/// contains invalid patches, it will attempt to recover them using the provided
/// refetch function. Patches that cannot be recovered are discarded.
pub async fn recover_manifest(
    parsed: &serde_json::Value,
    options: RecoveryOptions,
) -> RecoveryResult {
    let RecoveryOptions {
        refetch_patch,
        on_recovery_event,
    } = options;

    let emit = |event: RecoveryEvent| {
        if let Some(ref cb) = on_recovery_event {
            cb(event);
        }
    };

    // Try strict parse first (fast path for valid manifests)
    if let Ok(manifest) = serde_json::from_value::<PatchManifest>(parsed.clone()) {
        return RecoveryResult {
            manifest,
            repair_needed: false,
            invalid_patches: vec![],
            recovered_patches: vec![],
            discarded_patches: vec![],
        };
    }

    // Extract patches object with safety checks
    let patches_obj = parsed
        .as_object()
        .and_then(|obj| obj.get("patches"))
        .and_then(|p| p.as_object());

    let patches_obj = match patches_obj {
        Some(obj) => obj,
        None => {
            // Completely corrupted manifest
            emit(RecoveryEvent::CorruptedManifest);
            return RecoveryResult {
                manifest: PatchManifest::new(),
                repair_needed: true,
                invalid_patches: vec![],
                recovered_patches: vec![],
                discarded_patches: vec![],
            };
        }
    };

    // Try to recover individual patches
    let mut recovered_patches_map: HashMap<String, PatchRecord> = HashMap::new();
    let mut invalid_patches: Vec<String> = Vec::new();
    let mut recovered_patches: Vec<String> = Vec::new();
    let mut discarded_patches: Vec<String> = Vec::new();

    for (purl, patch_data) in patches_obj {
        // Try to parse this individual patch
        if let Ok(record) = serde_json::from_value::<PatchRecord>(patch_data.clone()) {
            // Valid patch, keep it as-is
            recovered_patches_map.insert(purl.clone(), record);
        } else {
            // Invalid patch, try to recover from external source
            let uuid = patch_data
                .as_object()
                .and_then(|obj| obj.get("uuid"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            invalid_patches.push(purl.clone());
            emit(RecoveryEvent::InvalidPatch {
                purl: purl.clone(),
                uuid: uuid.clone(),
            });

            if let (Some(ref uuid_str), Some(ref refetch)) = (&uuid, &refetch_patch) {
                // Try to refetch from external source
                match refetch(uuid_str.clone(), Some(purl.clone())).await {
                    Ok(Some(patch_from_source)) => {
                        if patch_from_source.purl == *purl {
                            // Successfully recovered, reconstruct patch record
                            let mut manifest_files: HashMap<String, PatchFileInfo> =
                                HashMap::new();
                            for (file_path, file_info) in &patch_from_source.files {
                                if let (Some(before), Some(after)) =
                                    (&file_info.before_hash, &file_info.after_hash)
                                {
                                    manifest_files.insert(
                                        file_path.clone(),
                                        PatchFileInfo {
                                            before_hash: before.clone(),
                                            after_hash: after.clone(),
                                        },
                                    );
                                }
                            }

                            let mut vulns: HashMap<String, VulnerabilityInfo> = HashMap::new();
                            for (vuln_id, vuln_data) in &patch_from_source.vulnerabilities {
                                vulns.insert(
                                    vuln_id.clone(),
                                    VulnerabilityInfo {
                                        cves: vuln_data.cves.clone(),
                                        summary: vuln_data.summary.clone(),
                                        severity: vuln_data.severity.clone(),
                                        description: vuln_data.description.clone(),
                                    },
                                );
                            }

                            recovered_patches_map.insert(
                                purl.clone(),
                                PatchRecord {
                                    uuid: patch_from_source.uuid.clone(),
                                    exported_at: patch_from_source.published_at.clone(),
                                    files: manifest_files,
                                    vulnerabilities: vulns,
                                    description: patch_from_source.description.clone(),
                                    license: patch_from_source.license.clone(),
                                    tier: patch_from_source.tier.clone(),
                                },
                            );

                            recovered_patches.push(purl.clone());
                            emit(RecoveryEvent::RecoveredPatch {
                                purl: purl.clone(),
                                uuid: uuid_str.clone(),
                            });
                        } else {
                            // PURL mismatch - wrong package!
                            discarded_patches.push(purl.clone());
                            emit(RecoveryEvent::DiscardedPatchPurlMismatch {
                                purl: purl.clone(),
                                uuid: uuid_str.clone(),
                                db_purl: patch_from_source.purl.clone(),
                            });
                        }
                    }
                    Ok(None) => {
                        // Not found in external source (might be unpublished)
                        discarded_patches.push(purl.clone());
                        emit(RecoveryEvent::DiscardedPatchNotFound {
                            purl: purl.clone(),
                            uuid: uuid_str.clone(),
                        });
                    }
                    Err(error_msg) => {
                        // Error during recovery
                        discarded_patches.push(purl.clone());
                        emit(RecoveryEvent::RecoveryError {
                            purl: purl.clone(),
                            uuid: uuid_str.clone(),
                            error: error_msg,
                        });
                    }
                }
            } else {
                // No UUID or no refetch function, can't recover
                discarded_patches.push(purl.clone());
                if uuid.is_none() {
                    emit(RecoveryEvent::DiscardedPatchNoUuid {
                        purl: purl.clone(),
                    });
                } else {
                    emit(RecoveryEvent::DiscardedPatchNotFound {
                        purl: purl.clone(),
                        uuid: uuid.unwrap(),
                    });
                }
            }
        }
    }

    let repair_needed = !invalid_patches.is_empty();

    RecoveryResult {
        manifest: PatchManifest {
            patches: recovered_patches_map,
        },
        repair_needed,
        invalid_patches,
        recovered_patches,
        discarded_patches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_valid_manifest_no_repair() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "test",
                    "license": "MIT",
                    "tier": "free"
                }
            }
        });

        let result = recover_manifest(&parsed, RecoveryOptions::default()).await;
        assert!(!result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 1);
        assert!(result.invalid_patches.is_empty());
        assert!(result.recovered_patches.is_empty());
        assert!(result.discarded_patches.is_empty());
    }

    #[tokio::test]
    async fn test_corrupted_manifest_no_patches_key() {
        let parsed = json!({
            "something": "else"
        });

        let result = recover_manifest(&parsed, RecoveryOptions::default()).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
    }

    #[tokio::test]
    async fn test_corrupted_manifest_patches_not_object() {
        let parsed = json!({
            "patches": "not-an-object"
        });

        let result = recover_manifest(&parsed, RecoveryOptions::default()).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
    }

    #[tokio::test]
    async fn test_invalid_patch_discarded_no_refetch() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111"
                    // missing required fields
                }
            }
        });

        let result = recover_manifest(&parsed, RecoveryOptions::default()).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
        assert_eq!(result.invalid_patches.len(), 1);
        assert_eq!(result.discarded_patches.len(), 1);
    }

    #[tokio::test]
    async fn test_invalid_patch_no_uuid_discarded() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "garbage": true
                }
            }
        });


        let events_clone = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_ref = events_clone.clone();

        let options = RecoveryOptions {
            refetch_patch: None,
            on_recovery_event: Some(Box::new(move |event| {
                events_ref.lock().unwrap().push(format!("{:?}", event));
            })),
        };

        let result = recover_manifest(&parsed, options).await;
        assert!(result.repair_needed);
        assert_eq!(result.discarded_patches.len(), 1);

        let logged = events_clone.lock().unwrap();
        assert!(logged.iter().any(|e| e.contains("DiscardedPatchNoUuid")));
    }

    #[tokio::test]
    async fn test_mix_valid_and_invalid_patches() {
        let parsed = json!({
            "patches": {
                "pkg:npm/good@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "good patch",
                    "license": "MIT",
                    "tier": "free"
                },
                "pkg:npm/bad@1.0.0": {
                    "uuid": "22222222-2222-4222-8222-222222222222"
                    // missing required fields
                }
            }
        });

        let result = recover_manifest(&parsed, RecoveryOptions::default()).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 1);
        assert!(result.manifest.patches.contains_key("pkg:npm/good@1.0.0"));
        assert_eq!(result.invalid_patches.len(), 1);
        assert_eq!(result.discarded_patches.len(), 1);
    }

    #[tokio::test]
    async fn test_recovery_with_refetch_success() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111"
                    // missing required fields
                }
            }
        });

        let options = RecoveryOptions {
            refetch_patch: Some(Box::new(|_uuid, _purl| {
                Box::pin(async {
                    Ok(Some(PatchData {
                        uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                        purl: "pkg:npm/test@1.0.0".to_string(),
                        published_at: "2024-01-01T00:00:00Z".to_string(),
                        files: {
                            let mut m = HashMap::new();
                            m.insert(
                                "package/index.js".to_string(),
                                PatchDataFileInfo {
                                    before_hash: Some("aaa".to_string()),
                                    after_hash: Some("bbb".to_string()),
                                },
                            );
                            m
                        },
                        vulnerabilities: HashMap::new(),
                        description: "recovered".to_string(),
                        license: "MIT".to_string(),
                        tier: "free".to_string(),
                    }))
                })
            })),
            on_recovery_event: None,
        };

        let result = recover_manifest(&parsed, options).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 1);
        assert_eq!(result.recovered_patches.len(), 1);
        assert_eq!(result.discarded_patches.len(), 0);

        let record = result.manifest.patches.get("pkg:npm/test@1.0.0").unwrap();
        assert_eq!(record.description, "recovered");
        assert_eq!(record.files.len(), 1);
    }

    #[tokio::test]
    async fn test_recovery_with_purl_mismatch() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111"
                }
            }
        });

        let options = RecoveryOptions {
            refetch_patch: Some(Box::new(|_uuid, _purl| {
                Box::pin(async {
                    Ok(Some(PatchData {
                        uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                        purl: "pkg:npm/other@2.0.0".to_string(), // wrong purl
                        published_at: "2024-01-01T00:00:00Z".to_string(),
                        files: HashMap::new(),
                        vulnerabilities: HashMap::new(),
                        description: "wrong".to_string(),
                        license: "MIT".to_string(),
                        tier: "free".to_string(),
                    }))
                })
            })),
            on_recovery_event: None,
        };

        let result = recover_manifest(&parsed, options).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
        assert_eq!(result.discarded_patches.len(), 1);
    }

    #[tokio::test]
    async fn test_recovery_with_refetch_not_found() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111"
                }
            }
        });

        let options = RecoveryOptions {
            refetch_patch: Some(Box::new(|_uuid, _purl| {
                Box::pin(async { Ok(None) })
            })),
            on_recovery_event: None,
        };

        let result = recover_manifest(&parsed, options).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
        assert_eq!(result.discarded_patches.len(), 1);
    }

    #[tokio::test]
    async fn test_recovery_with_refetch_error() {
        let parsed = json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111"
                }
            }
        });

        let options = RecoveryOptions {
            refetch_patch: Some(Box::new(|_uuid, _purl| {
                Box::pin(async { Err("network error".to_string()) })
            })),
            on_recovery_event: None,
        };

        let result = recover_manifest(&parsed, options).await;
        assert!(result.repair_needed);
        assert_eq!(result.manifest.patches.len(), 0);
        assert_eq!(result.discarded_patches.len(), 1);
    }
}
