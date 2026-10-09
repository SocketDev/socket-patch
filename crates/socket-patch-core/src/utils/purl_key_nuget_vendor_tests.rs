//! #1202: a NuGet entry vendored under a non-normalized purl version must
//! stay live for every reader that judges vendored wiring through
//! [`PurlKey`]: VEX discovery, `vendor --check` and the `scan --prune` GC.
//! The vendored backend matches the lock's `resolved` through
//! `normalize_nuget_version`; the liveness gates compare purls through
//! `PurlKey`. Both now use the same rule.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::PatchSources;
use crate::vendor::VendorOutcome;

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PRISTINE: &[u8] = b"The MIT License (MIT)\nCopyright (c) 2007 James Newton-King\n";
const PATCHED: &[u8] =
    b"The MIT License (MIT)\n// SOCKET-PATCH-MARKER\nCopyright (c) 2007 James Newton-King\n";

fn nupkg(license: &[u8]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    let files: &[(&str, &[u8])] = &[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
        ("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>"),
        (
            "Newtonsoft.Json.nuspec",
            b"<?xml version=\"1.0\"?><package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>",
        ),
        ("lib/net6.0/Newtonsoft.Json.dll", b"MZ-fake-assembly"),
        ("LICENSE.md", license),
    ];
    for (name, bytes) in files {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// A restored project resolving `Newtonsoft.Json` `13.0.3`, its global-cache
/// copy, and a blob store carrying the patched `LICENSE.md`.
async fn fixture(root: &Path) -> (std::path::PathBuf, std::path::PathBuf, PatchRecord) {
    let installed = root.join("packages/newtonsoft.json/13.0.3");
    tokio::fs::create_dir_all(installed.join("lib/net6.0"))
        .await
        .unwrap();
    tokio::fs::write(
        installed.join("newtonsoft.json.13.0.3.nupkg"),
        nupkg(PRISTINE),
    )
    .await
    .unwrap();
    // The service fixture builds its grant from `<id>.<purl version>.nupkg`,
    // the as-written spelling; NuGet's cache keeps the normalized one above.
    tokio::fs::write(
        installed.join("newtonsoft.json.13.0.3.0.nupkg"),
        nupkg(PRISTINE),
    )
    .await
    .unwrap();
    tokio::fs::write(installed.join("LICENSE.md"), PRISTINE)
        .await
        .unwrap();
    tokio::fs::write(
        installed.join("lib/net6.0/Newtonsoft.Json.dll"),
        b"MZ-fake-assembly",
    )
    .await
    .unwrap();
    let after = compute_git_sha256_from_bytes(PATCHED);
    let blobs = root.join("blobs");
    tokio::fs::create_dir_all(&blobs).await.unwrap();
    tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();
    let lock = serde_json::json!({
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[13.0.3, )",
                    "resolved": "13.0.3",
                    "contentHash": "ORIGINALcachedhash=="
                }
            }
        }
    });
    tokio::fs::write(
        root.join("packages.lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .await
    .unwrap();
    let files = HashMap::from([(
        "LICENSE.md".to_string(),
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(PRISTINE),
            after_hash: after,
        },
    )]);
    let record = PatchRecord {
        uuid: UUID.to_string(),
        exported_at: "2026-06-09T00:00:00Z".to_string(),
        files,
        vulnerabilities: HashMap::new(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    };
    (installed, blobs, record)
}

/// Every vendored-liveness reader agrees that an entry vendored at
/// `@13.0.3.0` (the 4-part `packages.config` spelling) against a lock
/// resolving `13.0.3` is in use. `test_support::vendor_nuget` asserts the
/// prune GC's verdict (`vendor_entry_in_use != Some(false)`); this test also
/// pins the VEX claim and `vendor --check`'s liveness.
#[tokio::test]
async fn nuget_vendored_at_a_four_part_version_stays_live() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (installed, blobs, record) = fixture(root).await;
    let sources = PatchSources::blobs_only(&blobs);
    let outcome = crate::vendor::test_support::vendor_nuget(
        "pkg:nuget/Newtonsoft.Json@13.0.3.0",
        installed.as_path(),
        root,
        &record,
        &sources,
        "2026-06-09T00:00:00Z",
        false,
        false,
        None,
    )
    .await;
    let VendorOutcome::Done {
        result,
        entry: Some(entry),
        ..
    } = outcome
    else {
        panic!("vendor_nuget did not vendor: {outcome:?}");
    };
    assert!(result.success, "{result:?}");
    assert_eq!(entry.base_purl, "pkg:nuget/Newtonsoft.Json@13.0.3.0");

    let refs = crate::vex::discover::discover_patched_refs(root).await;
    assert_eq!(refs.vendor_entry_in_use(root, &entry).await, Some(true));
    assert!(refs.vendor_entry_live(root, &entry).await);
}
