//! `Cargo.lock`: the registry view.

use std::path::Path;

use crate::patch::path_safety;
use crate::utils::fs::read_regular_to_string;

use super::{dedup_prefer_integrity, is_hex_of_len, LockIntegrity, LockfileEntry};

/// Inventory `Cargo.lock` `[[package]]` blocks. Only crates.io-sourced
/// entries are fetchable (their `checksum` is the sha256 of the `.crate`
/// file); workspace members (no `source`) are skipped, and git/custom-
/// registry sources stay listed for discovery without a verifier.
pub(super) async fn inventory_cargo_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("Cargo.lock"))
        .await
        .ok()?;
    /// One in-flight `[[package]]` block: name, version, source, checksum.
    type CargoBlock = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut out = Vec::new();
    let mut cur: Option<CargoBlock> = None;
    let flush = |cur: &mut Option<CargoBlock>, out: &mut Vec<LockfileEntry>| {
        if let Some((Some(name), Some(version), source, checksum)) = cur.take() {
            let Some(source) = source else {
                return; // workspace member
            };
            if !path_safety::is_safe_single_segment(&name)
                || !path_safety::is_safe_single_segment(&version)
            {
                return;
            }
            let crates_io = source.contains("github.com/rust-lang/crates.io-index")
                || source.contains("index.crates.io");
            let integrity = match checksum {
                Some(c) if crates_io && is_hex_of_len(&c, 64) => LockIntegrity::Sha256Hex(c),
                _ => LockIntegrity::None,
            };
            let purl = format!("pkg:cargo/{name}@{version}");
            out.push(LockfileEntry {
                ecosystem: "cargo",
                name,
                version,
                purl,
                resolved: None,
                integrity,
            });
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut cur, &mut out);
            cur = Some((None, None, None, None));
            continue;
        }
        if line.starts_with('[') {
            flush(&mut cur, &mut out);
            continue;
        }
        let Some(slot) = cur.as_mut() else { continue };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "name" => slot.0 = Some(value),
            "version" => slot.1 = Some(value),
            "source" => slot.2 = Some(value),
            "checksum" => slot.3 = Some(value),
            _ => {}
        }
    }
    flush(&mut cur, &mut out);
    Some(dedup_prefer_integrity(out))
}
