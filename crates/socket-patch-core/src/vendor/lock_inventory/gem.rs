//! `Gemfile.lock`: the registry view and the GEM remote set ledger recovery
//! reads.

use std::collections::HashMap;
use std::path::Path;

use crate::patch::path_safety;
use crate::utils::fs::read_regular_to_string;

use super::{dedup_prefer_integrity, http_url, is_hex_of_len, LockIntegrity, LockfileEntry};

/// Inventory `Gemfile.lock`: `GEM`-section `specs:` entries (4-space
/// indent; deeper lines are dependency ranges) plus the bundler ≥ 2.6
/// `CHECKSUMS` section's sha256 values when present (older locks stay
/// discovery-only). Platform-suffixed specs (`nokogiri (1.16.5-arm64-…)`)
/// are skipped — platform gems are unsupported for vendoring anyway.
///
/// Multi-source locks: bundler ≥ 2 emits ONE GEM section per source
/// (Gemfile `source … do` blocks; verified against bundler 4.0.15) and
/// hard-errors on multiple global sources, so each spec resolves against
/// its OWN section's remote — never the first remote in the file, which
/// for a private-server section would 404 at best and leak private gem
/// names to the public registry at worst. A section carrying SEVERAL
/// distinct `remote:` lines is a legacy bundler 1.x multisource lock whose
/// per-spec origin is genuinely ambiguous: its specs stay discovery-only
/// (no resolved URL — the fetch layer then refuses), fail-closed.
pub(super) async fn inventory_gemfile_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("Gemfile.lock"))
        .await
        .ok()?;
    let mut section_remotes: Vec<Vec<String>> = Vec::new();
    let mut checksums: HashMap<(String, String), String> = HashMap::new();
    let mut specs: Vec<(String, String, usize)> = Vec::new();

    let mut section = "";
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            section = line.trim();
            in_specs = false;
            if section == "GEM" {
                section_remotes.push(Vec::new());
            }
            continue;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        match section {
            "GEM" => {
                if indent == 2 {
                    if let Some(r) = trimmed.strip_prefix("remote:") {
                        let r = r.trim().trim_end_matches('/');
                        if !r.is_empty() {
                            if let Some(remotes) = section_remotes.last_mut() {
                                remotes.push(r.to_string());
                            }
                        }
                    }
                    in_specs = trimmed == "specs:";
                } else if in_specs && indent == 4 {
                    if let Some((name, version)) = parse_gem_spec_line(trimmed) {
                        specs.push((name, version, section_remotes.len() - 1));
                    }
                }
            }
            "CHECKSUMS" => {
                // `  name (version) sha256=hex`
                if let Some((spec_part, hash_part)) =
                    trimmed.rsplit_once(" sha256=").map(|(s, h)| (s, h.trim()))
                {
                    if let Some((name, version)) = parse_gem_spec_line(spec_part) {
                        if is_hex_of_len(hash_part, 64) {
                            checksums.insert((name, version), hash_part.to_ascii_lowercase());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if specs.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for (name, version, sec) in specs {
        if !path_safety::is_safe_single_segment(&name)
            || !path_safety::is_safe_single_segment(&version)
        {
            continue;
        }
        let integrity = checksums
            .get(&(name.clone(), version.clone()))
            .map(|h| LockIntegrity::Sha256Hex(h.clone()))
            .unwrap_or(LockIntegrity::None);
        let resolved = match section_remotes.get(sec).map(Vec::as_slice) {
            Some([base]) => http_url(&format!("{base}/downloads/{name}-{version}.gem")),
            // No remote (a missing `remote:` line defaults to rubygems.org
            // ONLY when the whole lock has one remote-less GEM section —
            // the pre-multisource shape) or several remotes: fail closed.
            Some([]) if section_remotes.len() == 1 => http_url(&format!(
                "https://rubygems.org/downloads/{name}-{version}.gem"
            )),
            _ => None,
        };
        out.push(LockfileEntry {
            ecosystem: "gem",
            purl: format!("pkg:gem/{name}@{version}"),
            resolved,
            name,
            version,
            integrity,
        });
    }
    Some(dedup_prefer_integrity(out))
}

/// `name (version)` → parts; platform-suffixed versions (`1.2.3-x86_64…`)
/// and dependency lines (no parens / range operators) yield `None`.
fn parse_gem_spec_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.strip_suffix(')')?;
    if name.is_empty()
        || version.is_empty()
        || version.contains(' ')
        || version.contains('-')
        || !version.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// The DISTINCT `GEM remote:` bases across ALL GEM sections of the
/// Gemfile.lock (trailing `/` trimmed), in first-appearance order. A
/// vendored gem's spec block moved into its PATH section, so which GEM
/// section it came from is unrecoverable — ledger recovery may only build
/// a download URL when the lock's GEM sources agree on a single remote.
/// Collected scheme-AGNOSTICALLY: a non-http remote (a `file://` gem repo —
/// bundler 4.0.15 locks one GEM section per `source "file://…" do` block)
/// still counts toward the ambiguity decision; filtering it out first would
/// collapse a mixed http+file lock to one "agreed" remote and send the
/// file-sourced gem's name to the http one. The caller requires the single
/// survivor to be http(s).
pub(super) async fn gem_remotes(project_root: &Path) -> Vec<String> {
    let Ok(text) = read_regular_to_string(&project_root.join("Gemfile.lock")).await else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    let mut in_gem = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_gem = line.trim_end() == "GEM";
            continue;
        }
        if in_gem {
            if let Some(rest) = line.trim().strip_prefix("remote:") {
                let url = rest.trim().trim_end_matches('/').to_string();
                if !url.is_empty() && !out.contains(&url) {
                    out.push(url);
                }
            }
        }
    }
    out
}
