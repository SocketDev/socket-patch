//! The hosted planner's `Cargo.lock` leg: repoint a crate's `[[package]]`
//! block (and a v1 lock's `[metadata]` checksum and full-id references) at
//! the Socket-hosted index, as text splices over cargo's own lock layout
//! (`[[package]]\nname = "…"\nversion = "…"\n`). The line grammar here is
//! the one the hosted rewriter's lock probes ([`is_locked`],
//! [`locked_versions`]) read with, so a probe and the splice always agree
//! on which blocks exist.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::patch::redirect::FileEdit;

/// The line-anchored header cargo writes for `name`@`version`.
fn package_head(name: &str, version: &str) -> String {
    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
}

/// Every offset of `needle` in `content` that starts a line.
fn line_anchored<'c>(content: &'c str, needle: &'c str) -> impl Iterator<Item = usize> + 'c {
    content
        .match_indices(needle)
        .map(|(at, _)| at)
        .filter(|&at| at == 0 || content.as_bytes()[at - 1] == b'\n')
}

/// Whether the lock holds a `[[package]]` block for `name`@`version`.
pub(crate) fn is_locked(lock: &str, name: &str, version: &str) -> bool {
    line_anchored(lock, &package_head(name, version))
        .next()
        .is_some()
}

/// Every version of `name` the lock holds a `[[package]]` block for, sorted
/// and deduplicated.
pub(crate) fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let head = format!("[[package]]\nname = \"{name}\"\nversion = \"");
    let mut versions: Vec<String> = line_anchored(lock, &head)
        .filter_map(|at| {
            let rest = &lock[at + head.len()..];
            rest.split_once('"').map(|(v, _)| v.to_string())
        })
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

/// The Cargo.lock edit kind for dependents' full-id references: `original`
/// / `new` are the quoted `"<name> <version> (<source>)"` ids, keyed
/// `<name>@<version>`, and the inverse replaces EVERY occurrence of `new`.
pub(crate) const CARGO_LOCK_REFERENCE_KIND: &str = "redirect_cargo_lock_reference";

static CARGO_LOCK_SOURCE_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^source = "([^"]*)"$"#).expect("static lock source-line regex is valid")
});
static CARGO_LOCK_CHECKSUM_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^checksum = "[^"]*"$"#).expect("static lock checksum-line regex is valid")
});
// `$` (not `\n`) so it also anchors a source line that ENDS the block: the
// trailing newline sits outside the block region.
static CARGO_LOCK_AFTER_SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^(source = "[^"]*")$"#).expect("static source-line anchor regex is valid")
});

/// Repoint the crate's `[[package]]` at the hosted index with the patched
/// `.crate`'s checksum, in whichever Cargo.lock format the file is:
///
/// * v2–v4: `source` + an inline `checksum` in the entry;
/// * v1 (cargo < 1.41, still read by every cargo): the entry carries only
///   `source`; the checksum lives in the trailing `[metadata]` table under
///   `"checksum <name> <version> (<source>)"`, and every dependent names the
///   crate by its FULL package id `"<name> <version> (<source>)"`. Both are
///   keyed by the source, so both must follow it — a v1 lock with only the
///   entry repointed names a package that no longer exists (cargo discards
///   the lock and re-resolves; `--locked` fails) and pins nothing.
///
/// Full-id references are rewritten in any format (v2+ spells them that way
/// when a name + version is ambiguous). Each changed fragment is its own
/// `redirect_cargo_lock_entry` edit (unique text, so the fragment revert is
/// unambiguous) — the entry and the `[metadata]` line — and the dependents'
/// references are one `redirect_cargo_lock_reference` edit holding the
/// quoted full id, reverted at every occurrence.
pub(crate) fn plan_cargo_lock(
    content: &str,
    crate_name: &str,
    version: &str,
    index_url: &str,
    cksum: &str,
) -> CargoLockPlan {
    // Rust's regex has NO lookahead, so bound the [[package]] block by string
    // search (see [`lock_block_end`]): from its header to the next block or
    // trailing table (or EOF), so the bytes after the block (incl. the final
    // newline) are preserved.
    let head = package_head(crate_name, version);
    // Every line-anchored header for this name@version. A Cargo.lock may
    // legitimately hold TWO blocks for one name@version from different
    // sources — after a redirect, a transitive crates.io copy resolves beside
    // the socket-registry copy, and cargo sorts the crates.io block FIRST —
    // so the first hit alone would repoint the wrong twin.
    let heads: Vec<usize> = line_anchored(content, &head).collect();
    let block_start = match heads.as_slice() {
        [] => return CargoLockPlan::NotFound,
        [only] => *only,
        twins => {
            // Exactly one twin already at the target index is OURS (a re-run
            // over a redirected lock); anything else cannot be attributed and
            // the dep is skipped transactionally.
            let target_source = format!("source = \"{index_url}\"");
            let mut ours = twins.iter().copied().filter(|&at| {
                let body_start = at + head.len();
                content[body_start..lock_block_end(content, body_start)]
                    .lines()
                    .any(|line| line == target_source)
            });
            match (ours.next(), ours.next()) {
                (Some(at), None) => at,
                _ => return CargoLockPlan::Ambiguous,
            }
        }
    };
    let body_start = block_start + head.len();
    let block_end = lock_block_end(content, body_start);
    let original = content[block_start..block_end].to_string();
    let mut body = content[body_start..block_end].to_string();
    let old_source = CARGO_LOCK_SOURCE_LINE_RE
        .captures(&body)
        .map(|c| c[1].to_string());
    if old_source.is_some() {
        body = CARGO_LOCK_SOURCE_LINE_RE
            .replace(&body, format!("source = \"{index_url}\"").as_str())
            .to_string();
    } else {
        body = format!("source = \"{index_url}\"\n{body}");
    }
    // A v1 lock keeps the checksum in `[metadata]`, keyed by the package id
    // — the chosen block's OWN source when it has one, so a multi-source
    // twin's line is never taken for ours.
    let metadata_source = old_source
        .as_deref()
        .map_or_else(|| r#"[^)"]*"#.to_string(), regex::escape);
    let metadata_re = Regex::new(&format!(
        r#"(?m)^"checksum {} {} \({metadata_source}\)" = "[^"]*"$"#,
        regex::escape(crate_name),
        regex::escape(version)
    ))
    .expect("escaped lock metadata-line regex is valid");
    let metadata_line = metadata_re.find(content).map(|m| m.as_str().to_string());
    if metadata_line.is_none() {
        if CARGO_LOCK_CHECKSUM_LINE_RE.is_match(&body) {
            body = CARGO_LOCK_CHECKSUM_LINE_RE
                .replace(&body, format!("checksum = \"{cksum}\"").as_str())
                .to_string();
        } else {
            body = CARGO_LOCK_AFTER_SOURCE_RE
                .replace(&body, format!("${{1}}\nchecksum = \"{cksum}\"").as_str())
                .to_string();
        }
    }
    let rebuilt = format!("{head}{body}");
    let key = format!("{crate_name}@{version}");
    let edit = |original: &str, new: &str| FileEdit {
        path: "Cargo.lock".into(),
        kind: "redirect_cargo_lock_entry".into(),
        action: "rewritten".into(),
        key: Some(key.clone()),
        original: Some(Value::String(original.to_string())),
        new: Some(Value::String(new.to_string())),
    };
    let mut edits = Vec::new();
    let mut new_content = content.to_string();
    if rebuilt != original {
        new_content.replace_range(block_start..block_end, &rebuilt);
        edits.push(edit(&original, &rebuilt));
    }
    if let Some(line) = metadata_line {
        let pinned = format!("\"checksum {crate_name} {version} ({index_url})\" = \"{cksum}\"");
        if line != pinned {
            new_content = new_content.replacen(&line, &pinned, 1);
            edits.push(edit(&line, &pinned));
        }
    }
    // Dependents' full-id references to the OLD source, recorded as ONE
    // `redirect_cargo_lock_reference` edit holding just the quoted id —
    // never a dependent's whole block: a block referencing two patched
    // packages (the root of a v1 lock) would hold two overlapping block
    // edits, and reverting the first-applied one alone would find neither of
    // its fragments. The id names this name + version + source exactly, so its
    // inverse puts back EVERY occurrence, independently of any other
    // package's edits and in any removal order.
    if let Some(old) = old_source.filter(|old| old != index_url) {
        let from = format!("\"{crate_name} {version} ({old})\"");
        let to = format!("\"{crate_name} {version} ({index_url})\"");
        let mut repointed_any = false;
        // The oldest v1 locks keep the ROOT package in a standalone `[root]`
        // table instead of the `[[package]]` array, with its own full-id
        // `dependencies`. It precedes the array, so the block walk below
        // never reaches it and the lock would keep naming a package it no
        // longer contains (`--locked` fails; an unlocked build silently
        // re-resolves).
        if let Some((start, end)) = lock_root_table(&new_content) {
            if new_content[start..end].contains(&from) {
                let repointed = new_content[start..end].replace(&from, &to);
                new_content.replace_range(start..end, &repointed);
                repointed_any = true;
            }
        }
        let mut cursor = 0;
        while let Some((start, end)) = next_lock_block(&new_content, cursor) {
            if new_content[start..end].contains(&from) {
                let repointed = new_content[start..end].replace(&from, &to);
                new_content.replace_range(start..end, &repointed);
                repointed_any = true;
                cursor = start + repointed.len();
            } else {
                cursor = end;
            }
        }
        if repointed_any {
            edits.push(FileEdit {
                kind: CARGO_LOCK_REFERENCE_KIND.into(),
                ..edit(&from, &to)
            });
        }
    }
    // Already redirected (re-run): every fragment is at the target values; a
    // recorded edit would have original == new and grow the ledger forever.
    if edits.is_empty() {
        return CargoLockPlan::AlreadyRedirected;
    }
    CargoLockPlan::Rewritten {
        content: new_content,
        edits,
    }
}

/// The v1 `[root]` table's span, when the lock has one: cargo before the
/// `[root]` removal recorded the root package there rather than in the
/// `[[package]]` array, and its `dependencies` spell full package ids the
/// same way. Bounded by [`lock_block_end`], like a package block.
fn lock_root_table(content: &str) -> Option<(usize, usize)> {
    const HEADER: &str = "[root]\n";
    let at = content
        .match_indices(HEADER)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || content.as_bytes()[at - 1] == b'\n')?;
    Some((at, lock_block_end(content, at + HEADER.len())))
}

/// The next `[[package]]` block starting at or after `from`, as
/// [`lock_block_end`] bounds it.
pub(crate) fn next_lock_block(content: &str, from: usize) -> Option<(usize, usize)> {
    let rel = content.get(from..)?.find("[[package]]\n")?;
    let start = from + rel;
    if start != 0 && content.as_bytes()[start - 1] != b'\n' {
        return next_lock_block(content, start + 1);
    }
    Some((
        start,
        lock_block_end(content, start + "[[package]]\n".len()),
    ))
}

/// End of the `[[package]]` block whose body starts at `body_start`,
/// excluding the newline(s) before the next block / trailing table / EOF (so
/// a recorded original/new stops after the block's last content byte — the
/// TS rewriter's `(?=\n*$)` lookahead — while the file keeps its newlines).
pub(crate) fn lock_block_end(content: &str, body_start: usize) -> usize {
    // The next block, or the `[metadata]` / `[[patch.unused]]` tables that
    // trail the packages. The trailing tables are searched only up to the
    // next block: they sit after every `[[package]]` (absent entirely from
    // v3/v4 locks), and an unbounded search per block scanned to EOF for
    // every block of every dep. Each marker holds its only `\n` at offset 0,
    // so a hit starting before the next block also ends by it — the bounded
    // minimum is the unbounded one.
    let rest = &content[body_start..];
    let next_block = rest.find("\n[[package]]").unwrap_or(rest.len());
    let mut end = ["\n[metadata]", "\n[[patch.unused]]", "\n[patch"]
        .iter()
        .filter_map(|marker| rest[..next_block].find(marker))
        .min()
        .map_or(body_start + next_block, |rel| body_start + rel);
    while end > body_start && content.as_bytes()[end - 1] == b'\n' {
        end -= 1;
    }
    end
}

/// The previous, unbounded [`lock_block_end`], kept as the equivalence
/// oracle.
#[cfg(test)]
pub(crate) fn lock_block_end_unbounded(content: &str, body_start: usize) -> usize {
    let mut end = [
        "\n[[package]]",
        "\n[metadata]",
        "\n[[patch.unused]]",
        "\n[patch",
    ]
    .iter()
    .filter_map(|marker| content[body_start..].find(marker))
    .min()
    .map_or(content.len(), |rel| body_start + rel);
    while end > body_start && content.as_bytes()[end - 1] == b'\n' {
        end -= 1;
    }
    end
}

/// Outcome of the Cargo.lock `[[package]]` plan — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (the caller warns AND skips the dep entirely).
pub(crate) enum CargoLockPlan {
    Rewritten {
        content: String,
        edits: Vec<FileEdit>,
    },
    AlreadyRedirected,
    NotFound,
    /// Several `[[package]]` blocks for the name@version (multi-source twins)
    /// and not exactly one of them at the target index — which twin is ours
    /// cannot be decided, so the caller warns AND skips the dep entirely.
    Ambiguous,
}
