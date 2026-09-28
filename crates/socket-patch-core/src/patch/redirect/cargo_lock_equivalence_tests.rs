//! Equivalence oracle for the Cargo.lock hosted splice, which now edits the
//! byte spans of the lock's one parse ([`CargoLock::parse`] →
//! [`CargoLock::plan_hosted`]) instead of searching the text for cargo's
//! canonical `[[package]]\nname = …\nversion = …\n` header. The previous
//! line-grammar planner is kept below, test-only, as the oracle: over every
//! canonical lock shape (v1 `[metadata]` + full-id references, v3/v4 inline
//! checksums, multi-source twins, `[root]`, trailers, a missing final
//! newline) both must produce identical bytes and identical `FileEdit`s,
//! for every package of every lock and a re-run over the result. (Locks the
//! old grammar could not read — a comment or reordered key inside a block —
//! are where the two differ by design: the span planner finds them.)

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::formats::cargo::hosted::{CargoLockPlan, CARGO_LOCK_REFERENCE_KIND};
use crate::formats::cargo::CargoLock;
use crate::golden::Golden;
use crate::patch::redirect::FileEdit;

// ── the oracle: the previous line-grammar planner, verbatim ──

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
fn plan_cargo_lock(
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
fn next_lock_block(content: &str, from: usize) -> Option<(usize, usize)> {
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
fn lock_block_end(content: &str, body_start: usize) -> usize {
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


/// Deterministic xorshift64* — no `rand` dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// A lock in the given format: v1 (checksums in a trailing `[metadata]`,
/// full-id dependency references), or v3/v4 (inline checksums). Randomly
/// sprinkles the hostile shapes the bound must not be fooled by: marker
/// look-alikes inside strings, multi-byte names, blank-line runs between
/// blocks, `[[patch.unused]]` / `[patch.*]` trailers, and a missing final
/// newline.
fn synth_lock(rng: &mut Rng, blocks: usize, v1: bool) -> String {
    let mut out = String::new();
    out.push_str("# This file is automatically @generated by Cargo.\n");
    out.push_str("# It is not intended for manual editing.\n");
    if !v1 {
        out.push_str(if rng.chance(50) {
            "version = 4\n"
        } else {
            "version = 3\n"
        });
    }
    let mut metadata = Vec::new();
    for i in 0..blocks {
        out.push('\n');
        if rng.chance(10) {
            out.push('\n');
        }
        let name = match rng.below(5) {
            0 => format!("crate-é{i}"),
            1 => format!("crate_{i}"),
            _ => format!("c{i}"),
        };
        let version = format!("{}.{}.{}", rng.below(3), rng.below(20), rng.below(9));
        out.push_str(&format!(
            "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
        ));
        let has_source = !rng.chance(15);
        if has_source {
            out.push_str(&format!("source = \"{CRATES_IO}\"\n"));
            let sum = format!("{:016x}{:016x}", rng.next(), rng.next());
            if v1 {
                metadata.push(format!(
                    "\"checksum {name} {version} ({CRATES_IO})\" = \"{sum}\""
                ));
            } else {
                out.push_str(&format!("checksum = \"{sum}\"\n"));
            }
        }
        if rng.chance(70) {
            out.push_str("dependencies = [\n");
            for d in 0..rng.below(5) {
                let dep = format!("c{}", (i + d + 1) % blocks.max(1));
                if v1 || rng.chance(20) {
                    out.push_str(&format!(" \"{dep} 0.1.0 ({CRATES_IO})\",\n"));
                } else {
                    out.push_str(&format!(" \"{dep}\",\n"));
                }
            }
            if rng.chance(10) {
                // Marker look-alikes that are NOT line-anchored.
                out.push_str(" \"x [metadata] [[package]] [patch.unused]\",\n");
            }
            out.push_str("]\n");
        }
    }
    if (v1 || rng.chance(20)) && (!metadata.is_empty() || rng.chance(50)) {
        out.push_str("\n[metadata]\n");
        for line in &metadata {
            out.push_str(line);
            out.push('\n');
        }
    }
    if rng.chance(30) {
        out.push_str("\n[[patch.unused]]\nname = \"unused\"\nversion = \"1.0.0\"\n");
    }
    if rng.chance(15) {
        out.push_str("\n[patch.crates-io]\n");
    }
    if rng.chance(20) {
        while out.ends_with('\n') {
            out.pop();
        }
    } else if rng.chance(20) {
        out.push_str("\n\n");
    }
    out
}


// ── the comparison ──

const INDEX: &str = "sparse+https://socket.example/cargo/index/";

fn plan_new(lock: &str, name: &str, version: &str, cksum: &str) -> CargoLockPlan {
    CargoLock::parse(lock)
        .expect("synthesized locks parse")
        .plan_hosted(lock, name, version, INDEX, cksum)
}

/// A plan as comparable data.
fn shape(plan: &CargoLockPlan) -> (String, Option<String>, Vec<FileEdit>) {
    match plan {
        CargoLockPlan::Rewritten { content, edits } => {
            ("rewritten".into(), Some(content.clone()), edits.clone())
        }
        CargoLockPlan::AlreadyRedirected => ("already".into(), None, Vec::new()),
        CargoLockPlan::NotFound => ("not-found".into(), None, Vec::new()),
        CargoLockPlan::Ambiguous => ("ambiguous".into(), None, Vec::new()),
    }
}

fn assert_same(
    g: &mut Golden,
    lock: &str,
    name: &str,
    version: &str,
    cksum: &str,
    what: &str,
) -> Option<String> {
    let old = plan_cargo_lock(lock, name, version, INDEX, cksum);
    let new = plan_new(lock, name, version, cksum);
    let (old, new) = (shape(&old), shape(&new));
    g.next(&(lock, name, version, cksum), &new);
    // The one shape the line grammar cannot read and cargo can: the block's
    // canonical header without the newline after `version` (a final block
    // at EOF with no trailing newline). The span planner finds it.
    let canonical_head = format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n");
    if old.0 == "not-found" && new.0 != "not-found" && !lock.contains(&canonical_head) {
        return new.1;
    }
    assert_eq!(new.0, old.0, "{what}: {name}@{version} outcome\n{lock}");
    assert_eq!(new.1, old.1, "{what}: {name}@{version} bytes\n{lock}");
    assert_eq!(
        serde_json::to_value(&new.2).unwrap(),
        serde_json::to_value(&old.2).unwrap(),
        "{what}: {name}@{version} edits"
    );
    new.1
}

/// `(name, version)` of every `[[package]]` the lock holds, in order.
fn targets(lock: &str) -> Vec<(String, String)> {
    CargoLock::parse(lock)
        .expect("synthesized locks parse")
        .packages()
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect()
}

/// Every package of `lock`, planned by both, then a second package planned
/// over the first's output and a re-run of the first (the no-op path).
fn assert_lock(g: &mut Golden, lock: &str, rng: &mut Rng, what: &str) {
    let all = targets(lock);
    for (name, version) in &all {
        let cksum = format!("{:016x}{:016x}", rng.next(), rng.next());
        let Some(once) = assert_same(g, lock, name, version, &cksum, what) else {
            continue;
        };
        assert_same(g, &once, name, version, &cksum, &format!("{what} re-run"));
        if let Some((other, other_version)) = all.get(rng.below(all.len())) {
            assert_same(
                g,
                &once,
                other,
                other_version,
                "00ff",
                &format!("{what} then another"),
            );
        }
    }
    // An absent package, on both sides.
    assert_same(g, lock, "absent-crate", "9.9.9", "00", what);
}

#[test]
fn span_splice_matches_the_line_grammar_on_random_locks() {
    let mut g = Golden::new(
        "cargo_lock_random",
        "One package of a seeded Cargo.lock, planned for the hosted index.",
    )
    .chunked(20);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..300 {
        let v1 = rng.chance(50);
        let blocks = rng.below(12);
        let lock = synth_lock(&mut rng, blocks, v1);
        assert_lock(&mut g, &lock, &mut rng, &format!("case {case} (v1={v1})"));
    }
    g.finish();
}

/// Hand-written shapes the generator does not produce: multi-source twins
/// (one at the target index, and none), a v1 `[root]` table, a v1 block with
/// no source, a source ending the text, and blocks with neither line.
#[test]
fn span_splice_matches_the_line_grammar_on_hand_written_locks() {
    let crates_io = CRATES_IO;
    let twins_ours = format!(
        "version = 3\n\n[[package]]\nname = \"t\"\nversion = \"1.0.0\"\nsource = \"{crates_io}\"\nchecksum = \"aa\"\n\n[[package]]\nname = \"t\"\nversion = \"1.0.0\"\nsource = \"{INDEX}\"\nchecksum = \"bb\"\n"
    );
    let twins_neither = twins_ours.replace(INDEX, "registry+https://other.example/index");
    let v1_root = format!(
        "[root]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"d 1.0.0 ({crates_io})\",\n]\n\n[[package]]\nname = \"d\"\nversion = \"1.0.0\"\nsource = \"{crates_io}\"\n\n[[package]]\nname = \"u\"\nversion = \"2.0.0\"\nsource = \"{crates_io}\"\ndependencies = [\n \"d 1.0.0 ({crates_io})\",\n]\n\n[metadata]\n\"checksum d 1.0.0 ({crates_io})\" = \"cc\"\n\"checksum u 2.0.0 ({crates_io})\" = \"dd\"\n"
    );
    let sourceless_v1 = "[[package]]\nname = \"s\"\nversion = \"1.0.0\"\n\n[metadata]\n\"checksum s 1.0.0 (registry+x)\" = \"ee\"\n".to_string();
    let source_at_eof = format!("[[package]]\nname = \"e\"\nversion = \"1.0.0\"\nsource = \"{crates_io}\"");
    let bare = "version = 3\n\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"c\"\nversion = \"1.0.0\"\n".to_string();
    let mut g = Golden::new(
        "cargo_lock_hand_written",
        "One package of a hand-written Cargo.lock shape, planned for the hosted index.",
    );
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for (what, lock) in [
        ("twins, one ours", twins_ours),
        ("twins, neither ours", twins_neither),
        ("v1 [root]", v1_root),
        ("v1 sourceless", sourceless_v1),
        ("source at EOF", source_at_eof),
        ("bare blocks", bare),
    ] {
        assert_lock(&mut g, &lock, &mut rng, what);
    }
    g.finish();
}

/// The large-lock shape: ≥1k blocks, both formats, a sample of targets.
#[test]
fn span_splice_matches_the_line_grammar_on_a_large_lock() {
    let mut g = Golden::new(
        "cargo_lock_large",
        "One sampled package of a seeded ≥1k-block Cargo.lock, planned for the hosted index.",
    );
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for v1 in [false, true] {
        let lock = synth_lock(&mut rng, 1_200, v1);
        let all = targets(&lock);
        assert!(all.len() >= 1_000, "fixture keeps the ≥1k-block shape");
        for (name, version) in all.iter().step_by(97) {
            assert_same(
                &mut g,
                &lock,
                name,
                version,
                "abcd",
                &format!("large (v1={v1})"),
            );
        }
    }
    g.finish();
}
