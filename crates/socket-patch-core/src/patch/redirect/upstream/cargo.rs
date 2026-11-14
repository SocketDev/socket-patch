//! Cargo upstream restore: `Cargo.lock` entries back on crates.io (source +
//! the index's checksum), every `Cargo.toml` declaration loses its
//! `registry = "socket-patch-<uuid>"` pin, and the project cargo config
//! drops the `[registries.socket-patch-<uuid>]` block nothing references
//! any more.
//!
//! The hosted rewriter only ever pins crates.io dependencies (it refuses a
//! dep declared against any other registry), so the upstream source is
//! always crates.io's. A declaration's original spelling is not recorded:
//! the shorthand `name = { version = "…", registry = "…" }` the rewriter
//! produces from `name = "…"` collapses back to that shorthand, and every
//! other form just loses the pin. That includes a pin that overwrote an
//! explicit `registry = "crates-io"` (#386): the declaration comes back
//! without the redundant key, which cargo resolves the same way.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{Ctx, FormatResult, HostedPin, View};
use crate::formats::cargo::CargoLock;

/// How Cargo.lock names crates.io (cargo keeps this spelling even when it
/// fetches over the sparse protocol).
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The project cargo configs, in cargo's read preference.
const CARGO_CONFIGS: [&str; 2] = [".cargo/config", ".cargo/config.toml"];

use crate::patch::redirect::generation::{self, hosted_pin_name as registry_name};

struct LockHit {
    uuid: String,
    /// The package's position in [`CargoLock::packages`].
    index: usize,
    name: String,
    version: String,
    /// The hosted source string (`sparse+https://…/index/`).
    source: String,
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    _files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let by_uuid: BTreeMap<&str, &HostedPin> = pins.iter().map(|p| (p.uuid.as_str(), *p)).collect();

    // ── Cargo.lock ──
    let lock_raw = match view.read("Cargo.lock").await {
        Ok(t) => t,
        Err(e) => {
            for pin in pins {
                result.refuse(&pin.uuid, e.clone());
            }
            return result;
        }
    };
    if let Some(raw) = lock_raw {
        let crlf = raw.contains("\r\n");
        let mut lock = raw.replace("\r\n", "\n");
        // The one parse of the lock: every package with its value spans.
        let model = match CargoLock::parse(&lock) {
            Ok(model) => model,
            Err(_) => {
                for pin in pins {
                    result.refuse(&pin.uuid, "Cargo.lock does not parse as TOML");
                }
                return result;
            }
        };
        let mut hits: Vec<LockHit> = Vec::new();
        for (i, pkg) in model.packages().iter().enumerate() {
            let Some(source) = &pkg.source else {
                continue;
            };
            let Some(uuid) = ctx.hosted_uuid(source) else {
                continue;
            };
            if !by_uuid.contains_key(uuid.as_str()) {
                continue;
            }
            hits.push(LockHit {
                uuid,
                index: i,
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                source: source.clone(),
            });
        }
        // The rewriter only pins crates.io crates, so a hosted block named
        // as no crates.io crate can be is not its work. The pin is refused
        // whole, before any lookup: its other blocks are left as they are
        // too, rather than restored around one that cannot be.
        for hit in &hits {
            if !super::client::is_crates_io_name(&hit.name) {
                result.refuse(
                    &hit.uuid,
                    format!(
                        "{}@{}: {:?} is not a crates.io crate name",
                        hit.name, hit.version, hit.name
                    ),
                );
            }
        }
        hits.retain(|hit| !result.refused.contains_key(&hit.uuid));
        // A hit whose name@version crates.io ALSO locks (a dependency added
        // after the pin resolved its own crates.io copy, which cargo cannot
        // unify with the Socket one, #679) merges into that block: splicing
        // crates.io's source into the Socket block would leave two
        // identical blocks, which cargo refuses to parse (#863). The twin
        // already carries the checksum, so no registry lookup is needed.
        let twin_of = |h: &LockHit| {
            model.packages().iter().any(|p| {
                p.name == h.name
                    && p.version == h.version
                    && p.source.as_deref() == Some(CRATES_IO_SOURCE)
            })
        };
        let lookups = hits.iter().filter(|h| !twin_of(h)).map(|h| async move {
            (
                h.uuid.clone(),
                ctx.client.cargo_cksum(&h.name, &h.version).await,
            )
        });
        let cksums: BTreeMap<String, Result<String, String>> =
            futures_util::future::join_all(lookups)
                .await
                .into_iter()
                .collect();
        let mut changed = false;
        let mut restored: Vec<(&LockHit, String)> = Vec::new();
        let mut merged: Vec<&LockHit> = Vec::new();
        for hit in &hits {
            if twin_of(hit) {
                merged.push(hit);
                continue;
            }
            let cksum = match cksums.get(&hit.uuid) {
                Some(Ok(c)) => c.clone(),
                Some(Err(why)) => {
                    result.refuse(&hit.uuid, format!("{}@{}: {why}", hit.name, hit.version));
                    continue;
                }
                None => continue,
            };
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            restored.push((hit, cksum));
        }
        // A pin refused on another hit (it wires two versions) is restored
        // nowhere.
        merged.retain(|h| !result.refused.contains_key(&h.uuid));
        // The entries' own source + checksum values, spliced at the parse's
        // spans (every hit is a distinct block: its source names its uuid).
        let spans = model
            .spans()
            .expect("a lock parsed from text carries spans");
        let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
        for (hit, cksum) in &restored {
            let at = &spans.packages[hit.index];
            if let Some(source) = &at.source {
                splices.push((source.clone(), format!("\"{CRATES_IO_SOURCE}\"")));
            }
            if let Some(checksum) = &at.checksum {
                splices.push((checksum.clone(), format!("\"{cksum}\"")));
            }
        }
        for hit in &merged {
            // The whole block, up to the next table header (its blank
            // separator line included); a last block also drops the blank
            // line before it.
            let start = spans.packages[hit.index].header;
            let range = match spans.headers.iter().copied().find(|&h| h > start) {
                Some(next) => start..next,
                None => {
                    let kept = lock[..start].trim_end_matches('\n').len() + 1;
                    kept.min(start)..lock.len()
                }
            };
            splices.push((range, String::new()));
            // A v1 lock's `[metadata]` checksum line for the Socket id.
            let key =
                crate::formats::cargo::metadata_checksum_key(&hit.name, &hit.version, &hit.source);
            if let Some((_, line)) = spans.metadata.iter().find(|(k, _)| *k == key) {
                let end = match lock[line.end..].find('\n') {
                    Some(n) => line.end + n + 1,
                    None => lock.len(),
                };
                splices.push((line.start..end, String::new()));
            }
        }
        splices.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
        // Two blocks of one name, version and source (a hand-merged lock)
        // name the same `[metadata]` line. Every other range is its own
        // block or value, so equal ranges are the only ones that meet.
        splices.dedup_by(|a, b| a.0 == b.0);
        for (range, with) in splices {
            lock.replace_range(range, &with);
        }
        for (hit, cksum) in &restored {
            // Dependents' full-id references and the v1 `[metadata]` key.
            lock = lock.replace(
                &format!("({})", hit.source),
                &format!("({CRATES_IO_SOURCE})"),
            );
            let metadata_key = format!(
                "\"checksum {} {} ({CRATES_IO_SOURCE})\" = \"",
                hit.name, hit.version
            );
            let rebuilt: Vec<String> = lock
                .split('\n')
                .map(|l| match l.strip_prefix(&metadata_key) {
                    Some(_) => format!("{metadata_key}{cksum}\""),
                    None => l.to_string(),
                })
                .collect();
            lock = rebuilt.join("\n");
            result.handled.insert(hit.uuid.clone());
            changed = true;
        }
        if !merged.is_empty() {
            lock = merged_references(&lock, &model, &merged);
            for hit in &merged {
                result.handled.insert(hit.uuid.clone());
            }
            changed = true;
        }
        if changed {
            view.write(
                "Cargo.lock",
                if crlf {
                    lock.replace('\n', "\r\n")
                } else {
                    lock
                },
            );
        }
    }

    // ── Cargo.toml pins ──
    let root = view.root().to_path_buf();
    let mut manifests: Vec<String> = vec!["Cargo.toml".to_string()];
    manifests.extend(
        tokio::task::spawn_blocking(move || crate::utils::cargo_workspace::member_manifests(&root))
            .await
            .unwrap_or_default(),
    );
    for rel in &manifests {
        let Ok(Some(text)) = view.read(rel).await else {
            continue;
        };
        let mut changed = false;
        let mut out: Vec<String> = Vec::new();
        for line in text.split('\n') {
            let mut kept = Some(line.to_string());
            for pin in pins {
                if result.refused.contains_key(&pin.uuid) {
                    continue;
                }
                let reg = registry_name(&pin.uuid);
                let Some(current) = kept.as_deref() else {
                    break;
                };
                if !current.contains(&format!("\"{reg}\"")) {
                    continue;
                }
                match unpin_line(current, &reg) {
                    Some(next) => {
                        kept = next;
                        changed = true;
                        result.handled.insert(pin.uuid.clone());
                    }
                    None => result.refuse(
                        &pin.uuid,
                        format!("{rel} pins it with a declaration socket-patch cannot unpin"),
                    ),
                }
            }
            if let Some(line) = kept {
                out.push(line);
            }
        }
        if changed {
            view.write(rel, out.join("\n"));
        }
    }

    // ── cargo config registry blocks ──
    // Every hosted generation a config defines is a candidate, not only the
    // pins found in the lock: a superseded generation's block an older CLI
    // left behind on re-pin is referenced by nothing and would otherwise
    // outlive the restore (#864). A block any manifest or the lock still
    // names stays.
    let mut configs: Vec<(&str, String)> = Vec::new();
    for rel in CARGO_CONFIGS {
        if let Ok(Some(config)) = view.read(rel).await {
            configs.push((rel, config));
        }
    }
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for rel in manifests.iter().map(String::as_str).chain(["Cargo.lock"]) {
        if let Ok(Some(text)) = view.read(rel).await {
            referenced.extend(generation::named_generations(&text));
            for (_, config) in &configs {
                for uuid in generation::named_generations(config) {
                    if lock_names_index(&text, &uuid) {
                        referenced.insert(uuid);
                    }
                }
            }
        }
    }
    for (rel, config) in configs {
        let mut next = config.clone();
        for uuid in generation::named_generations(&config) {
            if result.refused.contains_key(&uuid) || referenced.contains(&uuid) {
                continue;
            }
            if let Some(removed) = remove_registry_block(&next, &registry_name(&uuid)) {
                next = removed;
                if by_uuid.contains_key(uuid.as_str()) {
                    result.handled.insert(uuid);
                }
            }
        }
        if next != config {
            if next.trim().is_empty() {
                view.remove(rel);
            } else {
                view.write(rel, next);
            }
        }
    }
    result
}

/// Whether a Cargo.lock still sources a crate from the hosted index of
/// `uuid` (a pin this pass did not restore).
fn lock_names_index(text: &str, uuid: &str) -> bool {
    text.contains(&format!("/{uuid}/index/"))
}

static SHORTHAND_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r#"^(\s*[^=\s][^=]*?\s*=\s*)\{ version = ("[^"]+"), registry = "(socket-patch-[0-9a-fA-F-]{36})" \}(.*)$"#,
    )
    .expect("static shorthand regex is valid")
});

/// The rewriter's pin of a literal-string version (#757), written
/// registry-first so it is never a user's own `{ version = '…' }` table.
static LITERAL_SHORTHAND_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r#"^(\s*[^=\s][^=]*?\s*=\s*)\{ registry = "(socket-patch-[0-9a-fA-F-]{36})", version = ('[^']+') \}(.*)$"#,
    )
    .expect("static literal shorthand regex is valid")
});

/// Whether `body` (a line without its comment) is a dotted-key pin,
/// `<key>.registry = "<reg>"` (#757).
fn is_dotted_pin(body: &str, reg: &str) -> bool {
    let pinned = super::super::parse_cargo_entry_key(body)
        .and_then(|(_, rest)| rest.trim_start().strip_prefix('.'))
        .and_then(|rest| super::super::parse_cargo_entry_key(rest.trim_start()))
        .filter(|(sub, _)| sub == "registry")
        .and_then(|(_, rest)| rest.trim_start().strip_prefix('='));
    pinned.is_some_and(|value| value.trim() == format!("\"{reg}\""))
}

/// The line with its `registry = "<reg>"` pin removed: `Some(None)` drops
/// the whole line (the table form's `registry = …` line, or a dotted
/// `<key>.registry = …` one; a trailing comment on it survives as a
/// comment-only line),
/// `Some(Some(line))` is the unpinned declaration, `None` a spelling this
/// restore does not recognize.
fn unpin_line(line: &str, reg: &str) -> Option<Option<String>> {
    let trimmed = line.trim();
    let body = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if body == format!("registry = \"{reg}\"") || is_dotted_pin(body, reg) {
        // The pin may have overwritten a user's commented line in place
        // (a superseded pin, or `registry = "crates-io"`): the comment
        // stays, on its own line.
        // Sliced from the raw line, so a CRLF file's `\r` stays on it.
        return Some(line.find('#').map(|hash| {
            let indent = &line[..line.len() - line.trim_start().len()];
            format!("{indent}{}", &line[hash..])
        }));
    }
    if let Some(c) = SHORTHAND_RE.captures(line) {
        if &c[3] == reg {
            return Some(Some(format!("{}{}{}", &c[1], &c[2], &c[4])));
        }
    }
    if let Some(c) = LITERAL_SHORTHAND_RE.captures(line) {
        if &c[2] == reg {
            return Some(Some(format!("{}{}{}", &c[1], &c[3], &c[4])));
        }
    }
    let open = line.find('{')?;
    // The opening line of a multi-line inline table, which the rewriter
    // pins right after its `{` (#757).
    let opening_pin = format!(" registry = \"{reg}\",");
    let wraps = super::super::cargo_inline_table(&[line], 0, &line[open..]).is_none();
    if wraps && line[open + 1..].starts_with(&opening_pin) {
        return Some(Some(format!(
            "{}{}",
            &line[..=open],
            &line[open + 1 + opening_pin.len()..]
        )));
    }
    let close = open + line[open..].find('}')?;
    let inner = &line[open + 1..close];
    let pin_re = Regex::new(&format!(
        r#",?\s*registry\s*=\s*"{}"\s*,?"#,
        regex::escape(reg)
    ))
    .expect("registry pin regex is valid");
    let m = pin_re.find(inner)?;
    let mut rest = String::new();
    rest.push_str(inner[..m.start()].trim_end());
    let tail = inner[m.end()..].trim_start();
    if !tail.is_empty() {
        if !rest.trim().is_empty() {
            rest.push_str(", ");
        }
        rest.push_str(tail.trim_end());
    }
    let rest = rest.trim().trim_end_matches(',').trim();
    let rebuilt = if rest.is_empty() {
        format!("{}{{}}{}", &line[..open], &line[close + 1..])
    } else {
        format!("{}{{ {rest} }}{}", &line[..open], &line[close + 1..])
    };
    Some(Some(rebuilt))
}

/// The config with its `[registries.<reg>]` block removed, together with
/// the one newline the rewriter put before it; `None` when absent.
///
/// The rewriter wrote `config + "\n" + block` (just `block` into an empty
/// config), whether or not the config ended in a newline: that newline is
/// a blank separator line after a final newline, and the line ending of a
/// config that had none. Taking the block and that newline back restores
/// the config's exact bytes, a missing final newline or trailing blank
/// lines included. A file whose every line ends in CRLF is edited as LF
/// and written back CRLF, as the rewriter does; mixed endings stay as they
/// are.
///
/// The block is the header and the keys under it. Blank lines and comments
/// after its last key are the user's (a separator, or the heading of the
/// next section) and stay, as does everything after them. When the user
/// put content straight after the block of a config that had no final
/// newline, the newline stays too: without it the config's last line and
/// that content would become one line.
///
/// Earlier releases wrote `config + "\n\n" + block` into a config with no
/// final newline. Nothing in the file tells that apart from a config that
/// had one, so a config they patched comes back with a final newline added.
pub(crate) fn remove_registry_block(config: &str, reg: &str) -> Option<String> {
    let lf = super::super::crlf_to_lf(config);
    let text = lf.as_deref().unwrap_or(config);
    let header = format!("[registries.{reg}]");
    let lines: Vec<&str> = text.split('\n').collect();
    let i = lines.iter().position(|l| l.trim() == header)?;
    let mut end = lines[i + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |next| i + 1 + next);
    while end > i + 1 {
        let line = lines[end - 1].trim();
        if !(line.is_empty() || line.starts_with('#')) {
            break;
        }
        end -= 1;
    }
    let bytes = |lines: &[&str]| lines.iter().map(|l| l.len() + 1).sum::<usize>();
    let start = bytes(&lines[..i]);
    // The last line of a file with no final newline has no newline to take.
    let stop = (start + bytes(&lines[i..end])).min(text.len());
    let (before, after) = (&text[..start], &text[stop..]);
    let unseparated = before
        .strip_suffix("\r\n")
        .or_else(|| before.strip_suffix('\n'))
        .unwrap_or(before);
    // Without the newline, would the line before the block and what follows
    // it still be separate lines?
    let lines_stay_apart = unseparated.is_empty()
        || unseparated.ends_with('\n')
        || after.is_empty()
        || after.starts_with('\n')
        || after.starts_with("\r\n");
    let kept = if lines_stay_apart {
        unseparated
    } else {
        before
    };
    let removed = format!("{kept}{after}");
    Some(if lf.is_some() {
        removed.replace('\n', "\r\n")
    } else {
        removed
    })
}

/// Respell the dependents' references to each merged hit's crate the way
/// cargo writes them once the Socket block is gone (`lock`: the text with
/// the merged blocks removed; `model`: the lock before). A v1 lock spells
/// every reference as the full package id, now the crates.io one. Later
/// formats use the shortest unambiguous form: the bare name when the lock
/// holds one block of that crate, `"<name> <version>"` when it holds one of
/// that version, else the full crates.io id.
fn merged_references(lock: &str, model: &CargoLock, merged: &[&LockHit]) -> String {
    let v1 = !lock
        .lines()
        .take_while(|l| !l.starts_with('['))
        .any(|l| l.starts_with("version"))
        && lock.lines().any(|l| l.trim_end() == "[metadata]");
    let mut out = lock.to_string();
    for hit in merged {
        let full = format!("\"{} {} ({CRATES_IO_SOURCE})\"", hit.name, hit.version);
        let spelled = if v1 {
            full.clone()
        } else {
            let left: Vec<_> = model
                .packages()
                .iter()
                .enumerate()
                .filter(|(i, p)| p.name == hit.name && !merged.iter().any(|m| m.index == *i))
                .map(|(_, p)| p)
                .collect();
            if left.len() == 1 {
                format!("\"{}\"", hit.name)
            } else if left.iter().filter(|p| p.version == hit.version).count() == 1 {
                format!("\"{} {}\"", hit.name, hit.version)
            } else {
                full.clone()
            }
        };
        let socket = format!("\"{} {} ({})\"", hit.name, hit.version, hit.source);
        out = out.replace(&socket, &spelled).replace(&full, &spelled);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: &str = "socket-patch-55555555-5555-5555-5555-555555555555";

    #[test]
    fn shorthand_collapses_back() {
        let line = format!("serde = {{ version = \"1.0.190\", registry = \"{REG}\" }}");
        assert_eq!(
            unpin_line(&line, REG),
            Some(Some("serde = \"1.0.190\"".to_string()))
        );
    }

    #[test]
    fn inline_table_loses_only_the_pin() {
        let line = format!(
            "serde = {{ version = \"1\", features = [\"derive\"], registry = \"{REG}\" }} # hi"
        );
        assert_eq!(
            unpin_line(&line, REG),
            Some(Some(
                "serde = { version = \"1\", features = [\"derive\"] } # hi".to_string()
            ))
        );
    }

    /// #757: the rewriter pins a multi-line inline table on its opening
    /// line; restore drops exactly the text it inserted.
    #[test]
    fn multiline_inline_table_opening_line_loses_only_the_pin() {
        for (pinned, original) in [
            (
                format!("serde = {{ registry = \"{REG}\", version = \"1\", features = ["),
                "serde = { version = \"1\", features = [",
            ),
            (
                format!("serde = {{ registry = \"{REG}\", features = [ # wrapped\r"),
                "serde = { features = [ # wrapped\r",
            ),
            (
                format!("serde = {{ registry = \"{REG}\", features = [ # see {{x}}"),
                "serde = { features = [ # see {x}",
            ),
        ] {
            assert_eq!(unpin_line(&pinned, REG), Some(Some(original.to_string())));
        }
    }

    /// #757 end to end: restoring a hosted pin on a multi-line inline
    /// table returns the manifest byte-exact, for LF, CRLF and a BOM.
    #[tokio::test]
    async fn restore_unpins_a_multiline_inline_table_byte_exact() {
        let head = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n";
        let original = format!(
            "{head}cfg-if = {{ version = \"1.0.4\", features = [\n  \"core\", # why\n] }}\nlog = \"0.4\"\n"
        );
        let pinned = format!(
            "{head}cfg-if = {{ registry = \"socket-patch-{B}\", version = \"1.0.4\", features = [\n  \"core\", # why\n] }}\nlog = \"0.4\"\n"
        );
        for (crlf, bom) in [(false, false), (true, false), (false, true), (true, true)] {
            let shape = |s: &str| {
                let s = if crlf {
                    s.replace('\n', "\r\n")
                } else {
                    s.to_string()
                };
                if bom {
                    format!("\u{feff}{s}")
                } else {
                    s
                }
            };
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("Cargo.toml"), shape(&pinned)).unwrap();
            let pins = [super::super::HostedPin {
                purl: "pkg:cargo/cfg-if@1.0.4".into(),
                uuid: B.into(),
                files: vec!["Cargo.toml".into()],
            }];
            let opts = super::super::RestoreOptions {
                offline: true,
                ..Default::default()
            };
            let outcome = super::super::restore_upstream(tmp.path(), &pins, &opts).await;
            assert_eq!(
                outcome.restored().count(),
                1,
                "crlf={crlf} bom={bom}: {:?}",
                outcome.pins
            );
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap(),
                shape(&original),
                "crlf={crlf} bom={bom}"
            );
        }
    }

    /// #757: the rewriter pins a dotted-key dependency with an added
    /// `<key>.registry` line, and a literal-string version as a table
    /// that keeps the user's quotes; restore drops or collapses exactly
    /// that.
    #[test]
    fn dotted_and_literal_pins_unpin_to_the_original_spelling() {
        for (pinned, original) in [
            (format!("serde.registry = \"{REG}\""), None),
            (format!("  \"serde\" .registry = \"{REG}\"\r"), None),
            (format!("'serde'.registry = \"{REG}\""), None),
            (
                format!("serde.registry = \"{REG}\" # explicit"),
                Some("# explicit".to_string()),
            ),
            (
                format!("serde = {{ registry = \"{REG}\", version = '1.0.190' }} # why\r"),
                Some("serde = '1.0.190' # why\r".to_string()),
            ),
            (
                format!("'serde' = {{ registry = \"{REG}\", version = '^1.0' }}"),
                Some("'serde' = '^1.0'".to_string()),
            ),
            // A user's own one-line literal table keeps its table.
            (
                format!("serde = {{ version = '1.0.190', registry = \"{REG}\" }}"),
                Some("serde = { version = '1.0.190' }".to_string()),
            ),
        ] {
            assert_eq!(unpin_line(&pinned, REG), Some(original), "{pinned:?}");
        }
        // Another crate's own `registry` key is not a dotted pin.
        assert_eq!(
            unpin_line(&format!("serde.registry.x = \"{REG}\""), REG),
            None
        );
    }

    /// #757 end to end: restoring hosted pins written as dotted keys and
    /// as a literal-string version returns the manifest byte-exact, for
    /// LF, CRLF and a BOM.
    #[tokio::test]
    async fn restore_unpins_dotted_and_literal_pins_byte_exact() {
        let head = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n";
        let original = format!(
            "{head}cfg-if.version = \"1.0.4\" # why\ncfg-if.features = [\n  \"core\",\n]\n\
             log = '0.4.20'\n"
        );
        let pinned = format!(
            "{head}cfg-if.version = \"1.0.4\" # why\ncfg-if.registry = \"socket-patch-{B}\"\n\
             cfg-if.features = [\n  \"core\",\n]\n\
             log = {{ registry = \"socket-patch-{B}\", version = '0.4.20' }}\n"
        );
        for (crlf, bom) in [(false, false), (true, false), (false, true), (true, true)] {
            let shape = |s: &str| {
                let s = if crlf {
                    s.replace('\n', "\r\n")
                } else {
                    s.to_string()
                };
                if bom {
                    format!("\u{feff}{s}")
                } else {
                    s
                }
            };
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("Cargo.toml"), shape(&pinned)).unwrap();
            let pins = [super::super::HostedPin {
                purl: "pkg:cargo/cfg-if@1.0.4".into(),
                uuid: B.into(),
                files: vec!["Cargo.toml".into()],
            }];
            let opts = super::super::RestoreOptions {
                offline: true,
                ..Default::default()
            };
            let outcome = super::super::restore_upstream(tmp.path(), &pins, &opts).await;
            assert_eq!(
                outcome.restored().count(),
                1,
                "crlf={crlf} bom={bom}: {:?}",
                outcome.pins
            );
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap(),
                shape(&original),
                "crlf={crlf} bom={bom}"
            );
        }
    }

    #[test]
    fn table_form_line_is_dropped() {
        assert_eq!(
            unpin_line(&format!("registry = \"{REG}\""), REG),
            Some(None)
        );
    }

    /// A table-form pin that overwrote a commented `registry = "crates-io"`
    /// line (#386) or an earlier pin keeps the user's comment on restore.
    #[test]
    fn table_form_line_keeps_its_comment() {
        assert_eq!(
            unpin_line(&format!("  registry = \"{REG}\" # stay on crates.io"), REG),
            Some(Some("  # stay on crates.io".to_string()))
        );
        // A CRLF manifest is split on `\n`: the kept line keeps its `\r`.
        assert_eq!(
            unpin_line(&format!("registry = \"{REG}\" # note\r"), REG),
            Some(Some("# note\r".to_string()))
        );
    }

    #[test]
    fn appended_block_leaves_the_config_byte_identical() {
        let original = "[net]\ngit-fetch-with-cli = true\n";
        let hosted = format!(
            "{original}\n[registries.{REG}]\nindex = \"sparse+https://patch.socket.dev/x/index/\"\n"
        );
        assert_eq!(
            remove_registry_block(&hosted, REG).as_deref(),
            Some(original)
        );
        let created = format!("[registries.{REG}]\nindex = \"sparse+https://x/\"\n");
        assert_eq!(remove_registry_block(&created, REG).as_deref(), Some(""));
    }

    const A: &str = "aaaaaaaa-0000-4000-8000-00000000000a";
    const B: &str = "bbbbbbbb-0000-4000-8000-00000000000b";
    const C: &str = "cccccccc-0000-4000-8000-00000000000c";

    fn block(uuid: &str) -> String {
        format!(
            "[registries.socket-patch-{uuid}]\nindex = \"sparse+https://patch.socket.dev/patch-registry/cargo/tok/{uuid}/index/\"\n"
        )
    }

    /// Restore cfg-if's hosted pin `B` (lock-free, so offline) over
    /// `manifest` and `config`; the outcome and the config after (`None`
    /// once deleted).
    async fn restore_b(
        manifest: &str,
        config: &str,
    ) -> (super::super::RestoreOutcome, Option<String>) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), manifest).unwrap();
        std::fs::create_dir_all(tmp.path().join(".cargo")).unwrap();
        std::fs::write(tmp.path().join(".cargo/config.toml"), config).unwrap();
        let pins = [super::super::HostedPin {
            purl: "pkg:cargo/cfg-if@1.0.4".into(),
            uuid: B.into(),
            files: vec!["Cargo.toml".into(), ".cargo/config.toml".into()],
        }];
        let opts = super::super::RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let outcome = super::super::restore_upstream(tmp.path(), &pins, &opts).await;
        let config = std::fs::read_to_string(tmp.path().join(".cargo/config.toml")).ok();
        (outcome, config)
    }

    fn manifest(extra: &str) -> String {
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             cfg-if = {{ version = \"1.0.4\", registry = \"socket-patch-{B}\" }}\n{extra}"
        )
    }

    /// #864: a superseded generation's block an older CLI left beside the
    /// live pin's is referenced by nothing; restoring the live pin sweeps
    /// it too, and the config the rewriter created is deleted once empty.
    #[tokio::test]
    async fn restore_sweeps_a_leftover_superseded_registry_block() {
        let config = format!("{}\n{}", block(A), block(B));
        let (outcome, after) = restore_b(&manifest(""), &config).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        assert_eq!(after, None, "the emptied config must be deleted");
    }

    /// The rewriter's own append (`plan_cargo_config`), undone by the
    /// restore `remove` runs: a config comes back as it was, with no final
    /// newline when it had none.
    #[tokio::test]
    async fn restore_gives_back_a_config_with_no_final_newline() {
        for original in [
            "[net]\nretry = 3",
            "[net]\nretry = 3\n",
            "[net]\nretry = 3\n\n",
        ] {
            let hosted = super::super::super::plan_cargo_config(
                original,
                ".cargo/config.toml",
                &format!("socket-patch-{B}"),
                "sparse+https://patch.socket.dev/patch-registry/cargo/tok/b/index/",
            )
            .expect("block appended")
            .content;
            let (outcome, after) = restore_b(&manifest(""), &hosted).await;
            assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
            assert_eq!(after.as_deref(), Some(original), "{original:?}");
        }
    }

    /// What the user wrote after the block stays, on lines of its own.
    #[test]
    fn content_after_the_block_is_kept() {
        let block = format!("[registries.{REG}]\nindex = \"sparse+https://x/\"\n");
        let rest = "[build]\njobs = 4\n";
        // A config with no final newline, then `[build]` put straight after
        // the block: the newline before the block has to stay, or
        // `retry = 3[build]` is one line cargo cannot parse.
        assert_eq!(
            remove_registry_block(&format!("[net]\nretry = 3\n{block}{rest}"), REG).as_deref(),
            Some("[net]\nretry = 3\n[build]\njobs = 4\n")
        );
        // Behind a blank line, or after a config that ended in a newline,
        // the newline before the block goes as it does at the end of the
        // file.
        assert_eq!(
            remove_registry_block(&format!("[net]\nretry = 3\n{block}\n{rest}"), REG).as_deref(),
            Some("[net]\nretry = 3\n[build]\njobs = 4\n")
        );
        assert_eq!(
            remove_registry_block(&format!("[net]\nretry = 3\n\n{block}{rest}"), REG).as_deref(),
            Some("[net]\nretry = 3\n[build]\njobs = 4\n")
        );
        // A comment heading the next section is the user's, with the blank
        // line before it.
        assert_eq!(
            remove_registry_block(
                &format!("[net]\nretry = 3\n\n{block}\n# build settings\n{rest}"),
                REG
            )
            .as_deref(),
            Some("[net]\nretry = 3\n\n# build settings\n[build]\njobs = 4\n")
        );
        // So is a comment at the end of the file.
        assert_eq!(
            remove_registry_block(&format!("[net]\nretry = 3\n{block}# note"), REG).as_deref(),
            Some("[net]\nretry = 3\n# note")
        );
    }

    /// A file of mixed line endings is not an all-CRLF file: the lines the
    /// block never touched keep the endings they had.
    #[test]
    fn mixed_line_endings_are_left_as_they_are() {
        let block = format!("[registries.{REG}]\nindex = \"sparse+https://x/\"\n");
        for original in ["[a]\r\nx = 1\ny = 2", "[a]\r\nx = 1\ny = 2\n"] {
            assert_eq!(
                remove_registry_block(&format!("{original}\n{block}"), REG).as_deref(),
                Some(original),
                "{original:?}"
            );
        }
        let crlf = "[a]\r\nx = 1\r\n";
        assert_eq!(
            remove_registry_block(
                &format!("{crlf}\n{block}")
                    .replace("\r\n", "\n")
                    .replace('\n', "\r\n"),
                REG
            )
            .as_deref(),
            Some(crlf)
        );
    }

    /// A generation the restore did not select that a manifest still pins
    /// stays wired: only unreferenced blocks are swept.
    #[tokio::test]
    async fn restore_keeps_an_unselected_generation_still_referenced() {
        let config = format!("{}\n{}", block(B), block(C));
        let other = format!("log = {{ version = \"0.4.20\", registry = \"socket-patch-{C}\" }}\n");
        let (outcome, after) = restore_b(&manifest(&other), &config).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        assert_eq!(
            after.as_deref().map(str::trim_start),
            Some(block(C).as_str())
        );
    }

    const CRATES_IO_CKSUM: &str =
        "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801";
    const SOCKET_CKSUM: &str = "cb5ea0124d6d4ab3fa7c9a2c4e20e8f0e2e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0";

    fn socket_source(uuid: &str) -> String {
        format!("sparse+https://patch.socket.dev/patch-registry/cargo/tok/{uuid}/index/")
    }

    /// Restore cfg-if's hosted pin `B` over `lock` (offline); the outcome
    /// and the lock after.
    async fn restore_lock(lock: &str) -> (super::super::RestoreOutcome, String) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            manifest("crc32fast = \"=1.5.0\"\n"),
        )
        .unwrap();
        std::fs::write(tmp.path().join("Cargo.lock"), lock).unwrap();
        std::fs::create_dir_all(tmp.path().join(".cargo")).unwrap();
        std::fs::write(tmp.path().join(".cargo/config.toml"), block(B)).unwrap();
        let pins = [super::super::HostedPin {
            purl: "pkg:cargo/cfg-if@1.0.4".into(),
            uuid: B.into(),
            files: vec![
                "Cargo.lock".into(),
                "Cargo.toml".into(),
                ".cargo/config.toml".into(),
            ],
        }];
        let opts = super::super::RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let outcome = super::super::restore_upstream(tmp.path(), &pins, &opts).await;
        let after = std::fs::read_to_string(tmp.path().join("Cargo.lock")).unwrap();
        (outcome, after)
    }

    /// A hosted-source block whose `name` crates.io cannot hold (empty, or
    /// not ASCII) refuses its pin with the name, online too, and leaves the
    /// lock as it was: the index path is never built from it.
    #[tokio::test]
    async fn restore_refuses_a_hosted_block_named_like_no_crate() {
        for name in ["éa", ""] {
            let lock = format!(
                "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                 [[package]]\nname = \"{name}\"\nversion = \"1.0.4\"\n\
                 source = \"{}\"\nchecksum = \"{SOCKET_CKSUM}\"\n",
                socket_source(B)
            );
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("Cargo.toml"), manifest("")).unwrap();
            std::fs::write(tmp.path().join("Cargo.lock"), &lock).unwrap();
            let pins = [super::super::HostedPin {
                purl: "pkg:cargo/cfg-if@1.0.4".into(),
                uuid: B.into(),
                files: vec!["Cargo.lock".into(), "Cargo.toml".into()],
            }];
            // Online: the name is refused before any registry request.
            let opts = super::super::RestoreOptions::default();
            let outcome = super::super::restore_upstream(tmp.path(), &pins, &opts).await;
            let refusals: Vec<&str> = outcome.refused().map(|(_, why)| why).collect();
            assert_eq!(refusals.len(), 1, "{:?}", outcome.pins);
            assert!(
                refusals[0].contains(&format!("{name:?} is not a crates.io crate name")),
                "{refusals:?}"
            );
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("Cargo.lock")).unwrap(),
                lock
            );
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap(),
                manifest("")
            );
        }
    }

    /// Such a block refuses its pin whole, wherever it sits: a block of
    /// the same hosted source that could be restored is left alone too,
    /// and no lookup is made for it (its answer would otherwise be spliced
    /// into both).
    #[tokio::test]
    async fn restore_refuses_the_whole_pin_beside_a_block_named_like_no_crate() {
        let socket = socket_source(B);
        let block = |name: &str| {
            format!(
                "[[package]]\nname = \"{name}\"\nversion = \"1.0.4\"\n\
                 source = \"{socket}\"\nchecksum = \"{SOCKET_CKSUM}\"\n\n"
            )
        };
        for (first, second) in [("é", "cfg-if"), ("cfg-if", "é")] {
            let lock = format!(
                "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n{}{}",
                block(first),
                block(second)
            );
            let (outcome, after) = restore_lock(&lock).await;
            let refusals: Vec<&str> = outcome.refused().map(|(_, why)| why).collect();
            assert_eq!(refusals.len(), 1, "{:?}", outcome.pins);
            assert!(
                refusals[0].contains("\"é\" is not a crates.io crate name"),
                "{first} then {second}: {refusals:?}"
            );
            assert_eq!(after, lock, "{first} then {second}");
        }
    }

    /// A hand-merged v1 lock holding the Socket block twice (cargo refuses
    /// it, TOML does not) names one `[metadata]` line from both blocks: the
    /// line is removed once, not spliced out of the text a second time.
    #[tokio::test]
    async fn restore_merge_drops_a_shared_metadata_line_once() {
        let socket = socket_source(B);
        let socket_block = format!(
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{socket}\"\n\n"
        );
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({socket})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             {socket_block}{socket_block}\
             [metadata]\n\
             \"checksum cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{CRATES_IO_CKSUM}\"\n\
             \"checksum cfg-if 1.0.4 ({socket})\" = \"{SOCKET_CKSUM}\"\n"
        );
        let (outcome, after) = restore_lock(&lock).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        let want = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [metadata]\n\
             \"checksum cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{CRATES_IO_CKSUM}\"\n"
        );
        assert_eq!(after, want);
    }

    /// The lock cargo writes once a later dependency (crc32fast) locks a
    /// crates.io copy of the hosted-pinned cfg-if 1.0.4 (#679): two blocks
    /// for one name@version, so every reference is a full package id.
    /// `extra_cfg_if` also locks cfg-if 0.1.10.
    fn contested_lock(extra_cfg_if: bool) -> String {
        let socket = socket_source(B);
        let old = if extra_cfg_if {
            "[[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"4785bdd1c96b2a846b2bd7cc02e86b6b3dbf14e7e53446c4f54c92a361040822\"\n\n"
        } else {
            ""
        };
        let old_dep = if extra_cfg_if {
            " \"cfg-if 0.1.10\",\n"
        } else {
            ""
        };
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\nversion = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n{old_dep} \
             \"cfg-if 1.0.4 ({socket})\",\n \"crc32fast\",\n]\n\n\
             {old}\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{CRATES_IO_CKSUM}\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"{socket}\"\nchecksum = \"{SOCKET_CKSUM}\"\n\n\
             [[package]]\nname = \"crc32fast\"\nversion = \"1.5.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"9d7fe8a1a6b8f4a28b3b6e2b0f7a1d1fa2f1e1d8c1c6b2a4d3e9f6a1b5c7d8e9\"\n\
             dependencies = [\n \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n"
        )
    }

    /// #863: restoring a hosted pin whose name@version crates.io ALSO locks
    /// merges the Socket block into the existing crates.io one (no
    /// duplicate block, which cargo refuses to parse) and spells every
    /// reference the way cargo does for an unambiguous crate — the lock
    /// `cargo generate-lockfile` would write. No registry lookup is needed:
    /// the crates.io block already carries the checksum, so it works
    /// offline.
    #[tokio::test]
    async fn restore_merges_into_an_existing_crates_io_twin() {
        let (outcome, after) = restore_lock(&contested_lock(false)).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        let want = format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\nversion = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if\",\n \"crc32fast\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{CRATES_IO_CKSUM}\"\n\n\
             [[package]]\nname = \"crc32fast\"\nversion = \"1.5.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"9d7fe8a1a6b8f4a28b3b6e2b0f7a1d1fa2f1e1d8c1c6b2a4d3e9f6a1b5c7d8e9\"\n\
             dependencies = [\n \"cfg-if\",\n]\n"
        );
        assert_eq!(after, want);
        CargoLock::parse(&after).expect("the restored lock parses");
    }

    /// With another cfg-if version locked too, the merged crate's
    /// references keep their version (`"cfg-if 1.0.4"`): the name alone is
    /// still ambiguous.
    #[tokio::test]
    async fn restore_merge_keeps_versioned_refs_while_the_name_is_ambiguous() {
        let (outcome, after) = restore_lock(&contested_lock(true)).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        let model = CargoLock::parse(&after).expect("the restored lock parses");
        let blocks: Vec<_> = model
            .packages()
            .iter()
            .filter(|p| p.name == "cfg-if")
            .map(|p| (p.version.as_str(), p.source.as_deref()))
            .collect();
        assert_eq!(
            blocks,
            [
                ("0.1.10", Some(CRATES_IO_SOURCE)),
                ("1.0.4", Some(CRATES_IO_SOURCE))
            ],
            "{after}"
        );
        assert!(!after.contains("patch.socket.dev"), "{after}");
        assert!(
            after.contains(
                "dependencies = [\n \"cfg-if 0.1.10\",\n \"cfg-if 1.0.4\",\n \"crc32fast\",\n]"
            ) && after.contains("dependencies = [\n \"cfg-if 1.0.4\",\n]"),
            "{after}"
        );
    }

    /// The v1 format spells every reference as a full id and files the
    /// checksum in `[metadata]`: the merge keeps one crates.io metadata line
    /// and full crates.io ids.
    #[tokio::test]
    async fn restore_merge_in_a_v1_lock() {
        let socket = socket_source(B);
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({socket})\",\n \
             \"crc32fast 1.5.0 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{socket}\"\n\n\
             [[package]]\nname = \"crc32fast\"\nversion = \"1.5.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             dependencies = [\n \
             \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [metadata]\n\
             \"checksum cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{CRATES_IO_CKSUM}\"\n\
             \"checksum cfg-if 1.0.4 ({socket})\" = \"{SOCKET_CKSUM}\"\n\
             \"checksum crc32fast 1.5.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \"00\"\n"
        );
        let (outcome, after) = restore_lock(&lock).await;
        assert_eq!(outcome.restored().count(), 1, "{:?}", outcome.pins);
        let want = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n \
             \"crc32fast 1.5.0 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"crc32fast\"\nversion = \"1.5.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             dependencies = [\n \
             \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [metadata]\n\
             \"checksum cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{CRATES_IO_CKSUM}\"\n\
             \"checksum crc32fast 1.5.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \"00\"\n"
        );
        assert_eq!(after, want);
    }
}
