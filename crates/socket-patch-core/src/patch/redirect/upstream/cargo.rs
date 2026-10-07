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
//! other form just loses the pin.

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
        let lookups = hits.iter().map(|h| async move {
            (
                h.uuid.clone(),
                ctx.client.cargo_cksum(&h.name, &h.version).await,
            )
        });
        let cksums: BTreeMap<String, Result<String, String>> =
            futures_util::future::join_all(lookups).await.into_iter().collect();
        let mut changed = false;
        let mut restored: Vec<(&LockHit, String)> = Vec::new();
        for hit in &hits {
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
        // The entries' own source + checksum values, spliced at the parse's
        // spans (every hit is a distinct block: its source names its uuid).
        let spans = model.spans().expect("a lock parsed from text carries spans");
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
        splices.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
        for (range, with) in splices {
            lock.replace_range(range, &with);
        }
        for (hit, cksum) in &restored {
            // Dependents' full-id references and the v1 `[metadata]` key.
            lock = lock.replace(&format!("({})", hit.source), &format!("({CRATES_IO_SOURCE})"));
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
        if changed {
            view.write(
                "Cargo.lock",
                if crlf { lock.replace('\n', "\r\n") } else { lock },
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
        r#"^(\s*[^=\s][^=]*?\s*=\s*)\{ version = "([^"]+)", registry = "(socket-patch-[0-9a-fA-F-]{36})" \}(.*)$"#,
    )
    .expect("static shorthand regex is valid")
});

/// The line with its `registry = "<reg>"` pin removed: `Some(None)` drops
/// the whole line (the table form's inserted `registry = …` line),
/// `Some(Some(line))` is the unpinned declaration, `None` a spelling this
/// restore does not recognize.
fn unpin_line(line: &str, reg: &str) -> Option<Option<String>> {
    let trimmed = line.trim();
    let body = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if body == format!("registry = \"{reg}\"") {
        return Some(None);
    }
    if let Some(c) = SHORTHAND_RE.captures(line) {
        if &c[3] == reg {
            return Some(Some(format!("{}\"{}\"{}", &c[1], &c[2], &c[4])));
        }
    }
    let open = line.find('{')?;
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

/// The config with its `[registries.<reg>]` block (and the blank separator
/// the rewriter put before it) removed; `None` when absent.
pub(crate) fn remove_registry_block(config: &str, reg: &str) -> Option<String> {
    let crlf = config.contains("\r\n");
    let lf = config.replace("\r\n", "\n");
    let header = format!("[registries.{reg}]");
    let lines: Vec<&str> = lf.split('\n').collect();
    let i = lines.iter().position(|l| l.trim() == header)?;
    let mut end = lines.len();
    for (j, l) in lines.iter().enumerate().skip(i + 1) {
        if l.trim_start().starts_with('[') {
            end = j;
            break;
        }
    }
    while end > i + 1 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    let fragment = format!("{}\n", lines[i..end].join("\n"));
    let removed = remove_appended_cargo_block(&lf, &fragment)
        .or_else(|| {
            // The block ends the file with no final newline.
            remove_appended_cargo_block(&lf, fragment.trim_end_matches('\n'))
        })?;
    Some(if crlf {
        removed.replace('\n', "\r\n")
    } else {
        removed
    })
}

/// Invert the cargo rewriter's append of a `[registries.…]` block: it wrote
/// `config + "\n" + block` (just `block` into an empty config), or
/// `config + "\n\n" + block` when the config lacked a final newline.
/// Removing the block plus the one newline before it restores the config's
/// exact bytes, a missing final newline or trailing blank lines included,
/// and anything the user appended after the block kept. An all-CRLF file is
/// inverted as LF and written back CRLF. `None` when the block is not in
/// the file.
fn remove_appended_cargo_block(content: &str, fragment: &str) -> Option<String> {
    if !content.is_empty() && content.matches('\n').count() == content.matches("\r\n").count() {
        return remove_appended_cargo_block(
            &content.replace("\r\n", "\n"),
            &fragment.replace("\r\n", "\n"),
        )
        .map(|lf| lf.replace('\n', "\r\n"));
    }
    let lf_fragment = fragment.replace("\r\n", "\n");
    let (pos, len) = match content.find(fragment) {
        Some(pos) => (pos, fragment.len()),
        None => (content.find(&lf_fragment)?, lf_fragment.len()),
    };
    let before = &content[..pos];
    let before = before
        .strip_suffix("\r\n")
        .or_else(|| before.strip_suffix('\n'))
        .unwrap_or(before);
    Some(format!("{before}{}", &content[pos + len..]))
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

    #[test]
    fn table_form_line_is_dropped() {
        assert_eq!(unpin_line(&format!("registry = \"{REG}\""), REG), Some(None));
    }

    #[test]
    fn appended_block_leaves_the_config_byte_identical() {
        let original = "[net]\ngit-fetch-with-cli = true\n";
        let hosted = format!(
            "{original}\n[registries.{REG}]\nindex = \"sparse+https://patch.socket.dev/x/index/\"\n"
        );
        assert_eq!(remove_registry_block(&hosted, REG).as_deref(), Some(original));
        let created = format!("[registries.{REG}]\nindex = \"sparse+https://x/\"\n");
        assert_eq!(remove_registry_block(&created, REG).as_deref(), Some(""));
    }
}
