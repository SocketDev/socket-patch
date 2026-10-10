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
    let removed = remove_appended_cargo_block(&lf, &fragment).or_else(|| {
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

    #[test]
    fn table_form_line_is_dropped() {
        assert_eq!(
            unpin_line(&format!("registry = \"{REG}\""), REG),
            Some(None)
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
