//! Cross-mode takeover: per-purl revert of a HOSTED redirect, driven by the
//! redirect ledger's recorded [`FileEdit`]s.
//!
//! The vendored flows (`vendor`, `scan --mode vendored`) call this BEFORE
//! vendoring a package the hosted redirect ledger still claims, so a
//! hosted→vendored migration leaves the project FULLY in vendored mode.
//!
//! Cargo: Cargo.toml loses its `registry = "socket-patch-…"` pin, Cargo.lock
//! gets its original crates.io `source`/`checksum` back (so the subsequent
//! vendor detach records the PRISTINE originals in the vendor ledger, not the
//! hosted values), and the now-unused `[registries.socket-patch-…]` block is
//! dropped. Without this, `[patch.crates-io]` cannot even apply (it only
//! patches crates-io-sourced deps) and the project is unbuildable in both
//! modes.
//!
//! npm family (package-lock/npm-shrinkwrap, yarn classic, yarn berry, pnpm,
//! bun): each recorded lock edit's `original` fragment is replayed over its
//! `new` fragment. For most flavors the follow-up vendor rewire happens to
//! succeed either way (the vendored wiring replaces whatever resolution is
//! present), but WITHOUT the pre-revert the vendor ledger records the
//! grant-tokenized hosted fragment as its unrecoverable pre-vendor
//! "original" (so `vendor --revert` restores an expiring hosted URL with no
//! CLI path back to registry state), and the superseded redirect
//! records/edits survive forever — a stale ledger that VEX/audits keep
//! reading and a replay hazard for any later redirect revert. bun is
//! stricter still: its hosted rewrite REPLACES the `name@version` spec the
//! bun vendor backend keys on (registry 4-tuple → URL 3-tuple), so without
//! the pre-revert the package cannot be vendored at all
//! (`vendor_lock_entry_not_found`).
//!
//! golang: the module's go.mod `replace` and the socket module's go.sum
//! lines are removed and the pruned upstream go.sum lines come back in
//! go's sort order, so the vendor backend wires its `replace` over the
//! pristine files instead of taking over the hosted directive.
//!
//! FAIL CLOSED: a file that matches neither the recorded redirected fragment
//! nor the recorded original has drifted — the revert refuses (`Err`) rather
//! than half-applying, and the caller must then refuse to vendor that purl.
//! Refusing has to leave the project byte-identical across ALL the files the
//! ledger claims, not just the one that drifted: the caller reports the purl
//! as untouched ("cannot vendor over the live hosted redirect"), so an
//! already-rewritten Cargo.lock behind that message would be a half-hosted
//! project nobody is told about, and every retry refuses on the same drift.
//! So each inverse is resolved against a staged view and NOTHING reaches disk
//! until all of them have resolved.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::utils::purl::{
    parse_cargo_purl, parse_golang_purl, parse_name_version, strip_purl_qualifiers,
};
use crate::vendor::go_mod_edit::{
    is_hosted_module_path, parse_replace_entries, HOSTED_GO_MODULE_PREFIX,
};

use super::staged::{flush_staged, read_rel, staged_read, Staged, StagedBytes};
use super::state::RedirectState;
use super::FileEdit;

/// What a redirect revert rewrote.
#[derive(Debug, Default)]
pub struct RedirectRevert {
    /// Repo-relative files this revert actually rewrote or removed.
    pub reverted_files: Vec<String>,
    /// Advisory (code, detail) pairs — e.g. a redirect-created `.npmrc`
    /// that was modified since (`redirect_npmrc_allow_remote_modified`).
    pub warnings: Vec<(String, String)>,
}

/// Does [`revert_redirect_purl`] have an implementation for this purl's
/// ecosystem? Callers (the vendor dispatch loop's cross-mode takeover gate)
/// must consult this instead of hardcoding `pkg:cargo/`.
pub fn redirect_revert_supported(purl: &str) -> bool {
    purl.starts_with("pkg:cargo/")
        || purl.starts_with("pkg:npm/")
        || purl.starts_with("pkg:golang/")
}

/// Revert every hosted-redirect edit the ledger records for `purl`, then
/// drop that purl's record and edits from `state`. The caller persists the
/// mutated ledger (see `persist_redirect_state`). Dispatches per ecosystem;
/// purls outside [`redirect_revert_supported`] are refused (fail closed).
///
/// `dry_run` resolves every inverse and drift check exactly like a wet run
/// and skips ONLY the disk flush: the purl's record and edits are still
/// dropped from `state`, so a composed preview (the whole-ledger replay run
/// after the per-purl reverts inside one rollback) sees the post-claim
/// ledger. Callers pass a throwaway clone and never persist it on a dry run
/// (rollback.rs / vendor.rs do). Contrast `revert_remaining_redirect_edits`,
/// whose dry run leaves its `state` untouched.
pub async fn revert_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
    dry_run: bool,
) -> Result<RedirectRevert, String> {
    if purl.starts_with("pkg:cargo/") {
        revert_cargo_redirect_purl(project_root, state, purl, dry_run).await
    } else if purl.starts_with("pkg:npm/") {
        revert_npm_redirect_purl(project_root, state, purl, dry_run).await
    } else if purl.starts_with("pkg:golang/") {
        revert_golang_redirect_purl(project_root, state, purl, dry_run).await
    } else {
        Err(format!(
            "no hosted-redirect revert implementation for {purl}"
        ))
    }
}

/// The ledger record whose canonical purl (qualifiers stripped,
/// percent-decoded) matches `purl`: `(record key as stored, canonical purl)`.
/// Refused when the ledger records no hosted redirect for the purl.
fn find_record_key(state: &RedirectState, purl: &str) -> Result<(String, String), String> {
    let Some(record_key) = state.record_keys_for(purl).into_iter().next() else {
        return Err(format!(
            "the redirect ledger records no hosted redirect for {purl}"
        ));
    };
    // The target keeps the purl's ORIGINAL (percent-encoded) spelling minus
    // its qualifiers: `parse_cargo_purl` / `parse_name_version` decode the
    // components themselves, and `canonical_purl` here would decode a second
    // time (a literal `%2B` in a name would become `+`).
    Ok((record_key, strip_purl_qualifiers(purl).to_string()))
}

/// Drop the claimed edits (by ledger index) and the purl's record from the
/// ledger — only after every inverse applied cleanly. The caller persists.
fn drop_claimed(state: &mut RedirectState, claimed: Vec<usize>, record_key: &str) {
    let drop: HashSet<usize> = claimed.into_iter().collect();
    let mut idx = 0usize;
    state.edits.retain(|_| {
        let keep = !drop.contains(&idx);
        idx += 1;
        keep
    });
    state.records.remove(record_key);
}

/// `socket-patch-<uuid>` registry names as they appear in Cargo.toml pins,
/// Cargo.lock sources and `[registries.…]` headers.
static SOCKET_REGISTRY_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"socket-patch-([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})")
        .expect("static registry-uuid regex is valid")
});

/// The `socket-patch-<uuid>` registry uuids a recorded fragment names.
fn registry_uuids(fragment: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    fragment
        .and_then(Value::as_str)
        .into_iter()
        .flat_map(|s| SOCKET_REGISTRY_UUID.captures_iter(s))
        .map(|c| c[1].to_string())
}

/// A Cargo.lock edit (keyed `<name>@<version>`): the entry / `[metadata]`
/// fragments, or the dependents' full-id reference.
fn is_cargo_lock_edit(e: &FileEdit) -> bool {
    e.kind == "redirect_cargo_lock_entry" || e.kind == super::CARGO_LOCK_REFERENCE_KIND
}

/// Every patch uuid `name@version` was redirected at: its record's, plus
/// each managed registry whose index URL one of its (version-keyed)
/// Cargo.lock edits names — the older links of a re-redirect chain.
fn cargo_lineage(state: &RedirectState, name: &str, version: &str, uuid: &str) -> HashSet<String> {
    let lock_key = format!("{name}@{version}");
    let lock_fragments: Vec<&str> = state
        .edits
        .iter()
        .filter(|e| is_cargo_lock_edit(e) && e.key.as_deref() == Some(lock_key.as_str()))
        .flat_map(|e| [e.original.as_ref(), e.new.as_ref()])
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut lineage: HashSet<String> = HashSet::from([uuid.to_string()]);
    for e in state
        .edits
        .iter()
        .filter(|e| e.kind == "redirect_cargo_registry")
    {
        let Some(u) = e
            .key
            .as_deref()
            .and_then(|k| k.strip_prefix("socket-patch-"))
        else {
            continue;
        };
        let index = e
            .new
            .as_ref()
            .and_then(Value::as_str)
            .and_then(|block| block.split('"').nth(1));
        if index.is_some_and(|index| lock_fragments.iter().any(|f| f.contains(index))) {
            lineage.insert(u.to_string());
        }
    }
    lineage
}

/// Revert every hosted-redirect edit the ledger records for `purl` (a cargo
/// package), then drop that purl's record and edits from `state`. The caller
/// persists the mutated ledger (see `persist_redirect_state`).
///
/// Chained re-redirects (the same purl redirected at successive patch uuids)
/// unwind newest-first: each edit's `new` fragment is replaced by its
/// `original`, and an intermediate edit whose `original` is already live is a
/// no-op. `[registries.socket-patch-…]` blocks tied to this purl's uuids are
/// removed only when nothing in Cargo.toml / Cargo.lock still references them.
/// `dry_run` skips only the disk flush; the in-memory ledger claim still
/// happens (see [`revert_redirect_purl`]).
pub async fn revert_cargo_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
    dry_run: bool,
) -> Result<RedirectRevert, String> {
    let (record_key, target) = find_record_key(state, purl)?;
    let Some((name, version)) = parse_cargo_purl(&target) else {
        return Err(format!("not a cargo purl: {purl}"));
    };
    let (name, version) = (name.into_owned(), version.into_owned());
    let lock_key = format!("{name}@{version}");

    // Manifest edits are keyed by crate NAME (the shared golden ledger
    // shape), so when another version of the crate is redirected too, its
    // pins carry the same key: skip every manifest edit whose pin names a
    // registry of a sibling version's lineage. Without a sibling the claim
    // stays name-wide, as before.
    let sibling_uuids: HashSet<String> = state
        .records
        .iter()
        .filter(|(key, _)| **key != record_key)
        .filter_map(|(key, rec)| {
            let (n, v) = parse_cargo_purl(strip_purl_qualifiers(key))?;
            (n == name && v != version).then(|| cargo_lineage(state, &n, &v, &rec.uuid))
        })
        .flatten()
        .collect();
    let is_wiring_edit = |e: &FileEdit| {
        (e.kind == "redirect_cargo_toml_dep"
            && e.key.as_deref() == Some(name.as_str())
            && !registry_uuids(e.new.as_ref()).any(|u| sibling_uuids.contains(&u)))
            || (is_cargo_lock_edit(e) && e.key.as_deref() == Some(lock_key.as_str()))
    };
    // Registry blocks tie to this purl via the `socket-patch-<uuid>` names in
    // its record + wiring edits (a patch uuid is per purl, so this cannot
    // claim another package's block).
    let mut uuids: HashSet<String> = HashSet::new();
    uuids.insert(state.records[&record_key].uuid.clone());
    for e in state.edits.iter().filter(|e| is_wiring_edit(e)) {
        for v in [&e.original, &e.new] {
            if let Some(s) = v.as_ref().and_then(Value::as_str) {
                for c in SOCKET_REGISTRY_UUID.captures_iter(s) {
                    uuids.insert(c[1].to_string());
                }
            }
        }
    }
    let is_registry_edit = |e: &FileEdit| {
        e.kind == "redirect_cargo_registry"
            && e.key
                .as_deref()
                .and_then(|k| k.strip_prefix("socket-patch-"))
                .is_some_and(|u| uuids.contains(u))
    };

    let mine: Vec<usize> = state
        .edits
        .iter()
        .enumerate()
        .filter(|(_, e)| is_wiring_edit(e) || is_registry_edit(e))
        .map(|(i, _)| i)
        .collect();

    // Every manifest the ledger ever pinned (workspace members included),
    // plus the lock: where a registry block can still be referenced from.
    let mut probes: Vec<String> = vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()];
    for e in state
        .edits
        .iter()
        .filter(|e| e.kind == "redirect_cargo_toml_dep")
    {
        if !probes.contains(&e.path) {
            probes.push(e.path.clone());
        }
    }

    let mut out = RedirectRevert::default();
    let mut staged: Staged = Staged::new();
    // Newest-first: the hosted flow appends edits, so reverse index order
    // unwinds re-redirect chains correctly (each step's `original` is the
    // previous step's `new`), and the registry-block removals — recorded
    // before their wiring edits — run last, after the references are gone.
    for &i in mine.iter().rev() {
        let edit = &state.edits[i];
        match edit.kind.as_str() {
            "redirect_cargo_toml_dep"
            | "redirect_cargo_lock_entry"
            | super::CARGO_LOCK_REFERENCE_KIND => {
                let (Some(new), Some(orig)) = (
                    edit.new.as_ref().and_then(Value::as_str),
                    edit.original.as_ref().and_then(Value::as_str),
                ) else {
                    return Err(format!(
                        "the redirect ledger edit for {} in {} records no original \
                         fragment; cannot revert the hosted redirect",
                        name, edit.path
                    ));
                };
                let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                    return Err(format!(
                        "{} no longer exists; cannot revert the recorded hosted \
                         redirect for {name}@{version}",
                        edit.path
                    ));
                };
                if content.contains(new) {
                    // A full-id reference edit stands for every dependent's
                    // occurrence of that exact id.
                    let reverted = if edit.kind == super::CARGO_LOCK_REFERENCE_KIND {
                        content.replace(new, orig)
                    } else {
                        content.replacen(new, orig, 1)
                    };
                    staged.insert(edit.path.clone(), Some(reverted));
                    out.reverted_files.push(edit.path.clone());
                } else if content.contains(orig) {
                    // Already at (or unwound to) the pre-redirect fragment.
                } else {
                    return Err(format!(
                        "the {} entry for {name}@{version} has drifted from the \
                         recorded hosted redirect (neither the redirected nor the \
                         original fragment is present); refusing to touch it — \
                         re-run `scan --mode hosted` to normalize the redirect, \
                         or restore the crates.io wiring manually, then re-run",
                        edit.path
                    ));
                }
            }
            "redirect_cargo_registry" => {
                let Some(block) = edit.new.as_ref().and_then(Value::as_str) else {
                    continue; // nothing recorded to remove — leave the config
                };
                let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                    continue; // config already gone
                };
                if !content.contains(block) {
                    continue; // block already removed
                }
                // Keep the block while anything still references its registry
                // name or index URL (defensive — a hand-edited project may
                // have pinned another dep to it).
                let reg = edit.key.as_deref().unwrap_or_default();
                let index = block
                    .split('"')
                    .nth(1)
                    .map(str::to_string)
                    .unwrap_or_default();
                let mut referenced = false;
                for probe in &probes {
                    if let Some(text) = staged_read(&staged, project_root, probe).await? {
                        if (!reg.is_empty() && text.contains(reg))
                            || (!index.is_empty() && text.contains(&index))
                        {
                            referenced = true;
                            break;
                        }
                    }
                }
                if referenced {
                    continue;
                }
                // A REGENERATED block (`action: "rewritten"` — the rewriter
                // replaced a degraded/commented region in place and recorded
                // it as `original`) restores that pre-existing region instead
                // of deleting it: the original bytes are the user's.
                if let Some(orig) = edit.original.as_ref().and_then(Value::as_str) {
                    let reverted = content.replacen(block, orig, 1);
                    staged.insert(edit.path.clone(), Some(reverted));
                    out.reverted_files.push(edit.path.clone());
                    continue;
                }
                // The block leaves with exactly the blank separator the
                // rewrite put before it, so the user's config comes back
                // byte-for-byte — its trailing newlines (or missing final
                // newline) included. A config the rewrite created ends
                // empty and is deleted.
                let Some(restored) = super::replay::remove_appended_cargo_block(&content, block)
                else {
                    continue;
                };
                staged.insert(
                    edit.path.clone(),
                    (!restored.is_empty()).then_some(restored),
                );
                out.reverted_files.push(edit.path.clone());
            }
            _ => {}
        }
    }

    // Every inverse resolved — only now does any of it reach disk, so a
    // refusal above left the project exactly as it was found. A dry run
    // skips ONLY the disk flush: the in-memory ledger mutation below still
    // happens, so composed previews (the whole-ledger replay running after
    // the per-purl reverts inside one rollback) see exactly the state a
    // wet run would hand them. The caller owns the state clone and never
    // persists it on a dry run, so nothing durable changes.
    if !dry_run {
        flush_staged(project_root, &staged, &StagedBytes::new()).await?;
    }

    drop_claimed(state, mine, &record_key);
    Ok(out)
}

/// Revert one Go module's hosted redirect: its go.mod `replace`, the
/// socket module's go.sum lines, and the pruned upstream go.sum pair, then
/// drop its record and edits from `state`. The claimed edits unwind through
/// the whole-ledger replay's golang inverses, staged all-or-nothing. A
/// go.mod whose directive for the module is no longer the recorded one has
/// drifted and refuses byte-untouched.
pub async fn revert_golang_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
    dry_run: bool,
) -> Result<RedirectRevert, String> {
    let (record_key, target) = find_record_key(state, purl)?;
    let Some((module, version)) = parse_golang_purl(&target) else {
        return Err(format!("not a golang purl: {purl}"));
    };
    let (module, version) = (module.into_owned(), version.into_owned());
    let lhs = format!("{module} {version} =>");
    let is_replace_edit = |e: &FileEdit| {
        matches!(
            e.kind.as_str(),
            "redirect_golang_replace" | "redirect_golang_stale_replace_removed"
        ) && e.key.as_deref() == Some(module.as_str())
            && [&e.new, &e.original].iter().any(|v| {
                v.as_ref()
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.contains(&lhs))
            })
    };
    // The socket modules this purl's directives pointed at: go.sum edits
    // key by those, never by the upstream module.
    let mut socket_modules: HashSet<String> = HashSet::new();
    socket_modules.insert(format!(
        "{HOSTED_GO_MODULE_PREFIX}{}",
        state.records[&record_key].uuid
    ));
    for e in state.edits.iter().filter(|e| is_replace_edit(e)) {
        for text in [&e.new, &e.original]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            for entry in parse_replace_entries(text) {
                if let Some(rhs) = entry.rhs_module.filter(|m| is_hosted_module_path(m)) {
                    socket_modules.insert(rhs);
                }
            }
        }
    }
    let prune_key = format!("{module}@{version}");
    let mine: Vec<usize> = state
        .edits
        .iter()
        .enumerate()
        .filter(|(_, e)| match e.kind.as_str() {
            "redirect_golang_replace" | "redirect_golang_stale_replace_removed" => {
                is_replace_edit(e)
            }
            "redirect_golang_gosum_prune" => e.key.as_deref() == Some(prune_key.as_str()),
            "redirect_golang_gosum" => e
                .key
                .as_deref()
                .and_then(|k| k.rsplit_once('@'))
                .is_some_and(|(m, _)| socket_modules.contains(m)),
            "redirect_golang_stale_gosum_removed" => {
                e.key.as_deref().is_some_and(|k| socket_modules.contains(k))
            }
            _ => false,
        })
        .map(|(i, _)| i)
        .collect();

    // Drift: the newest recorded directive must still be live, or the
    // module must carry no replace at all (already unwound).
    let newest = mine
        .iter()
        .rev()
        .map(|&i| &state.edits[i])
        .find(|e| e.kind == "redirect_golang_replace");
    if let Some(directive) = newest.and_then(|e| e.new.as_ref()).and_then(Value::as_str) {
        let go_mod = read_rel(project_root, "go.mod").await?.unwrap_or_default();
        if !go_mod.contains(directive)
            && parse_replace_entries(&go_mod)
                .iter()
                .any(|e| e.module == module)
        {
            return Err(format!(
                "go.mod's replace for {module} has drifted from the recorded hosted \
                 redirect; refusing to touch it — re-run `scan --mode hosted` to \
                 normalize the redirect, or remove the replace manually, then re-run"
            ));
        }
    }

    let mut claimed = RedirectState::new();
    claimed.edits = mine.iter().map(|&i| state.edits[i].clone()).collect();
    claimed
        .records
        .insert(record_key.clone(), state.records[&record_key].clone());
    let replay =
        super::replay::revert_remaining_redirect_edits(project_root, &mut claimed, dry_run).await;
    if let Some(refusal) = replay.refusals.first() {
        return Err(refusal.reason.clone());
    }
    drop_claimed(state, mine, &record_key);
    Ok(RedirectRevert {
        reverted_files: replay.reverted_files.into_iter().collect(),
        warnings: replay.warnings,
    })
}

/// The npm-family text-fragment edit kinds CLAIMED BY KEY: `original`/`new`
/// hold the whole lock fragment as a string, the edit's `key` embeds
/// `<name>@<version>`, and the revert is a `replacen(new, original)`.
const NPM_TEXT_KINDS: [&str; 3] = [
    "redirect_yarn_classic_entry",
    "redirect_yarn_berry_entry",
    "redirect_pnpm_resolution",
];

/// The bun hosted rewriter's edit kind (`rewrite_bun_lock`): `original`/`new`
/// hold the whole `packages` entry LINE, so it replays exactly like the
/// [`NPM_TEXT_KINDS`]. It is CLAIMED differently: bun edits key by the
/// lock's package map key — `minimist`, a nested `other/minimist`, or the
/// alias of an `alias@npm:minimist@1.2.2` install — never by
/// `name@version`, so ownership is read from the recorded line's spec
/// (`elems[0]`), the field the rewriter itself matched on.
const BUN_TEXT_KIND: &str = "redirect_bun_lock_package";

/// Does this edit kind replay as a whole text fragment
/// (`content.replacen(new, original, 1)`, fail-closed on drift)?
fn replays_as_text_fragment(kind: &str) -> bool {
    NPM_TEXT_KINDS.contains(&kind) || kind == BUN_TEXT_KIND
}

/// Ownership verdict for one [`BUN_TEXT_KIND`] edit.
#[derive(Debug, PartialEq)]
enum BunClaim {
    /// The edit rewrote an instance of exactly this `name@version`.
    Ours,
    /// Another package, or another version of this one (a nested
    /// `other/minimist` instance at 1.2.8 while reverting 1.2.2): not ours
    /// to touch, and no reason to refuse.
    Foreign,
    /// The recorded fragments mention this package but neither one parses
    /// under bun's entry grammar (hand-edited or truncated ledger), so
    /// ownership cannot be decided. Deciding "foreign" would drop this
    /// purl's record while stranding an edit that may be its own — half a
    /// takeover — so the caller refuses.
    Undecidable,
}

/// Attribute a bun.lock edit to `name@version` the way the hosted rewriter
/// matched it: by the spec of the recorded line.
///
/// A registry 4-tuple's spec is exactly `<name>@<version>`; a hosted URL
/// 3-tuple's spec is `<name>@<artifact url>`. Either fragment may be the
/// hosted URL (a re-redirect chain records `original` = the PRIOR hosted
/// line, `new` = the current one), so both are consulted and one match
/// claims. The URL half is discriminated by version through its tarball
/// leaf — see [`hosted_url_names`] — never by the name substring alone,
/// which would claim a sibling version's edit and silently un-host it.
fn bun_edit_ownership(edit: &FileEdit, name: &str, version: &str) -> BunClaim {
    use crate::vendor::bun_lock_text::{decode_json_string, parse_entry_line};
    fn fragment(v: &Option<Value>) -> Option<&str> {
        v.as_ref().and_then(Value::as_str)
    }
    let spec_of = |line: &str| -> Option<String> {
        let entry = parse_entry_line(line).ok()?;
        decode_json_string(entry.elems.first()?)
    };
    let mut parsed_any = false;
    for line in [fragment(&edit.original), fragment(&edit.new)]
        .into_iter()
        .flatten()
    {
        if let Some(spec) = spec_of(line) {
            parsed_any = true;
            if bun_spec_names(&spec, name, version) {
                return BunClaim::Ours;
            }
        }
    }
    if parsed_any {
        return BunClaim::Foreign;
    }
    // Neither fragment is a bun entry line. Only refuse when the raw text
    // so much as mentions this package; an edit naming nothing of ours is
    // someone else's problem and must not block this purl's takeover.
    let probe = format!("\"{name}@");
    let mentions = |v: &Option<Value>| fragment(v).is_some_and(|s| s.contains(&probe));
    if mentions(&edit.original) || mentions(&edit.new) {
        BunClaim::Undecidable
    } else {
        BunClaim::Foreign
    }
}

/// Is `spec` (a bun.lock entry's decoded `elems[0]`) the registry spec
/// `<name>@<version>` or a hosted artifact URL spec for that exact
/// `name@version`?
fn bun_spec_names(spec: &str, name: &str, version: &str) -> bool {
    use crate::vendor::bun_lock_text::split_name_spec;
    let Some((spec_name, rest)) = split_name_spec(spec) else {
        return false;
    };
    spec_name == name && (rest == version || hosted_url_names(rest, name, version))
}

/// True when `url` is an http(s) artifact URL whose last path segment is
/// `<bare>-<version>.tgz` — the leaf every hosted artifact URL for this
/// `name@version` ends in. `<bare>` is the name without its `@scope/`: the
/// vendor path layer (`tgz_rel_leaf`) keeps a scope as a directory level
/// (`@scope/pkg-1.0.0.tgz`), and the hosted rewriter's prior-URL match
/// (`is_prior_hosted_bun_spec`) compares the same last path segment, so
/// `pkg-1.0.0.tgz` is the one spelling both agree on. Anything that fails
/// to parse fails the match (closed). The exact-leaf comparison is the
/// version discriminator: `pkg-1.3.0.tgz` never equals `pkg-11.3.0.tgz`
/// or `pkg-1.3.0-rc1.tgz`.
pub(crate) fn hosted_url_names(url: &str, name: &str, version: &str) -> bool {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return false;
    }
    let scheme_end = url
        .find("://")
        .expect("url starts with http(s):// — checked above")
        + 3;
    let Some(path_start) = url[scheme_end..].find('/').map(|i| i + scheme_end) else {
        return false;
    };
    let leaf = url[path_start..].rsplit('/').next().unwrap_or_default();
    let bare = name.rsplit('/').next().unwrap_or(name);
    !leaf.is_empty() && leaf == format!("{bare}-{version}.tgz")
}

/// The version a hosted artifact `url` names for `name`: its last path
/// segment is `<bare>-<version>.tgz` with a semver `<version>`, confirmed by
/// [`hosted_url_names`]. How a hosted bun binary redirect's version is
/// recovered (`bun_binary::names`) and how lockfile discovery reads a bun
/// hosted ref's version.
pub(crate) fn hosted_url_version<'u>(url: &'u str, name: &str) -> Option<&'u str> {
    let bare = name.rsplit('/').next().unwrap_or(name);
    let version = url
        .rsplit('/')
        .next()?
        .strip_prefix(bare)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")?;
    (semver::Version::parse(version).is_ok() && hosted_url_names(url, name, version))
        .then_some(version)
}

/// Revert every hosted-redirect edit the ledger records for `purl` (an npm
/// package), then drop that purl's record and edits from `state`. The caller
/// persists the mutated ledger (see `persist_redirect_state`).
///
/// Same fail-closed contract as [`revert_cargo_redirect_purl`]: every inverse
/// is resolved against a staged view and NOTHING reaches disk until all of
/// them have resolved, so a drift refusal leaves the project byte-identical
/// across ALL the files the ledger claims. `dry_run` skips only the disk
/// flush; the in-memory ledger claim still happens (see
/// [`revert_redirect_purl`]).
pub async fn revert_npm_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
    dry_run: bool,
) -> Result<RedirectRevert, String> {
    let (record_key, target) = find_record_key(state, purl)?;
    // The parse percent-decodes both components; the name keeps its `@scope/`.
    let Some((name, version)) = parse_name_version(&target, "pkg:npm/") else {
        return Err(format!("not an npm purl: {purl}"));
    };
    let (name, version) = (name.into_owned(), version.into_owned());
    let lock_key = format!("{name}@{version}");

    // The package-lock/shrinkwrap files any `redirect_npm_lock_entry` edits
    // touch, read ONCE from disk: the raw text is kept (`disk_texts`) so the
    // replay below never re-reads a lock this attribution pass already
    // loaded, and the parse is used for ownership — an ALIAS install (`npm i
    // alias@npm:name`) keys its entry by the alias, so ownership is resolved
    // through the entry's `name` field, exactly how the rewriter matched it
    // (the rewrite never touches name/version, so the probe is symmetric).
    let mut disk_texts: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut disk_locks: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for e in &state.edits {
        if e.kind == "redirect_npm_lock_entry" && !disk_texts.contains_key(&e.path) {
            let text = read_rel(project_root, &e.path).await?;
            let parsed = text
                .as_deref()
                .and_then(|c| serde_json::from_str::<Value>(c).ok());
            disk_texts.insert(e.path.clone(), text);
            disk_locks.insert(e.path.clone(), parsed);
        }
    }

    // Claim this purl's edits. The berry/classic rewriters key edits by
    // `<name>@<version>`; the pnpm rewriter keys by the canonical INSTANCE
    // key — `<name>@<version>` for a plain instance, but one edit per
    // resolved-peer instance keyed `<name>@<version>(<peer>@<ver>)…` (v6) or
    // `<name>@<version>_<peer-suffix>` (v5) — so pnpm claims accept a `(`/`_`
    // peer boundary after the exact version (never `-`/`.`/alnum, which
    // would extend the version into a sibling's, e.g. 1.3.0 vs 1.3.0-rc1).
    // The legacy npm v2 `dependencies` tree keys by bare name; the v3
    // `packages` map keys by the lock path. The package-lock JSON kinds carry no version in their
    // key, so ownership is version-discriminated the way the rewriter
    // matched (entry `name`+`version`, mod.rs) — name-only would claim a
    // SIBLING purl's edits (left-pad@1.2.0 vs @1.3.0 both hosted-redirected,
    // or `npm i name@npm:other` aliasing another package onto this key path)
    // and replaying those silently un-hosts the other purl while dropping
    // its edits. bun edits key by the lock's package MAP key (`minimist`,
    // nested `other/minimist`, an install alias) — never `name@version` —
    // so they are attributed by the spec of the recorded line, the field
    // the rewriter matched on (`bun_edit_ownership`); a sibling version's
    // line is foreign, and a fragment that mentions the package but cannot
    // be parsed at all refuses rather than guess (dropping the record while
    // stranding a possibly-own edit would be half a takeover).
    let mut mine: Vec<usize> = Vec::new();
    for (i, e) in state.edits.iter().enumerate() {
        let key = e.key.as_deref().unwrap_or_default();
        let claimed = match e.kind.as_str() {
            k if NPM_TEXT_KINDS.contains(&k) => {
                key == lock_key
                    || (k == "redirect_pnpm_resolution"
                        && key
                            .strip_prefix(lock_key.as_str())
                            .is_some_and(|peer| peer.starts_with('(') || peer.starts_with('_')))
            }
            "redirect_npm_lock_dep" => key == name && edit_references_version(e, &version),
            "redirect_npm_lock_entry" => {
                let key_name = key
                    .rsplit_once("node_modules/")
                    .map(|(_, n)| n)
                    .unwrap_or(key);
                match disk_locks
                    .get(&e.path)
                    .and_then(|l| l.as_ref())
                    .and_then(|l| l.get("packages"))
                    .and_then(|p| p.get(key))
                {
                    // The entry is live: attribute it exactly the way the
                    // rewriter matched it — effective name (the `name` field
                    // npm writes for alias installs, else the key's trailing
                    // path; the rewrite never touches either, so the probe
                    // is symmetric) AND version.
                    Some(entry) => {
                        let entry_name = entry
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or(key_name);
                        entry_name == name
                            && match entry.get("version").and_then(Value::as_str) {
                                Some(v) => v == version,
                                // Version field gone (hand-edited lock): fall
                                // back to the recorded URLs, which must name
                                // this exact package AND version — version
                                // alone would claim a same-version alias
                                // collision (`npm i <name>@npm:other`, name
                                // field stripped too) whose live values ARE
                                // its edit's `new` values, so the replay
                                // would NOT fail closed and the sibling would
                                // be silently un-hosted.
                                None => edit_references_package(e, &name, &version),
                            }
                    }
                    // Entry (or the whole lock) gone: keep the fail-closed
                    // "no longer exists" refusal for edits attributable to
                    // this purl — by key path + recorded URLs, or (an alias
                    // install OF this package keys its entry by the ALIAS,
                    // so the key path exonerates nothing) by recorded URLs
                    // naming this exact package. Leaving the alias edit
                    // unclaimed would drop the record while stranding it —
                    // half a takeover. A sibling purl's edit is still not
                    // ours to claim.
                    None => {
                        (key_name == name && edit_references_version(e, &version))
                            || edit_references_package(e, &name, &version)
                    }
                }
            }
            super::bun_binary::KIND => super::bun_binary::names(e, &name, &version)?,
            BUN_TEXT_KIND => match bun_edit_ownership(e, &name, &version) {
                BunClaim::Ours => true,
                BunClaim::Foreign => false,
                // The WORKING remedy is the whole-ledger replay: a plain
                // `bun install` keeps a hosted URL tuple byte-identically
                // (it re-locks nothing), and hand-editing the ledger is
                // exactly what the hosted flow tells users never to do.
                BunClaim::Undecidable => {
                    return Err(format!(
                        "the redirect ledger records a {} hosted redirect edit \
                         that mentions {name} but is not a bun packages entry \
                         line, so it cannot be attributed to {lock_key}; run an \
                         unscoped `socket-patch rollback` (the whole-ledger \
                         replay unwinds bun.lock hosted edits), then re-run; do \
                         not edit .socket/vendor/redirect-state.json by hand",
                        e.path
                    ));
                }
            },
            _ => false,
        };
        if claimed {
            mine.push(i);
        }
    }

    let mut out = RedirectRevert::default();
    let mut staged: Staged = Staged::new();
    let mut staged_bytes: StagedBytes = StagedBytes::new();
    // Newest-first: the hosted flow appends edits, so reverse index order
    // unwinds re-redirect chains correctly (each step's `original` is the
    // previous step's `new`).
    for &i in mine.iter().rev() {
        let edit = &state.edits[i];
        if edit.kind == super::bun_binary::KIND {
            if edit.path != "bun.lockb" {
                return Err("unexpected binary lock edit path".into());
            }
            let path = project_root.join("bun.lockb");
            let content = match staged_bytes.remove(&edit.path) {
                Some(pending) => pending,
                None => {
                    let metadata = tokio::fs::symlink_metadata(&path)
                        .await
                        .map_err(|e| format!("cannot inspect bun.lockb: {e}"))?;
                    if !metadata.is_file() {
                        return Err("bun.lockb is not a regular file".into());
                    }
                    crate::utils::fs::read_regular_to_bytes(&path)
                        .await
                        .map_err(|e| format!("cannot read bun.lockb: {e}"))?
                }
            };
            staged_bytes.insert(
                edit.path.clone(),
                super::bun_binary::restore(&content, edit)?,
            );
            if !out.reverted_files.iter().any(|p| p == "bun.lockb") {
                out.reverted_files.push("bun.lockb".into());
            }
        } else if replays_as_text_fragment(&edit.kind) {
            // Whole-fragment replay. For bun the fragments are whole lines
            // (a CRLF lock's carry their trailing `\r`), so a
            // `contains`/`replacen` on the raw content restores the line
            // byte-exactly whatever the line ending.
            let (Some(new), Some(orig)) = (
                edit.new.as_ref().and_then(Value::as_str),
                edit.original.as_ref().and_then(Value::as_str),
            ) else {
                return Err(format!(
                    "the redirect ledger edit for {name} in {} records no \
                     original fragment; cannot revert the hosted redirect",
                    edit.path
                ));
            };
            let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                return Err(format!(
                    "{} no longer exists; cannot revert the recorded hosted \
                     redirect for {lock_key}",
                    edit.path
                ));
            };
            // A yarn block recorded on a CRLF checkout, replayed on an LF
            // one (or the reverse — `core.autocrlf` re-spells the lock on
            // every OS switch, never the committed ledger): when neither
            // fragment matches verbatim, try both in the file's ending.
            let respelled = (super::yarn_lock_fragment_kind(&edit.kind)
                && !content.contains(new)
                && !content.contains(orig))
            .then(|| crate::utils::line_endings::fragments_in_eol_of(&content, orig, new))
            .flatten();
            let (orig, new) = match &respelled {
                Some((orig, new)) => (orig.as_str(), new.as_str()),
                None => (orig, new),
            };
            if content.contains(new) {
                staged.insert(edit.path.clone(), Some(content.replacen(new, orig, 1)));
                out.reverted_files.push(edit.path.clone());
            } else if content.contains(orig) {
                // Already at (or unwound to) the pre-redirect fragment.
            } else {
                // bun only: Bun 1.1.39–1.3.9 re-save our URL 3-tuple WITHOUT
                // its sha512 on any later lock re-save, so the recorded
                // `new` is on disk as a digest-less 2-tuple (same key, spec
                // and meta). That spelling IS the recorded wiring — restore
                // `orig` over it; a stale ledger of its own making must not
                // block the takeover, scoped rollback or remove. Anything
                // else still refuses (fail closed).
                let healed = if edit.kind == BUN_TEXT_KIND {
                    crate::vendor::bun_lock_text::restore_digestless_line(&content, new, orig)
                        .map_err(|ambiguous| format!("{}: {ambiguous}", edit.path))?
                } else {
                    None
                };
                match healed {
                    Some(restored) => {
                        staged.insert(edit.path.clone(), Some(restored));
                        out.reverted_files.push(edit.path.clone());
                    }
                    None => {
                        return Err(format!(
                            "the {} entry for {lock_key} has drifted from the recorded \
                             hosted redirect (neither the redirected nor the original \
                             fragment is present); refusing to touch it — re-run \
                             `scan --mode hosted` to normalize the redirect, or \
                             restore the registry wiring manually, then re-run",
                            edit.path
                        ));
                    }
                }
            }
        } else {
            revert_npm_json_edit(
                project_root,
                &mut staged,
                &disk_texts,
                edit,
                &name,
                &version,
                &mut out,
            )
            .await?;
        }
    }

    // LAST ONE OUT: the `.npmrc` `allow-remote=all` auto-config exists only
    // for package-lock / shrinkwrap hosted entries (npm >= 12 refuses them
    // without it). When this purl's revert leaves no such entry in the
    // ledger, unwind the recorded `.npmrc` edit(s) in the SAME transaction —
    // scoped rollback / remove of the last npm purl and the vendored
    // takeover then leave no loosened install policy behind. An ambiguous
    // `.npmrc` refuses the whole revert (nothing written), like any drift.
    let mut npmrc_staged: Option<Option<String>> = None;
    {
        let dropping: HashSet<usize> = mine.iter().copied().collect();
        // Checked BEFORE the read: the read refuses a symlinked / non-regular
        // `.npmrc` here, at plan time — so the whole revert refuses with
        // nothing written (flush_npmrc refusing it after flush_staged had
        // already written the lock would strand a reverted lock behind a
        // ledger that still records the redirect) — but only when the
        // unwind is actually due.
        if super::npmrc::npmrc_unwind_due(&state.edits, &dropping) {
            let current = super::npmrc::read_project_npmrc(project_root)?;
            if let Some(plan) =
                super::npmrc::plan_unneeded_npmrc_unwind(&state.edits, &dropping, current)?
            {
                if plan.staged.is_some() {
                    out.reverted_files.push(super::npmrc::NPMRC_REL.to_string());
                }
                npmrc_staged = plan.staged;
                out.warnings.extend(plan.warnings);
                mine.extend(plan.indices);
            }
        }
    }

    // Every inverse resolved — only now does any of it reach disk, so a
    // refusal above left the project exactly as it was found. A dry run
    // skips ONLY the disk flush: the in-memory ledger mutation below still
    // happens, so composed previews (the whole-ledger replay running after
    // the per-purl reverts inside one rollback) see exactly the state a
    // wet run would hand them. The caller owns the state clone and never
    // persists it on a dry run, so nothing durable changes.
    if !dry_run {
        flush_staged(project_root, &staged, &staged_bytes).await?;
        // After the lock: an I/O fault here leaves the (reverted) lock plus
        // a still-present `allow-remote=all` — never a hosted lock entry
        // whose `.npmrc` setting was already taken away.
        if let Some(npmrc) = &npmrc_staged {
            super::npmrc::flush_npmrc(project_root, npmrc).await?;
        }
    }

    drop_claimed(state, mine, &record_key);
    Ok(out)
}

/// Does one of this edit's recorded `resolved` URLs reference `version`?
///
/// Version discriminator for the package-lock JSON edit kinds, whose keys
/// carry no version (`redirect_npm_lock_dep` keys by bare name,
/// `redirect_npm_lock_entry` by lock path): both the hosted artifact URL
/// (`…/npm/<name>/<version>/…/<name>-<version>.tgz`) and the registry
/// tarball URL (`…/-/<name>-<version>.tgz`) embed the version behind a
/// `/<version>/` or `-<version>.tgz` delimiter, so sibling versions of the
/// same package never
/// match each other (`/1.3.0/` is not a substring of `/11.3.0/`, nor
/// `-1.3.0.tgz` of `-11.3.0.tgz`). Checked against `new` and `original` so
/// every link of a re-redirect chain (each hosted URL names this purl's
/// version) attributes correctly. A false positive here is safe — the
/// replay itself fails closed on any value mismatch — while name-only
/// claiming silently un-hosts the sibling purl.
fn edit_references_version(edit: &FileEdit, version: &str) -> bool {
    let path_seg = format!("/{version}/");
    let tarball = format!("-{version}.tgz");
    [&edit.new, &edit.original].into_iter().any(|v| {
        v.as_ref()
            .and_then(|o| o.get("resolved"))
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains(&path_seg) || s.contains(&tarball))
    })
}

/// Does one of this edit's recorded `resolved` URLs reference BOTH `name`
/// and `version`?
///
/// Name-discriminated twin of [`edit_references_version`], for the claims
/// where the lock key path cannot vouch for the name (an alias install keys
/// its entry by the alias, and `npm i <name>@npm:other` keys ANOTHER package
/// by this name's path). The probes are the two URL shapes whole, not
/// independent name/version substrings: the hosted artifact URL embeds the
/// name and version as adjacent path segments
/// (`…/npm/<name>/<version>/…/<bare>-<version>.tgz`) and the registry
/// tarball URL as `…/<name>/-/<bare>-<version>.tgz` — where a scoped name's
/// `@scope/` prefix is dropped from the BASENAME only, never from the path.
/// A match for an UNSCOPED name whose preceding path segment is a scope
/// (`…/@scope/<name>/…` — the slash closing `@scope` starts the probe) is
/// rejected: it is a scoped sibling's URL, whose path and basename would
/// otherwise satisfy independent substring probes at an identical version.
/// So a sibling purl of a different name — bare or scoped — never matches
/// even at an identical version.
fn edit_references_package(edit: &FileEdit, name: &str, version: &str) -> bool {
    let bare = name.rsplit('/').next().unwrap_or(name);
    let hosted = format!("/{name}/{version}/");
    let registry = format!("/{name}/-/{bare}-{version}.tgz");
    let scoped_sibling = |s: &str, at: usize| {
        !name.starts_with('@')
            && s[..at]
                .rsplit('/')
                .next()
                .is_some_and(|seg| seg.starts_with('@'))
    };
    let references = |s: &str| {
        [&hosted, &registry].into_iter().any(|probe| {
            let mut from = 0;
            while let Some(pos) = s[from..].find(probe.as_str()) {
                let at = from + pos;
                if !scoped_sibling(s, at) {
                    return true;
                }
                from = at + 1;
            }
            false
        })
    };
    [&edit.new, &edit.original].into_iter().any(|v| {
        v.as_ref()
            .and_then(|o| o.get("resolved"))
            .and_then(Value::as_str)
            .is_some_and(references)
    })
}

/// Replay one recorded package-lock JSON edit (`redirect_npm_lock_entry` /
/// `redirect_npm_lock_dep`) through the staged view. `disk_texts` is the
/// attribution pass's read of the lock (`None` = missing on disk), consulted
/// before touching the disk again; `staged` still wins over both.
async fn revert_npm_json_edit(
    project_root: &Path,
    staged: &mut Staged,
    disk_texts: &BTreeMap<String, Option<String>>,
    edit: &FileEdit,
    name: &str,
    version: &str,
    out: &mut RedirectRevert,
) -> Result<(), String> {
    let content = match (staged.get(&edit.path), disk_texts.get(&edit.path)) {
        (Some(pending), _) => pending.clone(),
        (None, Some(on_disk)) => on_disk.clone(),
        (None, None) => read_rel(project_root, &edit.path).await?,
    };
    let Some(content) = content else {
        return Err(format!(
            "{} no longer exists; cannot revert the recorded hosted redirect \
             for {name}@{version}",
            edit.path
        ));
    };
    let mut lock: Value = serde_json::from_str(&content).map_err(|e| {
        format!(
            "{} is not valid JSON ({e}); cannot revert the recorded hosted \
             redirect for {name}@{version}",
            edit.path
        )
    })?;
    let key = edit.key.as_deref().unwrap_or_default();
    let changed = match edit.kind.as_str() {
        "redirect_npm_lock_entry" => {
            let Some(entry) = lock.get_mut("packages").and_then(|p| p.get_mut(key)) else {
                return Err(format!(
                    "the {} entry `{key}` for {name}@{version} no longer \
                     exists; cannot revert the recorded hosted redirect",
                    edit.path
                ));
            };
            replay_resolved_integrity(entry, edit, &edit.path, key)?
        }
        "redirect_npm_lock_dep" => {
            let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) else {
                return Err(format!(
                    "{} no longer holds a `dependencies` tree; cannot revert \
                     the recorded hosted redirect for {name}@{version}",
                    edit.path
                ));
            };
            let mut any_found = false;
            let mut changed = false;
            revert_v2_deps(
                deps,
                name,
                version,
                edit,
                &edit.path,
                &mut any_found,
                &mut changed,
            )?;
            if !any_found {
                return Err(format!(
                    "the {} `dependencies` entry for {name}@{version} no \
                     longer exists; cannot revert the recorded hosted redirect",
                    edit.path
                ));
            }
            changed
        }
        other => {
            return Err(format!(
                "no revert implementation for redirect edit kind `{other}`"
            ));
        }
    };
    if changed {
        staged.insert(edit.path.clone(), Some(super::serialize_json(&lock)));
        out.reverted_files.push(edit.path.clone());
    }
    Ok(())
}

/// Replace an entry's `resolved`/`integrity` with the edit's recorded
/// originals. `Ok(false)` when the entry already holds the originals;
/// `Err` (drift, fail closed) when it holds neither the recorded redirected
/// values nor the originals.
fn replay_resolved_integrity(
    entry: &mut Value,
    edit: &FileEdit,
    path: &str,
    key: &str,
) -> Result<bool, String> {
    let field = |v: &Option<Value>, f: &str| -> Value {
        v.as_ref()
            .and_then(|o| o.get(f))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let orig_res = field(&edit.original, "resolved");
    let orig_int = field(&edit.original, "integrity");
    let cur = |f: &str| entry.get(f).cloned().unwrap_or(Value::Null);
    if cur("resolved") == orig_res && cur("integrity") == orig_int {
        return Ok(false); // already at (or unwound to) the pre-redirect values
    }
    if cur("resolved") != field(&edit.new, "resolved")
        || cur("integrity") != field(&edit.new, "integrity")
    {
        return Err(format!(
            "the {path} entry `{key}` has drifted from the recorded hosted \
             redirect (neither the redirected nor the original \
             resolved/integrity is present); refusing to touch it — re-run \
             `scan --mode hosted` to normalize the redirect, or restore the \
             registry wiring manually, then re-run"
        ));
    }
    let Some(obj) = entry.as_object_mut() else {
        return Err(format!("the {path} entry `{key}` is not an object"));
    };
    for (f, orig) in [("resolved", orig_res), ("integrity", orig_int)] {
        if orig.is_null() {
            obj.remove(f);
        } else {
            obj.insert(f.to_string(), orig);
        }
    }
    Ok(true)
}

/// Recursive twin of the rewriter's `rewrite_npm_v2_deps` walk: replay the
/// edit's originals over every legacy `dependencies` node for this
/// name+version. Bundled nodes mirror the rewriter's skip — they were never
/// rewritten, so their registry-shaped (or absent) values must not read as
/// drift.
fn revert_v2_deps(
    deps: &mut serde_json::Map<String, Value>,
    name: &str,
    version: &str,
    edit: &FileEdit,
    path: &str,
    any_found: &mut bool,
    changed: &mut bool,
) -> Result<(), String> {
    for (dep_name, entry) in deps.iter_mut() {
        if dep_name == name
            && entry.get("version").and_then(Value::as_str) == Some(version)
            && entry.get("bundled").and_then(Value::as_bool) != Some(true)
        {
            *any_found = true;
            if replay_resolved_integrity(entry, edit, path, dep_name)? {
                *changed = true;
            }
        }
        if let Some(nested) = entry.get_mut("dependencies").and_then(Value::as_object_mut) {
            revert_v2_deps(nested, name, version, edit, path, any_found, changed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchRecord;
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    const UUID: &str = "6b7c8d9e-0f1a-4a1b-8c2d-3e4f5a6b7c8d";
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const INDEX: &str = "sparse+http://127.0.0.1:5555/index/";
    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn record() -> PatchRecord {
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn pristine_toml() -> String {
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1.0\"\n"
            .to_string()
    }

    fn pristine_lock_block() -> String {
        format!(
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{}\"",
            "9".repeat(64)
        )
    }

    /// Run the real hosted rewriter over a pristine project, write its output
    /// to a tempdir, and return the resulting ledger — the exact state the
    /// takeover revert consumes in production.
    async fn redirected_fixture() -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lock = format!(
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n{}\n",
            pristine_lock_block()
        );
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), pristine_toml());
        files.insert("Cargo.lock".into(), lock.clone());
        let dep: crate::patch::redirect::DepOverride = serde_json::from_value(serde_json::json!({
            "ecosystem": "cargo",
            "name": "cfg-if",
            "version": "1.0.4",
            "token": "tok",
            "patchUuid": UUID,
            "artifactUrl": format!("http://127.0.0.1:5555/cfg-if-1.0.4.crate"),
            "registryOverride": {
                "kind": "cargo-sparse",
                "indexUrl": INDEX,
                "identifiers": {
                    "name": "cfg-if", "version": "1.0.4",
                    "cargoCksumSha256": "a".repeat(64),
                },
            },
            "integrity": { "sha256": "a".repeat(64) },
        }))
        .unwrap();
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[dep]);
        tokio::fs::write(root.join("Cargo.toml"), &pristine_toml())
            .await
            .unwrap();
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        for (rel, content) in &rewrite.files {
            let path = root.join(rel);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.unwrap();
            }
            tokio::fs::write(&path, content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(PURL.to_string(), record());
        (tmp, state)
    }

    /// Bug I: two redirected versions of one crate share the manifest edit
    /// key (the crate name). Removing one version must revert ONLY its own
    /// declaration + lock entry + registry block — claiming the sibling's
    /// manifest edit reverted the other pin while its lock entry stayed
    /// hosted (a broken build), and dropped the sibling's registry edit, so
    /// the second removal left the created `.cargo/config.toml` behind.
    #[tokio::test]
    async fn multi_version_removes_each_version_independently() {
        const UUID_OLD: &str = "3c5d7e9f-2a4b-4c6d-8e0f-1a3b5c7d9e1f";
        const PURL_OLD: &str = "pkg:cargo/cfg-if@0.1.10";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let toml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                    cfg-if = \"1.0\"\ncfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n";
        let lock = format!(
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n\
             source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n\n{}\n",
            "8".repeat(64),
            pristine_lock_block()
        );
        let dep = |version: &str, uuid: &str| -> crate::patch::redirect::DepOverride {
            serde_json::from_value(serde_json::json!({
                "ecosystem": "cargo", "name": "cfg-if", "version": version, "token": "tok",
                "patchUuid": uuid,
                "artifactUrl": format!("http://127.0.0.1:5555/cfg-if-{version}.crate"),
                "registryOverride": {
                    "kind": "cargo-sparse",
                    "indexUrl": format!("sparse+http://127.0.0.1:5555/{uuid}/index/"),
                    "identifiers": {
                        "name": "cfg-if", "version": version,
                        "cargoCksumSha256": "a".repeat(64),
                    },
                },
                "integrity": { "sha256": "a".repeat(64) },
            }))
            .unwrap()
        };
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), toml.to_string());
        files.insert("Cargo.lock".into(), lock.clone());
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(
            &files,
            &[dep("1.0.4", UUID), dep("0.1.10", UUID_OLD)],
        );
        assert_eq!(
            rewrite.confirmed_cargo_uuids.len(),
            2,
            "{:?}",
            rewrite.warnings
        );
        tokio::fs::write(root.join("Cargo.toml"), toml)
            .await
            .unwrap();
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        for (rel, content) in &rewrite.files {
            let path = root.join(rel);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&path, content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(PURL.to_string(), record());
        let mut old = record();
        old.uuid = UUID_OLD.to_string();
        state.records.insert(PURL_OLD.to_string(), old);

        revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("1.0.4 reverts");
        let t = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(
            t.contains("cfg-if = \"1.0\"\n")
                && t.contains(&format!("registry = \"socket-patch-{UUID_OLD}\"")),
            "only the 1.0.4 pin is reverted: {t}"
        );
        let l = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            l.contains(&format!("sparse+http://127.0.0.1:5555/{UUID_OLD}/index/")),
            "{l}"
        );
        let cfg = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(
            !cfg.contains(&format!("socket-patch-{UUID}]")) && cfg.contains(UUID_OLD),
            "{cfg}"
        );

        revert_cargo_redirect_purl(root, &mut state, PURL_OLD, false)
            .await
            .expect("0.1.10 reverts");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            toml
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock
        );
        assert!(
            !root.join(".cargo/config.toml").exists(),
            "the created config goes with the last block"
        );
        assert!(
            state.edits.is_empty() && state.records.is_empty(),
            "{:?}",
            state.edits
        );
    }

    /// A hosted override for `name@version` at patch `uuid`.
    fn cargo_dep(name: &str, version: &str, uuid: &str) -> crate::patch::redirect::DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "cargo", "name": name, "version": version, "token": "tok",
            "patchUuid": uuid,
            "artifactUrl": format!("http://127.0.0.1:5555/{name}-{version}.crate"),
            "registryOverride": {
                "kind": "cargo-sparse",
                "indexUrl": format!("sparse+http://127.0.0.1:5555/{uuid}/index/"),
                "identifiers": {
                    "name": name, "version": version,
                    "cargoCksumSha256": "a".repeat(64),
                },
            },
            "integrity": { "sha256": "a".repeat(64) },
        }))
        .unwrap()
    }

    /// Redirect `deps` (applied in order) over a pristine project with the
    /// real rewriter, write the output to a tempdir, and return the ledger
    /// with one record per purl.
    async fn redirect_on_disk(
        toml: &str,
        lock: &str,
        deps: &[(&str, &str, &str)],
    ) -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), toml.to_string());
        files.insert("Cargo.lock".into(), lock.to_string());
        let overrides: Vec<_> = deps
            .iter()
            .map(|(name, version, uuid)| cargo_dep(name, version, uuid))
            .collect();
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &overrides);
        assert_eq!(
            rewrite.confirmed_cargo_uuids.len(),
            deps.len(),
            "{:?}",
            rewrite.warnings
        );
        for (rel, content) in files.iter().chain(rewrite.files.iter()) {
            let path = root.join(rel);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&path, content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        for (name, version, uuid) in deps {
            let mut rec = record();
            rec.uuid = uuid.to_string();
            state
                .records
                .insert(format!("pkg:cargo/{name}@{version}"), rec);
        }
        (tmp, state)
    }

    /// Redirect `deps`, then remove the purls in EVERY order: each order
    /// must succeed and restore the manifest and lock byte-for-byte, with no
    /// config and no ledger left.
    async fn assert_removes_in_every_order(toml: &str, lock: &str, deps: &[(&str, &str, &str)]) {
        let purls: Vec<String> = deps
            .iter()
            .map(|(name, version, _)| format!("pkg:cargo/{name}@{version}"))
            .collect();
        for order in [purls.clone(), purls.iter().rev().cloned().collect()] {
            let (tmp, mut state) = redirect_on_disk(toml, lock, deps).await;
            let root = tmp.path();
            for purl in &order {
                revert_cargo_redirect_purl(root, &mut state, purl, false)
                    .await
                    .unwrap_or_else(|e| panic!("remove {purl} (order {order:?}): {e}"));
            }
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.toml"))
                    .await
                    .unwrap(),
                toml,
                "{order:?}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.lock"))
                    .await
                    .unwrap(),
                lock,
                "{order:?}"
            );
            assert!(!root.join(".cargo/config.toml").exists(), "{order:?}");
            assert!(
                state.edits.is_empty() && state.records.is_empty(),
                "{order:?}: {:?}",
                state.edits
            );
        }
    }

    /// A v1 lock names every dependency by its full id, so the root block
    /// references BOTH patched cfg-if versions. REGRESSION: each dependent
    /// block was one whole-block edit, the second version's edit recorded
    /// the first one's output as its `original`, and removing the
    /// first-applied version alone found neither fragment — `remove`
    /// refused as drifted unless purls went in exact reverse apply order.
    #[tokio::test]
    async fn v1_lock_multi_version_removes_in_any_order() {
        const UUID_OLD: &str = "3c5d7e9f-2a4b-4c6d-8e0f-1a3b5c7d9e1f";
        let toml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                    cfg-if = \"1.0\"\ncfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n";
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 0.1.10 ({CRATES_IO})\",\n \"cfg-if 1.0.4 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum cfg-if 0.1.10 ({CRATES_IO})\" = \"{}\"\n\
             \"checksum cfg-if 1.0.4 ({CRATES_IO})\" = \"{}\"\n",
            "8".repeat(64),
            "9".repeat(64)
        );
        assert_removes_in_every_order(
            toml,
            &lock,
            &[("cfg-if", "1.0.4", UUID), ("cfg-if", "0.1.10", UUID_OLD)],
        )
        .await;
    }

    /// The whole-ledger replay (rollback) inverts a v1 full-id reference
    /// named by several dependents at every occurrence.
    #[tokio::test]
    async fn v1_lock_reference_named_by_several_dependents_replays_clean() {
        let toml = "[workspace]\nmembers = [\"a\", \"b\"]\n\n\
                    [workspace.dependencies]\ncfg-if = \"1.0\"\n";
        let member = |name: &str| {
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n\
                 [dependencies]\ncfg-if = {{ workspace = true }}\n"
            )
        };
        let lock = format!(
            "[[package]]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"b\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({CRATES_IO})\" = \"{}\"\n",
            "9".repeat(64)
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), toml.to_string());
        files.insert("Cargo.lock".into(), lock.clone());
        files.insert("a/Cargo.toml".into(), member("a"));
        files.insert("b/Cargo.toml".into(), member("b"));
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(
            &files,
            &[cargo_dep("cfg-if", "1.0.4", UUID)],
        );
        assert_eq!(
            rewrite.confirmed_cargo_uuids.len(),
            1,
            "{:?}",
            rewrite.warnings
        );
        let references: Vec<&FileEdit> = rewrite
            .edits
            .iter()
            .filter(|e| e.kind == super::super::CARGO_LOCK_REFERENCE_KIND)
            .collect();
        assert_eq!(
            references.len(),
            1,
            "one edit per full id: {:?}",
            rewrite.edits
        );
        for (rel, content) in files.iter().chain(rewrite.files.iter()) {
            let path = root.join(rel);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&path, content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(PURL.to_string(), record());
        let outcome =
            crate::patch::redirect::revert_remaining_redirect_edits(root, &mut state, false).await;
        assert!(outcome.fully_reverted(), "{:?}", outcome.refusals);
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            toml
        );
    }

    /// Two different patched crates with one shared v1 dependent block.
    #[tokio::test]
    async fn v1_lock_two_crates_sharing_a_dependent_remove_in_any_order() {
        const UUID_ITOA: &str = "4d6e8f0a-3b5c-4d7e-9f1a-2b4c6d8e0f2a";
        let toml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                    cfg-if = \"1.0\"\nitoa = \"1.0.11\"\n";
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({CRATES_IO})\",\n \"itoa 1.0.11 ({CRATES_IO})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CRATES_IO}\"\n\n\
             [[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\nsource = \"{CRATES_IO}\"\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({CRATES_IO})\" = \"{}\"\n\
             \"checksum itoa 1.0.11 ({CRATES_IO})\" = \"{}\"\n",
            "8".repeat(64),
            "9".repeat(64)
        );
        assert_removes_in_every_order(
            toml,
            &lock,
            &[("cfg-if", "1.0.4", UUID), ("itoa", "1.0.11", UUID_ITOA)],
        )
        .await;
    }

    #[tokio::test]
    async fn reverts_toml_lock_and_registry_block_and_drops_ledger_entries() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // Sanity: the fixture really is hosted-wired.
        let toml = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(toml.contains("socket-patch-"), "{toml}");

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        assert!(!out.reverted_files.is_empty());

        let toml = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert_eq!(toml, pristine_toml(), "Cargo.toml restored byte-identical");
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            lock.contains(CRATES_IO),
            "crates.io source restored: {lock}"
        );
        assert!(!lock.contains("sparse+"), "hosted index gone: {lock}");
        assert!(
            !root.join(".cargo/config.toml").exists(),
            "socket-only config removed"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn preserves_user_config_content_when_removing_the_registry_block() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // Prepend user content to the config the rewrite created.
        let cfg_path = root.join(".cargo/config.toml");
        let cfg = tokio::fs::read_to_string(&cfg_path).await.unwrap();
        tokio::fs::write(&cfg_path, format!("[net]\nretry = 2\n{cfg}"))
            .await
            .unwrap();

        revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        let cfg = tokio::fs::read_to_string(&cfg_path).await.unwrap();
        assert!(cfg.contains("[net]"), "user content kept: {cfg}");
        assert!(!cfg.contains("socket-patch-"), "block removed: {cfg}");
    }

    #[tokio::test]
    async fn refuses_on_drifted_lock_fail_closed() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // A third party re-resolved the lock to a shape the ledger never saw.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"registry+https://corp.example/index\"\n",
        )
        .await
        .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect_err("drifted lock must refuse");
        assert!(err.contains("drifted"), "{err}");
        // The ledger keeps everything on refusal.
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// The unwind runs newest-first (edits are recorded config, manifest,
    /// lock), so Cargo.lock's inverse resolves BEFORE Cargo.toml's. Drifting
    /// only Cargo.toml therefore refuses at a point where the lock's inverse
    /// has already been decided — and the caller reports the purl as
    /// untouched ("cannot vendor over the live hosted redirect"), so a
    /// revert that had written the lock by then would leave the project
    /// half-hosted behind a message saying nothing happened.
    #[tokio::test]
    async fn a_later_drifted_edit_leaves_every_earlier_file_untouched() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let drifted_toml =
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = { version = \"1.0\", registry = \"corp-mirror\" }\n";
        tokio::fs::write(root.join("Cargo.toml"), drifted_toml)
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let cfg_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(
            lock_before.contains("sparse+"),
            "fixture is hosted-wired: {lock_before}"
        );

        let err = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect_err("drifted manifest must refuse");
        assert!(err.contains("drifted"), "{err}");

        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "Cargo.lock must be untouched — its inverse resolved before the refusal"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            drifted_toml,
            "Cargo.toml untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg_before,
            ".cargo/config.toml untouched"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert!(!state.edits.is_empty(), "ledger keeps the edits");
    }

    #[tokio::test]
    async fn missing_record_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_cargo_redirect_purl(tmp.path(), &mut state, PURL, false)
            .await
            .expect_err("no record");
        assert!(err.contains("records no hosted redirect"), "{err}");
    }

    #[tokio::test]
    async fn dry_run_previews_the_wet_summary_without_touching_disk_or_ledger() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let toml_before = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let cfg_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let dry = revert_cargo_redirect_purl(root, &mut state, PURL, true)
            .await
            .expect("dry-run revert succeeds");

        // Nothing reached disk and the ledger still claims everything.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            toml_before,
            "Cargo.toml untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "Cargo.lock untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg_before,
            ".cargo/config.toml untouched"
        );
        // The IN-MEMORY ledger is claimed exactly like a wet run (composed
        // previews — the whole-ledger replay running after per-purl
        // reverts — must see the post-claim state); the caller owns the
        // clone and never persists it on a dry run.
        assert!(
            state.records.len() < records_before,
            "record claimed in memory"
        );
        assert!(state.edits.len() < edits_before, "edits claimed in memory");

        // The preview names exactly the files a wet run then reverts —
        // re-run wet on a FRESH state clone of the same fixture.
        let (tmp2, mut state2) = redirected_fixture().await;
        let root = tmp2.path();
        let wet = revert_cargo_redirect_purl(root, &mut state2, PURL, false)
            .await
            .expect("wet revert succeeds");
        assert_eq!(dry.reverted_files, wet.reverted_files);
    }

    #[tokio::test]
    async fn dry_run_still_fail_closes_on_drift() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // Same drift as the wet refusal above: a third party re-resolved the
        // lock to a shape the ledger never saw.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"registry+https://corp.example/index\"\n",
        )
        .await
        .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_cargo_redirect_purl(root, &mut state, PURL, true)
            .await
            .expect_err("drifted lock must refuse on a dry run too");
        assert!(err.contains("drifted"), "{err}");
        // The ledger keeps everything on refusal.
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    // ── npm family ───────────────────────────────────────────────────────

    const NPM_PURL: &str = "pkg:npm/left-pad@1.3.0";
    const NPM_URL: &str =
        "http://127.0.0.1:5555/patch/npm/left-pad/1.3.0/tok/6b7c/left-pad-1.3.0.tgz";

    fn npm_dep_for(name: &str, version: &str) -> crate::patch::redirect::DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "token": "tok",
            "patchUuid": UUID,
            "artifactUrl": format!(
                "http://127.0.0.1:5555/patch/npm/{name}/{version}/tok/6b7c/{name}-{version}.tgz"
            ),
            "integrity": {
                "sha512": format!("sha512-{}==", "B".repeat(86)),
                "sha1": "1".repeat(40),
                "yarnBerry10c0": format!("10c0/{}", "b".repeat(128)),
            },
        }))
        .unwrap()
    }

    fn npm_dep() -> crate::patch::redirect::DepOverride {
        npm_dep_for("left-pad", "1.3.0")
    }

    /// Run the real hosted rewriter over one pristine lock (redirecting every
    /// purl in `deps`), write its output to a tempdir, and return the
    /// resulting ledger — the exact state the takeover revert consumes in
    /// production.
    async fn npm_redirected_fixture_multi(
        rel: &str,
        pristine: &str,
        deps: &[(&str, crate::patch::redirect::DepOverride)],
    ) -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert(rel.to_string(), pristine.to_string());
        let overrides: Vec<_> = deps.iter().map(|(_, d)| d.clone()).collect();
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &overrides);
        let rewritten = rewrite
            .files
            .get(rel)
            .unwrap_or_else(|| panic!("rewriter must rewrite {rel}: {:?}", rewrite.warnings));
        tokio::fs::write(root.join(rel), rewritten).await.unwrap();
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        for (purl, _) in deps {
            state.records.insert(purl.to_string(), record());
        }
        (tmp, state)
    }

    /// Run the real hosted rewriter over one pristine lock, write its output
    /// to a tempdir, and return the resulting ledger — the exact state the
    /// takeover revert consumes in production.
    async fn npm_redirected_fixture(
        rel: &str,
        pristine: &str,
    ) -> (tempfile::TempDir, RedirectState) {
        npm_redirected_fixture_multi(rel, pristine, &[(NPM_PURL, npm_dep())]).await
    }

    fn classic_pristine() -> String {
        "# yarn lockfile v1\n\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \
         \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a\"\n  \
         integrity sha512-original==\n"
            .to_string()
    }

    // ---------- shared staging guards (twins of the replay's) ----------

    /// A FIFO planted at a lockfile the ledger claims refuses fast (`read
    /// <rel>: … not a regular file`) instead of wedging the takeover in a
    /// blocking open; the ledger is untouched for a retry.
    #[cfg(unix)]
    #[tokio::test]
    async fn npm_fifo_squatting_the_lock_refuses_instead_of_wedging() {
        use std::os::unix::ffi::OsStrExt;
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let path = root.join("yarn.lock");
        tokio::fs::remove_file(&path).await.unwrap();
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o644) }, 0);
        let edits_before = state.edits.len();
        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("a FIFO must refuse");
        assert!(
            err.starts_with("read yarn.lock:") && err.contains("not a regular file"),
            "{err}"
        );
        assert_eq!(state.edits.len(), edits_before, "ledger untouched");
        assert!(state.records.contains_key(NPM_PURL), "record kept");
    }

    /// A symlinked lockfile reads fine (the opener follows it) but refuses
    /// at flush: a rename-over would replace the link with a detached
    /// regular file. Nothing is written and the ledger is untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn npm_symlinked_lock_reads_fine_but_refuses_at_flush() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let redirected = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        tokio::fs::rename(root.join("yarn.lock"), root.join("real.lock"))
            .await
            .unwrap();
        std::os::unix::fs::symlink(root.join("real.lock"), root.join("yarn.lock")).unwrap();
        let edits_before = state.edits.len();
        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("a symlinked lock must refuse");
        assert_eq!(err, "yarn.lock is not a regular file");
        assert_eq!(
            tokio::fs::read_to_string(root.join("real.lock"))
                .await
                .unwrap(),
            redirected,
            "the symlink target must stay byte-identical"
        );
        assert!(
            std::fs::symlink_metadata(root.join("yarn.lock"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link itself must survive"
        );
        assert_eq!(state.edits.len(), edits_before, "ledger untouched");
        assert!(state.records.contains_key(NPM_PURL), "record kept");
    }

    /// The text flush is the mode-preserving atomic writer: a `0600` lock
    /// keeps its bits through the takeover revert.
    #[cfg(unix)]
    #[tokio::test]
    async fn npm_text_lock_revert_keeps_the_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let path = root.join("yarn.lock");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            classic_pristine()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the lockfile's mode must survive the atomic rewrite"
        );
    }

    fn berry_pristine() -> String {
        "# This file is generated by running \"yarn install\" inside your project.\n\n\
         __metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
         \"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
         checksum: 10c0/cccc\n  languageName: node\n  linkType: hard\n"
            .to_string()
    }

    /// Pristine package-lock (lockfileVersion 2: BOTH the v3 `packages` map
    /// and the legacy v2 `dependencies` tree), serialized exactly as the
    /// rewriter serializes, so the revert round-trip is byte-comparable.
    fn package_lock_pristine() -> String {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                }
            },
            "dependencies": {
                "left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                }
            }
        });
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap())
    }

    #[test]
    fn revert_supported_gate_covers_cargo_and_npm_only() {
        assert!(redirect_revert_supported("pkg:cargo/cfg-if@1.0.4"));
        assert!(redirect_revert_supported("pkg:npm/left-pad@1.3.0"));
        assert!(redirect_revert_supported("pkg:npm/%40scope/x@1.0.0"));
        assert!(!redirect_revert_supported("pkg:gem/rack@3.0.0"));
        assert!(!redirect_revert_supported("pkg:pypi/flask@2.0.0"));
    }

    #[tokio::test]
    async fn npm_classic_lock_round_trips_and_drops_ledger_entries() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        assert!(wired.contains(NPM_URL), "fixture is hosted-wired: {wired}");

        let out = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(out.reverted_files, vec!["yarn.lock".to_string()]);
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            classic_pristine(),
            "yarn.lock restored byte-identical"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn npm_berry_lock_round_trips_and_drops_ledger_entries() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &berry_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        assert!(
            wired.contains("::__archiveUrl="),
            "fixture is hosted-wired: {wired}"
        );

        revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            berry_pristine(),
            "yarn.lock restored byte-identical"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// A CRLF (and BOM'd) berry lock — yarn's own output on Windows —
    /// round-trips through the takeover byte-exactly: the rewriter records
    /// the CRLF fragments, the revert replays them. Across checkouts too: a
    /// ledger written on a CRLF checkout reverts an LF checkout of the same
    /// commit and vice versa (`core.autocrlf` re-spells the lock, never the
    /// committed ledger), landing on the pristine lock in the LIVE file's
    /// endings. A lock whose endings are mixed proves nothing: it refuses
    /// as drift, byte-untouched, ledger intact.
    #[tokio::test]
    async fn npm_berry_crlf_lock_round_trips_across_checkouts() {
        let respell = |text: &str, crlf: bool| {
            let lf = text.replace("\r\n", "\n");
            if crlf {
                lf.replace('\n', "\r\n")
            } else {
                lf
            }
        };
        for (label, bom, recorded_crlf, live_crlf) in [
            ("crlf", "", true, true),
            ("bom+crlf", "\u{feff}", true, true),
            ("recorded crlf, reverted lf", "", true, false),
            ("recorded lf, reverted crlf", "\u{feff}", false, true),
        ] {
            let pristine = format!("{bom}{}", respell(&berry_pristine(), recorded_crlf));
            let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &pristine).await;
            let root = tmp.path();
            let edit = state
                .edits
                .iter()
                .find(|e| e.kind == "redirect_yarn_berry_entry")
                .expect("berry edit");
            let recorded = edit.original.as_ref().and_then(Value::as_str).unwrap();
            assert_eq!(
                recorded.contains("\r\n"),
                recorded_crlf,
                "{label}: the ledger records the on-disk endings: {recorded:?}"
            );
            let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap();
            tokio::fs::write(root.join("yarn.lock"), respell(&wired, live_crlf))
                .await
                .unwrap();

            revert_redirect_purl(root, &mut state, NPM_PURL, false)
                .await
                .unwrap_or_else(|e| panic!("{label}: revert must succeed: {e}"));
            assert_eq!(
                tokio::fs::read_to_string(root.join("yarn.lock"))
                    .await
                    .unwrap(),
                format!("{bom}{}", respell(&berry_pristine(), live_crlf)),
                "{label}: the pristine lock, in the live file's endings"
            );
            assert!(state.edits.is_empty(), "{label}: edits dropped");
        }

        // Mixed live endings: neither the verbatim nor a respelled fragment
        // is provable — refuse, touch nothing, keep the ledger.
        let pristine = respell(&berry_pristine(), true);
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &pristine).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        let mixed = wired.replacen("  languageName: node\r\n", "  languageName: node\n", 1);
        assert_ne!(mixed, wired, "the fixture edit must hit");
        tokio::fs::write(root.join("yarn.lock"), &mixed)
            .await
            .unwrap();
        let edits_before = state.edits.len();
        let err = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("a mixed lock must refuse");
        assert!(err.contains("drifted"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            mixed,
            "byte-untouched"
        );
        assert_eq!(state.edits.len(), edits_before, "ledger intact");
    }

    #[tokio::test]
    async fn npm_package_lock_v2_round_trips_both_trees() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "packages + dependencies edits");
        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(wired.contains(NPM_URL), "fixture is hosted-wired: {wired}");

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            package_lock_pristine(),
            "package-lock.json restored byte-identical (both trees)"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    fn npmrc_edit(action: &str) -> FileEdit {
        FileEdit {
            path: ".npmrc".into(),
            kind: super::super::npmrc::NPMRC_ALLOW_REMOTE_EDIT_KIND.into(),
            action: action.into(),
            key: Some("allow-remote".into()),
            original: None,
            new: Some(serde_json::json!("all")),
        }
    }

    /// Pristine lockfileVersion 3 package-lock holding two registry deps.
    fn two_dep_package_lock() -> String {
        let entry = |name: &str, version: &str| {
            serde_json::json!({
                "version": version,
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                "integrity": "sha512-pristine=="
            })
        };
        let lock = serde_json::json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": entry("left-pad", "1.3.0"),
                "node_modules/other": entry("other", "2.0.0"),
            }
        });
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap())
    }

    /// The `.npmrc` `allow-remote=all` auto-config is unwound in the SAME
    /// transaction as the LAST package-lock purl's revert (created file
    /// deleted), and never while another package-lock entry still needs it.
    #[tokio::test]
    async fn npm_revert_unwinds_npmrc_only_when_the_last_lock_entry_goes() {
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &two_dep_package_lock(),
            &[
                (NPM_PURL, npm_dep()),
                ("pkg:npm/other@2.0.0", npm_dep_for("other", "2.0.0")),
            ],
        )
        .await;
        let root = tmp.path();
        tokio::fs::write(root.join(".npmrc"), "allow-remote=all\n")
            .await
            .unwrap();
        state.edits.push(npmrc_edit("created"));

        // The last-but-one lock entry goes: .npmrc stays.
        let out = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("first revert");
        assert!(!out.reverted_files.iter().any(|f| f == ".npmrc"), "{out:?}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(".npmrc"))
                .await
                .unwrap(),
            "allow-remote=all\n",
            "still needed by the other package-lock entry"
        );
        assert!(state
            .edits
            .iter()
            .any(|e| e.kind == "redirect_npmrc_allow_remote"));

        // Dry run of the last one: previews the removal, writes nothing.
        let mut probe = state.clone();
        let out = revert_npm_redirect_purl(root, &mut probe, "pkg:npm/other@2.0.0", true)
            .await
            .expect("dry-run revert");
        assert!(out.reverted_files.iter().any(|f| f == ".npmrc"), "{out:?}");
        assert!(root.join(".npmrc").exists(), "dry run writes nothing");

        let out = revert_npm_redirect_purl(root, &mut state, "pkg:npm/other@2.0.0", false)
            .await
            .expect("last revert");
        assert!(out.reverted_files.iter().any(|f| f == ".npmrc"), "{out:?}");
        assert!(
            !root.join(".npmrc").exists(),
            "the created .npmrc is deleted"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            two_dep_package_lock()
        );
        assert!(
            state.edits.is_empty() && state.records.is_empty(),
            "{state:?}"
        );
    }

    /// An APPENDED line is removed exactly (user bytes, BOM and CRLF kept);
    /// an ambiguous duplicate refuses the whole revert byte-untouched.
    #[tokio::test]
    async fn npm_revert_removes_only_the_appended_npmrc_line() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        state.edits.push(npmrc_edit("added"));

        tokio::fs::write(
            root.join(".npmrc"),
            "allow-remote=all\r\n; mine\r\nallow-remote=all\r\n",
        )
        .await
        .unwrap();
        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("ambiguous .npmrc refuses");
        assert!(err.contains("more than once"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            wired,
            "a refusal leaves the lock untouched"
        );

        tokio::fs::write(
            root.join(".npmrc"),
            "\u{feff}registry=https://r.example/\r\nallow-remote=all\r\n",
        )
        .await
        .unwrap();
        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join(".npmrc"))
                .await
                .unwrap(),
            "\u{feff}registry=https://r.example/\r\n"
        );
        assert!(state.edits.is_empty(), "{state:?}");
    }

    /// Finding: a symlinked `.npmrc` passed planning (the read followed
    /// the link), `flush_staged` wrote the reverted lock, and only then did
    /// `flush_npmrc` refuse the link — leaving the lock un-hosted while the
    /// ledger still recorded the redirect. The refusal now happens while
    /// planning: lock byte-identical, ledger untouched. While another
    /// package-lock entry still needs the setting, the odd `.npmrc` shape
    /// does not block the revert at all (the file is never read).
    #[cfg(unix)]
    #[tokio::test]
    async fn npm_revert_refuses_a_symlinked_npmrc_before_writing_anything() {
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &two_dep_package_lock(),
            &[
                (NPM_PURL, npm_dep()),
                ("pkg:npm/other@2.0.0", npm_dep_for("other", "2.0.0")),
            ],
        )
        .await;
        let root = tmp.path();
        tokio::fs::write(root.join("shared.npmrc"), "allow-remote=all\n")
            .await
            .unwrap();
        std::os::unix::fs::symlink("shared.npmrc", root.join(".npmrc")).unwrap();
        state.edits.push(npmrc_edit("created"));

        // Not the last lock entry: the unwind is not due, the link is fine.
        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("first revert is not blocked by the .npmrc shape");

        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        let before = state.clone();
        let err = revert_npm_redirect_purl(root, &mut state, "pkg:npm/other@2.0.0", false)
            .await
            .expect_err("symlinked .npmrc refuses the last revert");
        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            wired,
            "the lock must not be reverted behind the refusal"
        );
        assert_eq!(state.edits.len(), before.edits.len(), "ledger untouched");
        assert_eq!(
            state.records.len(),
            before.records.len(),
            "ledger untouched"
        );
        assert!(root
            .join(".npmrc")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Pristine pnpm v6 lock holding a PLAIN instance and a resolved-peer
    /// instance of the same purl: the rewriter records one edit per
    /// instance, keying the peered one `<name>@<version>(<peer>@<ver>)`.
    fn pnpm_v6_pristine() -> String {
        [
            "lockfileVersion: '6.0'",
            "",
            "dependencies:",
            "  left-pad:",
            "    specifier: 1.3.0",
            "    version: 1.3.0",
            "",
            "packages:",
            "",
            "  /left-pad@1.3.0:",
            "    resolution: {integrity: sha512-pristine==}",
            "    dev: false",
            "",
            "  /left-pad@1.3.0(react@18.2.0):",
            "    resolution: {integrity: sha512-pristine==}",
            "    dev: false",
            "",
        ]
        .join("\n")
    }

    /// Pristine pnpm v5 lock: same two-instance shape, `/name/version` keys
    /// with the peer combination spelled as a `_<suffix>` (respelled
    /// `<name>@<version>_<suffix>` in the recorded instance key).
    fn pnpm_v5_pristine() -> String {
        [
            "lockfileVersion: 5.4",
            "",
            "specifiers:",
            "  left-pad: 1.3.0",
            "",
            "dependencies:",
            "  left-pad: 1.3.0",
            "",
            "packages:",
            "",
            "  /left-pad/1.3.0:",
            "    resolution: {integrity: sha512-pristine==}",
            "    dev: false",
            "",
            "  /left-pad/1.3.0_react@18.2.0:",
            "    resolution: {integrity: sha512-pristine==}",
            "    dev: false",
            "",
        ]
        .join("\n")
    }

    /// The pnpm rewriter keys a resolved-peer instance's edit
    /// `<name>@<version>(<peer>@<ver>)`, not bare `<name>@<version>` — the
    /// takeover claim must cover it. A missed instance is a silent HALF
    /// takeover: the plain entry reverts, the record is dropped, the peered
    /// edit is stranded in the ledger, and every dependent resolving through
    /// the peered instance keeps installing the expiring hosted tarball.
    #[tokio::test]
    async fn npm_pnpm_v6_peered_instance_takeover_reverts_every_instance() {
        let (tmp, mut state) = npm_redirected_fixture("pnpm-lock.yaml", &pnpm_v6_pristine()).await;
        let root = tmp.path();
        assert_eq!(
            state.edits.len(),
            2,
            "plain + peered instance edits: {:?}",
            state.edits
        );
        let wired = tokio::fs::read_to_string(root.join("pnpm-lock.yaml"))
            .await
            .unwrap();
        assert_eq!(
            wired.matches(NPM_URL).count(),
            2,
            "both instances hosted-wired: {wired}"
        );

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("pnpm-lock.yaml"))
                .await
                .unwrap(),
            pnpm_v6_pristine(),
            "pnpm-lock.yaml restored byte-identical (both instances)"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(
            state.edits.is_empty(),
            "no stranded instance edits: {:?}",
            state.edits
        );
    }

    /// v5 twin of the peered-instance claim: the `_<peer-suffix>` instance
    /// key (`left-pad@1.3.0_react@18.2.0`) must be claimed too.
    #[tokio::test]
    async fn npm_pnpm_v5_suffixed_instance_takeover_reverts_every_instance() {
        let (tmp, mut state) = npm_redirected_fixture("pnpm-lock.yaml", &pnpm_v5_pristine()).await;
        let root = tmp.path();
        assert_eq!(
            state.edits.len(),
            2,
            "plain + suffixed instance edits: {:?}",
            state.edits
        );

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("pnpm-lock.yaml"))
                .await
                .unwrap(),
            pnpm_v5_pristine(),
            "pnpm-lock.yaml restored byte-identical (both instances)"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(
            state.edits.is_empty(),
            "no stranded instance edits: {:?}",
            state.edits
        );
    }

    /// The peered-instance claim is boundary-checked: `left-pad@1.3.0-rc1`'s
    /// peered key starts with `left-pad@1.3.0`, but `-` extends the version —
    /// taking over 1.3.0 must not claim (and replay) the prerelease sibling's
    /// edit.
    #[tokio::test]
    async fn npm_pnpm_prerelease_sibling_peered_edit_is_not_claimed() {
        let rc1_url =
            "http://127.0.0.1:5555/patch/npm/left-pad/1.3.0-rc1/tok/6b7c/left-pad-1.3.0-rc1.tgz";
        let lock = format!(
            "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    \
             resolution: {{integrity: sha512-h==, tarball: {NPM_URL}}}\n\n  \
             /left-pad@1.3.0-rc1(react@18.2.0):\n    \
             resolution: {{integrity: sha512-h2==, tarball: {rc1_url}}}\n"
        );
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("pnpm-lock.yaml"), &lock)
            .await
            .unwrap();
        let mut state = RedirectState::new();
        state.records.insert(NPM_PURL.to_string(), record());
        state
            .records
            .insert("pkg:npm/left-pad@1.3.0-rc1".to_string(), record());
        state.edits.push(FileEdit {
            path: "pnpm-lock.yaml".into(),
            kind: "redirect_pnpm_resolution".into(),
            action: "rewritten".into(),
            key: Some("left-pad@1.3.0".into()),
            original: Some(Value::String("{integrity: sha512-p==}".into())),
            new: Some(Value::String(format!(
                "{{integrity: sha512-h==, tarball: {NPM_URL}}}"
            ))),
        });
        state.edits.push(FileEdit {
            path: "pnpm-lock.yaml".into(),
            kind: "redirect_pnpm_resolution".into(),
            action: "rewritten".into(),
            key: Some("left-pad@1.3.0-rc1(react@18.2.0)".into()),
            original: Some(Value::String("{integrity: sha512-p2==}".into())),
            new: Some(Value::String(format!(
                "{{integrity: sha512-h2==, tarball: {rc1_url}}}"
            ))),
        });

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of 1.3.0 succeeds without touching 1.3.0-rc1");

        let lock_after = tokio::fs::read_to_string(root.join("pnpm-lock.yaml"))
            .await
            .unwrap();
        assert!(
            !lock_after.contains(NPM_URL),
            "1.3.0 un-hosted: {lock_after}"
        );
        assert!(
            lock_after.contains(rc1_url),
            "1.3.0-rc1 still hosted-wired: {lock_after}"
        );
        assert_eq!(
            state.edits.len(),
            1,
            "the sibling keeps its edit: {:?}",
            state.edits
        );
        assert!(
            state.records.contains_key("pkg:npm/left-pad@1.3.0-rc1")
                && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
    }

    /// Pristine package-lock (lockfileVersion 2, both trees) holding TWO
    /// versions of left-pad — the sibling-purl fixture the claim matcher
    /// must not cross-claim.
    fn two_version_lock_pristine() -> String {
        let lp = |v: &str| {
            serde_json::json!({
                "version": v,
                "resolved": format!("https://registry.npmjs.org/left-pad/-/left-pad-{v}.tgz"),
                "integrity": format!("sha512-pristine-{v}=="),
            })
        };
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-a=="
                },
                "node_modules/a/node_modules/left-pad": lp("1.2.0"),
                "node_modules/left-pad": lp("1.3.0"),
            },
            "dependencies": {
                "a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-a==",
                    "dependencies": { "left-pad": lp("1.2.0") }
                },
                "left-pad": lp("1.3.0"),
            }
        });
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap())
    }

    /// Two hosted-redirected VERSIONS of the same package: taking over one
    /// purl must not claim (and silently un-host) the sibling's lock edits —
    /// the package-lock JSON edit keys carry no version, so a name-only
    /// matcher replays the sibling's `original` back over its live hosted
    /// wiring and drops its edits while its ledger record survives edit-less.
    #[tokio::test]
    async fn npm_two_versions_takeover_of_one_leaves_the_siblings_redirect_intact() {
        let sibling_purl = "pkg:npm/left-pad@1.2.0";
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &two_version_lock_pristine(),
            &[
                (NPM_PURL, npm_dep()),
                (sibling_purl, npm_dep_for("left-pad", "1.2.0")),
            ],
        )
        .await;
        let root = tmp.path();
        // 2 edits per purl: one v3 `packages` entry + one v2 `dependencies`
        // node each.
        assert_eq!(state.edits.len(), 4, "{:?}", state.edits);
        let sibling_url = npm_dep_for("left-pad", "1.2.0").artifact_url.clone();
        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(wired.contains(NPM_URL) && wired.contains(&sibling_url));

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of 1.3.0 succeeds without touching 1.2.0");

        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(!lock.contains(NPM_URL), "1.3.0 un-hosted: {lock}");
        assert!(
            lock.contains("left-pad/-/left-pad-1.3.0.tgz"),
            "1.3.0 back on the registry: {lock}"
        );
        assert_eq!(
            lock.matches(&sibling_url).count(),
            2,
            "1.2.0 still hosted-wired in BOTH trees: {lock}"
        );
        assert!(
            state.records.contains_key(sibling_purl) && !state.records.contains_key(NPM_PURL),
            "only 1.3.0's record dropped: {:?}",
            state.records.keys()
        );
        assert_eq!(
            state.edits.len(),
            2,
            "1.2.0 keeps its two edits: {:?}",
            state.edits
        );

        // The sibling's own takeover still round-trips the file to pristine.
        revert_npm_redirect_purl(root, &mut state, sibling_purl, false)
            .await
            .expect("takeover of 1.2.0 succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            two_version_lock_pristine(),
            "package-lock.json restored byte-identical"
        );
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// `npm i left-pad@npm:other` keys package `other` under the lock path
    /// `node_modules/left-pad`: taking over left-pad must not claim that
    /// entry's edit through the key name (the entry's `name` field exonerates
    /// it, exactly as the rewriter matched), while an alias install OF
    /// left-pad (`npm i mylp@npm:left-pad`) must still be claimed through
    /// the `name` field.
    #[tokio::test]
    async fn npm_alias_collision_takeover_claims_by_entry_name_not_key_path() {
        let other_purl = "pkg:npm/other@1.3.0";
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                // Alias of ANOTHER package onto this key path — same version
                // on purpose, so only the name field can exonerate it.
                "node_modules/left-pad": {
                    "name": "other",
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/other/-/other-1.3.0.tgz",
                    "integrity": "sha512-pristine-other=="
                },
                // Alias OF the target package: claimed via the name field.
                "node_modules/mylp": {
                    "name": "left-pad",
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-1.3.0=="
                },
                "node_modules/b/node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-1.3.0=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &pristine,
            &[
                (NPM_PURL, npm_dep()),
                (other_purl, npm_dep_for("other", "1.3.0")),
            ],
        )
        .await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 3, "{:?}", state.edits);
        let other_url = npm_dep_for("other", "1.3.0").artifact_url.clone();

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of left-pad succeeds without touching `other`");

        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(
            !lock.contains(NPM_URL),
            "both left-pad entries (path-keyed AND alias-keyed) un-hosted: {lock}"
        );
        assert!(
            lock.contains(&other_url),
            "`other` (aliased onto node_modules/left-pad) still hosted-wired: {lock}"
        );
        assert!(
            state.records.contains_key(other_purl) && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
        assert_eq!(
            state.edits.len(),
            1,
            "other keeps its edit: {:?}",
            state.edits
        );

        revert_npm_redirect_purl(root, &mut state, other_purl, false)
            .await
            .expect("takeover of other succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            pristine,
            "package-lock.json restored byte-identical"
        );
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// The version-scoped claim must not soften the fail-closed contract: a
    /// lock entry that VANISHED after being redirected still refuses (its
    /// edit is attributed by key path + recorded URLs), never a silent
    /// record-drop that strands the edit.
    #[tokio::test]
    async fn npm_missing_lock_entry_still_fails_closed() {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture("package-lock.json", &pristine).await;
        let root = tmp.path();
        // A third party pruned the entry from the lock after the redirect.
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("packages")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("node_modules/left-pad")
            .expect("fixture entry present");
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .await
        .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("vanished entry must refuse");
        assert!(err.contains("no longer exists"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// `npm i mylp@npm:left-pad` records an edit keyed by the ALIAS lock path
    /// (`node_modules/mylp`); after `npm uninstall mylp` regenerates the lock
    /// without that entry, the takeover must still attribute the edit to this
    /// purl (via its recorded URLs — the key path says "mylp") and refuse
    /// fail-closed exactly like the path-keyed vanished entry above — never
    /// report success with the alias edit stranded in the ledger behind a
    /// dropped record (half a takeover).
    #[tokio::test]
    async fn npm_vanished_alias_keyed_entry_fails_closed_not_half_takeover() {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                },
                // Alias install OF the target package: the rewriter matches
                // it via the `name` field and keys its edit by this path.
                "node_modules/mylp": {
                    "name": "left-pad",
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture("package-lock.json", &pristine).await;
        let root = tmp.path();
        assert_eq!(
            state.edits.len(),
            2,
            "path-keyed + alias-keyed edits: {:?}",
            state.edits
        );
        // `npm uninstall mylp` regenerated the lock: the alias entry is gone,
        // the surviving entry keeps the hosted `resolved`.
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("packages")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("node_modules/mylp")
            .expect("fixture alias entry present");
        let on_disk_text = serde_json::to_string_pretty(&on_disk).unwrap();
        tokio::fs::write(root.join("package-lock.json"), &on_disk_text)
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("vanished alias-keyed entry must refuse, not strand its edit");
        assert!(err.contains("no longer exists"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            on_disk_text,
            "nothing reached disk on refusal"
        );
    }

    /// `npm i left-pad@npm:other` keys package `other` under
    /// `node_modules/left-pad`; a hand edit strips BOTH the `name` and
    /// `version` fields from that live entry. Taking over left-pad must not
    /// claim `other`'s edit through a version-only URL fallback — the entry's
    /// live values ARE that edit's `new` values, so the replay would NOT fail
    /// closed: `other` would be silently un-hosted and its edit dropped while
    /// its record survives edit-less.
    #[tokio::test]
    async fn npm_version_gone_fallback_does_not_claim_alias_collision_sibling() {
        let other_purl = "pkg:npm/other@1.3.0";
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                // Alias of ANOTHER package onto this key path — same version
                // on purpose.
                "node_modules/left-pad": {
                    "name": "other",
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/other/-/other-1.3.0.tgz",
                    "integrity": "sha512-pristine-other=="
                },
                // The real target package, nested.
                "node_modules/b/node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-1.3.0=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &pristine,
            &[
                (NPM_PURL, npm_dep()),
                (other_purl, npm_dep_for("other", "1.3.0")),
            ],
        )
        .await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "{:?}", state.edits);
        let other_url = npm_dep_for("other", "1.3.0").artifact_url.clone();
        // Hand edit / merge artifact: strip the alias entry's name+version.
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        let entry = on_disk
            .get_mut("packages")
            .and_then(|p| p.get_mut("node_modules/left-pad"))
            .and_then(Value::as_object_mut)
            .unwrap();
        entry.remove("name").expect("fixture name field present");
        entry
            .remove("version")
            .expect("fixture version field present");
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .await
        .unwrap();

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of left-pad succeeds without touching `other`");

        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(!lock.contains(NPM_URL), "left-pad un-hosted: {lock}");
        assert!(
            lock.contains(&other_url),
            "`other` (aliased onto node_modules/left-pad, fields stripped) \
             still hosted-wired: {lock}"
        );
        assert!(
            state.records.contains_key(other_purl) && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
        assert_eq!(
            state.edits.len(),
            1,
            "other keeps its edit: {:?}",
            state.edits
        );
    }

    /// Narrowing guard for the version-gone fallback: with only the `version`
    /// field hand-stripped from the target's own live entry, the recorded
    /// URLs name this exact package+version, so the takeover still claims and
    /// reverts it rather than stranding the edit.
    #[tokio::test]
    async fn npm_version_stripped_target_entry_is_still_claimed_via_recorded_urls() {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture("package-lock.json", &pristine).await;
        let root = tmp.path();
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("packages")
            .and_then(|p| p.get_mut("node_modules/left-pad"))
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("version")
            .expect("fixture version field present");
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .await
        .unwrap();

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(!lock.contains(NPM_URL), "left-pad un-hosted: {lock}");
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// Scope-blindness guard for the version-gone URL fallback: `npm i
    /// left-pad@npm:@scope/left-pad` keys the SCOPED fork under
    /// `node_modules/left-pad`, and its registry URL
    /// (`…/@scope/left-pad/-/left-pad-1.3.0.tgz`) embeds both `/left-pad/`
    /// (the slash closing `@scope`) and the bare `left-pad-1.3.0.tgz`
    /// basename. With the entry's `name`+`version` hand-stripped, taking
    /// over unscoped left-pad must not claim the scoped sibling's edit
    /// through those substrings — the entry's live values ARE that edit's
    /// `new` values, so the replay would NOT fail closed: @scope/left-pad
    /// would be silently un-hosted and its edit dropped while its record
    /// survives edit-less.
    #[tokio::test]
    async fn npm_version_gone_fallback_does_not_claim_scoped_sibling_of_same_bare_name() {
        let scoped_purl = "pkg:npm/@scope/left-pad@1.3.0";
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                // The scoped fork aliased onto the bare key path — same bare
                // name AND version on purpose.
                "node_modules/left-pad": {
                    "name": "@scope/left-pad",
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/@scope/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-scoped=="
                },
                // The real target package, nested.
                "node_modules/b/node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-1.3.0=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &pristine,
            &[
                (NPM_PURL, npm_dep()),
                (scoped_purl, npm_dep_for("@scope/left-pad", "1.3.0")),
            ],
        )
        .await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "{:?}", state.edits);
        let scoped_url = npm_dep_for("@scope/left-pad", "1.3.0").artifact_url.clone();
        // Hand edit / merge artifact: strip the alias entry's name+version.
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        let entry = on_disk
            .get_mut("packages")
            .and_then(|p| p.get_mut("node_modules/left-pad"))
            .and_then(Value::as_object_mut)
            .unwrap();
        entry.remove("name").expect("fixture name field present");
        entry
            .remove("version")
            .expect("fixture version field present");
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .await
        .unwrap();

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of left-pad succeeds without touching @scope/left-pad");

        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(!lock.contains(NPM_URL), "left-pad un-hosted: {lock}");
        assert!(
            lock.contains(&scoped_url),
            "@scope/left-pad (aliased onto node_modules/left-pad, fields \
             stripped) still hosted-wired: {lock}"
        );
        assert!(
            state.records.contains_key(scoped_purl) && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
        assert_eq!(
            state.edits.len(),
            1,
            "the scoped sibling keeps its edit: {:?}",
            state.edits
        );
    }

    /// Fail-closed-direction twin of the scoped-sibling guard: with
    /// @scope/left-pad installed at its own scoped path and then
    /// uninstalled (its entry vanished, its edit orphaned in the ledger),
    /// taking over UNSCOPED left-pad@1.3.0 must not claim the orphan
    /// through the URL fallback — claiming it refuses with "entry
    /// `node_modules/@scope/left-pad` … no longer exists", a spurious
    /// permanent refusal for a purl whose own wiring is intact.
    #[tokio::test]
    async fn npm_vanished_scoped_sibling_entry_does_not_block_the_unscoped_takeover() {
        let scoped_purl = "pkg:npm/@scope/left-pad@1.3.0";
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-1.3.0=="
                },
                "node_modules/@scope/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/@scope/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine-scoped=="
                },
            },
        });
        let pristine = format!("{}\n", serde_json::to_string_pretty(&lock).unwrap());
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "package-lock.json",
            &pristine,
            &[
                (NPM_PURL, npm_dep()),
                (scoped_purl, npm_dep_for("@scope/left-pad", "1.3.0")),
            ],
        )
        .await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "{:?}", state.edits);
        // `npm uninstall @scope/left-pad` regenerated the lock without the
        // scoped entry; the ledger still holds its edit.
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("packages")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("node_modules/@scope/left-pad")
            .expect("fixture scoped entry present");
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&on_disk).unwrap(),
        )
        .await
        .unwrap();

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of left-pad succeeds despite the scoped orphan edit");

        let lock = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(!lock.contains(NPM_URL), "left-pad un-hosted: {lock}");
        assert!(
            state.records.contains_key(scoped_purl) && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
        assert_eq!(
            state.edits.len(),
            1,
            "the scoped orphan edit survives for its own takeover: {:?}",
            state.edits
        );
        assert_eq!(
            state.edits[0].key.as_deref(),
            Some("node_modules/@scope/left-pad"),
            "{:?}",
            state.edits
        );
    }

    #[tokio::test]
    async fn npm_refuses_on_drifted_lock_fail_closed() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        // A third party re-resolved the entry to a shape the ledger never saw.
        let drifted = classic_pristine().replace(
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a",
            "https://corp.example/left-pad-1.3.0.tgz#dead",
        );
        tokio::fs::write(root.join("yarn.lock"), &drifted)
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("drifted lock must refuse");
        assert!(err.contains("drifted"), "{err}");
        // The ledger keeps everything on refusal, and the file is untouched.
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            drifted
        );
    }

    #[tokio::test]
    async fn npm_missing_record_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_npm_redirect_purl(tmp.path(), &mut state, NPM_PURL, false)
            .await
            .expect_err("no record");
        assert!(err.contains("records no hosted redirect"), "{err}");
    }

    // ── bun ──────────────────────────────────────────────────────────────

    /// Real text-lock grammar (bun 1.4.2 matrix capture, lockfileVersion 2;
    /// the `packages` tuple grammar is identical on 0/1/2): the root
    /// `left-pad@1.3.0` registry 4-tuple, a nested `haspad/left-pad`
    /// instance at the SIBLING version 1.2.0, and an unrelated `other`.
    fn bun_pristine() -> String {
        r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "takeover-fixture",
      "dependencies": {
        "haspad": "1.0.0",
        "left-pad": "1.3.0",
        "other": "1.0.0",
      },
    },
  },
  "packages": {
    "haspad": ["haspad@1.0.0", "", { "dependencies": { "left-pad": "^1.2.0" } }, "sha512-hh=="],

    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],

    "other": ["other@1.0.0", "", {}, "sha512-oo=="],

    "haspad/left-pad": ["left-pad@1.2.0", "", {}, "sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg=="],
  }
}
"#
        .to_string()
    }

    /// The packages-entry line keyed `key` (verbatim, without its line
    /// terminator).
    fn bun_line(lock: &str, key: &str) -> String {
        let prefix = format!("    \"{key}\": [");
        lock.split('\n')
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no `{key}` entry in:\n{lock}"))
            .trim_end_matches('\r')
            .to_string()
    }

    async fn read_lock(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("bun.lock"))
            .await
            .unwrap()
    }

    /// The bun revert used to be a hard refusal ("cannot replay yet");
    /// now the takeover claims the purl's `redirect_bun_lock_package` edit
    /// by the recorded line's spec and replays the registry line back,
    /// leaving the sibling-version and foreign entries untouched.
    #[tokio::test]
    async fn npm_bun_lock_takeover_restores_the_registry_line_and_drops_the_ledger() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        assert!(wired.contains(NPM_URL), "fixture is hosted-wired:\n{wired}");
        assert_eq!(
            state
                .edits
                .iter()
                .filter(|e| e.kind == BUN_TEXT_KIND)
                .count(),
            1,
            "one bun edit for the one 1.3.0 instance: {:?}",
            state.edits
        );

        let out = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("bun takeover revert succeeds");
        assert_eq!(out.reverted_files, vec!["bun.lock".to_string()]);
        assert_eq!(
            read_lock(root).await,
            bun_pristine(),
            "bun.lock restored byte-identical"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edit consumed");
    }

    /// (a) A hosted edit for ANOTHER VERSION of the same package (the nested
    /// `haspad/left-pad` at 1.2.0) is not this purl's to claim: reverting
    /// 1.3.0 leaves the 1.2.0 line hosted and its record + edit in the
    /// ledger.
    #[tokio::test]
    async fn npm_bun_sibling_version_edit_is_neither_claimed_nor_a_refusal() {
        const SIBLING: &str = "pkg:npm/left-pad@1.2.0";
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "bun.lock",
            &bun_pristine(),
            &[
                (NPM_PURL, npm_dep()),
                (SIBLING, npm_dep_for("left-pad", "1.2.0")),
            ],
        )
        .await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let sibling_line = bun_line(&wired, "haspad/left-pad");
        assert!(
            sibling_line.contains("/left-pad/1.2.0/")
                && sibling_line.contains("left-pad-1.2.0.tgz"),
            "sibling instance is hosted-wired too: {sibling_line}"
        );
        assert_eq!(state.edits.len(), 2, "{:?}", state.edits);

        revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of 1.3.0 succeeds");
        let after = read_lock(root).await;
        assert_eq!(
            bun_line(&after, "left-pad"),
            bun_line(&bun_pristine(), "left-pad"),
            "the 1.3.0 line is back to its registry tuple"
        );
        assert_eq!(
            bun_line(&after, "haspad/left-pad"),
            sibling_line,
            "the sibling version's hosted line is untouched"
        );
        assert_eq!(state.edits.len(), 1, "{:?}", state.edits);
        assert_eq!(state.edits[0].key.as_deref(), Some("haspad/left-pad"));
        assert!(
            state.records.contains_key(SIBLING) && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
    }

    /// The digest-less spelling Bun 1.1.39–1.3.9 re-save a URL 3-tuple as
    /// (`bun add`, `bun install` after a manifest change): the recorded
    /// `new` is no longer on disk byte-for-byte, but the 2-tuple with the
    /// same key/spec/meta IS our wiring — the claim must not refuse as
    /// drift (that blocked hosted→vendored takeover, scoped `rollback` and
    /// `remove` for every user on those releases). The registry line comes
    /// back and the ledger is cleared.
    fn drop_digest(line: &str) -> String {
        let cut = line
            .rfind(", \"sha512-")
            .unwrap_or_else(|| panic!("no sha512 element in {line}"));
        let tail = if line.trim_end_matches('\r').ends_with("],") {
            "],"
        } else {
            "]"
        };
        let cr = if line.ends_with('\r') { "\r" } else { "" };
        format!("{}{tail}{cr}", &line[..cut])
    }

    #[tokio::test]
    async fn npm_bun_digestless_live_line_is_claimed_and_restored() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let wired_line = bun_line(&wired, "left-pad");
        let digestless = drop_digest(&wired_line);
        assert!(
            digestless.ends_with("{}],") && !digestless.contains("sha512"),
            "{digestless}"
        );
        tokio::fs::write(
            root.join("bun.lock"),
            wired.replace(&wired_line, &digestless),
        )
        .await
        .unwrap();

        let out = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("the digest-less spelling of our own wiring must not refuse");
        assert_eq!(out.reverted_files, vec!["bun.lock".to_string()]);
        assert_eq!(
            read_lock(root).await,
            bun_pristine(),
            "registry line restored"
        );
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// Both hosted instances re-saved digest-less; reverting 1.3.0 restores
    /// ONLY its line — the sibling 1.2.0 keeps its digest-less hosted
    /// 2-tuple untouched (it is that purl's wiring, not ours to heal).
    #[tokio::test]
    async fn npm_bun_digestless_sibling_stays_untouched() {
        const SIBLING: &str = "pkg:npm/left-pad@1.2.0";
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "bun.lock",
            &bun_pristine(),
            &[
                (NPM_PURL, npm_dep()),
                (SIBLING, npm_dep_for("left-pad", "1.2.0")),
            ],
        )
        .await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let main_line = bun_line(&wired, "left-pad");
        let sibling_line = bun_line(&wired, "haspad/left-pad");
        let sibling_digestless = drop_digest(&sibling_line);
        let live = wired
            .replace(&main_line, &drop_digest(&main_line))
            .replace(&sibling_line, &sibling_digestless);
        tokio::fs::write(root.join("bun.lock"), &live)
            .await
            .unwrap();

        revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover of 1.3.0 succeeds");
        let after = read_lock(root).await;
        assert_eq!(
            bun_line(&after, "left-pad"),
            bun_line(&bun_pristine(), "left-pad")
        );
        assert_eq!(
            bun_line(&after, "haspad/left-pad"),
            sibling_digestless,
            "the sibling's digest-less hosted line is left exactly as found"
        );
        assert_eq!(state.edits.len(), 1);
        assert!(state.records.contains_key(SIBLING) && !state.records.contains_key(NPM_PURL));
    }

    /// A digest-less 2-tuple at ANOTHER uuid (someone re-granted the patch
    /// and Bun re-saved it) is not the recorded wiring: still drift, still
    /// a refusal, file byte-identical.
    #[tokio::test]
    async fn npm_bun_digestless_line_at_another_uuid_still_refuses() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let wired_line = bun_line(&wired, "left-pad");
        let foreign = drop_digest(&wired_line).replace("/6b7c/", "/7c8d/");
        assert_ne!(
            foreign,
            drop_digest(&wired_line),
            "the uuid segment must differ"
        );
        let live = wired.replace(&wired_line, &foreign);
        tokio::fs::write(root.join("bun.lock"), &live)
            .await
            .unwrap();

        let err = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("another uuid's digest-less line is drift");
        assert!(err.contains("drifted"), "{err}");
        assert_eq!(
            read_lock(root).await,
            live,
            "refusal leaves the lock untouched"
        );
        assert_eq!(state.edits.len(), 1);
        assert!(state.records.contains_key(NPM_PURL));
    }

    /// (b) Scoped package + re-redirect chain: the hosted rewrite destroys
    /// the `@scope/pkg@1.0.0` spec, so the SECOND redirect (a rotated
    /// artifact URL) records a hosted-URL line as its `original`. That edit
    /// is claimed through the URL's tarball leaf (`pkg-1.0.0.tgz` — the
    /// scope is a path level, not part of the basename) plus the full
    /// scoped name in the spec; `@other/pkg` and bare `pkg`, whose leaves
    /// are identical, stay hosted. Both links unwind newest-first to the
    /// registry line.
    #[tokio::test]
    async fn npm_bun_scoped_package_claims_the_re_redirect_chain_by_spec_and_leaf() {
        const SCOPED: &str = "pkg:npm/%40scope/pkg@1.0.0";
        const OTHER_SCOPE: &str = "pkg:npm/%40other/pkg@1.0.0";
        const BARE: &str = "pkg:npm/pkg@1.0.0";
        let pristine = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "scoped-fixture",
      "dependencies": {
        "@other/pkg": "1.0.0",
        "@scope/pkg": "1.0.0",
        "pkg": "1.0.0",
      },
    },
  },
  "packages": {
    "@other/pkg": ["@other/pkg@1.0.0", "", {}, "sha512-o1=="],

    "@scope/pkg": ["@scope/pkg@1.0.0", "", {}, "sha512-s1=="],

    "pkg": ["pkg@1.0.0", "", {}, "sha512-p1=="],
  }
}
"#;
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "bun.lock",
            pristine,
            &[
                (SCOPED, npm_dep_for("@scope/pkg", "1.0.0")),
                (OTHER_SCOPE, npm_dep_for("@other/pkg", "1.0.0")),
                (BARE, npm_dep_for("pkg", "1.0.0")),
            ],
        )
        .await;
        let root = tmp.path();
        let first = read_lock(root).await;
        let first_scoped_line = bun_line(&first, "@scope/pkg");
        assert!(
            first_scoped_line.contains("/@scope/pkg/1.0.0/"),
            "{first_scoped_line}"
        );

        // Second redirect of ONLY @scope/pkg with a rotated artifact URL
        // (same origin + leaf, different uuid path segment): the rewriter's
        // prior-hosted match re-pins it and records the chain link.
        let mut rotated = npm_dep_for("@scope/pkg", "1.0.0");
        rotated.artifact_url = rotated.artifact_url.replace("/6b7c/", "/7c8d/");
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("bun.lock".into(), first.clone());
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[rotated]);
        let second = rewrite
            .files
            .get("bun.lock")
            .unwrap_or_else(|| panic!("re-redirect must rewrite: {:?}", rewrite.warnings))
            .clone();
        assert!(
            bun_line(&second, "@scope/pkg").contains("/7c8d/"),
            "{second}"
        );
        tokio::fs::write(root.join("bun.lock"), &second)
            .await
            .unwrap();
        state.edits.extend(rewrite.edits);
        assert_eq!(state.edits.len(), 4, "{:?}", state.edits);
        let chain_link = state.edits.last().unwrap();
        assert!(
            chain_link.original.as_ref().and_then(Value::as_str)
                == Some(first_scoped_line.as_str()),
            "the chain link's original is the PRIOR hosted line: {chain_link:?}"
        );

        revert_redirect_purl(root, &mut state, "pkg:npm/@scope/pkg@1.0.0", false)
            .await
            .expect("scoped takeover succeeds");
        let after = read_lock(root).await;
        assert_eq!(
            bun_line(&after, "@scope/pkg"),
            bun_line(pristine, "@scope/pkg"),
            "both chain links unwound to the registry tuple"
        );
        assert_eq!(
            bun_line(&after, "@other/pkg"),
            bun_line(&first, "@other/pkg"),
            "same-leaf scoped sibling stays hosted"
        );
        assert_eq!(
            bun_line(&after, "pkg"),
            bun_line(&first, "pkg"),
            "same-leaf bare sibling stays hosted"
        );
        assert_eq!(state.edits.len(), 2, "{:?}", state.edits);
        assert!(
            state
                .edits
                .iter()
                .all(|e| matches!(e.key.as_deref(), Some("@other/pkg") | Some("pkg"))),
            "{:?}",
            state.edits
        );
        assert!(
            !state.records.contains_key(SCOPED)
                && state.records.contains_key(OTHER_SCOPE)
                && state.records.contains_key(BARE),
            "{:?}",
            state.records.keys()
        );
    }

    /// The claim rule in isolation: registry spec by exact version, hosted
    /// URL spec by exact tarball leaf, full (scoped) name in every case;
    /// anything else — sibling versions, local vendored paths, workspace
    /// specs, URLs without a path — is not ours.
    #[test]
    fn bun_spec_names_discriminates_name_and_version() {
        assert!(bun_spec_names("left-pad@1.3.0", "left-pad", "1.3.0"));
        assert!(!bun_spec_names("left-pad@1.3.0-rc1", "left-pad", "1.3.0"));
        assert!(!bun_spec_names("left-pad@11.3.0", "left-pad", "1.3.0"));
        assert!(!bun_spec_names("left-pad@1.3.0", "other", "1.3.0"));
        assert!(bun_spec_names(
            &format!("left-pad@{NPM_URL}"),
            "left-pad",
            "1.3.0"
        ));
        assert!(!bun_spec_names(
            "left-pad@http://127.0.0.1:5555/p/left-pad-11.3.0.tgz",
            "left-pad",
            "1.3.0"
        ));
        assert!(!bun_spec_names(
            "left-pad@http://127.0.0.1:5555/p/left-pad-1.3.0-rc1.tgz",
            "left-pad",
            "1.3.0"
        ));
        // Vendored local path, workspace and origin-only specs are never
        // hosted redirects.
        assert!(!bun_spec_names(
            "left-pad@.socket/vendor/npm/6b7c/left-pad-1.3.0.tgz",
            "left-pad",
            "1.3.0"
        ));
        assert!(!bun_spec_names(
            "left-pad@workspace:packages/left-pad",
            "left-pad",
            "1.3.0"
        ));
        assert!(!bun_spec_names(
            "left-pad@https://patch.socket.dev",
            "left-pad",
            "1.3.0"
        ));
        // Scoped: the leaf is the BARE basename whether the URL keeps the
        // scope as a path level (production, test fixtures) or not; the
        // full scoped name must match the spec's name.
        assert!(bun_spec_names(
            "@scope/pkg@https://patch.socket.dev/patch/npm/@scope/pkg/1.0.0/t/u/pkg-1.0.0.tgz",
            "@scope/pkg",
            "1.0.0"
        ));
        assert!(bun_spec_names(
            "@scope/pkg@http://127.0.0.1:5555/patch/npm/@scope/pkg/1.0.0/tok/6b7c/@scope/pkg-1.0.0.tgz",
            "@scope/pkg",
            "1.0.0"
        ));
        assert!(!bun_spec_names(
            "@other/pkg@https://h/patch/npm/@other/pkg/1.0.0/t/u/pkg-1.0.0.tgz",
            "@scope/pkg",
            "1.0.0"
        ));
        assert!(!bun_spec_names(
            "pkg@https://h/patch/npm/pkg/1.0.0/t/u/pkg-1.0.0.tgz",
            "@scope/pkg",
            "1.0.0"
        ));
        assert!(bun_spec_names("@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"));
    }

    /// (c) Drift: the line was re-resolved by a third party since the
    /// redirect (neither the hosted nor the registry line is present) —
    /// the same fail-closed refusal the yarn/pnpm text kinds give, with the
    /// file and ledger left exactly as found.
    #[tokio::test]
    async fn npm_bun_drifted_line_refuses_fail_closed() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let drifted = wired.replace(
            &bun_line(&wired, "left-pad"),
            "    \"left-pad\": [\"left-pad@https://corp.example/mirror/left-pad-1.3.0.tgz\", {}, \"sha512-corp==\"],",
        );
        assert_ne!(drifted, wired);
        tokio::fs::write(root.join("bun.lock"), &drifted)
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("drifted line must refuse");
        assert!(err.contains("drifted"), "{err}");
        assert!(err.contains("bun.lock"), "{err}");
        assert_eq!(read_lock(root).await, drifted, "file untouched");
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// (d) CRLF lock: the recorded lines carry (or, for a rewriter that
    /// normalized the rewritten line, lack) a trailing `\r`; the whole-line
    /// replace restores the pristine CRLF bytes either way.
    #[tokio::test]
    async fn npm_bun_crlf_lock_round_trips_byte_exact() {
        let pristine = bun_pristine().replace('\n', "\r\n");
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &pristine).await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        assert!(wired.contains(NPM_URL), "{wired}");
        assert!(
            wired.contains("\r\n"),
            "CRLF preserved elsewhere: {wired:?}"
        );

        revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("CRLF takeover succeeds");
        assert_eq!(
            read_lock(root).await,
            pristine,
            "CRLF bun.lock restored byte-identical"
        );
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// (e) Two hosted records (different packages): the takeover of one
    /// restores only its line and keeps the other purl's record + edit —
    /// the state a scoped `rollback <purl>` / `remove <purl>` needs.
    #[tokio::test]
    async fn npm_bun_two_hosted_records_takeover_of_one_leaves_the_other_hosted() {
        const OTHER: &str = "pkg:npm/other@1.0.0";
        let (tmp, mut state) = npm_redirected_fixture_multi(
            "bun.lock",
            &bun_pristine(),
            &[
                (NPM_PURL, npm_dep()),
                (OTHER, npm_dep_for("other", "1.0.0")),
            ],
        )
        .await;
        let root = tmp.path();
        let wired = read_lock(root).await;
        let other_line = bun_line(&wired, "other");
        assert!(other_line.contains("other-1.0.0.tgz"), "{other_line}");

        let out = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover succeeds");
        assert_eq!(out.reverted_files, vec!["bun.lock".to_string()]);
        let after = read_lock(root).await;
        assert_eq!(
            bun_line(&after, "left-pad"),
            bun_line(&bun_pristine(), "left-pad")
        );
        assert_eq!(bun_line(&after, "other"), other_line, "other stays hosted");
        assert_eq!(state.edits.len(), 1);
        assert_eq!(state.edits[0].key.as_deref(), Some("other"));
        assert_eq!(state.records.len(), 1);
        assert!(state.records.contains_key(OTHER));

        // Taking over the second one finishes the job.
        revert_redirect_purl(root, &mut state, OTHER, false)
            .await
            .expect("second takeover succeeds");
        assert_eq!(read_lock(root).await, bun_pristine());
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// bun's dry run mirrors the cargo/yarn contract: every inverse and
    /// drift check resolves, nothing reaches disk, the in-memory ledger is
    /// claimed, and the preview names the files a wet run rewrites.
    #[tokio::test]
    async fn npm_bun_dry_run_previews_without_touching_disk() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        let wired = read_lock(root).await;

        let dry = revert_redirect_purl(root, &mut state, NPM_PURL, true)
            .await
            .expect("dry-run revert succeeds");
        assert_eq!(dry.reverted_files, vec!["bun.lock".to_string()]);
        assert_eq!(read_lock(root).await, wired, "disk untouched");
        assert!(state.records.is_empty(), "record claimed in memory");
        assert!(state.edits.is_empty(), "edit claimed in memory");
    }

    /// A hand-edited ledger whose bun fragments mention the package but are
    /// not entry lines cannot be attributed: refuse with the WORKING remedy
    /// (the whole-ledger `rollback` replay) — never `bun install`, which
    /// keeps a hosted URL tuple byte-identically — and keep the ledger.
    #[tokio::test]
    async fn npm_bun_unparseable_edit_mentioning_the_package_refuses_with_the_rollback_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state.records.insert(NPM_PURL.to_string(), record());
        state.edits.push(FileEdit {
            path: "bun.lock".into(),
            kind: BUN_TEXT_KIND.into(),
            action: "rewritten".into(),
            key: Some("left-pad".into()),
            original: Some(Value::String("\"left-pad@1.3.0\" (truncated".into())),
            new: Some(Value::String(format!("\"left-pad@{NPM_URL}\" (truncated"))),
        });
        let err = revert_npm_redirect_purl(tmp.path(), &mut state, NPM_PURL, false)
            .await
            .expect_err("undecidable bun edit must refuse");
        assert!(err.contains("unscoped `socket-patch rollback`"), "{err}");
        assert!(err.contains("do not edit"), "{err}");
        assert!(!err.contains("bun install"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert!(!state.edits.is_empty(), "ledger keeps the edit");
    }

    /// An alias install (`bun add alias@npm:left-pad@1.3.0`) keys the entry
    /// by the alias; the rewriter matched it by spec, and so does the
    /// claim.
    #[tokio::test]
    async fn npm_bun_alias_keyed_instance_is_claimed_by_spec() {
        let pristine = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "alias-fixture",
      "dependencies": {
        "alias": "npm:left-pad@1.3.0",
      },
    },
  },
  "packages": {
    "alias": ["left-pad@1.3.0", "", {}, "sha512-XI5M=="],
  }
}
"#;
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", pristine).await;
        let root = tmp.path();
        assert_eq!(state.edits[0].key.as_deref(), Some("alias"));
        revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("alias takeover succeeds");
        assert_eq!(read_lock(root).await, pristine);
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    /// A user hand-restored bun.lock (git checkout): the revert is a clean
    /// no-op that still drops the ledger entries.
    #[tokio::test]
    async fn npm_bun_hand_restored_lock_is_a_noop_that_drops_the_ledger() {
        let (tmp, mut state) = npm_redirected_fixture("bun.lock", &bun_pristine()).await;
        let root = tmp.path();
        tokio::fs::write(root.join("bun.lock"), bun_pristine())
            .await
            .unwrap();
        let out = revert_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert!(out.reverted_files.is_empty(), "{:?}", out.reverted_files);
        assert_eq!(read_lock(root).await, bun_pristine());
        assert!(state.records.is_empty() && state.edits.is_empty());
    }

    // ── refusal / degenerate arms of the fail-closed contract ────────────

    #[tokio::test]
    async fn unsupported_ecosystem_purl_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_redirect_purl(tmp.path(), &mut state, "pkg:gem/rack@3.0.0", false)
            .await
            .expect_err("unsupported ecosystem must refuse");
        assert!(
            err.contains("no hosted-redirect revert implementation"),
            "{err}"
        );
        assert!(err.contains("pkg:gem/rack@3.0.0"), "names the purl: {err}");
    }

    /// A hand-edited ledger can hold a VERSIONLESS record key; the canon
    /// match finds it, but the purl parse must still refuse fail-closed
    /// rather than guess a version.
    #[tokio::test]
    async fn versionless_cargo_purl_record_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:cargo/cfg-if".to_string(), record());
        let err = revert_cargo_redirect_purl(tmp.path(), &mut state, "pkg:cargo/cfg-if", false)
            .await
            .expect_err("versionless purl must refuse");
        assert!(err.contains("not a cargo purl"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
    }

    /// npm twin of the versionless-record refusal.
    #[tokio::test]
    async fn npm_versionless_purl_record_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert("pkg:npm/left-pad".to_string(), record());
        let err = revert_npm_redirect_purl(tmp.path(), &mut state, "pkg:npm/left-pad", false)
            .await
            .expect_err("versionless purl must refuse");
        assert!(err.contains("not an npm purl"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
    }

    /// Corrupt ledger (hand-edited): a wiring edit without an `original`
    /// fragment cannot be inverted — refuse and leave every claimed file
    /// AND the ledger untouched.
    #[tokio::test]
    async fn cargo_edit_without_original_fragment_is_refused_fail_closed() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let toml_before = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let cfg_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();
        state
            .edits
            .iter_mut()
            .find(|e| e.kind == "redirect_cargo_toml_dep")
            .expect("fixture records a toml wiring edit")
            .original = None;

        let err = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect_err("edit without an original must refuse");
        assert!(err.contains("records no original fragment"), "{err}");

        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            toml_before,
            "Cargo.toml untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "Cargo.lock untouched — its inverse resolved before the refusal"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg_before,
            ".cargo/config.toml untouched"
        );
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// Cargo.lock deleted after the redirect: refuse, and leave the OTHER
    /// claimed files and the ledger exactly as found — the contract this
    /// module exists for.
    #[tokio::test]
    async fn cargo_missing_lock_file_refuses_and_leaves_the_rest_untouched() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let toml_before = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        let cfg_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect_err("deleted lock must refuse");
        assert!(err.contains("no longer exists"), "{err}");
        assert!(err.contains("Cargo.lock"), "{err}");

        assert!(!root.join("Cargo.lock").exists(), "not resurrected");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            toml_before,
            "Cargo.toml untouched (still hosted-wired)"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg_before,
            ".cargo/config.toml untouched"
        );
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// A user hand-restored Cargo.toml to the pre-redirect wiring: that edit
    /// is a no-op (already at `original`) and the rest still reverts.
    #[tokio::test]
    async fn cargo_hand_restored_manifest_is_a_noop_and_the_rest_reverts() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        tokio::fs::write(root.join("Cargo.toml"), pristine_toml())
            .await
            .unwrap();

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        assert!(
            out.reverted_files.iter().any(|f| f == "Cargo.lock"),
            "{:?}",
            out.reverted_files
        );
        assert!(
            !out.reverted_files.iter().any(|f| f == "Cargo.toml"),
            "hand-restored file skipped: {:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            pristine_toml()
        );
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            lock.contains(CRATES_IO) && !lock.contains("sparse+"),
            "Cargo.lock restored: {lock}"
        );
        assert!(
            !root.join(".cargo/config.toml").exists(),
            "socket-only config removed"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// `rm -rf .cargo` after the redirect: the registry-block edit is
    /// skipped and the takeover still succeeds.
    #[tokio::test]
    async fn cargo_registry_config_already_deleted_is_skipped() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        tokio::fs::remove_file(root.join(".cargo/config.toml"))
            .await
            .unwrap();

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        assert!(
            !out.reverted_files.iter().any(|f| f.contains(".cargo")),
            "{:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            pristine_toml(),
            "Cargo.toml restored byte-identical"
        );
        assert!(
            !root.join(".cargo/config.toml").exists(),
            "config not resurrected"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// Bug H: removing the block the redirect APPENDED to an existing
    /// config (the legacy `.cargo/config` here) restores the user's bytes —
    /// it left a trailing blank line (`[net]\nretry = 2\n\n`) — and never
    /// touches blank runs of the user's own elsewhere in the file.
    #[tokio::test]
    async fn appended_registry_block_revert_restores_the_config_bytes() {
        let cases = [
            "[net]\nretry = 2\n",
            "[net]\n\n\n\nretry = 2\n",
            "# a comment\n\n[http]\ntimeout = 5\n",
            "[net]\r\nretry = 2\r\n",
            // No final newline, trailing blank lines, whitespace only.
            "[net]\nretry = 2",
            "[net]\r\nretry = 2",
            "[net]\nretry = 2\n\n",
            "[net]\r\nretry = 2\r\n\r\n",
            "\n",
        ];
        // Both unwind paths: `remove <purl>` and the whole-ledger replay.
        for (user_cfg, replay) in cases.iter().flat_map(|cfg| [(*cfg, false), (*cfg, true)]) {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let lock = format!("version = 4\n\n{}\n", pristine_lock_block());
            let mut files: BTreeMap<String, String> = BTreeMap::new();
            files.insert("Cargo.toml".into(), pristine_toml());
            files.insert("Cargo.lock".into(), lock.clone());
            files.insert(".cargo/config".into(), user_cfg.to_string());
            let dep: crate::patch::redirect::DepOverride =
                serde_json::from_value(serde_json::json!({
                    "ecosystem": "cargo", "name": "cfg-if", "version": "1.0.4",
                    "token": "tok", "patchUuid": UUID,
                    "artifactUrl": "http://127.0.0.1:5555/cfg-if-1.0.4.crate",
                    "registryOverride": {
                        "kind": "cargo-sparse", "indexUrl": INDEX,
                        "identifiers": {
                            "name": "cfg-if", "version": "1.0.4",
                            "cargoCksumSha256": "a".repeat(64),
                        },
                    },
                    "integrity": { "sha256": "a".repeat(64) },
                }))
                .unwrap();
            let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[dep]);
            tokio::fs::create_dir_all(root.join(".cargo"))
                .await
                .unwrap();
            for (rel, content) in files.iter().chain(rewrite.files.iter()) {
                tokio::fs::write(root.join(rel), content).await.unwrap();
            }
            let mut state = RedirectState::new();
            state.edits = rewrite.edits;
            state.records.insert(PURL.to_string(), record());

            if replay {
                let outcome = crate::patch::redirect::revert_remaining_redirect_edits(
                    root, &mut state, false,
                )
                .await;
                assert!(outcome.fully_reverted(), "{:?}", outcome.refusals);
            } else {
                revert_cargo_redirect_purl(root, &mut state, PURL, false)
                    .await
                    .expect("revert succeeds");
            }
            assert_eq!(
                tokio::fs::read_to_string(root.join(".cargo/config"))
                    .await
                    .unwrap(),
                user_cfg,
                "replay: {replay}"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.toml"))
                    .await
                    .unwrap(),
                pristine_toml()
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.lock"))
                    .await
                    .unwrap(),
                lock
            );
        }
    }

    /// Bug K: a CRLF project (manifest, lock and legacy config) is
    /// redirected with CRLF kept and `remove` restores every byte.
    #[tokio::test]
    async fn crlf_project_reverts_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let crlf = |s: &str| s.replace('\n', "\r\n");
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), crlf(&pristine_toml()));
        files.insert(
            "Cargo.lock".into(),
            crlf(&format!("version = 4\n\n{}\n", pristine_lock_block())),
        );
        files.insert(".cargo/config".into(), crlf("[net]\nretry = 2\n"));
        let dep: crate::patch::redirect::DepOverride = serde_json::from_value(serde_json::json!({
            "ecosystem": "cargo", "name": "cfg-if", "version": "1.0.4",
            "token": "tok", "patchUuid": UUID,
            "artifactUrl": "http://127.0.0.1:5555/cfg-if-1.0.4.crate",
            "registryOverride": {
                "kind": "cargo-sparse", "indexUrl": INDEX,
                "identifiers": {
                    "name": "cfg-if", "version": "1.0.4",
                    "cargoCksumSha256": "a".repeat(64),
                },
            },
            "integrity": { "sha256": "a".repeat(64) },
        }))
        .unwrap();
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[dep]);
        assert_eq!(rewrite.files.len(), 3, "{:?}", rewrite.warnings);
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        for (rel, content) in files.iter().chain(rewrite.files.iter()) {
            tokio::fs::write(root.join(rel), content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(PURL.to_string(), record());
        revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        for (rel, content) in &files {
            assert_eq!(
                &tokio::fs::read_to_string(root.join(rel)).await.unwrap(),
                content,
                "{rel}"
            );
        }
    }

    /// The socket block was already hand-removed (the config now holds only
    /// user content): skip it, byte-untouched, and still succeed.
    #[tokio::test]
    async fn cargo_registry_block_hand_removed_keeps_user_config_untouched() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let user_cfg = "[net]\nretry = 2\n";
        tokio::fs::write(root.join(".cargo/config.toml"), user_cfg)
            .await
            .unwrap();

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        assert!(
            !out.reverted_files.iter().any(|f| f.contains(".cargo")),
            "{:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            user_cfg,
            "user config byte-untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            pristine_toml()
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// A user hand-pinned a SECOND dep to the socket registry: the block is
    /// kept while anything still references it (the documented defensive
    /// keep), and the takeover still reverts the wiring it owns.
    #[tokio::test]
    async fn cargo_registry_block_kept_while_still_referenced() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let reg = format!("socket-patch-{UUID}");
        let pinned_line = format!("other = {{ version = \"1.0\", registry = \"{reg}\" }}\n");
        let wired_toml = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("Cargo.toml"),
            format!("{wired_toml}{pinned_line}"),
        )
        .await
        .unwrap();

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");

        let cfg = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(cfg.contains(&reg), "block kept while referenced: {cfg}");
        assert!(
            !out.reverted_files.iter().any(|f| f.contains(".cargo")),
            "{:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            format!("{}{pinned_line}", pristine_toml()),
            "cfg-if wiring reverted, hand pin survives"
        );
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            lock.contains(CRATES_IO) && !lock.contains("sparse+"),
            "Cargo.lock restored: {lock}"
        );
        // The edits/record are dropped by design even when the block is
        // kept: the kept block now belongs to the user's hand pin, and a
        // stale ledger claim over it would poison later reverts.
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// A REGENERATED block (`action: "rewritten"` — the rewriter replaced a
    /// degraded/commented region in place and recorded it as `original`)
    /// restores that pre-existing region instead of deleting the block: the
    /// original bytes are the user's.
    #[tokio::test]
    async fn cargo_regenerated_registry_block_restores_the_user_region() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let user_region = "# corp mirror config (degraded)\n";
        state
            .edits
            .iter_mut()
            .find(|e| e.kind == "redirect_cargo_registry")
            .expect("fixture records a registry edit")
            .original = Some(Value::String(user_region.into()));

        let out = revert_cargo_redirect_purl(root, &mut state, PURL, false)
            .await
            .expect("revert succeeds");
        let cfg = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(
            cfg.contains("# corp mirror config"),
            "user region restored: {cfg}"
        );
        assert!(!cfg.contains("socket-patch-"), "block gone: {cfg}");
        assert!(
            out.reverted_files.iter().any(|f| f.contains(".cargo")),
            "{:?}",
            out.reverted_files
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// Corrupt-ledger guard, npm text kinds: an edit without an `original`
    /// fragment refuses and leaves the file and ledger untouched.
    #[tokio::test]
    async fn npm_text_edit_without_original_fragment_is_refused_fail_closed() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();
        state
            .edits
            .iter_mut()
            .find(|e| e.kind == "redirect_yarn_classic_entry")
            .expect("fixture records a classic edit")
            .original = None;

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("edit without an original must refuse");
        assert!(err.contains("records no original fragment"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            wired,
            "yarn.lock untouched (still hosted-wired)"
        );
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// yarn.lock deleted after the redirect: refuse; ledger intact.
    #[tokio::test]
    async fn npm_missing_text_lock_refuses_and_keeps_the_ledger() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        tokio::fs::remove_file(root.join("yarn.lock"))
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("deleted lock must refuse");
        assert!(err.contains("no longer exists"), "{err}");
        assert!(err.contains("yarn.lock"), "{err}");
        assert!(!root.join("yarn.lock").exists(), "not resurrected");
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// A user hand-restored the text lock to pristine: the revert is a clean
    /// no-op that still drops the ledger entries (the takeover is complete).
    #[tokio::test]
    async fn npm_hand_restored_text_lock_is_a_noop_that_drops_the_ledger() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        tokio::fs::write(root.join("yarn.lock"), classic_pristine())
            .await
            .unwrap();

        let out = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert!(
            out.reverted_files.is_empty(),
            "nothing rewritten: {:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            classic_pristine(),
            "yarn.lock untouched"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// package-lock.json deleted for the JSON kinds: the claim survives via
    /// the recorded-URL attribution (the lock can no longer vouch for the
    /// entry), then the replay refuses fail-closed.
    #[tokio::test]
    async fn npm_missing_package_lock_refuses_via_url_attribution() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "packages + dependencies edits");
        tokio::fs::remove_file(root.join("package-lock.json"))
            .await
            .unwrap();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("deleted lock must refuse");
        assert!(err.contains("no longer exists"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), 2, "ledger keeps the edits");
    }

    /// package-lock.json is no longer valid JSON: the disk-lock parse
    /// degrades to `None` (so the claim still happens via recorded URLs) and
    /// the replay refuses on the parse.
    #[tokio::test]
    async fn npm_invalid_json_package_lock_refuses_fail_closed() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        tokio::fs::write(root.join("package-lock.json"), "{ not json")
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("invalid JSON must refuse");
        assert!(err.contains("is not valid JSON"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            "{ not json",
            "file untouched"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// JSON-kind drift refusal: the v3 `packages` entry was re-resolved to a
    /// shape the ledger never saw — refuse, file byte-untouched.
    #[tokio::test]
    async fn npm_json_drifted_package_lock_entry_refuses_fail_closed() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("packages")
            .and_then(|p| p.get_mut("node_modules/left-pad"))
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                "resolved".into(),
                Value::String("https://corp.example/left-pad-1.3.0.tgz".into()),
            );
        let drifted = serde_json::to_string_pretty(&on_disk).unwrap();
        tokio::fs::write(root.join("package-lock.json"), &drifted)
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("drifted entry must refuse");
        assert!(err.contains("drifted"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            drifted,
            "nothing reached disk on refusal"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// A user hand-restored package-lock.json to pristine: both trees replay
    /// as `Ok(false)` no-ops and the ledger entries still drop.
    #[tokio::test]
    async fn npm_hand_restored_package_lock_is_a_noop_that_drops_the_ledger() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        tokio::fs::write(root.join("package-lock.json"), package_lock_pristine())
            .await
            .unwrap();

        let out = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert!(
            out.reverted_files.is_empty(),
            "nothing rewritten: {:?}",
            out.reverted_files
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            package_lock_pristine(),
            "package-lock.json untouched"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// npm upgraded the lock to a v3-only shape after the redirect (the
    /// legacy `dependencies` tree is gone) — the recorded v2 edit refuses,
    /// and the v3 entry's hosted wiring stays exactly as found (nothing
    /// half-applied).
    #[tokio::test]
    async fn npm_v2_dependencies_tree_gone_refuses_fail_closed() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .as_object_mut()
            .unwrap()
            .remove("dependencies")
            .expect("fixture v2 tree present");
        let v3_only = serde_json::to_string_pretty(&on_disk).unwrap();
        tokio::fs::write(root.join("package-lock.json"), &v3_only)
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("vanished v2 tree must refuse");
        assert!(
            err.contains("no longer holds a `dependencies` tree"),
            "{err}"
        );
        let after = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert_eq!(after, v3_only, "nothing reached disk on refusal");
        assert!(
            after.contains(NPM_URL),
            "the v3 entry keeps its hosted wiring: {after}"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// The v2 `dependencies` node for this purl vanished (the tree survives):
    /// `any_found` stays false and the replay refuses.
    #[tokio::test]
    async fn npm_v2_dependencies_node_gone_refuses_fail_closed() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("dependencies")
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("left-pad")
            .expect("fixture v2 node present");
        let pruned = serde_json::to_string_pretty(&on_disk).unwrap();
        tokio::fs::write(root.join("package-lock.json"), &pruned)
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("vanished v2 node must refuse");
        assert!(
            err.contains("`dependencies` entry") && err.contains("no longer exists"),
            "{err}"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            pruned,
            "nothing reached disk on refusal"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// A drift inside a v2 `dependencies` node propagates out of the
    /// recursive walk as the same fail-closed refusal.
    #[tokio::test]
    async fn npm_v2_dependencies_node_drift_refuses_fail_closed() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        let mut on_disk: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        on_disk
            .get_mut("dependencies")
            .and_then(|d| d.get_mut("left-pad"))
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("integrity".into(), Value::String("sha512-corp==".into()));
        let drifted = serde_json::to_string_pretty(&on_disk).unwrap();
        tokio::fs::write(root.join("package-lock.json"), &drifted)
            .await
            .unwrap();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect_err("drifted v2 node must refuse");
        assert!(err.contains("drifted"), "{err}");
        let after = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert_eq!(after, drifted, "nothing reached disk on refusal");
        assert!(
            after.contains(NPM_URL),
            "the v3 entry keeps its hosted wiring: {after}"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert_eq!(state.edits.len(), edits_before, "ledger keeps the edits");
    }

    /// Pristine v3-only lock whose entry has `resolved` but NO `integrity`
    /// key: the rewriter records `integrity: null` in `original`, so the
    /// revert must REMOVE the hosted integrity field, not leave it stale.
    fn no_integrity_lock_pristine() -> String {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                }
            }
        });
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap())
    }

    #[tokio::test]
    async fn npm_entry_without_integrity_round_trips_the_field_removal() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &no_integrity_lock_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(
            wired.contains("\"integrity\""),
            "the rewriter wrote a hosted integrity: {wired}"
        );

        let out = revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("revert succeeds");
        assert_eq!(out.reverted_files, vec!["package-lock.json".to_string()]);
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            no_integrity_lock_pristine(),
            "integrity key REMOVED on revert, not left null/stale"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    /// A bun.lock edit belonging to a DIFFERENT package is neither claimed
    /// nor a refusal: this purl's takeover proceeds and the foreign edit and
    /// its record stay in the ledger untouched.
    #[tokio::test]
    async fn npm_foreign_bun_edit_is_neither_claimed_nor_a_refusal() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        state
            .records
            .insert("pkg:npm/other@1.0.0".to_string(), record());
        state.edits.push(FileEdit {
            path: "bun.lock".into(),
            kind: "redirect_bun_lock_package".into(),
            action: "rewritten".into(),
            key: Some("other".into()),
            original: Some(Value::String(
                "    \"other\": [\"other@1.0.0\", \"reg\", {}, \"sha512-p==\"],".into(),
            )),
            new: Some(Value::String(
                "    \"other\": [\"other@http://127.0.0.1:5555/patch/npm/other/1.0.0/tok/6b7c/other-1.0.0.tgz\", {}, \"sha512-h==\"],"
                    .into(),
            )),
        });

        revert_npm_redirect_purl(root, &mut state, NPM_PURL, false)
            .await
            .expect("takeover succeeds despite the foreign bun edit");
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            classic_pristine(),
            "yarn.lock restored byte-identical"
        );
        assert_eq!(
            state.edits.len(),
            1,
            "the foreign bun edit survives: {:?}",
            state.edits
        );
        assert_eq!(state.edits[0].kind, "redirect_bun_lock_package");
        assert!(
            state.records.contains_key("pkg:npm/other@1.0.0")
                && !state.records.contains_key(NPM_PURL),
            "{:?}",
            state.records.keys()
        );
    }

    const GO_PURL: &str = "pkg:golang/example.com/lib@v1.10.0";
    const GO_UUID: &str = "7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a";
    const GO_OTHER_PURL: &str = "pkg:golang/example.com/other@v0.2.0";
    const GO_OTHER_UUID: &str = "8e9f0a1b-2c3d-4e4f-9a5b-6c7d8e9f0a1b";
    const GO_ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
    const GO_MOD_H1: &str = "h1:XgagPTRZSCprrzR+3Ro36/XJpibdovhAbsKThYI8bxg=";

    fn go_override(module: &str, version: &str, uuid: &str) -> crate::patch::redirect::DepOverride {
        let socket_module = format!("patch.socket.dev/gopatch/{uuid}");
        let socket_version = format!("{version}-socketpatch.1");
        serde_json::from_value(serde_json::json!({
            "ecosystem": "golang",
            "name": module,
            "version": version,
            "token": "",
            "patchUuid": uuid,
            "artifactUrl": format!("https://patch.socket.dev/{socket_module}/@v/{socket_version}.zip"),
            "registryOverride": {
                "kind": "goproxy",
                "indexUrl": "https://patch.socket.dev",
                "identifiers": {
                    "name": module, "version": version,
                    "goModulePath": socket_module,
                    "goModuleVersion": socket_version,
                },
            },
            "integrity": { "dirhashH1": GO_ZIP_H1, "goModH1": GO_MOD_H1 },
        }))
        .unwrap()
    }

    /// go's own go.sum order: `v1.9.0/go.mod` sorts BEFORE `v1.10.0`
    /// (semver), although it is bytewise greater.
    fn go_pristine(eol: &str) -> (String, String) {
        let go_mod = "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/lib v1.10.0\n\texample.com/other v0.2.0\n)\n"
            .replace('\n', eol);
        let go_sum = "example.com/leaf v1.0.0 h1:L=\n\
                      example.com/leaf v1.0.0/go.mod h1:LM=\n\
                      example.com/lib v1.9.0/go.mod h1:N9=\n\
                      example.com/lib v1.10.0 h1:T=\n\
                      example.com/lib v1.10.0/go.mod h1:TM=\n\
                      example.com/other v0.2.0 h1:O=\n\
                      example.com/other v0.2.0/go.mod h1:OM=\n"
            .replace('\n', eol);
        (go_mod, go_sum)
    }

    /// Both modules hosted-redirected by the real rewriter, written to disk.
    async fn go_redirected_fixture(eol: &str) -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let (go_mod, go_sum) = go_pristine(eol);
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("go.mod".into(), go_mod);
        files.insert("go.sum".into(), go_sum);
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(
            &files,
            &[
                go_override("example.com/lib", "v1.10.0", GO_UUID),
                go_override("example.com/other", "v0.2.0", GO_OTHER_UUID),
            ],
        );
        assert!(rewrite.warnings.is_empty(), "{:?}", rewrite.warnings);
        for (rel, content) in &rewrite.files {
            tokio::fs::write(tmp.path().join(rel), content)
                .await
                .unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        let mut lib = record();
        lib.uuid = GO_UUID.to_string();
        let mut other = record();
        other.uuid = GO_OTHER_UUID.to_string();
        state.records.insert(GO_PURL.to_string(), lib);
        state.records.insert(GO_OTHER_PURL.to_string(), other);
        (tmp, state)
    }

    /// hosted → vendored takeover of one Go module: its replace and gopatch
    /// go.sum lines go, its pruned go.sum pair comes back where go sorts it,
    /// and its ledger record is dropped. The other hosted module is intact.
    #[tokio::test]
    async fn golang_per_purl_revert_unwinds_only_that_module() {
        for eol in ["\n", "\r\n"] {
            let (tmp, mut state) = go_redirected_fixture(eol).await;
            let root = tmp.path();
            assert!(redirect_revert_supported(GO_PURL));
            revert_redirect_purl(root, &mut state, GO_PURL, false)
                .await
                .expect("golang takeover revert succeeds");

            let go_mod = tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap();
            let go_sum = tokio::fs::read_to_string(root.join("go.sum"))
                .await
                .unwrap();
            assert!(!go_mod.contains(GO_UUID), "{go_mod:?}");
            assert!(
                go_mod.contains(&format!(
                    "replace example.com/other v0.2.0 => patch.socket.dev/gopatch/{GO_OTHER_UUID}"
                )),
                "{go_mod:?}"
            );
            let expected_sum = format!(
                "example.com/leaf v1.0.0 h1:L={eol}\
                 example.com/leaf v1.0.0/go.mod h1:LM={eol}\
                 example.com/lib v1.9.0/go.mod h1:N9={eol}\
                 example.com/lib v1.10.0 h1:T={eol}\
                 example.com/lib v1.10.0/go.mod h1:TM={eol}\
                 patch.socket.dev/gopatch/{GO_OTHER_UUID} v0.2.0-socketpatch.1 {GO_ZIP_H1}{eol}\
                 patch.socket.dev/gopatch/{GO_OTHER_UUID} v0.2.0-socketpatch.1/go.mod {GO_MOD_H1}{eol}"
            );
            assert_eq!(go_sum, expected_sum, "eol {eol:?}");
            assert!(!state.records.contains_key(GO_PURL));
            assert!(state.records.contains_key(GO_OTHER_PURL));
            assert!(
                state.edits.iter().all(|e| {
                    let text = format!("{:?}{:?}{:?}", e.key, e.new, e.original);
                    !text.contains(GO_UUID) && !text.contains("example.com/lib")
                }),
                "{:?}",
                state.edits
            );

            // The remaining module unwinds through the same path, back to
            // the pristine bytes.
            revert_redirect_purl(root, &mut state, GO_OTHER_PURL, false)
                .await
                .expect("second revert succeeds");
            let (pristine_mod, pristine_sum) = go_pristine(eol);
            assert_eq!(
                tokio::fs::read_to_string(root.join("go.mod"))
                    .await
                    .unwrap(),
                pristine_mod
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("go.sum"))
                    .await
                    .unwrap(),
                pristine_sum
            );
            assert!(state.records.is_empty() && state.edits.is_empty());
        }
    }

    /// A go.mod whose socket replace was hand-edited away from the recorded
    /// directive has drifted: refuse, byte-untouched, ledger kept.
    #[tokio::test]
    async fn golang_per_purl_revert_refuses_a_drifted_replace() {
        let (tmp, mut state) = go_redirected_fixture("\n").await;
        let root = tmp.path();
        let go_mod = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();
        let drifted = go_mod.replace(
            &format!("patch.socket.dev/gopatch/{GO_UUID} v1.10.0-socketpatch.1"),
            "../my-fork",
        );
        tokio::fs::write(root.join("go.mod"), &drifted)
            .await
            .unwrap();
        let go_sum = tokio::fs::read_to_string(root.join("go.sum"))
            .await
            .unwrap();
        let before = state.clone();

        let err = revert_redirect_purl(root, &mut state, GO_PURL, false)
            .await
            .expect_err("a drifted replace refuses");
        assert!(err.contains("go.mod"), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            drifted
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.sum"))
                .await
                .unwrap(),
            go_sum
        );
        assert_eq!(state.records.len(), before.records.len());
        assert_eq!(state.edits.len(), before.edits.len());
    }
}
