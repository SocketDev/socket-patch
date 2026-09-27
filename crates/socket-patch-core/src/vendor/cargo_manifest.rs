//! Read / write the workspace-root `Cargo.toml` `[patch.crates-io]` wiring of
//! the cargo vendor backend (v5+; the pre-v5 backend wrote the same entry to
//! `.cargo/config.toml` — see [`super::cargo_config`] for the legacy reader
//! and the migration cleanup).
//!
//! ## Why the manifest
//! `Cargo.toml` is the file every Socket scanner already ingests, so the
//! `.socket/vendor/cargo/<uuid>/<name>-<version>` path — and with it the
//! patch uuid — is recoverable for SBOM annotation without uploading
//! `.cargo/config*` (which may hold registry tokens and other secrets).
//! A single vendored version per crate also builds, with no network, on
//! cargo older than 1.56 (the floor of config-file `[patch]`); two vendored
//! versions of ONE crate additionally need `--offline` (or a reachable
//! registry index) on such old cargo, which loads the crates.io index to
//! tell them apart — current stable does not.
//!
//! ## Entry shape and keys
//! `<name>-socket-<first 8 hex of the uuid> = { package = "<name>", path =
//! ".socket/vendor/cargo/<uuid>/<name>-<version>" }` under the manifest's
//! `[patch.crates-io]` (the workspace-root Cargo.toml, next to the
//! `Cargo.lock` the backend detaches). The key is ALWAYS the Socket-owned
//! renamed form, never the bare crate name: cargo lets any config-file
//! `[patch]` item (project, ancestor directory, or `$CARGO_HOME`) replace
//! the manifest item with the same key regardless of version, so a bare key
//! could be silently shadowed by a user's same-named config entry. With a
//! distinct key a conflicting same-version config patch is a loud cargo
//! error instead, and several versions of one crate get distinct keys. The
//! fallback when the short key is taken is `<name>-socket-<uuid hex>`.
//!
//! A manifest that also spells the crates.io source by URL
//! (`[patch."https://github.com/rust-lang/crates.io-index"]`) is refused:
//! cargo keys manifest `[patch]` tables by URL and that table silently
//! replaces `[patch.crates-io]` wholesale.
//!
//! ## Ownership (no sidecar)
//! Exactly as for the legacy config: an entry is Socket-owned iff its `path`
//! is a root-anchored relative path under THIS project's
//! `.socket/vendor/cargo/`. Lookups are KEY-AGNOSTIC — an entry belongs to
//! `name@version` when its effective crate name (`package` when renamed,
//! else the key) is `name` and its path's leaf is `<name>-<version>` — so a
//! re-run, a revert, and lockfile discovery never depend on which key a
//! previous run picked. User-authored entries are never modified.
//!
//! ## Formatting
//! Edits go through `toml_edit` (comments, ordering, and spacing survive),
//! and [`reconcile_line_endings`] maps the result back onto the original
//! file's line endings (`toml_edit` renders LF only): CRLF and mixed files
//! keep every untouched line's ending, new lines take the file's dominant
//! ending, the presence or absence of a trailing newline is preserved, and
//! a leading UTF-8 BOM (which `toml_edit` drops) is put back — so a revert
//! with nothing else changed restores the manifest byte for byte. A revert
//! keeps a user's explicit `[patch]` header, and a `[patch.crates-io]`
//! header that another table follows or that carries a comment (the table
//! socket-patch creates is appended last and bare).

use std::path::Path;

use toml_edit::{DocumentMut, InlineTable, Item, Value};

use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};

use super::cargo_config::{ensure_table_like, patch_entries, path_is_socket_owned};

/// The root manifest, relative to the project root.
pub const CARGO_TOML: &str = "Cargo.toml";

/// The infix of the Socket-owned key
/// (`<name>-socket-<first 8 hex of the uuid>`).
pub const SOCKET_KEY_INFIX: &str = "-socket-";

/// The index URL cargo maps the `crates-io` `[patch]` key to.
pub const CRATES_IO_INDEX_URL: &str = "https://github.com/rust-lang/crates.io-index";

/// Does a `[patch.<source>]` key spell the crates.io index by URL
/// (case, a trailing `/`, and a `.git` suffix ignored — conservative)?
pub fn is_crates_io_url_alias(source: &str) -> bool {
    let lower = source.trim().to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('/');
    trimmed.strip_suffix(".git").unwrap_or(trimmed) == CRATES_IO_INDEX_URL
}

/// Does a `[patch.<source>]` key name crates.io (`crates-io` or the URL)?
pub fn is_crates_io_source(source: &str) -> bool {
    source == "crates-io" || is_crates_io_url_alias(source)
}

/// The `[patch.<url>]` keys of a document that spell crates.io by URL.
pub fn crates_io_url_alias_tables(doc: &DocumentMut) -> Vec<String> {
    doc.get("patch")
        .and_then(Item::as_table_like)
        .map(|patch| {
            patch
                .iter()
                .filter(|(source, item)| is_crates_io_url_alias(source) && item.is_table_like())
                .map(|(source, _)| source.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Is `key` a Socket-owned key for crate `name`
/// (`<name>-socket-<8 or 32 lowercase hex>`)?
pub fn is_socket_key(key: &str, name: &str) -> bool {
    key.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(SOCKET_KEY_INFIX))
        .is_some_and(|hex| {
            (hex.len() == 8 || hex.len() == 32)
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

// ── pure reader ──────────────────────────────────────────────────────────────
// The read-only view of a parsed manifest shared by the writer below, the
// vendor backend, and lockfile discovery.

/// One crates.io `[patch]` item of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPatchEntry {
    /// The `[patch.<source>]` key: `crates-io`, or a URL spelling of it.
    pub source: String,
    /// The item's key as written.
    pub key: String,
    /// The crate it patches: `package = "…"` when renamed, else the key.
    pub name: String,
    /// The `path` value as written, `None` for a git / registry patch.
    pub path: Option<String>,
    /// True iff `path` is under this project's `.socket/vendor/cargo/`.
    pub socket_owned: bool,
}

/// Every crates.io `[patch]` item of a parsed manifest (or config) —
/// `[patch.crates-io]` and its URL spellings ([`is_crates_io_source`]) — in
/// document order, header, dotted, sub-table and inline forms alike.
pub fn crates_io_patch_entries(doc: &DocumentMut) -> Vec<ManifestPatchEntry> {
    patch_entries(doc)
        .into_iter()
        .filter(|entry| is_crates_io_source(entry.source))
        .map(|entry| ManifestPatchEntry {
            source: entry.source.to_string(),
            key: entry.key.to_string(),
            name: entry.name.to_string(),
            path: entry.path.map(str::to_string),
            socket_owned: entry.path.is_some_and(path_is_socket_owned),
        })
        .collect()
}

/// A Socket-owned path normalised to the canonical
/// `.socket/vendor/cargo/<uuid>/<leaf>` spelling (forward slashes, no `./`
/// segments, no trailing slash); `None` for a path that is not Socket-owned.
pub fn normalize_socket_path(path: &str) -> Option<String> {
    if !path_is_socket_owned(path) {
        return None;
    }
    let norm = path.replace('\\', "/");
    let segments: Vec<&str> = norm
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    Some(segments.join("/"))
}

/// Is `path` a Socket-owned copy of exactly `name@version`: under
/// `.socket/vendor/cargo/<one uuid level>/` with the leaf
/// `<name>-<version>`?
pub fn is_socket_copy_of(path: &str, name: &str, version: &str) -> bool {
    let Some(norm) = normalize_socket_path(path) else {
        return false;
    };
    let segments: Vec<&str> = norm.split('/').collect();
    segments.len() == 5 && segments[4] == format!("{name}-{version}")
}

/// Does `entry` wire `name@version` to one of this project's copies?
pub fn entry_wires(entry: &ManifestPatchEntry, name: &str, version: &str) -> bool {
    entry.socket_owned
        && entry.name == name
        && entry
            .path
            .as_deref()
            .is_some_and(|p| is_socket_copy_of(p, name, version))
}

/// The key a fresh entry for `name` takes: `<name>-socket-<uuid8>`, else
/// `<name>-socket-<uuid without dashes>` — never the bare crate name (see
/// the module docs). `taken` answers whether a key is occupied (the
/// manifest table, plus every config-file `[patch]` key cargo merges).
/// `None` when every candidate is taken.
pub fn choose_key(name: &str, uuid: &str, taken: impl Fn(&str) -> bool) -> Option<String> {
    let compact: String = uuid
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let short: String = compact.chars().take(8).collect();
    [
        format!("{name}{SOCKET_KEY_INFIX}{short}"),
        format!("{name}{SOCKET_KEY_INFIX}{compact}"),
    ]
    .into_iter()
    .find(|key| !taken(key))
}

/// Map `edited` (LF-only `toml_edit` output for `original`) back onto
/// `original`'s line endings. Lines are aligned by content (longest common
/// subsequence over the region between the common prefix and suffix — the
/// edits here are localised): an unchanged line keeps its original ending,
/// an inserted line takes the file's dominant ending, a deleted line goes.
/// The presence of a trailing newline is preserved.
pub fn reconcile_line_endings(original: &str, edited: &str) -> String {
    let orig: Vec<(&str, &str)> = split_lines(original);
    let crlf = orig.iter().filter(|(_, e)| *e == "\r\n").count();
    let lf = orig.iter().filter(|(_, e)| *e == "\n").count();
    let eol = if crlf > lf { "\r\n" } else { "\n" };
    let new: Vec<&str> = split_lines(edited).into_iter().map(|(l, _)| l).collect();

    let mut pre = 0;
    while pre < orig.len() && pre < new.len() && orig[pre].0 == new[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < orig.len() - pre
        && suf < new.len() - pre
        && orig[orig.len() - 1 - suf].0 == new[new.len() - 1 - suf]
    {
        suf += 1;
    }
    let o_mid = &orig[pre..orig.len() - suf];
    let n_mid = &new[pre..new.len() - suf];

    // `Some(i)`: new line j keeps original line pre+i; `None`: inserted.
    let mut mapping: Vec<Option<usize>> = (0..pre).map(Some).collect();
    if o_mid.len().saturating_mul(n_mid.len()) <= 4_000_000 {
        let (n, m) = (o_mid.len(), n_mid.len());
        let mut dp = vec![0u32; (n + 1) * (m + 1)];
        let at = |i: usize, j: usize| i * (m + 1) + j;
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                dp[at(i, j)] = if o_mid[i].0 == n_mid[j] {
                    dp[at(i + 1, j + 1)] + 1
                } else {
                    dp[at(i + 1, j)].max(dp[at(i, j + 1)])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while j < m {
            if i < n && o_mid[i].0 == n_mid[j] {
                mapping.push(Some(pre + i));
                i += 1;
                j += 1;
            } else if i < n && dp[at(i + 1, j)] >= dp[at(i, j + 1)] {
                i += 1;
            } else {
                mapping.push(None);
                j += 1;
            }
        }
    } else {
        mapping.extend(std::iter::repeat_n(None, n_mid.len()));
    }
    mapping.extend((orig.len() - suf..orig.len()).map(Some));

    let mut out = String::with_capacity(edited.len() + new.len());
    for (j, keep) in mapping.iter().enumerate() {
        match keep {
            Some(i) => {
                out.push_str(orig[*i].0);
                out.push_str(if orig[*i].1.is_empty() {
                    eol
                } else {
                    orig[*i].1
                });
            }
            None => {
                out.push_str(new[j]);
                out.push_str(eol);
            }
        }
    }
    let trailing = original.is_empty() || original.ends_with('\n');
    if !trailing {
        if let Some(stripped) = out.strip_suffix("\r\n").or_else(|| out.strip_suffix('\n')) {
            out.truncate(stripped.len());
        }
    }
    out
}

/// `(content, ending)` per line, ending ∈ {`"\r\n"`, `"\n"`, `""`}; an
/// empty text has no lines.
fn split_lines(text: &str) -> Vec<(&str, &str)> {
    text.split_inclusive('\n')
        .map(|seg| {
            if let Some(content) = seg.strip_suffix("\r\n") {
                (content, "\r\n")
            } else if let Some(content) = seg.strip_suffix('\n') {
                (content, "\n")
            } else {
                (seg, "")
            }
        })
        .collect()
}

// ── pure transforms ──────────────────────────────────────────────────────────

/// Why the manifest could not be read or edited. Each variant has a stable
/// refusal code ([`ManifestError::code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Missing, not a regular file, or unreadable.
    Unreadable(String),
    /// Not valid TOML, or `[patch.crates-io]` is not a table.
    Unparseable(String),
    /// No free key for the entry (every Socket-owned candidate is taken).
    NoFreeKey(String),
    /// The manifest spells crates.io by URL in a `[patch]` table, which
    /// makes cargo ignore `[patch.crates-io]`.
    SourceAlias(String),
    /// The write failed.
    Write(String),
}

impl ManifestError {
    /// The stable refusal / warning code.
    pub fn code(&self) -> &'static str {
        match self {
            ManifestError::Unreadable(_) => "cargo_manifest_unreadable",
            ManifestError::Unparseable(_) => "cargo_manifest_unparseable",
            ManifestError::NoFreeKey(_) => "cargo_manifest_patch_key_conflict",
            ManifestError::SourceAlias(_) => "cargo_manifest_patch_source_alias",
            ManifestError::Write(_) => "cargo_manifest_write_failed",
        }
    }

    /// The human detail.
    pub fn detail(&self) -> &str {
        match self {
            ManifestError::Unreadable(d)
            | ManifestError::Unparseable(d)
            | ManifestError::NoFreeKey(d)
            | ManifestError::SourceAlias(d)
            | ManifestError::Write(d) => d,
        }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

/// Parse a manifest (CRLF and a leading BOM tolerated).
pub fn parse_manifest(content: &str) -> Result<DocumentMut, ManifestError> {
    split_bom(content)
        .1
        .replace("\r\n", "\n")
        .parse::<DocumentMut>()
        .map_err(|e| ManifestError::Unparseable(format!("Cargo.toml is not valid TOML: {e}")))
}

/// `(bom, rest)`: a leading UTF-8 BOM (`toml_edit` accepts it but never
/// renders it back), split off so an edit can restore it.
fn split_bom(content: &str) -> (&str, &str) {
    match content.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", content),
    }
}

/// `edited` (the `toml_edit` rendering of `original` after an edit) mapped
/// back onto `original`'s BOM and line endings.
fn render_like(original: &str, edited: &str) -> String {
    let (bom, body) = split_bom(original);
    format!("{bom}{}", reconcile_line_endings(body, edited))
}

/// Refuse a manifest that spells crates.io by URL in `[patch]`
/// ([`ManifestError::SourceAlias`]).
pub fn check_source_alias(doc: &DocumentMut) -> Result<(), ManifestError> {
    match crates_io_url_alias_tables(doc).first() {
        None => Ok(()),
        Some(alias) => Err(ManifestError::SourceAlias(format!(
            "Cargo.toml has a `[patch.\"{alias}\"]` table: cargo treats it as the same \
             source as `[patch.crates-io]` and lets it replace that table wholesale, so a \
             vendored `[patch.crates-io]` entry would be silently ignored; move its \
             entries under `[patch.crates-io]` and re-run"
        ))),
    }
}

/// The result of [`upsert_patch_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upsert {
    /// The new manifest text, `None` when already in the desired state.
    pub content: Option<String>,
    /// The key the entry lives under.
    pub key: String,
    /// The path a pre-existing Socket-owned entry for `name@version` held.
    pub prior_path: Option<String>,
}

/// Wire `name@version` to `rel_path` in the manifest's `[patch.crates-io]`.
/// A Socket-owned entry already wiring `name@version` (any uuid) is
/// refreshed in place when it sits under a Socket-owned key that no config
/// file uses; otherwise it moves to a fresh [`choose_key`] key (a key in
/// `reserved` — every config-file `[patch]` key — counts as taken, since a
/// config item replaces the manifest item with the same key). Extra
/// Socket-owned duplicates for `name@version` are dropped. User-authored
/// entries are never touched. A `[patch.<crates.io URL>]` table refuses
/// ([`ManifestError::SourceAlias`]).
pub fn upsert_patch_entry(
    content: &str,
    name: &str,
    version: &str,
    uuid: &str,
    rel_path: &str,
    reserved: &[String],
) -> Result<Upsert, ManifestError> {
    let mut doc = parse_manifest(content)?;
    check_source_alias(&doc)?;
    let mine: Vec<ManifestPatchEntry> = crates_io_patch_entries(&doc)
        .into_iter()
        .filter(|e| e.source == "crates-io" && entry_wires(e, name, version))
        .collect();
    let is_reserved = |k: &str| reserved.iter().any(|r| r == k);
    let root = doc.as_table_mut();
    let patch = ensure_table_like(root, "patch", true).map_err(ManifestError::Unparseable)?;
    let crates_io =
        ensure_table_like(patch, "crates-io", false).map_err(ManifestError::Unparseable)?;

    let mut changed = false;
    let fresh_key = |crates_io: &dyn toml_edit::TableLike| {
        choose_key(name, uuid, |k| crates_io.contains_key(k) || is_reserved(k)).ok_or_else(|| {
            ManifestError::NoFreeKey(format!(
                "every `[patch.crates-io]` key socket-patch could use for {name}@{version} \
                 is already taken in Cargo.toml or a cargo config file"
            ))
        })
    };
    let fresh_entry = || {
        let mut entry = InlineTable::new();
        entry.insert("package", Value::from(name));
        entry.insert("path", Value::from(rel_path));
        Item::Value(Value::InlineTable(entry))
    };
    let (key, prior_path) = match mine.first() {
        Some(existing) if !is_socket_key(&existing.key, name) || is_reserved(&existing.key) => {
            // A bare-name (hand-copied / pre-release) or config-shadowed key:
            // move the entry to a fresh Socket-owned key.
            for entry in &mine {
                crates_io.remove(&entry.key);
            }
            let key = fresh_key(&*crates_io)?;
            crates_io.insert(&key, fresh_entry());
            changed = true;
            (key, existing.path.clone())
        }
        Some(existing) => {
            for dup in &mine[1..] {
                crates_io.remove(&dup.key);
                changed = true;
            }
            let current = existing.path.as_deref().and_then(normalize_socket_path);
            if current.as_deref() != Some(rel_path) {
                let path_item = crates_io
                    .get_mut(&existing.key)
                    .and_then(Item::as_table_like_mut)
                    .and_then(|t| t.get_mut("path"))
                    .and_then(Item::as_value_mut)
                    .ok_or_else(|| {
                        ManifestError::Unparseable(format!(
                            "`patch.crates-io.{}` has no editable `path`",
                            existing.key
                        ))
                    })?;
                let decor = path_item.decor().clone();
                *path_item = Value::from(rel_path);
                *path_item.decor_mut() = decor;
                changed = true;
            }
            (existing.key.clone(), existing.path.clone())
        }
        None => {
            let key = fresh_key(&*crates_io)?;
            crates_io.insert(&key, fresh_entry());
            changed = true;
            (key, None)
        }
    };
    let content = changed.then(|| render_like(content, &doc.to_string()));
    Ok(Upsert {
        content,
        key,
        prior_path,
    })
}

/// Remove every Socket-owned `[patch.crates-io]` entry wiring `name@version`
/// (key-agnostic), then clean up the tables the removal emptied: an emptied
/// `[patch.crates-io]` is dropped unless it looks user-authored (another
/// table follows it, or its header carries a comment — the table
/// socket-patch creates is appended last and bare), an emptied `[patch]` is
/// dropped unless the user wrote an explicit `[patch]` header, and a
/// `[patch.crates-io]` left holding only sub-tables goes back to implicit
/// (no bare header). A user-authored or absent entry is a no-op (`None`).
pub fn remove_patch_entries(
    content: &str,
    name: &str,
    version: &str,
) -> Result<Option<String>, ManifestError> {
    let mut doc = parse_manifest(content)?;
    let keys: Vec<String> = crates_io_patch_entries(&doc)
        .into_iter()
        .filter(|e| e.source == "crates-io" && entry_wires(e, name, version))
        .map(|e| e.key)
        .collect();
    if keys.is_empty() {
        return Ok(None);
    }
    let last_position = max_table_position(doc.as_table());
    let mut patch_explicit = false;
    if let Some(patch_item) = doc.get_mut("patch") {
        patch_explicit = patch_item.as_table().is_some_and(|t| !t.is_implicit());
        if let Some(patch) = patch_item.as_table_like_mut() {
            let mut prune_crates_io = false;
            if let Some(crates_io) = patch.get_mut("crates-io") {
                let mut emptied = false;
                if let Some(table) = crates_io.as_table_like_mut() {
                    for key in &keys {
                        table.remove(key);
                    }
                    emptied = table.is_empty();
                }
                match crates_io.as_table_mut() {
                    Some(table) if emptied => {
                        let followed = table
                            .position()
                            .zip(last_position)
                            .is_some_and(|(own, last)| own < last);
                        let commented = table
                            .decor()
                            .suffix()
                            .and_then(|s| s.as_str())
                            .is_some_and(|s| s.contains('#'));
                        prune_crates_io = !followed && !commented;
                    }
                    Some(table) => {
                        if table.iter().all(|(_, item)| item.is_table()) {
                            table.set_implicit(true);
                        }
                    }
                    None => prune_crates_io = emptied,
                }
            }
            if prune_crates_io {
                patch.remove("crates-io");
            }
        }
    }
    if !patch_explicit
        && doc
            .get("patch")
            .and_then(Item::as_table_like)
            .is_some_and(|t| t.is_empty())
    {
        doc.as_table_mut().remove("patch");
    }
    Ok(Some(render_like(content, &doc.to_string())))
}

/// The greatest document position of any header table under `table`.
fn max_table_position(table: &toml_edit::Table) -> Option<isize> {
    table
        .iter()
        .filter_map(|(_, item)| item.as_table())
        .flat_map(|t| [t.position(), max_table_position(t)])
        .flatten()
        .max()
}

// ── manifest I/O ─────────────────────────────────────────────────────────────

/// Guarded read of `<project_root>/Cargo.toml` (a FIFO / device / directory
/// squatting the path errors instead of blocking).
pub async fn read_manifest(project_root: &Path) -> Result<String, ManifestError> {
    let path = project_root.join(CARGO_TOML);
    read_regular_to_string(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ManifestError::Unreadable(format!(
                "no Cargo.toml next to the project's Cargo.lock ({})",
                path.display()
            ))
        } else {
            ManifestError::Unreadable(format!("cannot read {}: {e}", path.display()))
        }
    })
}

/// The root manifest's `[patch.crates-io]` entries. Read-only and fail-soft:
/// a missing or malformed manifest yields none.
pub async fn read_patch_entries(project_root: &Path) -> Vec<ManifestPatchEntry> {
    match read_manifest(project_root).await {
        Ok(text) => parse_manifest(&text)
            .map(|doc| crates_io_patch_entries(&doc))
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// What [`ensure_patch_entry`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ensured {
    /// Whether the manifest changed (or would, under `dry_run`).
    pub changed: bool,
    /// The key the entry lives under.
    pub key: String,
    /// The path a pre-existing Socket-owned entry for `name@version` held.
    pub prior_path: Option<String>,
}

/// [`upsert_patch_entry`] against the project's root manifest, written
/// atomically (mode-preserving) unless `dry_run`.
pub async fn ensure_patch_entry(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    rel_path: &str,
    reserved: &[String],
    dry_run: bool,
) -> Result<Ensured, ManifestError> {
    let content = read_manifest(project_root).await?;
    let up = upsert_patch_entry(&content, name, version, uuid, rel_path, reserved)?;
    let changed = up.content.is_some();
    if let (Some(new), false) = (up.content, dry_run) {
        write_manifest(project_root, &new).await?;
    }
    Ok(Ensured {
        changed,
        key: up.key,
        prior_path: up.prior_path,
    })
}

/// [`remove_patch_entries`] against the project's root manifest. A missing
/// manifest has nothing to remove (`Ok(false)`); an unparseable one is an
/// error (fail closed — the entry may still be live).
pub async fn drop_patch_entries(
    project_root: &Path,
    name: &str,
    version: &str,
    dry_run: bool,
) -> Result<bool, ManifestError> {
    let content = match read_regular_to_string(&project_root.join(CARGO_TOML)).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(ManifestError::Unreadable(format!(
                "cannot read Cargo.toml: {e}"
            )))
        }
    };
    match remove_patch_entries(&content, name, version)? {
        None => Ok(false),
        Some(new) => {
            if !dry_run {
                write_manifest(project_root, &new).await?;
            }
            Ok(true)
        }
    }
}

async fn write_manifest(project_root: &Path, content: &str) -> Result<(), ManifestError> {
    let path = project_root.join(CARGO_TOML);
    atomic_write_bytes_preserving_mode(&path, content.as_bytes())
        .await
        .map_err(|e| ManifestError::Write(format!("write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID2: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

    fn rel(uuid: &str, name: &str, version: &str) -> String {
        format!(".socket/vendor/cargo/{uuid}/{name}-{version}")
    }

    const PKG: &str =
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n";

    fn add(content: &str, name: &str, version: &str, uuid: &str) -> Upsert {
        upsert_patch_entry(content, name, version, uuid, &rel(uuid, name, version), &[]).unwrap()
    }

    fn add_err(content: &str, name: &str, version: &str, uuid: &str) -> ManifestError {
        upsert_patch_entry(content, name, version, uuid, &rel(uuid, name, version), &[])
            .unwrap_err()
    }

    fn entries(content: &str) -> Vec<ManifestPatchEntry> {
        crates_io_patch_entries(&parse_manifest(content).unwrap())
    }

    #[test]
    fn creates_the_table_and_reverts_byte_identical() {
        let up = add(PKG, "cfg-if", "1.0.4", UUID);
        let out = up.content.expect("changed");
        assert_eq!(up.key, "cfg-if-socket-9f6b2c4e");
        assert_eq!(up.prior_path, None);
        assert_eq!(
            out,
            format!(
                "{PKG}\n[patch.crates-io]\ncfg-if-socket-9f6b2c4e = {{ package = \"cfg-if\", \
                 path = \"{}\" }}\n",
                rel(UUID, "cfg-if", "1.0.4")
            )
        );
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, PKG, "revert restores the manifest byte for byte");
    }

    #[test]
    fn idempotent_rerun_is_a_noop() {
        let out = add(PKG, "cfg-if", "1.0.4", UUID).content.unwrap();
        let again = add(&out, "cfg-if", "1.0.4", UUID);
        assert_eq!(again.content, None);
        assert_eq!(again.key, "cfg-if-socket-9f6b2c4e");
        assert_eq!(
            again.prior_path.as_deref(),
            Some(rel(UUID, "cfg-if", "1.0.4").as_str())
        );
    }

    #[test]
    fn crlf_manifest_keeps_crlf_everywhere() {
        let crlf = PKG.replace('\n', "\r\n");
        let out = add(&crlf, "cfg-if", "1.0.4", UUID).content.unwrap();
        assert!(!out.replace("\r\n", "").contains('\n'), "{out:?}");
        assert!(
            out.contains("[patch.crates-io]\r\ncfg-if-socket-9f6b2c4e = {"),
            "{out:?}"
        );
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, crlf);
    }

    #[test]
    fn mixed_line_endings_keep_every_untouched_line() {
        let mixed = "[package]\r\nname = \"app\"\nversion = \"0.1.0\"\r\n\r\n[dependencies]\ncfg-if = \"1\"\r\n";
        let out = add(mixed, "cfg-if", "1.0.4", UUID).content.unwrap();
        assert!(out.starts_with(mixed), "{out:?}");
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, mixed);
    }

    #[test]
    fn missing_trailing_newline_is_preserved() {
        let bare = PKG.trim_end();
        let out = add(bare, "cfg-if", "1.0.4", UUID).content.unwrap();
        assert!(!out.ends_with('\n'), "{out:?}");
        assert!(
            out.contains("cfg-if = \"1\"\n\n[patch.crates-io]\n"),
            "{out:?}"
        );
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, bare);
    }

    #[test]
    fn comments_and_existing_user_entries_survive() {
        let src = "# top comment\n[package]\nname = \"app\" # inline\nversion = \"0.1.0\"\n\n\
                   [patch.crates-io]\n# user fork\nserde = { git = \"https://example.com/serde\" }\n\n\
                   [dependencies]\ncfg-if = \"1\"\n";
        let out = add(src, "cfg-if", "1.0.4", UUID).content.unwrap();
        assert!(out.contains("# top comment\n"));
        assert!(out.contains("name = \"app\" # inline\n"));
        assert!(out.contains(&format!(
            "# user fork\nserde = {{ git = \"https://example.com/serde\" }}\n\
             cfg-if-socket-9f6b2c4e = {{ package = \"cfg-if\", path = \"{}\" }}\n",
            rel(UUID, "cfg-if", "1.0.4")
        )));
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, src, "only our line goes; the user's table stays");
    }

    #[test]
    fn subtable_only_crates_io_goes_back_to_implicit() {
        let src = "[package]\nname = \"app\"\n\n[patch.crates-io.serde]\npath = \"../serde\"\n";
        let out = add(src, "cfg-if", "1.0.4", UUID).content.unwrap();
        let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
            .unwrap()
            .unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn virtual_workspace_manifest() {
        let src = "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n";
        let out = add(src, "cfg-if", "1.0.4", UUID).content.unwrap();
        let doc = parse_manifest(&out).unwrap();
        assert!(doc.get("package").is_none());
        assert_eq!(entries(&out).len(), 1);
        assert_eq!(
            remove_patch_entries(&out, "cfg-if", "1.0.4")
                .unwrap()
                .unwrap(),
            src
        );
    }

    #[test]
    fn second_version_gets_a_socket_key_with_package() {
        let first = add(PKG, "cfg-if", "1.0.4", UUID);
        assert_eq!(first.key, "cfg-if-socket-9f6b2c4e");
        let one = first.content.unwrap();
        let up = add(&one, "cfg-if", "0.1.10", UUID2);
        assert_eq!(up.key, "cfg-if-socket-0a1b2c3d");
        let two = up.content.unwrap();
        assert!(
            two.contains(&format!(
                "cfg-if-socket-0a1b2c3d = {{ package = \"cfg-if\", path = \"{}\" }}",
                rel(UUID2, "cfg-if", "0.1.10")
            )),
            "{two}"
        );
        let es = entries(&two);
        assert_eq!(es.len(), 2);
        assert!(es.iter().all(|e| e.name == "cfg-if" && e.socket_owned));
        // Each version's re-run finds its own entry, whatever its key.
        assert_eq!(add(&two, "cfg-if", "1.0.4", UUID).content, None);
        assert_eq!(add(&two, "cfg-if", "0.1.10", UUID2).content, None);
        // Reverting one version leaves the other.
        let back = remove_patch_entries(&two, "cfg-if", "0.1.10")
            .unwrap()
            .unwrap();
        assert_eq!(back, one);
    }

    #[test]
    fn occupied_crate_key_and_reserved_config_keys_are_avoided() {
        let user = format!("{PKG}\n[patch.crates-io]\ncfg-if = {{ path = \"../cfg-if-0.1\" }}\n");
        let up = add(&user, "cfg-if", "1.0.4", UUID);
        assert_eq!(up.key, "cfg-if-socket-9f6b2c4e");
        let out = up.content.unwrap();
        assert!(out.contains("cfg-if = { path = \"../cfg-if-0.1\" }"));
        assert_eq!(
            remove_patch_entries(&out, "cfg-if", "1.0.4")
                .unwrap()
                .unwrap(),
            user
        );
        let reserved = vec!["cfg-if-socket-9f6b2c4e".to_string()];
        let up = upsert_patch_entry(
            PKG,
            "cfg-if",
            "1.0.4",
            UUID,
            &rel(UUID, "cfg-if", "1.0.4"),
            &reserved,
        )
        .unwrap();
        assert_eq!(up.key, "cfg-if-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f");
    }

    /// Cargo lets a config-file `[patch]` item replace the manifest item
    /// with the same key (any version): a re-run over an entry whose key a
    /// config now uses moves it to a fresh key instead of refreshing it in
    /// place under the shadowed one.
    #[test]
    fn existing_entry_under_a_reserved_key_moves_to_a_fresh_key() {
        let out = add(PKG, "cfg-if", "1.0.4", UUID).content.unwrap();
        let reserved = vec!["cfg-if-socket-9f6b2c4e".to_string()];
        for uuid in [UUID, UUID2] {
            let up = upsert_patch_entry(
                &out,
                "cfg-if",
                "1.0.4",
                uuid,
                &rel(uuid, "cfg-if", "1.0.4"),
                &reserved,
            )
            .unwrap();
            assert_ne!(up.key, "cfg-if-socket-9f6b2c4e", "{uuid}");
            assert!(is_socket_key(&up.key, "cfg-if"), "{}", up.key);
            let moved = up.content.expect("re-keyed");
            let es = entries(&moved);
            assert_eq!(es.len(), 1, "{moved}");
            assert_eq!(es[0].key, up.key);
            assert_eq!(es[0].name, "cfg-if");
            assert_eq!(
                es[0].path.as_deref(),
                Some(rel(uuid, "cfg-if", "1.0.4").as_str())
            );
        }
    }

    /// A Socket-owned entry under the bare crate name (hand-copied, or
    /// written by a pre-release build) moves to the Socket-owned key: a bare
    /// key is exactly what a user's config entry would silently shadow.
    #[test]
    fn bare_crate_name_key_is_rekeyed() {
        let src = format!(
            "{PKG}\n[patch.crates-io]\ncfg-if = {{ path = \"{}\" }}\n",
            rel(UUID, "cfg-if", "1.0.4")
        );
        let up = add(&src, "cfg-if", "1.0.4", UUID);
        assert_eq!(up.key, "cfg-if-socket-9f6b2c4e");
        assert_eq!(
            up.prior_path.as_deref(),
            Some(rel(UUID, "cfg-if", "1.0.4").as_str())
        );
        let out = up.content.unwrap();
        assert!(!out.contains("\ncfg-if = { path"), "{out}");
        assert_eq!(entries(&out).len(), 1);
    }

    #[test]
    fn socket_keys() {
        assert!(is_socket_key("cfg-if-socket-9f6b2c4e", "cfg-if"));
        assert!(is_socket_key(
            "cfg-if-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f",
            "cfg-if"
        ));
        assert!(!is_socket_key("cfg-if", "cfg-if"));
        assert!(!is_socket_key("cfg-if-socket-9F6B2C4E", "cfg-if"));
        assert!(!is_socket_key("cfg-if-socket-9f6b", "cfg-if"));
        assert!(!is_socket_key("serde-socket-9f6b2c4e", "cfg-if"));
    }

    /// Cargo keys manifest `[patch]` tables by source URL, and the URL
    /// spelling of crates.io replaces `[patch.crates-io]` wholesale — a
    /// vendored entry written there would be silently ignored. Refuse.
    #[test]
    fn url_spelled_crates_io_patch_table_refuses() {
        for alias in [
            "https://github.com/rust-lang/crates.io-index",
            "https://github.com/rust-lang/crates.io-index/",
            "HTTPS://GITHUB.COM/rust-lang/crates.io-index.git",
        ] {
            let src = format!("{PKG}\n[patch.\"{alias}\"]\nitoa = {{ path = \"../itoa\" }}\n");
            let err = add_err(&src, "cfg-if", "1.0.4", UUID);
            assert_eq!(err.code(), "cargo_manifest_patch_source_alias", "{alias}");
            assert!(err.detail().contains(alias), "{}", err.detail());
        }
        // Another registry's URL table is unrelated.
        let src = format!(
            "{PKG}\n[patch.\"https://example.com/index\"]\nitoa = {{ path = \"../itoa\" }}\n"
        );
        assert!(add(&src, "cfg-if", "1.0.4", UUID).content.is_some());
        assert!(is_crates_io_source("crates-io"));
        assert!(!is_crates_io_source("https://example.com/index"));
    }

    /// `toml_edit` drops a leading BOM; the edit and the revert put it back.
    #[test]
    fn utf8_bom_survives_vendor_and_revert() {
        for src in [
            format!("\u{feff}{PKG}"),
            format!("\u{feff}{PKG}").replace('\n', "\r\n"),
        ] {
            let out = add(&src, "cfg-if", "1.0.4", UUID).content.unwrap();
            assert!(out.starts_with('\u{feff}'), "{out:?}");
            assert_eq!(out.matches('\u{feff}').count(), 1);
            assert!(out.starts_with(&src), "only lines are appended: {out:?}");
            let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
                .unwrap()
                .unwrap();
            assert_eq!(back, src);
            assert_eq!(add(&out, "cfg-if", "1.0.4", UUID).content, None);
        }
    }

    /// A revert keeps table headers the user wrote before vendoring.
    #[test]
    fn user_authored_empty_patch_headers_survive_revert() {
        for src in [
            // An explicit empty table in the middle of the file.
            "[package]\nname = \"a\"\n\n[patch.crates-io]\n\n[dependencies]\ncfg-if = \"1\"\n"
                .to_string(),
            // An explicit `[patch]` header.
            "[package]\nname = \"a\"\n\n[patch]\n".to_string(),
            // A header carrying a comment.
            "[package]\nname = \"a\"\n\n[patch.crates-io] # forks go here\n".to_string(),
        ] {
            let out = add(&src, "cfg-if", "1.0.4", UUID).content.unwrap();
            let back = remove_patch_entries(&out, "cfg-if", "1.0.4")
                .unwrap()
                .unwrap();
            assert_eq!(back, src, "{out}");
        }
    }

    #[test]
    fn uuid_bump_refreshes_in_place_keeping_the_key() {
        let two = add(
            &add(PKG, "cfg-if", "1.0.4", UUID).content.unwrap(),
            "cfg-if",
            "0.1.10",
            UUID2,
        )
        .content
        .unwrap();
        let new_uuid = "11111111-2222-4333-8444-555555555555";
        let up = upsert_patch_entry(
            &two,
            "cfg-if",
            "0.1.10",
            new_uuid,
            &rel(new_uuid, "cfg-if", "0.1.10"),
            &[],
        )
        .unwrap();
        assert_eq!(up.key, "cfg-if-socket-0a1b2c3d", "the key is sticky");
        assert_eq!(
            up.prior_path.as_deref(),
            Some(rel(UUID2, "cfg-if", "0.1.10").as_str())
        );
        let out = up.content.unwrap();
        assert!(out.contains(&rel(new_uuid, "cfg-if", "0.1.10")));
        assert!(!out.contains(UUID2));
    }

    #[test]
    fn user_entries_are_never_removed_or_rewritten() {
        for src in [
            format!("{PKG}\n[patch.crates-io]\ncfg-if = {{ path = \"../fork\" }}\n"),
            format!(
                "{PKG}\n[patch.crates-io]\ncfg-if = {{ path = \"../other/{}\" }}\n",
                rel(UUID, "cfg-if", "1.0.4")
            ),
            format!(
                "{PKG}\n[patch.crates-io]\nx = {{ package = \"other\", path = \"{}\" }}\n",
                rel(UUID, "cfg-if", "1.0.4")
            ),
        ] {
            assert_eq!(remove_patch_entries(&src, "cfg-if", "1.0.4").unwrap(), None);
        }
    }

    #[test]
    fn inline_and_dotted_spellings_are_found() {
        for src in [
            format!(
                "[patch]\ncrates-io = {{ cfg-if-socket-9f6b2c4e = {{ package = \"cfg-if\", \
                 path = \"{}\" }} }}\n",
                rel(UUID, "cfg-if", "1.0.4")
            ),
            format!(
                "[patch.crates-io.cfg-if-socket-9f6b2c4e]\npackage = \"cfg-if\"\npath = \"./{}/\"\n",
                rel(UUID, "cfg-if", "1.0.4")
            ),
        ] {
            let up = add(&src, "cfg-if", "1.0.4", UUID);
            assert_eq!(up.content, None, "{src}");
            let out = remove_patch_entries(&src, "cfg-if", "1.0.4")
                .unwrap()
                .unwrap();
            assert!(!out.contains("cfg-if"), "{out}");
        }
    }

    #[test]
    fn unparseable_manifest_and_scalar_patch_table_are_errors() {
        let err = upsert_patch_entry("[package\n", "a", "1.0.0", UUID, "x", &[]).unwrap_err();
        assert_eq!(err.code(), "cargo_manifest_unparseable");
        let err = upsert_patch_entry("[patch]\ncrates-io = 1\n", "a", "1.0.0", UUID, "x", &[])
            .unwrap_err();
        assert_eq!(err.code(), "cargo_manifest_unparseable");
        assert_eq!(
            remove_patch_entries("[package\n", "a", "1.0.0")
                .unwrap_err()
                .code(),
            "cargo_manifest_unparseable"
        );
    }

    #[test]
    fn no_free_key_is_reported() {
        let taken = |_: &str| true;
        assert_eq!(choose_key("a", UUID, taken), None);
        assert_eq!(
            choose_key("a", UUID, |k| k == "a" || k == "a-socket-9f6b2c4e"),
            Some("a-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f".to_string())
        );
    }

    #[test]
    fn socket_copy_paths() {
        assert!(is_socket_copy_of(
            &rel(UUID, "cfg-if", "1.0.4"),
            "cfg-if",
            "1.0.4"
        ));
        assert!(is_socket_copy_of(
            &format!("./{}/", rel(UUID, "cfg-if", "1.0.4")),
            "cfg-if",
            "1.0.4"
        ));
        assert!(!is_socket_copy_of(
            &rel(UUID, "cfg-if", "1.0.4"),
            "cfg-if",
            "1.0.5"
        ));
        assert!(!is_socket_copy_of(
            &format!("{}/nested", rel(UUID, "cfg-if", "1.0.4")),
            "cfg-if",
            "1.0.4"
        ));
        assert!(!is_socket_copy_of(
            "../x/.socket/vendor/cargo/u/cfg-if-1.0.4",
            "cfg-if",
            "1.0.4"
        ));
    }

    #[test]
    fn reconcile_handles_empty_and_pure_insertions() {
        assert_eq!(reconcile_line_endings("", "a = 1\n"), "a = 1\n");
        assert_eq!(
            reconcile_line_endings("a = 1\r\n", "a = 1\nb = 2\n"),
            "a = 1\r\nb = 2\r\n"
        );
        assert_eq!(
            reconcile_line_endings("a = 1\r\nb = 2\r\n", "a = 1\n"),
            "a = 1\r\n"
        );
    }

    #[tokio::test]
    async fn io_wrappers_round_trip_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let err = ensure_patch_entry(
            root,
            "a",
            "1.0.0",
            UUID,
            &rel(UUID, "a", "1.0.0"),
            &[],
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), "cargo_manifest_unreadable");
        assert!(!drop_patch_entries(root, "a", "1.0.0", false).await.unwrap());

        tokio::fs::write(root.join(CARGO_TOML), PKG).await.unwrap();
        let dry = ensure_patch_entry(
            root,
            "cfg-if",
            "1.0.4",
            UUID,
            &rel(UUID, "cfg-if", "1.0.4"),
            &[],
            true,
        )
        .await
        .unwrap();
        assert!(dry.changed);
        assert_eq!(
            tokio::fs::read_to_string(root.join(CARGO_TOML))
                .await
                .unwrap(),
            PKG
        );
        let wet = ensure_patch_entry(
            root,
            "cfg-if",
            "1.0.4",
            UUID,
            &rel(UUID, "cfg-if", "1.0.4"),
            &[],
            false,
        )
        .await
        .unwrap();
        assert!(wet.changed);
        assert_eq!(read_patch_entries(root).await.len(), 1);
        assert!(drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap());
        assert_eq!(
            tokio::fs::read_to_string(root.join(CARGO_TOML))
                .await
                .unwrap(),
            PKG
        );

        tokio::fs::write(root.join(CARGO_TOML), "[package\n")
            .await
            .unwrap();
        assert_eq!(
            drop_patch_entries(root, "cfg-if", "1.0.4", false)
                .await
                .unwrap_err()
                .code(),
            "cargo_manifest_unparseable"
        );
        assert!(read_patch_entries(root).await.is_empty());
    }
}
