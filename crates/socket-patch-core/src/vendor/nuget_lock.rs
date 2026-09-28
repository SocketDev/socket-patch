//! `packages.lock.json` splicing for the NuGet fallback layout
//! ([`super::nuget_fallback`]).
//!
//! The edits are the ones `dotnet restore --force-evaluate` itself writes
//! once a project resolves the patched version `V′` (captured from real SDK
//! runs, see `tests/fixtures/nuget-fallback/`), applied as byte-preserving
//! splices of string VALUES only: no key is renamed, no entry added, removed
//! or reordered, and the file's indentation, EOL and (missing) trailing
//! newline are kept.
//!
//! | entry (key == id, case-insensitive) | edit |
//! |---|---|
//! | `Direct` / `CentralTransitive`, `resolved` == V | `requested "[V, )"` → `"[V′, )"`, `resolved` → V′, `contentHash` → seed hash |
//! | `Transitive`, `resolved` == V | `resolved` → V′, `contentHash` → seed hash |
//! | `Direct` / `CentralTransitive`, `requested "[V, )"`, `resolved` ≠ V | `requested` only (NuGet re-records the central range; resolution is unchanged) |
//! | `Project` entry, `dependencies.<id>` == `"[V, )"` | → `"[V′, )"` |
//!
//! A value at an OLDER Socket version of the same upstream V (a lock spliced
//! by an earlier patch uuid) is treated like V: it is re-spliced to the
//! current V′ and seed hash, so a patch update never strands a lock on a
//! seed that is about to be swept. [`unsplice_lock`] is the per-entry
//! inverse the revert uses.
//!
//! Package-to-package dependency maps (plain minimum versions) are never
//! touched. A `Direct`/`CentralTransitive` range other than `[V, )` refuses
//! `vendor_nuget_range_unsupported`; a V entry nothing redirects (no project
//! reference reaching a redirected project and, under central management,
//! no transitive pinning) refuses `vendor_nuget_transitive_only`.

use std::collections::BTreeMap;

use super::nuget_feed::normalize_nuget_version;
use super::nuget_version::parse_socket_nuget_version;

/// Bound on JSON nesting (a real lock is five levels deep).
const MAX_DEPTH: usize = 64;

/// One string value of the document: its key path and the byte span of the
/// whole quoted token.
#[derive(Debug, Clone)]
struct StrValue {
    path: Vec<String>,
    start: usize,
    end: usize,
    value: String,
}

/// A minimal JSON walker that records every string VALUE with its key path
/// (array elements are keyed `[i]`). The text is validated by `serde_json`
/// first; this pass only locates spans.
struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
    out: Vec<StrValue>,
}

impl Scanner<'_> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }

    fn string(&mut self) -> Result<(usize, usize, String), String> {
        let start = self.at;
        if self.bytes.get(self.at) != Some(&b'"') {
            return Err(format!("expected a string at byte {start}"));
        }
        self.at += 1;
        loop {
            match self.bytes.get(self.at) {
                None => return Err("unterminated string".to_string()),
                Some(b'\\') => self.at += 2,
                Some(b'"') => {
                    self.at += 1;
                    break;
                }
                Some(_) => self.at += 1,
            }
        }
        let raw = self
            .text
            .get(start..self.at)
            .ok_or_else(|| "unterminated string".to_string())?;
        let value: String =
            serde_json::from_str(raw).map_err(|e| format!("bad string at byte {start}: {e}"))?;
        Ok((start, self.at, value))
    }

    fn expect_separator(&mut self, close: u8) -> Result<bool, String> {
        self.ws();
        match self.bytes.get(self.at) {
            Some(b',') => {
                self.at += 1;
                Ok(false)
            }
            Some(b) if *b == close => {
                self.at += 1;
                Ok(true)
            }
            _ => Err(format!("unexpected byte at {}", self.at)),
        }
    }

    fn value(&mut self, path: &mut Vec<String>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("nesting too deep".to_string());
        }
        self.ws();
        match self.bytes.get(self.at) {
            Some(b'{') => {
                self.at += 1;
                self.ws();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Ok(());
                }
                loop {
                    self.ws();
                    let (_, _, key) = self.string()?;
                    self.ws();
                    if self.bytes.get(self.at) != Some(&b':') {
                        return Err(format!("expected `:` at byte {}", self.at));
                    }
                    self.at += 1;
                    path.push(key);
                    self.value(path, depth + 1)?;
                    path.pop();
                    if self.expect_separator(b'}')? {
                        return Ok(());
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                self.ws();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Ok(());
                }
                let mut i = 0usize;
                loop {
                    path.push(format!("[{i}]"));
                    self.value(path, depth + 1)?;
                    path.pop();
                    i += 1;
                    if self.expect_separator(b']')? {
                        return Ok(());
                    }
                }
            }
            Some(b'"') => {
                let (start, end, value) = self.string()?;
                self.out.push(StrValue {
                    path: path.clone(),
                    start,
                    end,
                    value,
                });
                Ok(())
            }
            Some(_) => {
                let start = self.at;
                while self.bytes.get(self.at).is_some_and(|b| {
                    !matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                }) {
                    self.at += 1;
                }
                if start == self.at {
                    return Err(format!("unexpected byte at {start}"));
                }
                Ok(())
            }
            None => Err("unexpected end of document".to_string()),
        }
    }
}

/// Every string value of `text` with its path, or `Err` when `text` is not
/// a JSON document.
fn scan_strings(text: &str) -> Result<Vec<StrValue>, String> {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    serde_json::from_str::<serde_json::Value>(body).map_err(|e| e.to_string())?;
    let mut scanner = Scanner {
        text,
        bytes: text.as_bytes(),
        at: text.len() - body.len(),
        out: Vec::new(),
    };
    scanner.value(&mut Vec::new(), 0)?;
    Ok(scanner.out)
}

/// What the splice needs to know about the patched package.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LockTarget<'a> {
    /// The package id (compared case-insensitively).
    pub(crate) id: &'a str,
    /// The normalized upstream version V.
    pub(crate) version: &'a str,
    /// The Socket version V′.
    pub(crate) socket_version: &'a str,
    /// The seed's contentHash.
    pub(crate) content_hash: &'a str,
    /// `CentralPackageTransitivePinningEnabled` is on for this project.
    pub(crate) transitive_pinning: bool,
}

/// A planned splice of one lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockSplice {
    /// The spliced text (`== text` when nothing needed editing).
    pub(crate) text: String,
    /// How many string values changed.
    pub(crate) edits: usize,
    /// The lock resolves or references the id at V or V′ anywhere (a lock
    /// that does not is not this package's business).
    pub(crate) references_id: bool,
}

/// One lock entry's string fields.
#[derive(Default)]
struct Entry<'a> {
    kind: Option<&'a StrValue>,
    requested: Option<&'a StrValue>,
    resolved: Option<&'a StrValue>,
    content_hash: Option<&'a StrValue>,
    /// `dependencies.<id>` of this entry (id matched case-insensitively).
    dependency: Option<&'a StrValue>,
}

fn quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Plan the splice of one `packages.lock.json` (see the module doc).
/// `Err((code, detail))` is a refusal.
pub(crate) fn splice_lock(
    text: &str,
    target: &LockTarget<'_>,
) -> Result<LockSplice, (&'static str, String)> {
    let values = scan_strings(text).map_err(|e| {
        (
            "vendor_nuget_lock_unreadable",
            format!("unparseable packages.lock.json: {e}"),
        )
    })?;
    let sections = group_entries(&values, target.id);

    let v = target.version;
    let vp = target.socket_version;
    let range_v = format!("[{v}, )");
    let range_vp = format!("[{vp}, )");
    let vp_norm = normalize_nuget_version(vp);
    // A value naming an OLDER Socket version of V (an earlier patch uuid's
    // splice): re-spliced like V.
    let stale_socket = |s: &str| {
        normalize_nuget_version(s) != vp_norm
            && parse_socket_nuget_version(s).is_some_and(|(up, _)| up == v)
    };
    let stale_range = |s: &str| floor_of(s).is_some_and(stale_socket);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut references_id = false;

    for (tfm, entries) in &sections {
        // A project reference whose own lock pins the id: this project
        // follows that project's (redirected) range.
        let reaches = entries.values().any(|e| {
            e.kind.is_some_and(|k| k.value == "Project")
                && e.dependency.is_some_and(|d| {
                    d.value == range_v || d.value == range_vp || stale_range(&d.value)
                })
        });
        // Project entries first: a range refusal there outranks a
        // transitive-only refusal of the entry it would have redirected.
        let (projects, packages): (Vec<_>, Vec<_>) = entries
            .iter()
            .partition(|(_, e)| e.kind.is_some_and(|k| k.value == "Project"));
        for (key, e) in projects.into_iter().chain(packages) {
            let kind = e.kind.map(|k| k.value.as_str()).unwrap_or("");
            if kind == "Project" {
                let Some(dep) = e.dependency else { continue };
                if dep.value == range_v || stale_range(&dep.value) {
                    references_id = true;
                    edits.push((dep.start, dep.end, quoted(&range_vp)));
                } else if dep.value == range_vp {
                    references_id = true;
                } else if range_mentions(&dep.value, v) {
                    return Err((
                        "vendor_nuget_range_unsupported",
                        format!(
                            "{tfm}: project `{key}` depends on {} {:?}; only `[{v}, )` can be \
                             redirected",
                            target.id, dep.value
                        ),
                    ));
                }
                continue;
            }
            if !key.eq_ignore_ascii_case(target.id) {
                continue;
            }
            let Some(resolved) = e.resolved else { continue };
            let resolved_norm = normalize_nuget_version(&resolved.value);
            let ranged = matches!(kind, "Direct" | "CentralTransitive");
            if stale_socket(&resolved.value) {
                // Spliced by an earlier patch uuid: move it to this seed.
                references_id = true;
                edits.push((resolved.start, resolved.end, quoted(vp)));
                if let Some(h) = e.content_hash {
                    edits.push((h.start, h.end, quoted(target.content_hash)));
                }
                if let Some(r) = e.requested.filter(|r| ranged && stale_range(&r.value)) {
                    edits.push((r.start, r.end, quoted(&range_vp)));
                }
                continue;
            }
            if resolved_norm == vp_norm {
                // Already spliced: keep the pin at this seed's hash.
                references_id = true;
                if let Some(h) = e.content_hash.filter(|h| h.value != target.content_hash) {
                    edits.push((h.start, h.end, quoted(target.content_hash)));
                }
                continue;
            }
            if resolved_norm != v {
                // A central (or direct) range at V that resolved elsewhere is
                // re-recorded at V′, its resolution unchanged.
                if let Some(r) = e.requested.filter(|_| ranged) {
                    if r.value == range_v || stale_range(&r.value) {
                        references_id = true;
                        edits.push((r.start, r.end, quoted(&range_vp)));
                    } else if r.value == range_vp {
                        references_id = true;
                    }
                }
                continue;
            }
            references_id = true;
            match kind {
                "Direct" | "CentralTransitive" => {
                    let requested = e.requested.map(|r| r.value.as_str()).unwrap_or_default();
                    let Some(r) = e.requested.filter(|r| r.value == range_v) else {
                        return Err((
                            "vendor_nuget_range_unsupported",
                            format!(
                                "{tfm}: {kind} {key} {v} requests {requested:?}; only `[{v}, )` \
                                 can be redirected"
                            ),
                        ));
                    };
                    if kind == "CentralTransitive" && !reaches && !target.transitive_pinning {
                        return Err(transitive_only(tfm, key, v));
                    }
                    edits.push((r.start, r.end, quoted(&range_vp)));
                }
                "Transitive" => {
                    if !reaches {
                        return Err(transitive_only(tfm, key, v));
                    }
                }
                other => {
                    return Err((
                        "vendor_nuget_range_unsupported",
                        format!("{tfm}: {key} {v} has unsupported lock entry type {other:?}"),
                    ));
                }
            }
            edits.push((resolved.start, resolved.end, quoted(vp)));
            if let Some(h) = e.content_hash {
                edits.push((h.start, h.end, quoted(target.content_hash)));
            }
        }
    }

    edits.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(text.len() + edits.len() * 16);
    let mut pos = 0;
    for (start, end, replacement) in &edits {
        out.push_str(&text[pos..*start]);
        out.push_str(replacement);
        pos = *end;
    }
    out.push_str(&text[pos..]);
    Ok(LockSplice {
        text: out,
        edits: edits.len(),
        references_id,
    })
}

/// The lock entries of every `dependencies.<tfm>` section, with the
/// `dependencies.<id>` value of each entry that names `id`.
fn group_entries<'a>(
    values: &'a [StrValue],
    id: &str,
) -> BTreeMap<&'a str, BTreeMap<&'a str, Entry<'a>>> {
    let mut sections: BTreeMap<&str, BTreeMap<&str, Entry<'_>>> = BTreeMap::new();
    for v in values {
        if v.path.first().map(String::as_str) != Some("dependencies") {
            continue;
        }
        match v.path.len() {
            4 => {
                let e = sections
                    .entry(v.path[1].as_str())
                    .or_default()
                    .entry(v.path[2].as_str())
                    .or_default();
                match v.path[3].as_str() {
                    "type" => e.kind = Some(v),
                    "requested" => e.requested = Some(v),
                    "resolved" => e.resolved = Some(v),
                    "contentHash" => e.content_hash = Some(v),
                    _ => {}
                }
            }
            5 if v.path[3] == "dependencies" && v.path[4].eq_ignore_ascii_case(id) => {
                sections
                    .entry(v.path[1].as_str())
                    .or_default()
                    .entry(v.path[2].as_str())
                    .or_default()
                    .dependency = Some(v);
            }
            _ => {}
        }
    }
    sections
}

/// The lower bound of a `[X, )` floor range.
fn floor_of(range: &str) -> Option<&str> {
    range.strip_prefix('[')?.strip_suffix(", )")
}

/// The per-entry inverse of [`splice_lock`] for one entry's revert: every
/// value of `target.id` at `target.socket_version` in `live` goes back to
/// the upstream V, touching nothing else — so another seed's splice, a
/// package added since, or a new framework section survive the revert.
///
/// Each value is restored to what `original` (the pre-vendor text, when
/// recorded) held at the same JSON path, else to the plain V spelling; a
/// `contentHash` comes only from `original` (at the same path, else any
/// upstream V entry of the id). Returns the text and whether every V′ value
/// could be restored (`false`: a hash had no recorded upstream value and was
/// left, together with its entry's `resolved`, at V′).
pub(crate) fn unsplice_lock(
    live: &str,
    original: Option<&str>,
    target: &LockTarget<'_>,
) -> Result<(String, bool), String> {
    let values = scan_strings(live)?;
    let sections = group_entries(&values, target.id);
    let orig_values = original
        .and_then(|o| scan_strings(o).ok())
        .unwrap_or_default();
    let v = target.version;
    let vp_norm = normalize_nuget_version(target.socket_version);
    let is_vp = |s: &str| normalize_nuget_version(s) == vp_norm;
    let is_vp_range = |s: &str| floor_of(s).is_some_and(is_vp);
    let orig_at = |path: &[String]| {
        orig_values
            .iter()
            .find(|o| o.path == path)
            .map(|o| o.value.as_str())
    };
    // Any upstream hash of the id at V in the original.
    let orig_groups = group_entries(&orig_values, target.id);
    let any_upstream_hash = orig_groups
        .values()
        .flat_map(|es| es.iter())
        .find_map(|(k, e)| {
            (k.eq_ignore_ascii_case(target.id)
                && e.resolved
                    .is_some_and(|r| normalize_nuget_version(&r.value) == v))
            .then(|| e.content_hash.map(|h| h.value.clone()))
            .flatten()
        });
    let restore_version = |sv: &StrValue| {
        orig_at(&sv.path)
            .filter(|o| normalize_nuget_version(o) == v)
            .map_or_else(|| v.to_string(), str::to_string)
    };
    let restore_range = |sv: &StrValue| {
        orig_at(&sv.path)
            .filter(|o| floor_of(o).is_some_and(|f| normalize_nuget_version(f) == v))
            .map_or_else(|| format!("[{v}, )"), str::to_string)
    };
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut complete = true;
    for entries in sections.values() {
        for (key, e) in entries {
            if e.kind.is_some_and(|k| k.value == "Project") {
                if let Some(dep) = e.dependency.filter(|d| is_vp_range(&d.value)) {
                    edits.push((dep.start, dep.end, quoted(&restore_range(dep))));
                }
                continue;
            }
            if !key.eq_ignore_ascii_case(target.id) {
                continue;
            }
            if let Some(r) = e.requested.filter(|r| is_vp_range(&r.value)) {
                edits.push((r.start, r.end, quoted(&restore_range(r))));
            }
            let Some(resolved) = e.resolved.filter(|r| is_vp(&r.value)) else {
                continue;
            };
            let hash = match e.content_hash {
                None => Some(None),
                Some(h) => orig_at(&h.path)
                    .filter(|_| {
                        e.resolved
                            .and_then(|r| orig_at(&r.path))
                            .is_some_and(|o| normalize_nuget_version(o) == v)
                    })
                    .map(str::to_string)
                    .or_else(|| any_upstream_hash.clone())
                    .map(|value| Some((h, value))),
            };
            match hash {
                Some(h) => {
                    edits.push((
                        resolved.start,
                        resolved.end,
                        quoted(&restore_version(resolved)),
                    ));
                    if let Some((h, value)) = h {
                        edits.push((h.start, h.end, quoted(&value)));
                    }
                }
                None => complete = false,
            }
        }
    }
    edits.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(live.len());
    let mut pos = 0;
    for (start, end, replacement) in &edits {
        out.push_str(&live[pos..*start]);
        out.push_str(replacement);
        pos = *end;
    }
    out.push_str(&live[pos..]);
    Ok((out, complete))
}

fn transitive_only(tfm: &str, key: &str, v: &str) -> (&'static str, String) {
    (
        "vendor_nuget_transitive_only",
        format!(
            "{tfm}: {key} {v} is resolved only transitively through packages, and nothing the \
             vendored layout rewrites pins it (no reference to a redirected project, no \
             central transitive pinning)"
        ),
    )
}

/// Whether a NuGet range string names `v` as one of its bounds.
fn range_mentions(range: &str, v: &str) -> bool {
    range
        .trim_matches(|c| matches!(c, '[' | ']' | '(' | ')'))
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|bound| normalize_nuget_version(bound) == v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/nuget-fallback");
    const V: &str = "13.0.1";
    const VP: &str = "13.0.1.1340506223";
    const HASH: &str =
        "DDiM9JFGWawv1+fJNCo4t23ht/5mS7kCKb4PWYSQBB1w/Ku4Vrwbv1ATHzCbTv/3ZFPci1UuW5waP8K9SwKRBA==";

    fn target(pinning: bool) -> LockTarget<'static> {
        LockTarget {
            id: "Newtonsoft.Json",
            version: V,
            socket_version: VP,
            content_hash: HASH,
            transitive_pinning: pinning,
        }
    }

    fn read(rel: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{rel}"))
            .unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// Every captured lock: `splice(before)` is byte-identical to what
    /// `dotnet restore --force-evaluate` wrote after vendoring, and a second
    /// splice is a no-op.
    #[test]
    fn splice_matches_nuget_force_evaluate_goldens() {
        let cases: &[(&str, &[&str], bool)] = &[
            ("sln", &["Lib", "App", "Other"], false),
            ("cpm", &["Lib", "App"], false),
            ("cpmpin", &["Lib", "App", "Tool"], true),
            ("cpm-tool", &["Lib", "App", "Tool"], false),
        ];
        for (shape, projects, pinning) in cases {
            for p in *projects {
                let rel = format!("src/{p}/packages.lock.json");
                let before = read(&format!("{shape}/before/{rel}"));
                let after = read(&format!("{shape}/after/{rel}"));
                let got = splice_lock(&before, &target(*pinning))
                    .unwrap_or_else(|e| panic!("{shape}/{p}: {e:?}"));
                assert_eq!(got.text, after, "{shape}/{p}");
                assert_eq!(got.references_id, *p != "Other", "{shape}/{p}");
                let again = splice_lock(&after, &target(*pinning)).unwrap();
                assert_eq!(again.edits, 0, "{shape}/{p} idempotent");
                assert_eq!(again.text, after);
            }
        }
    }

    #[test]
    fn package_dependency_maps_are_never_touched() {
        let before = read("cpm-tool/before/src/Tool/packages.lock.json");
        let got = splice_lock(&before, &target(false)).unwrap();
        assert!(got.text.contains("\"Newtonsoft.Json\": \"12.0.1\""));
        assert!(got.text.contains("\"resolved\": \"12.0.1\""));
        assert_eq!(got.edits, 1, "requested only");
    }

    #[test]
    fn crlf_bom_and_tfm_rid_sections_are_preserved() {
        let before = read("sln/before/src/Lib/packages.lock.json");
        let after = read("sln/after/src/Lib/packages.lock.json");
        let crlf = format!("\u{feff}{}", before.replace('\n', "\r\n"));
        let got = splice_lock(&crlf, &target(false)).unwrap();
        assert_eq!(got.text, format!("\u{feff}{}", after.replace('\n', "\r\n")));

        let rid = before.replace(
            "\"net8.0\": {",
            "\"net8.0\": {\n      \"Newtonsoft.Json\": {\"type\": \"Direct\", \"requested\": \
             \"[13.0.1, )\", \"resolved\": \"13.0.1\", \"contentHash\": \"x\"}\n    },\n    \
             \"net8.0/linux-x64\": {",
        );
        let got = splice_lock(&rid, &target(false)).unwrap();
        assert_eq!(got.edits, 6);
        assert!(!got.text.contains("\"13.0.1\""));
    }

    #[test]
    fn unsupported_ranges_refuse() {
        let before = read("sln/before/src/Lib/packages.lock.json");
        let exact = before.replace("\"[13.0.1, )\"", "\"[13.0.1]\"");
        let err = splice_lock(&exact, &target(false)).unwrap_err();
        assert_eq!(err.0, "vendor_nuget_range_unsupported");

        let app = read("sln/before/src/App/packages.lock.json");
        let exact = app.replace("\"[13.0.1, )\"", "\"[13.0.1]\"");
        let err = splice_lock(&exact, &target(false)).unwrap_err();
        assert_eq!(err.0, "vendor_nuget_range_unsupported");
    }

    #[test]
    fn transitive_only_refuses() {
        // App without the project reference that carries the redirect.
        let app = read("sln/before/src/App/packages.lock.json");
        let orphan = app.replace(
            "\"Newtonsoft.Json\": \"[13.0.1, )\"",
            "\"Other\": \"[1.0.0, )\"",
        );
        let err = splice_lock(&orphan, &target(false)).unwrap_err();
        assert_eq!(err.0, "vendor_nuget_transitive_only");

        // CPM without pinning: a CentralTransitive at V reached only through
        // packages is not redirected; with pinning it is.
        let cpm = read("cpm/before/src/App/packages.lock.json");
        let orphan = cpm.replace(
            "\"Newtonsoft.Json\": \"[13.0.1, )\"",
            "\"Other\": \"[1.0.0, )\"",
        );
        assert_eq!(
            splice_lock(&orphan, &target(false)).unwrap_err().0,
            "vendor_nuget_transitive_only"
        );
        assert!(splice_lock(&orphan, &target(true)).is_ok());
    }

    #[test]
    fn a_hash_only_drift_on_an_already_spliced_lock_is_repinned() {
        let after = read("sln/after/src/Lib/packages.lock.json");
        let got = splice_lock(
            &after,
            &LockTarget {
                content_hash: "bmV3",
                ..target(false)
            },
        )
        .unwrap();
        assert_eq!(got.edits, 1);
        assert!(got.text.contains("\"contentHash\": \"bmV3\""));
    }

    /// A lock spliced by an earlier patch uuid is moved to the new V′ (what
    /// the same splice of the pristine lock gives), and un-splicing any
    /// captured lock with its pristine original restores it byte for byte.
    #[test]
    fn a_new_patch_uuid_re_splices_and_unsplice_inverts() {
        let vp2 = super::super::nuget_version::socket_nuget_version(
            V,
            "7b2c0d11-2222-4333-8444-555566667777",
        )
        .unwrap();
        let t2 = LockTarget {
            socket_version: &vp2,
            content_hash: "bmV3",
            ..target(false)
        };
        let cases: &[(&str, &[&str], bool)] = &[
            ("sln", &["Lib", "App", "Other"], false),
            ("cpm", &["Lib", "App"], false),
            ("cpmpin", &["Lib", "App", "Tool"], true),
            ("cpm-tool", &["Lib", "App", "Tool"], false),
        ];
        for (shape, projects, pinning) in cases {
            for p in *projects {
                let rel = format!("src/{p}/packages.lock.json");
                let before = read(&format!("{shape}/before/{rel}"));
                let after = read(&format!("{shape}/after/{rel}"));
                let t2 = LockTarget {
                    transitive_pinning: *pinning,
                    ..t2
                };
                let moved = splice_lock(&after, &t2).unwrap();
                assert_eq!(
                    moved.text,
                    splice_lock(&before, &t2).unwrap().text,
                    "{shape}/{p}"
                );
                assert!(!moved.text.contains(VP), "{shape}/{p}");
                assert_eq!(moved.references_id, *p != "Other");
                let (back, complete) =
                    unsplice_lock(&after, Some(&before), &target(*pinning)).unwrap();
                assert!(complete, "{shape}/{p}");
                assert_eq!(back, before, "{shape}/{p}");
                let (back, complete) = unsplice_lock(&moved.text, Some(&before), &t2).unwrap();
                assert!(complete);
                assert_eq!(back, before, "{shape}/{p} after the uuid update");
            }
        }
    }

    #[test]
    fn garbage_is_unreadable() {
        assert_eq!(
            splice_lock("{\"dependencies\": ", &target(false))
                .unwrap_err()
                .0,
            "vendor_nuget_lock_unreadable"
        );
    }
}
