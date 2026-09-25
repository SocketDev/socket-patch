//! Leaf helpers shared by the vendor backends (and [`crate::patch::redirect::golang_local`]).
//!
//! Each backend used to carry a private, byte-identical copy of these; they
//! are hoisted here so the shapes stay in lockstep.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::Value;
use toml_edit::{DocumentMut, Item, Table};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::{
    is_safe_relative_subpath, normalize_file_path, ApplyResult, VerifyResult, VerifyStatus,
};
use crate::patch::copy_tree::remove_tree;
use crate::patch::file_hash::compute_file_git_sha256;
use crate::utils::fs::{
    atomic_write_bytes_preserving_mode, first_symlink, open_regular_file_sync,
    read_regular_to_string,
};

use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// A [`VerifyResult`] reporting `file` as already patched.
fn already_patched_verify(file: &str) -> VerifyResult {
    VerifyResult {
        file: file.to_string(),
        status: VerifyStatus::AlreadyPatched,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    }
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: a
/// success [`ApplyResult`] in which every patched file reads as
/// `AlreadyPatched`, synthesized without running the apply pipeline (the
/// in-sync hot paths, and the service-download paths where trust is the
/// verified artifact integrity rather than a local apply).
pub(crate) fn already_patched_result(
    package_key: &str,
    path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> ApplyResult {
    let files_verified = files.keys().map(|f| already_patched_verify(f)).collect();
    synthesized_result(package_key, path, files_verified, true, None)
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: an
/// [`ApplyResult`] synthesized without running the apply pipeline.
pub(crate) fn synthesized_result(
    package_key: &str,
    path: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: path.display().to_string(),
        success,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
    }
}

/// Shared helper the vendor backends delegate to: a [`VendorOutcome::Refused`].
pub(crate) fn refused(code: &'static str, detail: impl Into<String>) -> VendorOutcome {
    VendorOutcome::Refused {
        code,
        detail: detail.into(),
    }
}

/// Shared helper the vendor backends delegate to: a [`VendorOutcome::Done`].
pub(crate) fn done(
    result: ApplyResult,
    entry: Option<VendorEntry>,
    warnings: Vec<VendorWarning>,
) -> VendorOutcome {
    VendorOutcome::Done {
        result,
        entry,
        warnings,
    }
}

/// Shared helper the vendor backends delegate to: the fail-closed refusals
/// for a `--vendor-source=service` run that cannot reach the service —
/// combined with `--offline`, or with no API client configured — checked
/// before any service consultation. Every backend's service helper treats
/// `!service_enabled()` as "build locally", so this is the one gate that
/// keeps `service` mode from silently building.
pub(crate) fn service_offline_conflict(
    service: Option<&VendorServiceConfig>,
) -> Option<VendorOutcome> {
    let cfg = service?;
    if !cfg.source.requires_service() {
        return None;
    }
    if cfg.offline {
        return Some(refused(
            "vendor_service_offline_conflict",
            "--vendor-source=service needs the network but --offline is set",
        ));
    }
    if cfg.client.is_none() {
        return Some(refused(
            "vendor_prebuilt_required",
            "--vendor-source=service needs the patch service but no API client is configured",
        ));
    }
    None
}

/// Shared helper the vendor backends delegate to: an un-successful
/// [`ApplyResult`] carrying `error`, synthesized without running the apply
/// pipeline.
pub(crate) fn failed_result(package_key: &str, path: &Path, error: String) -> ApplyResult {
    synthesized_result(package_key, path, Vec::new(), false, Some(error))
}

/// The file's indent unit: the leading whitespace of the first indented
/// line (npm emits 2 spaces; respect whatever formatter the project uses
/// so untouched lines stay byte-identical in diffs). Defaults to 2 spaces.
pub(crate) fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if !trimmed.is_empty() && trimmed.len() < line.len() {
            return line[..line.len() - trimmed.len()].to_string();
        }
    }
    "  ".to_string()
}

/// The file's dominant line terminator (new lines we write use it; bytes
/// outside edited spans keep whatever they had).
pub(crate) fn detect_eol(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Pretty-print JSON with `indent` + a trailing newline (the shape npm and
/// composer themselves emit), so untouched keys stay byte-identical and a
/// later `npm install` / `composer update` produces no format-only churn.
pub(crate) fn serialize_json(value: &Value, indent: &str) -> std::io::Result<Vec<u8>> {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    value.serialize(&mut ser).map_err(std::io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

/// Parse a JSON manifest, reading past a leading UTF-8 BOM the way npm,
/// Node and yarn berry (`Manifest.loadFromText`'s `stripBOM`) all do —
/// serde_json rejects one.
pub(crate) fn parse_json_manifest(bytes: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes))
}

/// The byte layout a re-serialized JSON manifest keeps from the text it
/// replaces, so a vendor edit and its revert change nothing but the edited
/// keys: the leading UTF-8 BOM, the indent unit ([`detect_indent`]), the
/// line terminator, and whatever trails the closing brace (the
/// trailing-newline shape, verbatim).
///
/// The terminator is CRLF for a CRLF file — yarn berry writes a
/// `package.json` it creates or first pretty-prints with `os.EOL`, so every
/// Windows project carries one — LF for an LF or single-line file, and, for
/// a file mixing both, the majority terminator yarn itself would rewrite it
/// with ([`majority_terminator`]; the forward vendor paths refuse such a
/// file before this runs, so only a revert reaches that arm).
pub(crate) struct JsonLayout {
    bom: bool,
    indent: String,
    eol: &'static str,
    trailer: String,
}

impl JsonLayout {
    /// The layout of `text` (a manifest's current contents).
    pub(crate) fn of(text: &str) -> Self {
        use crate::utils::line_endings::{majority_terminator, LineEndings};
        let (bom, body) = match text.strip_prefix('\u{feff}') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let content = body.trim_end_matches([' ', '\t', '\r', '\n']);
        let eol = match LineEndings::of(body) {
            LineEndings::Crlf => "\r\n",
            LineEndings::Mixed => majority_terminator(body),
            LineEndings::Lf | LineEndings::None => "\n",
        };
        Self {
            bom,
            indent: detect_indent(body),
            eol,
            trailer: body[content.len()..].to_string(),
        }
    }

    /// `value` pretty-printed ([`serialize_json`]) in this layout.
    pub(crate) fn render(&self, value: &Value) -> std::io::Result<Vec<u8>> {
        let mut pretty = serialize_json(value, &self.indent)?;
        // serialize_json's own trailing newline gives way to the trailer.
        pretty.pop();
        let pretty = String::from_utf8(pretty).map_err(std::io::Error::other)?;
        let mut out = String::with_capacity(pretty.len() + self.trailer.len() + 3);
        if self.bom {
            out.push('\u{feff}');
        }
        // serde_json escapes every newline INSIDE a string value, so each
        // `\n` it emits is a line break of the layout.
        if self.eol == "\n" {
            out.push_str(&pretty);
        } else {
            out.push_str(&pretty.replace('\n', self.eol));
        }
        out.push_str(&self.trailer);
        Ok(out.into_bytes())
    }
}

/// Serialize `(name, bytes, unix mode)` entries — in the given order — into
/// a deterministic zip: a fixed DOS timestamp (1980-01-01 00:00:00) and a
/// fixed deflate level, so rebuilding the same content always yields
/// identical bytes (churn-free commits, stable checksums).
pub(crate) fn write_zip_entries(entries: &[(String, Vec<u8>, u32)]) -> Result<Vec<u8>, String> {
    use std::io::Write as _;

    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes, mode) in entries {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(*mode);
        writer
            .start_file(name, options)
            .map_err(|e| format!("zip start {name}: {e}"))?;
        writer
            .write_all(bytes)
            .map_err(|e| format!("zip write {name}: {e}"))?;
    }
    let cursor = writer.finish().map_err(|e| format!("zip finish: {e}"))?;
    Ok(cursor.into_inner())
}

/// True when `metadata`'s unix mode carries any exec bit (always false on
/// non-unix, where archive modes are normalized at pack time instead).
pub(crate) fn is_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Re-zip a patched stage into a deterministic archive (see
/// [`write_zip_entries`]) with entries sorted lexicographically. Both
/// consumers (`.jar` / `.nupkg`) are plain zips whose resolvers read the
/// central directory, so entry order is free to be lexicographic.
/// `skip_entry` drops one archive-relative name (NuGet's `.signature.p7s` —
/// the content changed, so the rebuilt package must read as unsigned).
pub(crate) fn rebuild_zip(stage: &Path, skip_entry: Option<&str>) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(String, Vec<u8>, u32)> = Vec::new();
    for entry in walkdir::WalkDir::new(stage).follow_links(false) {
        let entry = entry.map_err(|e| format!("walk {}: {e}", stage.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(stage)
            .map_err(|e| format!("strip prefix: {e}"))?;
        let name = rel.to_string_lossy().replace('\\', "/");
        if skip_entry == Some(name.as_str()) {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| format!("read {name}: {e}"))?;
        entries.push((name, bytes, 0o644));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    write_zip_entries(&entries)
}

// ── in-memory local repack (the maven / nuget local build paths) ────────────

/// One archive member, decompressed into memory instead of onto disk.
pub(crate) struct ArchiveMember {
    /// Archive-relative, `/`-separated name — the name the rebuilt zip uses.
    name: String,
    bytes: Vec<u8>,
    /// The entry's unix exec bit, i.e. the mode
    /// [`super::registry_fetch::extract_zip`] would have put on the
    /// extracted file (0o755 vs 0o644).
    exec: bool,
    /// Set when the staged twin is gone after the apply (NuGet's sidecar
    /// fixup deletes `.nupkg.metadata`): the member then drops out of the
    /// rebuild exactly as it drops out of a walk over the stage.
    dropped: bool,
}

/// The in-memory twin of an [`super::registry_fetch::extract_zip`] with
/// `strip_first = false`:
/// every member decompressed into memory, in archive order, with the LAST
/// spelling of a repeated name winning — what an extraction to disk leaves
/// behind. Every guard (entry count, the per-entry and total decompressed
/// caps, the traversal refusal and the declared-vs-actual size check) runs in
/// the same order over the same constants and yields the same message, so a
/// refusal is indistinguishable from the on-disk path's.
///
/// The one thing it cannot reproduce is an extraction that fails because the
/// *filesystem* mangles or collides names — [`names_are_unambiguous`] is the
/// gate that keeps those archives on the on-disk path.
pub(crate) fn read_zip_members(bytes: &[u8]) -> Result<Vec<ArchiveMember>, String> {
    use std::io::Read as _;

    use super::registry_fetch::{MAX_ENTRIES, MAX_ENTRY_BYTES, MAX_TOTAL_DECOMPRESSED_BYTES};

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut members: Vec<ArchiveMember> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("unreadable zip entry: {e}"))?;
        if file.is_dir() {
            continue;
        }
        let raw = std::path::PathBuf::from(file.name());
        let rel_str = raw.to_string_lossy().into_owned();
        if !is_safe_relative_subpath(&rel_str) {
            return Err(format!(
                "zip entry `{}` escapes the extraction dir — refusing the artifact",
                raw.display()
            ));
        }
        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            return Err(format!(
                "zip entry `{rel_str}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"
            ));
        }
        total += declared;
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(format!(
                "zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
            ));
        }
        // The declared size is header data a crafted zip can understate, so
        // hold the caps against the ACTUAL decompressed bytes too: read at
        // most declared+1 and refuse on any mismatch (the on-disk twin's
        // `take(declared + 1)` copy).
        let mut content = Vec::with_capacity(declared as usize);
        (&mut file)
            .take(declared + 1)
            .read_to_end(&mut content)
            .map_err(|e| format!("cannot extract `{rel_str}`: {e}"))?;
        if content.len() as u64 != declared {
            return Err(format!(
                "zip entry `{rel_str}` decompresses to {} bytes but declares {declared} \
                 — refusing the artifact",
                content.len()
            ));
        }
        let exec = file.unix_mode().is_some_and(|m| m & 0o111 != 0);
        match at.get(&rel_str) {
            // A repeated name overwrote the earlier extraction in place. Two
            // entries whose RAW name bytes are identical never get this far —
            // `ZipArchive` keys its central directory on them in an `IndexMap`
            // and already collapsed the pair, last-wins, at the first index —
            // so what lands here is two raw spellings that DECODE to one name
            // (`String::from_utf8_lossy` folds distinct invalid bytes onto
            // U+FFFD), which `extract_zip` writes to one path just the same.
            Some(&i) => {
                members[i].bytes = content;
                members[i].exec = exec;
            }
            None => {
                at.insert(rel_str.clone(), members.len());
                members.push(ArchiveMember {
                    name: rel_str,
                    bytes: content,
                    exec,
                    dropped: false,
                });
            }
        }
    }
    Ok(members)
}

/// DOS device names: a file created under one of these on Windows opens the
/// device instead, so the "extracted" member never lands in the stage.
const DOS_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// `NAME_MAX`: the longest single path component APFS, ext4 and NTFS will
/// create. A member past it cannot be extracted at all — the on-disk path
/// fails the whole rebuild with `cannot create <path>: File name too long`,
/// so a name this long has to keep taking that path to keep failing.
const MAX_COMPONENT_BYTES: usize = 255;

/// And the whole name, so `<stage>/<name>` cannot pass `PATH_MAX` either
/// (1024 on macOS, the tightest of the three; a `tempfile` stage prefix is
/// ~60 bytes there, and Rust's Windows `File::create` takes the verbatim
/// `\\?\` route past `MAX_PATH`). Deliberately far above real archives: the
/// longest entry name across 78k members of 362 real jars is 149 bytes.
const MAX_NAME_BYTES: usize = 512;

/// True when `name` is spelled so that a filesystem can only ever store it as
/// itself — and can store it at all: printable ASCII (so no Unicode-normalising
/// filesystem folds it into a sibling), none of the characters Windows rewrites
/// or rejects, no component that a path walk re-spells (`.`, `..`, empty) or
/// that Windows trims (a trailing `.` or space) or redirects (a DOS device
/// name), and nothing longer than the filesystem would accept.
fn is_plain_archive_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return false;
    }
    if !name.chars().all(|c| {
        (c.is_ascii_graphic() || c == ' ')
            && !matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return false;
    }
    name.split('/').all(|part| {
        !part.is_empty()
            && part.len() <= MAX_COMPONENT_BYTES
            && part != "."
            && part != ".."
            && !part.ends_with('.')
            && !part.ends_with(' ')
            && !DOS_DEVICE_NAMES.iter().any(|d| {
                part.split('.')
                    .next()
                    .is_some_and(|stem| stem.eq_ignore_ascii_case(d))
            })
    })
}

/// True when `members` (the archive's, or the installed tree's) and `targets`
/// (the patch keys, normalized) name disjoint filesystem entries on any
/// filesystem, and no member is a directory another name lives in — the
/// precondition under which keeping members in memory is indistinguishable
/// from extracting them (see [`read_zip_members`]).
///
/// Extracting to disk is lossy in ways only the filesystem knows about: a
/// case-insensitive or Unicode-normalising volume collapses two names into one
/// entry, Windows trims and redirects some spellings, a `\` in a name becomes a
/// `/` on the way back out of the walk, and a name that is a file where another
/// needs a directory fails the extraction (or the patch write) outright. Rather
/// than model any of that, the callers keep memory and disk in lockstep only
/// while every name is plain ASCII and no two distinct spellings fold together;
/// anything else falls back to the extract-to-disk path, whose behaviour is then
/// reproduced by definition.
///
/// Members and targets are told apart for the ancestor rule alone: a target
/// that names a DIRECTORY of the archive is ordinary (the staging materialises
/// one), whereas a name living under a member — which is a FILE — is the case
/// where the two paths diverge.
///
/// Every `/`-separated PREFIX is checked, not only the whole name: a directory
/// is a filesystem entry too, so `Lib/a.class` + `lib/b.class` collapse into
/// one directory on a case-insensitive volume and the walk back out re-spells
/// the second member under the first's casing — a different rebuilt archive,
/// silently.
pub(crate) fn names_are_unambiguous<'a>(
    members: impl IntoIterator<Item = &'a str>,
    targets: impl IntoIterator<Item = &'a str>,
) -> bool {
    let mut folded: HashMap<String, &str> = HashMap::new();
    let mut member_folded: HashSet<String> = HashSet::new();
    for (name, is_member) in members
        .into_iter()
        .map(|n| (n, true))
        .chain(targets.into_iter().map(|n| (n, false)))
    {
        if !is_plain_archive_name(name) {
            return false;
        }
        for end in name
            .match_indices('/')
            .map(|(at, _)| at)
            .chain(std::iter::once(name.len()))
        {
            let part = &name[..end];
            let lower = part.to_ascii_lowercase();
            // The same path can legitimately arrive twice — a patch target IS
            // usually a member, and siblings share their directories. Only a
            // DIFFERENT spelling folding onto one already seen is ambiguous.
            match folded.get(lower.as_str()) {
                Some(seen) if *seen != part => return false,
                Some(_) => {}
                None => {
                    folded.insert(lower.clone(), part);
                }
            }
            // Only the whole name is a member FILE; its prefixes are the
            // directories it lives in, which the ancestor rule below is about.
            if is_member && end == name.len() {
                member_folded.insert(lower);
            }
        }
    }
    for name in folded.keys() {
        let mut prefix = name.as_str();
        while let Some(cut) = prefix.rfind('/') {
            prefix = &prefix[..cut];
            if member_folded.contains(prefix) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
thread_local! {
    /// Test seam: forces every local rebuild down the extract-to-disk staging
    /// the in-memory repack is defined against, so the equivalence tests can
    /// drive one fixture through both and compare the rebuilt artifact byte
    /// for byte. Only [`can_repack_in_memory`] reads it —
    /// [`names_are_unambiguous`] keeps answering for itself, so the gate's own
    /// tests are unaffected.
    ///
    /// THREAD-LOCAL, not process-wide: `#[tokio::test]` runs its whole future
    /// on the test's own thread, and libtest gives every test a thread of its
    /// own, so a forced run cannot reach the ~40 other local-rebuild tests
    /// running beside it and silently move them off the in-memory path.
    static FORCE_ON_DISK_REPACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// How many rebuilds took the in-memory path on THIS thread — the
    /// equivalence tests read it to prove which staging each of their two runs
    /// actually used, rather than trusting the seam and the fixture's names.
    static IN_MEMORY_REPACKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Sets [`FORCE_ON_DISK_REPACK`] for as long as it is held.
#[cfg(test)]
pub(crate) struct OnDiskRepackGuard;

#[cfg(test)]
impl OnDiskRepackGuard {
    pub(crate) fn acquire() -> Self {
        FORCE_ON_DISK_REPACK.set(true);
        Self
    }
}

#[cfg(test)]
impl Drop for OnDiskRepackGuard {
    fn drop(&mut self) {
        FORCE_ON_DISK_REPACK.set(false);
    }
}

/// The running count of [`IN_MEMORY_REPACKS`] for this thread; a test brackets
/// a rebuild with it to assert which staging ran.
#[cfg(test)]
pub(crate) fn in_memory_repacks() -> usize {
    IN_MEMORY_REPACKS.get()
}

/// Whether a local rebuild may keep the archive (or the installed tree) in
/// memory: the [`names_are_unambiguous`] gate, plus the test seam.
pub(crate) fn can_repack_in_memory<'a>(
    members: impl IntoIterator<Item = &'a str>,
    targets: impl IntoIterator<Item = &'a str>,
) -> bool {
    #[cfg(test)]
    if FORCE_ON_DISK_REPACK.get() {
        return false;
    }
    let in_memory = names_are_unambiguous(members, targets);
    #[cfg(test)]
    if in_memory {
        IN_MEMORY_REPACKS.set(IN_MEMORY_REPACKS.get() + 1);
    }
    in_memory
}

/// A local rebuild carried in memory: the archive's members never touch the
/// stage, only the handful of paths the apply pipeline (and the ecosystem's
/// sidecar fixup) resolves do, and the rebuilt archive is assembled from the
/// two halves.
pub(crate) struct MemoryRepack {
    members: Vec<ArchiveMember>,
    at: HashMap<String, usize>,
    /// The paths materialised in the stage — everything the apply pipeline
    /// can read, write, create or delete — in a deterministic order: the
    /// sorted patch targets, then the extras the caller adds, each once.
    /// [`Self::stage_into`] and [`Self::into_entries`] both return on the
    /// first I/O failure, so the order decides which path a failure names.
    wanted: Vec<String>,
}

/// Read `archive` into memory for an in-place rebuild, or `Ok(None)` when its
/// names (together with `files`' patch targets and `extra`) are not unambiguous
/// on every filesystem — the caller must then extract to disk instead, which is
/// what this path is defined against. Errors are
/// [`super::registry_fetch::extract_zip`]'s, verbatim.
///
/// `extra` names the fixed paths the ecosystem's sidecar fixup resolves beside
/// the patch targets (NuGet's `.nupkg.metadata`). They are materialised like a
/// target and, like one, must not fold onto a member under a different
/// spelling — the fixup would delete that member on a case-insensitive volume
/// and leave it in place on a case-sensitive one.
pub(crate) fn prepare_memory_repack(
    archive: &[u8],
    files: &HashMap<String, PatchFileInfo>,
    extra: &[&str],
) -> Result<Option<MemoryRepack>, String> {
    let members = read_zip_members(archive)?;
    let mut targets: Vec<&str> = patch_target_paths(files);
    targets.extend_from_slice(extra);
    if !can_repack_in_memory(
        members.iter().map(|m| m.name.as_str()),
        targets.iter().copied(),
    ) {
        return Ok(None);
    }
    let at = members
        .iter()
        .enumerate()
        .map(|(i, m)| (m.name.clone(), i))
        .collect();
    let mut repack = MemoryRepack {
        members,
        at,
        wanted: Vec::new(),
    };
    for target in targets {
        repack.also_stage(target);
    }
    Ok(Some(repack))
}

/// The in-package paths the apply pipeline resolves for `files`: each key
/// normalized, with the escaping keys the pipeline itself refuses dropped (it
/// never joins them, so nothing has to be materialised for them either).
///
/// SORTED, because `files` is a `HashMap` with a per-process random hasher and
/// every caller walks this list until the first I/O error: without the sort,
/// two runs over one package under ENOSPC or EACCES name a different file in
/// the failure. That is the invariant `patch::apply::files_in_order` states for
/// the apply itself, and the reason `PatchRecord::files` serializes sorted.
pub(crate) fn patch_target_paths(files: &HashMap<String, PatchFileInfo>) -> Vec<&str> {
    let mut paths: Vec<&str> = files
        .keys()
        .map(|key| normalize_file_path(key))
        .filter(|path| is_safe_relative_subpath(path))
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

impl MemoryRepack {
    /// Also materialise `name` in the stage — the hook the ecosystem sidecar
    /// fixups need for the paths they inspect outside the patch target set
    /// (NuGet's `.nupkg.metadata` and its `*.nupkg.sha512` markers).
    pub(crate) fn also_stage(&mut self, name: &str) {
        if !self.wanted.iter().any(|w| w == name) {
            self.wanted.push(name.to_string());
        }
    }

    /// Every member name, for the callers that pick their extra staged paths
    /// out of the archive itself.
    pub(crate) fn member_names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|m| m.name.as_str())
    }

    /// Materialise the wanted paths under `stage`: a member is written with
    /// the mode [`super::registry_fetch::extract_zip`] would have given it, a name that only exists
    /// as a directory in the archive is created as one (so a patch key
    /// pointing at a directory still hashes as one), and a name the archive
    /// does not carry is left absent.
    pub(crate) async fn stage_into(&self, stage: &Path) -> Result<(), String> {
        for name in &self.wanted {
            let target = stage.join(name);
            match self.at.get(name) {
                Some(&i) => {
                    if let Some(parent) = target.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                    }
                    tokio::fs::write(&target, &self.members[i].bytes)
                        .await
                        .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let perms = if self.members[i].exec { 0o755 } else { 0o644 };
                        let _ = std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(perms),
                        );
                    }
                }
                None if self.names_a_directory(name) => {
                    tokio::fs::create_dir_all(&target)
                        .await
                        .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// True when the archive carries members UNDER `name`, i.e. extracting it
    /// would have created a directory there.
    fn names_a_directory(&self, name: &str) -> bool {
        let prefix = format!("{name}/");
        self.members.iter().any(|m| m.name.starts_with(&prefix))
    }

    /// Reconcile the staged paths back into the in-memory members and emit the
    /// [`write_zip_entries`] list: the same lexicographic order and flat 0o644
    /// mode [`rebuild_zip`] produces over a fully extracted stage. A staged
    /// path the apply wrote carries its new bytes, one it created joins the
    /// archive, and one it deleted leaves it.
    pub(crate) async fn into_entries(
        mut self,
        stage: &Path,
        skip_entry: Option<&str>,
    ) -> Result<Vec<(String, Vec<u8>, u32)>, String> {
        for name in &self.wanted {
            let path = stage.join(name);
            // A walk over the stage yields regular files and nothing else, so
            // an absent path (or a directory left where a patch key pointed)
            // simply contributes no entry.
            let live = matches!(tokio::fs::metadata(&path).await, Ok(m) if m.is_file());
            match (live, self.at.get(name)) {
                (true, Some(&i)) => {
                    self.members[i].bytes = tokio::fs::read(&path)
                        .await
                        .map_err(|e| format!("read {name}: {e}"))?;
                }
                (true, None) => {
                    let bytes = tokio::fs::read(&path)
                        .await
                        .map_err(|e| format!("read {name}: {e}"))?;
                    self.members.push(ArchiveMember {
                        name: name.clone(),
                        bytes,
                        exec: false,
                        dropped: false,
                    });
                }
                (false, Some(&i)) => self.members[i].dropped = true,
                (false, None) => {}
            }
        }
        let mut entries: Vec<(String, Vec<u8>, u32)> = self
            .members
            .into_iter()
            .filter(|m| !m.dropped && skip_entry != Some(m.name.as_str()))
            .map(|m| (m.name, m.bytes, 0o644))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

/// A private stage directory whose (recursive) deletion can be handed to the
/// blocking pool: [`tempfile::TempDir`]'s own `Drop` unlinks the whole tree
/// synchronously, which on the build paths ran on the runtime thread. Dropping
/// a `Stage` without [`Stage::dispose`] still deletes it the old way, so every
/// early return stays correct.
pub(crate) struct Stage(Option<tempfile::TempDir>);

impl Stage {
    pub(crate) fn new() -> std::io::Result<Self> {
        Ok(Self(Some(tempfile::tempdir()?)))
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.as_ref().expect("stage is live until dispose").path()
    }

    /// Delete the stage on the blocking pool.
    pub(crate) async fn dispose(mut self) {
        if let Some(dir) = self.0.take() {
            let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
        }
    }
}

/// Bound on a committed `.jar` / `.nupkg` the in-sync probe is willing to
/// read into memory: the whole-file cap `verify.rs` applies to the same
/// artifacts (`MAX_HEALTH_HASH_BYTES`), which also covers everything the
/// rebuild path can produce (`extract_zip` bounds the decompressed payload
/// at 512 MiB and a deflated archive is never larger than its payload) — so
/// a valid committed artifact can never read as stale because of the cap.
const MAX_ZIP_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// The committed archive's bytes, or `None` when it is missing, not a regular
/// file, or over the cap. Guarded open (`open_regular_file`: O_NONBLOCK +
/// regular-file check): a FIFO planted at the archive path must read as
/// out-of-sync, not wedge the probe forever in an `open(2)` waiting for a
/// writer. The archive is committed and tamper-able: the size gate runs on
/// the open handle's metadata BEFORE anything is read, like the blob harvest
/// in `vendor/mod.rs`, so an oversized file is never slurped into memory.
/// Backends that need the bytes for more than the member check (a sidecar /
/// content hash) read once through this and hand them to
/// [`zip_bytes_match_after_hashes`].
pub(crate) async fn read_zip_artifact(archive_path: &Path) -> Option<Vec<u8>> {
    read_zip_artifact_capped(archive_path, MAX_ZIP_ARTIFACT_BYTES).await
}

async fn read_zip_artifact_capped(archive_path: &Path, cap: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let path = archive_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let (mut file, metadata) = open_regular_file_sync(&path).ok()?;
        if metadata.len() > cap {
            return None;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes).ok()?;
        Some(bytes)
    })
    .await
    .ok()
    .flatten()
}

/// True when the committed archive (a plain zip: `.jar` / `.nupkg`) — its
/// bytes read once through [`read_zip_artifact`] — has every patched file
/// already hashing to its `afterHash` (the zip twin of
/// [`copy_matches_after_hashes`], reading the archive's entries).
pub(crate) fn zip_bytes_match_after_hashes(
    bytes: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    use std::io::Read as _;

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return false;
    };
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never look up a key that escapes the package dir — treat
        // it as out-of-sync (the full pipeline would refuse it anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        let Ok(mut entry) = archive.by_name(normalized) else {
            return false;
        };
        let mut content = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut content).is_err() {
            return false;
        }
        if compute_git_sha256_from_bytes(&content) != info.after_hash {
            return false;
        }
    }
    true
}

// ── staged materialisation (cargo / composer / gem / golang) ────────────────

/// A swap sibling for a copy dir: `<parent>/<leaf><suffix>`. Same directory
/// as the copy → every swap step is a real rename, never a cross-device copy.
/// The suffixes can never collide with a copy dir: every backend creates
/// exactly one validated `<name>-<version>` / `<module>@<version>` leaf per
/// uuid dir, and no version token ends in `.socket-stage` / `.socket-old`.
pub(crate) fn swap_sibling_for(copy_dir: &Path, suffix: &str) -> std::path::PathBuf {
    let name = copy_dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "copy".to_string());
    match copy_dir.parent() {
        Some(parent) => parent.join(format!("{name}{suffix}")),
        None => copy_dir.join(suffix),
    }
}

/// The staging sibling for a copy dir: `<copy>.socket-stage`. (Re)builds are
/// materialised here and swapped into place only on success, so a failure
/// can never destroy a pre-existing (possibly live-wired) copy.
pub(crate) fn stage_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-stage")
}

/// The backup sibling the old copy is parked at mid-swap: `<copy>.socket-old`.
pub(crate) fn backup_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-old")
}

/// Swap a fully-built stage into place without a destructive window: park the
/// old copy (if any) at `<copy>.socket-old` with a same-dir rename, rename the
/// stage over the now-vacant copy path, and only then delete the backup. Every
/// step is a single atomic rename — unlike a remove-then-rename swap (where a
/// partial `remove_dir_all`, realistic under Windows file locks, strands a
/// half-deleted copy) no step can leave less recoverable state than it started
/// with. If the stage rename fails the backup is renamed straight back; should
/// even that restore fail (an external process racing the uuid dir), the old
/// copy still exists intact at `<copy>.socket-old` instead of being destroyed.
pub(crate) async fn swap_stage_into_place(stage: &Path, copy_dir: &Path) -> std::io::Result<()> {
    let backup = backup_dir_for(copy_dir);
    // A stale backup (crash mid-swap on an earlier run) would make the
    // park rename fail; `remove_tree` is a no-op when it is absent.
    remove_tree(&backup).await?;
    let had_old = match tokio::fs::rename(copy_dir, &backup).await {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    match tokio::fs::rename(stage, copy_dir).await {
        Ok(()) => {
            if had_old {
                let _ = remove_tree(&backup).await;
            }
            Ok(())
        }
        Err(e) => {
            if had_old {
                let _ = tokio::fs::rename(&backup, copy_dir).await;
            }
            Err(e)
        }
    }
}

/// Best-effort removal of an EMPTY `<uuid>/` dir plus the empty
/// `.socket/vendor/<eco>/` and `.socket/vendor/` levels a vendor run may have
/// created (or a revert may have emptied), so neither a hard failure nor the
/// reversal of the last entry of an ecosystem leaves a husk for the user to
/// commit. The climb is the shared
/// [`prune_empty_dirs`](crate::utils::socket_dir::prune_empty_dirs):
/// non-recursive, so live copies, markers, the ledger and other entries'
/// vendor dirs always survive, and a uuid level already unwound wholesale
/// (`remove_tree` before the prune) still lets its parents go. `uuid_dir` is
/// `<project>/.socket/vendor/<eco>/<uuid>`, so the stop dir — never removed —
/// is three levels up: `.socket/` itself, which the apply lock guard owns.
pub(crate) async fn prune_empty_vendor_levels(uuid_dir: &Path) {
    let Some(socket_dir) = uuid_dir.ancestors().nth(3) else {
        return;
    };
    crate::utils::socket_dir::prune_empty_dirs(uuid_dir, socket_dir).await;
}

/// True when any of `files` (root-relative wiring files a backend authored)
/// still names `uuid_dir_rel`: the package manager can still be routed at
/// the vendored artifact even though no wiring record could restore the
/// fragment. This is the drift-keep gate of the whole-file backends
/// (composer / maven / nuget). Unlike the lock backends, their drift
/// classification is not liveness-aware — a converged file (our block
/// already gone, a regenerated pom) reads as `vendor_lock_entry_drifted`
/// too — so gating the keep on the drift warning alone would keep the
/// artifact and ledger entry forever (the LIVENESS CONTRACT on
/// [`RevertOutcome::drift_skipped`]). A live reference is the one thing a
/// converged file never carries, so keeping exactly while one exists is
/// both safe (nothing a file still routes at is deleted) and live (the
/// user can always undo the drift). A file that cannot be read (absent,
/// unreadable, not a regular file) references nothing.
pub(crate) async fn any_live_file_references(
    root: &Path,
    files: &[&str],
    uuid_dir_rel: &str,
) -> bool {
    for file in files {
        if read_regular_to_string(&root.join(file))
            .await
            .is_ok_and(|live| live.contains(uuid_dir_rel))
        {
            return true;
        }
    }
    false
}

// ── pre-write guards shared by the pypi lock flavors ────────────────────────

/// Refuse (with the flavor's stable `code`) when any of `files` (root-relative)
/// is itself a symbolic link. Every lock writer stages a replacement next to
/// the path and renames over it, which REPLACES the link with a detached
/// regular file: the shared target the link points at stays unpatched (git
/// shows a 120000→100644 typechange), and `revert` restores bytes but never
/// the link. Both wire and revert check before any write — the package
/// managers themselves write THROUGH a linked lock.
pub(crate) async fn refuse_symlinked(
    root: &Path,
    files: &[&str],
    code: &'static str,
) -> Result<(), (&'static str, String)> {
    match first_symlink(root, files.iter().copied()).await {
        Some(file) => Err((
            code,
            format!(
                "{file} is a symbolic link; the atomic rewrite would replace the link with \
                 a regular file and leave its target stale — vendor the real file's directory \
                 instead"
            ),
        )),
        None => Ok(()),
    }
}

/// Refuse (with the flavor's stable `code`) when `file` (root-relative) no
/// longer holds the `snapshot` the wiring plan was computed from. The lock
/// flavors deliberately snapshot their files in the pre-flight (so refusals
/// leave the tree byte-untouched) and only write after the wheel build — a
/// `poetry lock` / `pdm lock` / editor save landing in between would
/// otherwise be silently overwritten with stale snapshot-derived text and
/// recorded as the entry's `original`. A file that has been REMOVED since
/// the snapshot is refused the same way: the stage-and-rename write would
/// otherwise recreate it from snapshot-derived text and record it as wired.
/// Any other re-read failure is left to the write that follows — a
/// directory squatting on the path fails the rename with the flavor's own
/// write-failed code.
pub(crate) async fn ensure_unchanged(
    root: &Path,
    file: &str,
    snapshot: &str,
    code: &'static str,
) -> Result<(), (&'static str, String)> {
    match read_regular_to_string(&root.join(file)).await {
        Ok(live) if live != snapshot => Err((
            code,
            format!("{file} changed during vendoring; re-run to vendor against the new contents"),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err((
            code,
            format!(
                "{file} changed during vendoring (it no longer exists); re-run to vendor against the new contents"
            ),
        )),
        _ => Ok(()),
    }
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: true
/// when the copy exists and every patched file in it already hashes to its
/// `afterHash`.
pub(crate) async fn copy_matches_after_hashes(
    copy_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    if tokio::fs::metadata(copy_dir).await.is_err() {
        return false;
    }
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never hash through a manifest key that escapes the copy
        // dir — fail the sync check instead (the full pipeline would refuse
        // the key anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        match compute_file_git_sha256(&copy_dir.join(normalized)).await {
            Ok(h) if h == info.after_hash => {}
            _ => return false,
        }
    }
    true
}

/// Shared [`WiringRecord`] constructor for the lock-splicing backends:
/// `original`/`new` are verbatim text fragments of `file`.
pub(crate) fn record(
    file: &str,
    kind: &str,
    action: WiringAction,
    key: &str,
    original: Option<String>,
    new: String,
) -> WiringRecord {
    WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action,
        key: Some(key.to_string()),
        original: original.map(Value::String),
        new: Some(Value::String(new)),
    }
}

/// `key` looked up through any table-like TOML item (standard or inline
/// table).
pub(crate) fn item_get<'a>(item: &'a Item, key: &str) -> Option<&'a Item> {
    item.as_table_like().and_then(|t| t.get(key))
}

/// Leading PEP 508 distribution name of a dependency spec.
pub(crate) fn pep508_name(spec: &str) -> &str {
    let s = spec.trim_start();
    let end = s
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

/// Whether a `[[package]]` unit (as its lines) names `canon` — PEP 503
/// canonical comparison, the form the pypi lock generators record.
pub(crate) fn unit_has_canon_name(lines: &[&str], canon: &str) -> bool {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("name = "))
        .map(|r| canonicalize_pypi_name(r.trim().trim_matches('"')))
        .as_deref()
        == Some(canon)
}

/// The lock's `[[package]]` tables whose `name` canonicalizes (PEP 503) to
/// `canon_name` — the poetry/pdm target-guard probe (uv records names
/// pre-canonicalized and counts them directly instead).
pub(crate) fn lock_units_named<'a>(lock: &'a DocumentMut, canon_name: &str) -> Vec<&'a Table> {
    lock.get("package")
        .and_then(Item::as_array_of_tables)
        .map(|pkgs| {
            pkgs.iter()
                .filter(|t| {
                    t.get("name")
                        .and_then(Item::as_str)
                        .map(canonicalize_pypi_name)
                        .as_deref()
                        == Some(canon_name)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The pyproject table a PEP 508 dependency string is declared in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeclTable {
    /// `[project] dependencies`.
    Project,
    /// A `[project.optional-dependencies]` extra.
    Optional,
    /// A PEP 735 `[dependency-groups]` group.
    Group,
    /// A Hatch environment's `dependencies` / `extra-dependencies`
    /// (`utils::hatch::dependency_specs`).
    Env,
}

/// Every PEP 508 string of `doc`'s PEP 621 / PEP 735 declaration tables, in
/// document order: `[project] dependencies`, then each
/// `[project.optional-dependencies]` extra, then each `[dependency-groups]`
/// group. Non-string members (a PEP 735 `{include-group = …}`) and
/// non-array groups are skipped. The one walk the uv / pdm / poetry
/// classifiers, the uv metadata rewriter, the Hatch planner and lockfile
/// discovery share; each applies its own name rule to the strings.
pub(crate) fn pyproject_dependency_specs(doc: &DocumentMut) -> Vec<(DeclTable, &str)> {
    fn strings(item: Option<&Item>) -> impl Iterator<Item = &str> {
        item.and_then(Item::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml_edit::Value::as_str)
    }
    fn groups(item: Option<&Item>) -> impl Iterator<Item = (&str, &Item)> {
        item.and_then(Item::as_table_like)
            .into_iter()
            .flat_map(|table| table.iter())
    }
    let project = doc.get("project");
    let mut specs: Vec<(DeclTable, &str)> = strings(project.and_then(|p| p.get("dependencies")))
        .map(|s| (DeclTable::Project, s))
        .collect();
    for (_, group) in groups(project.and_then(|p| p.get("optional-dependencies"))) {
        specs.extend(strings(Some(group)).map(|s| (DeclTable::Optional, s)));
    }
    for (_, group) in groups(doc.get("dependency-groups")) {
        specs.extend(strings(Some(group)).map(|s| (DeclTable::Group, s)));
    }
    specs
}

/// Collect the PEP 621 `[project] dependencies` / `optional-dependencies`
/// distribution names into `declared` — the pyproject surface shared by the
/// poetry/pdm/uv dep classifiers (each adds its tool-specific tables on top).
pub(crate) fn pep621_declared_names(doc: &DocumentMut, declared: &mut Vec<String>) {
    declared.extend(
        pyproject_dependency_specs(doc)
            .into_iter()
            .filter(|(table, _)| *table != DeclTable::Group)
            .map(|(_, spec)| pep508_name(spec).to_string()),
    );
}

/// Shared revert for the single-file, single-kind lock-splice backends
/// (poetry/pdm): restore the verbatim original fragment each wiring record
/// holds for `lock_file`. A fragment that no longer matches what we wrote is
/// left alone with a `vendor_lock_entry_drifted` warning — revert never
/// clobbers third-party edits.
pub(crate) async fn revert_lock_fragment_splice(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
    lock_file: &str,
    kind: &str,
    flavor: &str,
) -> RevertOutcome {
    revert_lock_fragment_splice_inner(entry, root, dry_run, lock_file, kind, flavor, false).await
}

/// [`revert_lock_fragment_splice`] for backends whose records are COUPLED
/// (poetry's legacy formats write the `[package.source]` table and the
/// `[metadata.files]` entry as two fragments): when any recorded fragment has
/// drifted, nothing is written — a half-restored lock (registry hashes with a
/// vendored source, or the reverse) is worse than the wired one. Records this
/// build does not recognize are skipped with a warning as usual and do not
/// hold the write.
pub(crate) async fn revert_lock_fragment_splice_atomic(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
    lock_file: &str,
    kind: &str,
    flavor: &str,
) -> RevertOutcome {
    revert_lock_fragment_splice_inner(entry, root, dry_run, lock_file, kind, flavor, true).await
}

async fn revert_lock_fragment_splice_inner(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
    lock_file: &str,
    kind: &str,
    flavor: &str,
    atomic: bool,
) -> RevertOutcome {
    let lock_path = root.join(lock_file);
    // Guarded read (`read_regular_to_string`: O_NONBLOCK + regular-file
    // check): a FIFO planted as the lock must fail this revert fast and
    // loudly, not wedge remove/rollback forever in an `open(2)` waiting for
    // a writer.
    let mut lock_text = match read_regular_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read {lock_file}: {e}")),
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();
    // Set once a fragment was actually spliced: a fully converged revert (a
    // second `vendor --revert`, a rollback after a relock) must not rewrite a
    // byte-identical lock (new inode + mtime, spurious "modified" in
    // editors and watchers).
    let mut changed = false;
    // Set when a recorded fragment is neither present nor already restored:
    // the only condition under which the atomic flavor must hold the write
    // (restoring the source table while its integrity entry stays patched, or
    // vice versa, would leave a lock Poetry cannot install). A record this
    // build does not understand (foreign file, unknown kind) is skipped with a
    // warning but must not veto restoring the fragments it does understand.
    let mut drifted = false;

    for rec in entry.wiring.iter().rev() {
        // SECURITY: `rec.file` comes verbatim from the committed, tamper-able
        // state.json. These backends only ever wrote their single lock file
        // (the per-flavor file allowlist); any other recorded path is skipped
        // fail-closed with a warning and is NEVER resolved against the
        // filesystem.
        if rec.file != lock_file {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for unexpected file `{}` (only {lock_file} is \
                     {flavor}-owned)",
                    rec.file
                ),
            ));
            continue;
        }
        // Forward compatibility: a newer ledger's unknown kind degrades to a
        // warning (never guess at a fragment shape).
        if rec.kind != kind {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown {flavor} wiring kind {:?}; skipped", rec.kind),
            ));
            continue;
        }
        let new_text = rec.new.as_ref().and_then(Value::as_str);
        let original_text = rec.original.as_ref().and_then(Value::as_str);
        match super::toml_surgery::replace_fragment(&lock_text, new_text, original_text) {
            Some(t) => {
                if t != lock_text {
                    lock_text = t;
                    changed = true;
                }
            }
            None => {
                // ALREADY CONVERGED (the LIVENESS CONTRACT, vendor/mod.rs):
                // the lock already carries the recorded pre-vendor original
                // — an earlier partial revert or a relock regeneration
                // already restored the unit. Not drift: stay silent so the
                // drift-skip keep gate can converge instead of keeping the
                // artifact dir and ledger entry forever.
                if original_text.is_some_and(|orig| lock_text.contains(orig)) {
                    continue;
                }
                drifted = true;
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!(
                        "{lock_file} fragment for {:?} changed since vendoring; left untouched",
                        rec.key
                    ),
                ));
            }
        }
    }

    if changed && !dry_run && (!atomic || !drifted) {
        // Mode-preserving: the lock is a user-owned file we merely edit, so
        // the swapped-in inode must keep its permission bits rather than
        // reset them to umask defaults.
        if let Err(e) = atomic_write_bytes_preserving_mode(&lock_path, lock_text.as_bytes()).await {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings,
                error: Some(format!("cannot write {lock_file}: {e}")),
            };
        }
    }
    RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    /// A manifest re-rendered in its own layout is byte-identical to itself
    /// whenever it is in the canonical pretty shape (what yarn / npm write):
    /// indent, CRLF vs LF, BOM and the trailing-newline shape all carry.
    #[test]
    fn json_layout_round_trips_canonical_manifests_in_every_shape() {
        let lf = "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"x\": \"1\"\n  }\n}\n";
        let shapes = [
            lf.to_string(),
            lf.replace('\n', "\r\n"),
            format!("\u{feff}{lf}"),
            format!("\u{feff}{}", lf.replace('\n', "\r\n")),
            lf.trim_end().to_string(),
            lf.trim_end().replace('\n', "\r\n"),
            format!("{lf}\n"),
            lf.replace("  ", "\t"),
            lf.replace("  ", "    ").replace('\n', "\r\n"),
        ];
        for text in shapes {
            let value = parse_json_manifest(text.as_bytes()).unwrap();
            let out = JsonLayout::of(&text).render(&value).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), text, "{text:?}");
        }
    }

    /// An edit lands in the file's layout; a single-line file becomes a
    /// pretty LF one (no line ending to inherit, and none from the OS); a
    /// mixed file takes the ending yarn would rewrite it with (majority,
    /// ties LF); a newline inside a string value stays escaped.
    #[test]
    fn json_layout_renders_edits_in_the_file_layout() {
        let render = |text: &str, value: serde_json::Value| {
            String::from_utf8(JsonLayout::of(text).render(&value).unwrap()).unwrap()
        };
        let value = serde_json::json!({ "a": "x\ny", "b": 1 });
        assert_eq!(
            render("\u{feff}{\r\n  \"a\": 0\r\n}\r\n", value.clone()),
            "\u{feff}{\r\n  \"a\": \"x\\ny\",\r\n  \"b\": 1\r\n}\r\n"
        );
        assert_eq!(
            render("{\"a\":0}", value.clone()),
            "{\n  \"a\": \"x\\ny\",\n  \"b\": 1\n}"
        );
        assert_eq!(
            render("{\r\n  \"a\": 0,\r\n  \"c\": 2\n}\r\n", value.clone()),
            "{\r\n  \"a\": \"x\\ny\",\r\n  \"b\": 1\r\n}\r\n",
            "majority CRLF"
        );
        assert_eq!(
            render("{\r\n  \"a\": 0\n}", value),
            "{\n  \"a\": \"x\\ny\",\n  \"b\": 1\n}",
            "a tie is LF"
        );
    }

    #[test]
    fn parse_json_manifest_reads_past_one_bom_only() {
        assert_eq!(
            parse_json_manifest(b"\xef\xbb\xbf{\"a\":1}").unwrap(),
            serde_json::json!({ "a": 1 })
        );
        assert!(parse_json_manifest(b"\xef\xbb\xbf\xef\xbb\xbf{}").is_err());
        assert!(parse_json_manifest(b"{} \xef\xbb\xbf").is_err());
    }

    /// `[project] dependencies` and every optional-dependencies extra, by
    /// PEP 508 name; groups, tool tables, non-array extras and non-string
    /// members are not PEP 621 declarations.
    #[test]
    fn pep621_declared_names_reads_dependencies_and_extras_only() {
        let doc: DocumentMut = "[project]\ndependencies = [\" Alpha >=1\", 3]\n\
                                [project.optional-dependencies]\nx = [\"beta[extra]; os_name == 'nt'\"]\n\
                                y = \"gamma\"\nz = [{ include = 1 }, \"delta\"]\n\
                                [dependency-groups]\nqa = [\"epsilon\"]\n\
                                [tool.uv]\ndev-dependencies = [\"zeta\"]\n"
            .parse()
            .unwrap();
        let mut declared = vec!["kept".to_string()];
        pep621_declared_names(&doc, &mut declared);
        assert_eq!(declared, ["kept", "Alpha", "beta", "delta"]);
        let mut none = Vec::new();
        pep621_declared_names(&"[tool.x]\ny = 1\n".parse().unwrap(), &mut none);
        assert!(none.is_empty());
    }

    /// An archive over the size cap reads as out-of-sync (`None`) without
    /// being read, and one within it is returned whole.
    #[tokio::test]
    async fn read_zip_artifact_gates_on_size_before_reading() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pkg.jar");
        tokio::fs::write(&path, b"0123456789").await.unwrap();
        assert!(read_zip_artifact_capped(&path, 9).await.is_none());
        assert_eq!(
            read_zip_artifact_capped(&path, 10).await.as_deref(),
            Some(&b"0123456789"[..])
        );
        assert!(
            read_zip_artifact_capped(&tmp.path().join("missing.jar"), 10)
                .await
                .is_none()
        );
    }

    /// A lock removed between the pre-flight snapshot and the write is a
    /// change too: refused before the write would recreate it.
    #[tokio::test]
    async fn ensure_unchanged_refuses_a_removed_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err = ensure_unchanged(tmp.path(), "poetry.lock", "snapshot", "x_changed")
            .await
            .unwrap_err();
        assert_eq!(err.0, "x_changed");
        assert!(err.1.contains("changed during vendoring"), "{}", err.1);
        assert!(!tmp.path().join("poetry.lock").exists());

        tokio::fs::write(tmp.path().join("poetry.lock"), "snapshot")
            .await
            .unwrap();
        ensure_unchanged(tmp.path(), "poetry.lock", "snapshot", "x_changed")
            .await
            .unwrap();
    }

    /// The path-taking shape the maven / nuget probes compose out of
    /// [`read_zip_artifact`] + [`zip_bytes_match_after_hashes`]: one guarded,
    /// capped read, then the member-hash check.
    async fn zip_matches_after_hashes(
        archive_path: &Path,
        files: &HashMap<String, PatchFileInfo>,
    ) -> bool {
        match read_zip_artifact(archive_path).await {
            Some(bytes) => zip_bytes_match_after_hashes(&bytes, files),
            None => false,
        }
    }

    /// A one-entry `pkg.jar` (`lib/a.js` = `b"patched\n"`) written into `dir`,
    /// plus the files map whose `afterHash` matches it — the in-sync baseline
    /// each `zip_matches_after_hashes` case perturbs.
    fn in_sync_jar_fixture(
        dir: &Path,
    ) -> (std::path::PathBuf, HashMap<String, PatchFileInfo>, Vec<u8>) {
        let zip_bytes =
            write_zip_entries(&[("lib/a.js".to_string(), b"patched\n".to_vec(), 0o644)])
                .expect("fixture zip");
        let jar = dir.join("pkg.jar");
        std::fs::write(&jar, &zip_bytes).unwrap();
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        (jar, files, zip_bytes)
    }

    /// Control for the negative cases below: an archive whose every patched
    /// entry hashes to its `afterHash` reads as in-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_accepts_in_sync_archive() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, _) = in_sync_jar_fixture(dir.path());
        assert!(
            zip_matches_after_hashes(&jar, &files).await,
            "an archive matching every afterHash must read as in-sync"
        );
    }

    /// Bytes that aren't a zip archive at all (a truncated or clobbered
    /// `.jar` / `.nupkg`) must read as out-of-sync, not error or panic.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_non_zip_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, _) = in_sync_jar_fixture(dir.path());
        std::fs::write(&jar, b"not a zip archive").unwrap();
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "non-zip bytes must read as out-of-sync"
        );
    }

    /// SECURITY: a manifest key that escapes the package dir must read as
    /// out-of-sync BEFORE any lookup — even when the archive itself carries
    /// a literal `../evil.js` entry whose content hashes to the afterHash
    /// (so without the guard the probe would say in-sync).
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_escaping_manifest_key() {
        let dir = tempfile::tempdir().unwrap();
        let zip_bytes =
            write_zip_entries(&[("../evil.js".to_string(), b"patched\n".to_vec(), 0o644)])
                .expect("fixture zip");
        let jar = dir.path().join("pkg.jar");
        std::fs::write(&jar, &zip_bytes).unwrap();
        let files = HashMap::from([(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a manifest key escaping the package dir must read as out-of-sync"
        );
    }

    /// A patched file the archive no longer contains must read as
    /// out-of-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, _, _) = in_sync_jar_fixture(dir.path());
        let files = HashMap::from([(
            "lib/missing.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "an entry absent from the archive must read as out-of-sync"
        );
    }

    /// A corrupted entry payload (deflate/CRC read error behind an intact
    /// central directory, so `by_name` still succeeds) must read as
    /// out-of-sync instead of erroring.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_corrupt_entry_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, mut zip_bytes) = in_sync_jar_fixture(dir.path());
        // The byte just before the central-directory signature is the last
        // byte of the (sole) entry's deflate payload — ZipWriter over a
        // Cursor seeks back to patch the local header, so there is no data
        // descriptor in between. Flipping it corrupts the stream/CRC while
        // the central directory stays intact.
        let cd_offset = zip_bytes
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("central directory signature");
        zip_bytes[cd_offset - 1] ^= 0xff;
        std::fs::write(&jar, &zip_bytes).unwrap();
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a corrupt entry payload must read as out-of-sync"
        );
    }

    /// An entry whose content no longer hashes to its `afterHash` must read
    /// as out-of-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_after_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, _, _) = in_sync_jar_fixture(dir.path());
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: "0".repeat(64),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a content-hash mismatch must read as out-of-sync"
        );
    }

    /// Control for the escape test below: a copy whose every patched file
    /// hashes to its `afterHash` reads as in-sync.
    #[tokio::test]
    async fn copy_matches_after_hashes_accepts_in_sync_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy");
        std::fs::create_dir_all(copy.join("lib")).unwrap();
        std::fs::write(copy.join("lib/a.js"), b"patched\n").unwrap();
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            copy_matches_after_hashes(&copy, &files).await,
            "a copy matching every afterHash must read as in-sync"
        );
    }

    /// SECURITY: a manifest key that escapes the copy dir must read as
    /// out-of-sync BEFORE any hashing — even when a real file at the escaped
    /// location hashes to the afterHash (so without the guard the probe
    /// would resolve outside the copy dir and say in-sync).
    #[tokio::test]
    async fn copy_matches_after_hashes_refuses_escaping_key() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy");
        std::fs::create_dir_all(copy.join("lib")).unwrap();
        std::fs::write(copy.join("lib/a.js"), b"patched\n").unwrap();
        // A real, afterHash-matching file OUTSIDE the copy dir at the exact
        // spot `copy.join("../evil.js")` would resolve to.
        std::fs::write(dir.path().join("evil.js"), b"patched\n").unwrap();
        let files = HashMap::from([(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !copy_matches_after_hashes(&copy, &files).await,
            "a manifest key escaping the copy dir must read as out-of-sync"
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted at the committed archive path (`.jar` / `.nupkg`) must
    /// read as out-of-sync instead of wedging the maven/nuget in-sync probes
    /// — and with them every apply — forever in an `open(2)` that waits for
    /// a writer that never comes. Same `open_regular_file` guard class as
    /// the Cargo.lock / lock-splice twins.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_archive_fails_fast_in_zip_matches_after_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("pkg.jar");
        mkfifo(&jar);
        let files: HashMap<String, PatchFileInfo> = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: "after".to_string(),
            },
        )]);

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(in_sync) =
            tokio::time::timeout(deadline, zip_matches_after_hashes(&jar, &files)).await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&jar);
            panic!("zip_matches_after_hashes must fail fast on a FIFO archive");
        };
        assert!(!in_sync, "a FIFO archive must read as out-of-sync");
    }

    /// A FIFO planted as the lock file must fail the revert fast and loudly
    /// instead of wedging `remove` / rollback forever in an `open(2)` that
    /// waits for a writer that never comes.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_in_revert_lock_fragment_splice() {
        let dir = tempfile::tempdir().unwrap();
        mkfifo(&dir.path().join("poetry.lock"));

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        // Same timeout-then-release shape as the archive test above.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(outcome) = tokio::time::timeout(
            deadline,
            revert_lock_fragment_splice(
                &entry,
                dir.path(),
                false,
                "poetry.lock",
                "poetry_lock_package",
                "poetry",
            ),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .open(dir.path().join("poetry.lock"));
            panic!("revert_lock_fragment_splice must fail fast on a FIFO lock");
        };
        assert!(!outcome.success, "a FIFO lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot read poetry.lock")),
            "{:?}",
            outcome.error
        );
    }

    /// LIVENESS CONTRACT (vendor/mod.rs): a fragment whose lock already
    /// carries the recorded pre-vendor original — a relock regenerated the
    /// unit, or an earlier partial revert restored it — is CONVERGED, not
    /// drifted: re-classifying it would make the pypi drift-keep gate
    /// retain the artifact dir and ledger entry forever, with remediation
    /// advice that can never be satisfied.
    #[tokio::test]
    async fn revert_lock_fragment_splice_converged_fragment_is_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nOLD-FRAGMENT\nomega\n")
            .await
            .unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];
        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(&lock).unwrap().ino()
        };

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "converged fragments must not read as drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nOLD-FRAGMENT\nomega\n",
            "nothing to restore"
        );
        // A converged revert must not churn the file either: the atomic
        // writer would swap in a fresh inode (new mtime, spurious "modified"
        // in editors and watchers) for byte-identical content.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                std::fs::metadata(&lock).unwrap().ino(),
                inode_before,
                "a converged revert never rewrites the lock"
            );
        }
    }

    /// The lock file is user-owned: reverting the splice must not reset its
    /// permission bits (the `package_json/update.rs` mode-reset bug, same
    /// class — see `atomic_write_bytes_preserving_mode`).
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_fragment_splice_preserves_lock_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nNEW-FRAGMENT\nomega\n")
            .await
            .unwrap();
        let mut perms = std::fs::metadata(&lock).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&lock, perms).unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nOLD-FRAGMENT\nomega\n",
            "fragment restored"
        );
        let mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "revert must preserve the lock file's permission bits"
        );
    }

    /// A lock file that opens as a regular file but isn't valid UTF-8 (a
    /// stray Latin-1 byte in a poetry.lock/pdm.lock) must fail the revert
    /// loudly with `cannot read <lock>` — and leave the bytes on disk
    /// untouched — rather than proceed on garbled text.
    #[tokio::test]
    async fn revert_lock_fragment_splice_fails_on_non_utf8_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        let lock_bytes: &[u8] = b"alpha\nNEW-FRAGMENT\n\xff\xfe\n";
        std::fs::write(&lock, lock_bytes).unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(!outcome.success, "a non-UTF-8 lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot read poetry.lock")),
            "{:?}",
            outcome.error
        );
        assert!(
            !outcome.kept_artifact,
            "kept_artifact is never set on failure"
        );
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            lock_bytes,
            "a failed revert must leave the lock bytes untouched"
        );
    }

    /// When the final atomic write fails (read-only parent dir — the
    /// documented 'atomic write needs writable parent' class), the revert
    /// must fail with `cannot write <lock>`, keep `kept_artifact == false`
    /// (the mod.rs contract), and — the reason lines 462-467 hand-build the
    /// outcome instead of calling `RevertOutcome::failed` — carry the drift
    /// warnings accumulated before the write into the failed outcome.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_fragment_splice_write_failure_keeps_warnings() {
        use std::os::unix::fs::PermissionsExt;
        // root ignores permission bits, so the read-only dir wouldn't fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nNEW-FRAGMENT\nomega\n")
            .await
            .unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![
            // Allowlist-skipped record: seeds a vendor_lock_entry_drifted
            // warning that must survive the failed write below.
            record(
                "other.lock",
                "poetry_lock_package",
                WiringAction::Rewritten,
                "six",
                Some("OLD".into()),
                "NEW".into(),
            ),
            record(
                "poetry.lock",
                "poetry_lock_package",
                WiringAction::Rewritten,
                "six",
                Some("OLD-FRAGMENT".into()),
                "NEW-FRAGMENT".into(),
            ),
        ];

        // Read-only parent: the atomic write stages its temp file in the
        // parent dir, so the write fails EACCES while the lock itself stays
        // readable.
        let mut dir_perms = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_perms.set_mode(0o555);
        std::fs::set_permissions(dir.path(), dir_perms).unwrap();

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;

        // Restore before asserting so tempdir cleanup succeeds even on a
        // failed assertion.
        let mut dir_perms = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_perms.set_mode(0o755);
        std::fs::set_permissions(dir.path(), dir_perms).unwrap();

        assert!(!outcome.success, "a failed write must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot write poetry.lock")),
            "{:?}",
            outcome.error
        );
        assert!(
            !outcome.kept_artifact,
            "kept_artifact is never set on failure"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("other.lock")),
            "warnings accumulated before the failed write must survive it: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nNEW-FRAGMENT\nomega\n",
            "a failed revert must leave the lock content untouched"
        );
    }

    // ── in-memory repack equivalence (X10) ──────────────────────────────────

    /// A zip built entry by entry, so the oracle fixtures can carry the
    /// spellings `write_zip_entries` never emits: repeated names, STORED
    /// members, zero-length members, an exec bit, a directory entry and a
    /// traversal-escaping name.
    fn build_zip(entries: &[(&str, &[u8], zip::CompressionMethod, u32)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes, method, mode) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(*method)
                .unix_permissions(*mode);
            if name.ends_with('/') {
                writer.add_directory(*name, options).unwrap();
                continue;
            }
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// The default zip fixture entry: deflated, 0o644.
    fn entry<'a>(
        name: &'a str,
        bytes: &'a [u8],
    ) -> (&'a str, &'a [u8], zip::CompressionMethod, u32) {
        (name, bytes, zip::CompressionMethod::Deflated, 0o644)
    }

    /// A patch-files map naming `keys` (content irrelevant: these tests drive
    /// the staging and the rebuild, not the apply).
    fn target_files(keys: &[&str]) -> HashMap<String, PatchFileInfo> {
        keys.iter()
            .map(|k| {
                (
                    (*k).to_string(),
                    PatchFileInfo {
                        before_hash: compute_git_sha256_from_bytes(b"before"),
                        after_hash: compute_git_sha256_from_bytes(b"after"),
                    },
                )
            })
            .collect()
    }

    /// The pre-X10 repack, kept verbatim as the oracle: extract every member
    /// to a stage, let the caller stand in for the apply pipeline, then walk
    /// the stage back into a deterministic zip.
    async fn on_disk_repack(
        archive: &[u8],
        skip_entry: Option<&str>,
        apply: impl AsyncFn(&Path),
    ) -> Result<Vec<u8>, String> {
        let stage = tempfile::tempdir().map_err(|e| format!("stage: {e}"))?;
        super::super::registry_fetch::extract_zip(archive, stage.path(), false)?;
        apply(stage.path()).await;
        rebuild_zip(stage.path(), skip_entry)
    }

    /// The X10 repack: members stay in memory, only the patch targets (plus
    /// `extra`) are materialised, and the same stand-in apply runs over them.
    /// `None` means the name gate sent the rebuild back to the on-disk path.
    async fn in_memory_repack(
        archive: &[u8],
        files: &HashMap<String, PatchFileInfo>,
        extra: &[&str],
        skip_entry: Option<&str>,
        apply: impl AsyncFn(&Path),
    ) -> Result<Option<Vec<u8>>, String> {
        let Some(mut repack) = prepare_memory_repack(archive, files, extra)? else {
            return Ok(None);
        };
        for name in extra {
            repack.also_stage(name);
        }
        let stage = tempfile::tempdir().map_err(|e| format!("stage: {e}"))?;
        repack.stage_into(stage.path()).await?;
        apply(stage.path()).await;
        let entries = repack.into_entries(stage.path(), skip_entry).await?;
        write_zip_entries(&entries).map(Some)
    }

    /// Both repacks over one fixture must agree byte for byte; returns the
    /// shared bytes so a caller can assert on the archive itself.
    async fn assert_repacks_agree(
        archive: &[u8],
        keys: &[&str],
        extra: &[&str],
        skip_entry: Option<&str>,
        apply: impl AsyncFn(&Path) + Copy,
    ) -> Vec<u8> {
        let files = target_files(keys);
        let oracle = on_disk_repack(archive, skip_entry, apply).await.unwrap();
        let fast = in_memory_repack(archive, &files, extra, skip_entry, apply)
            .await
            .unwrap()
            .expect("this fixture's names must take the in-memory path");
        assert_eq!(
            fast, oracle,
            "the in-memory repack must reproduce the extract-and-rezip bytes"
        );
        fast
    }

    /// An untouched archive: nested dirs, an explicit directory entry, a
    /// zero-length member, a STORED member, an exec-bit member and a member
    /// large enough to span several read buffers must all repack to the same
    /// bytes as a full extraction would.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn in_memory_repack_matches_the_extract_and_rezip_oracle() {
        let big = vec![b'z'; 3 * 1024 * 1024];
        let archive = build_zip(&[
            ("META-INF/", b"", zip::CompressionMethod::Stored, 0o755),
            entry("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            entry("lib/empty.txt", b""),
            (
                "lib/stored.bin",
                b"stored bytes",
                zip::CompressionMethod::Stored,
                0o644,
            ),
            (
                "bin/run.sh",
                b"#!/bin/sh\nexit 0\n",
                zip::CompressionMethod::Deflated,
                0o755,
            ),
            entry("lib/big.bin", &big),
            entry("LICENSE", b"license\n"),
        ]);
        let bytes = assert_repacks_agree(&archive, &["LICENSE"], &[], None, async |_| {}).await;
        let names = zip_entry_names(&bytes);
        assert_eq!(
            names,
            [
                "LICENSE",
                "META-INF/MANIFEST.MF",
                "bin/run.sh",
                "lib/big.bin",
                "lib/empty.txt",
                "lib/stored.bin",
            ],
            "directory entries drop out; files sort lexicographically"
        );
    }

    /// The three ways an apply can change the stage — rewriting a patch
    /// target, creating one that was not in the archive, and deleting a
    /// staged path (NuGet's `.nupkg.metadata` fixup) — must land in the
    /// rebuilt archive exactly as they do over a full extraction.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn in_memory_repack_tracks_rewrites_creations_and_deletions() {
        let archive = build_zip(&[
            entry("LICENSE", b"pristine\n"),
            entry(".nupkg.metadata", b"{\"contentHash\":\"x\"}"),
            entry("lib/keep.txt", b"keep\n"),
        ]);
        let bytes = assert_repacks_agree(
            &archive,
            &["LICENSE", "lib/new.txt"],
            &[".nupkg.metadata"],
            None,
            async |stage: &Path| {
                tokio::fs::write(stage.join("LICENSE"), b"patched\n")
                    .await
                    .unwrap();
                // `apply_file_patch_at` materialises a created file's parent
                // itself, so the stand-in does too.
                tokio::fs::create_dir_all(stage.join("lib")).await.unwrap();
                tokio::fs::write(stage.join("lib/new.txt"), b"created\n")
                    .await
                    .unwrap();
                tokio::fs::remove_file(stage.join(".nupkg.metadata"))
                    .await
                    .unwrap();
            },
        )
        .await;
        assert_eq!(
            zip_entry_names(&bytes),
            ["LICENSE", "lib/keep.txt", "lib/new.txt"],
            "the deleted part is gone and the created one joined"
        );
        assert_eq!(zip_member(&bytes, "LICENSE"), b"patched\n");
    }

    /// The `skip_entry` drop (NuGet's `.signature.p7s`) is applied by both
    /// repacks at the same point.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn in_memory_repack_drops_the_skipped_entry() {
        let archive = build_zip(&[
            entry(".signature.p7s", b"FAKE-SIGNATURE"),
            entry("LICENSE", b"pristine\n"),
        ]);
        let bytes = assert_repacks_agree(
            &archive,
            &["LICENSE"],
            &[],
            Some(".signature.p7s"),
            async |_| {},
        )
        .await;
        assert_eq!(zip_entry_names(&bytes), ["LICENSE"]);
    }

    /// A patch key that names a DIRECTORY of the archive must find one in the
    /// stage, exactly as a full extraction leaves one there — otherwise the
    /// verify reports "File not found" where it used to report a hash
    /// failure, and `--force` would silently skip the key.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn in_memory_repack_materialises_a_directory_a_patch_key_names() {
        let archive = build_zip(&[entry("lib/net6.0/x.dll", b"MZ")]);
        let files = target_files(&["lib/net6.0"]);
        let repack = prepare_memory_repack(&archive, &files, &[])
            .unwrap()
            .unwrap();
        let stage = tempfile::tempdir().unwrap();
        repack.stage_into(stage.path()).await.unwrap();
        assert!(
            stage.path().join("lib/net6.0").is_dir(),
            "a patch key naming a directory must be staged as one"
        );
        assert!(
            !stage.path().join("lib/net6.0/x.dll").exists(),
            "its members stay in memory"
        );
    }

    /// Only the patch targets and the explicitly requested extras are written
    /// out — the point of the whole change.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn in_memory_repack_stages_only_what_the_apply_resolves() {
        let archive = build_zip(&[
            entry("LICENSE", b"pristine\n"),
            entry("lib/a.dll", b"MZ-a"),
            entry("lib/b.dll", b"MZ-b"),
            entry(".nupkg.metadata", b"{}"),
        ]);
        let files = target_files(&["LICENSE"]);
        let mut repack = prepare_memory_repack(&archive, &files, &[])
            .unwrap()
            .unwrap();
        repack.also_stage(".nupkg.metadata");
        let stage = tempfile::tempdir().unwrap();
        repack.stage_into(stage.path()).await.unwrap();
        assert!(stage.path().join("LICENSE").is_file());
        assert!(stage.path().join(".nupkg.metadata").is_file());
        assert!(!stage.path().join("lib/a.dll").exists());
        assert!(!stage.path().join("lib/b.dll").exists());
        assert!(!stage.path().join("lib").exists(), "no directory pass");
    }

    /// Archives whose names a filesystem can fold together, re-spell or
    /// refuse must go back to the extract-to-disk path rather than be guessed
    /// at in memory. Repeated names are the load-bearing case: on disk the
    /// last one wins, in memory a naive map would keep both.
    #[tokio::test]
    async fn ambiguous_names_fall_back_to_the_on_disk_repack() {
        let over_name_max = format!("lib/{}.class", "A".repeat(MAX_COMPONENT_BYTES));
        let cases: Vec<(&str, Vec<u8>, Vec<&str>)> = vec![
            (
                "case-colliding names",
                build_zip(&[
                    entry("META-INF/NOTICE", b"a"),
                    entry("META-INF/notice", b"b"),
                ]),
                vec![],
            ),
            (
                "a name that is also a directory",
                build_zip(&[entry("lib", b"a"), entry("lib/x.dll", b"b")]),
                vec![],
            ),
            (
                "a backslash in a name",
                build_zip(&[entry("lib\\x.dll", b"a")]),
                vec![],
            ),
            (
                "a non-ASCII name",
                build_zip(&[entry("lib/caf\u{e9}.txt", b"a")]),
                vec![],
            ),
            (
                "a DOS device name",
                build_zip(&[entry("lib/NUL.txt", b"a")]),
                vec![],
            ),
            (
                "a trailing dot",
                build_zip(&[entry("lib/x.", b"a")]),
                vec![],
            ),
            (
                "a patch key colliding with a member",
                build_zip(&[entry("LICENSE", b"a")]),
                vec!["license"],
            ),
            (
                "two spellings of one directory",
                build_zip(&[entry("Lib/a.class", b"a"), entry("lib/b.class", b"b")]),
                vec![],
            ),
            (
                "a patch key naming a member's directory under another spelling",
                build_zip(&[entry("Lib/x.dll", b"a")]),
                vec!["lib"],
            ),
            (
                "a component past NAME_MAX",
                build_zip(&[entry(&over_name_max, b"a")]),
                vec![],
            ),
        ];
        for (label, archive, keys) in cases {
            let files = target_files(&keys);
            assert!(
                prepare_memory_repack(&archive, &files, &[])
                    .unwrap()
                    .is_none(),
                "{label} must fall back to the on-disk repack"
            );
        }
    }

    /// `record.files` is a `HashMap` with a per-process random hasher, and
    /// every walk over the staged paths returns on the FIRST I/O error — so
    /// without a sort, two runs over one package under ENOSPC or EACCES name a
    /// different file in the failure that reaches stdout.
    #[test]
    fn staged_paths_are_walked_in_a_deterministic_order() {
        let files = target_files(&[
            "z.txt",
            "a/b.txt",
            "m.txt",
            "package/m.txt",
            "d.txt",
            "q/r.txt",
            "../escapes.txt",
        ]);
        assert_eq!(
            patch_target_paths(&files),
            ["a/b.txt", "d.txt", "m.txt", "q/r.txt", "z.txt"],
            "sorted, deduplicated past `package/`, and without the keys the \
             apply pipeline refuses to join"
        );
    }

    /// And the order survives into the stage, ahead of the extras the caller
    /// adds for its sidecar fixup.
    #[tokio::test]
    async fn the_repack_stages_the_sorted_targets_then_the_extras() {
        let archive = build_zip(&[
            entry("z.txt", b"z"),
            entry("m.txt", b"m"),
            entry("d.txt", b"d"),
            entry("a/b.txt", b"b"),
            entry("q/r.txt", b"r"),
            entry(".nupkg.metadata", b"{}"),
        ]);
        let files = target_files(&["z.txt", "m.txt", "d.txt", "a/b.txt", "q/r.txt"]);
        let repack = prepare_memory_repack(&archive, &files, &[".nupkg.metadata"])
            .unwrap()
            .unwrap();
        assert_eq!(
            repack.wanted,
            [
                "a/b.txt",
                "d.txt",
                "m.txt",
                "q/r.txt",
                "z.txt",
                ".nupkg.metadata"
            ]
        );
    }

    /// A member folding onto one of the sidecar fixup's fixed paths must fall
    /// back too: the fixup would delete that member on a case-insensitive
    /// volume and leave it in place on a case-sensitive one, so the rebuilt
    /// package is only reproducible through the on-disk path.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_member_folding_onto_a_sidecar_path_falls_back() {
        let archive = build_zip(&[entry(".NUPKG.METADATA", b"{}"), entry("LICENSE", b"x")]);
        let files = target_files(&["LICENSE"]);
        assert!(
            prepare_memory_repack(&archive, &files, &[".nupkg.metadata"])
                .unwrap()
                .is_none(),
            "a member folding onto `.nupkg.metadata` must take the on-disk path"
        );
        assert!(
            prepare_memory_repack(&archive, &files, &[])
                .unwrap()
                .is_some(),
            "and only because the fixup path was declared"
        );
    }

    /// A repeated entry name: the extraction overwrites in place, so the LAST
    /// spelling's bytes are what the rebuild carries. The in-memory reader
    /// collapses the pair the same way, and the two repacks must agree.
    #[tokio::test]
    // The fixture must take the in-memory path, and `FORCE_ON_DISK_REPACK` is
    // thread-local, so `#[serial]` is belt and braces here.
    #[serial_test::serial]
    async fn repeated_entry_names_repack_as_last_one_wins() {
        // `ZipWriter` refuses a repeated name, so build two same-length names
        // and rename the second in place (local header + central directory).
        let mut archive = build_zip(&[entry("dup.txt", b"first"), entry("dup2txt", b"second")]);
        rename_zip_entry(&mut archive, b"dup2txt", b"dup.txt");
        // WHERE the pair collapses is the zip crate's business: it keys the
        // central directory on the RAW name bytes in an `IndexMap`, so
        // `ZipArchive` hands out one entry, at the first one's index, before
        // `read_zip_members` sees it. Pinned here so a crate bump that stops
        // doing it is caught rather than silently changing what the rebuild
        // carries.
        assert_eq!(
            zip::ZipArchive::new(std::io::Cursor::new(archive.clone()))
                .unwrap()
                .len(),
            1,
            "the zip crate collapses identical raw names itself"
        );
        let members = read_zip_members(&archive).unwrap();
        assert_eq!(members.len(), 1, "the repeat collapses, as on disk");
        assert_eq!(members[0].bytes, b"second");
        let bytes = assert_repacks_agree(&archive, &["dup.txt"], &[], None, async |_| {}).await;
        assert_eq!(zip_entry_names(&bytes), ["dup.txt"]);
        assert_eq!(zip_member(&bytes, "dup.txt"), b"second");
    }

    /// The collapse `read_zip_members` does itself: two DIFFERENT raw names
    /// that decode to one (`from_utf8_lossy` folds distinct invalid bytes onto
    /// U+FFFD), which the zip crate keeps apart and `extract_zip` writes to a
    /// single path — last one wins, exactly as the reader's `at` map does.
    #[tokio::test]
    async fn raw_names_decoding_to_one_name_collapse_last_one_wins() {
        let mut archive = build_zip(&[entry("dupA.txt", b"first"), entry("dupB.txt", b"second")]);
        rename_zip_entry(&mut archive, b"dupA.txt", b"dup\xff.txt");
        rename_zip_entry(&mut archive, b"dupB.txt", b"dup\xfe.txt");
        // Without the language-encoding flag the names decode through CP437,
        // which is a bijection — the lossy fold needs the UTF-8 flag set.
        set_utf8_name_flag(&mut archive);
        let decoded = "dup\u{fffd}.txt";
        assert_eq!(
            zip::ZipArchive::new(std::io::Cursor::new(archive.clone()))
                .unwrap()
                .len(),
            2,
            "the raw names differ, so the zip crate keeps both entries"
        );
        let members = read_zip_members(&archive).unwrap();
        assert_eq!(members.len(), 1, "but they name one file");
        assert_eq!(members[0].name, decoded);
        assert_eq!(members[0].bytes, b"second");
        // And that is what an extraction leaves behind.
        let stage = tempfile::tempdir().unwrap();
        super::super::registry_fetch::extract_zip(&archive, stage.path(), false).unwrap();
        assert_eq!(
            tokio::fs::read(stage.path().join(decoded)).await.unwrap(),
            b"second"
        );
        // The name is not plain ASCII, so the rebuild itself takes the
        // extract-to-disk path — the reader still has to agree about it,
        // because it runs before the gate does.
        assert!(
            prepare_memory_repack(&archive, &target_files(&["dup.txt"]), &[])
                .unwrap()
                .is_none()
        );
    }

    /// Set the general-purpose "language encoding" bit (bit 11) on every local
    /// file header and central directory header, so the reader decodes entry
    /// names as UTF-8 instead of CP437.
    fn set_utf8_name_flag(archive: &mut [u8]) {
        for (signature, flags_at) in [(b"PK\x03\x04".as_slice(), 6), (b"PK\x01\x02".as_slice(), 8)]
        {
            let mut at = 0;
            let mut hits = 0;
            while at + flags_at + 2 <= archive.len() {
                if archive[at..].starts_with(signature) {
                    archive[at + flags_at + 1] |= 0b0000_1000;
                    hits += 1;
                    at += signature.len();
                } else {
                    at += 1;
                }
            }
            assert_eq!(hits, 2, "two entries, one header of each kind apiece");
        }
    }

    /// A member no filesystem can create: the extraction fails the whole
    /// rebuild with ENAMETOOLONG, so the gate has to keep such an archive on
    /// that path. In memory it would rebuild cleanly and turn a package the
    /// baseline refused into a vendored one.
    #[tokio::test]
    async fn a_member_past_name_max_still_fails_the_rebuild() {
        let long = format!("lib/{}.class", "A".repeat(MAX_COMPONENT_BYTES));
        let archive = build_zip(&[entry("LICENSE", b"a"), entry(&long, b"b")]);
        assert!(
            prepare_memory_repack(&archive, &target_files(&["LICENSE"]), &[])
                .unwrap()
                .is_none(),
            "an unwritable member name must take the on-disk repack"
        );
        let stage = tempfile::tempdir().unwrap();
        let error = super::super::registry_fetch::extract_zip(&archive, stage.path(), false)
            .expect_err("no filesystem creates a component past NAME_MAX");
        assert!(
            error.starts_with("cannot create ") && error.contains(&long["lib/".len()..]),
            "{error}"
        );
    }

    /// Two spellings of one directory: a case-insensitive stage collapses them,
    /// and the walk back out re-spells the second member under the first's
    /// casing — a different rebuilt artifact, and so a different `.sha1`
    /// sidecar and NuGet `contentHash`. The in-memory repack cannot reproduce
    /// that, so the gate must send the archive to disk.
    #[tokio::test]
    async fn case_variant_directory_spellings_take_the_on_disk_repack() {
        let archive = build_zip(&[
            entry("LICENSE", b"pristine\n"),
            entry("Lib/a.class", b"a"),
            entry("lib/b.class", b"b"),
        ]);
        assert!(
            prepare_memory_repack(&archive, &target_files(&["LICENSE"]), &[])
                .unwrap()
                .is_none(),
            "a folded directory spelling must take the on-disk repack"
        );
        // And on a volume that really does fold, pin what the extraction
        // leaves behind — so the gate stays necessary rather than cosmetic.
        let probe = tempfile::tempdir().unwrap();
        std::fs::create_dir(probe.path().join("Lib")).unwrap();
        if std::fs::create_dir(probe.path().join("lib")).is_err() {
            let oracle = on_disk_repack(&archive, None, async |_| {}).await.unwrap();
            assert_eq!(
                zip_entry_names(&oracle),
                ["LICENSE", "Lib/a.class", "Lib/b.class"],
                "the second member is republished under the first's casing"
            );
        }
    }

    /// Rewrite every occurrence of an entry name in a zip's bytes. `from` and
    /// `to` must be the same length so no offset in the archive moves.
    fn rename_zip_entry(archive: &mut [u8], from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len(), "renaming must not move offsets");
        let mut at = 0;
        let mut hits = 0;
        while at + from.len() <= archive.len() {
            if &archive[at..at + from.len()] == from {
                archive[at..at + from.len()].copy_from_slice(to);
                hits += 1;
                at += from.len();
            } else {
                at += 1;
            }
        }
        assert_eq!(hits, 2, "local header and central directory");
    }

    /// Every refusal the on-disk extractor raises must come out of the
    /// in-memory reader with the identical message, so a poisoned artifact
    /// fails the same way whichever path ran.
    #[tokio::test]
    async fn in_memory_reader_refuses_exactly_what_the_extractor_refuses() {
        let escaping = build_zip(&[entry("../evil.js", b"x")]);
        let truncated = {
            let mut bytes = build_zip(&[entry("a.txt", b"hello")]);
            bytes.truncate(bytes.len() / 2);
            bytes
        };
        for (label, archive) in [("escaping entry", escaping), ("truncated", truncated)] {
            let stage = tempfile::tempdir().unwrap();
            let oracle = super::super::registry_fetch::extract_zip(&archive, stage.path(), false)
                .unwrap_err();
            let fast = match read_zip_members(&archive) {
                Err(e) => e,
                Ok(_) => panic!("{label}: the in-memory reader must refuse this archive"),
            };
            assert_eq!(fast, oracle, "{label}: the two readers must agree");
        }
    }

    /// The entry names of a zip, in central-directory order.
    fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect()
    }

    /// One member's bytes.
    fn zip_member(bytes: &[u8], name: &str) -> Vec<u8> {
        use std::io::Read as _;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut out = Vec::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// The name gate's rules, one by one.
    #[test]
    fn names_are_unambiguous_rejects_what_a_filesystem_can_fold_or_respell() {
        let plain = |names: [&str; 1]| names_are_unambiguous(names, []);
        assert!(names_are_unambiguous(["a/b.txt", "a/c.txt", "d.txt"], []));
        assert!(
            names_are_unambiguous(["a/b.txt"], ["a/b.txt"]),
            "a patch target IS usually a member"
        );
        assert!(
            !names_are_unambiguous(["A.txt"], ["a.txt"]),
            "a target folding onto a member"
        );
        assert!(!names_are_unambiguous(["A.txt", "a.txt"], []), "case fold");
        assert!(
            !names_are_unambiguous(["Lib/a.class", "lib/b.class"], []),
            "two spellings of one DIRECTORY fold into one entry too — the walk \
             back out would re-spell the second member under the first's casing"
        );
        assert!(
            !names_are_unambiguous(["META-INF/services/a", "meta-inf/services/b"], []),
            "a folded directory anywhere along the path"
        );
        assert!(
            !names_are_unambiguous(["Lib/x.dll"], ["lib"]),
            "a target naming a member's directory under a different spelling"
        );
        assert!(
            names_are_unambiguous(["lib/a.dll", "lib/b.dll", "lib/net6.0/c.dll"], []),
            "siblings sharing a directory spelling stay on the fast path"
        );
        assert!(
            !names_are_unambiguous(["a", "a/b"], []),
            "file vs directory"
        );
        assert!(!names_are_unambiguous(["a/b", "A"], []), "folded ancestor");
        assert!(
            !names_are_unambiguous(["lib"], ["lib/x"]),
            "a target living under a member FILE"
        );
        assert!(
            names_are_unambiguous(["lib/net6.0/x.dll"], ["lib/net6.0"]),
            "a target naming a member's DIRECTORY is ordinary"
        );
        assert!(!plain(["a\\b"]), "backslash");
        assert!(!plain(["caf\u{e9}"]), "non-ASCII");
        assert!(!plain(["a:b"]), "alternate data stream");
        assert!(!plain(["a*"]), "Windows wildcard");
        assert!(!plain(["a."]), "trailing dot");
        assert!(!plain(["a "]), "trailing space");
        assert!(!plain(["nul"]), "DOS device");
        assert!(!plain(["dir/COM1.txt"]), "DOS device stem");
        assert!(!plain(["a/./b"]), "re-spelled component");
        assert!(!plain(["a//b"]), "empty component");
        assert!(!plain([""]), "empty name");
        let long_part = "A".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(
            !plain([format!("org/apache/{long_part}.class").as_str()]),
            "a component past NAME_MAX — the extraction would have failed with \
             ENAMETOOLONG, so the rebuild has to keep failing"
        );
        assert!(
            plain([format!("org/apache/{}.class", "A".repeat(MAX_COMPONENT_BYTES - 6)).as_str()]),
            "a component exactly at NAME_MAX still extracts"
        );
        let deep = vec!["dir"; MAX_NAME_BYTES / 4 + 1].join("/");
        assert!(
            !plain([deep.as_str()]),
            "a whole name long enough to push `<stage>/<name>` past PATH_MAX"
        );
        assert!(
            names_are_unambiguous(["my lib/x.dll", "a-b_c+d$e.txt", "[Content_Types].xml"], []),
            "ordinary jar/nupkg spellings stay on the fast path"
        );
    }
}
