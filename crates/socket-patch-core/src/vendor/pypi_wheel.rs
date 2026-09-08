//! Rebuild an installable wheel from the patched installed distribution.
//!
//! pypi vendoring cannot reuse a registry artifact: the patch applies to the
//! *installed* site-packages tree, so the committable `.socket/vendor/pypi/`
//! artifact must be reconstructed from that tree. The installed
//! `*.dist-info/RECORD` is the authoritative member list (spike-verified: pip
//! 26 / uv 0.11 only require RECORD to exist and parse at install time — per
//! file hashes are unchecked — but we regenerate it correctly anyway, because
//! the RECORD drives uninstall bookkeeping and post-hoc audits). The rebuild
//! is byte-for-byte deterministic so the emitted `--hash` / uv lock hash pin
//! is stable across re-runs and never churns committed files.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::Digest as _;

use crate::crawlers::python_crawler::{canonicalize_pypi_name, read_python_metadata};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{
    is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
};
use crate::utils::fs::{atomic_write_bytes, list_dir_entries};

use super::common::{failed_result, is_executable, write_zip_entries};

/// The located installed distribution for one `name@version`.
#[derive(Debug, Clone)]
pub struct InstalledDist {
    /// Absolute path of the `<dist>-<version>.dist-info` directory.
    pub dist_info_dir: PathBuf,
    /// Raw distribution-name part of the dist-info directory stem (casing
    /// and separators as installed, e.g. `Flask-SQLAlchemy`) — the input to
    /// the wheel-filename escaping, NOT a canonical PEP 503 name.
    pub dist_name: String,
    pub version: String,
    /// Member paths parsed from `RECORD` (the path field of each row).
    pub record: Vec<String>,
    /// Raw `Tag:` header values from the `WHEEL` file, in file order.
    pub wheel_tags: Vec<String>,
}

/// The rebuilt artifact: leaf filename + content identity for the lock pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelArtifact {
    pub file_name: String,
    /// Plain sha256 hex of the wheel bytes (what pip `--hash=` and uv lock
    /// `hash = "sha256:..."` verify).
    pub sha256_hex: String,
    pub size: u64,
}

/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular
/// files, so a FIFO planted in the dist-info (or squatting a RECORD member)
/// fails fast — surfacing as the same unreadable-file refusal/failure as a
/// missing file — instead of wedging the vendor run forever in an `open(2)`
/// that waits for a writer.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// Byte-reading twin of [`read_regular_to_string`], also handing back the
/// metadata from the already-open handle (the member staging loop needs the
/// exec bit without a second stat).
async fn read_regular(path: &Path) -> std::io::Result<(Vec<u8>, std::fs::Metadata)> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut content).await?;
    Ok((content, metadata))
}

/// Find the installed dist for `purl_name@version` by scanning the
/// `*.dist-info` directories under the site-packages root (the crawler's
/// `pkg_path` for pypi). Name matching is PEP 503-canonical on BOTH sides so
/// `Flask_SQLAlchemy` / `flask-sqlalchemy` spellings collapse, mirroring
/// [`crate::crawlers::python_crawler`].
pub async fn locate_installed_dist(
    site_packages: &Path,
    purl_name: &str,
    version: &str,
) -> Result<InstalledDist, (&'static str, String)> {
    let want = canonicalize_pypi_name(purl_name);
    for entry in list_dir_entries(site_packages).await {
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = dir_name.strip_suffix(".dist-info") else {
            continue;
        };
        let dist_info = entry.path();
        let Some((raw_name, found_version)) = read_python_metadata(&dist_info).await else {
            continue;
        };
        if canonicalize_pypi_name(&raw_name) != want || found_version != version {
            continue;
        }

        // Wheel filenames re-escape from the RAW installed name; the
        // dist-info stem keeps it (`Flask-SQLAlchemy-2.5.1.dist-info`), with
        // the METADATA Name as fallback for stems that carry no version part.
        let dist_name = match stem.rfind('-') {
            Some(i) if i > 0 => stem[..i].to_string(),
            _ => raw_name.clone(),
        };

        let record_text = read_regular_to_string(&dist_info.join("RECORD"))
            .await
            .map_err(|e| {
                (
                    "pypi_missing_record",
                    format!(
                        "cannot rebuild a wheel for {purl_name}@{version}: {}/RECORD is unreadable ({e})",
                        dist_info.display()
                    ),
                )
            })?;
        let record = parse_record_paths(&record_text);
        if record.is_empty() {
            return Err((
                "pypi_missing_record",
                format!(
                    "cannot rebuild a wheel for {purl_name}@{version}: {}/RECORD lists no files",
                    dist_info.display()
                ),
            ));
        }

        let wheel_text = read_regular_to_string(&dist_info.join("WHEEL"))
            .await
            .map_err(|e| {
                (
                    "pypi_missing_wheel_metadata",
                    format!(
                        "cannot rebuild a wheel for {purl_name}@{version}: {}/WHEEL is unreadable ({e})",
                        dist_info.display()
                    ),
                )
            })?;
        let wheel_tags: Vec<String> = wheel_text
            .lines()
            .filter_map(|l| l.strip_prefix("Tag:"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if wheel_tags.is_empty() {
            return Err((
                "pypi_missing_wheel_metadata",
                format!(
                    "cannot rebuild a wheel for {purl_name}@{version}: {}/WHEEL carries no Tag: headers",
                    dist_info.display()
                ),
            ));
        }

        return Ok(InstalledDist {
            dist_info_dir: dist_info,
            dist_name,
            version: found_version,
            record,
            wheel_tags,
        });
    }
    Err((
        "pypi_dist_not_found",
        format!(
            "{purl_name}@{version} is not installed under {}",
            site_packages.display()
        ),
    ))
}

/// The PEP 427 filename for the rebuilt wheel:
/// `<escaped dist>-<escaped version>-<compressed tags>.whl`.
pub fn wheel_file_name(dist: &InstalledDist) -> Result<String, (&'static str, String)> {
    let name = escape_wheel_component(&dist.dist_name);
    let version = escape_wheel_version(&dist.version);
    let (py, abi, plat) = compress_wheel_tags(&dist.wheel_tags)?;
    Ok(format!("{name}-{version}-{py}-{abi}-{plat}.whl"))
}

/// Wheel-spec component escaping: runs of `[^A-Za-z0-9.]` collapse to a
/// single `_` so the filename stays unambiguous at the `-` separators.
fn escape_wheel_component(s: &str) -> String {
    escape_wheel_chars(s, false)
}

/// Version-component escaping: PEP 440 normalized versions legitimately
/// carry `!` (epoch) and `+` (local separator), and real tools keep them
/// literally in the filename (bdist_wheel's `safer_version` only maps `-`
/// runs to `_`). pip/uv REJECT the `_`-escaped spelling as an invalid wheel
/// version (`packaging.utils.parse_wheel_filename` raises on
/// `torch-2.0.0_cu118-…` but parses `torch-2.0.0+cu118-…`), so escaping
/// those two would make the rebuilt wheel uninstallable.
fn escape_wheel_version(s: &str) -> String {
    escape_wheel_chars(s, true)
}

fn escape_wheel_chars(s: &str, keep_version_separators: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_run = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric()
            || ch == '.'
            || (keep_version_separators && (ch == '+' || ch == '!'))
        {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// Compress the WHEEL `Tag:` set back into the filename's dotted triple
/// (`py2.py3-none-any`). The dotted form expands to the CROSS PRODUCT of the
/// three component sets, so the compression is only faithful when the
/// observed tag set IS a full cross product — anything else would synthesize
/// a filename claiming compatibility the installed dist never declared, so
/// it is refused instead.
fn compress_wheel_tags(
    tags: &[String],
) -> Result<(String, String, String), (&'static str, String)> {
    let mut pys: Vec<&str> = Vec::new();
    let mut abis: Vec<&str> = Vec::new();
    let mut plats: Vec<&str> = Vec::new();
    let mut seen: HashSet<(&str, &str, &str)> = HashSet::new();
    for tag in tags {
        let parts: Vec<&str> = tag.split('-').collect();
        let [py, abi, plat] = parts.as_slice() else {
            return Err((
                "pypi_wheel_tags_unrecoverable",
                format!("WHEEL tag {tag:?} is not a py-abi-platform triple"),
            ));
        };
        if !pys.contains(py) {
            pys.push(py);
        }
        if !abis.contains(abi) {
            abis.push(abi);
        }
        if !plats.contains(plat) {
            plats.push(plat);
        }
        seen.insert((py, abi, plat));
    }
    let product = pys.len() * abis.len() * plats.len();
    let all_present = pys.iter().all(|p| {
        abis.iter()
            .all(|a| plats.iter().all(|pl| seen.contains(&(p, a, pl))))
    });
    if product != seen.len() || !all_present {
        return Err((
            "pypi_wheel_tags_unrecoverable",
            format!(
                "WHEEL tag set {tags:?} is not a cross product of its components and cannot be \
                 expressed as a single wheel filename"
            ),
        ));
    }
    Ok((pys.join("."), abis.join("."), plats.join(".")))
}

/// Build the patched wheel at `dest` from the installed dist:
/// stage the RECORD members → apply the patch in the stage → regenerate
/// RECORD → deterministic zip → atomic write.
///
/// Errors (`Err((code, detail))`) are refusal-shaped — nothing was written
/// and the orchestrator maps them to [`VendorOutcome::Refused`]. Runtime
/// failures after staging surface as a failed [`ApplyResult`] instead, in the
/// same shape `apply` reports them.
///
/// `dry_run` stops after the in-stage verification (no zip, no `dest` write).
///
/// [`VendorOutcome::Refused`]: super::VendorOutcome::Refused
#[allow(clippy::too_many_arguments)]
pub async fn build_patched_wheel(
    purl: &str,
    site_packages: &Path,
    dist: &InstalledDist,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dest: &Path,
    dry_run: bool,
    force: bool,
    warnings: &mut Vec<super::VendorWarning>,
) -> Result<(ApplyResult, Option<WheelArtifact>), (&'static str, String)> {
    // Editable installs (`pip install -e` / uv tool dev mode) point
    // site-packages at the user's own working tree: the RECORD describes a
    // `.pth`/finder shim, not the package contents, so a rebuilt wheel would
    // vendor the shim instead of the code. Checked BEFORE staging.
    if is_editable_install(&dist.dist_info_dir).await {
        return Err((
            "pypi_editable_install",
            format!(
                "{purl} is an editable install ({}); vendor needs a regular installed distribution",
                dist.dist_info_dir.display()
            ),
        ));
    }

    let dist_info_name = dist
        .dist_info_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let script_names =
        match read_regular_to_string(&dist.dist_info_dir.join("entry_points.txt")).await {
            Ok(text) => console_script_names(&text),
            Err(_) => HashSet::new(),
        };

    // Select the wheel members from the installed RECORD.
    let mut members: Vec<String> = Vec::new();
    let mut out_of_tree: Vec<String> = Vec::new();
    for path in &dist.record {
        let path = path.as_str();
        if path.is_empty()
            || is_installer_bookkeeping(path, &dist_info_name)
            || path.ends_with(".pyc")
            || path.split('/').any(|c| c == "__pycache__")
        {
            continue;
        }
        // SECURITY: `is_safe_relative_subpath` is the in-tree gate. A RECORD
        // row that escapes site-packages (`../../../bin/x`, absolute paths)
        // must never be staged or zipped — only the installer-regenerated
        // console/gui scripts (matched by entry_points.txt NAME, never by
        // extension heuristics: the spike's splitext shortcut wrongly dropped
        // `../../../share/man/man6/pycowsay.6`) are silently excluded; any
        // OTHER out-of-tree entry is data the rebuilt wheel cannot carry, so
        // the whole vendor is refused fail-closed.
        if !is_safe_relative_subpath(path) {
            let last = path.rsplit('/').next().unwrap_or(path);
            if is_console_script_artifact(last, &script_names) {
                continue;
            }
            out_of_tree.push(path.to_string());
            continue;
        }
        members.push(path.to_string());
    }
    if !out_of_tree.is_empty() {
        out_of_tree.sort();
        return Err((
            "pypi_out_of_tree_files",
            format!(
                "RECORD lists files outside site-packages that are not console scripts \
                 (a rebuilt wheel cannot reproduce them): {}",
                out_of_tree.join(", ")
            ),
        ));
    }
    members.sort();
    members.dedup();

    // Stage the members into a private tree preserving the site-packages-
    // relative layout, so the manifest's sp-relative pypi file keys resolve.
    let stage = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok((
                failed_result(purl, site_packages, format!("cannot create stage dir: {e}")),
                None,
            ))
        }
    };
    let mut exec_bits: HashMap<String, bool> = HashMap::new();
    for member in &members {
        let src = site_packages.join(member);
        let (bytes, metadata) = match read_regular(&src).await {
            Ok(pair) => pair,
            Err(e) => {
                return Ok((
                    failed_result(
                        purl,
                        site_packages,
                        format!("RECORD member {member} is unreadable: {e}"),
                    ),
                    None,
                ))
            }
        };
        exec_bits.insert(member.clone(), is_executable(&metadata));
        let dst = stage.path().join(member);
        if let Some(parent) = dst.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return Ok((
                    failed_result(purl, site_packages, format!("cannot stage {member}: {e}")),
                    None,
                ));
            }
        }
        if let Err(e) = tokio::fs::write(&dst, &bytes).await {
            return Ok((
                failed_result(purl, site_packages, format!("cannot stage {member}: {e}")),
                None,
            ));
        }
    }

    // Patch the stage through the shared apply pipeline (same verify/source
    // strategy contract as `apply`, with the vendor auto-force policy —
    // see `force_apply_staged`). The installed tree is never touched.
    let mut result = super::force_apply_staged(
        purl,
        stage.path(),
        record,
        sources,
        dry_run,
        force,
        &dist.dist_name,
        &dist.version,
        warnings,
    )
    .await;
    if dry_run || !result.success {
        return Ok((result, None));
    }

    // Files CREATED by the patch (empty beforeHash) exist only in the stage;
    // union them into the member list so the wheel ships them.
    for (file_name, info) in &record.files {
        if info.before_hash.is_empty() {
            let normalized = normalize_file_path(file_name).to_string();
            if !members.contains(&normalized) {
                exec_bits.insert(normalized.clone(), false);
                members.push(normalized);
            }
        }
    }
    members.sort();

    // Regenerate RECORD from the staged (patched) bytes and assemble the
    // deterministic zip entry list (`(name, bytes, unix mode)` with the exec
    // bit preserved as 0o755): lexicographic order, RECORD forced last
    // (installers stream-read it; last is also what bdist_wheel emits).
    let mut entries: Vec<(String, Vec<u8>, u32)> = Vec::with_capacity(members.len() + 1);
    let mut record_lines = String::new();
    for member in &members {
        let bytes = match tokio::fs::read(stage.path().join(member)).await {
            Ok(b) => b,
            Err(e) => {
                result.success = false;
                result.error = Some(format!("staged member {member} vanished: {e}"));
                return Ok((result, None));
            }
        };
        let digest = sha2::Sha256::digest(&bytes);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        record_lines.push_str(&format!(
            "{},sha256={},{}\n",
            csv_quote(member),
            b64,
            bytes.len()
        ));
        let mode = if exec_bits.get(member).copied().unwrap_or(false) {
            0o755
        } else {
            0o644
        };
        entries.push((member.clone(), bytes, mode));
    }
    record_lines.push_str(&format!("{}/RECORD,,\n", csv_quote(&dist_info_name)));
    entries.push((
        format!("{dist_info_name}/RECORD"),
        record_lines.into_bytes(),
        0o644,
    ));

    let zip_bytes = match tokio::task::spawn_blocking(move || write_zip_entries(&entries)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            result.success = false;
            result.error = Some(format!("wheel zip assembly failed: {e}"));
            return Ok((result, None));
        }
        Err(e) => {
            result.success = false;
            result.error = Some(format!("wheel zip task failed: {e}"));
            return Ok((result, None));
        }
    };

    if let Some(parent) = dest.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            result.success = false;
            result.error = Some(format!("cannot create {}: {e}", parent.display()));
            return Ok((result, None));
        }
    }
    if let Err(e) = atomic_write_bytes(dest, &zip_bytes).await {
        result.success = false;
        result.error = Some(format!("cannot write {}: {e}", dest.display()));
        return Ok((result, None));
    }

    let artifact = WheelArtifact {
        file_name: dest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sha256_hex: hex::encode(sha2::Sha256::digest(&zip_bytes)),
        size: zip_bytes.len() as u64,
    };
    Ok((result, Some(artifact)))
}

/// Installer bookkeeping the wheel must not carry: signatures and per-install
/// state regenerated by pip/uv (`RECORD` itself is rebuilt; `direct_url.json`
/// describes the OLD origin and would mislabel the vendored install).
fn is_installer_bookkeeping(path: &str, dist_info_name: &str) -> bool {
    const NAMES: [&str; 6] = [
        "RECORD",
        "RECORD.jws",
        "RECORD.p7s",
        "INSTALLER",
        "REQUESTED",
        "direct_url.json",
    ];
    NAMES
        .iter()
        .any(|n| path == format!("{dist_info_name}/{n}"))
}

/// True when `dist-info/direct_url.json` marks the install editable.
async fn is_editable_install(dist_info_dir: &Path) -> bool {
    let Ok((bytes, _)) = read_regular(&dist_info_dir.join("direct_url.json")).await else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value
        .get("dir_info")
        .and_then(|d| d.get("editable"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// `[console_scripts]` / `[gui_scripts]` entry names from `entry_points.txt`.
fn console_script_names(text: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut in_scripts = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_scripts = section == "console_scripts" || section == "gui_scripts";
            continue;
        }
        if in_scripts {
            if let Some((name, _)) = line.split_once('=') {
                let name = name.trim();
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// True when an out-of-tree RECORD entry's final component is an installer-
/// generated script for a declared entry point (`x`, `x.exe`, `x-script.py`).
fn is_console_script_artifact(final_component: &str, script_names: &HashSet<String>) -> bool {
    if script_names.contains(final_component) {
        return true;
    }
    if let Some(stem) = final_component.strip_suffix(".exe") {
        if script_names.contains(stem) {
            return true;
        }
    }
    if let Some(stem) = final_component.strip_suffix("-script.py") {
        if script_names.contains(stem) {
            return true;
        }
    }
    false
}

/// Parse the member paths out of `RECORD` rows (`path,hash,size` CSV; quoted
/// fields possible). Only the path field is consumed — the RECORD is
/// regenerated from the patched bytes, so the recorded hash/size are never
/// read. Unparseable/blank lines are skipped rather than failing the whole
/// file — fail-open here is safe because the member list only ever loses a
/// row it could not have staged anyway.
fn parse_record_paths(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| parse_csv_record(line).into_iter().next())
        .filter(|path| !path.is_empty())
        .collect()
}

/// Minimal CSV record parser (RFC 4180 quoting: `"a,b"`, doubled `""`).
fn parse_csv_record(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => fields.push(std::mem::take(&mut current)),
                _ => current.push(c),
            }
        }
    }
    fields.push(current);
    fields
}

/// CSV-quote a field when it needs it (comma/quote/newline).
fn csv_quote(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG: &[u8] = b"class Six:\n    pass\n";
    const PATCHED: &[u8] = b"class Six:\n    pass\n# SOCKET-PATCH-MARKER\n";

    struct Fixture {
        _tmp: tempfile::TempDir,
        site_packages: PathBuf,
        blobs: PathBuf,
        dest: PathBuf,
    }

    /// A six-like installed dist plus a blob store carrying the afterHash
    /// bytes, mirroring a real `.socket/blobs/` layout.
    async fn make_fixture(extra_record_lines: &str, entry_points: Option<&str>) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let sp = tmp.path().join("site-packages");
        let di = sp.join("six-1.16.0.dist-info");
        tokio::fs::create_dir_all(&di).await.unwrap();
        tokio::fs::write(sp.join("six.py"), ORIG).await.unwrap();
        tokio::fs::write(
            di.join("METADATA"),
            "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nREADME body\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            di.join("WHEEL"),
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
        )
        .await
        .unwrap();
        let record = format!(
            "six.py,sha256=AAAA,20\n\
             six-1.16.0.dist-info/METADATA,sha256=BBBB,60\n\
             six-1.16.0.dist-info/WHEEL,,\n\
             six-1.16.0.dist-info/INSTALLER,sha256=,4\n\
             six-1.16.0.dist-info/RECORD,,\n\
             __pycache__/six.cpython-314.pyc,,\n{extra_record_lines}"
        );
        tokio::fs::write(di.join("RECORD"), record).await.unwrap();
        if let Some(ep) = entry_points {
            tokio::fs::write(di.join("entry_points.txt"), ep)
                .await
                .unwrap();
        }
        let blobs = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(compute_git_sha256_from_bytes(PATCHED)), PATCHED)
            .await
            .unwrap();
        let dest = tmp.path().join(format!(
            ".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl"
        ));
        Fixture {
            _tmp: tmp,
            site_packages: sp,
            blobs,
            dest,
        }
    }

    fn patch_record(files: &[(&str, &[u8], &[u8])]) -> PatchRecord {
        let mut map = HashMap::new();
        for (name, before, after) in files {
            map.insert(
                name.to_string(),
                PatchFileInfo {
                    before_hash: if before.is_empty() {
                        String::new()
                    } else {
                        compute_git_sha256_from_bytes(before)
                    },
                    after_hash: compute_git_sha256_from_bytes(after),
                },
            );
        }
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: map,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn zip_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect()
    }

    fn zip_file(bytes: &[u8], name: &str) -> Vec<u8> {
        use std::io::Read as _;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        let mut file = archive.by_name(name).unwrap();
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        out
    }

    #[cfg(unix)]
    fn zip_unix_mode(bytes: &[u8], name: &str) -> u32 {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        let file = archive.by_name(name).unwrap();
        file.unix_mode()
            .unwrap_or_else(|| panic!("{name} carries no unix mode"))
    }

    #[test]
    fn record_parse_round_trips_quoted_and_empty_fields() {
        let text = "six.py,sha256=abc_DEF,123\n\
                    \"weird,name.py\",sha256=zz,9\n\
                    six-1.16.0.dist-info/RECORD,,\n\
                    \n";
        let rows = parse_record_paths(text);
        // Quoted CSV path with an embedded comma survives; the empty-field
        // RECORD row and the blank line don't derail the parse.
        assert_eq!(
            rows,
            ["six.py", "weird,name.py", "six-1.16.0.dist-info/RECORD"]
        );
        // Emit side: a path needing quoting survives a parse round-trip.
        let quoted = csv_quote("weird,\"name\".py");
        assert_eq!(parse_csv_record(&quoted)[0], "weird,\"name\".py");
    }

    #[test]
    fn tag_compression_round_trips_and_rejects_non_cross_products() {
        let dist = InstalledDist {
            dist_info_dir: PathBuf::from("x"),
            dist_name: "six".into(),
            version: "1.16.0".into(),
            record: vec![],
            wheel_tags: vec!["py2-none-any".into(), "py3-none-any".into()],
        };
        assert_eq!(
            wheel_file_name(&dist).unwrap(),
            "six-1.16.0-py2.py3-none-any.whl"
        );

        // A tag set that is NOT a cross product of its components must refuse
        // rather than fabricate compatibility.
        let err =
            compress_wheel_tags(&["py2-none-any".into(), "py3-abi3-manylinux1_x86_64".into()])
                .unwrap_err();
        assert_eq!(err.0, "pypi_wheel_tags_unrecoverable");
        // Malformed (non-triple) tag.
        let err = compress_wheel_tags(&["py3".into()]).unwrap_err();
        assert_eq!(err.0, "pypi_wheel_tags_unrecoverable");
    }

    #[test]
    fn wheel_name_escapes_dist_info_stem_names() {
        let dist = InstalledDist {
            dist_info_dir: PathBuf::from("x"),
            dist_name: "Flask-SQLAlchemy".into(),
            version: "2.5.1".into(),
            record: vec![],
            wheel_tags: vec!["py3-none-any".into()],
        };
        assert_eq!(
            wheel_file_name(&dist).unwrap(),
            "Flask_SQLAlchemy-2.5.1-py3-none-any.whl"
        );
    }

    #[tokio::test]
    async fn locate_finds_dist_with_canonicalized_name_and_parses_metadata() {
        let fx = make_fixture("", None).await;
        // PEP 503: `SIX` and `six` collapse to the same name.
        let dist = locate_installed_dist(&fx.site_packages, "SIX", "1.16.0")
            .await
            .unwrap();
        assert_eq!(dist.dist_name, "six");
        assert_eq!(dist.version, "1.16.0");
        assert_eq!(dist.wheel_tags, vec!["py2-none-any", "py3-none-any"]);
        assert!(dist.record.iter().any(|r| r == "six.py"));

        let err = locate_installed_dist(&fx.site_packages, "six", "1.17.0")
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_dist_not_found");
    }

    #[tokio::test]
    async fn locate_refuses_missing_record_and_missing_wheel_metadata() {
        let fx = make_fixture("", None).await;
        let di = fx.site_packages.join("six-1.16.0.dist-info");

        let wheel_backup = tokio::fs::read(di.join("WHEEL")).await.unwrap();
        tokio::fs::remove_file(di.join("WHEEL")).await.unwrap();
        let err = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_missing_wheel_metadata");
        tokio::fs::write(di.join("WHEEL"), wheel_backup)
            .await
            .unwrap();

        tokio::fs::remove_file(di.join("RECORD")).await.unwrap();
        let err = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_missing_record");
    }

    #[tokio::test]
    async fn member_filter_excludes_bookkeeping_and_console_scripts() {
        // Console script `six-cmd` lives out of tree but is declared in
        // entry_points.txt — excluded, not refused. RECORD signature files,
        // INSTALLER, pyc files all drop out.
        let fx = make_fixture(
            "../../../bin/six-cmd,sha256=cc,99\n\
             ../../../bin/six-cmd.exe,,\n\
             six-1.16.0.dist-info/RECORD.jws,,\n\
             six-1.16.0.dist-info/entry_points.txt,sha256=dd,40\n",
            Some("[console_scripts]\nsix-cmd = six:main\n"),
        )
        .await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        let artifact = artifact.unwrap();
        let bytes = tokio::fs::read(&fx.dest).await.unwrap();
        assert_eq!(artifact.size, bytes.len() as u64);
        let names = zip_names(&bytes);
        assert!(names.contains(&"six.py".to_string()));
        assert!(names.contains(&"six-1.16.0.dist-info/METADATA".to_string()));
        assert!(names.contains(&"six-1.16.0.dist-info/entry_points.txt".to_string()));
        for forbidden in [
            "six-1.16.0.dist-info/INSTALLER",
            "six-1.16.0.dist-info/RECORD.jws",
            "__pycache__/six.cpython-314.pyc",
            "../../../bin/six-cmd",
        ] {
            assert!(
                !names.contains(&forbidden.to_string()),
                "{forbidden} leaked"
            );
        }
        // Patched bytes actually landed in the wheel.
        assert_eq!(zip_file(&bytes, "six.py"), PATCHED);
    }

    #[tokio::test]
    async fn out_of_tree_data_file_is_refused() {
        // `share/man/...` is a wheel .data payload, NOT a console script —
        // the spike showed name-stem heuristics must not swallow it.
        let fx = make_fixture(
            "../../../share/man/man6/six.6,sha256=ee,10\n",
            Some("[console_scripts]\nsix-cmd = six:main\n"),
        )
        .await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let err = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_out_of_tree_files");
        assert!(err.1.contains("share/man/man6/six.6"), "{}", err.1);
        assert!(!fx.dest.exists(), "refusal must not write the artifact");
    }

    #[tokio::test]
    async fn deterministic_zip_record_last_and_stable_across_builds() {
        let fx = make_fixture("", None).await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (r1, a1) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(r1.success);
        let bytes1 = tokio::fs::read(&fx.dest).await.unwrap();

        // Second build: the stage re-applies onto already-patched members
        // (AlreadyPatched verify) — bytes and hash must be identical.
        let (r2, a2) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(r2.success);
        let bytes2 = tokio::fs::read(&fx.dest).await.unwrap();
        assert_eq!(bytes1, bytes2, "wheel rebuild must be byte-deterministic");
        assert_eq!(a1.unwrap().sha256_hex, a2.unwrap().sha256_hex);

        // RECORD is the final zip entry and self-describes with `path,,`.
        let names = zip_names(&bytes1);
        assert_eq!(
            names.last().map(String::as_str),
            Some("six-1.16.0.dist-info/RECORD")
        );
        let record_text =
            String::from_utf8(zip_file(&bytes1, "six-1.16.0.dist-info/RECORD")).unwrap();
        assert!(record_text.ends_with("six-1.16.0.dist-info/RECORD,,\n"));
        // RECORD hash of six.py matches the patched bytes.
        let digest = sha2::Sha256::digest(PATCHED);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        assert!(
            record_text.contains(&format!("six.py,sha256={},{}", b64, PATCHED.len())),
            "{record_text}"
        );
    }

    #[tokio::test]
    async fn created_by_patch_file_is_unioned_into_the_wheel() {
        let fx = make_fixture("", None).await;
        let created = b"# brand new module\n";
        tokio::fs::write(
            fx.blobs.join(compute_git_sha256_from_bytes(created)),
            created,
        )
        .await
        .unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED), ("six_extra.py", b"", created)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, _) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        let bytes = tokio::fs::read(&fx.dest).await.unwrap();
        assert!(zip_names(&bytes).contains(&"six_extra.py".to_string()));
        assert_eq!(zip_file(&bytes, "six_extra.py"), created);
        let record_text =
            String::from_utf8(zip_file(&bytes, "six-1.16.0.dist-info/RECORD")).unwrap();
        assert!(record_text.contains("six_extra.py,sha256="));
        // The created file must NOT exist in the real site-packages.
        assert!(!fx.site_packages.join("six_extra.py").exists());
    }

    #[tokio::test]
    async fn editable_install_is_refused_before_staging() {
        let fx = make_fixture("", None).await;
        tokio::fs::write(
            fx.site_packages
                .join("six-1.16.0.dist-info/direct_url.json"),
            r#"{"url": "file:///work/six", "dir_info": {"editable": true}}"#,
        )
        .await
        .unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let err = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_editable_install");
    }

    #[tokio::test]
    async fn dry_run_verifies_but_writes_nothing() {
        let fx = make_fixture("", None).await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            true,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(result.success);
        assert!(artifact.is_none());
        assert!(!fx.dest.exists());
        // Installed tree untouched.
        assert_eq!(
            tokio::fs::read(fx.site_packages.join("six.py"))
                .await
                .unwrap(),
            ORIG
        );
    }

    /// Vendor auto-force policy: installed content matching NEITHER hash is
    /// overwritten with the verified patched content in the STAGE (the
    /// installed tree is never touched), and the overwrite is surfaced as a
    /// `vendor_content_mismatch_overwritten` warning.
    #[tokio::test]
    async fn hash_mismatch_overwrites_in_stage_with_warning() {
        let fx = make_fixture("", None).await;
        // Corrupt the installed six.py so verify sees a HashMismatch.
        tokio::fs::write(fx.site_packages.join("six.py"), b"tampered")
            .await
            .unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let mut warnings = Vec::new();
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut warnings,
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(artifact.is_some());
        assert!(fx.dest.exists(), "patched wheel must be written");
        assert_eq!(
            warnings
                .iter()
                .filter(|w| w.code == "vendor_content_mismatch_overwritten")
                .count(),
            1,
            "overwrite surfaced as a warning: {warnings:?}"
        );
        // Installed tree untouched — only the stage was overwritten.
        assert_eq!(
            tokio::fs::read(fx.site_packages.join("six.py"))
                .await
                .unwrap(),
            b"tampered"
        );
    }

    /// A patch-target file MISSING from the install still fails closed
    /// without `--force` — auto-force must not inherit force's silent
    /// NotFound skip (the wheel would ship without the fix).
    #[tokio::test]
    async fn missing_patch_file_fails_without_force() {
        let fx = make_fixture("", None).await;
        tokio::fs::remove_file(fx.site_packages.join("six.py"))
            .await
            .unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(!result.success);
        // The RECORD staging step trips first ("RECORD member ... is
        // unreadable") — either way the build fails closed rather than
        // packing a wheel without the fix.
        assert!(
            result.error.is_some(),
            "missing file fails closed with an error"
        );
        assert!(artifact.is_none());
        assert!(!fx.dest.exists());
    }

    #[test]
    fn console_script_artifact_matching_is_name_exact() {
        let names: HashSet<String> = ["pycowsay".to_string()].into_iter().collect();
        assert!(is_console_script_artifact("pycowsay", &names));
        assert!(is_console_script_artifact("pycowsay.exe", &names));
        assert!(is_console_script_artifact("pycowsay-script.py", &names));
        // The spike's splitext bug: `pycowsay.6` (a man page) must NOT match.
        assert!(!is_console_script_artifact("pycowsay.6", &names));
        assert!(!is_console_script_artifact("other", &names));
    }

    /// PEP 440 normalized versions legitimately carry `!` (epoch) and `+`
    /// (local separator), and real tools keep them literally in the wheel
    /// filename (bdist_wheel's `safer_version`). pip/uv REJECT the
    /// `_`-escaped spelling: `packaging.utils.parse_wheel_filename` raises
    /// InvalidWheelFilename on `torch-2.0.0_cu118-…` but parses
    /// `torch-2.0.0+cu118-…` — escaping them makes the vendored wheel
    /// uninstallable.
    #[test]
    fn wheel_version_keeps_local_and_epoch_separators() {
        let dist = InstalledDist {
            dist_info_dir: PathBuf::from("x"),
            dist_name: "torch".into(),
            version: "2.0.0+cu118".into(),
            record: vec![],
            wheel_tags: vec!["cp310-cp310-linux_x86_64".into()],
        };
        assert_eq!(
            wheel_file_name(&dist).unwrap(),
            "torch-2.0.0+cu118-cp310-cp310-linux_x86_64.whl"
        );

        let dist = InstalledDist {
            dist_info_dir: PathBuf::from("x"),
            dist_name: "pkg".into(),
            version: "1!2.0".into(),
            record: vec![],
            wheel_tags: vec!["py3-none-any".into()],
        };
        assert_eq!(wheel_file_name(&dist).unwrap(), "pkg-1!2.0-py3-none-any.whl");
    }

    /// `mkfifo(2)` directly instead of shelling out to the binary — the
    /// same helper as the sibling vendor FIFO tests: fork/exec flakes under
    /// heavy parallel load and the syscall needs no process at all.
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

    /// Await `fut` with a deadline. On timeout the open is wedged in a
    /// `spawn_blocking` thread that the runtime waits for on shutdown;
    /// connect a writer to release it so the test can FAIL instead of
    /// hanging the whole suite. (`timeout` drops the future itself, so
    /// nothing else keeps running after the release.)
    #[cfg(unix)]
    async fn expect_prompt<T>(fifo: &Path, fut: impl std::future::Future<Output = T>) -> T {
        let deadline = std::time::Duration::from_secs(5);
        match tokio::time::timeout(deadline, fut).await {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::OpenOptions::new().write(true).open(fifo);
                panic!(
                    "must complete promptly with a FIFO at {} instead of wedging in open(2)",
                    fifo.display()
                );
            }
        }
    }

    /// A FIFO planted as RECORD or WHEEL must fail fast as the existing
    /// unreadable-file refusal, not wedge `locate_installed_dist` (and the
    /// whole vendor run) forever in an `open(2)` waiting for a writer.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_record_or_wheel_does_not_wedge_locate() {
        let fx = make_fixture("", None).await;
        let di = fx.site_packages.join("six-1.16.0.dist-info");

        let record_backup = tokio::fs::read(di.join("RECORD")).await.unwrap();
        tokio::fs::remove_file(di.join("RECORD")).await.unwrap();
        mkfifo(&di.join("RECORD"));
        let err = expect_prompt(
            &di.join("RECORD"),
            locate_installed_dist(&fx.site_packages, "six", "1.16.0"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_missing_record");

        tokio::fs::remove_file(di.join("RECORD")).await.unwrap();
        tokio::fs::write(di.join("RECORD"), record_backup)
            .await
            .unwrap();
        tokio::fs::remove_file(di.join("WHEEL")).await.unwrap();
        mkfifo(&di.join("WHEEL"));
        let err = expect_prompt(
            &di.join("WHEEL"),
            locate_installed_dist(&fx.site_packages, "six", "1.16.0"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_missing_wheel_metadata");
    }

    /// A FIFO squatting a RECORD member must fail the build closed (same as
    /// an unreadable member), not wedge the staging loop forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_record_member_fails_closed_instead_of_wedging_build() {
        let fx = make_fixture("", None).await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        tokio::fs::remove_file(fx.site_packages.join("six.py"))
            .await
            .unwrap();
        mkfifo(&fx.site_packages.join("six.py"));
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = expect_prompt(
            &fx.site_packages.join("six.py"),
            build_patched_wheel(
                "pkg:pypi/six@1.16.0",
                &fx.site_packages,
                &dist,
                &record,
                &sources,
                &fx.dest,
                false,
                false,
                &mut Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(!result.success);
        assert!(
            result.error.as_deref().unwrap_or("").contains("unreadable"),
            "{:?}",
            result.error
        );
        assert!(artifact.is_none());
        assert!(!fx.dest.exists());
    }

    /// FIFOs planted as the optional dist-info extras (`direct_url.json`,
    /// `entry_points.txt` — both probed with fall-through-on-error reads)
    /// must read as absent and let the build succeed, not wedge it.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_direct_url_json_does_not_wedge_editable_probe() {
        let fx = make_fixture("", None).await;
        let fifo = fx
            .site_packages
            .join("six-1.16.0.dist-info/direct_url.json");
        mkfifo(&fifo);
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = expect_prompt(
            &fifo,
            build_patched_wheel(
                "pkg:pypi/six@1.16.0",
                &fx.site_packages,
                &dist,
                &record,
                &sources,
                &fx.dest,
                false,
                false,
                &mut Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(artifact.is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_entry_points_does_not_wedge_build() {
        let fx = make_fixture("", None).await;
        let fifo = fx
            .site_packages
            .join("six-1.16.0.dist-info/entry_points.txt");
        mkfifo(&fifo);
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = expect_prompt(
            &fifo,
            build_patched_wheel(
                "pkg:pypi/six@1.16.0",
                &fx.site_packages,
                &dist,
                &record,
                &sources,
                &fx.dest,
                false,
                false,
                &mut Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(artifact.is_some());
    }

    /// Locate-side degraded shapes: an undecodable `*.dist-info` entry is
    /// skipped (the real dist is still found), a RECORD that parses to zero
    /// member paths is refused, and a WHEEL whose only `Tag:` header is
    /// whitespace-valued is refused.
    #[tokio::test]
    async fn locate_skips_undecodable_dist_info_and_refuses_empty_record_and_tagless_wheel() {
        let fx = make_fixture("", None).await;
        // A regular FILE named like a dist-info: METADATA is unreadable
        // beneath it and the dir-name fallback rejects non-directories, so
        // read_python_metadata yields None and the entry is skipped. (An
        // empty dist-info DIRECTORY would instead be rescued by the
        // crawler's dir-name fallback and never exercise the skip.)
        tokio::fs::write(fx.site_packages.join("stray-1.0.dist-info"), b"not a dir")
            .await
            .unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        assert_eq!(dist.dist_name, "six");

        // RECORD present but degenerate: blank / whitespace-only lines and
        // an empty-path row all drop out of the parse, leaving no members.
        let di = fx.site_packages.join("six-1.16.0.dist-info");
        let record_backup = tokio::fs::read(di.join("RECORD")).await.unwrap();
        tokio::fs::write(di.join("RECORD"), "\n  \n,,\n")
            .await
            .unwrap();
        let err = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_missing_record");
        assert!(err.1.contains("lists no files"), "{}", err.1);

        // WHEEL present but its only Tag: value is whitespace, which the
        // non-empty filter drops — same refusal as a missing WHEEL.
        tokio::fs::write(di.join("RECORD"), record_backup)
            .await
            .unwrap();
        tokio::fs::write(
            di.join("WHEEL"),
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag:   \n",
        )
        .await
        .unwrap();
        let err = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap_err();
        assert_eq!(err.0, "pypi_missing_wheel_metadata");
        assert!(err.1.contains("no Tag: headers"), "{}", err.1);
    }

    /// A noncompliant dist-info stem carrying no version part
    /// (`six.dist-info`): `rfind('-')` misses, so `dist_name` falls back to
    /// the METADATA raw name — which then drives the rebuilt wheel filename.
    #[tokio::test]
    async fn locate_versionless_dist_info_stem_falls_back_to_metadata_name() {
        let tmp = tempfile::tempdir().unwrap();
        let sp = tmp.path().join("site-packages");
        let di = sp.join("six.dist-info");
        tokio::fs::create_dir_all(&di).await.unwrap();
        tokio::fs::write(sp.join("six.py"), ORIG).await.unwrap();
        tokio::fs::write(
            di.join("METADATA"),
            "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\n",
        )
        .await
        .unwrap();
        tokio::fs::write(di.join("WHEEL"), "Wheel-Version: 1.0\nTag: py3-none-any\n")
            .await
            .unwrap();
        tokio::fs::write(
            di.join("RECORD"),
            "six.py,sha256=AAAA,20\nsix.dist-info/METADATA,,\n",
        )
        .await
        .unwrap();

        let dist = locate_installed_dist(&sp, "six", "1.16.0").await.unwrap();
        assert_eq!(dist.dist_name, "six");
        assert_eq!(
            wheel_file_name(&dist).unwrap(),
            "six-1.16.0-py3-none-any.whl"
        );
    }

    /// An installed RECORD member with the exec bit set must come back out
    /// of the rebuilt wheel as unix mode 0o755 (a package script losing +x
    /// breaks the reinstalled dist), non-executables as 0o644 — and the
    /// exec bit must not break byte determinism.
    #[cfg(unix)]
    #[tokio::test]
    async fn executable_record_member_keeps_exec_bit_in_wheel() {
        use std::os::unix::fs::PermissionsExt as _;

        let fx = make_fixture("six_cli.py,sha256=cc,10\n", None).await;
        let cli = fx.site_packages.join("six_cli.py");
        tokio::fs::write(&cli, b"#!/usr/bin/env python3\n")
            .await
            .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();

        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (r1, a1) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(r1.success, "{:?}", r1.error);
        assert!(a1.is_some());
        let bytes1 = tokio::fs::read(&fx.dest).await.unwrap();
        assert_eq!(
            zip_unix_mode(&bytes1, "six_cli.py") & 0o777,
            0o755,
            "installed exec bit must survive into the wheel"
        );
        assert_eq!(
            zip_unix_mode(&bytes1, "six.py") & 0o777,
            0o644,
            "non-executable members stay 0o644"
        );

        let (r2, _) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(r2.success, "{:?}", r2.error);
        let bytes2 = tokio::fs::read(&fx.dest).await.unwrap();
        assert_eq!(bytes1, bytes2, "exec bit must not break determinism");
    }

    /// Dest-side write failures after a SUCCESSFUL apply flip the result to
    /// an Ok-shaped FAILED ApplyResult (success=false, artifact=None) — not
    /// an Err refusal. Both shapes are root-proof squatter states: a regular
    /// file blocking a dest path component, and a directory occupying dest
    /// itself.
    #[tokio::test]
    async fn dest_write_failures_fail_closed_with_ok_shaped_failed_result() {
        let fx = make_fixture("", None).await;
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);

        // A regular file squatting a dest path component: create_dir_all of
        // dest's parent fails with ENOTDIR.
        let blocker = fx._tmp.path().join("blocker");
        tokio::fs::write(&blocker, b"file").await.unwrap();
        let dest_a = blocker.join("sub").join("x.whl");
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &dest_a,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .starts_with("cannot create "),
            "{:?}",
            result.error
        );
        assert!(artifact.is_none());

        // Dest itself occupied by a directory: the atomic rename fails and
        // the squatter is left alone (never unlinked first).
        let dest_b = fx._tmp.path().join("out").join("x.whl");
        tokio::fs::create_dir_all(&dest_b).await.unwrap();
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &dest_b,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .starts_with("cannot write "),
            "{:?}",
            result.error
        );
        assert!(artifact.is_none());
        assert!(
            tokio::fs::metadata(&dest_b).await.unwrap().is_dir(),
            "the squatting directory must be left alone"
        );
    }

    /// The editable-install probe fails OPEN on a `direct_url.json` that is
    /// not valid JSON (deliberate, matching the missing-file twin) and on
    /// valid JSON with no `dir_info` — both read as not-editable and the
    /// build proceeds.
    #[tokio::test]
    async fn malformed_direct_url_json_reads_as_non_editable() {
        let fx = make_fixture("", None).await;
        let du = fx
            .site_packages
            .join("six-1.16.0.dist-info/direct_url.json");
        tokio::fs::write(&du, b"{ not json").await.unwrap();
        let dist = locate_installed_dist(&fx.site_packages, "six", "1.16.0")
            .await
            .unwrap();
        let record = patch_record(&[("six.py", ORIG, PATCHED)]);
        let sources = PatchSources::blobs_only(&fx.blobs);
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(artifact.is_some());
        assert!(fx.dest.exists());

        // Valid JSON, no dir_info: the unwrap_or(false) chain also reads
        // as not-editable.
        tokio::fs::write(&du, r#"{"url": "https://pypi.org/simple/six"}"#)
            .await
            .unwrap();
        let (result, artifact) = build_patched_wheel(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &dist,
            &record,
            &sources,
            &fx.dest,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(result.success, "{:?}", result.error);
        assert!(artifact.is_some());
    }

    /// entry_points.txt parser fall-throughs and script-artifact negatives:
    /// an in-section line without `=`, an empty-name row, a non-script
    /// section whose entries never reach the insert, and suffix strips
    /// whose stem is not a declared script.
    #[test]
    fn entry_points_parser_and_script_artifact_negative_edges() {
        let names = console_script_names(
            "[console_scripts]\n\
             junk line without equals\n\
             = empty-name\n\
             six-cmd = six:main\n\
             [flake8.extension]\n\
             not-a-script = x\n",
        );
        assert_eq!(
            names,
            ["six-cmd".to_string()].into_iter().collect::<HashSet<_>>()
        );

        let declared: HashSet<String> = ["pycowsay".to_string()].into_iter().collect();
        assert!(!is_console_script_artifact("other.exe", &declared));
        assert!(!is_console_script_artifact("other-script.py", &declared));
    }
}
