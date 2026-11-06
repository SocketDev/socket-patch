//! The patched wheel's own `RECORD`: the hosted Python stale-install
//! probe's evidence. A hosted rewrite pins the wheel in the lock and
//! installs nothing, so whether a warm virtualenv already holds the patched
//! bytes is read off the wheel the lock now pins: downloaded through its
//! grant URL, verified against the pinned sha256, and compared file by file
//! with the installed copy.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::api::client::ApiClient;
use crate::patch::apply::is_safe_relative_subpath;
use crate::vex::verify::InstalledRecordJudgment;

/// Largest `RECORD` or `WHEEL` member read out of a wheel.
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

/// What the patched wheel says it installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelRecord {
    /// The wheel's `<name>-<version>.dist-info` directory, which installers
    /// keep under that name in site-packages.
    dist_info: String,
    /// The wheel's `Tag:` lines: an installed copy built for other tags is
    /// another wheel, whose bytes say nothing about this one.
    tags: BTreeSet<String>,
    /// `(path relative to site-packages, urlsafe base64 sha256)` for every
    /// hashed file outside the dist-info and `.data` directories, which
    /// installers rewrite or move.
    files: Vec<(String, String)>,
}

/// The patched wheel at `url` (a grant-tokenized artifact URL), verified
/// against `sha256` (hex). `None` when it cannot be fetched, does not
/// verify, or carries no readable `RECORD`.
pub async fn fetch_patched_wheel_record(
    client: &ApiClient,
    url: &str,
    sha256: &str,
) -> Option<WheelRecord> {
    let bytes = client.download_artifact(url).await.ok()?;
    if !crate::utils::digest::sha256_hex_of(&bytes).eq_ignore_ascii_case(sha256) {
        return None;
    }
    crate::utils::fs::run_blocking(move || parse_wheel_record(&bytes)).await
}

fn read_member(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    name: &str,
) -> Option<String> {
    let entry = archive.by_name(name).ok()?;
    if entry.size() > MAX_RECORD_BYTES {
        return None;
    }
    let mut text = String::new();
    entry
        .take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// One `RECORD` row's fields: CSV, with `"`-quoted fields doubling `"`.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

fn parse_wheel_record(bytes: &[u8]) -> Option<WheelRecord> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
    // The wheel's own dist-info sits at the root, never nested.
    let dist_info = archive.file_names().find_map(|name| {
        let stem = name.strip_suffix("/RECORD")?;
        (stem.ends_with(".dist-info") && !stem.contains('/')).then(|| stem.to_string())
    })?;
    let record = read_member(&mut archive, &format!("{dist_info}/RECORD"))?;
    let wheel = read_member(&mut archive, &format!("{dist_info}/WHEEL"))?;
    let data_dir = format!("{}.data/", dist_info.strip_suffix(".dist-info")?);
    let dist_info_dir = format!("{dist_info}/");
    let files = record
        .lines()
        .filter_map(|line| {
            let fields = csv_fields(line);
            let path = fields.first()?;
            let hash = fields.get(1)?.strip_prefix("sha256=")?;
            (!hash.is_empty() && !path.starts_with(&dist_info_dir) && !path.starts_with(&data_dir))
                .then(|| (path.clone(), hash.to_string()))
        })
        .collect();
    Some(WheelRecord {
        tags: wheel_tags(&wheel),
        dist_info,
        files,
    })
}

fn wheel_tags(wheel: &str) -> BTreeSet<String> {
    wheel
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("Tag"))
        .map(|(_, value)| value.trim().to_string())
        .collect()
}

/// Judge the copy installed in `site` against `record`.
///
/// * The installed `<dist-info>/WHEEL` must carry the patched wheel's tags;
///   any other copy (another platform's build, an sdist install with no
///   `WHEEL`) is never judged.
/// * `patched`: every recorded file reads back at its recorded hash.
/// * `stale_evidence`: some recorded file was read and hashes to something
///   else. Missing, unreadable and unsafe-path files are never evidence.
pub async fn judge_installed_wheel(site: &Path, record: &WheelRecord) -> InstalledRecordJudgment {
    let site = site.to_path_buf();
    let record = record.clone();
    crate::utils::fs::run_blocking(move || {
        let installed_wheel = site.join(&record.dist_info).join("WHEEL");
        // Site-packages is user-writable: read through the regular-file
        // guard so a FIFO or device counts as unreadable instead of blocking.
        let same_build = crate::utils::fs::read_regular_to_string_sync(&installed_wheel)
            .is_ok_and(|text| wheel_tags(&text) == record.tags && !record.tags.is_empty());
        if !same_build || record.files.is_empty() {
            return InstalledRecordJudgment::default();
        }
        let mut out = InstalledRecordJudgment {
            patched: true,
            stale_evidence: false,
        };
        for (path, want) in &record.files {
            if !is_safe_relative_subpath(path) {
                out.patched = false;
                continue;
            }
            let Ok(bytes) = crate::utils::fs::read_regular_to_bytes_sync(&site.join(path)) else {
                out.patched = false;
                continue;
            };
            let got =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes));
            if got != want.trim_end_matches('=') {
                return InstalledRecordJudgment {
                    patched: false,
                    stale_evidence: true,
                };
            }
        }
        out
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    }

    const PATCHED: &[u8] = b"print('patched')\n";
    const UPSTREAM: &[u8] = b"print('upstream')\n";
    const WHEEL: &str = "Wheel-Version: 1.0\nTag: py3-none-any\n";

    fn wheel() -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut out);
            let options = zip::write::SimpleFileOptions::default();
            let record = format!(
                "pkg/mod.py,sha256={},{}\n\"pkg/a,b.py\",sha256={},1\n\
                 pkg-1.0.dist-info/METADATA,sha256={},1\npkg-1.0.data/scripts/x,sha256={},1\n\
                 pkg-1.0.dist-info/RECORD,,\n",
                b64(PATCHED),
                PATCHED.len(),
                b64(b"x"),
                b64(b"m"),
                b64(b"s"),
            );
            for (name, body) in [
                ("pkg/mod.py", PATCHED.to_vec()),
                ("pkg-1.0.dist-info/WHEEL", WHEEL.as_bytes().to_vec()),
                ("pkg-1.0.dist-info/RECORD", record.into_bytes()),
            ] {
                zip.start_file(name, options).unwrap();
                zip.write_all(&body).unwrap();
            }
            zip.finish().unwrap();
        }
        out.into_inner()
    }

    fn install(site: &Path, module: &[u8], wheel: &str) {
        std::fs::create_dir_all(site.join("pkg")).unwrap();
        std::fs::create_dir_all(site.join("pkg-1.0.dist-info")).unwrap();
        std::fs::write(site.join("pkg/mod.py"), module).unwrap();
        std::fs::write(site.join("pkg/a,b.py"), b"x").unwrap();
        std::fs::write(site.join("pkg-1.0.dist-info/WHEEL"), wheel).unwrap();
    }

    #[test]
    fn record_skips_dist_info_and_data_rows_and_reads_quoted_paths() {
        let record = parse_wheel_record(&wheel()).unwrap();
        assert_eq!(record.dist_info, "pkg-1.0.dist-info");
        assert_eq!(record.tags, BTreeSet::from(["py3-none-any".to_string()]));
        assert_eq!(
            record.files,
            [
                ("pkg/mod.py".to_string(), b64(PATCHED)),
                ("pkg/a,b.py".to_string(), b64(b"x")),
            ]
        );
    }

    #[tokio::test]
    async fn patched_stale_and_other_builds() {
        let record = parse_wheel_record(&wheel()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        install(tmp.path(), PATCHED, WHEEL);
        let judged = judge_installed_wheel(tmp.path(), &record).await;
        assert!(judged.patched && !judged.stale_evidence, "{judged:?}");

        install(tmp.path(), UPSTREAM, WHEEL);
        let judged = judge_installed_wheel(tmp.path(), &record).await;
        assert!(!judged.patched && judged.stale_evidence, "{judged:?}");

        install(
            tmp.path(),
            UPSTREAM,
            "Wheel-Version: 1.0\nTag: cp312-cp312-macosx_11_0_arm64\n",
        );
        assert_eq!(
            judge_installed_wheel(tmp.path(), &record).await,
            InstalledRecordJudgment::default(),
            "another build's bytes are never evidence"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_in_site_packages_is_unreadable_not_a_hang() {
        let record = parse_wheel_record(&wheel()).unwrap();
        for target in ["pkg/mod.py", "pkg-1.0.dist-info/WHEEL"] {
            let tmp = tempfile::tempdir().unwrap();
            install(tmp.path(), PATCHED, WHEEL);
            let fifo = tmp.path().join(target);
            std::fs::remove_file(&fifo).unwrap();
            let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            let judged = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                judge_installed_wheel(tmp.path(), &record),
            )
            .await
            .expect("a FIFO must not block the probe");
            assert_eq!(judged, InstalledRecordJudgment::default(), "{target}");
        }
    }

    #[tokio::test]
    async fn missing_files_are_not_evidence() {
        let record = parse_wheel_record(&wheel()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        install(tmp.path(), PATCHED, WHEEL);
        std::fs::remove_file(tmp.path().join("pkg/mod.py")).unwrap();
        assert_eq!(
            judge_installed_wheel(tmp.path(), &record).await,
            InstalledRecordJudgment::default()
        );
    }

    #[test]
    fn a_wheel_without_record_or_wheel_metadata_has_no_record() {
        assert!(parse_wheel_record(b"not a zip").is_none());
    }
}
