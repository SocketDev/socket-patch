//! Shared fixture for the self-update e2e suites: a staged copy of the
//! real binary (so `--update` never aims at the `CARGO_BIN_EXE` build
//! artifact) plus a wiremock fake of the GitHub release surface.
//!
//! Consumers pull this in alongside the main helpers:
//! ```ignore
//! #[path = "common/mod.rs"]
//! mod common;
//! #[path = "common/update_fixture.rs"]
//! mod update_fixture;
//! ```

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path as urlpath};
use wiremock::{Mock, MockServer, ResponseTemplate};

use socket_patch_cli::commands::update::UPDATE_TARGET;
use socket_patch_core::update::asset_name_for_target;

/// Release asset filename for the target this test binary was built for.
pub fn asset_name_for_current_target() -> String {
    asset_name_for_target(UPDATE_TARGET)
}

/// Run the staged install's binary under the standard hermetic scrub
/// (`common::run_bin_with_env`), plus the update kit: the state dir points
/// into the tempdir and the notifier stays off unless the caller's env —
/// which lands last and wins — flips it back on.
///
/// NOTE: resolves `crate::common`, so consumers must declare
/// `#[path = "common/mod.rs"] mod common;` BEFORE this module.
pub fn run_installed(
    install: &StagedInstall,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let state_dir = install.state_dir.display().to_string();
    let mut merged: Vec<(&str, &str)> = vec![
        ("SOCKET_UPDATE_STATE_DIR", state_dir.as_str()),
        ("SOCKET_NO_UPDATE_CHECK", "1"),
    ];
    merged.extend_from_slice(env);
    crate::common::run_bin_with_env(&install.bin, &install.workdir, args, &merged)
}

// ── Staged install ─────────────────────────────────────────────────────

/// A copy of the built binary living in its own tempdir "install", with
/// enough recorded state to prove (or disprove) a swap afterwards.
pub struct StagedInstall {
    pub root: tempfile::TempDir,
    /// `<root>/bin/socket-patch[.exe]` — the copy tests run and update.
    pub bin: PathBuf,
    /// `<root>/state` — SOCKET_UPDATE_STATE_DIR for the child.
    pub state_dir: PathBuf,
    /// `<root>/work` — the child's cwd; update must never create
    /// `.socket/` here.
    pub workdir: PathBuf,
    /// SHA-256 of the binary at staging time.
    pub pre_hash: String,
    /// Inode at staging time (a rename-based swap always changes it; an
    /// in-place overwrite of the running binary keeps it).
    #[cfg(unix)]
    pub pre_ino: u64,
}

pub fn sha256_file(p: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).expect("read file for hashing")))
}

fn real_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn bin_file_name() -> &'static str {
    if cfg!(windows) {
        "socket-patch.exe"
    } else {
        "socket-patch"
    }
}

/// Copy the built binary into a fresh tempdir install layout.
pub fn staged_install() -> StagedInstall {
    staged_install_at("bin")
}

/// Like [`staged_install`], but places the binary under an arbitrary
/// relative directory — the channel-detection suites craft shapes like
/// `node_modules/@socketsecurity/socket-patch-x/bin`.
pub fn staged_install_at(rel_bin_dir: &str) -> StagedInstall {
    let root = tempfile::tempdir().expect("create install tempdir");
    let bin_dir = root.path().join(rel_bin_dir);
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let bin = bin_dir.join(bin_file_name());
    std::fs::copy(real_binary(), &bin).expect("copy binary into staged install");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .expect("chmod staged binary");
    }
    let state_dir = root.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    let workdir = root.path().join("work");
    std::fs::create_dir_all(&workdir).expect("create workdir");
    let pre_hash = sha256_file(&bin);
    #[cfg(unix)]
    let pre_ino = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&bin).expect("stat staged binary").ino()
    };
    StagedInstall {
        root,
        bin,
        state_dir,
        workdir,
        pre_hash,
        #[cfg(unix)]
        pre_ino,
    }
}

impl StagedInstall {
    /// The binary is byte-identical to staging time and still executes.
    pub fn assert_binary_intact(&self) {
        assert_eq!(
            sha256_file(&self.bin),
            self.pre_hash,
            "installed binary must be untouched"
        );
        let out = std::process::Command::new(&self.bin)
            .arg("--version")
            .output()
            .expect("spawn staged binary");
        assert!(out.status.success(), "staged binary must still run");
    }

    /// `bin/` contains exactly the binary — no `.old` parked exes, no
    /// stage droppings. Retries briefly for Windows delete-pending files.
    pub fn assert_only_binary_present(&self) {
        let dir = self.bin.parent().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let extras: Vec<String> = std::fs::read_dir(dir)
                .expect("read bin dir")
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != bin_file_name())
                .collect();
            if extras.is_empty() {
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!("unexpected files next to the binary: {extras:?}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Update never touches project scope.
    pub fn assert_workdir_untouched(&self) {
        assert!(
            !self.workdir.join(".socket").exists(),
            "update must not create .socket/ in the working directory"
        );
    }

    /// The real build artifact was never the swap target.
    pub fn assert_build_artifact_untouched(pre_hash_of_real: &str) {
        assert_eq!(
            sha256_file(&real_binary()),
            pre_hash_of_real,
            "CARGO_BIN_EXE binary must never be modified by update tests"
        );
    }
}

/// Hash of the real build artifact — capture once at test start, compare
/// via [`StagedInstall::assert_build_artifact_untouched`] at the end.
pub fn real_binary_hash() -> String {
    sha256_file(&real_binary())
}

// ── The served "new binary" ────────────────────────────────────────────

/// Bytes to serve as the release's binary, plus whether they are
/// byte-distinct from the current binary (drives which swap assertion the
/// crux test can make).
///
/// Linux (ELF) and Windows (PE) loaders ignore trailing bytes, so the real
/// binary plus a marker trailer is an executable that (a) runs, (b)
/// reports the real version, and (c) differs byte-wise from the original.
/// macOS arm64 mandates a valid code signature that trailing garbage
/// breaks — there we serve pristine bytes and rely on inode-change
/// evidence instead. The `make_served_binary_output_execs` self-test below
/// is the canary that fails loudly if a platform stops tolerating this.
pub fn make_served_binary() -> (Vec<u8>, bool) {
    let mut bytes = std::fs::read(real_binary()).expect("read real binary");
    if cfg!(target_os = "macos") {
        (bytes, false)
    } else {
        bytes.extend_from_slice(b"\nSOCKET-PATCH-E2E-TRAILER-0123456789abcdef0123456789abcdef\n");
        (bytes, true)
    }
}

// ── Archive + SHA256SUMS builders ──────────────────────────────────────

/// Wrap `binary_bytes` the way release CI does: tar.gz with a single
/// `socket-patch` (mode 0755) entry, or a zip with `socket-patch.exe`.
pub fn archive_for_current_target(binary_bytes: &[u8]) -> Vec<u8> {
    if cfg!(windows) {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            use std::io::Write;
            writer
                .start_file("socket-patch.exe", opts)
                .expect("zip start_file");
            writer.write_all(binary_bytes).expect("zip write");
            writer.finish().expect("zip finish");
        }
        buf.into_inner()
    } else {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(binary_bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "socket-patch", binary_bytes)
            .expect("tar append");
        builder
            .into_inner()
            .expect("tar finish")
            .finish()
            .expect("gzip finish")
    }
}

/// `sha256sum`-format body: `<hex>  <name>` per line, sorted like
/// release.yml's `sha256sum * | sort`.
pub fn sha256sums_for(assets: &[(String, Vec<u8>)]) -> String {
    let mut lines: Vec<String> = assets
        .iter()
        .map(|(name, bytes)| format!("{}  {name}", hex::encode(Sha256::digest(bytes))))
        .collect();
    lines.sort();
    lines.join("\n") + "\n"
}

// ── Fake release server ────────────────────────────────────────────────

pub struct FakeRelease {
    pub server: MockServer,
    /// Value for the child's SOCKET_UPDATE_BASE_URL.
    pub base_url: String,
    pub version: String,
}

impl FakeRelease {
    /// Cross-cutting request hygiene: the updater must never send the
    /// Socket bearer to a release host, and must identify itself.
    pub async fn verify_request_hygiene(&self) {
        for req in self.server.received_requests().await.unwrap_or_default() {
            assert!(
                !req.headers.contains_key("authorization"),
                "no request to the release host may carry an Authorization header: {} {}",
                req.method,
                req.url
            );
            let ua = req
                .headers
                .get("user-agent")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            assert!(
                ua.starts_with("SocketPatchCLI/"),
                "User-Agent must identify the CLI, got {ua:?} on {} {}",
                req.method,
                req.url
            );
        }
    }

    pub async fn received_request_count(&self) -> usize {
        self.server.received_requests().await.unwrap_or_default().len()
    }
}

#[derive(Default)]
pub struct FakeReleaseBuilder {
    version: String,
    assets: Vec<(String, Vec<u8>)>,
    corrupt_sums_for: Vec<String>,
    omit_sums_for: Vec<String>,
    omit_sums_file: bool,
    omit_assets: Vec<String>,
    truncate: Vec<(String, usize)>,
    metadata_delay: Option<Duration>,
    asset_delay: Option<Duration>,
    expect_resolves: Option<u64>,
    expect_sums: Option<u64>,
    expect_asset_downloads: Option<u64>,
}

impl FakeReleaseBuilder {
    pub fn new(version: &str) -> Self {
        FakeReleaseBuilder {
            version: version.to_string(),
            ..Default::default()
        }
    }

    /// Add `binary_bytes`, wrapped as the archive for the current target.
    pub fn asset_for_current_target(mut self, binary_bytes: &[u8]) -> Self {
        self.assets.push((
            asset_name_for_current_target(),
            archive_for_current_target(binary_bytes),
        ));
        self
    }

    /// Add a raw pre-built asset (exotic shapes: garbage archives, other
    /// targets).
    pub fn raw_asset(mut self, filename: &str, bytes: Vec<u8>) -> Self {
        self.assets.push((filename.to_string(), bytes));
        self
    }

    /// Flip a nibble in this asset's SHA256SUMS entry.
    pub fn corrupt_sums_entry_for(mut self, filename: &str) -> Self {
        self.corrupt_sums_for.push(filename.to_string());
        self
    }

    /// Leave this asset out of SHA256SUMS entirely.
    pub fn omit_sums_entry_for(mut self, filename: &str) -> Self {
        self.omit_sums_for.push(filename.to_string());
        self
    }

    /// SHA256SUMS itself 404s.
    pub fn omit_sums_file(mut self) -> Self {
        self.omit_sums_file = true;
        self
    }

    /// Keep the asset in SHA256SUMS but 404 its download.
    pub fn omit_asset(mut self, filename: &str) -> Self {
        self.omit_assets.push(filename.to_string());
        self
    }

    /// Serve only the first `keep` bytes (SHA256SUMS covers the full
    /// bytes, so this manifests as a checksum mismatch).
    pub fn truncate_asset(mut self, filename: &str, keep: usize) -> Self {
        self.truncate.push((filename.to_string(), keep));
        self
    }

    pub fn delay_metadata(mut self, d: Duration) -> Self {
        self.metadata_delay = Some(d);
        self
    }

    pub fn delay_asset(mut self, d: Duration) -> Self {
        self.asset_delay = Some(d);
        self
    }

    /// Pin exact hit counts (verified when the MockServer drops).
    pub fn expect_resolves(mut self, n: u64) -> Self {
        self.expect_resolves = Some(n);
        self
    }

    pub fn expect_sums_fetches(mut self, n: u64) -> Self {
        self.expect_sums = Some(n);
        self
    }

    pub fn expect_asset_downloads(mut self, n: u64) -> Self {
        self.expect_asset_downloads = Some(n);
        self
    }

    pub async fn mount(self) -> FakeRelease {
        let server = MockServer::start().await;
        let base = server.uri();
        let ver = &self.version;

        // Latest resolution, redirect style (the primary path).
        let mut resolve = Mock::given(method("GET"))
            .and(urlpath("/SocketDev/socket-patch/releases/latest"))
            .respond_with({
                let mut resp = ResponseTemplate::new(302).insert_header(
                    "Location",
                    format!("{base}/SocketDev/socket-patch/releases/tag/v{ver}").as_str(),
                );
                if let Some(d) = self.metadata_delay {
                    resp = resp.set_delay(d);
                }
                resp
            });
        if let Some(n) = self.expect_resolves {
            resolve = resolve.expect(n);
        }
        resolve.mount(&server).await;

        // Latest resolution, API style (the fallback path) — mounted too so
        // the fixture survives either resolution choice.
        Mock::given(method("GET"))
            .and(urlpath("/repos/SocketDev/socket-patch/releases/latest"))
            .respond_with({
                let mut resp = ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": format!("v{ver}"),
                    "assets": self.assets.iter().map(|(name, _)| serde_json::json!({
                        "name": name,
                        "browser_download_url": format!(
                            "{base}/SocketDev/socket-patch/releases/download/v{ver}/{name}"
                        ),
                    })).collect::<Vec<_>>(),
                }));
                if let Some(d) = self.metadata_delay {
                    resp = resp.set_delay(d);
                }
                resp
            })
            .mount(&server)
            .await;

        // SHA256SUMS (unless withheld), with requested corruptions.
        if !self.omit_sums_file {
            let mut sums = sha256sums_for(
                &self
                    .assets
                    .iter()
                    .filter(|(name, _)| !self.omit_sums_for.contains(name))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            for name in &self.corrupt_sums_for {
                // Flip the first hex nibble of the matching line. Match on
                // the full "  <name>" suffix, not a bare ends_with — a
                // bare match would also corrupt a DIFFERENT asset whose
                // name merely ends with this one ("a.tar.gz" vs
                // "socket-patch-a.tar.gz").
                let suffix = format!("  {name}");
                sums = sums
                    .lines()
                    .map(|line| {
                        if line.ends_with(&suffix) {
                            let flipped = if line.starts_with('0') { "f" } else { "0" };
                            format!("{flipped}{}", &line[1..])
                        } else {
                            line.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
            }
            let mut sums_mock = Mock::given(method("GET"))
                .and(urlpath(format!(
                    "/SocketDev/socket-patch/releases/download/v{ver}/SHA256SUMS"
                )))
                .respond_with({
                    let mut resp = ResponseTemplate::new(200).set_body_string(sums);
                    if let Some(d) = self.metadata_delay {
                        resp = resp.set_delay(d);
                    }
                    resp
                });
            if let Some(n) = self.expect_sums {
                sums_mock = sums_mock.expect(n);
            }
            sums_mock.mount(&server).await;
        }

        // The assets themselves.
        for (name, bytes) in &self.assets {
            if self.omit_assets.contains(name) {
                continue;
            }
            let body = match self.truncate.iter().find(|(n, _)| n == name) {
                Some((_, keep)) => bytes[..(*keep).min(bytes.len())].to_vec(),
                None => bytes.clone(),
            };
            let mut asset_mock = Mock::given(method("GET"))
                .and(urlpath(format!(
                    "/SocketDev/socket-patch/releases/download/v{ver}/{name}"
                )))
                .respond_with({
                    let mut resp = ResponseTemplate::new(200).set_body_bytes(body);
                    if let Some(d) = self.asset_delay {
                        resp = resp.set_delay(d);
                    }
                    resp
                });
            if let Some(n) = self.expect_asset_downloads {
                asset_mock = asset_mock.expect(n);
            }
            asset_mock.mount(&server).await;
        }

        FakeRelease {
            base_url: base,
            server,
            version: self.version,
        }
    }
}

// ── Fixture self-tests (house style: run in every consuming binary) ────

#[cfg(test)]
mod fixture_selftests {
    use super::*;

    /// THE canary: if a platform ever stops tolerating trailer bytes on
    /// its executables, this fails here — loudly — instead of the crux
    /// test silently degrading.
    #[test]
    fn make_served_binary_output_execs() {
        let (bytes, byte_distinct) = make_served_binary();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(bin_file_name());
        std::fs::write(&path, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = std::process::Command::new(&path)
            .arg("--version")
            .output()
            .expect("spawn served binary");
        assert!(
            out.status.success(),
            "served binary must exec --version cleanly (trailer tolerance)"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.starts_with("socket-patch"), "{stdout}");
        if byte_distinct {
            assert_ne!(
                sha256_file(&path),
                real_binary_hash(),
                "trailered bytes must differ from the original"
            );
        }
    }

    #[test]
    fn staged_install_copies_not_links() {
        let install = staged_install();
        assert_eq!(sha256_file(&install.bin), real_binary_hash());
        assert_ne!(install.bin, real_binary());
        assert!(
            !std::fs::symlink_metadata(&install.bin)
                .unwrap()
                .file_type()
                .is_symlink(),
            "staged install must be a real copy"
        );
        install.assert_binary_intact();
        install.assert_only_binary_present();
    }

    #[test]
    fn sums_builder_matches_sha256sum_format() {
        let assets = vec![("a.tar.gz".to_string(), b"hello".to_vec())];
        let sums = sha256sums_for(&assets);
        let expected = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(sums, format!("{expected}  a.tar.gz\n"));
    }
}
