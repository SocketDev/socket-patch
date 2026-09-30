//! Real-`dotnet` capstones for NuGet HOSTED and VENDORED patches, each ending
//! in a manifest-less `socket-patch vex`.
//!
//! Both legs run the REAL .NET SDK on the host (whatever `dotnet` resolves
//! to, or `SOCKET_PATCH_DOTNET`), against a real nuget.org fixture restore:
//!
//! * **hosted** — `dotnet restore` of a `net<major>.0` project locking
//!   Newtonsoft.Json 13.0.3 → a patched nupkg is built from the REAL cached
//!   one (LICENSE.md + a marker line, `.signature.p7s` dropped — what the
//!   patch server does) and served as a NuGet v3 flat-container feed by a
//!   wiremock stand-in for patch.socket.dev (`--patch-server-url`) → `scan
//!   --mode hosted --vex` (the real rewriter adds the Socket source + an
//!   exact-id `packageSourceMapping` and re-pins the lock's `contentHash`;
//!   the in-run VEX attests `(redirected)`) → a FRESH checkout of only the
//!   committable files, cold `NUGET_PACKAGES`, `dotnet restore
//!   --locked-mode` must download the patched nupkg from the stand-in and
//!   extract the patched LICENSE.md byte-for-byte.
//! * **vendored** — the same fixture → `scan --mode vendored --vendor-source
//!   build --vex` (the real backend rebuilds the nupkg into
//!   `.socket/vendor/nuget/<uuid>/`, wires a local feed source + mapping and
//!   re-pins the lock) → fresh checkout, cold cache, `dotnet restore
//!   --locked-mode` extracts the patched bytes from the committed feed.
//!
//! Then, on the fresh checkout (the shape a depscan-opened PR / CI clone
//! has), the manifest-less VEX matrix:
//!
//! | step | shape | expectation |
//! |---|---|---|
//! | 1 | no manifest, ledger present | attested `(redirected)` / `(vendored)` online and `--offline` (ledger record) |
//! | 2 | no manifest, no ledgers | attested from the lockfile wiring + the patch API record; embedded `apply --vex` (+ `vendor --vex`) too |
//! | 3 | `--offline`, no ledgers | omitted `record_unavailable`, ZERO requests to the API |
//! | 4 | lock + config reverted to the registry, ledger + artifacts kept | omitted `redirect_unwired` / `vendor_unwired`, with and without `--no-verify`; a real `dotnet restore --locked-mode` of the reverted files installs the PRISTINE bytes |
//!
//! Gates (the `e2e` CI matrix runs this suite once per SDK major with
//! `--ignored`): `#[ignore]` keeps it out of the unpinned `test` job (it
//! needs nuget.org). Without `SOCKET_PATCH_DOTNET_E2E_REQUIRED` (set AND
//! non-empty) a missing `dotnet` is a `println` SKIP; with it that is a hard
//! failure. `SOCKET_PATCH_DOTNET_E2E_VERSION` (when non-empty; `9` or
//! `9.0`) selects that SDK through a sandbox `global.json` (runners carry
//! several side by side) and must then prefix `dotnet --version`, so a leg
//! can never pass on the wrong SDK or none.
//!
//! Local loop over side-by-side SDKs (`dotnet-install.sh --channel <M>.0
//! --install-dir <dir>`):
//!
//! ```sh
//! for m in 6 7 8 9 10; do
//!   SOCKET_PATCH_DOTNET=$HOME/dn$m/dotnet SOCKET_PATCH_DOTNET_E2E_REQUIRED=1 \
//!   SOCKET_PATCH_DOTNET_E2E_VERSION=$m \
//!   cargo test -p socket-patch-cli --test e2e_nuget_dotnet_build -- --ignored
//! done
//! ```

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use vex_e2e_common::*;

const ORG: &str = "test-org";
const ID: &str = "Newtonsoft.Json";
const ID_LOWER: &str = "newtonsoft.json";
const VERSION: &str = "13.0.3";
/// The purl the crawler, the patch API and the records name.
const PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
const PRODUCT: &str = "pkg:nuget/app@1.0.0";
const GHSA: &str = "GHSA-nuget-dotnet-e2e";
const CVE: &str = "CVE-2026-7310";
/// The patched file, keyed relative to the package dir the global packages
/// folder extracts (`<NUGET_PACKAGES>/<idLower>/<version>/`).
const FILE_KEY: &str = "LICENSE.md";
const MARKER: &[u8] = b"\nSOCKET-PATCH-NUGET-DOTNET-E2E-MARKER\n";
const HOSTED_UUID: &str = "4e4e4e4e-1111-4111-8111-4e4e4e4e4e4e";
const VENDORED_UUID: &str = "4f4f4f4f-1111-4111-8111-4f4f4f4f4f4f";
const NUPKG_NAME: &str = "newtonsoft.json.13.0.3.nupkg";

// ── toolchain gate ────────────────────────────────────────────────────

fn required() -> bool {
    std::env::var_os("SOCKET_PATCH_DOTNET_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

fn pinned_version() -> Option<String> {
    std::env::var("SOCKET_PATCH_DOTNET_E2E_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Serializes every `dotnet` process this binary spawns. The .NET 9 PAL
/// races when two processes create the same named mutex while the machine's
/// shared-memory root does not exist yet (a fresh CI runner has no
/// `/tmp/.dotnet`): both first-run `dotnet restore`s take NuGet's
/// `NuGet-Migrations` mutex, and the loser dies with `System.IO.IOException:
/// ... 'NuGet-Migrations' ... mkdir("/tmp/.dotnet/shm/session<N>",
/// AllUsers_ReadWriteExecute) == -1; errno == EEXIST` before restoring
/// anything. The hosted and vendored tests run in parallel, so without this
/// the SDK 9 leg failed whichever test lost. (Reproduced in
/// `mcr.microsoft.com/dotnet/sdk:9.0`: two concurrent first-run CLI
/// commands with fresh HOMEs and `/tmp/.dotnet` wiped before each of 60
/// rounds lost up to 9 of the 120 processes; none with the root pre-created
/// or the commands run one at a time.) Only the SDK phases
/// serialize — the socket-patch runs between them stay parallel.
static DOTNET_SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn dotnet_output(cmd: &mut Command) -> std::io::Result<Output> {
    let _one_at_a_time = DOTNET_SPAWN.lock().unwrap_or_else(|p| p.into_inner());
    cmd.output()
}

/// The SDK under test: its `dotnet` muxer, `--version`, and major.
struct Dotnet {
    bin: PathBuf,
    version: String,
    major: u32,
}

impl Dotnet {
    /// Preflight: `dotnet` present, the pinned SDK honored. `None` = SKIP
    /// (printed) — a hard failure under the REQUIRED gate.
    ///
    /// A pin (`SOCKET_PATCH_DOTNET_E2E_VERSION`) also SELECTS the SDK: the
    /// muxer runs the newest installed SDK unless a `global.json` says
    /// otherwise, and CI runners ship several side by side, so the sandbox
    /// root (the parent of every project dir this suite restores in) gets a
    /// `global.json` pinning `<major>.<minor>.100` with `rollForward:
    /// latestFeature` — the newest feature band of exactly that release.
    fn probe(tag: &str, sb: &Sandbox) -> Option<Self> {
        let bin = std::env::var_os("SOCKET_PATCH_DOTNET")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        if let Some(pin) = pinned_version() {
            let mut parts = pin.split('.');
            let major = parts.next().unwrap_or_default();
            let minor = parts.next().unwrap_or("0");
            std::fs::write(
                sb.root().join("global.json"),
                serde_json::json!({ "sdk": {
                    "version": format!("{major}.{minor}.100"),
                    "rollForward": "latestFeature",
                    "allowPrerelease": false,
                } })
                .to_string(),
            )
            .unwrap();
        }
        let out = dotnet_output(
            Command::new(&bin)
                .arg("--version")
                .current_dir(sb.root())
                .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
                .env("DOTNET_NOLOGO", "1"),
        );
        let version = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                assert!(
                    !required(),
                    "SOCKET_PATCH_DOTNET_E2E_REQUIRED is set but `{} --version` did not run — \
                     the matrix leg must install the .NET SDK first",
                    bin.display()
                );
                println!("SKIP e2e_nuget_dotnet_build ({tag}): no .NET SDK (`dotnet`)");
                return None;
            }
        };
        if let Some(pin) = pinned_version() {
            assert!(
                version == pin || version.starts_with(&format!("{pin}.")),
                "SOCKET_PATCH_DOTNET_E2E_VERSION pins SDK {pin} but `dotnet --version` is \
                 {version}: the matrix must run the pinned SDK"
            );
        }
        let major = version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or_else(|| panic!("unparsable `dotnet --version` {version:?}"));
        println!("e2e_nuget_dotnet_build ({tag}): .NET SDK {version}");
        Some(Dotnet {
            bin,
            version,
            major,
        })
    }

    /// `dotnet restore [extra]` in `cwd`, extracting into `store`, with a
    /// private HOME / user NuGet.Config / http cache (an ambient
    /// `~/.nuget/packages` or http cache would mask a download that did not
    /// happen) and every ambient `NUGET_*` / `DOTNET_*` override scrubbed.
    fn restore(&self, sb: &Sandbox, cwd: &Path, store: &Path, extra: &[&str]) -> Output {
        let mut cmd = Command::new(&self.bin);
        for (key, _) in std::env::vars_os() {
            let k = key.to_string_lossy().to_ascii_uppercase();
            if k.starts_with("NUGET_") || (k.starts_with("DOTNET_") && k != "DOTNET_ROOT") {
                cmd.env_remove(&key);
            }
        }
        let home = sb.root().join("home");
        std::fs::create_dir_all(&home).unwrap();
        cmd.current_dir(cwd)
            .args(["restore", "-p:NuGetAudit=false"])
            .args(extra)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_GENERATE_ASPNET_CERTIFICATE", "false")
            .env("DOTNET_MULTILEVEL_LOOKUP", "0")
            .env("DOTNET_CLI_HOME", &home)
            .env("HOME", &home)
            .env("APPDATA", home.join("appdata"))
            .env("NUGET_PACKAGES", store)
            .env("NUGET_HTTP_CACHE_PATH", sb.root().join("http-cache"))
            .env("NUGET_PLUGINS_CACHE_PATH", sb.root().join("plugins-cache"));
        if self.bin.is_absolute() {
            // A dotnet-install.sh SDK dir: pin the muxer's own root.
            cmd.env("DOTNET_ROOT", self.bin.parent().unwrap());
        }
        dotnet_output(&mut cmd).expect("spawn dotnet restore")
    }

    fn restore_ok(&self, sb: &Sandbox, cwd: &Path, store: &Path, extra: &[&str], what: &str) {
        let out = self.restore(sb, cwd, store, extra);
        assert!(
            out.status.success(),
            "SDK {}: {what}: dotnet restore {extra:?} failed\n--- stdout\n{}\n--- stderr\n{}",
            self.version,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn csproj(&self) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
             <TargetFramework>net{}.0</TargetFramework>\n    \
             <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n    \
             <NuGetAudit>false</NuGetAudit>\n  </PropertyGroup>\n  <ItemGroup>\n    \
             <PackageReference Include=\"{ID}\" Version=\"{VERSION}\" />\n  </ItemGroup>\n\
             </Project>\n",
            self.major
        )
    }
}

// ── sandbox + project plumbing ────────────────────────────────────────

struct Sandbox {
    tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Sandbox {
            tmp: tempfile::tempdir().unwrap(),
        }
    }

    fn root(&self) -> PathBuf {
        // Canonical: macOS `/var` → `/private/var` must not split one
        // directory into two spellings between NuGet and the CLI.
        self.tmp.path().canonicalize().unwrap()
    }

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

const REGISTRY_CONFIG: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  \
    <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
    </packageSources>\n</configuration>\n";

/// The registry fixture: csproj + nuget.org-only nuget.config, a REAL
/// `dotnet restore` writing packages.lock.json and extracting the package
/// into `store`. Returns the registry `(nuget.config, packages.lock.json)`.
fn restore_fixture(dn: &Dotnet, sb: &Sandbox, dir: &Path, store: &Path) -> (String, String) {
    std::fs::write(dir.join("app.csproj"), dn.csproj()).unwrap();
    std::fs::write(dir.join("nuget.config"), REGISTRY_CONFIG).unwrap();
    dn.restore_ok(sb, dir, store, &[], "fixture restore from nuget.org");
    let lock = std::fs::read_to_string(dir.join("packages.lock.json"))
        .expect("the fixture restore writes packages.lock.json");
    assert!(
        lock.contains(&format!("\"{ID}\"")) && lock.contains("\"contentHash\""),
        "the fixture lock pins {ID}: {lock}"
    );
    let license = pkg_dir(store).join(FILE_KEY);
    assert!(license.is_file(), "{} missing", license.display());
    (REGISTRY_CONFIG.to_string(), lock)
}

fn pkg_dir(store: &Path) -> PathBuf {
    store.join(ID_LOWER).join(VERSION)
}

/// Copy the committable files of `from` into a fresh `to`: csproj, nuget
/// config, lock and `.socket/` — never `obj/` or a package cache — then
/// drop the manifest and blobs (what a hosted / vendored checkout commits).
fn fresh_checkout(from: &Path, to: &Path) {
    for f in ["app.csproj", "nuget.config", "packages.lock.json"] {
        std::fs::copy(from.join(f), to.join(f)).unwrap_or_else(|e| panic!("copy {f}: {e}"));
    }
    copy_tree(&from.join(".socket"), &to.join(".socket"));
    strip_manifest(to);
    let blobs = to.join(".socket/blobs");
    if blobs.exists() {
        std::fs::remove_dir_all(blobs).unwrap();
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dst = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dst);
        } else {
            std::fs::copy(entry.path(), dst).unwrap();
        }
    }
}

/// The patch server's rebuild: the upstream nupkg with `FILE_KEY` replaced
/// and the package signature dropped (its digest no longer matches).
fn patched_nupkg(upstream: &[u8], patched: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(upstream)).unwrap();
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut replaced = false;
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).unwrap();
            let name = f.name().to_string();
            if name == ".signature.p7s" || f.is_dir() {
                continue;
            }
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();
            if name == FILE_KEY {
                bytes = patched.to_vec();
                replaced = true;
            }
            w.start_file(name, opts).unwrap();
            w.write_all(&bytes).unwrap();
        }
        assert!(replaced, "upstream nupkg has no {FILE_KEY}");
        w.finish().unwrap();
    }
    buf.into_inner()
}

/// NuGet's `contentHash`: base64(sha512(nupkg)).
fn content_hash(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha512};
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Run socket-patch (`args`) with a scrubbed environment and the crawler's
/// global packages folder pinned to `store` → (exit, envelope, stderr).
fn socket_patch(cwd: &Path, store: &Path, args: &[&str]) -> (Option<i32>, Value, String) {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("NUGET_PACKAGES", store)
        .env_remove("VIRTUAL_ENV")
        .output()
        .expect("spawn socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: stdout is not one JSON object ({e})\n--- stdout\n{}\n--- stderr\n{stderr}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    (out.status.code(), env, stderr)
}

/// A standalone / embedded VEX run over the checkout, crawling `store`.
fn vex_in(project: &Path, store: &Path, run: VexRun) -> VexOutcome {
    let run = VexRun {
        product: Some(PRODUCT.to_string()),
        ..run
    }
    .env("NUGET_PACKAGES", store);
    run_vex(&binary(), project, &run)
}

/// [`assert_not_attested`] with NuGet's case-insensitive ids: an omitted
/// reference is reported under the DISCOVERED purl (the lock/feed spelling,
/// lowercased by the extractor), attested ones under the record's purl.
fn assert_omitted(out: &VexOutcome, reason: &str, what: &str) {
    assert_omitted_parts(
        out.code,
        &out.envelope,
        out.doc.as_ref(),
        PURL,
        reason,
        what,
    );
}

fn vulns() -> [(&'static str, &'static [&'static str]); 1] {
    [(GHSA, &[CVE])]
}

// ── the Socket backend stand-in (API + hosted NuGet feed) ─────────────

/// One wiremock server playing both the authenticated patch API `scan`
/// drives (batch → by-package → reference grant → view with inline blob)
/// and, for the hosted leg, patch.socket.dev's NuGet v3 flat-container
/// feed for the patched nupkg.
struct Backend {
    server: wiremock::MockServer,
    rt: tokio::runtime::Runtime,
}

impl Backend {
    fn start(uuid: &str, pristine: &[u8], patched: &[u8], hosted_nupkg: Option<&[u8]>) -> Self {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let base = server.uri();
        let feed = format!("{base}/patch-registry/nuget/{HOSTED_TOKEN}/{uuid}");
        let view = serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { FILE_KEY: {
                "beforeHash": git_sha256(pristine),
                "afterHash": git_sha256(patched),
                "blobContent": b64(patched),
            } },
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "nuget dotnet e2e patch",
            "license": "MIT",
            "tier": "free",
        });
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{ "purl": PURL, "patches": [{
                        "uuid": uuid, "purl": PURL, "tier": "free", "cveIds": [CVE],
                        "ghsaIds": [GHSA], "severity": "high", "title": "t"
                    }] }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": uuid, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                        "description": "d", "license": "MIT", "tier": "free",
                        "vulnerabilities": view["vulnerabilities"].clone()
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            for p in [
                format!("/v0/orgs/{ORG}/patches/view/{uuid}"),
                format!("/patch/view/{uuid}"),
            ] {
                Mock::given(method("GET"))
                    .and(path(p))
                    .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
                    .mount(&server)
                    .await;
            }
            if let Some(nupkg) = hosted_nupkg {
                let artifact = format!("{feed}/flat/{ID_LOWER}/{VERSION}/{NUPKG_NAME}");
                Mock::given(method("POST"))
                    .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "results": { uuid: {
                            "status": "granted",
                            "url": artifact,
                            "purl": PURL,
                            "artifacts": [{
                                "kind": "tarball",
                                "url": artifact,
                                "integrity": { "sha512": format!("sha512-{}", content_hash(nupkg)) },
                            }],
                            "registryOverride": {
                                "kind": "nuget-v3",
                                "indexUrl": format!("{feed}/index.json"),
                                "identifiers": {
                                    "name": ID, "version": VERSION,
                                    "nugetIdLower": ID_LOWER, "nugetVersionNorm": VERSION,
                                },
                            },
                        } }
                    })))
                    .mount(&server)
                    .await;
                let feed_path = format!("/patch-registry/nuget/{HOSTED_TOKEN}/{uuid}");
                Mock::given(method("GET"))
                    .and(path(format!("{feed_path}/index.json")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "version": "3.0.0",
                        "resources": [{
                            "@id": format!("{feed}/flat/"),
                            "@type": "PackageBaseAddress/3.0.0",
                        }],
                    })))
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(format!("{feed_path}/flat/{ID_LOWER}/index.json")))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({ "versions": [VERSION] })),
                    )
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(format!(
                        "{feed_path}/flat/{ID_LOWER}/{VERSION}/{NUPKG_NAME}"
                    )))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .insert_header("content-type", "application/octet-stream")
                            .set_body_bytes(nupkg.to_vec()),
                    )
                    .mount(&server)
                    .await;
            }
        });
        Backend { server, rt }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn hits(&self, suffix: &str) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().ends_with(suffix))
            .count()
    }
}

/// .NET 9+ (NuGet 6.12+) refuses plain-http sources (NU1302) unless the
/// source opts in; the stand-in is `http://127.0.0.1`, production is https.
/// The opt-in is a hand edit on the Socket `<add>` the rewriter wrote —
/// discovery must still recognize it.
fn allow_http_source(config_path: &Path, uuid: &str) {
    let text = std::fs::read_to_string(config_path).unwrap();
    let key = format!("<add key=\"socket-patch-{uuid}\" ");
    assert!(text.contains(&key), "no Socket source to opt in: {text}");
    std::fs::write(
        config_path,
        text.replace(&key, &format!("{key}allowInsecureConnections=\"true\" ")),
    )
    .unwrap();
}

// ── the shared manifest-less VEX matrix ───────────────────────────────

/// Steps 1–4 on a fresh, really-restored checkout. `ledger` is the one the
/// flow persisted; `store` holds the checkout's (patched) restore.
#[allow(clippy::too_many_arguments)]
fn manifestless_vex_matrix(
    dn: &Dotnet,
    sb: &Sandbox,
    checkout: &Path,
    store: &Path,
    uuid: &str,
    marker: Marker,
    ledger: &str,
    dead_reason: &str,
    pristine: &[u8],
    patched: &[u8],
    registry: &(String, String),
    backend_uri: Option<&str>,
) {
    let sdk = &dn.version;
    let view = patch_view(uuid, PURL, &[(FILE_KEY, &git_sha256(patched))], &vulns());
    let api = PatchApi::start(vec![(uuid.to_string(), view)]);
    let hosted_origin = |r: VexRun| VexRun {
        patch_server_url: backend_uri.map(str::to_string),
        ..r
    };
    assert!(!checkout.join(".socket/manifest.json").exists());
    assert!(
        checkout.join(ledger).is_file(),
        "the flow committed {ledger}"
    );

    // (1) manifest gone, ledger present: online and offline (ledger record).
    for (label, run) in [
        ("online+ledger", VexRun::online(&api)),
        ("offline+ledger", VexRun::offline()),
    ] {
        let out = vex_in(checkout, store, hosted_origin(run));
        assert_eq!(out.code, Some(0), "SDK {sdk} {label}: {out}");
        assert_attested(out.doc(), PURL, uuid, marker, &vulns());
    }

    // (2) ledgers gone too: the lockfile/config wiring + the API record.
    let saved_ledger = std::fs::read(checkout.join(ledger)).unwrap();
    strip_ledgers(checkout);
    let before = api.view_requests(uuid);
    let out = vex_in(checkout, store, hosted_origin(VexRun::online(&api)));
    assert_eq!(out.code, Some(0), "SDK {sdk} no ledgers: {out}");
    assert_attested(out.doc(), PURL, uuid, marker, &vulns());
    assert!(
        api.view_requests(uuid) > before,
        "the record came from the API"
    );
    let mut nv = hosted_origin(VexRun::online(&api));
    nv.no_verify = true;
    let out = vex_in(checkout, store, nv);
    assert_eq!(out.code, Some(0), "SDK {sdk} no ledgers --no-verify: {out}");
    assert_attested(out.doc(), PURL, uuid, marker, &vulns());
    // Embedded: `apply --vex` with no manifest (and `vendor --vex` for a
    // vendored checkout) attests the same wiring.
    let mut embedded = vec![VexVia::Apply];
    if marker == Marker::Vendored {
        embedded.push(VexVia::Vendor);
    }
    for via in embedded {
        let out = vex_in(
            checkout,
            store,
            hosted_origin(VexRun::online(&api).via(via)),
        );
        assert_eq!(out.code, Some(0), "SDK {sdk} embedded {via:?}: {out}");
        assert_attested(out.doc(), PURL, uuid, marker, &vulns());
        assert!(
            !checkout.join(".socket/manifest.json").exists(),
            "{via:?} --vex never writes a manifest"
        );
    }

    // (3) offline with no ledgers: nothing to read the record from.
    let quiet = PatchApi::empty();
    let out = vex_in(
        checkout,
        store,
        hosted_origin(VexRun {
            proxy_url: Some(quiet.uri()),
            ..VexRun::offline()
        }),
    );
    assert_omitted(
        &out,
        "record_unavailable",
        &format!("SDK {sdk} offline no ledgers"),
    );
    quiet.assert_no_requests();

    // (4) the lock + config reverted to the registry, ledger + artifacts
    // kept: the claim is dead even though the patched bytes are still in
    // the checkout's store, with and without --no-verify.
    std::fs::write(checkout.join(ledger), &saved_ledger).unwrap();
    std::fs::write(checkout.join("nuget.config"), &registry.0).unwrap();
    std::fs::write(checkout.join("packages.lock.json"), &registry.1).unwrap();
    let reverted_store = sb.dir(&format!("store-reverted-{uuid}"));
    dn.restore_ok(
        sb,
        checkout,
        &reverted_store,
        &["--locked-mode"],
        "reverted restore",
    );
    assert_eq!(
        std::fs::read(pkg_dir(&reverted_store).join(FILE_KEY)).unwrap(),
        pristine,
        "SDK {sdk}: the reverted files restore the REGISTRY bytes"
    );
    for s in [store, reverted_store.as_path()] {
        for no_verify in [false, true] {
            let mut run = hosted_origin(VexRun::offline());
            run.no_verify = no_verify;
            let out = vex_in(checkout, s, run);
            assert_omitted(
                &out,
                dead_reason,
                &format!("SDK {sdk} reverted nv={no_verify}"),
            );
        }
    }
}

// ── hosted ────────────────────────────────────────────────────────────

#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored (CI e2e matrix pins each SDK major)"]
fn nuget_hosted_dotnet_restore_then_manifestless_vex() {
    let sb = Sandbox::new();
    let Some(dn) = Dotnet::probe("hosted", &sb) else {
        return;
    };
    let sdk = dn.version.clone();
    let fixture = sb.dir("fixture");
    let store_fx = sb.dir("store-fixture");
    let registry = restore_fixture(&dn, &sb, &fixture, &store_fx);

    let pristine = std::fs::read(pkg_dir(&store_fx).join(FILE_KEY)).unwrap();
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let upstream = std::fs::read(pkg_dir(&store_fx).join(NUPKG_NAME)).unwrap();
    let nupkg = patched_nupkg(&upstream, &patched);
    let backend = Backend::start(HOSTED_UUID, &pristine, &patched, Some(&nupkg));
    let uri = backend.uri();

    // `scan --mode hosted --vex`: the real rewriter + the in-run VEX.
    let embedded = fixture.join("scan.vex.json");
    let (code, env, stderr) = socket_patch(
        &fixture,
        &store_fx,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake-token",
            "--patch-server-url",
            &uri,
            "--vex",
            embedded.to_str().unwrap(),
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(
        code,
        Some(0),
        "SDK {sdk} scan --mode hosted: {env:#}\n{stderr}"
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let doc: Value = serde_json::from_slice(&std::fs::read(&embedded).unwrap()).unwrap();
    assert_attested(&doc, PURL, HOSTED_UUID, Marker::Redirected, &vulns());
    let config = std::fs::read_to_string(fixture.join("nuget.config")).unwrap();
    assert!(
        config.contains(&format!("socket-patch-{HOSTED_UUID}"))
            && config.contains(&format!("pattern=\"{ID}\"")),
        "the rewriter wired the Socket source + mapping: {config}"
    );
    let lock = std::fs::read_to_string(fixture.join("packages.lock.json")).unwrap();
    assert!(
        lock.contains(&content_hash(&nupkg)),
        "the lock is re-pinned to the patched nupkg: {lock}"
    );
    assert!(!fixture.join(".socket/manifest.json").exists());

    // Fresh checkout, cold cache: the REAL locked restore downloads the
    // patched nupkg from the hosted feed and extracts the patched bytes.
    let checkout = sb.dir("checkout");
    fresh_checkout(&fixture, &checkout);
    if dn.major >= 9 {
        allow_http_source(&checkout.join("nuget.config"), HOSTED_UUID);
    }
    let store_co = sb.dir("store-checkout");
    dn.restore_ok(
        &sb,
        &checkout,
        &store_co,
        &["--locked-mode"],
        "hosted fresh restore",
    );
    assert_eq!(
        std::fs::read(pkg_dir(&store_co).join(FILE_KEY)).unwrap(),
        patched,
        "SDK {sdk}: the hosted restore installed the PATCHED {FILE_KEY}"
    );
    assert!(
        backend.hits(&format!("/{NUPKG_NAME}")) >= 1,
        "SDK {sdk}: the nupkg came from the Socket feed stand-in"
    );

    manifestless_vex_matrix(
        &dn,
        &sb,
        &checkout,
        &store_co,
        HOSTED_UUID,
        Marker::Redirected,
        socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
        "redirect_unwired",
        &pristine,
        &patched,
        &registry,
        Some(&uri),
    );
}

// ── vendored ──────────────────────────────────────────────────────────

#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored (CI e2e matrix pins each SDK major)"]
fn nuget_vendored_dotnet_restore_then_manifestless_vex() {
    let sb = Sandbox::new();
    let Some(dn) = Dotnet::probe("vendored", &sb) else {
        return;
    };
    let sdk = dn.version.clone();
    let fixture = sb.dir("fixture");
    let store_fx = sb.dir("store-fixture");
    let registry = restore_fixture(&dn, &sb, &fixture, &store_fx);

    let pristine = std::fs::read(pkg_dir(&store_fx).join(FILE_KEY)).unwrap();
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let backend = Backend::start(VENDORED_UUID, &pristine, &patched, None);
    let uri = backend.uri();

    // `scan --mode vendored --vendor-source build --vex`: the real backend
    // rebuilds the nupkg from the restored cache copy + the patch blob.
    let embedded = fixture.join("scan.vex.json");
    let (code, env, stderr) = socket_patch(
        &fixture,
        &store_fx,
        &[
            "scan",
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--json",
            "--yes",
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake-token",
            "--vex",
            embedded.to_str().unwrap(),
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(
        code,
        Some(0),
        "SDK {sdk} scan --mode vendored: {env:#}\n{stderr}"
    );
    let doc: Value = serde_json::from_slice(&std::fs::read(&embedded).unwrap()).unwrap();
    assert_attested(&doc, PURL, VENDORED_UUID, Marker::Vendored, &vulns());
    let artifact = fixture.join(format!(".socket/vendor/nuget/{VENDORED_UUID}/{NUPKG_NAME}"));
    let artifact_bytes = std::fs::read(&artifact)
        .unwrap_or_else(|e| panic!("vendored nupkg {}: {e}", artifact.display()));
    let lock = std::fs::read_to_string(fixture.join("packages.lock.json")).unwrap();
    assert!(
        lock.contains(&content_hash(&artifact_bytes)),
        "the lock is re-pinned to the vendored nupkg: {lock}"
    );
    let config = std::fs::read_to_string(fixture.join("nuget.config")).unwrap();
    assert!(
        config.contains(&format!("socket-patch-{VENDORED_UUID}")),
        "the vendored feed source is wired: {config}"
    );

    // Fresh checkout, cold cache: the locked restore extracts the patched
    // bytes from the COMMITTED feed (the mapping routes the id only there).
    let checkout = sb.dir("checkout");
    fresh_checkout(&fixture, &checkout);
    let store_co = sb.dir("store-checkout");
    dn.restore_ok(
        &sb,
        &checkout,
        &store_co,
        &["--locked-mode"],
        "vendored fresh restore",
    );
    assert_eq!(
        std::fs::read(pkg_dir(&store_co).join(FILE_KEY)).unwrap(),
        patched,
        "SDK {sdk}: the vendored restore installed the PATCHED {FILE_KEY}"
    );

    manifestless_vex_matrix(
        &dn,
        &sb,
        &checkout,
        &store_co,
        VENDORED_UUID,
        Marker::Vendored,
        socket_patch_core::vendor::VENDOR_STATE_REL,
        "vendor_unwired",
        &pristine,
        &patched,
        &registry,
        None,
    );
}
