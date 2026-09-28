//! Real-`dotnet` capstone for the NuGet FALLBACK vendoring layout
//! (`SOCKET_PATCH_NUGET_LAYOUT=fallback`).
//!
//! Each leg builds a multi-project repo, restores it with lock files against
//! nuget.org, runs the REAL `socket-patch scan --mode vendored` with the
//! fallback layout (a wiremock stand-in plays the patch API; the patch
//! appends a marker to `lib/netstandard2.0/Newtonsoft.Json.dll`), and then
//! on fresh copies of only the committable files:
//!
//! 1. `dotnet restore --locked-mode` with a COLD global packages folder, and
//!    a build whose output carries the PATCHED dll;
//! 2. the same with a WARM global packages folder that already holds the
//!    upstream 13.0.1 (the collision the unique version exists for);
//! 3. a tampered seed file fails restore with `SOCKETPATCH002`, and putting
//!    the committed bytes back (what `git checkout` does) restores cleanly;
//! 4. a second `scan` is a no-op on every project file;
//! 5. `vendor --revert` restores the tree byte for byte, and a locked
//!    restore + build of it installs the UPSTREAM dll again.
//!
//! Legs: `sln_locked` (Lib → Newtonsoft.Json, App → ProjectReference Lib,
//! Other unrelated), `cpm_locked` (central package management without
//! transitive pinning) and `cpm_pinning` (with
//! `CentralPackageTransitivePinningEnabled`, plus a Tool that only reaches
//! the id through Newtonsoft.Json.Bson).
//!
//! Gates: `#[ignore]` (needs nuget.org); a missing `dotnet` is a SKIP unless
//! `SOCKET_PATCH_DOTNET_E2E_REQUIRED` is set and non-empty. Run with
//! `cargo test -p socket-patch-cli --all-features --test
//! e2e_nuget_fallback_dotnet -- --ignored --test-threads=1`.

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use vex_e2e_common::{binary, git_sha256};

const ORG: &str = "test-org";
const ID: &str = "Newtonsoft.Json";
const ID_LOWER: &str = "newtonsoft.json";
const VERSION: &str = "13.0.1";
const PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.1";
const UUID: &str = "3f9a01bc-1111-4222-8333-444455556666";
/// `13.0.1.(2^30 + (0x3f9a01bc >> 2))`.
const SOCKET_VERSION: &str = "13.0.1.1340506223";
const FILE_KEY: &str = "lib/netstandard2.0/Newtonsoft.Json.dll";
const MARKER: &[u8] = b"SOCKETPATCHED";
const GHSA: &str = "GHSA-nuget-fallback-e2e";
const CVE: &str = "CVE-2026-7311";

fn required() -> bool {
    std::env::var_os("SOCKET_PATCH_DOTNET_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

// ── sandbox + dotnet ──────────────────────────────────────────────────

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
        self.tmp.path().canonicalize().unwrap()
    }

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

struct Dotnet {
    bin: PathBuf,
    major: u32,
}

impl Dotnet {
    fn probe(sb: &Sandbox) -> Option<Self> {
        let bin = std::env::var_os("SOCKET_PATCH_DOTNET")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        let out = Command::new(&bin)
            .arg("--version")
            .current_dir(sb.root())
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1")
            .output();
        let version = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                assert!(
                    !required(),
                    "SOCKET_PATCH_DOTNET_E2E_REQUIRED is set but `{} --version` did not run",
                    bin.display()
                );
                println!("SKIP e2e_nuget_fallback_dotnet: no .NET SDK (`dotnet`)");
                return None;
            }
        };
        let major = version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or_else(|| panic!("unparsable `dotnet --version` {version:?}"));
        println!("e2e_nuget_fallback_dotnet: .NET SDK {version}");
        Some(Dotnet { bin, major })
    }

    /// `dotnet <args>` in `cwd` with `store` as the global packages folder
    /// and every other NuGet / .NET location private to the sandbox.
    fn run(&self, sb: &Sandbox, cwd: &Path, store: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.bin);
        for (key, _) in std::env::vars_os() {
            let k = key.to_string_lossy().to_ascii_uppercase();
            if k.starts_with("NUGET_") || (k.starts_with("DOTNET_") && k != "DOTNET_ROOT") {
                cmd.env_remove(&key);
            }
        }
        let home = sb.dir("home");
        let tmp = sb.dir("dotnet-tmp");
        cmd.current_dir(cwd)
            .args(args)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_GENERATE_ASPNET_CERTIFICATE", "false")
            .env("DOTNET_MULTILEVEL_LOOKUP", "0")
            .env("MSBUILDDISABLENODEREUSE", "1")
            .env("DOTNET_CLI_HOME", &home)
            .env("HOME", &home)
            .env("TMPDIR", &tmp)
            .env("APPDATA", home.join("appdata"))
            .env("NUGET_PACKAGES", store)
            .env("NUGET_HTTP_CACHE_PATH", sb.root().join("http-cache"))
            .env("NUGET_PLUGINS_CACHE_PATH", sb.root().join("plugins-cache"));
        if self.bin.is_absolute() {
            cmd.env("DOTNET_ROOT", self.bin.parent().unwrap());
        }
        cmd.output().expect("spawn dotnet")
    }

    fn ok(&self, sb: &Sandbox, cwd: &Path, store: &Path, args: &[&str], what: &str) -> String {
        let out = self.run(sb, cwd, store, args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "{what}: dotnet {args:?} failed in {}\n{text}",
            cwd.display()
        );
        text
    }

    fn restore(&self, sb: &Sandbox, cwd: &Path, store: &Path, locked: bool) -> Output {
        let mut args = vec![
            "restore",
            "Repo.sln",
            "--disable-build-servers",
            "-p:NuGetAudit=false",
        ];
        if locked {
            args.push("--locked-mode");
        }
        self.run(sb, cwd, store, &args)
    }

    fn restore_ok(&self, sb: &Sandbox, cwd: &Path, store: &Path, locked: bool, what: &str) {
        let out = self.restore(sb, cwd, store, locked);
        assert!(
            out.status.success(),
            "{what}: dotnet restore failed in {}\n{}{}",
            cwd.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn build_ok(&self, sb: &Sandbox, cwd: &Path, store: &Path, what: &str) {
        self.ok(
            sb,
            cwd,
            store,
            &[
                "build",
                "Repo.sln",
                "--no-restore",
                "--disable-build-servers",
                "-p:NuGetAudit=false",
            ],
            what,
        );
    }
}

// ── repo shapes ───────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Sln,
    Cpm,
    CpmPinning,
}

impl Shape {
    fn central(self) -> bool {
        self != Shape::Sln
    }

    /// Executables whose build output carries Newtonsoft.Json 13.0.1 (a
    /// library's output does not copy its package assemblies).
    fn patched_outputs(self) -> &'static [&'static str] {
        match self {
            Shape::Sln | Shape::Cpm => &["App"],
            Shape::CpmPinning => &["App", "Tool"],
        }
    }
}

fn csproj(tfm: &str, exe: bool, items: &str) -> String {
    let output = if exe {
        "\n    <OutputType>Exe</OutputType>"
    } else {
        ""
    };
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>{output}\n    \
         <TargetFramework>{tfm}</TargetFramework>\n    \
         <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n    \
         <NuGetAudit>false</NuGetAudit>\n  </PropertyGroup>\n  <ItemGroup>\n{items}  \
         </ItemGroup>\n</Project>\n"
    )
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn make_repo(dn: &Dotnet, sb: &Sandbox, shape: Shape, repo: &Path, store: &Path) {
    let tfm = format!("net{}.0", dn.major);
    let ver = |v: &str| {
        if shape.central() {
            String::new()
        } else {
            format!(" Version=\"{v}\"")
        }
    };
    write(
        &repo.join("nuget.config"),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
         <clear />\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
         </packageSources>\n</configuration>\n",
    );
    write(
        &repo.join("src/Lib/Lib.csproj"),
        &csproj(
            &tfm,
            false,
            &format!(
                "    <PackageReference Include=\"{ID}\"{} />\n",
                ver(VERSION)
            ),
        ),
    );
    write(
        &repo.join("src/Lib/Class1.cs"),
        "namespace Lib;\npublic static class Class1 { public static string S() => \
         Newtonsoft.Json.JsonConvert.SerializeObject(new { a = 1 }); }\n",
    );
    write(
        &repo.join("src/App/App.csproj"),
        &csproj(
            &tfm,
            true,
            "    <ProjectReference Include=\"../Lib/Lib.csproj\" />\n",
        ),
    );
    write(
        &repo.join("src/App/Program.cs"),
        "System.Console.WriteLine(Lib.Class1.S());\n",
    );
    let mut projects = vec!["src/Lib/Lib.csproj", "src/App/App.csproj"];
    match shape {
        Shape::Sln => {
            write(
                &repo.join("src/Other/Other.csproj"),
                &csproj(
                    &tfm,
                    false,
                    "    <PackageReference Include=\"Humanizer.Core\" Version=\"2.14.1\" />\n",
                ),
            );
            projects.push("src/Other/Other.csproj");
        }
        Shape::CpmPinning => {
            write(
                &repo.join("src/Tool/Tool.csproj"),
                &csproj(
                    &tfm,
                    true,
                    "    <PackageReference Include=\"Newtonsoft.Json.Bson\" />\n",
                ),
            );
            write(
                &repo.join("src/Tool/Program.cs"),
                "System.Console.WriteLine(typeof(Newtonsoft.Json.Bson.BsonDataReader).Assembly.\
                 FullName);\n",
            );
            projects.push("src/Tool/Tool.csproj");
        }
        Shape::Cpm => {}
    }
    if shape.central() {
        let pin = if shape == Shape::CpmPinning {
            "\n    <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>"
        } else {
            ""
        };
        let bson = if shape == Shape::CpmPinning {
            "\n    <PackageVersion Include=\"Newtonsoft.Json.Bson\" Version=\"1.0.2\" />"
        } else {
            ""
        };
        write(
            &repo.join("Directory.Packages.props"),
            &format!(
                "<Project>\n  <PropertyGroup>\n    \
                 <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>{pin}\n  \
                 </PropertyGroup>\n  <ItemGroup>\n    <PackageVersion Include=\"{ID}\" \
                 Version=\"{VERSION}\" />{bson}\n  </ItemGroup>\n</Project>\n"
            ),
        );
    }
    dn.ok(sb, repo, store, &["new", "sln", "-n", "Repo"], "new sln");
    let mut add = vec!["sln", "Repo.sln", "add"];
    add.extend(projects.iter().copied());
    dn.ok(sb, repo, store, &add, "sln add");
}

// ── tree helpers ──────────────────────────────────────────────────────

fn skip_dir(name: &str) -> bool {
    name == "bin" || name == "obj"
}

/// Every committable file of `root` (no `bin/` / `obj/`) → bytes.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                if !skip_dir(&name) {
                    walk(root, &path, out);
                }
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, std::fs::read(&path).unwrap());
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A fresh "checkout" of `from`: only its committable files.
fn checkout(from: &Path, to: &Path) {
    for (rel, bytes) in tree(from) {
        let dst = to.join(&rel);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::write(dst, bytes).unwrap();
    }
}

fn locks(root: &Path) -> BTreeMap<String, Vec<u8>> {
    tree(root)
        .into_iter()
        .filter(|(k, _)| k.ends_with("packages.lock.json"))
        .collect()
}

fn diff_trees(a: &BTreeMap<String, Vec<u8>>, b: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in a {
        match b.get(k) {
            None => out.push(format!("- {k}")),
            Some(w) if w != v => out.push(format!("~ {k}")),
            _ => {}
        }
    }
    for k in b.keys() {
        if !a.contains_key(k) {
            out.push(format!("+ {k}"));
        }
    }
    out
}

fn assert_output_dll(root: &Path, projects: &[&str], tfm: &str, want: &[u8], what: &str) {
    for p in projects {
        let dll = root.join(format!("src/{p}/bin/Debug/{tfm}/Newtonsoft.Json.dll"));
        let bytes =
            std::fs::read(&dll).unwrap_or_else(|e| panic!("{what}: {}: {e}", dll.display()));
        assert!(
            bytes == want,
            "{what}: {} is not the expected dll (len {} vs {}, tail {:?})",
            dll.display(),
            bytes.len(),
            want.len(),
            String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(13)..])
        );
    }
}

// ── the patch API stand-in ────────────────────────────────────────────

struct Backend {
    server: wiremock::MockServer,
    _rt: tokio::runtime::Runtime,
}

impl Backend {
    fn start(pristine: &[u8], patched: &[u8]) -> Self {
        Self::start_with(UUID, pristine, patched)
    }

    /// The patch API serving patch `uuid` of [`PURL`].
    fn start_with(uuid: &str, pristine: &[u8], patched: &[u8]) -> Self {
        use base64::Engine as _;
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let vulnerabilities = serde_json::json!({ GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
        } });
        let view = serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { FILE_KEY: {
                "beforeHash": git_sha256(pristine),
                "afterHash": git_sha256(patched),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(patched),
            } },
            "vulnerabilities": vulnerabilities,
            "description": "nuget fallback e2e patch",
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
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
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
        });
        Backend { server, _rt: rt }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }
}

/// Run socket-patch with a scrubbed environment and the crawler's global
/// packages folder at `store`. `opt_in` sets `SOCKET_PATCH_NUGET_LAYOUT=
/// fallback`; without it only the ledger's fallback entries select the
/// layout.
fn socket_patch_layout(
    cwd: &Path,
    store: &Path,
    args: &[&str],
    opt_in: bool,
) -> (Option<i32>, Value, String) {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    if opt_in {
        cmd.env("SOCKET_PATCH_NUGET_LAYOUT", "fallback");
    }
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("NUGET_PACKAGES", store)
        .env("HOME", store.parent().unwrap().join("home"))
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

fn scan_vendored(repo: &Path, store: &Path, backend: &Backend) -> (Option<i32>, Value, String) {
    scan_vendored_layout(repo, store, backend, true)
}

fn scan_vendored_layout(
    repo: &Path,
    store: &Path,
    backend: &Backend,
    opt_in: bool,
) -> (Option<i32>, Value, String) {
    let uri = backend.uri();
    socket_patch_layout(
        repo,
        store,
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
        ],
        opt_in,
    )
}

fn dotnet_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── the leg ───────────────────────────────────────────────────────────

fn run_leg(shape: Shape) {
    let sb = Sandbox::new();
    let Some(dn) = Dotnet::probe(&sb) else {
        return;
    };
    let tfm = format!("net{}.0", dn.major);
    let repo = sb.dir("repo");
    let store_fx = sb.dir("store-fixture");
    make_repo(&dn, &sb, shape, &repo, &store_fx);
    dn.restore_ok(
        &sb,
        &repo,
        &store_fx,
        false,
        "fixture restore from nuget.org",
    );
    let pre_vendor = tree(&repo);
    assert!(
        pre_vendor.contains_key("src/Lib/packages.lock.json")
            && pre_vendor.contains_key("src/App/packages.lock.json"),
        "{shape:?}: the fixture restore wrote per-project locks"
    );
    let upstream_dir = store_fx.join(ID_LOWER).join(VERSION);
    let pristine = std::fs::read(upstream_dir.join(FILE_KEY)).unwrap();
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let backend = Backend::start(&pristine, &patched);

    // ── vendor (the real CLI, fallback layout) ───────────────────────────
    let (code, env, stderr) = scan_vendored(&repo, &store_fx, &backend);
    assert_eq!(
        code,
        Some(0),
        "{shape:?} scan --mode vendored: {env:#}\n{stderr}"
    );
    let seed = repo.join(format!(
        ".socket/vendor/nuget/{UUID}/{ID_LOWER}/{SOCKET_VERSION}"
    ));
    assert_eq!(
        std::fs::read(seed.join(FILE_KEY))
            .unwrap_or_else(|e| panic!("{shape:?}: no seed dll ({e}): {env:#}\n{stderr}")),
        patched,
        "{shape:?}: the seed carries the patched dll"
    );
    for f in [".nupkg.metadata", "newtonsoft.json.nuspec"] {
        assert!(seed.join(f).is_file(), "{shape:?}: seed {f}");
    }
    assert!(
        !seed.join(".signature.p7s").exists() && !seed.join("[Content_Types].xml").exists(),
        "{shape:?}: OPC parts dropped"
    );
    for f in ["socket-patch.targets", ".gitattributes", ".gitignore"] {
        assert!(
            repo.join(".socket/vendor/nuget").join(f).is_file(),
            "{shape:?}: {f}"
        );
    }
    let dbp = std::fs::read_to_string(repo.join("Directory.Build.props")).unwrap();
    assert!(dbp.contains("socket-patch:begin"), "{dbp}");
    let lib_lock = std::fs::read_to_string(repo.join("src/Lib/packages.lock.json")).unwrap();
    assert!(
        lib_lock.contains(&format!("\"resolved\": \"{SOCKET_VERSION}\"")),
        "{shape:?}: {lib_lock}"
    );
    let state: Value =
        serde_json::from_slice(&std::fs::read(repo.join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    let entry = state["entries"]
        .as_object()
        .and_then(|m| m.values().next())
        .cloned()
        .unwrap_or_else(|| panic!("{shape:?}: no ledger entry: {state:#}"));
    assert_eq!(entry["flavor"], "nuget-fallback", "{entry:#}");
    assert_eq!(
        entry["artifact"]["path"],
        format!(".socket/vendor/nuget/{UUID}/{ID_LOWER}/{SOCKET_VERSION}")
    );
    assert!(entry["artifact"]["fileInventory"]
        .as_object()
        .is_some_and(|m| m.len() > 3));
    let vendored = tree(&repo);
    let vendored_locks = locks(&repo);

    // ── (1) cold global packages folder ──────────────────────────────────
    let cold = sb.dir("checkout-cold");
    checkout(&repo, &cold);
    let store_cold = sb.dir("store-cold");
    dn.restore_ok(&sb, &cold, &store_cold, true, "locked restore, cold GPF");
    assert_eq!(
        diff_trees(&vendored_locks, &locks(&cold)),
        Vec::<String>::new(),
        "{shape:?}: the locked restore accepted every spliced lock unchanged"
    );
    dn.build_ok(&sb, &cold, &store_cold, "build, cold GPF");
    assert_output_dll(&cold, shape.patched_outputs(), &tfm, &patched, "cold GPF");
    if shape == Shape::Sln {
        assert!(
            !cold
                .join(format!("src/Other/bin/Debug/{tfm}/Newtonsoft.Json.dll"))
                .exists(),
            "Other never used the id"
        );
    }

    // ── (2) warm global packages folder (upstream 13.0.1 cached) ─────────
    assert!(upstream_dir.join(FILE_KEY).is_file());
    let warm = sb.dir("checkout-warm");
    checkout(&repo, &warm);
    dn.restore_ok(&sb, &warm, &store_fx, true, "locked restore, warm GPF");
    assert_eq!(
        diff_trees(&vendored_locks, &locks(&warm)),
        Vec::<String>::new(),
        "{shape:?}: warm locked restore left the locks alone"
    );
    dn.build_ok(&sb, &warm, &store_fx, "build, warm GPF");
    assert_output_dll(&warm, shape.patched_outputs(), &tfm, &patched, "warm GPF");
    assert_eq!(
        std::fs::read(upstream_dir.join(FILE_KEY)).unwrap(),
        pristine,
        "the cached upstream package is untouched"
    );

    // ── (3) a tampered seed file fails restore; git-style restore heals ──
    let seed_file = cold.join(format!(
        ".socket/vendor/nuget/{UUID}/{ID_LOWER}/{SOCKET_VERSION}/{FILE_KEY}"
    ));
    let committed = std::fs::read(&seed_file).unwrap();
    let mut tampered = committed.clone();
    tampered.extend_from_slice(b"TAMPER");
    std::fs::write(&seed_file, &tampered).unwrap();
    let out = dn.restore(&sb, &cold, &store_cold, true);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success() && text.contains("SOCKETPATCH002"),
        "{shape:?}: a tampered seed must fail restore with SOCKETPATCH002\n{text}"
    );
    std::fs::write(&seed_file, &committed).unwrap();
    dn.restore_ok(&sb, &cold, &store_cold, true, "restore after git checkout");

    // ── (3b) a checkout without .socket/vendor/nuget fails closed ────────
    let sparse = sb.dir("checkout-sparse");
    checkout(&repo, &sparse);
    std::fs::remove_dir_all(sparse.join(".socket/vendor/nuget")).unwrap();
    for locked in [true, false] {
        let out = dn.restore(&sb, &sparse, &sb.dir("store-sparse"), locked);
        let text = dotnet_text(&out);
        assert!(
            !out.status.success() && text.contains("SOCKETPATCH007"),
            "{shape:?}: restore (locked={locked}) without the vendored tree must fail \
             SOCKETPATCH007\n{text}"
        );
    }

    // ── (4) re-running vendor is a no-op (the ledger alone opts in) ──────
    let (code, env, stderr) = scan_vendored_layout(&repo, &store_fx, &backend, false);
    assert_eq!(code, Some(0), "{shape:?} re-scan: {env:#}\n{stderr}");
    let rerun = tree(&repo);
    let changed: Vec<String> = diff_trees(&vendored, &rerun)
        .into_iter()
        .filter(|d| !d.ends_with(".socket/vendor/state.json"))
        .collect();
    assert_eq!(
        changed,
        Vec::<String>::new(),
        "{shape:?}: re-vendor rewrote files"
    );

    // ── (5) revert: byte-identical tree, upstream restores again ─────────
    let (code, env, stderr) =
        socket_patch_layout(&repo, &store_fx, &["vendor", "--revert", "--json"], false);
    assert_eq!(
        code,
        Some(0),
        "{shape:?} vendor --revert: {env:#}\n{stderr}"
    );
    let reverted = tree(&repo);
    let outside_socket = |t: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, Vec<u8>> {
        t.iter()
            .filter(|(k, _)| !k.starts_with(".socket/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    assert_eq!(
        diff_trees(&outside_socket(&pre_vendor), &outside_socket(&reverted)),
        Vec::<String>::new(),
        "{shape:?}: revert restores the project byte for byte"
    );
    let leftovers: Vec<&String> = reverted
        .keys()
        .filter(|k| k.starts_with(".socket/vendor/"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "{shape:?}: revert left vendor residue: {leftovers:?}"
    );
    let upstream = sb.dir("checkout-reverted");
    checkout(&repo, &upstream);
    let store_up = sb.dir("store-reverted");
    dn.restore_ok(
        &sb,
        &upstream,
        &store_up,
        true,
        "locked restore after revert",
    );
    dn.build_ok(&sb, &upstream, &store_up, "build after revert");
    assert_output_dll(
        &upstream,
        shape.patched_outputs(),
        &tfm,
        &pristine,
        "after revert",
    );
}

/// A second patch uuid for the package: `13.0.1.(2^30 + (0x7b2c0d11 >> 2))`.
const UUID2: &str = "7b2c0d11-2222-4333-8444-555566667777";
const SOCKET_VERSION2: &str = "13.0.1.1590362948";

/// The patch-update flow: vendor uuid 1, then a newer patch (uuid 2) of the
/// same package. The locks, targets and seeds move to uuid 2 in one run
/// (uuid 1 swept), a locked restore of a fresh checkout builds the new
/// bytes, and the revert still restores the pre-vendor tree byte for byte.
#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored"]
fn sln_patch_update() {
    let sb = Sandbox::new();
    let Some(dn) = Dotnet::probe(&sb) else {
        return;
    };
    let tfm = format!("net{}.0", dn.major);
    let repo = sb.dir("repo");
    let store_fx = sb.dir("store-fixture");
    make_repo(&dn, &sb, Shape::Sln, &repo, &store_fx);
    dn.restore_ok(&sb, &repo, &store_fx, false, "fixture restore");
    let pre_vendor = tree(&repo);
    let upstream_dir = store_fx.join(ID_LOWER).join(VERSION);
    let pristine = std::fs::read(upstream_dir.join(FILE_KEY)).unwrap();
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let backend = Backend::start(&pristine, &patched);
    let (code, env, stderr) = scan_vendored(&repo, &store_fx, &backend);
    assert_eq!(code, Some(0), "first vendor: {env:#}\n{stderr}");
    drop(backend);

    let mut patched2 = pristine.clone();
    patched2.extend_from_slice(b"SOCKETPATCHED2");
    let backend2 = Backend::start_with(UUID2, &pristine, &patched2);
    let (code, env, stderr) = scan_vendored_layout(&repo, &store_fx, &backend2, false);
    assert_eq!(code, Some(0), "patch update: {env:#}\n{stderr}");
    let text = env.to_string();
    assert!(
        !text.contains("vendor_nuget_no_lockfile"),
        "the spliced locks are recognised: {env:#}"
    );
    for p in ["Lib", "App"] {
        let lock =
            std::fs::read_to_string(repo.join(format!("src/{p}/packages.lock.json"))).unwrap();
        assert!(
            lock.contains(SOCKET_VERSION2) && !lock.contains(SOCKET_VERSION),
            "{p}: {lock}"
        );
    }
    let targets =
        std::fs::read_to_string(repo.join(".socket/vendor/nuget/socket-patch.targets")).unwrap();
    assert!(
        targets.contains(UUID2) && !targets.contains(UUID),
        "{targets}"
    );
    assert!(!repo.join(format!(".socket/vendor/nuget/{UUID}")).exists());

    let cold = sb.dir("checkout-cold");
    checkout(&repo, &cold);
    let store_cold = sb.dir("store-cold");
    let before = locks(&cold);
    dn.restore_ok(&sb, &cold, &store_cold, true, "locked restore after update");
    assert_eq!(diff_trees(&before, &locks(&cold)), Vec::<String>::new());
    dn.build_ok(&sb, &cold, &store_cold, "build after update");
    assert_output_dll(&cold, &["App"], &tfm, &patched2, "after update");

    let (code, env, stderr) =
        socket_patch_layout(&repo, &store_fx, &["vendor", "--revert", "--json"], false);
    assert_eq!(code, Some(0), "revert: {env:#}\n{stderr}");
    let reverted = tree(&repo);
    let outside = |t: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, Vec<u8>> {
        t.iter()
            .filter(|(k, _)| !k.starts_with(".socket/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    assert_eq!(
        diff_trees(&outside(&pre_vendor), &outside(&reverted)),
        Vec::<String>::new(),
        "revert after a patch update restores the project byte for byte: {env:#}"
    );
    assert!(reverted.keys().all(|k| !k.starts_with(".socket/vendor/")));
}

#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored"]
fn sln_locked() {
    run_leg(Shape::Sln);
}

#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored"]
fn cpm_locked() {
    run_leg(Shape::Cpm);
}

#[test]
#[ignore = "real .NET SDK + nuget.org: run with --ignored"]
fn cpm_pinning() {
    run_leg(Shape::CpmPinning);
}
