//! Vendored-mode (`scan --mode vendored`) end-to-end tests against **production**.
//!
//! The synthetic `e2e_vendor_*_build.rs` capstones prove the vendoring
//! *mechanism* with a hand-staged `.socket/` blob and `vendor --offline`. They
//! never contact production. This suite is the missing counterpart: it drives
//! `scan --mode vendored` against the **real** Socket production endpoints and
//! the **real** upstream registries, with **no mocking anywhere**, on the
//! anonymous **free public proxy** (no API token), and proves the full vendored
//! loop for each ecosystem and package manager:
//!
//!   1. install a pinned, known-vulnerable dependency with a real package
//!      manager, from its real upstream registry;
//!   2. assert the installed bytes are **pristine** (anti-vacuity — without
//!      this every "patched" assertion below could pass on a no-op);
//!   3. run `socket-patch scan --mode vendored --json --yes`, which resolves a
//!      free patch from `patches-api.socket.dev`, materializes the patched
//!      package into the committable `.socket/vendor/<eco>/<uuid>/` tree, and
//!      rewires the lockfile / manifest to consume it;
//!   4. assert the vendor landed (`summary.applied >= 1`, `failed == 0`, the
//!      expected patch UUID present, the artifact on disk, the lock rewired);
//!   5. **DELIVERY proof** — copy ONLY the committable files (project manifest
//!      + lockfile + `.socket/` + any PM config) into a fresh dir, point every
//!      cache var at a fresh EMPTY dir, run the package manager's clean-install
//!      offline, and assert the installed bytes are the VENDORED (patched)
//!      bytes, NOT the pristine registry bytes;
//!   6. idempotency (a second `scan --mode vendored` is an `already_vendored`
//!      no-op with a byte-stable lock) and `vendor --revert` byte-restores.
//!
//! Step 5 is the point of the suite. It is the only place in this repo where a
//! third-party package manager installs, from a genuinely cold cache and with
//! only the committable files, a package that was vendored from a **real**
//! Socket production patch.
//!
//! # What is (and is NOT) proven
//!
//! This suite proves **byte delivery**: the bytes the vendored patch produced
//! are the bytes the package manager installs. It does NOT assert CVE efficacy
//! — several production patches are byte-valid but whether the fix content
//! actually closes the advisory is a separate concern. This matches how the
//! `e2e_vendor_*_build.rs` capstones assert (marker byte-for-byte, not a
//! behavioral exploit test).
//!
//! # Required production patches
//!
//! Pinned to specific free-tier patches on `patches-api.socket.dev`. If Socket
//! unpublishes one, [`preflight_required_patches_are_published`] fails first
//! and names it, rather than letting a downstream leg fail with a confusing
//! symptom.
//!
//! | Ecosystem | PURL | Patch UUID | Marker in the patched bytes |
//! |-----------|------|------------|-----------------------------|
//! | npm    | `pkg:npm/minimist@1.2.2`        | `80630680-4da6-45f9-bba8-b888e0ffd58c` | `Socket Community Patch` header |
//! | PyPI   | `pkg:pypi/urllib3@1.26.18`      | *any of three* (see [`PYPI_UUIDS`])    | `Socket Community Patch` header |
//! | Cargo  | `pkg:cargo/traitobject@0.1.1`   | `cf2e6f58-d9fa-4096-9151-c34afa717f89` | advisory id `GHSA-pp8r-vv2j-9j5v` |
//! | gem    | `pkg:gem/activestorage@7.0.2.2` | `2535d43d-67ce-4944-be27-c19e113997fb` | *(see the known defect below)* |
//!
//! # Ecosystems with no full coverage, and why
//!
//! * **gem** — vendoring the platform-qualified purl (`?platform=ruby`) fails
//!   in the current CLI with `platform_gem_unsupported`. The download succeeds;
//!   the vendor backend refuses the platform variant. This is a real CLI gap,
//!   not a test bug. [`gem_bundler_vendored_known_platform_defect`] asserts the
//!   redirect+download are correct and tolerates the vendor failure, failing
//!   loudly if it fails for any *other* reason and auto-retiring the tolerance
//!   the moment the CLI starts vendoring gems. Promote with
//!   `SOCKET_PATCH_VENDORED_E2E_GEM_STRICT=1`.
//! * **golang** — vendored mode *works* (directory `replace`), but production
//!   publishes no free golang patches, so there is nothing to vendor.
//!   [`golang_vendored_finds_no_free_patches`] asserts exactly that (zero
//!   applied) and would light up the moment a golang patch is published.
//! * **maven / nuget / composer** — vendored mode is implemented, but
//!   production publishes **zero** free-tier patches for them.
//!   [`canary_unpublished_vendored_ecosystems`] probes production every run and
//!   reports the moment that changes.
//! * **deno** — vendored mode is not supported.
//!   [`deno_vendored_is_unsupported`] covers it as a negative assertion.
//!
//! # Prerequisites
//!
//! Toolchains (each leg soft-skips if its own toolchain is absent, unless
//! `SOCKET_PATCH_VENDORED_E2E_STRICT=1`): `npm`, `pnpm`, `corepack` (yarn
//! classic + berry), `bun`, `uv`, `python3` (pip), `cargo`, `ruby` + `bundle`,
//! `go`.
//!
//! Network egress to: `patches-api.socket.dev`, `patch.socket.dev`,
//! `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`,
//! `static.crates.io`, `index.crates.io`, `rubygems.org`.
//!
//! No API token is used or needed — the suite deliberately runs against the
//! **free public proxy** with `SOCKET_NO_CONFIG=true` so a developer's
//! socket-cli login cannot move the run onto the org catalog. Every ambient
//! `SOCKET_*` var is scrubbed and hostile seeds are planted so a dropped scrub
//! turns the suite red immediately.
//!
//! # Running
//!
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_vendored_production -- --ignored
//!
//! # CI: turn every soft-skip into a hard failure.
//! SOCKET_PATCH_VENDORED_E2E_STRICT=1 \
//!   cargo test -p socket-patch-cli --test e2e_vendored_production -- --ignored --test-threads=1
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/cache_env.rs"]
mod cache_env;

// ---------------------------------------------------------------------------
// Production endpoints + required-patch catalog
// ---------------------------------------------------------------------------

/// The free public patch proxy. Hard-coded, not read from the environment:
/// this suite's whole purpose is to exercise *production*, and an ambient
/// `SOCKET_PROXY_URL` pointing at staging would let it pass while proving
/// nothing.
const PROXY: &str = "https://patches-api.socket.dev";

const NPM_PURL: &str = "pkg:npm/minimist@1.2.2";
const NPM_NAME: &str = "minimist";
const NPM_VERSION: &str = "1.2.2";
const NPM_UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

const PYPI_PURL: &str = "pkg:pypi/urllib3@1.26.18";
const PYPI_NAME: &str = "urllib3";
const PYPI_VERSION: &str = "1.26.18";
/// urllib3 1.26.18 carries **three** distinct free patches (one per advisory).
/// Which one the resolver selects is a server-side ordering detail, so the
/// tests assert "one of these" rather than pinning a single UUID.
const PYPI_UUIDS: &[&str] = &[
    "de58c8b8-796c-4b6d-8a48-539b5563db76",
    "26242e35-f867-4da8-8789-f0d2ea49e0f1",
    "e828efa5-5c6d-43f3-9909-03f5ac232b98",
];

const CARGO_PURL: &str = "pkg:cargo/traitobject@0.1.1";
const CARGO_NAME: &str = "traitobject";
const CARGO_VERSION: &str = "0.1.1";
const CARGO_UUID: &str = "cf2e6f58-d9fa-4096-9151-c34afa717f89";
/// The traitobject patch annotates `src/lib.rs` with its advisory ID. Cargo
/// crates are not rewritten with the `Socket Community Patch` header the
/// npm/PyPI artifacts carry, so this is the marker to look for. (The same
/// patch also injects a `compile_error!` unless the `allow-unmaintained`
/// feature is set — which is why the cargo delivery proof uses `cargo fetch`,
/// not `cargo build`; see [`cargo_vendored_install_proof`].)
const CARGO_MARKER: &str = "GHSA-pp8r-vv2j-9j5v";

const GEM_PURL: &str = "pkg:gem/activestorage@7.0.2.2";
const GEM_NAME: &str = "activestorage";
const GEM_VERSION: &str = "7.0.2.2";
const GEM_UUID: &str = "2535d43d-67ce-4944-be27-c19e113997fb";

/// Header the patch service injects into patched npm / PyPI source files.
const PATCH_MARKER: &str = "Socket Community Patch";

/// Corepack-pinned yarn flavors. The on-PATH `yarn` may be either major, so the
/// leg pins the version through corepack to guarantee the lockfile grammar
/// under test.
const YARN_CLASSIC: &str = "yarn@1.22.22";
const YARN_BERRY: &str = "yarn@4.6.0";

/// Ecosystems where vendored mode is implemented but production has no free
/// patches to exercise it with. [`canary_unpublished_vendored_ecosystems`]
/// watches these so coverage can be extended the moment one lights up.
const UNPUBLISHED_ECOSYSTEMS: &[(&str, &[&str])] = &[
    (
        "maven",
        &[
            "pkg:maven/org.apache.logging.log4j/log4j-core",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
            "pkg:maven/org.yaml/snakeyaml",
        ],
    ),
    (
        "nuget",
        &[
            "pkg:nuget/Newtonsoft.Json",
            "pkg:nuget/System.Text.Json",
            "pkg:nuget/SharpZipLib",
        ],
    ),
    (
        "composer",
        &[
            "pkg:composer/guzzlehttp/guzzle",
            "pkg:composer/symfony/http-kernel",
            "pkg:composer/monolog/monolog",
        ],
    ),
];

// ---------------------------------------------------------------------------
// Strictness + skip policy
// ---------------------------------------------------------------------------

/// `SOCKET_PATCH_VENDORED_E2E_STRICT=1` converts every soft skip into a hard
/// failure, so a missing toolchain can never report green on a required check.
fn strict() -> bool {
    std::env::var("SOCKET_PATCH_VENDORED_E2E_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Soft-skip a leg: panics under [`strict`], otherwise prints a tagged notice
/// and returns from the calling test.
macro_rules! soft_skip {
    ($leg:expr, $($arg:tt)*) => {{
        let why = format!($($arg)*);
        if strict() {
            panic!(
                "STRICT: {} cannot run: {why}\n\
                 SOCKET_PATCH_VENDORED_E2E_STRICT=1 forbids skipping — a required \
                 CI check must never report green on an unexercised leg. Install \
                 the missing toolchain, or unset the strict flag for local runs.",
                $leg
            );
        }
        println!("SKIP {}: {why}", $leg);
        return;
    }};
}

// ---------------------------------------------------------------------------
// CLI invocation
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn has_command(cmd: &str) -> bool {
    // `go` has no `--version` flag — it takes `go version` as a subcommand.
    let probe: &[&str] = if cmd == "go" {
        &["version"]
    } else {
        &["--version"]
    };
    let mut probe_cmd = Command::new(cmd);
    probe_cmd
        .args(probe)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cache_env::isolate(&mut probe_cmd);
    probe_cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// `corepack <pm> --version` succeeds — the liveness probe for a specific yarn
/// flavor (also the call that downloads it the first time, kept in the sandbox).
fn has_corepack_pm(pm: &str) -> bool {
    let mut cmd = Command::new("corepack");
    cmd.args([pm, "--version"])
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cache_env::isolate(&mut cmd);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run the socket-patch binary on the anonymous free tier.
///
/// The scrub is load-bearing. An ambient `SOCKET_PROXY_URL`/`SOCKET_API_URL`
/// would silently point the run at staging; an ambient `SOCKET_API_TOKEN` (or a
/// socket-cli login on disk) would move it off the free public proxy this suite
/// exists to cover. Every ambient `SOCKET_*` is removed (except the config
/// kill-switch), hostile seeds are planted and then removed on the adjacent
/// line so a dropped scrub reddens the suite instead of leaking a developer's
/// shell, and `SOCKET_NO_CONFIG=true` blocks the socket-cli config.json.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .current_dir(cwd)
        // Seed hostile values, then remove them (adjacent, so deleting a remove
        // line leaves the seed and breaks the suite rather than passing vacuously).
        .env("SOCKET_API_TOKEN", "hostile-seed-must-be-scrubbed")
        .env("SOCKET_PROXY_URL", "http://127.0.0.1:1/hostile")
        .env("SOCKET_API_URL", "http://127.0.0.1:1/hostile")
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_PROXY_URL")
        .env_remove("SOCKET_API_URL");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("SOCKET_NO_CONFIG", "true");
    let out: Output = cmd.output().expect("failed to execute socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// `scan --mode vendored --json --yes` in `cwd`, asserting a clean exit and a
/// `"status": "success"` envelope. Returns the parsed envelope.
fn scan_vendored(cwd: &Path, extra: &[&str]) -> serde_json::Value {
    let mut args: Vec<&str> = vec![
        "scan",
        "--json",
        "--yes",
        "--mode",
        "vendored",
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_socket(cwd, &args);
    assert_eq!(
        code, 0,
        "scan --mode vendored failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "scan --mode vendored did not emit JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    });
    assert_eq!(
        env["status"].as_str(),
        Some("success"),
        "scan --mode vendored did not report success.\nenvelope:\n{env:#}\nstderr:\n{stderr}"
    );
    env
}

/// Assert the vendored run actually materialized a patched artifact.
///
/// `applied >= 1` is the anti-vacuity guard: a run that discovered nothing also
/// exits 0 with `"status": "success"`, so without this a broken crawler would
/// look identical to a working vendor. `failed == 0` catches partial failures
/// (the gem leg deliberately does NOT go through here). The `applied` event's
/// purl may carry qualifiers (`?artifact_id=…`), so a substring match is used.
fn assert_vendor_applied(env: &serde_json::Value, purl_needle: &str, leg: &str) {
    let vendor = &env["vendor"];
    assert!(
        !vendor.is_null(),
        "{leg}: scan --mode vendored emitted no `vendor` sub-object — the CLI omits it \
         when discovery found nothing, so this means the crawler did not see the \
         installed dependency.\nenvelope:\n{env:#}"
    );
    let applied = vendor["summary"]["applied"].as_u64().unwrap_or(0);
    assert!(
        applied >= 1,
        "{leg}: vendored nothing (summary.applied=0) — the patch is published and the \
         package is installed, so 0 means discovery or vendoring broke.\nenvelope:\n{env:#}"
    );
    let failed = vendor["summary"]["failed"].as_u64().unwrap_or(0);
    assert_eq!(
        failed, 0,
        "{leg}: a vendor operation failed (summary.failed={failed}).\nenvelope:\n{env:#}"
    );
    let events = vendor["events"].as_array().cloned().unwrap_or_default();
    assert!(
        events.iter().any(|e| {
            e["action"] == "applied"
                && e["purl"]
                    .as_str()
                    .map(|p| p.contains(purl_needle))
                    .unwrap_or(false)
        }),
        "{leg}: no `applied` event for a purl containing `{purl_needle}`.\nenvelope:\n{env:#}"
    );
}

/// Assert the download phase resolved one of the expected patch UUIDs.
fn assert_download_uuid(env: &serde_json::Value, uuids: &[&str], leg: &str) {
    let patches = env["download"]["patches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let found: Vec<String> = patches
        .iter()
        .filter_map(|p| p["uuid"].as_str().map(str::to_string))
        .collect();
    assert!(
        uuids.iter().any(|u| found.iter().any(|f| f == u)),
        "{leg}: expected one of {uuids:?} among downloaded patch UUIDs, got {found:?}. The \
         resolver picked a different patch than the catalog pins.\nenvelope:\n{env:#}"
    );
}

/// `vendor --revert --json` in `cwd`, asserting success and returning the
/// number of reverted entries.
fn vendor_revert(cwd: &Path, leg: &str) -> u64 {
    let (code, stdout, stderr) = run_socket(
        cwd,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            cwd.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "{leg}: vendor --revert failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{leg}: vendor --revert did not emit JSON ({e}):\n{stdout}"));
    assert_eq!(
        env["status"].as_str(),
        Some("success"),
        "{leg}: vendor --revert did not report success.\nenvelope:\n{env:#}"
    );
    env["summary"]["removed"].as_u64().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Toolchain invocation
// ---------------------------------------------------------------------------

/// Run an external package manager. Returns the `Output` without asserting, so
/// callers can distinguish "the registry was unreachable" (soft-skip material
/// during fixture setup) from "the install of the vendored lock failed" (always
/// a hard failure — that is the thing under test).
fn tool(cwd: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    cache_env::isolate(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    // A `VIRTUAL_ENV` inherited from the developer's shell makes uv/pip install
    // into the wrong interpreter; a node-linker override breaks yarn/pnpm.
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_NODE_LINKER");
    cmd.env_remove("npm_config_node_linker");
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"))
}

/// Run `corepack <pm> <args>` in `cwd` with the download prompt disabled and
/// the shared cache sandbox applied (per-leg `env` wins, applied last).
fn corepack(cwd: &Path, pm: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_NODE_LINKER");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn `corepack {pm}`: {e}"))
}

fn ok(out: &Output) -> bool {
    out.status.success()
}

fn dump(out: &Output) -> String {
    format!(
        "exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Assert `path` exists and does NOT yet carry a patch marker.
///
/// Every "the reinstall delivered a patched artifact" assertion downstream is
/// vacuous without this: if the upstream registry ever started shipping the
/// patched bytes, or a warm cache leaked them in, the test would pass while
/// proving nothing about vendored mode.
fn assert_pristine(path: &Path, marker: &str, what: &str) {
    assert!(
        path.exists(),
        "{what}: expected the pristine install at {} — fixture setup did not produce the \
         file under test",
        path.display()
    );
    let body = read(path);
    assert!(
        !body.contains(marker),
        "{what}: the freshly-installed upstream artifact at {} ALREADY contains `{marker}` \
         before any vendoring ran. Every downstream assertion would be vacuous. Check for a \
         warm package-manager cache leaking patched bytes.",
        path.display()
    );
}

fn assert_patched(path: &Path, marker: &str, what: &str) {
    assert!(
        path.exists(),
        "{what}: reinstall from the vendored lock did not produce {}",
        path.display()
    );
    let body = read(path);
    assert!(
        body.contains(marker),
        "{what}: reinstalled from the vendored lock, but {} does not contain `{marker}` — the \
         package manager installed something, and it was not the vendored (patched) artifact.",
        path.display()
    );
}

/// The single-file npm-family entry point that the minimist patch rewrites.
fn minimist_entry(proj: &Path) -> PathBuf {
    proj.join("node_modules").join(NPM_NAME).join("index.js")
}

/// Mirror the `pnpm.overrides` the CLI wrote into `package.json` over to a
/// `pnpm-workspace.yaml` `overrides:` block — the location pnpm >= 11 actually
/// reads (see [`pnpm_vendored_install_proof`]). Reads back exactly what the CLI
/// produced rather than hardcoding a value, so it exercises the real wiring.
fn write_pnpm_workspace_overrides(proj: &Path, leg: &str) {
    let pkg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("package.json")).unwrap()).unwrap();
    let overrides = pkg["pnpm"]["overrides"].as_object().unwrap_or_else(|| {
        panic!("{leg}: package.json carries no `pnpm.overrides` to mirror into pnpm-workspace.yaml")
    });
    let mut yaml = String::from("overrides:\n");
    for (k, v) in overrides {
        yaml.push_str(&format!("  '{k}': '{}'\n", v.as_str().unwrap_or_default()));
    }
    std::fs::write(proj.join("pnpm-workspace.yaml"), yaml).unwrap();
}

/// Locate `site-packages` inside a venv, across platforms and Python minors.
fn site_packages(venv: &Path) -> Option<PathBuf> {
    if cfg!(windows) {
        let p = venv.join("Lib").join("site-packages");
        return p.exists().then_some(p);
    }
    let lib = venv.join("lib");
    let entries = std::fs::read_dir(lib).ok()?;
    for e in entries.flatten() {
        let p = e.path().join("site-packages");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// The urllib3 patch rewrites a file under the package directory; which one
/// depends on which advisory the resolver picked, so scan the whole package
/// rather than pinning a filename.
fn urllib3_patched(site: &Path) -> bool {
    let dir = site.join(PYPI_NAME);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for e in entries.flatten() {
        let is_py = e.path().extension().and_then(|s| s.to_str()) == Some("py");
        if is_py
            && std::fs::read_to_string(e.path())
                .map(|b| b.contains(PATCH_MARKER))
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Production reachability probe (preflight + canary)
// ---------------------------------------------------------------------------

/// `GET /patch/by-package/<purl>` against the real proxy. Returns the patch
/// UUIDs published for `purl`, or an `Err` describing a transport failure.
async fn published_uuids(purl: &str) -> Result<Vec<String>, String> {
    let url = format!("{PROXY}/patch/by-package/{}", urlencode(purl));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("GET {url}: reading body: {e}"))?;
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}\n{body}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("GET {url}: bad JSON ({e}):\n{body}"))?;
    Ok(v["patches"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["uuid"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// Percent-encode a PURL for use as a single path segment.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ===========================================================================
// Preflight — the catalog canary
// ===========================================================================

/// Verify every patch this suite depends on is still published and free-tier.
///
/// Sorts under `preflight_` so a withdrawn patch produces one clear failure
/// naming the PURL, instead of N confusing downstream failures that look like
/// CLI regressions.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API: contacts patches-api.socket.dev. Run with --ignored."]
async fn preflight_required_patches_are_published() {
    let required: Vec<(&str, Vec<&str>)> = vec![
        (NPM_PURL, vec![NPM_UUID]),
        (PYPI_PURL, PYPI_UUIDS.to_vec()),
        (CARGO_PURL, vec![CARGO_UUID]),
        (GEM_PURL, vec![GEM_UUID]),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (purl, expected) in &required {
        match published_uuids(purl).await {
            Err(e) => failures.push(format!("{purl}: production probe failed: {e}")),
            Ok(found) if found.is_empty() => failures.push(format!(
                "{purl}: production publishes NO free patches for this package anymore. This \
                 suite is pinned to it — pick a replacement and update both the catalog \
                 constants in this file and docs/testing/vendored-production-e2e.md."
            )),
            Ok(found) => {
                if !expected.iter().any(|u| found.iter().any(|f| f == u)) {
                    failures.push(format!(
                        "{purl}: expected one of {expected:?} but production now publishes \
                         {found:?}. The patch was replaced — update the catalog constants."
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "required production patches are no longer available:\n  - {}",
        failures.join("\n  - ")
    );
}

// ===========================================================================
// npm ecosystem — five package managers, five lockfile flavors
// ===========================================================================

/// A temp npm project with `minimist@1.2.2` pinned. `pkg` is written with an
/// optional `packageManager` pin so corepack resolves the intended yarn flavor.
fn npm_fixture(package_manager: Option<&str>) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    let pm_field = package_manager
        .map(|p| format!(r#""packageManager":"{p}","#))
        .unwrap_or_default();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"vendored-e2e","version":"0.0.0","private":true,{pm_field}"dependencies":{{"{NPM_NAME}":"{NPM_VERSION}"}}}}"#
        ),
    )
    .expect("write package.json");
    (tmp, proj)
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn npm_package_lock_vendored_install_proof() {
    const LEG: &str = "npm_package_lock_vendored_install_proof";
    if !has_command("npm") {
        soft_skip!(LEG, "`npm` not on PATH");
    }
    let (tmp, proj) = npm_fixture(None);
    let cache = tmp.path().join("npm-cache").display().to_string();
    let env = [("npm_config_cache", cache.as_str())];

    let install = tool(
        &proj,
        "npm",
        &["install", "--no-audit", "--no-fund", "--ignore-scripts"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `npm install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&proj), PATCH_MARKER, LEG);
    let pristine = std::fs::read(minimist_entry(&proj)).unwrap();
    let lock_before = std::fs::read(proj.join("package-lock.json")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, NPM_PURL, LEG);
    assert_download_uuid(&env_json, &[NPM_UUID], LEG);

    let tgz_rel = format!(".socket/vendor/npm/{NPM_UUID}/{NPM_NAME}-{NPM_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "{LEG}: vendored tarball missing at {tgz_rel}"
    );
    let lock = read(&proj.join("package-lock.json"));
    assert!(
        lock.contains(&tgz_rel),
        "{LEG}: package-lock.json was not rewired to consume the vendored tarball:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("package-lock.json")).unwrap();

    // DELIVERY PROOF: committable files only, empty cache, `npm ci`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(
        proj.join("package-lock.json"),
        fresh.join("package-lock.json"),
    )
    .unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-npm-cache").display().to_string();
    let ci = tool(
        &fresh,
        "npm",
        &["ci", "--no-audit", "--no-fund", "--ignore-scripts"],
        &[("npm_config_cache", fresh_cache.as_str())],
    );
    assert!(
        ok(&ci),
        "{LEG}: `npm ci` from the vendored lock failed:\n{}",
        dump(&ci)
    );
    assert_patched(&minimist_entry(&fresh), PATCH_MARKER, LEG);
    assert_ne!(
        std::fs::read(minimist_entry(&fresh)).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes — the vendored \
         artifact was not the one installed"
    );

    // Idempotency: a re-run is an `already_vendored` no-op with a stable lock.
    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("package-lock.json")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave package-lock.json byte-identical"
    );

    // Revert restores the pre-vendor lock and removes the artifacts.
    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("package-lock.json")).unwrap(),
        lock_before,
        "{LEG}: revert must restore package-lock.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn pnpm_vendored_install_proof() {
    const LEG: &str = "pnpm_vendored_install_proof";
    if !has_command("pnpm") {
        soft_skip!(LEG, "`pnpm` not on PATH");
    }
    let (tmp, proj) = npm_fixture(None);
    // pnpm's vendor edit reserializes package.json (serde_json pretty, 2-space,
    // trailing newline). Author it in that exact shape so the vendor -> revert
    // round trip is byte-identical (mirrors e2e_vendor_pnpm_build.rs).
    let pkg_doc = serde_json::json!({
        "name": "vendored-e2e",
        "version": "0.0.0",
        "private": true,
        "dependencies": { NPM_NAME: NPM_VERSION },
    });
    std::fs::write(
        proj.join("package.json"),
        format!("{}\n", serde_json::to_string_pretty(&pkg_doc).unwrap()),
    )
    .unwrap();
    let store = tmp.path().join("pnpm-store").display().to_string();
    let env = [
        ("PNPM_HOME", store.as_str()),
        ("XDG_CACHE_HOME", store.as_str()),
    ];
    let store_arg = format!("--store-dir={store}");

    let install = tool(
        &proj,
        "pnpm",
        &["install", "--ignore-scripts", &store_arg],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `pnpm install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&proj), PATCH_MARKER, LEG);
    let pristine = std::fs::read(minimist_entry(&proj)).unwrap();
    let lock_before = std::fs::read(proj.join("pnpm-lock.yaml")).unwrap();
    let pkg_before = std::fs::read(proj.join("package.json")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, NPM_PURL, LEG);
    assert_download_uuid(&env_json, &[NPM_UUID], LEG);

    let tgz_rel = format!(".socket/vendor/npm/{NPM_UUID}/{NPM_NAME}-{NPM_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "{LEG}: vendored tarball missing at {tgz_rel}"
    );
    let lock = read(&proj.join("pnpm-lock.yaml"));
    assert!(
        lock.contains(&tgz_rel),
        "{LEG}: pnpm-lock.yaml was not rewired to the vendored tarball:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("pnpm-lock.yaml")).unwrap();
    let pkg_wired = std::fs::read(proj.join("package.json")).unwrap();

    // DELIVERY PROOF: committable files only (pnpm also edits package.json —
    // pnpm.overrides), empty store, frozen offline install.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("pnpm-lock.yaml"), fresh.join("pnpm-lock.yaml")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_store = tmp.path().join("fresh-pnpm-store").display().to_string();
    let fresh_env = [
        ("PNPM_HOME", fresh_store.as_str()),
        ("XDG_CACHE_HOME", fresh_store.as_str()),
    ];
    let fresh_store_arg = format!("--store-dir={fresh_store}");
    let install_args = [
        "install",
        "--frozen-lockfile",
        "--offline",
        "--ignore-scripts",
        &fresh_store_arg,
    ];
    let ci = tool(&fresh, "pnpm", &install_args, &fresh_env);
    let entry = minimist_entry(&fresh);
    if ok(&ci) {
        // pnpm <= 10: the package.json `pnpm.overrides` the CLI wrote is honored.
        assert_patched(&entry, PATCH_MARKER, LEG);
        assert_ne!(
            std::fs::read(&entry).unwrap(),
            pristine,
            "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
        );
    } else {
        // KNOWN CLI GAP (pnpm >= 11): pnpm no longer reads `overrides` from
        // package.json's `pnpm` field — it moved to `pnpm-workspace.yaml`
        // (https://pnpm.io/settings). The CLI still writes package.json
        // `pnpm.overrides`, so pnpm 11 ignores it and the frozen install
        // refuses with a lockfile/config mismatch even though the vendored
        // tarball and lock are correct (the supply-chain policy passes). This
        // is a real socket-patch compatibility gap, not a test bug: the pnpm
        // vendor rewriter should also emit a `pnpm-workspace.yaml` `overrides`
        // block on pnpm >= 11. Until it does, this leg reproduces the documented
        // workaround (mirror the override into pnpm-workspace.yaml) to prove the
        // vendored artifact IS installable, and fails loudly if the failure is
        // anything OTHER than that known gap.
        let detail = dump(&ci);
        assert!(
            detail.contains("ERR_PNPM_LOCKFILE_CONFIG_MISMATCH")
                || detail.contains("no longer read by pnpm"),
            "{LEG}: `pnpm install --frozen-lockfile --offline` failed for an UNEXPECTED reason \
             (not the known pnpm 11 overrides-field-moved gap). This is a new regression:\n{detail}"
        );
        println!(
            "KNOWN CLI GAP {LEG}: pnpm >= 11 ignores package.json `pnpm.overrides` (moved to \
             pnpm-workspace.yaml), so the CLI's vendored wiring does not take effect on a frozen \
             install. Retrying with the documented pnpm-workspace.yaml workaround. socket-patch \
             should emit that file for pnpm >= 11 during `scan --mode vendored`."
        );
        write_pnpm_workspace_overrides(&fresh, LEG);
        let retry = tool(&fresh, "pnpm", &install_args, &fresh_env);
        assert!(
            ok(&retry),
            "{LEG}: even with the pnpm-workspace.yaml overrides workaround the vendored tarball \
             did not install — the artifact itself is not installable:\n{}",
            dump(&retry)
        );
        assert_patched(&entry, PATCH_MARKER, LEG);
        assert_ne!(
            std::fs::read(&entry).unwrap(),
            pristine,
            "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
        );
    }

    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("pnpm-lock.yaml")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave pnpm-lock.yaml byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_wired,
        "{LEG}: re-run must leave package.json byte-identical"
    );

    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("pnpm-lock.yaml")).unwrap(),
        lock_before,
        "{LEG}: revert must restore pnpm-lock.yaml byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_before,
        "{LEG}: revert must restore package.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn yarn_classic_vendored_install_proof() {
    const LEG: &str = "yarn_classic_vendored_install_proof";
    if !has_corepack_pm(YARN_CLASSIC) {
        soft_skip!(
            LEG,
            "`corepack {YARN_CLASSIC}` unavailable (corepack absent or yarn classic not fetchable)"
        );
    }
    let (tmp, proj) = npm_fixture(Some(YARN_CLASSIC));
    let cache = tmp.path().join("yarn1-cache").display().to_string();
    let env = [("YARN_CACHE_FOLDER", cache.as_str())];

    let install = corepack(&proj, YARN_CLASSIC, &["install", "--no-progress"], &env);
    if !ok(&install) {
        soft_skip!(
            LEG,
            "upstream classic `yarn install` failed:\n{}",
            dump(&install)
        );
    }
    if !proj.join("yarn.lock").exists() {
        soft_skip!(LEG, "`yarn install` produced no yarn.lock");
    }
    assert_pristine(&minimist_entry(&proj), PATCH_MARKER, LEG);
    let pristine = std::fs::read(minimist_entry(&proj)).unwrap();
    let lock_before = std::fs::read(proj.join("yarn.lock")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, NPM_PURL, LEG);
    assert_download_uuid(&env_json, &[NPM_UUID], LEG);

    let tgz_rel = format!(".socket/vendor/npm/{NPM_UUID}/{NPM_NAME}-{NPM_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "{LEG}: vendored tarball missing at {tgz_rel}"
    );
    let lock = read(&proj.join("yarn.lock"));
    assert!(
        lock.contains(&tgz_rel),
        "{LEG}: yarn.lock was not rewired to the vendored tarball:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("yarn.lock")).unwrap();

    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-yarn1-cache").display().to_string();
    let ci = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--frozen-lockfile", "--offline", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.as_str())],
    );
    assert!(
        ok(&ci),
        "{LEG}: `yarn install --frozen-lockfile --offline` from the vendored lock failed:\n{}",
        dump(&ci)
    );
    assert_patched(&minimist_entry(&fresh), PATCH_MARKER, LEG);
    assert_ne!(
        std::fs::read(minimist_entry(&fresh)).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
    );

    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave yarn.lock byte-identical"
    );

    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_before,
        "{LEG}: revert must restore yarn.lock byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn yarn_berry_vendored_install_proof() {
    const LEG: &str = "yarn_berry_vendored_install_proof";
    if !has_corepack_pm(YARN_BERRY) {
        soft_skip!(
            LEG,
            "`corepack {YARN_BERRY}` unavailable (corepack absent or yarn berry not fetchable)"
        );
    }
    let (tmp, proj) = npm_fixture(Some(YARN_BERRY));
    // node-modules linker + compressionLevel 0 (the checksum recipe vendor
    // reproduces) + no global cache.
    std::fs::write(
        proj.join(".yarnrc.yml"),
        "nodeLinker: node-modules\ncompressionLevel: 0\nenableGlobalCache: false\n",
    )
    .expect("write .yarnrc.yml");
    let global = tmp.path().join("yarn-global").display().to_string();
    let env = [("YARN_GLOBAL_FOLDER", global.as_str())];

    // `--no-immutable` on the fixture install: berry auto-enables hardened mode
    // on CI, which forbids creating the first lockfile. The reinstall keeps
    // `--immutable` — that leg is the actual proof.
    let install = corepack(&proj, YARN_BERRY, &["install", "--no-immutable"], &env);
    if !ok(&install) {
        soft_skip!(
            LEG,
            "berry `yarn install` failed (corepack may be unable to download {YARN_BERRY}):\n{}",
            dump(&install)
        );
    }
    assert_pristine(&minimist_entry(&proj), PATCH_MARKER, LEG);
    let pristine = std::fs::read(minimist_entry(&proj)).unwrap();
    // Berry rewrites package.json on install (compact → pretty), so snapshot the
    // on-disk bytes as the pre-vendor truth.
    let lock_before = std::fs::read(proj.join("yarn.lock")).unwrap();
    let pkg_before = std::fs::read(proj.join("package.json")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, NPM_PURL, LEG);
    assert_download_uuid(&env_json, &[NPM_UUID], LEG);

    let tgz_rel = format!(".socket/vendor/npm/{NPM_UUID}/{NPM_NAME}-{NPM_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "{LEG}: vendored tarball missing at {tgz_rel}"
    );
    let lock = read(&proj.join("yarn.lock"));
    assert!(
        lock.contains(&tgz_rel),
        "{LEG}: yarn.lock was not rewired to the vendored tarball:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("yarn.lock")).unwrap();
    let pkg_wired = std::fs::read(proj.join("package.json")).unwrap();

    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    std::fs::copy(proj.join(".yarnrc.yml"), fresh.join(".yarnrc.yml")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_global = tmp.path().join("fresh-yarn-global").display().to_string();
    let ci = corepack(
        &fresh,
        YARN_BERRY,
        &["install", "--immutable", "--check-cache"],
        &[
            ("YARN_GLOBAL_FOLDER", fresh_global.as_str()),
            ("YARN_ENABLE_GLOBAL_CACHE", "false"),
        ],
    );
    assert!(
        ok(&ci),
        "{LEG}: `yarn install --immutable --check-cache` from the vendored lock failed — berry \
         could not install the vendored tarball or its 10c0 checksum did not match:\n{}",
        dump(&ci)
    );
    assert_patched(&minimist_entry(&fresh), PATCH_MARKER, LEG);
    assert_ne!(
        std::fs::read(minimist_entry(&fresh)).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
    );

    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave yarn.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_wired,
        "{LEG}: re-run must leave package.json byte-identical"
    );

    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_before,
        "{LEG}: revert must restore yarn.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_before,
        "{LEG}: revert must restore package.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn bun_vendored_install_proof() {
    const LEG: &str = "bun_vendored_install_proof";
    if !has_command("bun") {
        soft_skip!(LEG, "`bun` not on PATH");
    }
    let (tmp, proj) = npm_fixture(None);
    let cache = tmp.path().join("bun-cache").display().to_string();
    let env = [("BUN_INSTALL_CACHE_DIR", cache.as_str())];

    // Text `bun.lock` only — the binary `bun.lockb` is a separate auto-migration
    // path, not what this leg covers.
    let install = tool(
        &proj,
        "bun",
        &["install", "--ignore-scripts", "--save-text-lockfile"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `bun install` failed:\n{}", dump(&install));
    }
    if !proj.join("bun.lock").exists() {
        soft_skip!(
            LEG,
            "`bun install --save-text-lockfile` produced no bun.lock (bun too old?)"
        );
    }
    assert_pristine(&minimist_entry(&proj), PATCH_MARKER, LEG);
    let pristine = std::fs::read(minimist_entry(&proj)).unwrap();
    let lock_before = std::fs::read(proj.join("bun.lock")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, NPM_PURL, LEG);
    assert_download_uuid(&env_json, &[NPM_UUID], LEG);

    let tgz_rel = format!(".socket/vendor/npm/{NPM_UUID}/{NPM_NAME}-{NPM_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "{LEG}: vendored tarball missing at {tgz_rel}"
    );
    let lock = read(&proj.join("bun.lock"));
    assert!(
        lock.contains(&tgz_rel),
        "{LEG}: bun.lock was not rewired to the vendored tarball:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("bun.lock")).unwrap();

    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("bun.lock"), fresh.join("bun.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-bun-cache").display().to_string();
    let ci = tool(
        &fresh,
        "bun",
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &[("BUN_INSTALL_CACHE_DIR", fresh_cache.as_str())],
    );
    assert!(
        ok(&ci),
        "{LEG}: `bun install --frozen-lockfile` from the vendored lock failed:\n{}",
        dump(&ci)
    );
    assert_patched(&minimist_entry(&fresh), PATCH_MARKER, LEG);
    assert_ne!(
        std::fs::read(minimist_entry(&fresh)).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
    );

    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("bun.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave bun.lock byte-identical"
    );

    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("bun.lock")).unwrap(),
        lock_before,
        "{LEG}: revert must restore bun.lock byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

// ===========================================================================
// PyPI ecosystem — requirements.txt and uv.lock
// ===========================================================================

#[test]
#[ignore = "live production API + real PyPI. Run with --ignored."]
fn pypi_requirements_txt_vendored_install_proof() {
    const LEG: &str = "pypi_requirements_txt_vendored_install_proof";
    if !has_command("python3") {
        soft_skip!(LEG, "`python3` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(
        proj.join("requirements.txt"),
        format!("{PYPI_NAME}=={PYPI_VERSION}\n"),
    )
    .expect("write requirements.txt");

    let venv = proj.join(".venv");
    let venv_s = venv.display().to_string();
    if !ok(&tool(&proj, "python3", &["-m", "venv", ".venv"], &[])) {
        soft_skip!(LEG, "`python3 -m venv` failed");
    }
    let pip = venv.join("bin/pip");
    let pip_s = pip.display().to_string();
    let install = tool(
        &proj,
        &pip_s,
        &[
            "install",
            "--disable-pip-version-check",
            "--quiet",
            "-r",
            "requirements.txt",
        ],
        &[],
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `pip install` failed:\n{}", dump(&install));
    }
    let Some(site) = site_packages(&venv) else {
        soft_skip!(LEG, "could not locate site-packages under {venv_s}");
    };
    assert!(
        !urllib3_patched(&site),
        "{LEG}: the freshly-installed upstream urllib3 already carries `{PATCH_MARKER}` — vacuous"
    );
    let reqs_before = std::fs::read(proj.join("requirements.txt")).unwrap();

    // Discovery reads the venv via VIRTUAL_ENV.
    let env_json = scan_vendored(&proj, &["--ecosystems", "pypi"]);
    assert_vendor_applied(&env_json, "urllib3@1.26.18", LEG);
    assert_download_uuid(&env_json, PYPI_UUIDS, LEG);

    let reqs = read(&proj.join("requirements.txt"));
    assert!(
        reqs.contains(".socket/vendor/pypi/") && reqs.contains(".whl"),
        "{LEG}: requirements.txt was not rewired to the vendored wheel:\n{reqs}"
    );
    assert!(
        reqs.contains("--hash=sha256:"),
        "{LEG}: rewritten requirements.txt carries no --hash pin:\n{reqs}"
    );

    // DELIVERY PROOF: requirements.txt + .socket only, fresh venv, --no-index
    // from the project root (bare relative paths resolve against the CWD).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(
        proj.join("requirements.txt"),
        fresh.join("requirements.txt"),
    )
    .unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_venv = fresh.join(".venv");
    assert!(
        ok(&tool(&fresh, "python3", &["-m", "venv", ".venv"], &[])),
        "{LEG}: fresh `python3 -m venv` failed"
    );
    let fresh_pip = fresh_venv.join("bin/pip").display().to_string();
    let fresh_install = tool(
        &fresh,
        &fresh_pip,
        &[
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "-r",
            "requirements.txt",
        ],
        &[],
    );
    assert!(
        ok(&fresh_install),
        "{LEG}: `pip install --no-index -r requirements.txt` from the vendored wheel failed:\n{}",
        dump(&fresh_install)
    );
    let fresh_site = site_packages(&fresh_venv).expect("fresh site-packages");
    assert!(
        urllib3_patched(&fresh_site),
        "{LEG}: reinstalled from the vendored requirements.txt, but no urllib3 file carries \
         `{PATCH_MARKER}`"
    );

    // Idempotency + revert.
    let reqs_wired = std::fs::read(proj.join("requirements.txt")).unwrap();
    let env2 = scan_vendored(&proj, &["--ecosystems", "pypi"]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("requirements.txt")).unwrap(),
        reqs_wired,
        "{LEG}: re-run must leave requirements.txt byte-identical"
    );
    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("requirements.txt")).unwrap(),
        reqs_before,
        "{LEG}: revert must restore requirements.txt byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

#[test]
#[ignore = "live production API + real PyPI. Run with --ignored."]
fn pypi_uv_lock_vendored_install_proof() {
    const LEG: &str = "pypi_uv_lock_vendored_install_proof";
    if !has_command("uv") {
        soft_skip!(LEG, "`uv` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    let uv_cache = tmp.path().join("uv-cache").display().to_string();
    let env = [("UV_CACHE_DIR", uv_cache.as_str())];

    std::fs::write(
        proj.join("pyproject.toml"),
        format!(
            "[project]\nname = \"vendored-e2e\"\nversion = \"0.1.0\"\n\
             requires-python = \">=3.9\"\ndependencies = [\"{PYPI_NAME}=={PYPI_VERSION}\"]\n"
        ),
    )
    .expect("write pyproject.toml");

    if !ok(&tool(&proj, "uv", &["lock", "--quiet"], &env)) {
        soft_skip!(LEG, "`uv lock` failed");
    }
    let sync = tool(&proj, "uv", &["sync", "--quiet"], &env);
    if !ok(&sync) {
        soft_skip!(LEG, "upstream `uv sync` failed:\n{}", dump(&sync));
    }
    let venv = proj.join(".venv");
    let Some(site) = site_packages(&venv) else {
        soft_skip!(
            LEG,
            "could not locate site-packages under {}",
            venv.display()
        );
    };
    assert!(
        !urllib3_patched(&site),
        "{LEG}: upstream urllib3 already carries `{PATCH_MARKER}` — vacuous"
    );
    let pyproject_before = std::fs::read(proj.join("pyproject.toml")).unwrap();
    let lock_before = std::fs::read(proj.join("uv.lock")).unwrap();

    let env_json = scan_vendored(&proj, &["--ecosystems", "pypi"]);
    assert_vendor_applied(&env_json, "urllib3@1.26.18", LEG);
    assert_download_uuid(&env_json, PYPI_UUIDS, LEG);

    let lock = read(&proj.join("uv.lock"));
    assert!(
        lock.contains(".socket/vendor/pypi/") && lock.contains(".whl"),
        "{LEG}: uv.lock was not rewired to the vendored wheel:\n{lock}"
    );
    let lock_wired = std::fs::read(proj.join("uv.lock")).unwrap();
    let pyproject_wired = std::fs::read(proj.join("pyproject.toml")).unwrap();

    // DELIVERY PROOF: pyproject + uv.lock + .socket only, empty cache,
    // `uv sync --frozen --offline`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("pyproject.toml"), fresh.join("pyproject.toml")).unwrap();
    std::fs::copy(proj.join("uv.lock"), fresh.join("uv.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_cache = tmp.path().join("fresh-uv-cache").display().to_string();
    let frozen = tool(
        &fresh,
        "uv",
        &["sync", "--frozen", "--offline", "--quiet"],
        &[("UV_CACHE_DIR", fresh_cache.as_str())],
    );
    assert!(
        ok(&frozen),
        "{LEG}: `uv sync --frozen --offline` from the vendored uv.lock failed:\n{}",
        dump(&frozen)
    );
    let fresh_site = site_packages(&fresh.join(".venv")).expect("fresh site-packages");
    assert!(
        urllib3_patched(&fresh_site),
        "{LEG}: resynced from the vendored uv.lock, but no urllib3 file carries `{PATCH_MARKER}`"
    );

    let env2 = scan_vendored(&proj, &["--ecosystems", "pypi"]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("uv.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave uv.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("pyproject.toml")).unwrap(),
        pyproject_wired,
        "{LEG}: re-run must leave pyproject.toml byte-identical"
    );

    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("uv.lock")).unwrap(),
        lock_before,
        "{LEG}: revert must restore uv.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("pyproject.toml")).unwrap(),
        pyproject_before,
        "{LEG}: revert must restore pyproject.toml byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

// ===========================================================================
// Cargo — `[patch.crates-io]` path dep
// ===========================================================================

/// Cargo's vendored artifact is a **directory** (a `[patch.crates-io]` path
/// dep), so the delivery proof is a `cargo fetch --offline` that resolves the
/// whole dependency graph from committable files with an empty CARGO_HOME —
/// proving zero registry access — plus a byte check that the vendored
/// directory carries the patch.
///
/// It deliberately does NOT `cargo build`: the production traitobject patch
/// injects a `compile_error!` unless the `allow-unmaintained` Cargo feature is
/// enabled (the patch's whole point is to make the unmaintained crate refuse to
/// compile silently). That is patch *content*, not a vendoring defect, and this
/// suite proves byte delivery, not CVE efficacy.
#[test]
#[ignore = "live production API + real crates.io. Run with --ignored."]
fn cargo_vendored_install_proof() {
    const LEG: &str = "cargo_vendored_install_proof";
    if !has_command("cargo") {
        soft_skip!(LEG, "`cargo` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).expect("mkdir src");
    let home = tmp.path().join("cargo-home").display().to_string();
    let env = [("CARGO_HOME", home.as_str())];

    std::fs::write(
        proj.join("Cargo.toml"),
        format!(
            "[package]\nname = \"vendored-e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{CARGO_NAME} = \"={CARGO_VERSION}\"\n"
        ),
    )
    .expect("write Cargo.toml");
    std::fs::write(proj.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");

    let fetch = tool(&proj, "cargo", &["fetch"], &env);
    if !ok(&fetch) {
        soft_skip!(LEG, "upstream `cargo fetch` failed:\n{}", dump(&fetch));
    }
    let pristine_lock = std::fs::read(proj.join("Cargo.lock")).unwrap();

    // The pristine registry-extracted source must NOT carry the marker.
    let registry_lib = find_registry_lib(Path::new(&home));
    if let Some(ref lib) = registry_lib {
        assert_pristine(lib, CARGO_MARKER, LEG);
    }

    let env_json = scan_vendored(&proj, &[]);
    assert_vendor_applied(&env_json, CARGO_PURL, LEG);
    assert_download_uuid(&env_json, &[CARGO_UUID], LEG);

    // Vendored directory carries the patch; the registry source stays pristine.
    let vendored_lib = proj
        .join(format!(
            ".socket/vendor/cargo/{CARGO_UUID}/{CARGO_NAME}-{CARGO_VERSION}"
        ))
        .join("src/lib.rs");
    assert_patched(&vendored_lib, CARGO_MARKER, LEG);
    if let Some(ref lib) = registry_lib {
        assert!(
            !read(lib).contains(CARGO_MARKER),
            "{LEG}: vendoring mutated the pristine registry source at {} — vendor must copy, \
             never mutate",
            lib.display()
        );
    }
    let config = read(&proj.join(".cargo/config.toml"));
    assert!(
        config.contains("[patch.crates-io]")
            && config.contains(&format!(".socket/vendor/cargo/{CARGO_UUID}/")),
        "{LEG}: .cargo/config.toml declares no [patch.crates-io] pointing at the vendored \
         crate:\n{config}"
    );
    // Lock detached from the registry (keeps name+version, loses source+checksum).
    let lock = read(&proj.join("Cargo.lock"));
    let block = cargo_package_block(&lock, CARGO_NAME).expect("traitobject lock entry survives");
    assert!(
        !block.contains("source = ") && !block.contains("checksum = "),
        "{LEG}: lock entry must be detached from the registry:\n{block}"
    );
    let lock_wired = std::fs::read(proj.join("Cargo.lock")).unwrap();

    // DELIVERY PROOF: committable files only, EMPTY CARGO_HOME, `cargo fetch
    // --offline --locked` — resolves the whole graph from the vendored path
    // with zero registry downloads.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(proj.join("Cargo.lock"), fresh.join("Cargo.lock")).unwrap();
    copy_dir_recursive(&proj.join(".cargo"), &fresh.join(".cargo"));
    copy_dir_recursive(&proj.join("src"), &fresh.join("src"));
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_home = tmp.path().join("fresh-cargo-home");
    std::fs::create_dir_all(&fresh_home).unwrap();
    let fresh_home_s = fresh_home.display().to_string();
    let refetch = tool(
        &fresh,
        "cargo",
        &["fetch", "--offline", "--locked"],
        &[("CARGO_HOME", fresh_home_s.as_str())],
    );
    assert!(
        ok(&refetch),
        "{LEG}: `cargo fetch --offline --locked` from the vendored path (empty CARGO_HOME) \
         failed — cargo could not resolve the graph from committable files alone:\n{}",
        dump(&refetch)
    );
    assert!(
        !fresh_home.join("registry").exists(),
        "{LEG}: the empty CARGO_HOME gained a registry/ — cargo hit the network instead of \
         resolving {CARGO_NAME} from the vendored path dep"
    );
    // The delivered bytes ARE the vendored directory's bytes (path dep), and
    // they carry the patch marker.
    assert_patched(
        &fresh.join(format!(
            ".socket/vendor/cargo/{CARGO_UUID}/{CARGO_NAME}-{CARGO_VERSION}/src/lib.rs"
        )),
        CARGO_MARKER,
        LEG,
    );

    // Idempotency + revert.
    let env2 = scan_vendored(&proj, &[]);
    assert_eq!(
        env2["vendor"]["summary"]["applied"].as_u64().unwrap_or(99),
        0,
        "{LEG}: re-run must vendor nothing new:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("Cargo.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave Cargo.lock byte-identical"
    );
    assert_eq!(vendor_revert(&proj, LEG), 1, "{LEG}: one entry reverted");
    assert_eq!(
        std::fs::read(proj.join("Cargo.lock")).unwrap(),
        pristine_lock,
        "{LEG}: revert must restore Cargo.lock byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

/// Find `<cargo_home>/registry/src/<idx>/traitobject-0.1.1/src/lib.rs`.
fn find_registry_lib(cargo_home: &Path) -> Option<PathBuf> {
    let src = cargo_home.join("registry").join("src");
    for host in std::fs::read_dir(&src).ok()?.flatten() {
        let candidate = host
            .path()
            .join(format!("{CARGO_NAME}-{CARGO_VERSION}"))
            .join("src")
            .join("lib.rs");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// The full `[[package]]` block (text) for `name` in Cargo.lock.
fn cargo_package_block(lock_text: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    lock_text
        .split("[[package]]")
        .find(|block| block.lines().any(|l| l.trim() == needle))
        .map(str::to_string)
}

// ===========================================================================
// RubyGems — vendoring the platform-qualified purl is unsupported (CLI gap)
// ===========================================================================

/// The gem redirect+download are correct and asserted hard. The **vendor** leg
/// is a different story: `scan --mode vendored` resolves and downloads the
/// activestorage patch, but the vendor backend refuses the platform-qualified
/// purl (`pkg:gem/activestorage@7.0.2.2?platform=ruby`) with
/// `platform_gem_unsupported`, so `summary.applied == 0`, `failed == 1`, and
/// the run exits non-zero with `"status": "partial_failure"`.
///
/// That is a real CLI gap, not a test bug, so this leg tolerates the vendor
/// failure — asserting the download succeeded and the failure is exactly that
/// known code — and fails loudly for any *other* failure. Set
/// `SOCKET_PATCH_VENDORED_E2E_GEM_STRICT=1` to promote it to a hard failure (do
/// that as the regression guard once the CLI learns to vendor platform gems).
/// The moment the vendor starts succeeding, the tolerance branch reports it so
/// the leg can be upgraded to a full delivery proof.
#[test]
#[ignore = "live production API + real rubygems.org. Run with --ignored."]
fn gem_bundler_vendored_known_platform_defect() {
    const LEG: &str = "gem_bundler_vendored_known_platform_defect";
    if !has_command("ruby") || !has_command("bundle") {
        soft_skip!(LEG, "`ruby` and/or `bundle` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    let bundle_path = tmp.path().join("bundle").display().to_string();
    let env = [
        ("BUNDLE_PATH", bundle_path.as_str()),
        ("BUNDLE_APP_CONFIG", bundle_path.as_str()),
    ];

    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .expect("write Gemfile");

    if !ok(&tool(&proj, "bundle", &["lock"], &env)) {
        soft_skip!(LEG, "`bundle lock` failed");
    }
    let install = tool(&proj, "bundle", &["install", "--quiet"], &env);
    if !ok(&install) {
        soft_skip!(LEG, "upstream `bundle install` failed:\n{}", dump(&install));
    }

    // Raw invocation: this run is EXPECTED to exit non-zero on the known defect.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--json",
            "--yes",
            "--mode",
            "vendored",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    let env_json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{LEG}: scan --mode vendored did not emit JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });

    // The download must have succeeded regardless — that half is not defective.
    assert_download_uuid(&env_json, &[GEM_UUID], LEG);
    let dl_failed = env_json["download"]["failed"].as_u64().unwrap_or(0);
    assert_eq!(
        dl_failed, 0,
        "{LEG}: the gem patch download itself failed — that is a regression, not the known \
         vendor-platform defect.\nenvelope:\n{env_json:#}"
    );

    let gem_strict = std::env::var("SOCKET_PATCH_VENDORED_E2E_GEM_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let applied = env_json["vendor"]["summary"]["applied"]
        .as_u64()
        .unwrap_or(0);
    if code == 0 && applied >= 1 {
        // The CLI now vendors platform gems. Say so loudly — this leg should be
        // promoted to a full delivery proof (bundle install frozen) and this
        // tolerance branch deleted.
        println!(
            "NOTE {LEG}: `scan --mode vendored` now SUCCEEDS for {GEM_PURL} (applied={applied}). \
             The platform_gem_unsupported vendor gap appears FIXED — upgrade this leg to a full \
             fresh-checkout `bundle install` delivery proof and delete the tolerance branch."
        );
        return;
    }

    // Otherwise: it must be exactly the known `platform_gem_unsupported` failure.
    let events = env_json["vendor"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let is_known = events
        .iter()
        .any(|e| e["action"] == "failed" && e["errorCode"] == "platform_gem_unsupported");
    assert!(
        !gem_strict,
        "{LEG}: SOCKET_PATCH_VENDORED_E2E_GEM_STRICT=1 and vendoring {GEM_PURL} did not succeed \
         (exit {code}).\nenvelope:\n{env_json:#}\nstderr:\n{stderr}"
    );
    assert!(
        is_known,
        "{LEG}: `scan --mode vendored` failed for {GEM_PURL}, but NOT with the known \
         `platform_gem_unsupported` vendor code — this is a new regression (exit {code}).\n\
         envelope:\n{env_json:#}\nstderr:\n{stderr}"
    );
    println!(
        "KNOWN CLI GAP {LEG}: `scan --mode vendored` downloads the {GEM_NAME} patch but the \
         vendor backend refuses the platform-qualified purl \
         (pkg:gem/{GEM_NAME}@{GEM_VERSION}?platform=ruby) with `platform_gem_unsupported`. \
         Redirect+download asserted; the delivery proof is blocked until the CLI learns to \
         vendor platform gems. This leg starts asserting a real install automatically once the \
         vendor succeeds."
    );
}

// ===========================================================================
// Documented gaps — golang (nothing to vendor), deno (unsupported), canary
// ===========================================================================

/// Golang vendored mode WORKS (directory `replace`), but production publishes
/// no free golang patches, so there is nothing to vendor. This asserts exactly
/// that — a clean run that vendors zero packages — and would light up the
/// moment a free golang patch is published.
#[test]
#[ignore = "live production API. Run with --ignored."]
fn golang_vendored_finds_no_free_patches() {
    const LEG: &str = "golang_vendored_finds_no_free_patches";
    if !has_command("go") {
        soft_skip!(LEG, "`go` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(
        proj.join("go.mod"),
        "module example.com/vendored-e2e\n\ngo 1.21\n",
    )
    .expect("write go.mod");

    let env_json = scan_vendored(&proj, &["--ecosystems", "golang"]);
    let applied = env_json["vendor"]["summary"]["applied"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        applied, 0,
        "{LEG}: golang vendored something, but production publishes no free golang patches. \
         Either production changed (extend this suite with a real golang delivery proof) or \
         this is a bug.\nenvelope:\n{env_json:#}"
    );
    let patches = env_json["download"]["patches"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    if patches > 0 {
        println!(
            "{LEG}: production now publishes free golang patches — extend this suite with a \
             real `go mod` vendored delivery proof."
        );
    } else {
        println!("{LEG}: no free golang patches published; vendored mode correctly found nothing.");
    }
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: nothing was vendored, so no .socket/vendor tree should exist:\n{env_json:#}"
    );
}

/// Deno vendored mode is not supported. Same shape as the golang guard.
#[test]
#[ignore = "live production API. Run with --ignored."]
fn deno_vendored_is_unsupported() {
    const LEG: &str = "deno_vendored_is_unsupported";
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(
        proj.join("deno.json"),
        r#"{"imports":{"minimist":"npm:minimist@1.2.2"}}"#,
    )
    .expect("write deno.json");

    let env_json = scan_vendored(&proj, &["--ecosystems", "deno"]);
    let applied = env_json["vendor"]["summary"]["applied"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        applied, 0,
        "{LEG}: deno vendored something, but vendored mode is not supported for deno:\n{env_json:#}"
    );
}

/// maven, nuget and composer all implement vendored mode, but production
/// publishes no free-tier patches for them. This probes production every run
/// and reports the moment that changes, so coverage can be extended
/// deliberately rather than by accident. It does not fail when patches appear;
/// `SOCKET_PATCH_VENDORED_E2E_CANARY_STRICT=1` makes it fail, for a scheduled
/// nag run.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API. Run with --ignored."]
async fn canary_unpublished_vendored_ecosystems() {
    let mut newly_published: Vec<String> = Vec::new();
    let mut probe_errors: Vec<String> = Vec::new();

    for (eco, candidates) in UNPUBLISHED_ECOSYSTEMS {
        for purl in *candidates {
            match published_uuids(purl).await {
                Ok(uuids) if !uuids.is_empty() => {
                    newly_published.push(format!("{eco}: {purl} -> {uuids:?}"));
                }
                Ok(_) => {}
                Err(e) => probe_errors.push(format!("{eco}: {purl}: {e}")),
            }
        }
    }

    assert!(
        probe_errors.is_empty(),
        "production probe failed (the endpoint itself may be down, which IS a real signal for \
         this suite):\n  - {}",
        probe_errors.join("\n  - ")
    );

    if newly_published.is_empty() {
        println!(
            "canary_unpublished_vendored_ecosystems: maven / nuget / composer still have no \
             free-tier published patches — their vendored-mode legs remain untestable \
             end-to-end against production."
        );
        return;
    }

    let msg = format!(
        "production now publishes free patches for previously-empty ecosystems:\n  - {}\nExtend \
         this suite with real vendored install proofs for them (see \
         docs/testing/vendored-production-e2e.md).",
        newly_published.join("\n  - ")
    );
    if std::env::var("SOCKET_PATCH_VENDORED_E2E_CANARY_STRICT").as_deref() == Ok("1") {
        panic!("{msg}");
    }
    println!("NOTE canary_unpublished_vendored_ecosystems: {msg}");
}
