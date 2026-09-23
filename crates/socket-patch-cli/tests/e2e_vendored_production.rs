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
//!   5. **DELIVERY proof** — copy ONLY the committable files (project
//!      manifest + lockfile + `.socket/` + any PM config) into a fresh dir,
//!      point every cache var at a fresh EMPTY dir, run the package
//!      manager's clean-install offline, and assert the installed bytes are
//!      the VENDORED (patched) bytes, NOT the pristine registry bytes;
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
//! | gem    | `pkg:gem/activestorage@6.0.3`   | *any of* [`GEM_PATCHES`]               | `Socket Community Patch` header |
//!
//! # Ecosystem coverage notes (gaps, and one resolved gap)
//!
//! * **gem** — RESOLVED: full coverage. The old `platform_gem_unsupported`
//!   refusal for `?platform=ruby` purls was fixed in the CLI (#172 — only
//!   non-`ruby` platform qualifiers are refused), and the 2026-08-18 catalog
//!   republish restored the pinned patch, so
//!   [`gem_bundler_vendored_install_proof`] now runs the complete vendored
//!   loop including the fresh-dir `bundle install` delivery proof. While
//!   production's served `gem-stub-gemspec` remains invalid (D4: missing the
//!   rubygems-required `summary`/`authors`), the leg passes via the CLI's
//!   invalid-stub hardening — `--vendor-source auto` detects the defect and
//!   falls back to the local build (`vendor_prebuilt_stub_invalid` warning);
//!   once the server-side stub fix deploys and the artifacts rebuild, the
//!   same leg exercises the service artifact directly.
//! * **golang** — vendored mode *works* (directory `replace`), but production
//!   publishes no free golang patches, so there is nothing to vendor.
//!   [`golang_vendored_finds_no_free_patches`] asserts exactly that (zero
//!   applied) and would light up the moment a golang patch is published.
//! * **cargo / maven / nuget / composer** — vendored mode is implemented, but
//!   production publishes **zero** free-tier patches for them.
//!   [`canary_unpublished_vendored_ecosystems`] probes production every run and
//!   reports the moment that changes. cargo carried a full
//!   `[patch.crates-io]` delivery proof until 2026-09-01: production's free
//!   cargo tier emptied on 2026-08-28, so the leg was demoted to the canary
//!   (`docs/testing/vendored-production-e2e.md` says how to re-promote it).
//! * **deno** — vendored mode is not supported.
//!   [`deno_vendored_is_unsupported`] covers it as a negative assertion.
//!
//! # Prerequisites
//!
//! Toolchains (each leg soft-skips if its own toolchain is absent, unless
//! `SOCKET_PATCH_VENDORED_E2E_STRICT=1`): `npm`, `pnpm`, `corepack` (yarn
//! classic + berry), `bun`, `uv`, `python3` (pip), `ruby` + `bundle`, `go`.
//!
//! Network egress to: `patches-api.socket.dev`, `patch.socket.dev`,
//! `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`,
//! `rubygems.org`.
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
#[path = "npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
// yarn classic leg: release selection + the manifest-less VEX matrix.
#[path = "common/yarn_classic_vex.rs"]
mod yarn_classic_vex;
// uv legs: release selection + the manifest-less VEX matrix.
#[path = "vex_e2e_common/uv.rs"]
mod uv_vex;
#[path = "vex_pipenv_pip_steps/mod.rs"]
mod vex_pipenv_pip_steps;

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

/// The gem pin is deliberately UNQUALIFIED. Production publishes the purl as
/// `pkg:gem/activestorage@6.0.3?platform=ruby`, but nothing client-side
/// strips qualifiers — the SERVER normalizes both spellings to the same
/// patch set (verified live against `/patch/by-package`), so this pins the
/// bare spelling the CLI's own crawler synthesizes.
const GEM_PURL: &str = "pkg:gem/activestorage@6.0.3";
const GEM_NAME: &str = "activestorage";
const GEM_VERSION: &str = "6.0.3";
/// Any-of pin set for the gem leg: `(patch uuid, the file its diff marks)`.
/// Production has published several distinct free 6.0.3 patches (one per
/// advisory), the manifest holds one patch per PURL, and which one the
/// server-ranked resolver returns is a server-side ordering detail — so the
/// leg accepts any pinned patch and probes the marker file that PATCH
/// actually touches. When production publishes another acceptable 6.0.3
/// patch, verify its `/patch/view` blobs carry the marker and append it here
/// (and to the hosted suite's `GEM_UUIDS`).
const GEM_PATCHES: &[(&str, &str)] = &[
    // GHSA-m42x-37p3-fv5w / CVE-2020-8162, from the 2026-08-18 catalog
    // republish.
    (
        "15e960b5-f432-4b6c-b8aa-534a2b419323",
        "lib/active_storage/service/s3_service.rb",
    ),
    // GHSA-w749-p3v6-hccq / CVE-2022-21831, published 2026-08-19T21:19Z.
    (
        "6c4141c5-1535-4fd2-9db1-b5f8e4834bdb",
        "lib/active_storage/transformers/image_processing_transformer.rb",
    ),
    // GHSA-9xrj-h377-fr87 / CVE-2026-33195, published 2026-08-20T16:14Z
    // (also touches disk_controller.rb + errors.rb; the service file is the
    // marker probe).
    (
        "eeb6bf9f-96c0-4963-a0f1-2e88f91f8b1a",
        "lib/active_storage/service/disk_service.rb",
    ),
    // GHSA-r4mg-4433-c7g3 / CVE-2025-24293, published 2026-08-20T20:31Z —
    // the one the server-ranked selection wires as of 2026-08-20.
    (
        "c1a1cd3c-b670-4e44-b4fa-1a63ecd42db6",
        "lib/active_storage/transformers/image_processing_transformer.rb",
    ),
];

/// Header the patch service injects into patched npm / PyPI source files.
const PATCH_MARKER: &str = "Socket Community Patch";

/// Corepack-pinned yarn flavors. The on-PATH `yarn` may be either major, so the
/// leg pins the version through corepack to guarantee the lockfile grammar
/// under test.
const YARN_BERRY: &str = "yarn@4.6.0";

/// Ecosystems where vendored mode is implemented but production has no free
/// patches to exercise it with. [`canary_unpublished_vendored_ecosystems`]
/// watches these so coverage can be extended the moment one lights up.
const UNPUBLISHED_ECOSYSTEMS: &[(&str, &[&str])] = &[
    // cargo joined this list on 2026-09-01: production deleted its last free
    // cargo patches on 2026-08-28, retiring the pinned `[patch.crates-io]`
    // delivery proof this suite used to carry. Re-promotion procedure:
    // docs/testing/vendored-production-e2e.md.
    (
        "cargo",
        &["pkg:cargo/openssl", "pkg:cargo/tokio", "pkg:cargo/smallvec"],
    ),
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
/// look identical to a working vendor. `failed == 0` catches partial failures.
/// The gem leg uses the purl-SCOPED [`assert_vendor_applied_for`] instead: its
/// fixture has many transitive gems, so run-wide counts would couple the leg
/// to the production catalog's future patches. The `applied` event's purl may
/// carry qualifiers (`?artifact_id=…`), so a substring match is used.
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

/// The events for purls containing `purl_needle` (substring — purls may carry
/// qualifiers) with the given `action`.
fn vendor_events_for<'a>(
    env: &'a serde_json::Value,
    purl_needle: &str,
    action: &str,
) -> Vec<&'a serde_json::Value> {
    env["vendor"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| {
                    e["action"] == action
                        && e["purl"]
                            .as_str()
                            .map(|p| p.contains(purl_needle))
                            .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Purl-SCOPED variant of [`assert_vendor_applied`]: the named purl must have
/// an `applied` event and NO `failed` event. Other purls' outcomes are the
/// production catalog's business — a future free patch on a transitive gem of
/// the fixture must not red this leg — so run-wide `summary` counts are
/// deliberately not asserted.
fn assert_vendor_applied_for(env: &serde_json::Value, purl_needle: &str, leg: &str) {
    assert!(
        !env["vendor"].is_null(),
        "{leg}: scan --mode vendored emitted no `vendor` sub-object — the CLI omits it \
         when discovery found nothing, so this means the crawler did not see the \
         installed dependency.\nenvelope:\n{env:#}"
    );
    assert!(
        !vendor_events_for(env, purl_needle, "applied").is_empty(),
        "{leg}: no `applied` event for a purl containing `{purl_needle}`.\nenvelope:\n{env:#}"
    );
    assert!(
        vendor_events_for(env, purl_needle, "failed").is_empty(),
        "{leg}: a `failed` event for `{purl_needle}`.\nenvelope:\n{env:#}"
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

/// Run `bundle <args>` with the ambient `BUNDLE_*`/`GEM_*`/`RUBYOPT` state
/// scrubbed first (a developer's global bundler config — frozen mode, a
/// custom BUNDLE_PATH or gem home, a RUBYOPT require — must not leak into a
/// leg that hard-asserts bundler outcomes; mirrors e2e_vendor_gem_build.rs).
/// The cache sandbox re-pins its own BUNDLE_USER_HOME/GEM_SPEC_CACHE after
/// the scrub, and the per-leg `env` is applied last so the leg's pins win.
fn bundle(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("bundle");
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy().into_owned();
        if key.starts_with("BUNDLE_") || key.starts_with("GEM_") || key == "RUBYOPT" {
            cmd.env_remove(&k);
        }
    }
    cache_env::isolate(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn `bundle`: {e}"))
}

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
        (GEM_PURL, GEM_PATCHES.iter().map(|(u, _)| *u).collect()),
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

    // MANIFEST-LESS VEX against production over the fresh checkout (its own
    // copy): the committed artifact attests with the ledger, from lockfile
    // discovery + the public proxy without it, never offline, and not once
    // the lock is reverted.
    npm_e2e_common::production_manifestless_vex(
        LEG,
        &fresh,
        NPM_PURL,
        NPM_UUID,
        vex_e2e_common::Marker::Vendored,
        "GHSA-xvch-5gv4-984h",
        &[("package-lock.json", lock_before.clone())],
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
    // pnpm >= 11 reads `overrides` only from pnpm-workspace.yaml, so the CLI
    // creates/updates it too. Assert it landed and points at the tarball.
    let ws_path = proj.join("pnpm-workspace.yaml");
    let ws = read(&ws_path);
    assert!(
        ws.contains(&tgz_rel),
        "{LEG}: pnpm-workspace.yaml `overrides:` was not wired to the vendored tarball:\n{ws}"
    );
    let lock_wired = std::fs::read(proj.join("pnpm-lock.yaml")).unwrap();
    let pkg_wired = std::fs::read(proj.join("package.json")).unwrap();
    let ws_wired = std::fs::read(&ws_path).unwrap();

    // DELIVERY PROOF: committable files only (pnpm edits package.json's
    // `pnpm.overrides` AND creates pnpm-workspace.yaml), empty store, frozen
    // offline install. This must now succeed directly on pnpm >= 11 — the
    // pnpm-workspace.yaml override is exactly what closes the old
    // ERR_PNPM_LOCKFILE_CONFIG_MISMATCH gap.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("pnpm-lock.yaml"), fresh.join("pnpm-lock.yaml")).unwrap();
    std::fs::copy(&ws_path, fresh.join("pnpm-workspace.yaml")).unwrap();
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
    assert!(
        ok(&ci),
        "{LEG}: `pnpm install --frozen-lockfile --offline` must install the vendored tarball \
         from the committable files (no ERR_PNPM_LOCKFILE_CONFIG_MISMATCH — the \
         pnpm-workspace.yaml override is what makes pnpm >= 11 honor it):\n{}",
        dump(&ci)
    );
    assert_patched(&entry, PATCH_MARKER, LEG);
    assert_ne!(
        std::fs::read(&entry).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes"
    );
    pnpm_vendored_manifestless_vex(&fresh, &lock_before, &pkg_before, LEG);

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
    assert_eq!(
        std::fs::read(&ws_path).unwrap(),
        ws_wired,
        "{LEG}: re-run must leave pnpm-workspace.yaml byte-identical"
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
    assert!(
        !ws_path.exists(),
        "{LEG}: revert must delete the pnpm-workspace.yaml vendoring created"
    );
}

/// Manifest-less VEX over the fresh vendored pnpm checkout, against the
/// REAL public patch proxy: the vendor ledger's record attests
/// `(vendored)`; with both ledgers deleted the production `view/<uuid>`
/// record does; `--offline` has no record; and with the wiring reverted
/// (lock + package.json back, pnpm-workspace.yaml gone — ledger and
/// tarball kept) nothing attests, `--no-verify` included. Only the pinned
/// advisory is asserted — production may add more to the patch later.
fn pnpm_vendored_manifestless_vex(fresh: &Path, lock_before: &[u8], pkg_before: &[u8], leg: &str) {
    use vex_e2e_common::{
        assert_absent, assert_not_attested, run_vex, statements_for, strip_ledgers, strip_manifest,
        VexRun,
    };
    let bin = binary();
    let attested = |run: &VexRun, cell: &str| {
        let out = run_vex(&bin, fresh, run);
        assert_eq!(out.code, Some(0), "{leg} [{cell}]: {out}");
        let marker = format!("Patched via Socket patch {NPM_UUID} (vendored)");
        assert!(
            statements_for(out.doc(), NPM_PURL).iter().any(|st| {
                st["vulnerability"]["name"] == "GHSA-xvch-5gv4-984h"
                    && st["status"] == "not_affected"
                    && st["impact_statement"]
                        .as_str()
                        .is_some_and(|i| i.contains(&marker))
            }),
            "{leg} [{cell}]: minimist must be attested: {out}"
        );
    };
    strip_manifest(fresh);
    let state = fresh.join(".socket/vendor/state.json");
    let state_bytes = std::fs::read(&state).expect("vendor ledger");
    attested(&VexRun::default(), "manifest deleted");
    strip_ledgers(fresh);
    attested(&VexRun::default(), "ledgers deleted");
    let out = run_vex(&bin, fresh, &VexRun::offline());
    assert_eq!(out.code, Some(1), "{leg} [offline]: {out}");
    assert_not_attested(&out.envelope, NPM_PURL, "record_unavailable");
    std::fs::write(&state, &state_bytes).unwrap();
    std::fs::write(fresh.join("pnpm-lock.yaml"), lock_before).unwrap();
    std::fs::write(fresh.join("package.json"), pkg_before).unwrap();
    std::fs::remove_file(fresh.join("pnpm-workspace.yaml")).unwrap();
    for no_verify in [false, true] {
        let out = run_vex(
            &bin,
            fresh,
            &VexRun {
                no_verify,
                ..VexRun::default()
            },
        );
        assert_ne!(
            out.code,
            Some(0),
            "{leg} [reverted, no_verify={no_verify}]: {out}"
        );
        assert_absent(out.doc.as_ref(), NPM_PURL);
        assert_not_attested(&out.envelope, NPM_PURL, "vendor_unwired");
    }
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn yarn_classic_vendored_install_proof() {
    const LEG: &str = "yarn_classic_vendored_install_proof";
    // The release under test (`SOCKET_PATCH_yarn_classic_E2E_VERSION`,
    // default 1.22.22); < 1.7 cannot install a vendored `file:` tarball.
    let yarn_classic = yarn_classic_vex::yarn_classic();
    let yarn_classic = yarn_classic.as_str();
    if !yarn_classic_vex::installs_file_tarballs(&yarn_classic_vex::yarn_classic_version()) {
        println!("N/A {LEG}: {yarn_classic} cannot install vendored `file:` tarballs");
        return;
    }
    if !has_corepack_pm(yarn_classic) {
        soft_skip!(
            LEG,
            "`corepack {yarn_classic}` unavailable (corepack absent or yarn classic not fetchable)"
        );
    }
    let (tmp, proj) = npm_fixture(Some(yarn_classic));
    let cache = tmp.path().join("yarn1-cache").display().to_string();
    let env = [("YARN_CACHE_FOLDER", cache.as_str())];

    let install = corepack(&proj, yarn_classic, &["install", "--no-progress"], &env);
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
        yarn_classic,
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

    // Manifest-less VEX of the delivered checkout (a copy — the idempotency
    // and revert legs below still use `proj`), records from the REAL public
    // proxy once the vendor ledger is gone; `--offline` points at an empty
    // local stand-in so its zero-request claim is observable.
    let vex_dir = tmp.path().join("fresh-vex");
    copy_dir_recursive(&fresh, &vex_dir);
    let empty = vex_e2e_common::PatchApi::empty();
    let reverted_cache = tmp
        .path()
        .join("reverted-yarn1-cache")
        .display()
        .to_string();
    yarn_classic_vex::ManifestlessVex {
        leg: LEG,
        wiring: yarn_classic_vex::Wiring::Vendored,
        purl: NPM_PURL,
        uuid: NPM_UUID,
        vulns: &[],
        api: &empty,
        proxy_override: Some(PROXY.to_string()),
        patch_server_url: None,
        registry_lock: lock_before.clone(),
        reinstall: Some(Box::new(|dir: &Path| {
            std::fs::remove_dir_all(dir.join("node_modules")).expect("rm node_modules");
            let out = corepack(
                dir,
                yarn_classic,
                &["install", "--frozen-lockfile", "--no-progress"],
                &[("YARN_CACHE_FOLDER", reverted_cache.as_str())],
            );
            assert!(
                ok(&out),
                "{LEG}: reverted-lock install failed:\n{}",
                dump(&out)
            );
            assert_eq!(
                std::fs::read(minimist_entry(dir)).unwrap(),
                pristine,
                "{LEG}: the reverted lock installs the pristine bytes"
            );
        })),
        embedded: vec![
            ("apply --vex", yarn_classic_vex::via_apply()),
            ("vendor --vex", yarn_classic_vex::via_vendor()),
            // The command the leg itself ran, re-run manifest-less
            // (`--detached`: no manifest writes — the shape under test).
            (
                "scan --mode vendored --detached --vex",
                Box::new(|run: vex_e2e_common::VexRun| {
                    run.via(vex_e2e_common::VexVia::Scan)
                        .arg("--mode")
                        .arg("vendored")
                        .arg("--detached")
                        .arg("--yes")
                }),
            ),
        ],
    }
    .run(&vex_dir);

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

    yarn_berry_vendored_manifestless_vex(&fresh, &tmp, &lock_before, &pkg_before);

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

/// One `vex --json --output <dir>/../<name>.vex.json` run in `proj` on the
/// anonymous free tier. Returns (exit, envelope, document).
fn yarn_berry_vex(
    proj: &Path,
    extra: &[&str],
) -> (i32, serde_json::Value, Option<serde_json::Value>) {
    let out = proj.with_extension("vex.json");
    let _ = std::fs::remove_file(&out);
    let out_s = out.to_str().unwrap().to_string();
    let mut args = vec![
        "vex",
        "--json",
        "--output",
        out_s.as_str(),
        "--product",
        "pkg:npm/vendored-e2e@0.0.0",
        "--cwd",
        proj.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_socket(proj, &args);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vex --json is not JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    let doc = std::fs::read(&out)
        .ok()
        .map(|b| serde_json::from_slice(&b).expect("VEX document is JSON"));
    (code, env, doc)
}

/// The production patch attested `(vendored)` for [`NPM_PURL`].
fn assert_berry_vendored_attestation(
    code: i32,
    env: &serde_json::Value,
    doc: Option<serde_json::Value>,
    cell: &str,
) {
    assert_eq!(code, 0, "{cell}: {env:#}");
    let doc = doc.unwrap_or_else(|| panic!("{cell}: no VEX document: {env:#}"));
    let stmts: Vec<&serde_json::Value> = doc["statements"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|st| {
            st["products"][0]["subcomponents"]
                .as_array()
                .is_some_and(|subs| subs.iter().any(|s| s["@id"] == NPM_PURL))
        })
        .collect();
    assert!(
        !stmts.is_empty(),
        "{cell}: {NPM_PURL} not attested: {doc:#}"
    );
    for st in stmts {
        assert_eq!(st["status"], "not_affected", "{cell}: {st:#}");
        assert!(
            st["impact_statement"]
                .as_str()
                .is_some_and(|s| s.contains(&format!("Socket patch {NPM_UUID} (vendored)"))),
            "{cell}: {st:#}"
        );
    }
}

/// `errorCode` of the skipped event for [`NPM_PURL`].
fn berry_skip_code(env: &serde_json::Value) -> String {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["action"] == "skipped" && e["purl"] == NPM_PURL)
        .and_then(|e| e["errorCode"].as_str())
        .unwrap_or_else(|| panic!("no skipped event for {NPM_PURL}: {env:#}"))
        .to_string()
}

/// Manifest-less VEX against PRODUCTION for the berry vendored leg, on the
/// fresh checkout the real yarn just installed from the committed artifact:
/// with the manifest deleted (ledger online + `--offline`), with the
/// ledger deleted too (lockfile + artifact, record from the public proxy),
/// `--offline` with nothing local (`record_unavailable`), and a copy whose
/// lock + package.json are reverted to the registry while the ledger and
/// artifact stay (`vendor_unwired`, even with `--no-verify`).
fn yarn_berry_vendored_manifestless_vex(
    fresh: &Path,
    tmp: &tempfile::TempDir,
    lock_before: &[u8],
    pkg_before: &[u8],
) {
    const LEG: &str = "yarn_berry_vendored_install_proof (manifest-less vex)";
    let manifest = fresh.join(".socket/manifest.json");
    let ledger_path = fresh.join(".socket/vendor/state.json");
    let ledger = std::fs::read(&ledger_path).expect("vendor ledger");
    std::fs::remove_file(&manifest).expect("scan --mode vendored writes a manifest");

    let (code, env, doc) = yarn_berry_vex(fresh, &[]);
    assert_berry_vendored_attestation(code, &env, doc, &format!("{LEG}: ledger, online"));
    let (code, env, doc) = yarn_berry_vex(fresh, &["--offline"]);
    assert_berry_vendored_attestation(code, &env, doc, &format!("{LEG}: ledger, offline"));

    std::fs::remove_file(&ledger_path).unwrap();
    let (code, env, doc) = yarn_berry_vex(fresh, &[]);
    assert_berry_vendored_attestation(code, &env, doc, &format!("{LEG}: lockfile only"));
    let (code, env, doc) = yarn_berry_vex(fresh, &["--offline"]);
    assert_eq!(code, 1, "{LEG}: lockfile only, offline: {env:#}");
    assert_eq!(berry_skip_code(&env), "record_unavailable", "{LEG}");
    assert!(doc.is_none(), "{LEG}: no document");

    // Revert the lock + package.json to the registry; ledger + artifact stay.
    let reverted = tmp.path().join("vex-reverted");
    copy_dir_recursive(fresh, &reverted);
    std::fs::write(reverted.join(".socket/vendor/state.json"), &ledger).unwrap();
    std::fs::write(reverted.join("yarn.lock"), lock_before).unwrap();
    std::fs::write(reverted.join("package.json"), pkg_before).unwrap();
    std::fs::remove_dir_all(reverted.join("node_modules")).ok();
    let global = tmp.path().join("vex-reverted-global").display().to_string();
    let reinstall = corepack(
        &reverted,
        YARN_BERRY,
        &["install", "--immutable"],
        &[("YARN_GLOBAL_FOLDER", global.as_str())],
    );
    assert!(
        ok(&reinstall),
        "{LEG}: reverted reinstall:\n{}",
        dump(&reinstall)
    );
    assert_pristine(&minimist_entry(&reverted), PATCH_MARKER, LEG);
    for extra in [
        &["--offline"][..],
        &["--offline", "--no-verify"][..],
        &[][..],
    ] {
        let (code, env, doc) = yarn_berry_vex(&reverted, extra);
        assert_eq!(code, 1, "{LEG}: reverted {extra:?}: {env:#}");
        assert_eq!(
            berry_skip_code(&env),
            "vendor_unwired",
            "{LEG}: reverted {extra:?}"
        );
        assert!(doc.is_none(), "{LEG}: reverted {extra:?}: no document");
    }
    println!("VEX-MATRIX|{YARN_BERRY}|production|vendored|manifest-deleted+ledgers-deleted+offline+reverted|PASS");
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

    // This leg covers text `bun.lock`; native binary coverage lives in
    // e2e_bun_lockb and the Bun compatibility matrices.
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
    let manifest: serde_json::Value =
        serde_json::from_str(&read(&fresh.join(".socket/manifest.json"))).unwrap();
    let record = manifest["patches"][NPM_PURL].clone();
    bun_manifestless_vex_production(&fresh, &record, "vendored", &lock_before, LEG);

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

/// Manifest-less VEX over a PRODUCTION bun checkout (`checkout` holds the
/// committed state plus a real frozen install of the patched bytes):
/// with `.socket/manifest.json` deleted, standalone `vex` against the public
/// patch API attests minimist under the ledger record's uuid with `marker`
/// (`redirected` / `vendored`) and exactly the record's vulnerability ids;
/// with both ledgers deleted as well it still attests (lockfile discovery +
/// the API); `--offline` then omits it as `record_unavailable`; and with
/// the ledgers back but `bun.lock` reverted to `registry_lock` it is NOT
/// attested, verified or not. The hermetic twins (mock API, zero-request
/// oracle) run in `e2e_redirect_bun_build` / `e2e_vendor_bun_build`.
fn bun_manifestless_vex_production(
    checkout: &Path,
    record: &serde_json::Value,
    marker: &str,
    registry_lock: &[u8],
    leg: &str,
) {
    let uuid = record["uuid"].as_str().expect("record uuid").to_string();
    let mut want: Vec<String> = record["vulnerabilities"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    want.sort();
    assert!(
        !want.is_empty(),
        "{leg}: the production record lists no vulnerability: {record}"
    );
    let vex = |extra: &[&str]| -> (Option<i32>, serde_json::Value, Option<serde_json::Value>) {
        let out_path = checkout.join("out.vex.json");
        let _ = std::fs::remove_file(&out_path);
        let mut cmd = Command::new(binary());
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SOCKET_") {
                cmd.env_remove(key);
            }
        }
        let out = cmd
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("SOCKET_NO_API_TOKEN", "1")
            .current_dir(checkout)
            .args(["vex", "--json", "--output"])
            .arg(&out_path)
            .args(["--product", "pkg:npm/app@1.0.0", "--cwd"])
            .arg(checkout)
            .args(extra)
            .output()
            .expect("spawn socket-patch vex");
        let envelope = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{leg}: vex --json output is not JSON ({e}):\n{}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        let doc = std::fs::read(&out_path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap());
        (out.status.code(), envelope, doc)
    };
    let attested = |doc: &Option<serde_json::Value>| -> Vec<String> {
        let part = format!("Patched via Socket patch {uuid} ({marker})");
        let mut ids: Vec<String> = doc
            .as_ref()
            .and_then(|d| d["statements"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|st| {
                st["products"][0]["subcomponents"][0]["@id"] == NPM_PURL
                    && st["status"] == "not_affected"
                    && st["impact_statement"]
                        .as_str()
                        .is_some_and(|s| s.split("; ").any(|p| p == part))
            })
            .filter_map(|st| st["vulnerability"]["name"].as_str().map(str::to_string))
            .collect();
        ids.sort();
        ids
    };
    let skip = |env: &serde_json::Value| -> Option<String> {
        env["events"].as_array()?.iter().find_map(|e| {
            (e["action"] == "skipped" && e["purl"] == NPM_PURL)
                .then(|| e["errorCode"].as_str().unwrap_or_default().to_string())
        })
    };
    let _ = std::fs::remove_file(checkout.join(".socket/manifest.json"));
    let (code, env, doc) = vex(&[]);
    assert_eq!(code, Some(0), "{leg}: manifest-less vex: {env:#}");
    assert_eq!(attested(&doc), want, "{leg}: manifest-less vex: {env:#}");
    let ledgers: Vec<(PathBuf, Vec<u8>)> = [
        ".socket/vendor/state.json",
        ".socket/vendor/redirect-state.json",
    ]
    .iter()
    .map(|rel| checkout.join(rel))
    .filter_map(|p| std::fs::read(&p).ok().map(|b| (p, b)))
    .collect();
    assert!(!ledgers.is_empty(), "{leg}: the flow left no ledger");
    for (p, _) in &ledgers {
        std::fs::remove_file(p).unwrap();
    }
    let (code, env, doc) = vex(&[]);
    assert_eq!(code, Some(0), "{leg}: ledger-less vex: {env:#}");
    assert_eq!(attested(&doc), want, "{leg}: ledger-less vex: {env:#}");
    let (code, env, doc) = vex(&["--offline"]);
    assert_eq!(code, Some(1), "{leg}: offline vex: {env:#}");
    assert_eq!(
        skip(&env).as_deref(),
        Some("record_unavailable"),
        "{leg}: {env:#}"
    );
    assert!(attested(&doc).is_empty(), "{leg}: offline vex: {env:#}");
    for (p, b) in &ledgers {
        std::fs::write(p, b).unwrap();
    }
    std::fs::write(checkout.join("bun.lock"), registry_lock).unwrap();
    let unwired = if marker == "redirected" {
        "redirect_unwired"
    } else {
        "vendor_unwired"
    };
    for extra in [&[][..], &["--no-verify"][..]] {
        let (code, env, doc) = vex(extra);
        assert_eq!(code, Some(1), "{leg}: reverted vex {extra:?}: {env:#}");
        assert_eq!(
            skip(&env).as_deref(),
            Some(unwired),
            "{leg}: reverted {extra:?}: {env:#}"
        );
        assert!(
            attested(&doc).is_empty(),
            "{leg}: reverted vex {extra:?}: {env:#}"
        );
    }
    eprintln!("BUN-VEX production {marker} manifest-deleted/ledgers-deleted/offline/reverted ok");
}

// ===========================================================================
// PyPI ecosystem — requirements.txt and uv.lock
// ===========================================================================

/// The manifest-less VEX steps over an installed checkout wired to one of
/// [`PYPI_UUIDS`] (whichever `wiring` names), records from the LIVE public
/// proxy (vuln ids: whatever production's record carries), `revert`
/// putting requirements.txt back on the registry pin.
fn pypi_manifestless_vex(
    project: &Path,
    leg: &str,
    wiring: &str,
    marker: vex_e2e_common::Marker,
    revert: &(dyn Fn(&Path) + Sync),
) {
    let uuid = PYPI_UUIDS
        .iter()
        .find(|u| wiring.contains(**u))
        .unwrap_or_else(|| panic!("{leg}: no known urllib3 patch uuid is wired:\n{wiring}"));
    vex_pipenv_pip_steps::run_manifestless_steps(&vex_pipenv_pip_steps::Steps {
        what: format!("{leg} manifest-less vex"),
        project,
        purl: PYPI_PURL,
        uuid,
        marker,
        vulns: None,
        records: vex_pipenv_pip_steps::Records::Live(PROXY.to_string()),
        patch_server_url: None,
        product: "pkg:pypi/app@1.0.0",
        revert,
        envs: Vec::new(),
        on_step: None,
        expect_verified: true,
    });
}

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

    // Manifest-less VEX over the installed fresh checkout.
    pypi_manifestless_vex(
        &fresh,
        LEG,
        &reqs,
        vex_e2e_common::Marker::Vendored,
        &|p: &Path| std::fs::write(p.join("requirements.txt"), &reqs_before).unwrap(),
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
    // The uv under test (`SOCKET_PATCH_UV_E2E_BIN`, default `uv` on PATH).
    let uv = uv_vex::uv_program();
    if !has_command(&uv) {
        soft_skip!(LEG, "`{uv}` not on PATH");
    }
    if let Err(why) = uv_vex::production_supported(&uv, uv_vex::Mode::Vendored) {
        println!(
            "UV-VEX uv={} mode={} lane=production({LEG}) step=all result=n/a ({why})",
            uv_vex::version_of(&uv),
            uv_vex::Mode::Vendored.name()
        );
        return;
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

    if !ok(&tool(&proj, &uv, &["lock", "--quiet"], &env)) {
        soft_skip!(LEG, "`uv lock` failed");
    }
    let sync = tool(&proj, &uv, &["sync", "--quiet"], &env);
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
        &uv,
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

    // Manifest-less VEX over a fresh checkout (pyproject + uv.lock + .socket
    // minus the manifest, `uv sync --frozen --offline` from an empty cache):
    // the record comes from the vendor ledger, then — ledger deleted — from a
    // local stand-in serving the SAME production record; `--offline` makes
    // zero requests; `apply --vex` / `vendor --vex` and the leg's own `scan
    // --mode vendored --vex` (live) attest; the reverted pair, ledger + wheel
    // kept, reinstalled pristine, does not.
    let registry = vec![
        ("pyproject.toml".to_string(), pyproject_before.clone()),
        ("uv.lock".to_string(), lock_before.clone()),
    ];
    uv_vex::production_manifestless(&uv_vex::Production {
        leg: LEG,
        proj: &proj,
        tmp: tmp.path(),
        mode: uv_vex::Mode::Vendored,
        purl: PYPI_PURL,
        uuids: PYPI_UUIDS,
        registry: &registry,
        uv: &uv,
        patched: &|dir: &Path| {
            site_packages(&dir.join(".venv")).is_some_and(|s| urllib3_patched(&s))
        },
        embedded: vec![(
            "scan --mode vendored --vex",
            vex_e2e_common::VexRun::default()
                .via(vex_e2e_common::VexVia::Scan)
                .arg("--mode")
                .arg("vendored")
                .arg("--ecosystems")
                .arg("pypi")
                .arg("--yes"),
        )],
    });

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
// RubyGems — bundler `path:` source
// ===========================================================================

/// Full vendored install proof for RubyGems: `scan --mode vendored` resolves
/// the free activestorage patch, materializes the patched gem under
/// `.socket/vendor/gem/<uuid>/<name>-<version>/`, and lands the mandatory
/// pair edit (Gemfile exact pin + `path:`, lock `PATH` section +
/// `(= <version>)!` DEPENDENCIES pin). The delivery proof copies ONLY the
/// committable files into a fresh dir and runs a frozen `bundle install`
/// against a fresh empty `BUNDLE_PATH`: activestorage MUST resolve from the
/// vendored path source (its dependencies legitimately come from
/// rubygems.org — a path source only pins the one gem), and the file the
/// patch rewrites must carry the `Socket Community Patch` header.
///
/// # How the leg passes while production's served stub is invalid (D4)
///
/// The `gem-stub-gemspec` artifact production currently serves omits the
/// rubygems-required `summary`/`authors`, so writing it verbatim would make
/// the frozen `bundle install` below exit 1 on every bundler major. The CLI's
/// invalid-stub hardening is what this leg regression-tests live: under the
/// default `--vendor-source auto` the scan detects the defective stub, warns
/// (`vendor_prebuilt_stub_invalid`), and falls back to the LOCAL build
/// (installed gem + locally derived stub), which installs green. That is also
/// why the leg installs in bundler's deployment layout (`vendor/bundle`
/// inside the project): the crawler only sees a project-local install, and
/// the fallback needs the install's `specifications/` stub. Once the
/// server-side stub fix (depscan) deploys and the artifacts rebuild, the same
/// leg exercises the service artifact directly — no test change needed.
///
/// # History
///
/// This leg used to tolerate a `platform_gem_unsupported` vendor refusal:
/// production publishes the gem purl platform-qualified (`?platform=ruby`)
/// and the old vendor gate refused every platform qualifier. #172 fixed the
/// gate to refuse only non-empty, non-`ruby` platforms, and the 2026-08-18
/// catalog republish restored the pinned patch, so the leg was upgraded to
/// this full install proof per its own auto-retire NOTE.
#[test]
#[ignore = "live production API + real rubygems.org. Run with --ignored."]
fn gem_bundler_vendored_install_proof() {
    const LEG: &str = "gem_bundler_vendored_install_proof";
    if !has_command("ruby") || !has_command("bundle") {
        soft_skip!(LEG, "`ruby` and/or `bundle` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    // Deployment layout — `vendor/bundle` INSIDE the project: the gem crawler
    // probes `vendor/bundle/<engine>/*/gems/` in local mode, and the vendor
    // backend's local-build fallback needs the crawler-visible install (the
    // `specifications/` sibling carries the local stub gemspec) while
    // production's served stub is invalid (D4). The app config stays OUTSIDE
    // the project so no `.bundle/config` joins the committable set.
    let bundle_path = proj.join("vendor/bundle").display().to_string();
    let bundle_config = tmp.path().join("bundle-config").display().to_string();
    // mimemagic (pulled via activestorage → marcel) builds against the system
    // shared-mime-info DB, which not every host installs — use the gem's
    // bundled placeholder instead of depending on a host package.
    let env = [
        ("BUNDLE_PATH", bundle_path.as_str()),
        ("BUNDLE_APP_CONFIG", bundle_config.as_str()),
        ("USE_FREEDESKTOP_PLACEHOLDER", "true"),
    ];

    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .expect("write Gemfile");

    if !ok(&bundle(&proj, &["lock"], &env)) {
        soft_skip!(LEG, "`bundle lock` failed");
    }
    let install = bundle(&proj, &["install", "--quiet"], &env);
    if !ok(&install) {
        soft_skip!(LEG, "upstream `bundle install` failed:\n{}", dump(&install));
    }

    // Anti-vacuity: the upstream install must be pristine. `bundle info
    // --path` reports the exact directory bundler resolved for the gem.
    let info = bundle(&proj, &["info", GEM_NAME, "--path"], &env);
    assert!(
        ok(&info),
        "{LEG}: `bundle info {GEM_NAME} --path` failed after the upstream install:\n{}",
        dump(&info)
    );
    let installed_dir = PathBuf::from(String::from_utf8_lossy(&info.stdout).trim());
    // Anti-vacuity over EVERY pinned patch's marker file: whichever patch the
    // server-ranked resolver wires below, its target must start pristine.
    // Capture the pristine bytes now, keyed by file, for the post-install
    // byte-inequality probe.
    let mut pristine_by_file = std::collections::HashMap::new();
    for (_, file) in GEM_PATCHES {
        assert_pristine(&installed_dir.join(file), PATCH_MARKER, LEG);
        pristine_by_file
            .entry(*file)
            .or_insert_with(|| std::fs::read(installed_dir.join(file)).unwrap());
    }
    let gemfile_before = std::fs::read(proj.join("Gemfile")).unwrap();
    let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();

    let env_json = scan_vendored(&proj, &[]);
    let gem_uuids: Vec<&str> = GEM_PATCHES.iter().map(|(u, _)| *u).collect();
    assert_download_uuid(&env_json, &gem_uuids, LEG);
    // Which pinned patch did the resolver wire? The marker probes below are
    // per-patch — each advisory's diff marks a different file.
    let wired_uuid = env_json["download"]["patches"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p["uuid"].as_str())
        .find(|u| gem_uuids.contains(u))
        .expect("assert_download_uuid guarantees a pinned uuid is downloaded")
        .to_string();
    let patched_file_rel = GEM_PATCHES
        .iter()
        .find(|(u, _)| *u == wired_uuid)
        .map(|(_, f)| *f)
        .unwrap();
    let pristine = pristine_by_file[patched_file_rel].clone();
    assert_eq!(
        env_json["download"]["failed"].as_u64().unwrap_or(99),
        0,
        "{LEG}: the gem patch download failed.\nenvelope:\n{env_json:#}"
    );
    // Purl-scoped (NOT run-wide counts): a future free patch on one of the
    // fixture's transitive Rails gems must not red this leg.
    assert_vendor_applied_for(&env_json, &format!("{GEM_NAME}@{GEM_VERSION}"), LEG);

    // Route attribution: EXACTLY one of the two markers must be present for
    // this purl — the service artifact was used (`vendor_prebuilt_downloaded`)
    // or the invalid-served-stub fallback built locally
    // (`vendor_prebuilt_stub_invalid`). Asserting exactly one auto-retires the
    // fallback expectation the moment the depscan stub fix deploys and the
    // rebuilt artifacts serve valid stubs (and catches both-or-neither as a
    // defect either way).
    let route_markers = env_json["vendor"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|e| {
            e["purl"]
                .as_str()
                .map(|p| p.contains(GEM_NAME))
                .unwrap_or(false)
                && matches!(
                    e["errorCode"].as_str(),
                    Some("vendor_prebuilt_stub_invalid") | Some("vendor_prebuilt_downloaded")
                )
        })
        .count();
    assert_eq!(
        route_markers, 1,
        "{LEG}: expected exactly one route marker (vendor_prebuilt_downloaded XOR \
         vendor_prebuilt_stub_invalid) for {GEM_NAME}.\nenvelope:\n{env_json:#}"
    );

    // The committable artifact + the mandatory pair edit.
    let copy_rel = format!(".socket/vendor/gem/{wired_uuid}/{GEM_NAME}-{GEM_VERSION}");
    assert_patched(
        &proj
            .join(&copy_rel)
            .join(patched_file_rel),
        PATCH_MARKER,
        LEG,
    );
    let gemfile = read(&proj.join("Gemfile"));
    assert!(
        gemfile.contains(&format!(
            "gem \"{GEM_NAME}\", \"{GEM_VERSION}\", path: \"{copy_rel}\""
        )),
        "{LEG}: Gemfile line not rewritten to the exact-pin + path: form:\n{gemfile}"
    );
    let lock = read(&proj.join("Gemfile.lock"));
    assert!(
        lock.contains(&format!(
            "PATH\n  remote: {copy_rel}\n  specs:\n    {GEM_NAME} ({GEM_VERSION})"
        )),
        "{LEG}: canonical PATH section missing from Gemfile.lock:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  {GEM_NAME} (= {GEM_VERSION})!")),
        "{LEG}: DEPENDENCIES pin `  {GEM_NAME} (= {GEM_VERSION})!` missing from Gemfile.lock:\n{lock}"
    );

    // DELIVERY PROOF: ONLY the committable files (Gemfile, Gemfile.lock,
    // .socket/ — the leg's BUNDLE_APP_CONFIG lives outside the project, so
    // there is no .bundle/config to commit), a fresh EMPTY BUNDLE_PATH, and
    // a frozen `bundle install`. Frozen mode makes bundler enforce the
    // committed lock — including its vendored PATH source — and fail rather
    // than re-resolve, mirroring docker_e2e_vendor_gem's stage 2. The gem's
    // dependencies come from rubygems.org (a path source pins only the one
    // gem), so the install is online; the point is that activestorage itself
    // can only come from `.socket/vendor/`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Gemfile"), fresh.join("Gemfile")).unwrap();
    std::fs::copy(proj.join("Gemfile.lock"), fresh.join("Gemfile.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_bundle = tmp.path().join("fresh-bundle").display().to_string();
    let fresh_env = [
        ("BUNDLE_PATH", fresh_bundle.as_str()),
        ("BUNDLE_APP_CONFIG", fresh_bundle.as_str()),
        ("BUNDLE_FROZEN", "true"),
        // Same shared-mime-info hazard as the upstream install above.
        ("USE_FREEDESKTOP_PLACEHOLDER", "true"),
    ];
    let lock_committed = std::fs::read(fresh.join("Gemfile.lock")).unwrap();
    let fresh_install = bundle(&fresh, &["install"], &fresh_env);
    assert!(
        ok(&fresh_install),
        "{LEG}: frozen `bundle install` from the committable files failed:\n{}",
        dump(&fresh_install)
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_committed,
        "{LEG}: frozen `bundle install` churned the committed Gemfile.lock"
    );
    // Bundler must have resolved the gem FROM the vendored path source INSIDE
    // the fresh dir, and the bytes it will load must carry the patch marker
    // and differ from the captured pristine registry bytes. (`contains`
    // alone would also match the ORIGINAL project's vendored path;
    // canonicalize both sides — macOS reports tempdirs via /var symlinked to
    // /private/var.)
    let fresh_info = bundle(&fresh, &["info", GEM_NAME, "--path"], &fresh_env);
    assert!(
        ok(&fresh_info),
        "{LEG}: `bundle info {GEM_NAME} --path` failed after the fresh install:\n{}",
        dump(&fresh_info)
    );
    let resolved = String::from_utf8_lossy(&fresh_info.stdout)
        .trim()
        .to_string();
    let resolved_canon = std::fs::canonicalize(&resolved)
        .unwrap_or_else(|e| panic!("{LEG}: cannot canonicalize `{resolved}`: {e}"));
    let fresh_canon = std::fs::canonicalize(&fresh).unwrap();
    assert!(
        resolved_canon.starts_with(&fresh_canon) && resolved.contains(&copy_rel),
        "{LEG}: bundler resolved {GEM_NAME} from `{resolved}`, not the vendored \
         path `{copy_rel}` inside the fresh dir — the pair edit did not take \
         effect in the fresh dir"
    );
    assert_patched(
        &PathBuf::from(&resolved).join(patched_file_rel),
        PATCH_MARKER,
        LEG,
    );
    assert_ne!(
        std::fs::read(PathBuf::from(&resolved).join(patched_file_rel)).unwrap(),
        pristine,
        "{LEG}: the reinstalled bytes equal the PRISTINE registry bytes — the vendored \
         artifact was not the one installed"
    );

    // Manifest-less VEX over the fresh committed checkout (a copy, so the
    // idempotency / revert legs below keep the original project), against
    // the real public patch proxy.
    let vex_dir = tmp.path().join("fresh-vex");
    std::fs::create_dir_all(&vex_dir).unwrap();
    std::fs::copy(fresh.join("Gemfile"), vex_dir.join("Gemfile")).unwrap();
    std::fs::copy(fresh.join("Gemfile.lock"), vex_dir.join("Gemfile.lock")).unwrap();
    copy_dir_recursive(&fresh.join(".socket"), &vex_dir.join(".socket"));
    gem_manifestless_vex(
        LEG,
        &vex_dir,
        &wired_uuid,
        "vendored",
        "vendor_unwired",
        (&gemfile_before, &lock_before),
        &[],
    );

    // Idempotency + revert (mirrors the pip/uv legs; purl-scoped so a future
    // free patch on a transitive gem cannot red the leg).
    let gemfile_wired = std::fs::read(proj.join("Gemfile")).unwrap();
    let lock_wired = std::fs::read(proj.join("Gemfile.lock")).unwrap();
    let env2 = scan_vendored(&proj, &[]);
    assert!(
        vendor_events_for(&env2, GEM_NAME, "applied").is_empty(),
        "{LEG}: re-run must vendor nothing new for {GEM_NAME}:\n{env2:#}"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile")).unwrap(),
        gemfile_wired,
        "{LEG}: re-run must leave the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "{LEG}: re-run must leave Gemfile.lock byte-identical"
    );

    assert!(
        vendor_revert(&proj, LEG) >= 1,
        "{LEG}: at least the {GEM_NAME} entry reverted"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile")).unwrap(),
        gemfile_before,
        "{LEG}: revert must restore the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock_before,
        "{LEG}: revert must restore Gemfile.lock byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "{LEG}: .socket/vendor must be gone after revert"
    );
}

/// Manifest-less VEX over a gem production leg's installed checkout `dir`
/// (the real public patch proxy supplies records; `envs` point the crawler
/// at the leg's BUNDLE_PATH so the installed tree is hash-verified):
/// attested with the ledger kept → attested from the lockfile wiring alone
/// once both ledgers are deleted → `record_unavailable` offline (no
/// ledger) → `unwired` once the Gemfile + lock are reverted to `pristine`
/// (ledger restored), with and without `--no-verify`. Production's
/// vulnerability set is not pinned here: every statement for the purl must
/// be `not_affected` via `uuid` with `marker`.
fn gem_manifestless_vex(
    leg: &str,
    dir: &Path,
    uuid: &str,
    marker: &str,
    unwired: &str,
    pristine: (&[u8], &[u8]),
    envs: &[(&str, &str)],
) {
    use vex_e2e_common::{
        assert_not_attested, run_vex, statements_for, strip_ledgers, strip_manifest, VexRun,
    };
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
    let mut base = VexRun {
        product: Some("pkg:gem/app@1.0.0".into()),
        ..VexRun::default()
    };
    for (k, v) in envs {
        base = base.env(*k, *v);
    }
    let attested = |run: &VexRun, cell: &str| {
        let out = run_vex(&vex_e2e_common::binary(), dir, run);
        assert_eq!(out.code, Some(0), "{leg} manifest-less vex ({cell}): {out}");
        let statements = statements_for(out.doc(), &purl);
        assert!(
            !statements.is_empty(),
            "{leg} ({cell}): {purl} not attested: {out}"
        );
        let part = format!("Patched via Socket patch {uuid} ({marker})");
        for st in statements {
            assert_eq!(st["status"], "not_affected", "{leg} ({cell}): {st:#}");
            let impact = st["impact_statement"].as_str().unwrap_or_default();
            // The expected clause embeds the patch uuid: name it, never print
            // it (CodeQL rust/cleartext-logging).
            assert!(
                impact.split("; ").any(|p| p == part),
                "{leg} ({cell}): impact {impact:?} lacks the wired patch's ({marker}) clause"
            );
        }
    };
    let ledgers = dir.join(".socket/vendor");
    let saved: Vec<(std::ffi::OsString, Vec<u8>)> = std::fs::read_dir(&ledgers)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_file())
                .map(|e| (e.file_name(), std::fs::read(e.path()).unwrap()))
                .collect()
        })
        .unwrap_or_default();
    strip_manifest(dir);
    attested(&base, "ledger kept");
    strip_ledgers(dir);
    attested(&base, "ledgers deleted");
    let mut offline = base.clone();
    offline.offline = true;
    let out = run_vex(&vex_e2e_common::binary(), dir, &offline);
    assert_eq!(out.code, Some(1), "{leg} offline, no ledger: {out}");
    assert_not_attested(&out.envelope, &purl, "record_unavailable");
    for (name, bytes) in &saved {
        std::fs::write(ledgers.join(name), bytes).unwrap();
    }
    std::fs::write(dir.join("Gemfile"), pristine.0).unwrap();
    std::fs::write(dir.join("Gemfile.lock"), pristine.1).unwrap();
    for no_verify in [false, true] {
        let mut run = base.clone();
        run.no_verify = no_verify;
        let out = run_vex(&vex_e2e_common::binary(), dir, &run);
        assert_eq!(
            out.code,
            Some(1),
            "{leg} reverted no_verify={no_verify}: {out}"
        );
        assert_not_attested(&out.envelope, &purl, unwired);
    }
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

    // Manifest-less VEX: nothing was wired for deno, so without a manifest
    // there is nothing to attest (exit 2, `manifest_not_found`) — offline,
    // no document written.
    let _ = std::fs::remove_file(proj.join(".socket/manifest.json"));
    let out = vex_e2e_common::run_vex(
        &binary(),
        &proj,
        &vex_e2e_common::VexRun {
            product: Some("pkg:npm/deno-app@1.0.0".to_string()),
            ..vex_e2e_common::VexRun::offline()
        },
    );
    assert_eq!(out.code, Some(2), "{LEG}: manifest-less vex: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{LEG}: {out}"
    );
    assert!(out.doc.is_none(), "{LEG}: no document: {out}");
}

/// cargo, maven, nuget and composer all implement vendored mode, but
/// production publishes no free-tier patches for them. (cargo used to have a
/// full delivery proof — retired 2026-09-01 when production's free cargo tier
/// emptied.) This probes production every run and reports the moment that
/// changes, so coverage can be extended deliberately rather than by accident.
/// It does not fail when patches appear;
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
            "canary_unpublished_vendored_ecosystems: cargo / maven / nuget / composer still \
             have no free-tier published patches — their vendored-mode legs remain untestable \
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
