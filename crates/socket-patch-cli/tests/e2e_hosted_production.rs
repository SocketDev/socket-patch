//! Hosted-mode (`scan --mode hosted`) end-to-end tests against **production**.
//!
//! Every other hosted-mode capstone in this repo (`e2e_redirect_*_build.rs`)
//! points the CLI at a wiremock stand-in for `patch.socket.dev`. This suite is
//! the opposite: it contacts the **real** Socket production endpoints and the
//! **real** upstream registries, with **no mocking anywhere**, and proves the
//! full hosted loop for each ecosystem and package manager:
//!
//!   1. install a pinned, known-vulnerable dependency with a real package
//!      manager, from its real upstream registry;
//!   2. assert the installed bytes are **pristine** (anti-vacuity — without
//!      this every "patched" assertion below could pass on a no-op);
//!   3. run `socket-patch scan --mode hosted --json --yes`, which resolves a
//!      hosted patch reference from `patches-api.socket.dev` and rewrites the
//!      lockfile / registry config to point at `patch.socket.dev`;
//!   4. assert the rewrite landed (host + patch UUID present in the lock, and
//!      the integrity pin was replaced);
//!   5. **wipe the install tree and reinstall from the rewritten lock alone**,
//!      letting the package manager itself fetch from `patch.socket.dev` and
//!      verify the integrity pin it was given;
//!   6. assert the reinstalled bytes now carry the patch.
//!
//! Step 5 is the point of the suite. It is the only test in the repo where a
//! third-party package manager — not socket-patch — downloads a Socket-hosted
//! artifact and independently verifies its checksum.
//!
//! # Required production patches
//!
//! These tests are pinned to specific patches that must stay published and
//! **free-tier** on `patches-api.socket.dev`. If Socket unpublishes one, the
//! `preflight_required_patches_are_published` test fails first and names it,
//! rather than letting a downstream leg fail with a confusing symptom.
//!
//! | Ecosystem | PURL | Patch UUID | Advisory |
//! |-----------|------|------------|----------|
//! | npm    | `pkg:npm/minimist@1.2.2`        | `80630680-4da6-45f9-bba8-b888e0ffd58c` | GHSA-xvch-5gv4-984h (CVE-2021-44906) |
//! | PyPI   | `pkg:pypi/urllib3@1.26.18`      | *any of three* (see [`PYPI_UUIDS`])    | GHSA-gm62-xv2j-4w53 &co |
//! | Cargo  | `pkg:cargo/traitobject@0.1.1`   | `cf2e6f58-d9fa-4096-9151-c34afa717f89` | GHSA-pp8r-vv2j-9j5v |
//! | gem    | `pkg:gem/activestorage@7.0.2.2` | `2535d43d-67ce-4944-be27-c19e113997fb` | GHSA-w749-p3v6-hccq |
//!
//! `docs/testing/hosted-production-e2e.md` explains how these were chosen and
//! how to re-pick one if it is ever withdrawn.
//!
//! # Ecosystems with no coverage, and why
//!
//! * **maven / nuget / composer** — hosted mode is implemented and documented
//!   for all three, but production currently publishes **zero** free-tier
//!   patches for them, so there is nothing real to redirect to. Rather than
//!   silently skipping, [`canary_unpublished_ecosystems`] probes production
//!   every run and tells us the moment that changes.
//! * **golang** — hosted mode is refused **by design**
//!   (`docs/design/golang-hosted-no-go.md`). Covered as a negative assertion.
//! * **deno** — hosted mode is not supported. Covered as a negative assertion.
//!
//! # Prerequisites
//!
//! Toolchains (each leg soft-skips if its own toolchain is absent, unless
//! `SOCKET_PATCH_HOSTED_E2E_STRICT=1`): `npm`, `pnpm`, `yarn` (classic),
//! `corepack` (berry), `bun`, `uv`, `cargo`, `ruby` + `bundle`, `go`.
//!
//! Network egress to: `patches-api.socket.dev`, `patch.socket.dev`,
//! `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`,
//! `static.crates.io`, `index.crates.io`, `rubygems.org`.
//!
//! No API token is used or needed — the suite deliberately runs against the
//! **free public proxy**, which is the surface every unauthenticated user
//! gets. `SOCKET_API_TOKEN` is scrubbed from the child environment.
//!
//! # Running
//!
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_hosted_production -- --ignored
//!
//! # CI (required job): turn every soft-skip into a hard failure, so a missing
//! # toolchain can never report green on a required check.
//! SOCKET_PATCH_HOSTED_E2E_STRICT=1 \
//!   cargo test -p socket-patch-cli --test e2e_hosted_production -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

// ---------------------------------------------------------------------------
// Production endpoints + required-patch catalog
// ---------------------------------------------------------------------------

/// The free public patch proxy. Deliberately hard-coded rather than read from
/// the environment: this suite's entire purpose is to exercise *production*,
/// and an ambient `SOCKET_PROXY_URL` pointing at staging would let it pass
/// while proving nothing.
const PROXY: &str = "https://patches-api.socket.dev";

/// The host every hosted-mode rewrite must point the package manager at.
const PATCH_HOST: &str = "patch.socket.dev";

const NPM_PURL: &str = "pkg:npm/minimist@1.2.2";
const NPM_NAME: &str = "minimist";
const NPM_VERSION: &str = "1.2.2";
const NPM_UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

const PYPI_PURL: &str = "pkg:pypi/urllib3@1.26.18";
const PYPI_NAME: &str = "urllib3";
const PYPI_VERSION: &str = "1.26.18";
/// urllib3 1.26.18 carries **three** distinct free patches (one per advisory).
/// Which one the resolver selects is a server-side ordering detail, so the
/// tests assert "one of these" rather than pinning a single UUID — pinning one
/// would make the suite red on an unrelated server-side reorder.
const PYPI_UUIDS: &[&str] = &[
    "de58c8b8-796c-4b6d-8a48-539b5563db76",
    "26242e35-f867-4da8-8789-f0d2ea49e0f1",
    "e828efa5-5c6d-43f3-9909-03f5ac232b98",
];

const CARGO_PURL: &str = "pkg:cargo/traitobject@0.1.1";
const CARGO_NAME: &str = "traitobject";
const CARGO_VERSION: &str = "0.1.1";
const CARGO_UUID: &str = "cf2e6f58-d9fa-4096-9151-c34afa717f89";
/// The traitobject patch annotates `src/lib.rs` with its advisory ID (the
/// crate is unmaintained; the patch documents that and fixes deprecations).
/// Cargo crates are not rewritten with the `// Socket Community Patch` header
/// that npm/PyPI artifacts carry, so this is the marker to look for.
const CARGO_MARKER: &str = "GHSA-pp8r-vv2j-9j5v";

const GEM_PURL: &str = "pkg:gem/activestorage@7.0.2.2";
const GEM_NAME: &str = "activestorage";
const GEM_VERSION: &str = "7.0.2.2";
const GEM_UUID: &str = "2535d43d-67ce-4944-be27-c19e113997fb";

/// Header the patch service injects into patched npm / PyPI source files.
const PATCH_MARKER: &str = "Socket Community Patch";

/// Ecosystems where hosted mode is implemented but production has no free
/// patches to exercise it with. [`canary_unpublished_ecosystems`] watches
/// these so coverage can be extended the moment one lights up.
const UNPUBLISHED_ECOSYSTEMS: &[(&str, &[&str])] = &[
    (
        "maven",
        &[
            "pkg:maven/org.apache.logging.log4j/log4j-core",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
            "pkg:maven/org.yaml/snakeyaml",
            "pkg:maven/commons-io/commons-io",
        ],
    ),
    (
        "nuget",
        &[
            "pkg:nuget/Newtonsoft.Json",
            "pkg:nuget/System.Text.Json",
            "pkg:nuget/SharpZipLib",
            "pkg:nuget/RestSharp",
        ],
    ),
    (
        "composer",
        &[
            "pkg:composer/guzzlehttp/guzzle",
            "pkg:composer/symfony/http-kernel",
            "pkg:composer/laravel/framework",
            "pkg:composer/monolog/monolog",
        ],
    ),
];

// ---------------------------------------------------------------------------
// Strictness + skip policy
// ---------------------------------------------------------------------------

/// In CI this suite backs a **required** status check, so a leg that quietly
/// returns early because a toolchain is missing would report green while
/// proving nothing. `SOCKET_PATCH_HOSTED_E2E_STRICT=1` converts every soft
/// skip into a hard failure. Locally it stays off so a developer without,
/// say, `bun` can still run the rest.
fn strict() -> bool {
    std::env::var("SOCKET_PATCH_HOSTED_E2E_STRICT")
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
                 SOCKET_PATCH_HOSTED_E2E_STRICT=1 forbids skipping — a required \
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
    // `go` has no `--version` — it takes `go version` as a subcommand and
    // errors with "flag provided but not defined: -version" otherwise. Probing
    // it the usual way silently skips the golang leg on a machine that has Go.
    let probe: &[&str] = if cmd == "go" {
        &["version"]
    } else {
        &["--version"]
    };
    Command::new(cmd)
        .args(probe)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The three legacy `SOCKET_PATCH_*` names still honored at runtime via
/// `socket_patch_core::env_compat` — not in the clap-bound lists, so they need
/// scrubbing separately.
const LEGACY_ENV_VARS: &[&str] = &[
    "SOCKET_PATCH_PROXY_URL",
    "SOCKET_PATCH_DEBUG",
    "SOCKET_PATCH_TELEMETRY_DISABLED",
];

/// Run the CLI with a hermetically pinned environment.
///
/// The scrub matters more here than in any offline suite. An ambient
/// `SOCKET_PROXY_URL` or `SOCKET_API_URL` would silently point the run at
/// staging — and every assertion below would still pass, proving nothing about
/// production. An ambient `SOCKET_API_TOKEN` would move the run off the free
/// public proxy that this suite exists to cover. The hostile seeds below are
/// removed by the same loop that removes the real ones, so if the scrub is
/// ever dropped the seeds turn the suite red immediately instead of letting a
/// developer's ambient shell decide what got tested.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .current_dir(cwd)
        .env("SOCKET_GLOBAL", "true")
        .env("SOCKET_GLOBAL_PREFIX", "/nonexistent")
        .env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_SAVE_ONLY", "true")
        .env("SOCKET_OFFLINE", "true")
        .env("SOCKET_API_TOKEN", "hostile-seed-must-be-scrubbed")
        .env("SOCKET_PROXY_URL", "http://127.0.0.1:1/hostile")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json");
    for var in GLOBAL_ARG_ENV_VARS
        .iter()
        .chain(LOCAL_ARG_ENV_VARS)
        .chain(LEGACY_ENV_VARS)
    {
        cmd.env_remove(var);
    }
    let out: Output = cmd.output().expect("failed to execute socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// `scan --mode hosted --json --yes` in `cwd`, asserting a clean exit and a
/// `"status": "success"` envelope. Returns the parsed envelope.
fn scan_hosted(cwd: &Path, extra: &[&str]) -> serde_json::Value {
    let mut args: Vec<&str> = vec!["scan", "--mode", "hosted", "--json", "--yes"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run(cwd, &args);
    assert_eq!(
        code, 0,
        "scan --mode hosted failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("scan --mode hosted did not emit JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(
        env["status"].as_str(),
        Some("success"),
        // Exit 0 alone is not enough: the envelope carries the real verdict.
        "scan --mode hosted did not report success.\nenvelope:\n{env:#}\nstderr:\n{stderr}"
    );
    env
}

/// Assert the hosted redirect actually rewrote something, and return the list
/// of rewritten files.
///
/// `redirected >= 1` is the anti-vacuity guard: a run that discovered nothing
/// also exits 0 with `"status": "success"`, so without this a broken crawler
/// would look identical to a working redirect.
fn assert_redirected(env: &serde_json::Value, expect_file: &str) -> Vec<String> {
    let redirect = &env["redirect"];
    assert!(
        !redirect.is_null(),
        "scan --mode hosted emitted no `redirect` sub-object at all. The CLI \
         omits it entirely when discovery found nothing, so this means the \
         crawler did not see the installed dependency.\nenvelope:\n{env:#}"
    );
    assert_eq!(
        redirect["mode"].as_str(),
        Some("hosted"),
        "redirect sub-object missing or not hosted mode:\n{env:#}"
    );
    let n = redirect["redirected"].as_u64().unwrap_or(0);
    assert!(
        n >= 1,
        "hosted redirect rewrote nothing — the patch is published and the \
         package is installed, so 0 means discovery or reference resolution \
         broke.\nenvelope:\n{env:#}"
    );
    let files: Vec<String> = redirect["rewrittenFiles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        files.iter().any(|f| f == expect_file),
        "expected `{expect_file}` among rewrittenFiles, got {files:?}\nenvelope:\n{env:#}"
    );
    files
}

/// How many dependencies a hosted run redirected.
///
/// `scan --mode hosted` omits the whole `redirect` sub-object when discovery
/// turned up nothing — a plain scan envelope comes back instead. For the
/// documented-unsupported ecosystems (golang, deno) "no redirect object" and
/// `"redirected": 0` are the same verdict, so normalize them.
fn redirected_count(env: &serde_json::Value) -> u64 {
    let redirect = &env["redirect"];
    if redirect.is_null() {
        return 0;
    }
    redirect["redirected"].as_u64().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Toolchain invocation
// ---------------------------------------------------------------------------

/// Run an external package manager. Returns the `Output` without asserting, so
/// callers can distinguish "the registry was unreachable" (soft-skip material
/// during fixture setup) from "the install of the redirected lock failed"
/// (always a hard failure — that is the thing under test).
fn tool(cwd: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    // Keep every toolchain's cache inside the fixture so the reinstall leg
    // starts genuinely cold and cannot be satisfied from a warm host cache
    // holding the *pristine* artifact.
    for (k, v) in env {
        cmd.env(k, v);
    }
    // A `VIRTUAL_ENV` inherited from the developer's shell makes uv install
    // into the wrong interpreter.
    cmd.env_remove("VIRTUAL_ENV");
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"))
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

/// Assert `path` exists and does NOT yet carry a patch marker.
///
/// Every "the reinstall delivered a patched artifact" assertion downstream is
/// vacuous without this: if the upstream registry ever started shipping the
/// patched bytes, or a warm cache leaked them in, the test would pass while
/// proving nothing about hosted mode.
fn assert_pristine(path: &Path, marker: &str, what: &str) {
    assert!(
        path.exists(),
        "{what}: expected the pristine install at {} — fixture setup did not \
         produce the file under test",
        path.display()
    );
    let body = read(path);
    assert!(
        !body.contains(marker),
        "{what}: the freshly-installed upstream artifact at {} ALREADY contains \
         `{marker}` before any redirect ran. Every downstream assertion would be \
         vacuous. Check for a warm package-manager cache leaking patched bytes.",
        path.display()
    );
}

fn assert_patched(path: &Path, marker: &str, what: &str) {
    assert!(
        path.exists(),
        "{what}: reinstall from the redirected lock did not produce {}",
        path.display()
    );
    let body = read(path);
    assert!(
        body.contains(marker),
        "{what}: reinstalled from the redirected lock, but {} does not contain \
         `{marker}` — the package manager fetched something, and it was not the \
         patched artifact.",
        path.display()
    );
}

/// Assert a rewritten lockfile points at the hosted patch server for the
/// expected patch.
///
/// Deliberately does NOT assert the grant token embedded in the URL: the
/// service mints a fresh one per reference request, so pinning it would make
/// the suite red on the second run.
fn assert_hosted_pin(lock_body: &str, uuids: &[&str], what: &str) {
    assert!(
        lock_body.contains(PATCH_HOST),
        "{what}: rewritten lock does not reference {PATCH_HOST}:\n{lock_body}"
    );
    assert!(
        uuids.iter().any(|u| lock_body.contains(u)),
        "{what}: rewritten lock references {PATCH_HOST} but carries none of the \
         expected patch UUIDs {uuids:?} — the redirect resolved a different \
         patch than the catalog pins.\n{lock_body}"
    );
}

// ---------------------------------------------------------------------------
// Production reachability probes (used by the preflight + canary tests)
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

/// `GET /patch/by-package/<purl>` returning, per patch, the `(uuid,
/// advisory_count)` pair that drives merge-state inference.
async fn published_patch_advisory_counts(purl: &str) -> Result<Vec<(String, usize)>, String> {
    let url = format!("{PROXY}/patch/by-package/{}", urlencode(purl));
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let body = resp
        .text()
        .await
        .map_err(|e| format!("GET {url}: reading body: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("GET {url}: bad JSON ({e}):\n{body}"))?;
    Ok(v["patches"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    Some((
                        p["uuid"].as_str()?.to_string(),
                        p["vulnerabilities"].as_object()?.len(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// `GET /patch/by-package/<purl>` returning `(uuid, publishedAt)` pairs.
/// Sibling of [`published_uuids`] for tests that care about patch metadata
/// rather than just which UUIDs exist.
async fn published_patch_dates(purl: &str) -> Result<Vec<(String, String)>, String> {
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
                .filter_map(|p| {
                    Some((
                        p["uuid"].as_str()?.to_string(),
                        p["publishedAt"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Percent-encode a PURL for use as a single path segment. `reqwest` will not
/// do this for us — a raw `pkg:npm/...` would be split into path segments and
/// 404.
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
/// This runs first (alphabetically it sorts under `preflight_`) so that a
/// withdrawn patch produces one clear failure naming the PURL, instead of N
/// confusing downstream failures that look like CLI regressions.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API: contacts patches-api.socket.dev. Run with --ignored."]
async fn preflight_required_patches_are_published() {
    // (purl, acceptable uuids)
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
                "{purl}: production publishes NO free patches for this package \
                 anymore. This suite is pinned to it — pick a replacement and \
                 update both the catalog constants in this file and \
                 docs/testing/hosted-production-e2e.md."
            )),
            Ok(found) => {
                if !expected.iter().any(|u| found.iter().any(|f| f == u)) {
                    failures.push(format!(
                        "{purl}: expected one of {expected:?} but production now \
                         publishes {found:?}. The patch was replaced — update the \
                         catalog constants in this file."
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

/// Canary: production must keep naming advisories, because merge state is
/// **inferred** from the advisory count rather than read off a flag.
///
/// `api::ranking` ranks a patch that remediates several advisories above one
/// that remediates a single advisory. The whole signal is the size of the
/// `vulnerabilities` map. If production ever stopped populating it — shipping
/// patches with an empty map, or moving advisory ids somewhere else — every
/// patch would collapse to coverage 0, the merge rung would go permanently
/// inert, and selection would silently fall through to recency with no error
/// anywhere.
///
/// This asserts only that the signal EXISTS (every patch names >= 1
/// advisory), never how many. Production publishes no merged patches today —
/// all patches sampled cover exactly one advisory — and the day that changes
/// is not a regression, so a count of >= 2 must not fail this test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API: contacts patches-api.socket.dev. Run with --ignored."]
async fn canary_patches_name_advisories_so_merge_state_is_inferable() {
    let mut failures: Vec<String> = Vec::new();
    let mut coverage_seen: Vec<(String, String, usize)> = Vec::new();

    for purl in [NPM_PURL, PYPI_PURL, CARGO_PURL, GEM_PURL] {
        match published_patch_advisory_counts(purl).await {
            Err(e) => failures.push(format!("{purl}: production probe failed: {e}")),
            Ok(patches) if patches.is_empty() => {
                failures.push(format!("{purl}: production publishes no patches"))
            }
            Ok(patches) => {
                for (uuid, count) in patches {
                    if count == 0 {
                        failures.push(format!(
                            "{purl}: patch {uuid} names ZERO advisories — merge-state \
                             inference has no signal to work with, so the merge rung in \
                             api::ranking is dead for this patch"
                        ));
                    }
                    coverage_seen.push((purl.to_string(), uuid, count));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "merge-state inference signal is missing from production:\n  - {}",
        failures.join("\n  - ")
    );

    // Informational: surfaces the day production starts publishing merged
    // patches, without failing when it does.
    let merged: Vec<_> = coverage_seen.iter().filter(|(_, _, c)| *c >= 2).collect();
    if merged.is_empty() {
        eprintln!(
            "[info] production publishes no merged patches yet ({} patches, all single-advisory)",
            coverage_seen.len()
        );
    } else {
        eprintln!("[info] production now publishes merged patches: {merged:?}");
    }
}

/// Canary: production's `publishedAt` must stay a **per-patch** date.
///
/// Patch selection ranks by recency (`socket_patch_core::api::ranking`), and
/// that rung is only meaningful if `publishedAt` describes the patch rather
/// than the upstream package release. If the server ever started emitting the
/// package's release date, every patch for a given PURL would collapse to one
/// value, recency would silently stop discriminating, and selection would
/// quietly fall through to the UUID tiebreak — a wrong answer with no error
/// anywhere. Nothing else in the suite would catch that.
///
/// `PYPI_PURL` is the probe because production publishes three patches for
/// it (see [`PYPI_UUIDS`]). Two assertions:
///
///  1. the dates are not all identical — impossible for a package-level date;
///  2. no patch date equals the package's own upload time on PyPI.
///
/// (2) is skipped, with a note, if pypi.org is unreachable — a PyPI outage is
/// not a socket-patch regression. (1) is unconditional.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API: contacts patches-api.socket.dev + pypi.org. Run with --ignored."]
async fn canary_published_at_is_a_patch_date_not_a_package_date() {
    let patches = published_patch_dates(PYPI_PURL)
        .await
        .unwrap_or_else(|e| panic!("production probe failed for {PYPI_PURL}: {e}"));

    assert!(
        patches.len() >= 2,
        "{PYPI_PURL} must publish >=2 patches for this canary to have teeth; \
         production returned {}. Re-pick a multi-patch PURL and update this test.",
        patches.len()
    );

    let distinct: std::collections::HashSet<&str> =
        patches.iter().map(|(_, d)| d.as_str()).collect();
    assert!(
        distinct.len() > 1,
        "all {} patches for {PYPI_PURL} share one publishedAt ({:?}). That is the \
         signature of a PACKAGE-level date: recency ranking has stopped \
         discriminating and selection is falling through to the UUID tiebreak.\n\
         patches: {patches:#?}",
        patches.len(),
        distinct
    );

    // (2) Cross-check against the real upstream release date.
    let pypi_url = format!("https://pypi.org/pypi/{PYPI_NAME}/json");
    let Ok(resp) = reqwest::Client::new().get(&pypi_url).send().await else {
        eprintln!("[skip] pypi.org unreachable; distinct-dates assertion still enforced");
        return;
    };
    let Ok(body) = resp.text().await else {
        eprintln!("[skip] pypi.org body unreadable; distinct-dates assertion still enforced");
        return;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        eprintln!("[skip] pypi.org returned non-JSON; distinct-dates assertion still enforced");
        return;
    };
    let uploads: Vec<String> = v["releases"][PYPI_VERSION]
        .as_array()
        .map(|files| {
            files
                .iter()
                .filter_map(|f| f["upload_time_iso_8601"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if uploads.is_empty() {
        eprintln!("[skip] pypi.org listed no upload times for {PYPI_NAME} {PYPI_VERSION}");
        return;
    }
    // PyPI stamps ISO-8601; the patch API stamps RFC 2822. They cannot be
    // compared as strings, so compare the calendar DATE via the same parser
    // the ranking uses.
    use socket_patch_core::utils::date::parse_timestamp_secs;
    let upload_days: std::collections::HashSet<u64> = uploads
        .iter()
        .filter_map(|u| parse_timestamp_secs(u))
        .map(|s| s / 86_400)
        .collect();
    for (uuid, published) in &patches {
        let Some(secs) = parse_timestamp_secs(published) else {
            panic!(
                "production publishedAt {published:?} (patch {uuid}) does not parse — \
                    utils::date must handle every format the API emits"
            );
        };
        assert!(
            !upload_days.contains(&(secs / 86_400)),
            "patch {uuid} reports publishedAt {published:?}, which falls on the same day \
             {PYPI_NAME} {PYPI_VERSION} was uploaded to PyPI ({uploads:?}). That strongly \
             suggests the field switched to the PACKAGE release date."
        );
    }
}

// ===========================================================================
// npm ecosystem — five package managers, five lockfile flavors
// ===========================================================================

/// Shared npm-family fixture: a temp project with `minimist@1.2.2` pinned.
struct NpmFixture {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    cache: PathBuf,
}

fn npm_fixture(name: &str) -> NpmFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join(format!("{name}-cache"));
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::create_dir_all(&cache).expect("mkdir cache");
    // Hand-written rather than `npm init -y`, which rejects tempdir names.
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"hosted-e2e","version":"0.0.0","private":true,"dependencies":{{"{NPM_NAME}":"{NPM_VERSION}"}}}}"#
        ),
    )
    .expect("write package.json");
    NpmFixture {
        _tmp: tmp,
        proj,
        cache,
    }
}

fn minimist_entry(proj: &Path) -> PathBuf {
    proj.join("node_modules").join(NPM_NAME).join("index.js")
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn npm_package_lock_hosted_install_proof() {
    const LEG: &str = "npm_package_lock_hosted_install_proof";
    if !has_command("npm") {
        soft_skip!(LEG, "`npm` not on PATH");
    }
    let fx = npm_fixture("npm");
    let cache = fx.cache.display().to_string();
    let env = [("npm_config_cache", cache.as_str())];

    let install = tool(
        &fx.proj,
        "npm",
        &["install", "--no-audit", "--no-fund", "--ignore-scripts"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `npm install` failed:\n{}", dump(&install));
    }

    assert_pristine(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "package-lock.json");

    let lock = read(&fx.proj.join("package-lock.json"));
    assert_hosted_pin(&lock, &[NPM_UUID], LEG);
    assert!(
        !lock.contains("registry.npmjs.org/minimist/-/minimist-1.2.2.tgz"),
        "{LEG}: the upstream minimist tarball URL survived the rewrite — npm \
         would still install the unpatched artifact:\n{lock}"
    );

    // The proof: wipe node_modules and let npm install from the rewritten lock
    // alone. npm verifies the `integrity` pin it was handed, so a success here
    // means patch.socket.dev served bytes matching the hash the API published.
    std::fs::remove_dir_all(fx.proj.join("node_modules")).expect("rm node_modules");
    let ci = tool(
        &fx.proj,
        "npm",
        &["ci", "--no-audit", "--no-fund", "--ignore-scripts"],
        &env,
    );
    assert!(
        ok(&ci),
        "{LEG}: `npm ci` from the redirected lock failed — npm could not fetch \
         or could not verify the hosted artifact:\n{}",
        dump(&ci)
    );
    assert_patched(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn npm_shrinkwrap_hosted_redirect() {
    const LEG: &str = "npm_shrinkwrap_hosted_redirect";
    if !has_command("npm") {
        soft_skip!(LEG, "`npm` not on PATH");
    }
    let fx = npm_fixture("shrinkwrap");
    let cache = fx.cache.display().to_string();
    let env = [("npm_config_cache", cache.as_str())];

    let install = tool(
        &fx.proj,
        "npm",
        &["install", "--no-audit", "--no-fund", "--ignore-scripts"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `npm install` failed:\n{}", dump(&install));
    }
    let shrink = tool(&fx.proj, "npm", &["shrinkwrap"], &env);
    if !ok(&shrink) {
        soft_skip!(LEG, "`npm shrinkwrap` failed:\n{}", dump(&shrink));
    }
    assert!(
        fx.proj.join("npm-shrinkwrap.json").exists(),
        "{LEG}: npm shrinkwrap did not produce npm-shrinkwrap.json"
    );

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "npm-shrinkwrap.json");
    assert_hosted_pin(
        &read(&fx.proj.join("npm-shrinkwrap.json")),
        &[NPM_UUID],
        LEG,
    );
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn pnpm_hosted_install_proof() {
    const LEG: &str = "pnpm_hosted_install_proof";
    if !has_command("pnpm") {
        soft_skip!(LEG, "`pnpm` not on PATH");
    }
    let fx = npm_fixture("pnpm");
    let store = fx.cache.display().to_string();
    let env = [
        ("PNPM_HOME", store.as_str()),
        ("XDG_CACHE_HOME", store.as_str()),
    ];
    let store_arg = format!("--store-dir={store}");

    let install = tool(
        &fx.proj,
        "pnpm",
        &["install", "--ignore-scripts", &store_arg],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `pnpm install` failed:\n{}", dump(&install));
    }
    // pnpm's node_modules is a symlink farm over .pnpm/; resolve through it.
    let entry = fx.proj.join("node_modules").join(NPM_NAME).join("index.js");
    assert_pristine(&entry, PATCH_MARKER, LEG);

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "pnpm-lock.yaml");
    assert_hosted_pin(&read(&fx.proj.join("pnpm-lock.yaml")), &[NPM_UUID], LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).expect("rm node_modules");
    let reinstall = tool(
        &fx.proj,
        "pnpm",
        &[
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            &store_arg,
        ],
        &env,
    );

    if ok(&reinstall) {
        assert_patched(&entry, PATCH_MARKER, LEG);
        return;
    }

    // pnpm 11 added a lockfile supply-chain policy that compares every entry's
    // tarball URL against the registry's published metadata. Hosted mode
    // deliberately rewrites that URL to patch.socket.dev, so the policy
    // rejects the lockfile:
    //
    //   [ERR_PNPM_TARBALL_URL_MISMATCH] minimist@1.2.2 has a tarball URL
    //   (https://patch.socket.dev/...) that does not match the registry's
    //   published metadata (https://registry.npmjs.org/minimist/-/...)
    //
    // `--trust-lockfile` is pnpm's documented opt-out. This is a real
    // compatibility gap in socket-patch's pnpm hosted mode, not a test bug:
    // the CLI should emit a `redirect_pnpm_*` warning naming the flag, the way
    // it already does for the gem CHECKSUMS and Rush repo-state cases. Until
    // it does, this leg proves the artifact IS correctly served and installs
    // cleanly once the policy is relaxed — and it fails loudly if the failure
    // is anything OTHER than that known policy rejection.
    let detail = dump(&reinstall);
    assert!(
        detail.contains("ERR_PNPM_TARBALL_URL_MISMATCH"),
        "{LEG}: `pnpm install --frozen-lockfile` from the redirected lock \
         failed for an UNEXPECTED reason (not the known pnpm 11 tarball-URL \
         supply-chain policy). This is a new regression:\n{detail}"
    );
    println!(
        "KNOWN COMPAT GAP {LEG}: pnpm 11's lockfile supply-chain policy rejects \
         hosted-mode rewrites with ERR_PNPM_TARBALL_URL_MISMATCH. Retrying with \
         `--trust-lockfile` (pnpm's documented opt-out). socket-patch should \
         warn about this during `scan --mode hosted` on a pnpm project."
    );

    std::fs::remove_dir_all(fx.proj.join("node_modules")).ok();
    let trusted = tool(
        &fx.proj,
        "pnpm",
        &[
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--trust-lockfile",
            &store_arg,
        ],
        &env,
    );
    assert!(
        ok(&trusted),
        "{LEG}: even `pnpm install --trust-lockfile` failed against the \
         redirected lock — the hosted artifact itself is not installable:\n{}",
        dump(&trusted)
    );
    assert_patched(&entry, PATCH_MARKER, LEG);
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn yarn_classic_hosted_install_proof() {
    const LEG: &str = "yarn_classic_hosted_install_proof";
    if !has_command("yarn") {
        soft_skip!(LEG, "`yarn` not on PATH");
    }
    let fx = npm_fixture("yarn1");
    // Without an explicit `packageManager` pin, corepack resolves a bare
    // `yarn` to the latest berry (4.x) even when a classic yarn is on PATH —
    // which silently turned this leg into a duplicate of the berry one.
    std::fs::write(
        fx.proj.join("package.json"),
        format!(
            r#"{{"name":"hosted-e2e","version":"0.0.0","private":true,"packageManager":"yarn@1.22.22","dependencies":{{"{NPM_NAME}":"{NPM_VERSION}"}}}}"#
        ),
    )
    .expect("write package.json");

    let cache = fx.cache.display().to_string();
    let env = [
        ("YARN_CACHE_FOLDER", cache.as_str()),
        ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"),
    ];

    let version = tool(&fx.proj, "yarn", &["--version"], &env);
    let major = String::from_utf8_lossy(&version.stdout).trim().to_string();
    if !ok(&version) || !major.starts_with('1') {
        soft_skip!(
            LEG,
            "could not resolve yarn classic in this fixture (got version \
             {major:?}) — corepack may be unable to fetch yarn@1.22.22"
        );
    }

    let install = tool(&fx.proj, "yarn", &["install", "--ignore-scripts"], &env);
    if !ok(&install) {
        soft_skip!(
            LEG,
            "upstream classic `yarn install` failed:\n{}",
            dump(&install)
        );
    }
    if !fx.proj.join("yarn.lock").exists() {
        soft_skip!(LEG, "`yarn install` produced no yarn.lock");
    }
    assert_pristine(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "yarn.lock");
    assert_hosted_pin(&read(&fx.proj.join("yarn.lock")), &[NPM_UUID], LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).expect("rm node_modules");
    std::fs::remove_dir_all(&fx.cache).ok();
    let reinstall = tool(
        &fx.proj,
        "yarn",
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &env,
    );
    assert!(
        ok(&reinstall),
        "{LEG}: `yarn install --frozen-lockfile` from the redirected lock \
         failed:\n{}",
        dump(&reinstall)
    );
    assert_patched(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn yarn_berry_hosted_install_proof() {
    const LEG: &str = "yarn_berry_hosted_install_proof";
    if !has_command("corepack") {
        soft_skip!(LEG, "`corepack` not on PATH (needed to pin yarn berry)");
    }
    let fx = npm_fixture("berry");
    // Berry needs an explicit packageManager pin plus the node-modules linker
    // (PnP is documented as untested for hosted mode) and compressionLevel 0,
    // which is what the redirect's 10c0 checksum is computed against.
    std::fs::write(
        fx.proj.join("package.json"),
        format!(
            r#"{{"name":"hosted-e2e","version":"0.0.0","private":true,"packageManager":"yarn@4.6.0","dependencies":{{"{NPM_NAME}":"{NPM_VERSION}"}}}}"#
        ),
    )
    .expect("write package.json");
    std::fs::write(
        fx.proj.join(".yarnrc.yml"),
        "nodeLinker: node-modules\ncompressionLevel: 0\nenableGlobalCache: false\n",
    )
    .expect("write .yarnrc.yml");

    let cache = fx.cache.display().to_string();
    let env = [
        ("YARN_CACHE_FOLDER", cache.as_str()),
        ("YARN_GLOBAL_FOLDER", cache.as_str()),
        ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"),
    ];

    // `--no-immutable` on the FIXTURE install only. Berry auto-enables
    // hardened mode on a public-PR CI run, which implies `--immutable` and
    // refuses the lockfile this first install has to create (`YN0028: The
    // lockfile would have been created by this install, which is explicitly
    // forbidden`). The reinstall below keeps `--immutable` — that leg is the
    // actual proof, and it must stay strict.
    let install = tool(&fx.proj, "yarn", &["install", "--no-immutable"], &env);
    if !ok(&install) {
        soft_skip!(
            LEG,
            "berry `yarn install` failed (corepack may be unable to download \
             yarn@4.6.0):\n{}",
            dump(&install)
        );
    }
    assert_pristine(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "yarn.lock");
    let lock = read(&fx.proj.join("yarn.lock"));
    // Berry pins the hosted artifact through a percent-encoded `__archiveUrl`
    // resolution field, so the plain host string is encoded — check both the
    // encoded host and the (unencoded) patch UUID.
    assert!(
        lock.contains("__archiveUrl") && lock.contains("patch.socket.dev"),
        "{LEG}: berry lock carries no __archiveUrl pointing at the patch \
         host:\n{lock}"
    );
    assert!(
        lock.contains(NPM_UUID),
        "{LEG}: berry lock does not reference patch {NPM_UUID}:\n{lock}"
    );

    std::fs::remove_dir_all(fx.proj.join("node_modules")).ok();
    std::fs::remove_dir_all(fx.proj.join(".yarn")).ok();
    std::fs::remove_dir_all(&fx.cache).ok();
    let reinstall = tool(&fx.proj, "yarn", &["install", "--immutable"], &env);
    assert!(
        ok(&reinstall),
        "{LEG}: `yarn install --immutable` from the redirected lock failed — \
         berry could not fetch the hosted artifact or its 10c0 checksum did \
         not match:\n{}",
        dump(&reinstall)
    );
    assert_patched(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);
}

#[test]
#[ignore = "live production API + real npm registry. Run with --ignored."]
fn bun_hosted_install_proof() {
    const LEG: &str = "bun_hosted_install_proof";
    if !has_command("bun") {
        soft_skip!(LEG, "`bun` not on PATH");
    }
    let fx = npm_fixture("bun");
    let cache = fx.cache.display().to_string();
    let env = [("BUN_INSTALL_CACHE_DIR", cache.as_str())];

    // Text `bun.lock` only — the binary `bun.lockb` is a separate (documented)
    // auto-migration path, not what this leg covers.
    let install = tool(
        &fx.proj,
        "bun",
        &["install", "--ignore-scripts", "--save-text-lockfile"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `bun install` failed:\n{}", dump(&install));
    }
    if !fx.proj.join("bun.lock").exists() {
        soft_skip!(
            LEG,
            "`bun install --save-text-lockfile` produced no bun.lock (bun too old?)"
        );
    }
    assert_pristine(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);

    let env_json = scan_hosted(&fx.proj, &[]);
    assert_redirected(&env_json, "bun.lock");
    assert_hosted_pin(&read(&fx.proj.join("bun.lock")), &[NPM_UUID], LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).expect("rm node_modules");
    std::fs::remove_dir_all(&fx.cache).ok();
    let reinstall = tool(
        &fx.proj,
        "bun",
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &env,
    );
    assert!(
        ok(&reinstall),
        "{LEG}: `bun install --frozen-lockfile` from the redirected lock \
         failed:\n{}",
        dump(&reinstall)
    );
    assert_patched(&minimist_entry(&fx.proj), PATCH_MARKER, LEG);
}

// ===========================================================================
// PyPI ecosystem — requirements.txt and uv.lock
// ===========================================================================

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

/// The urllib3 patches rewrite files under the package directory; which file
/// depends on which of the three advisories the resolver picked, so look for
/// the marker anywhere in the package rather than pinning one filename.
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

#[test]
#[ignore = "live production API + real PyPI. Run with --ignored."]
fn pypi_requirements_txt_hosted_install_proof() {
    const LEG: &str = "pypi_requirements_txt_hosted_install_proof";
    if !has_command("uv") {
        soft_skip!(LEG, "`uv` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    let uv_cache = tmp.path().join("uv-cache").display().to_string();
    let venv = proj.join(".venv");
    let venv_s = venv.display().to_string();
    let env = [
        ("UV_CACHE_DIR", uv_cache.as_str()),
        ("VIRTUAL_ENV", venv_s.as_str()),
    ];

    std::fs::write(
        proj.join("requirements.txt"),
        format!("{PYPI_NAME}=={PYPI_VERSION}\n"),
    )
    .expect("write requirements.txt");

    if !ok(&tool(&proj, "uv", &["venv", "--quiet", ".venv"], &env)) {
        soft_skip!(LEG, "`uv venv` failed");
    }
    let install = tool(
        &proj,
        "uv",
        &["pip", "install", "--quiet", "-r", "requirements.txt"],
        &env,
    );
    if !ok(&install) {
        soft_skip!(LEG, "upstream `uv pip install` failed:\n{}", dump(&install));
    }
    let Some(site) = site_packages(&venv) else {
        soft_skip!(LEG, "could not locate site-packages under {venv_s}");
    };
    assert!(
        !urllib3_patched(&site),
        "{LEG}: the freshly-installed upstream urllib3 already carries \
         `{PATCH_MARKER}` — every downstream assertion would be vacuous"
    );

    let env_json = scan_hosted(&proj, &[]);
    assert_redirected(&env_json, "requirements.txt");
    let reqs = read(&proj.join("requirements.txt"));
    assert_hosted_pin(&reqs, PYPI_UUIDS, LEG);
    assert!(
        reqs.contains("--hash=sha256:"),
        "{LEG}: rewritten requirements.txt carries no --hash pin, so pip/uv \
         would install the hosted wheel unverified:\n{reqs}"
    );

    std::fs::remove_dir_all(&venv).expect("rm venv");
    assert!(
        ok(&tool(&proj, "uv", &["venv", "--quiet", ".venv"], &env)),
        "{LEG}: re-creating the venv failed"
    );
    let reinstall = tool(
        &proj,
        "uv",
        &["pip", "install", "--quiet", "-r", "requirements.txt"],
        &env,
    );
    assert!(
        ok(&reinstall),
        "{LEG}: `uv pip install` from the redirected requirements.txt failed — \
         the hosted wheel could not be fetched or failed its hash check:\n{}",
        dump(&reinstall)
    );
    let site = site_packages(&venv).expect("site-packages after reinstall");
    assert!(
        urllib3_patched(&site),
        "{LEG}: reinstalled from the redirected requirements.txt, but no urllib3 \
         source file carries `{PATCH_MARKER}`"
    );
}

#[test]
#[ignore = "live production API + real PyPI. Run with --ignored."]
fn pypi_uv_lock_hosted_install_proof() {
    const LEG: &str = "pypi_uv_lock_hosted_install_proof";
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
            "[project]\nname = \"hosted-e2e\"\nversion = \"0.1.0\"\n\
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

    let env_json = scan_hosted(&proj, &[]);
    assert_redirected(&env_json, "uv.lock");
    let lock = read(&proj.join("uv.lock"));
    assert_hosted_pin(&lock, PYPI_UUIDS, LEG);

    std::fs::remove_dir_all(&venv).expect("rm venv");
    let resync = tool(&proj, "uv", &["sync", "--frozen", "--quiet"], &env);
    assert!(
        ok(&resync),
        "{LEG}: `uv sync --frozen` from the redirected uv.lock failed:\n{}",
        dump(&resync)
    );
    let site = site_packages(&venv).expect("site-packages after resync");
    assert!(
        urllib3_patched(&site),
        "{LEG}: resynced from the redirected uv.lock, but no urllib3 source \
         file carries `{PATCH_MARKER}`"
    );
}

// ===========================================================================
// Cargo — per-patch sparse registry
// ===========================================================================

#[test]
#[ignore = "live production API + real crates.io. Run with --ignored."]
fn cargo_hosted_install_proof() {
    const LEG: &str = "cargo_hosted_install_proof";
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
            "[package]\nname = \"hosted-e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{CARGO_NAME} = \"={CARGO_VERSION}\"\n"
        ),
    )
    .expect("write Cargo.toml");
    std::fs::write(proj.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");

    let fetch = tool(&proj, "cargo", &["fetch"], &env);
    if !ok(&fetch) {
        soft_skip!(LEG, "upstream `cargo fetch` failed:\n{}", dump(&fetch));
    }
    let pristine_lock = read(&proj.join("Cargo.lock"));
    assert!(
        pristine_lock.contains("registry+https://github.com/rust-lang/crates.io-index"),
        "{LEG}: pristine Cargo.lock does not resolve {CARGO_NAME} from \
         crates.io — fixture setup is wrong:\n{pristine_lock}"
    );

    let env_json = scan_hosted(&proj, &[]);
    assert_redirected(&env_json, "Cargo.lock");

    let lock = read(&proj.join("Cargo.lock"));
    assert_hosted_pin(&lock, &[CARGO_UUID], LEG);
    let config = read(&proj.join(".cargo").join("config.toml"));
    assert!(
        config.contains(&format!(
            "sparse+https://{PATCH_HOST}/patch-registry/cargo/"
        )),
        "{LEG}: .cargo/config.toml declares no Socket sparse registry:\n{config}"
    );
    let manifest = read(&proj.join("Cargo.toml"));
    assert!(
        manifest.contains(&format!("socket-patch-{CARGO_UUID}")),
        "{LEG}: Cargo.toml does not route {CARGO_NAME} at the per-patch \
         registry:\n{manifest}"
    );

    // Proof: fetch again with a cold CARGO_HOME so cargo must reach the Socket
    // sparse index, download the crate, and verify the checksum in the lock.
    let cold = tmp.path().join("cargo-home-cold").display().to_string();
    let cold_env = [("CARGO_HOME", cold.as_str())];
    let refetch = tool(&proj, "cargo", &["fetch"], &cold_env);
    assert!(
        ok(&refetch),
        "{LEG}: `cargo fetch` from the Socket sparse registry failed — cargo \
         could not reach the index, download the crate, or verify its \
         checksum:\n{}",
        dump(&refetch)
    );

    // The extracted source must be the patched crate, not the crates.io one.
    let src_root = Path::new(&cold).join("registry").join("src");
    let mut found = None;
    if let Ok(hosts) = std::fs::read_dir(&src_root) {
        for host in hosts.flatten() {
            let candidate = host
                .path()
                .join(format!("{CARGO_NAME}-{CARGO_VERSION}"))
                .join("src")
                .join("lib.rs");
            if candidate.exists() {
                found = Some(candidate);
                break;
            }
        }
    }
    let lib_rs = found.unwrap_or_else(|| {
        panic!("{LEG}: no extracted {CARGO_NAME}-{CARGO_VERSION}/src/lib.rs under {src_root:?}")
    });
    assert!(
        lib_rs
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().contains(PATCH_HOST))
            .unwrap_or(false),
        "{LEG}: {CARGO_NAME} was extracted from a non-Socket registry dir \
         ({}) — cargo served it from the crates.io cache instead of the \
         redirect",
        lib_rs.display()
    );
    assert_patched(&lib_rs, CARGO_MARKER, LEG);
}

// ===========================================================================
// RubyGems — redirect works; the hosted install is blocked by a SERVER defect
// ===========================================================================

/// The gem redirect itself is correct and is asserted hard here.
///
/// The **install** leg is a different story. Socket's gem patch-registry serves
/// a compact index whose `/info/<gem>` line declares **no runtime
/// dependencies**, while the `.gem` it serves declares six. Bundler's
/// `ensure_same_dependencies` check fails closed:
///
/// ```text
/// Bundler::APIResponseMismatchError: Downloading activestorage-7.0.2.2
/// revealed dependencies not in the API (activesupport (= 7.0.2.2), ...)
/// ```
///
/// Compare production's own index, which does emit them:
/// `https://index.rubygems.org/info/activestorage` →
/// `7.0.2.2 actionpack:= 7.0.2.2,activejob:= 7.0.2.2,...|checksum:...`
/// versus `patch.socket.dev/patch-registry/gem/<grant>/<uuid>/info/activestorage`
/// → `7.0.2.2 |checksum:...`.
///
/// That is a **server-side** defect, not a CLI one, and it blocks hosted gem
/// mode for any gem with runtime dependencies. Until it is fixed the install
/// leg reports loudly but does not fail the suite; set
/// `SOCKET_PATCH_HOSTED_E2E_GEM_STRICT=1` to promote it to a hard failure
/// (do that as the regression guard once the server is fixed).
#[test]
#[ignore = "live production API + real rubygems.org. Run with --ignored."]
fn gem_bundler_hosted_redirect_and_known_install_defect() {
    const LEG: &str = "gem_bundler_hosted_redirect_and_known_install_defect";
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

    // `--add-checksums` produces the CHECKSUMS section the hosted rewrite pins
    // into; it needs bundler >= 2.6.
    if !ok(&tool(&proj, "bundle", &["lock", "--add-checksums"], &env)) {
        soft_skip!(
            LEG,
            "`bundle lock --add-checksums` failed (bundler < 2.6 has no \
             CHECKSUMS section)"
        );
    }
    let install = tool(&proj, "bundle", &["install", "--quiet"], &env);
    if !ok(&install) {
        soft_skip!(LEG, "upstream `bundle install` failed:\n{}", dump(&install));
    }

    let env_json = scan_hosted(&proj, &[]);
    assert_redirected(&env_json, "Gemfile.lock");

    // Hard assertions: the redirect itself must be correct.
    let gemfile = read(&proj.join("Gemfile"));
    assert!(
        gemfile.contains(&format!("https://{PATCH_HOST}/patch-registry/gem/"))
            && gemfile.contains(GEM_UUID),
        "{LEG}: Gemfile carries no per-dep Socket source block for \
         {GEM_UUID}:\n{gemfile}"
    );
    let lock = read(&proj.join("Gemfile.lock"));
    assert!(
        lock.contains("CHECKSUMS"),
        "{LEG}: Gemfile.lock lost its CHECKSUMS section:\n{lock}"
    );

    // Known-broken leg: reinstall from the redirected Gemfile.
    std::fs::remove_dir_all(&bundle_path).ok();
    let reinstall = tool(&proj, "bundle", &["install"], &env);
    let gem_strict = std::env::var("SOCKET_PATCH_HOSTED_E2E_GEM_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if ok(&reinstall) {
        // The server defect has been fixed. Say so loudly — the guard below
        // should be promoted to unconditional and this branch deleted.
        println!(
            "NOTE {LEG}: `bundle install` from the redirected Gemfile now \
             SUCCEEDS. The gem patch-registry compact-index dependency defect \
             appears to be FIXED — delete the tolerance branch in this test and \
             assert unconditionally."
        );
        return;
    }
    let detail = dump(&reinstall);
    let is_known_defect = detail.contains("APIResponseMismatchError")
        || detail.contains("revealed dependencies not in the API");
    assert!(
        !gem_strict,
        "{LEG}: SOCKET_PATCH_HOSTED_E2E_GEM_STRICT=1 and `bundle install` from \
         the redirected Gemfile failed:\n{detail}"
    );
    assert!(
        is_known_defect,
        "{LEG}: `bundle install` from the redirected Gemfile failed for an \
         UNEXPECTED reason (not the known compact-index dependency defect). \
         This is a new regression:\n{detail}"
    );
    println!(
        "KNOWN PRODUCTION DEFECT {LEG}: the Socket gem patch-registry compact \
         index omits runtime dependencies, so bundler refuses the download \
         (APIResponseMismatchError). Hosted gem mode is unusable for gems with \
         dependencies until the server emits them. Redirect assertions above \
         all passed."
    );
}

// ===========================================================================
// Documented negative cases
// ===========================================================================

/// Go hosted mode is refused by design (`docs/design/golang-hosted-no-go.md`).
///
/// This asserts the *documented* shape of the refusal rather than a specific
/// warning payload, because production publishes no free golang patches today,
/// so there is nothing for the rewriter to refuse. If that ever changes, the
/// `redirect_golang_unsupported` branch below starts exercising and this test
/// becomes a real guard with no edit needed.
#[test]
#[ignore = "live production API. Run with --ignored."]
fn golang_hosted_is_refused_by_design() {
    const LEG: &str = "golang_hosted_is_refused_by_design";
    if !has_command("go") {
        soft_skip!(LEG, "`go` not on PATH");
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(
        proj.join("go.mod"),
        "module example.com/hosted-e2e\n\ngo 1.21\n",
    )
    .expect("write go.mod");

    let env_json = scan_hosted(&proj, &["--ecosystems", "golang"]);
    assert_eq!(
        redirected_count(&env_json),
        0,
        "{LEG}: golang hosted mode redirected something — it is documented as \
         impossible (sumdb + module-path identity + GOPROXY leakage). Either \
         the design changed or this is a real bug:\n{env_json:#}"
    );
    let warnings = env_json["redirect"]["warnings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if warnings
        .iter()
        .any(|w| w["code"].as_str() == Some("redirect_golang_unsupported"))
    {
        println!("{LEG}: production now publishes golang patches; the documented refusal fired.");
    } else {
        println!(
            "{LEG}: no golang patches published, so the refusal path is inert. \
             Asserted only that hosted mode redirected nothing."
        );
    }
}

/// Deno hosted mode is not supported. Same shape as the golang guard.
#[test]
#[ignore = "live production API. Run with --ignored."]
fn deno_hosted_is_unsupported() {
    const LEG: &str = "deno_hosted_is_unsupported";
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    std::fs::write(
        proj.join("deno.json"),
        r#"{"imports":{"minimist":"npm:minimist@1.2.2"}}"#,
    )
    .expect("write deno.json");

    let env_json = scan_hosted(&proj, &["--ecosystems", "deno"]);
    assert_eq!(
        redirected_count(&env_json),
        0,
        "{LEG}: deno hosted mode redirected something, but hosted mode is \
         documented as unsupported for deno:\n{env_json:#}"
    );
}

// ===========================================================================
// Canary — ecosystems whose hosted support has nothing to test against
// ===========================================================================

/// maven, nuget and composer all implement hosted mode, but production
/// publishes no free-tier patches for them, so there is no honest end-to-end
/// leg to write. This probes production every run and reports the moment that
/// changes, so coverage can be extended deliberately rather than by accident.
///
/// It deliberately does NOT fail when patches appear: production publishing a
/// new patch is not a socket-patch regression, and a required check must not
/// go red for it. `SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT=1` makes it fail, for
/// use in a scheduled run where a nag is the point.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live production API. Run with --ignored."]
async fn canary_unpublished_ecosystems() {
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
        "production probe failed (the endpoint itself may be down, which IS a \
         real signal for this suite):\n  - {}",
        probe_errors.join("\n  - ")
    );

    if newly_published.is_empty() {
        println!(
            "canary_unpublished_ecosystems: maven / nuget / composer still have \
             no free-tier published patches — their hosted-mode legs remain \
             untestable end-to-end against production."
        );
        return;
    }

    let msg = format!(
        "production now publishes free patches for previously-empty \
         ecosystems:\n  - {}\nExtend this suite with real install proofs for \
         them (see docs/testing/hosted-production-e2e.md).",
        newly_published.join("\n  - ")
    );
    if std::env::var("SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT").as_deref() == Ok("1") {
        panic!("{msg}");
    }
    println!("NOTE canary_unpublished_ecosystems: {msg}");
}
