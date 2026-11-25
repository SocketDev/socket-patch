//! Live proof of the experimental `--patch-mirror-url` against a real
//! Artifactory.
//!
//! Nothing here is mocked. The suite needs an Artifactory instance with a
//! **generic remote repository** whose URL is `https://patch.socket.dev`,
//! and drives the real binary, Socket's production patch API (free
//! patches, no token) and the real package managers against it. It is
//! `#[ignore]`d and skips without its settings, so this repository's CI
//! only compiles it; Socket runs it against a real Artifactory outside
//! this repository. Each install-proof leg:
//!
//! 1. locks a pinned upstream package with the real package manager;
//! 2. runs `scan --mode hosted --patch-mirror-url <repository>` and checks
//!    that the pin names the Artifactory repository, not the patch server;
//! 3. installs from the rewritten lock alone, with cold caches, and checks
//!    the installed bytes carry the patch.
//!
//! The patched artifact can only have come through Artifactory: the lock
//! names no other host for it. Go is the exception, because its pin is a
//! module path: that leg lists the repository first in `GOPROXY` and checks
//! that every Socket module was fetched from it.
//!
//! Legs: npm, pnpm, yarn classic, yarn berry, Bun, vlt, pip, uv, PDM,
//! Pipenv, Bundler and Go. There is no Composer leg: Socket publishes no
//! Composer patch yet, so there is nothing to pin.
//!
//! ## Configuration
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `SOCKET_PATCH_ARTIFACTORY_E2E_BASE` | Base URL of a repository that needs credentials, such as `http://127.0.0.1:8081/artifactory/socket-patch`. Without it every leg skips. |
//! | `SOCKET_PATCH_ARTIFACTORY_E2E_USER`, `..._PASSWORD` | A user with Read and Deploy/Cache on that repository. |
//! | `SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE` | Base URL of a repository readable without credentials (the yarn, Bun and Go legs need one: yarn and Bun send no credentials for a URL pin, and go sends none over plain `http`). Without it those legs skip. |
//! | `SOCKET_PATCH_ARTIFACTORY_E2E_STRICT=1` | Fail instead of skipping a leg whose settings or toolchain are missing. |
//!
//! ```sh
//! cargo test --locked -p socket-patch-cli --test e2e_artifactory_mirror -- --ignored
//! ```

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "common/envelope.rs"]
mod envelope;
#[path = "common/hermetic.rs"]
mod hermetic;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envelope::warning_codes;

const NPM_NAME: &str = "minimist";
const NPM_VERSION: &str = "1.2.2";
const PYPI_NAME: &str = "urllib3";
const PYPI_VERSION: &str = "1.26.18";
const GEM_NAME: &str = "activestorage";
const GEM_VERSION: &str = "6.0.3";
/// The banner every Socket patch adds to the files it changes.
const PATCH_MARKER: &str = "Socket Community Patch";
const PATCH_HOST: &str = "patch.socket.dev";

// ---------------------------------------------------------------------------
// Settings + skip policy
// ---------------------------------------------------------------------------

fn setting(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

fn strict() -> bool {
    setting("SOCKET_PATCH_ARTIFACTORY_E2E_STRICT").is_some_and(|v| v == "1" || v == "true")
}

macro_rules! soft_skip {
    ($leg:expr, $($arg:tt)*) => {{
        let why = format!($($arg)*);
        if strict() {
            panic!("STRICT: {} cannot run: {why}", $leg);
        }
        println!("SKIP {}: {why}", $leg);
        return;
    }};
}

/// The repository that needs credentials, with the credentials.
struct Private {
    base: String,
    user: String,
    password: String,
}

impl Private {
    fn from_env() -> Option<Self> {
        Some(Private {
            base: setting("SOCKET_PATCH_ARTIFACTORY_E2E_BASE")?,
            user: setting("SOCKET_PATCH_ARTIFACTORY_E2E_USER")?,
            password: std::env::var("SOCKET_PATCH_ARTIFACTORY_E2E_PASSWORD").ok()?,
        })
    }

    /// The `Authorization` header value the CLI's own check sends.
    fn authorization(&self) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.user, self.password))
        )
    }

    /// `(scheme://host[:port], host[:port], host)` of the base.
    fn origin(&self) -> (String, String, String) {
        let (scheme, rest) = self.base.split_once("://").expect("base is a URL");
        let authority = rest.split('/').next().unwrap_or(rest).to_string();
        let host = authority
            .split(':')
            .next()
            .unwrap_or(&authority)
            .to_string();
        (format!("{scheme}://{authority}"), authority, host)
    }

    /// `(context root URL, repository key)`: the base is
    /// `<root>/<repository key>`.
    fn root_and_repo(&self) -> (String, String) {
        let (root, repo) = self.base.rsplit_once('/').expect("base has a repository");
        (root.to_string(), repo.to_string())
    }

    /// A netrc file for the repository's host: how pip and uv are handed
    /// credentials for a URL that is not their index.
    fn netrc(&self, dir: &Path) -> PathBuf {
        let path = dir.join("netrc");
        std::fs::write(
            &path,
            format!(
                "machine {}\nlogin {}\npassword {}\n",
                self.origin().2,
                self.user,
                self.password
            ),
        )
        .expect("write netrc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    /// The `.npmrc` line that hands npm and pnpm the credentials for every
    /// path on the repository's host.
    fn npmrc_auth(&self) -> String {
        use base64::Engine as _;
        format!(
            "//{}/:_auth={}\n",
            self.origin().1,
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.user, self.password))
        )
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

fn dump(out: &Output) -> String {
    format!(
        "exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The binary against production, with no ambient Socket settings: no
/// token (the free public proxy), no mirror, no crawler inputs.
fn cli(cwd: &Path) -> Command {
    let mut cmd = hermetic::binary_command();
    hermetic::scrub_crawler_inputs(&mut cmd);
    cmd.env_remove("SOCKET_PATCH_MIRROR_URL")
        .env_remove("SOCKET_PATCH_MIRROR_AUTHORIZATION")
        .current_dir(cwd);
    cmd
}

/// `scan --mode hosted --json --yes --patch-mirror-url <base>`; the parsed
/// envelope of a run that exited 0.
fn scan_mirrored(cwd: &Path, base: &str, authorization: Option<&str>) -> serde_json::Value {
    scan_mirrored_with(cwd, base, authorization, &[])
}

/// [`scan_mirrored`] with extra environment for the CLI (a Go module cache
/// to crawl, say).
fn scan_mirrored_with(
    cwd: &Path,
    base: &str,
    authorization: Option<&str>,
    env: &[(&str, &str)],
) -> serde_json::Value {
    let mut cmd = cli(cwd);
    cmd.envs(env.iter().copied());
    cmd.args([
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--patch-mirror-url",
        base,
    ]);
    if let Some(value) = authorization {
        cmd.env("SOCKET_PATCH_MIRROR_AUTHORIZATION", value);
    }
    let out = cmd.output().expect("run socket-patch");
    assert!(
        out.status.success(),
        "scan --mode hosted failed:\n{}",
        dump(&out)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("scan did not emit JSON ({e}):\n{}", dump(&out)))
}

/// The purls a hosted run pinned.
fn pinned(env: &serde_json::Value) -> Vec<String> {
    env["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| e["action"] == "applied" && e["details"]["mode"] == "hosted")
                .filter_map(|e| e["purl"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn has_command(program: &str) -> bool {
    let mut probe = pm_command(program);
    probe
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cache_env::isolate(&mut probe);
    probe.status().map(|s| s.success()).unwrap_or(false)
}

/// A package manager with no ambient Socket settings and no ambient
/// registry override.
fn pm_command(program: &str) -> Command {
    let mut cmd = hermetic::tool_command(program);
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Bundle]);
    for key in [
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
        "YARN_NPM_REGISTRY_SERVER",
        "YARN_NODE_LINKER",
        "PIP_INDEX_URL",
        "UV_INDEX_URL",
        "NETRC",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

fn tool(cwd: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = pm_command(program);
    cmd.args(args).current_dir(cwd);
    cache_env::isolate(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"))
}

fn assert_pristine(path: &Path, leg: &str) {
    let body = read(path);
    assert!(
        !body.contains(PATCH_MARKER),
        "{leg}: the upstream install at {} already carries the patch; every later assertion \
         would be vacuous",
        path.display()
    );
}

fn assert_patched(path: &Path, leg: &str) {
    assert!(path.exists(), "{leg}: {} was not installed", path.display());
    assert!(
        read(path).contains(PATCH_MARKER),
        "{leg}: {} was installed from the mirrored lock but does not carry the patch",
        path.display()
    );
}

/// The lock pins the mirror and no longer names the patch server.
fn assert_mirrored_pin(lock: &str, base: &str, leg: &str) {
    assert!(
        lock.contains(&format!("{base}/patch")),
        "{leg}: the lock does not pin the Artifactory repository {base}:\n{lock}"
    );
    assert!(
        !lock.contains(PATCH_HOST),
        "{leg}: the lock still names {PATCH_HOST}:\n{lock}"
    );
}

struct Fixture {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    scratch: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let proj = tmp.path().join("proj");
    let scratch = tmp.path().join("scratch");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    Fixture {
        _tmp: tmp,
        proj,
        scratch,
    }
}

fn write_npm_manifest(proj: &Path, extra: &str) {
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"artifactory-e2e","version":"0.0.0","private":true{extra},"dependencies":{{"{NPM_NAME}":"{NPM_VERSION}"}}}}"#
        ),
    )
    .expect("write package.json");
}

fn minimist_entry(proj: &Path) -> PathBuf {
    proj.join("node_modules").join(NPM_NAME).join("index.js")
}

// ---------------------------------------------------------------------------
// The mirror check
// ---------------------------------------------------------------------------

/// What the run does with a real Artifactory's answers before it pins
/// anything: a repository it can read is pinned without a warning, one that
/// wants credentials the run does not have is pinned with a warning, and a
/// repository key that does not exist gets nothing pinned to it.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn the_mirror_is_checked_before_anything_is_pinned() {
    const LEG: &str = "the_mirror_is_checked_before_anything_is_pinned";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("npm") {
        soft_skip!(LEG, "`npm` is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, "");
    let cache = fx.scratch.join("npm-cache").display().to_string();
    let lock_only = tool(
        &fx.proj,
        "npm",
        &[
            "install",
            "--package-lock-only",
            "--no-audit",
            "--no-fund",
            "--ignore-scripts",
        ],
        &[("npm_config_cache", &cache)],
    );
    if !lock_only.status.success() {
        soft_skip!(
            LEG,
            "the upstream lock could not be made:\n{}",
            dump(&lock_only)
        );
    }
    let lock_path = fx.proj.join("package-lock.json");
    let pristine = read(&lock_path);
    let reset = || {
        std::fs::write(&lock_path, &pristine).unwrap();
        let _ = std::fs::remove_file(fx.proj.join(".npmrc"));
    };

    // A repository key that does not exist: nothing is written.
    let (root, _) = private.root_and_repo();
    let missing = format!("{root}/socket-patch-e2e-no-such-repository");
    let env = scan_mirrored(&fx.proj, &missing, Some(&private.authorization()));
    assert!(pinned(&env).is_empty(), "{LEG}: {env:#}");
    assert!(
        warning_codes(&env).contains(&"redirect_mirror_unavailable".to_string()),
        "{LEG}: {env:#}"
    );
    assert_eq!(
        read(&lock_path),
        pristine,
        "{LEG}: the lock must be untouched"
    );
    assert!(
        !fx.proj.join(".npmrc").exists(),
        "{LEG}: no .npmrc is written"
    );

    // The real repository, checked with the operator's credential.
    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert!(
        !warning_codes(&env).iter().any(|c| c.contains("mirror")),
        "{LEG}: a repository the run could read raises no mirror warning: {env:#}"
    );
    assert_mirrored_pin(&read(&lock_path), &private.base, LEG);
    let checked = read(&lock_path);

    // A re-run finds its own pin and changes nothing.
    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert_eq!(
        read(&lock_path),
        checked,
        "{LEG}: a re-run must leave the lock as it is"
    );

    // The same repository with no credential: Artifactory answers 401, so
    // the pin is written unchecked and the run says so. Same lock.
    reset();
    let env = scan_mirrored(&fx.proj, &private.base, None);
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert!(
        warning_codes(&env).contains(&"redirect_mirror_unverified".to_string()),
        "{LEG}: {env:#}"
    );
    assert_eq!(
        read(&lock_path),
        checked,
        "{LEG}: the unchecked pin is the same pin"
    );

    // A run that was not given the mirror leaves the pin alone.
    let bare_scan = || {
        let mut bare = cli(&fx.proj);
        bare.args(["scan", "--mode", "hosted", "--json", "--yes"]);
        let out = bare.output().expect("run socket-patch");
        assert!(out.status.success(), "{}", dump(&out));
        serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("scan emits JSON")
    };
    let env = bare_scan();
    assert!(
        warning_codes(&env).contains(&"redirect_pin_on_unconfigured_host".to_string()),
        "{LEG}: {env:#}"
    );
    assert_eq!(
        read(&lock_path),
        checked,
        "{LEG}: the mirrored pin is untouched"
    );

    // A project pinned straight at the patch server moves onto the mirror
    // when a run is given one.
    reset();
    let env = bare_scan();
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert!(
        read(&lock_path).contains(PATCH_HOST),
        "{LEG}: a run without a mirror pins the patch server"
    );
    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert_eq!(
        read(&lock_path),
        checked,
        "{LEG}: the direct pin must move onto the mirror"
    );
}

// ---------------------------------------------------------------------------
// npm family
// ---------------------------------------------------------------------------

/// npm through a repository that needs credentials: the install fails
/// without them, succeeds with the host's credentials in `.npmrc`, and the
/// artifact ends up in Artifactory's cache. `list`, `vex` and `rollback`
/// then read the mirrored pin.
#[tokio::test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
async fn npm_installs_the_patch_through_artifactory() {
    const LEG: &str = "npm_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("npm") {
        soft_skip!(LEG, "`npm` is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, "");
    let cache = |name: &str| fx.scratch.join(name).display().to_string();
    let install = tool(
        &fx.proj,
        "npm",
        &["install", "--no-audit", "--no-fund", "--ignore-scripts"],
        &[("npm_config_cache", &cache("upstream-cache"))],
    );
    if !install.status.success() {
        soft_skip!(LEG, "upstream `npm install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&fx.proj), LEG);
    let upstream_lock = read(&fx.proj.join("package-lock.json"));

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(
        pinned(&env),
        [format!("pkg:npm/{NPM_NAME}@{NPM_VERSION}")],
        "{LEG}: {env:#}"
    );
    let lock = read(&fx.proj.join("package-lock.json"));
    assert_mirrored_pin(&lock, &private.base, LEG);

    // Without credentials Artifactory refuses the artifact.
    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let ci = ["ci", "--no-audit", "--no-fund", "--ignore-scripts"];
    let refused = tool(
        &fx.proj,
        "npm",
        &ci,
        &[("npm_config_cache", &cache("cold-a"))],
    );
    assert!(
        !refused.status.success() && dump(&refused).contains("E401"),
        "{LEG}: an install with no credentials must be refused by Artifactory:\n{}",
        dump(&refused)
    );

    // With the host's credentials in the user's npm config it installs the
    // patched bytes, from a cold cache.
    let userconfig = fx.scratch.join("user.npmrc");
    std::fs::write(&userconfig, private.npmrc_auth()).unwrap();
    let userconfig = userconfig.display().to_string();
    let installed = tool(
        &fx.proj,
        "npm",
        &ci,
        &[
            ("npm_config_cache", &cache("cold-b")),
            ("npm_config_userconfig", &userconfig),
        ],
    );
    assert!(
        installed.status.success(),
        "{LEG}: `npm ci` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);

    // Artifactory now holds the artifact in the repository's cache.
    let mirrored = lock
        .split('"')
        .find(|s| s.starts_with(&format!("{}/patch/npm/", private.base)))
        .expect("the mirrored URL is in the lock")
        .to_string();
    let (root, repo) = private.root_and_repo();
    let path = mirrored.strip_prefix(&private.base).unwrap();
    let storage = format!("{root}/api/storage/{repo}-cache{path}");
    let info = reqwest::Client::new()
        .get(&storage)
        .basic_auth(&private.user, Some(&private.password))
        .send()
        .await
        .expect("ask Artifactory for the cached artifact");
    assert!(
        info.status().is_success(),
        "{LEG}: Artifactory does not hold the artifact in {repo}-cache (HTTP {})",
        info.status()
    );
    let info: serde_json::Value = info.json().await.expect("storage info is JSON");
    assert_eq!(info["repo"], format!("{repo}-cache"), "{LEG}: {info:#}");

    // `list` and a verifying `vex` read the pin when given the mirror.
    let mut list = cli(&fx.proj);
    list.args(["list", "--patch-mirror-url", &private.base]);
    let out = list.output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Mode: hosted"),
        "{LEG}: {}",
        dump(&out)
    );
    let mut vex = cli(&fx.proj);
    vex.args([
        "vex",
        "--product",
        "pkg:npm/artifactory-e2e@0.0.0",
        "--patch-mirror-url",
        &private.base,
    ]);
    let out = vex.output().unwrap();
    let doc = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && doc.contains("not_affected") && doc.contains("(redirected)"),
        "{LEG}: vex must attest the installed, mirrored patch:\n{}",
        dump(&out)
    );

    // `rollback` restores what npm wrote, re-resolved from the registry.
    let mut rollback = cli(&fx.proj);
    rollback.args([
        "rollback",
        "--json",
        "--yes",
        "--patch-mirror-url",
        &private.base,
    ]);
    let out = rollback.output().unwrap();
    assert!(
        out.status.success(),
        "{LEG}: rollback failed:\n{}",
        dump(&out)
    );
    assert_eq!(
        read(&fx.proj.join("package-lock.json")),
        upstream_lock,
        "{LEG}: rollback must restore npm's own lock"
    );
    assert!(
        !fx.proj.join(".npmrc").exists(),
        "{LEG}: rollback removes its .npmrc"
    );
}

/// pnpm sends a token to a URL pin only when the token's scope covers the
/// pin's path, so the host's credentials go in `.npmrc` under the host.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn pnpm_installs_the_patch_through_artifactory() {
    const LEG: &str = "pnpm_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("pnpm") {
        soft_skip!(LEG, "`pnpm` is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, "");
    let store = |name: &str| fx.scratch.join(name).display().to_string();
    let install = tool(
        &fx.proj,
        "pnpm",
        &[
            "install",
            "--ignore-scripts",
            "--store-dir",
            &store("upstream-store"),
        ],
        &[],
    );
    if !install.status.success() {
        soft_skip!(LEG, "upstream `pnpm install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&fx.proj), LEG);

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert_mirrored_pin(&read(&fx.proj.join("pnpm-lock.yaml")), &private.base, LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let frozen = [
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--store-dir",
    ];
    let cold_a = store("cold-a");
    let refused = tool(
        &fx.proj,
        "pnpm",
        &[&frozen[..], &[cold_a.as_str()]].concat(),
        &[],
    );
    assert!(
        !refused.status.success(),
        "{LEG}: an install with no credentials must be refused:\n{}",
        dump(&refused)
    );

    let npmrc = fx.proj.join(".npmrc");
    let existing = std::fs::read_to_string(&npmrc).unwrap_or_default();
    std::fs::write(&npmrc, format!("{existing}{}", private.npmrc_auth())).unwrap();
    let _ = std::fs::remove_dir_all(fx.proj.join("node_modules"));
    let cold_b = store("cold-b");
    let installed = tool(
        &fx.proj,
        "pnpm",
        &[&frozen[..], &[cold_b.as_str()]].concat(),
        &[],
    );
    assert!(
        installed.status.success(),
        "{LEG}: `pnpm install --frozen-lockfile` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);
}

/// yarn classic sends no credentials for a URL pin outside its registry's
/// path, so it reads a repository that allows anonymous access.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn yarn_classic_installs_the_patch_through_an_anonymous_repository() {
    const LEG: &str = "yarn_classic_installs_the_patch_through_an_anonymous_repository";
    let Some(base) = setting("SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE") else {
        soft_skip!(LEG, "SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE is not set");
    };
    let version = tool(Path::new("."), "yarn", &["--version"], &[]);
    if !version.status.success() || !String::from_utf8_lossy(&version.stdout).starts_with("1.") {
        soft_skip!(LEG, "yarn 1.x is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, "");
    let cache = |name: &str| fx.scratch.join(name).display().to_string();
    let install = tool(
        &fx.proj,
        "yarn",
        &[
            "install",
            "--ignore-scripts",
            "--cache-folder",
            &cache("upstream-cache"),
        ],
        &[],
    );
    if !install.status.success() {
        soft_skip!(LEG, "upstream `yarn install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&fx.proj), LEG);

    let env = scan_mirrored(&fx.proj, &base, None);
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert!(
        !warning_codes(&env).iter().any(|c| c.contains("mirror")),
        "{LEG}: an anonymous repository is checked without credentials: {env:#}"
    );
    assert_mirrored_pin(&read(&fx.proj.join("yarn.lock")), &base, LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let installed = tool(
        &fx.proj,
        "yarn",
        &[
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--cache-folder",
            &cache("cold"),
        ],
        &[],
    );
    assert!(
        installed.status.success(),
        "{LEG}: `yarn install --frozen-lockfile` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);
}

/// yarn berry fetches a URL pin with no credentials at all, so it too
/// reads a repository that allows anonymous access.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn yarn_berry_installs_the_patch_through_an_anonymous_repository() {
    const LEG: &str = "yarn_berry_installs_the_patch_through_an_anonymous_repository";
    let Some(base) = setting("SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE") else {
        soft_skip!(LEG, "SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE is not set");
    };
    if !has_command("corepack") {
        soft_skip!(LEG, "`corepack` is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, r#","packageManager":"yarn@4.9.2""#);
    // A plain-http repository needs yarn's own opt-in; an https one does not.
    let host = base
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', ':']).next().unwrap_or(rest).to_string())
        .unwrap_or_default();
    std::fs::write(
        fx.proj.join(".yarnrc.yml"),
        format!(
            "nodeLinker: node-modules\nenableGlobalCache: false\nenableTelemetry: false\n\
             unsafeHttpWhitelist: [\"{host}\"]\n"
        ),
    )
    .unwrap();
    let env_vars = [("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")];
    // This install writes the lock. Under `CI` yarn installs immutably by
    // default and would refuse to create it.
    let install = tool(
        &fx.proj,
        "corepack",
        &["yarn", "install"],
        &[env_vars[0], ("YARN_ENABLE_IMMUTABLE_INSTALLS", "false")],
    );
    if !install.status.success() {
        soft_skip!(LEG, "upstream `yarn install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&fx.proj), LEG);

    let env = scan_mirrored(&fx.proj, &base, None);
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert_mirrored_pin(&read(&fx.proj.join("yarn.lock")), &base, LEG);

    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let _ = std::fs::remove_dir_all(fx.proj.join(".yarn").join("cache"));
    let installed = tool(
        &fx.proj,
        "corepack",
        &["yarn", "install", "--immutable"],
        &env_vars,
    );
    assert!(
        installed.status.success(),
        "{LEG}: `yarn install --immutable` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);
}

/// Lock minimist with Bun, pin it through `base` and return the lock. The
/// caller gets a project whose `node_modules` holds the upstream copy.
fn bun_lock_and_pin(
    fx: &Fixture,
    base: &str,
    authorization: Option<&str>,
    leg: &str,
) -> Option<String> {
    write_npm_manifest(&fx.proj, "");
    let cache = fx.scratch.join("bun-upstream").display().to_string();
    let install = tool(
        &fx.proj,
        "bun",
        &["install", "--ignore-scripts"],
        &[("BUN_INSTALL_CACHE_DIR", &cache)],
    );
    if !install.status.success() {
        println!("{leg}: upstream `bun install` failed:\n{}", dump(&install));
        return None;
    }
    assert_pristine(&minimist_entry(&fx.proj), leg);
    let env = scan_mirrored(&fx.proj, base, authorization);
    assert_eq!(
        pinned(&env),
        [format!("pkg:npm/{NPM_NAME}@{NPM_VERSION}")],
        "{leg}: {env:#}"
    );
    let lock = read(&fx.proj.join("bun.lock"));
    assert_mirrored_pin(&lock, base, leg);
    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    Some(lock)
}

/// `bun install --frozen-lockfile` from a cold cache of its own.
fn bun_frozen_install(fx: &Fixture, cache: &str) -> Output {
    let cache = fx.scratch.join(cache).display().to_string();
    tool(
        &fx.proj,
        "bun",
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &[("BUN_INSTALL_CACHE_DIR", &cache)],
    )
}

/// Bun sends no credentials for a URL pin, so it reads a repository that
/// allows anonymous access. With a repository that needs credentials, the
/// credentials `.npmrc` holds for its host do not help: the install is
/// refused (the contract's "Installing through the mirror").
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn bun_installs_the_patch_through_an_anonymous_repository() {
    const LEG: &str = "bun_installs_the_patch_through_an_anonymous_repository";
    let Some(base) = setting("SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE") else {
        soft_skip!(LEG, "SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE is not set");
    };
    if !has_command("bun") {
        soft_skip!(LEG, "`bun` is not on PATH");
    }
    let fx = fixture();
    let Some(lock) = bun_lock_and_pin(&fx, &base, None, LEG) else {
        soft_skip!(LEG, "the upstream lock could not be made");
    };
    assert!(
        lock.contains(&format!(
            "\"{NPM_NAME}@{base}/patch/npm/{NPM_NAME}/{NPM_VERSION}/"
        )),
        "{LEG}: bun.lock must resolve {NPM_NAME} to the mirrored tarball:\n{lock}"
    );
    let installed = bun_frozen_install(&fx, "bun-cold");
    assert!(
        installed.status.success(),
        "{LEG}: `bun install --frozen-lockfile` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);

    // The repository that needs credentials, with them in `.npmrc` under
    // its host: Bun still sends none for the pin.
    let Some(private) = Private::from_env() else {
        println!(
            "{LEG}: SOCKET_PATCH_ARTIFACTORY_E2E_BASE is not set; the credential case is not run"
        );
        return;
    };
    let fx = fixture();
    if bun_lock_and_pin(&fx, &private.base, Some(&private.authorization()), LEG).is_none() {
        soft_skip!(LEG, "the upstream lock could not be made");
    }
    std::fs::write(fx.proj.join(".npmrc"), private.npmrc_auth()).unwrap();
    let refused = bun_frozen_install(&fx, "bun-cold-private");
    assert!(
        !refused.status.success() && dump(&refused).contains("401"),
        "{LEG}: Bun sent credentials for a URL pin; the contract says it sends none, so \
         update \"Installing through the mirror\":\n{}",
        dump(&refused)
    );
}

/// vlt sends the token its keychain holds for a registry URL to every
/// request under that URL, so a token stored for the mirror's base reaches
/// the pins. `vlt token add` reads the token from a terminal, so the leg
/// writes the keychain file it would write.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the npm registry. Run with --ignored."]
fn vlt_installs_the_patch_through_artifactory() {
    const LEG: &str = "vlt_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("vlt") {
        soft_skip!(LEG, "`vlt` is not on PATH");
    }
    let fx = fixture();
    write_npm_manifest(&fx.proj, "");
    // Each run gets its own XDG tree: vlt keeps its cache and its keychain
    // there.
    let xdg = |name: &str| {
        let root = fx.scratch.join(name);
        [
            ("XDG_CACHE_HOME", root.join("cache").display().to_string()),
            ("XDG_DATA_HOME", root.join("data").display().to_string()),
            ("XDG_CONFIG_HOME", root.join("config").display().to_string()),
        ]
    };
    let vlt = |args: &[&str], name: &str| {
        let env = xdg(name);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        tool(&fx.proj, "vlt", args, &env)
    };
    let install = vlt(&["install"], "upstream");
    if !install.status.success() {
        soft_skip!(LEG, "upstream `vlt install` failed:\n{}", dump(&install));
    }
    assert_pristine(&minimist_entry(&fx.proj), LEG);

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(
        pinned(&env),
        [format!("pkg:npm/{NPM_NAME}@{NPM_VERSION}")],
        "{LEG}: {env:#}"
    );
    assert_mirrored_pin(&read(&fx.proj.join("vlt-lock.json")), &private.base, LEG);

    let _ = std::fs::remove_dir_all(fx.proj.join("node_modules"));
    let refused = vlt(&["ci"], "cold-a");
    assert!(
        !refused.status.success(),
        "{LEG}: an install with no credentials must be refused:\n{}",
        dump(&refused)
    );

    let keychain = fx.scratch.join("cold-b/data/vlt/auth/keychain.json");
    std::fs::create_dir_all(keychain.parent().unwrap()).unwrap();
    std::fs::write(
        &keychain,
        serde_json::json!({ private.base.as_str(): private.authorization() }).to_string(),
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(fx.proj.join("node_modules"));
    let installed = vlt(&["ci"], "cold-b");
    assert!(
        installed.status.success(),
        "{LEG}: `vlt ci` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert_patched(&minimist_entry(&fx.proj), LEG);

    // `list` reads the mirrored pin as a hosted patch.
    let mut list = cli(&fx.proj);
    list.args(["list", "--patch-mirror-url", &private.base]);
    let out = list.output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Mode: hosted"),
        "{LEG}: `list` must read the mirrored vlt pin:\n{}",
        dump(&out)
    );
}

// ---------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------

/// A file of the installed `urllib3` that carries the patch.
fn urllib3_patched(venv: &Path) -> bool {
    let Ok(libs) = std::fs::read_dir(venv.join("lib")) else {
        return false;
    };
    libs.flatten().any(|lib| {
        let package = lib.path().join("site-packages").join(PYPI_NAME);
        walk(&package)
            .iter()
            .any(|f| std::fs::read_to_string(f).is_ok_and(|body| body.contains(PATCH_MARKER)))
    })
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// pip installs a direct URL reference with the credentials a netrc file
/// holds for the repository's host.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and PyPI. Run with --ignored."]
fn pip_installs_the_patch_through_artifactory() {
    const LEG: &str = "pip_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("python3") {
        soft_skip!(LEG, "`python3` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(
        fx.proj.join("requirements.txt"),
        format!("{PYPI_NAME}=={PYPI_VERSION}\n"),
    )
    .unwrap();
    let venv = fx.proj.join(".venv");
    let made = tool(&fx.proj, "python3", &["-m", "venv", ".venv"], &[]);
    if !made.status.success() {
        soft_skip!(LEG, "`python3 -m venv` failed:\n{}", dump(&made));
    }
    let python = venv.join("bin").join("python").display().to_string();
    let pip = |extra_env: &[(&str, &str)]| {
        tool(
            &fx.proj,
            &python,
            &[
                "-m",
                "pip",
                "install",
                "--no-input",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "--force-reinstall",
                "--no-deps",
                "-r",
                "requirements.txt",
            ],
            extra_env,
        )
    };
    let upstream = pip(&[]);
    if !upstream.status.success() {
        soft_skip!(LEG, "upstream `pip install` failed:\n{}", dump(&upstream));
    }
    assert!(
        !urllib3_patched(&venv),
        "{LEG}: the upstream install is already patched"
    );

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(
        pinned(&env),
        [format!("pkg:pypi/{PYPI_NAME}@{PYPI_VERSION}")],
        "{LEG}: {env:#}"
    );
    assert_mirrored_pin(&read(&fx.proj.join("requirements.txt")), &private.base, LEG);

    let refused = pip(&[]);
    assert!(
        !refused.status.success(),
        "{LEG}: an install with no credentials must be refused:\n{}",
        dump(&refused)
    );
    let netrc = private.netrc(&fx.scratch).display().to_string();
    let installed = pip(&[("NETRC", &netrc)]);
    assert!(
        installed.status.success(),
        "{LEG}: `pip install` through Artifactory failed:\n{}",
        dump(&installed)
    );
    assert!(
        urllib3_patched(&venv),
        "{LEG}: the installed urllib3 is not patched"
    );
}

/// uv installs a `uv.lock` URL source with the credentials a netrc file
/// holds for the repository's host.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and PyPI. Run with --ignored."]
fn uv_installs_the_patch_through_artifactory() {
    const LEG: &str = "uv_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("uv") {
        soft_skip!(LEG, "`uv` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(
        fx.proj.join("pyproject.toml"),
        format!(
            "[project]\nname = \"artifactory-e2e\"\nversion = \"0.0.0\"\n\
             requires-python = \">=3.9\"\ndependencies = [\"{PYPI_NAME}=={PYPI_VERSION}\"]\n"
        ),
    )
    .unwrap();
    let cache = |name: &str| fx.scratch.join(name).display().to_string();
    let locked = tool(
        &fx.proj,
        "uv",
        &["lock"],
        &[("UV_CACHE_DIR", &cache("upstream"))],
    );
    if !locked.status.success() {
        soft_skip!(LEG, "`uv lock` failed:\n{}", dump(&locked));
    }

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(pinned(&env).len(), 1, "{LEG}: {env:#}");
    assert_mirrored_pin(&read(&fx.proj.join("uv.lock")), &private.base, LEG);

    let netrc = private.netrc(&fx.scratch).display().to_string();
    let synced = tool(
        &fx.proj,
        "uv",
        &["sync", "--frozen"],
        &[("UV_CACHE_DIR", &cache("cold")), ("NETRC", &netrc)],
    );
    assert!(
        synced.status.success(),
        "{LEG}: `uv sync --frozen` through Artifactory failed:\n{}",
        dump(&synced)
    );
    assert!(
        urllib3_patched(&fx.proj.join(".venv")),
        "{LEG}: the installed urllib3 is not patched"
    );
}

/// PDM installs a `pdm.lock` URL file with the credentials a netrc file
/// holds for the repository's host.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and PyPI. Run with --ignored."]
fn pdm_installs_the_patch_through_artifactory() {
    const LEG: &str = "pdm_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("pdm") {
        soft_skip!(LEG, "`pdm` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(
        fx.proj.join("pyproject.toml"),
        format!(
            "[project]\nname = \"artifactory-e2e\"\nversion = \"0.0.0\"\n\
             requires-python = \">=3.9\"\ndependencies = [\"{PYPI_NAME}=={PYPI_VERSION}\"]\n\n\
             [tool.pdm]\ndistribution = false\n"
        ),
    )
    .unwrap();
    let pdm = |args: &[&str], cache: &str, extra: &[(&str, &str)]| {
        let cache = fx.scratch.join(cache).display().to_string();
        let mut env = vec![
            ("PDM_CACHE_DIR", cache.as_str()),
            ("PDM_CHECK_UPDATE", "false"),
        ];
        env.extend_from_slice(extra);
        tool(&fx.proj, "pdm", args, &env)
    };
    let locked = pdm(&["lock"], "upstream", &[]);
    if !locked.status.success() {
        soft_skip!(LEG, "`pdm lock` failed:\n{}", dump(&locked));
    }

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(
        pinned(&env),
        [format!("pkg:pypi/{PYPI_NAME}@{PYPI_VERSION}")],
        "{LEG}: {env:#}"
    );
    assert_mirrored_pin(&read(&fx.proj.join("pdm.lock")), &private.base, LEG);

    let sync = ["sync", "--no-self"];
    let refused = pdm(&sync, "cold-a", &[]);
    assert!(
        !refused.status.success(),
        "{LEG}: an install with no credentials must be refused:\n{}",
        dump(&refused)
    );
    let _ = std::fs::remove_dir_all(fx.proj.join(".venv"));
    let netrc = private.netrc(&fx.scratch).display().to_string();
    let synced = pdm(&sync, "cold-b", &[("NETRC", &netrc)]);
    assert!(
        synced.status.success(),
        "{LEG}: `pdm sync` through Artifactory failed:\n{}",
        dump(&synced)
    );
    assert!(
        urllib3_patched(&fx.proj.join(".venv")),
        "{LEG}: the installed urllib3 is not patched"
    );
}

/// Pipenv installs a `Pipfile.lock` file URL with the credentials a netrc
/// file holds for the repository's host. (`vendor` of a Pipenv project
/// pinned through a mirror is not covered here.)
#[test]
#[ignore = "live: a real Artifactory, the production patch API and PyPI. Run with --ignored."]
fn pipenv_installs_the_patch_through_artifactory() {
    const LEG: &str = "pipenv_installs_the_patch_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("pipenv") {
        soft_skip!(LEG, "`pipenv` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(
        fx.proj.join("Pipfile"),
        format!(
            "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n\
             [packages]\n{PYPI_NAME} = \"=={PYPI_VERSION}\"\n"
        ),
    )
    .unwrap();
    let pipenv = |args: &[&str], cache: &str, extra: &[(&str, &str)]| {
        let cache = fx.scratch.join(cache);
        let pip_cache = cache.join("pip").display().to_string();
        let cache = cache.display().to_string();
        let mut env = vec![
            ("PIPENV_CACHE_DIR", cache.as_str()),
            ("PIP_CACHE_DIR", pip_cache.as_str()),
            ("PIPENV_VENV_IN_PROJECT", "1"),
            ("PIPENV_IGNORE_VIRTUALENVS", "1"),
            ("PIPENV_YES", "1"),
            ("PIPENV_NOSPIN", "1"),
        ];
        env.extend_from_slice(extra);
        tool(&fx.proj, "pipenv", args, &env)
    };
    let locked = pipenv(&["lock"], "upstream", &[]);
    if !locked.status.success() {
        soft_skip!(LEG, "`pipenv lock` failed:\n{}", dump(&locked));
    }

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert_eq!(
        pinned(&env),
        [format!("pkg:pypi/{PYPI_NAME}@{PYPI_VERSION}")],
        "{LEG}: {env:#}"
    );
    assert_mirrored_pin(&read(&fx.proj.join("Pipfile.lock")), &private.base, LEG);

    let _ = std::fs::remove_dir_all(fx.proj.join(".venv"));
    let refused = pipenv(&["sync"], "cold-a", &[]);
    assert!(
        !refused.status.success(),
        "{LEG}: an install with no credentials must be refused:\n{}",
        dump(&refused)
    );
    let _ = std::fs::remove_dir_all(fx.proj.join(".venv"));
    let netrc = private.netrc(&fx.scratch).display().to_string();
    let synced = pipenv(&["sync"], "cold-b", &[("NETRC", &netrc)]);
    assert!(
        synced.status.success(),
        "{LEG}: `pipenv sync` through Artifactory failed:\n{}",
        dump(&synced)
    );
    assert!(
        urllib3_patched(&fx.proj.join(".venv")),
        "{LEG}: the installed urllib3 is not patched"
    );
}

// ---------------------------------------------------------------------------
// RubyGems
// ---------------------------------------------------------------------------

/// The sha256 the lock's `CHECKSUMS` section pins for `name (version)`.
fn lock_checksum(lock: &str, name: &str, version: &str) -> Option<String> {
    let lead = format!("  {name} ({version}) sha256=");
    lock.lines()
        .find_map(|line| line.strip_prefix(&lead))
        .map(|sha| sha.trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Bundler reads each patch's compact index and `.gem` through the
/// repository, with the credentials it holds for the repository's host,
/// and the gems it fetches are the ones the lock's checksums pin.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and rubygems.org. Run with --ignored."]
fn bundler_fetches_the_patched_gems_through_artifactory() {
    const LEG: &str = "bundler_fetches_the_patched_gems_through_artifactory";
    let Some(private) = Private::from_env() else {
        soft_skip!(
            LEG,
            "SOCKET_PATCH_ARTIFACTORY_E2E_BASE / _USER / _PASSWORD are not set"
        );
    };
    if !has_command("bundle") {
        soft_skip!(LEG, "`bundle` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(
        fx.proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\n\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .unwrap();
    let app_config = fx.proj.join(".bundle").display().to_string();
    let home = |name: &str| fx.scratch.join(name).display().to_string();
    let bundle = |args: &[&str], user_home: &str, extra: &[(&str, &str)]| {
        let mut env = vec![
            ("BUNDLE_APP_CONFIG", app_config.as_str()),
            ("BUNDLE_USER_HOME", user_home),
            ("GEM_HOME", user_home),
            // Lockfile checksums are opt-in before Bundler 4.
            ("BUNDLE_LOCKFILE_CHECKSUMS", "true"),
        ];
        env.extend_from_slice(extra);
        tool(&fx.proj, "bundle", args, &env)
    };
    let locked = bundle(&["lock"], &home("upstream"), &[]);
    if !locked.status.success() {
        soft_skip!(LEG, "`bundle lock` failed:\n{}", dump(&locked));
    }
    let upstream_checksum =
        lock_checksum(&read(&fx.proj.join("Gemfile.lock")), GEM_NAME, GEM_VERSION);
    if upstream_checksum.is_none() {
        soft_skip!(
            LEG,
            "this Bundler writes no lockfile checksums (it needs 2.6 or later)"
        );
    }

    // A project already pinned straight at the patch server: Bundler's pin
    // cannot be moved onto the mirror in place, so the run leaves it, says
    // so, and the remedy it names (roll back, run again) works.
    let mut direct = cli(&fx.proj);
    direct.args(["scan", "--mode", "hosted", "--json", "--yes"]);
    let out = direct.output().expect("run socket-patch");
    assert!(out.status.success(), "{LEG}: {}", dump(&out));
    let direct_lock = read(&fx.proj.join("Gemfile.lock"));
    assert!(
        direct_lock.contains(PATCH_HOST),
        "{LEG}: a run without a mirror pins the patch server:\n{direct_lock}"
    );
    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert!(
        warning_codes(&env).contains(&"redirect_mirror_pin_not_moved".to_string()),
        "{LEG}: {env:#}"
    );
    assert_eq!(
        read(&fx.proj.join("Gemfile.lock")),
        direct_lock,
        "{LEG}: the direct pin is left as it is"
    );
    let mut rollback = cli(&fx.proj);
    rollback.args(["rollback", "--json", "--yes"]);
    let out = rollback.output().expect("run socket-patch");
    assert!(
        out.status.success(),
        "{LEG}: rollback failed:\n{}",
        dump(&out)
    );
    assert!(
        !read(&fx.proj.join("Gemfile.lock")).contains(PATCH_HOST),
        "{LEG}: rollback must unwind the direct pins"
    );

    let env = scan_mirrored(&fx.proj, &private.base, Some(&private.authorization()));
    assert!(
        pinned(&env).contains(&format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}")),
        "{LEG}: {env:#}"
    );
    let lock = read(&fx.proj.join("Gemfile.lock"));
    assert!(
        lock.contains(&format!("remote: {}/patch-registry/gem/", private.base)),
        "{LEG}: the lock does not resolve the gem from the Artifactory repository:\n{lock}"
    );
    assert!(
        !lock.contains(PATCH_HOST),
        "{LEG}: the lock still names {PATCH_HOST}:\n{lock}"
    );
    assert!(
        read(&fx.proj.join("Gemfile")).contains(&format!("{}/patch-registry/gem/", private.base)),
        "{LEG}: the Gemfile does not name the Artifactory repository"
    );
    let patched_checksum = lock_checksum(&lock, GEM_NAME, GEM_VERSION).expect("checksum pinned");
    assert_ne!(
        Some(&patched_checksum),
        upstream_checksum.as_ref(),
        "{LEG}: the lock must pin the patched gem's checksum"
    );

    let fetch = ["cache", "--no-install"];
    let refused = bundle(&fetch, &home("cold-a"), &[("BUNDLE_FROZEN", "true")]);
    assert!(
        !refused.status.success(),
        "{LEG}: a fetch with no credentials must be refused:\n{}",
        dump(&refused)
    );

    // Bundler keys credentials by host name.
    let credentials = format!("{}:{}", private.user, private.password);
    let configured = bundle(
        &[
            "config",
            "set",
            "--local",
            &private.origin().2,
            &credentials,
        ],
        &home("cold-b"),
        &[],
    );
    assert!(configured.status.success(), "{LEG}: {}", dump(&configured));
    let _ = std::fs::remove_dir_all(fx.proj.join("vendor"));
    let fetched = bundle(&fetch, &home("cold-b"), &[("BUNDLE_FROZEN", "true")]);
    assert!(
        fetched.status.success(),
        "{LEG}: `bundle cache` through Artifactory failed:\n{}",
        dump(&fetched)
    );
    let gem = fx
        .proj
        .join("vendor")
        .join("cache")
        .join(format!("{GEM_NAME}-{GEM_VERSION}.gem"));
    let bytes =
        std::fs::read(&gem).unwrap_or_else(|e| panic!("{LEG}: read {}: {e}", gem.display()));
    assert_eq!(
        sha256_hex(&bytes),
        patched_checksum,
        "{LEG}: the gem Bundler fetched through Artifactory is not the patched gem the lock pins"
    );
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

const GO_MODULE: &str = "github.com/jackc/pgx/v5";
const GO_VERSION: &str = "v5.7.0";
/// Prints `PANIC` on the upstream module and `REJECTED` on the patched one:
/// the patch makes `FunctionCall.Decode` refuse a negative argument length.
const GO_MAIN: &str = r#"package main

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

func probe() (result string) {
	defer func() {
		if recover() != nil {
			result = "PANIC"
		}
	}()
	var msg pgproto3.FunctionCall
	if msg.Decode([]byte{0, 0, 0, 1, 0, 0, 0, 1, 255, 255, 255, 254}) != nil {
		return "REJECTED"
	}
	return "ACCEPTED"
}

func main() { fmt.Println(probe()) }
"#;

/// The go environment of one "machine": its own module and build caches,
/// no ambient configuration, `GOPROXY` as given.
fn go_env(cache: &Path, proxy: &str) -> Vec<(&'static str, String)> {
    let at = |name: &str| cache.join(name).display().to_string();
    vec![
        ("GOMODCACHE", at("mod")),
        ("GOPATH", at("path")),
        ("GOCACHE", at("build")),
        ("GOTOOLCHAIN", "local".into()),
        ("GOENV", "off".into()),
        ("GOWORK", "off".into()),
        // Writable, so the tempdir can be removed.
        ("GOFLAGS", "-mod=readonly -modcacherw".into()),
        ("GOPRIVATE", String::new()),
        ("GONOPROXY", String::new()),
        ("GONOSUMDB", String::new()),
        ("GOSUMDB", "sum.golang.org".into()),
        ("GOPROXY", proxy.into()),
    ]
}

fn go(cwd: &Path, args: &[&str], env: &[(&'static str, String)]) -> Output {
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    tool(cwd, "go", args, &env)
}

/// Every `# get <url>: <status>` line `go -x` printed for a Socket module.
fn socket_module_fetches(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter_map(|line| line.strip_prefix("# get "))
        .filter(|line| line.contains("/gopatch/") && line.contains(": "))
        .map(str::to_string)
        .collect()
}

/// A Go pin is the module path `patch.socket.dev/gopatch/<uuid>`, which a
/// mirror run leaves as it is. go fetches that module through the GOPROXY
/// protocol from the patch server's root, which a generic remote of it
/// serves at its base, so a build that lists the base first in `GOPROXY`
/// fetches every Socket module through Artifactory and falls through its
/// 404s for the rest. go sends credentials only over https, so a plain-http
/// repository must allow anonymous reads.
#[test]
#[ignore = "live: a real Artifactory, the production patch API and the Go module proxy. Run with --ignored."]
fn go_fetches_the_patched_modules_through_an_anonymous_repository() {
    const LEG: &str = "go_fetches_the_patched_modules_through_an_anonymous_repository";
    let Some(base) = setting("SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE") else {
        soft_skip!(LEG, "SOCKET_PATCH_ARTIFACTORY_E2E_ANON_BASE is not set");
    };
    let probe = tool(Path::new("."), "go", &["version"], &[]);
    if !probe.status.success() {
        soft_skip!(LEG, "`go` is not on PATH");
    }
    let fx = fixture();
    std::fs::write(fx.proj.join("main.go"), GO_MAIN).unwrap();
    std::fs::write(
        fx.proj.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {GO_MODULE} {GO_VERSION}\n"),
    )
    .unwrap();
    let upstream = go_env(&fx.scratch.join("go-upstream"), "https://proxy.golang.org");
    let tidy = go(
        &fx.proj,
        &["mod", "tidy"],
        &[&upstream[..], &[("GOFLAGS", "-mod=mod -modcacherw".into())]].concat(),
    );
    if !tidy.status.success() {
        soft_skip!(LEG, "`go mod tidy` failed:\n{}", dump(&tidy));
    }
    let run = go(&fx.proj, &["run", "."], &upstream);
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        "PANIC",
        "{LEG}: the upstream module must be the vulnerable one:\n{}",
        dump(&run)
    );

    let crawl: Vec<(&str, &str)> = upstream
        .iter()
        .filter(|(k, _)| matches!(*k, "GOMODCACHE" | "GOPATH" | "GOCACHE"))
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    let env = scan_mirrored_with(&fx.proj, &base, None, &crawl);
    assert!(
        pinned(&env).contains(&format!("pkg:golang/{GO_MODULE}@{GO_VERSION}")),
        "{LEG}: {env:#}"
    );
    let go_mod = read(&fx.proj.join("go.mod"));
    assert!(
        go_mod.contains(&format!(
            "replace {GO_MODULE} {GO_VERSION} => {PATCH_HOST}/gopatch/"
        )),
        "{LEG}: the pin is the module path, which a mirror run leaves as it is:\n{go_mod}"
    );
    let (_, base_rest) = base.split_once("://").expect("base is a URL");
    assert!(
        !go_mod.contains(base_rest) && !read(&fx.proj.join("go.sum")).contains(base_rest),
        "{LEG}: go.mod and go.sum name no mirror"
    );

    // A fresh machine with the repository first in GOPROXY.
    let cold = go_env(
        &fx.scratch.join("go-cold"),
        &format!("{base},https://proxy.golang.org"),
    );
    let download = go(&fx.proj, &["mod", "download", "-x", "all"], &cold);
    assert!(
        download.status.success(),
        "{LEG}: `go mod download` through Artifactory failed:\n{}",
        dump(&download)
    );
    let fetches = socket_module_fetches(&download);
    let zips: Vec<&String> = fetches.iter().filter(|f| f.contains(".zip: ")).collect();
    assert!(
        !zips.is_empty()
            && fetches
                .iter()
                .all(|f| f.starts_with(&format!("{base}/{PATCH_HOST}/gopatch/"))),
        "{LEG}: every Socket module must come from the repository:\n{fetches:#?}"
    );
    assert!(
        zips.iter().all(|f| f.contains(".zip: 200")),
        "{LEG}: {zips:#?}"
    );
    let run = go(&fx.proj, &["run", "."], &cold);
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        "REJECTED",
        "{LEG}: the module built from the repository must be the patched one:\n{}",
        dump(&run)
    );
}
