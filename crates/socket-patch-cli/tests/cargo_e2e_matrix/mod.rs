//! Toolchain / Cargo.lock-format knobs shared by the real-cargo e2e suites
//! (`e2e_redirect_cargo_build`, `e2e_vendor_cargo_build`,
//! `mode_migration_cargo`, `e2e_safety_cargo_build`), so one local loop (or
//! one CI matrix leg per cell) drives every hosted + vendored flow through a
//! given cargo release and lock format:
//!
//! * `SOCKET_PATCH_CARGO_E2E_TOOLCHAIN` — a rustup toolchain (`1.82.0`,
//!   `stable`, …) every child `cargo` runs under (`RUSTUP_TOOLCHAIN`).
//!   Unset: the ambient `cargo` (under `cargo test` that is the repo's
//!   pinned `rust-toolchain.toml` channel, which rustup exports to the test
//!   process). When set, the suites assert `cargo --version` really is that
//!   release (a leg can never go green on the wrong toolchain).
//! * `SOCKET_PATCH_CARGO_E2E_LOCK_VERSION` — `1`..`4`: the fixture's
//!   baseline `Cargo.lock` (whatever the toolchain wrote) is re-encoded in
//!   that lock format BEFORE socket-patch touches it, so the rewriters and
//!   discovery meet each format cargo has ever written. Formats older than
//!   the toolchain's default are the committed-lockfile shape (cargo reads
//!   every older format and, under `--locked`, never rewrites it — verified
//!   on cargo 1.97 for v1/v2/v3). Unset: the toolchain's own default (v4
//!   from cargo 1.83, v3 from 1.53, v2 from 1.41).
//! * `SOCKET_PATCH_CARGO_E2E_REQUIRED=1` — turn the soft skips (`cargo`
//!   missing, crates.io unreachable for the fixture build) into failures.
//!
//! Local sweep (every cell of the v1–v4 lock format × toolchain grid):
//!
//! ```sh
//! for tc in 1.82.0 stable; do for lv in 1 2 3 4; do
//!   SOCKET_PATCH_CARGO_E2E_REQUIRED=1 SOCKET_PATCH_CARGO_E2E_TOOLCHAIN=$tc \
//!   SOCKET_PATCH_CARGO_E2E_LOCK_VERSION=$lv \
//!   cargo test -p socket-patch-cli --test e2e_redirect_cargo_build \
//!     --test e2e_vendor_cargo_build --test mode_migration_cargo
//! done; done
//! ```

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

pub const TOOLCHAIN_ENV: &str = "SOCKET_PATCH_CARGO_E2E_TOOLCHAIN";
pub const LOCK_VERSION_ENV: &str = "SOCKET_PATCH_CARGO_E2E_LOCK_VERSION";
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_CARGO_E2E_REQUIRED";

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The pinned toolchain, if any.
pub fn toolchain() -> Option<String> {
    env_nonempty(TOOLCHAIN_ENV)
}

/// The requested Cargo.lock format, if any (panics on a bad value).
pub fn lock_version() -> Option<u8> {
    env_nonempty(LOCK_VERSION_ENV).map(|v| match v.parse::<u8>() {
        Ok(n @ 1..=4) => n,
        _ => panic!("{LOCK_VERSION_ENV}={v:?}: expected 1, 2, 3 or 4"),
    })
}

/// Whether a missing toolchain / unreachable crates.io must fail the test.
pub fn required() -> bool {
    env_nonempty(REQUIRED_ENV).is_some_and(|v| v != "0")
}

/// `true` = the caller must return (skipped); panics instead when
/// [`required`].
#[must_use]
pub fn skip(suite: &str, why: &str) -> bool {
    assert!(
        !required(),
        "{suite}: {why} (and {REQUIRED_ENV} is set, so this leg must not skip)"
    );
    println!("SKIP {suite}: {why}");
    true
}

/// A `cargo` child with the fixture's private `CARGO_HOME`, the pinned
/// toolchain, and no ambient `CARGO_TARGET_DIR` (shared-build-cache setups
/// would redirect child builds out of the fixture).
pub fn cargo_command(cwd: &Path, cargo_home: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(cwd)
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_TARGET_DIR");
    if let Some(tc) = toolchain() {
        cmd.env("RUSTUP_TOOLCHAIN", tc);
    }
    cmd
}

/// `cargo --version` of the toolchain the children run, or `None` when no
/// `cargo` can be spawned.
pub fn cargo_version() -> Option<String> {
    let tmp = std::env::temp_dir();
    let out = cargo_command(&tmp, &home_for_version_probe())
        .arg("--version")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn home_for_version_probe() -> std::path::PathBuf {
    // `cargo --version` touches nothing in CARGO_HOME; keep the ambient one.
    std::env::var_os("CARGO_HOME")
        .map(Into::into)
        .unwrap_or_else(std::env::temp_dir)
}

/// Gate a real-cargo test: `false` (skip, message printed) when cargo is
/// not runnable and the leg is not [`required`]. When a toolchain is pinned
/// by number, asserts the children really run it.
pub fn cargo_available(suite: &str) -> bool {
    let Some(version) = cargo_version() else {
        let why = match toolchain() {
            Some(tc) => format!("`cargo` for toolchain {tc} is not runnable"),
            None => "`cargo` not installed".to_string(),
        };
        let _ = skip(suite, &why);
        return false;
    };
    if let Some(tc) = toolchain() {
        if tc.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            assert!(
                version.starts_with(&format!("cargo {tc}")),
                "{TOOLCHAIN_ENV}={tc} but the children run {version:?}"
            );
        }
    }
    println!("{suite}: {version}, lock format {:?}", lock_version());
    true
}

// ── Cargo.lock formats ────────────────────────────────────────────────

/// One `[[package]]` of a lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
    /// Dependency NAMES (the fixtures never lock two versions of a crate).
    pub dependencies: Vec<String>,
}

/// The lock format of `text`: `version = N` (3 / 4), else v1 when it has
/// a `[metadata]` table or `"name version (source)"` references, else v2.
pub fn lock_format(text: &str) -> u8 {
    if let Some(v) = text.lines().find_map(|l| {
        l.strip_prefix("version = ")
            .and_then(|v| v.trim().parse::<u8>().ok())
    }) {
        return v;
    }
    let v1_ref = text
        .lines()
        .any(|l| l.trim_start().starts_with('"') && l.contains(" (") && l.contains(")\","));
    if text.contains("\n[metadata]") || v1_ref {
        1
    } else {
        2
    }
}

fn quoted(value: &str) -> Option<String> {
    let v = value.trim();
    v.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .map(str::to_string)
}

/// Parse the `[[package]]` tables of a v1–v4 lock (the flat shape cargo
/// writes; v1 checksums are read back from `[metadata]`).
pub fn parse_lock(text: &str) -> Vec<LockPackage> {
    let mut pkgs: Vec<LockPackage> = Vec::new();
    let mut metadata: Vec<(String, String)> = Vec::new();
    let mut section = "";
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && !in_deps {
            section = if t == "[[package]]" {
                pkgs.push(LockPackage {
                    name: String::new(),
                    version: String::new(),
                    source: None,
                    checksum: None,
                    dependencies: Vec::new(),
                });
                "package"
            } else if t == "[metadata]" {
                "metadata"
            } else {
                "other"
            };
            continue;
        }
        match section {
            "package" => {
                let pkg = pkgs.last_mut().expect("inside a [[package]]");
                if in_deps {
                    if t == "]" {
                        in_deps = false;
                    } else if let Some(dep) = quoted(t.trim_end_matches(',')) {
                        let name = dep.split(' ').next().unwrap_or_default().to_string();
                        pkg.dependencies.push(name);
                    }
                    continue;
                }
                let Some((key, value)) = t.split_once(" = ") else {
                    continue;
                };
                match key {
                    "name" => pkg.name = quoted(value).unwrap_or_default(),
                    "version" => pkg.version = quoted(value).unwrap_or_default(),
                    "source" => pkg.source = quoted(value),
                    "checksum" => pkg.checksum = quoted(value),
                    "dependencies" if value.trim() == "[" => in_deps = true,
                    _ => {}
                }
            }
            "metadata" => {
                if let Some((key, value)) = t.split_once(" = ") {
                    if let (Some(k), Some(v)) = (quoted(key), quoted(value)) {
                        metadata.push((k, v));
                    }
                }
            }
            _ => {}
        }
    }
    for pkg in &mut pkgs {
        if pkg.checksum.is_none() {
            if let Some(src) = &pkg.source {
                let key = format!("checksum {} {} ({src})", pkg.name, pkg.version);
                pkg.checksum = metadata
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v.clone());
            }
        }
    }
    pkgs
}

/// Serialize `pkgs` in lock format `version` — byte-for-byte the layout
/// the cargo release that defaults to that format writes (header comment
/// for v2+, `version = N` for v3+, v1's full `"name version (source)"`
/// references and trailing `[metadata]` checksums).
pub fn write_lock(pkgs: &[LockPackage], version: u8) -> String {
    let mut sorted = pkgs.to_vec();
    sorted.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    let mut out = String::new();
    if version >= 2 {
        out.push_str(
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\n",
        );
    }
    if version >= 3 {
        out.push_str(&format!("version = {version}\n\n"));
    }
    let dep_ref = |name: &str| -> String {
        if version >= 2 {
            return name.to_string();
        }
        let dep = sorted
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("lock dependency {name} is not a locked package"));
        match &dep.source {
            Some(src) => format!("{} {} ({src})", dep.name, dep.version),
            None => format!("{} {}", dep.name, dep.version),
        }
    };
    let blocks: Vec<String> = sorted
        .iter()
        .map(|p| {
            let mut b = format!(
                "[[package]]\nname = \"{}\"\nversion = \"{}\"\n",
                p.name, p.version
            );
            if let Some(src) = &p.source {
                b.push_str(&format!("source = \"{src}\"\n"));
            }
            if version >= 2 {
                if let Some(sum) = &p.checksum {
                    b.push_str(&format!("checksum = \"{sum}\"\n"));
                }
            }
            if !p.dependencies.is_empty() {
                b.push_str("dependencies = [\n");
                for d in &p.dependencies {
                    b.push_str(&format!(" \"{}\",\n", dep_ref(d)));
                }
                b.push_str("]\n");
            }
            b
        })
        .collect();
    out.push_str(&blocks.join("\n"));
    if version == 1 {
        let sums: Vec<String> = sorted
            .iter()
            .filter_map(|p| {
                let (src, sum) = (p.source.as_ref()?, p.checksum.as_ref()?);
                Some(format!(
                    "\"checksum {} {} ({src})\" = \"{sum}\"\n",
                    p.name, p.version
                ))
            })
            .collect();
        if !sums.is_empty() {
            out.push_str("\n[metadata]\n");
            out.push_str(&sums.concat());
        }
    }
    out
}

/// Re-encode `<proj>/Cargo.lock` in the requested [`lock_version`] (no-op
/// when unset). Returns the format the lock is in afterwards.
pub fn apply_lock_version(proj: &Path) -> u8 {
    let path = proj.join("Cargo.lock");
    let text = std::fs::read_to_string(&path).expect("read Cargo.lock");
    let Some(version) = lock_version() else {
        return lock_format(&text);
    };
    let pkgs = parse_lock(&text);
    let encoded = write_lock(&pkgs, version);
    assert_eq!(
        parse_lock(&encoded),
        {
            let mut s = pkgs.clone();
            s.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
            s
        },
        "lock v{version} re-encoding must be lossless"
    );
    assert_eq!(lock_format(&encoded), version, "{encoded}");
    std::fs::write(&path, encoded).expect("write Cargo.lock");
    version
}
