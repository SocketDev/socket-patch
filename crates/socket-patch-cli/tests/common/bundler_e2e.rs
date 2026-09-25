//! Bundler selection + gating for the real-bundler gem suites
//! (`e2e_redirect_gem_build`, `e2e_vendor_gem_build`).
//!
//! The suites shell out to whatever `bundle` is first on `PATH` — in CI the
//! one `ruby/setup-ruby`'s `bundler:` input installed, selected by exporting
//! `BUNDLER_VERSION` (without it RubyGems' binstub runs the highest installed
//! bundler, i.e. the Ruby's newer default gem on a leg pinned below it);
//! locally the host's, or a per-version wrapper dir prepended to `PATH`:
//!
//! ```text
//! gem install bundler -v 2.4.22 --install-dir "$D/2.4.22" --no-document
//! # "$D/wrap-2.4.22/bundle":
//! #   GEM_PATH="$D/2.4.22:$(ruby -e 'print Gem.path.join(":")')" //! #     exec ruby "$D/2.4.22/bin/bundle" _2.4.22_ "$@"
//! PATH="$D/wrap-2.4.22:$PATH" SOCKET_PATCH_BUNDLER_E2E_VERSION=2.4.22 //!   cargo test -p socket-patch-cli --test e2e_vendor_gem_build -- --ignored
//! ```
//!
//! (bundler <= 2.2 does not boot on Ruby >= 3.4 — run it under Ruby 3.1–3.3.
//! 1.17–2.1 also need that Ruby's own RubyGems (<= 3.4; later releases drop
//! `Gem::Platform.match`) and call `untaint`, removed in Ruby 3.2 — on
//! 3.2/3.3 load a no-op `Object#untaint` ahead of bundler, or use Ruby 3.1
//! as `tests/docker/Dockerfile.gem-b1` does.) Two env knobs turn that into a
//! checked version matrix:
//!
//! * `SOCKET_PATCH_BUNDLER_E2E_VERSION=<x[.y[.z]]>` — the bundler the leg
//!   was provisioned with. The probed `bundle --version` must match it at a
//!   component boundary (`2.5` matches `2.5.23`, never `2.50.0`), else the
//!   suite PANICS: a matrix leg that silently runs the runner's default
//!   bundler proves nothing about the version it is named after.
//! * `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1` — a missing `ruby` / `gem` /
//!   `bundle` (or an unparseable version) is a hard failure instead of the
//!   local-dev SKIP. A test whose own floor is above the provisioned bundler
//!   (e.g. the CHECKSUMS arm on bundler 2.5) still skips — that is a
//!   version gate, not a missing tool — and says so on stdout.
//!
//! Pull in with `#[path = "common/bundler_e2e.rs"] mod bundler_e2e;`.

#![allow(dead_code)]

use std::process::{Command, Stdio};

pub const VERSION_ENV: &str = "SOCKET_PATCH_BUNDLER_E2E_VERSION";
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_BUNDLER_E2E_REQUIRED";

/// A probed `bundle --version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundler {
    /// The full version string (`1.17.3`, `2.5.23`, `4.0.15`).
    pub version: String,
    pub major: u32,
    pub minor: u32,
}

impl Bundler {
    /// `self >= major.minor`.
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }

    /// argv for `bundle config <key> <value>` scoped to the project's
    /// `.bundle/config`. `config set --local` only exists from bundler 2.1;
    /// older releases (1.17, 2.0) take the flag form (which 2.1+ still
    /// accepts with a deprecation warning, and bundler 4 removed).
    pub fn config_local_args(&self, key: &str, value: &str) -> Vec<String> {
        let mut argv = vec!["config".to_string()];
        if self.at_least(2, 1) {
            argv.push("set".into());
        }
        argv.extend(["--local".into(), key.into(), value.into()]);
        argv
    }
}

/// Parse `bundle --version` stdout: `Bundler version 2.7.2` (bundler < 4)
/// or a bare `4.0.15` (bundler 4).
pub fn parse_version(stdout: &str) -> Option<Bundler> {
    let version = stdout.split_whitespace().last()?.to_string();
    let mut it = version.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some(Bundler {
        version,
        major,
        minor,
    })
}

/// `want` names `have` at a version-component boundary.
pub fn version_matches(have: &str, want: &str) -> bool {
    have == want
        || have
            .strip_prefix(want)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn required() -> bool {
    std::env::var(REQUIRED_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// A missing toolchain: panic under [`REQUIRED_ENV`], else print the SKIP.
fn missing(suite: &str, tag: &str, why: &str) -> Option<Bundler> {
    assert!(
        !required(),
        "{suite} ({tag}): {why}, and {REQUIRED_ENV}=1 forbids skipping"
    );
    println!("SKIP {suite} ({tag}): {why}");
    None
}

/// Gate one real-bundler test: the toolchain must be present (see the
/// module docs for the env contract) and the probed bundler at least
/// `floor`. `isolate` applies the suite's cache isolation to the probes so
/// they answer for the same environment the real installs run in.
pub fn gate(
    suite: &str,
    tag: &str,
    floor: (u32, u32),
    isolate: &dyn Fn(&mut Command),
) -> Option<Bundler> {
    for cmd in ["ruby", "gem", "bundle"] {
        let mut probe = Command::new(cmd);
        probe.arg("--version");
        isolate(&mut probe);
        let ok = probe
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if !ok {
            return missing(suite, tag, &format!("`{cmd}` not installed"));
        }
    }
    let mut probe = Command::new("bundle");
    probe.arg("--version");
    isolate(&mut probe);
    let parsed = probe
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_version(&String::from_utf8_lossy(&o.stdout)));
    let Some(bundler) = parsed else {
        return missing(suite, tag, "`bundle --version` failed or is unparseable");
    };
    if let Ok(want) = std::env::var(VERSION_ENV) {
        let want = want.trim();
        assert!(
            want.is_empty() || version_matches(&bundler.version, want),
            "{suite} ({tag}): {VERSION_ENV}={want} but `bundle` on PATH is {} — the matrix \
             leg is not running the bundler it is named after (a bundler older than the \
             Ruby's default gem is only selected with BUNDLER_VERSION={want})",
            bundler.version
        );
    }
    if !bundler.at_least(floor.0, floor.1) {
        println!(
            "SKIP {suite} ({tag}): bundler {} is below this test's {}.{} floor",
            bundler.version, floor.0, floor.1
        );
        return None;
    }
    println!(
        "{suite} ({tag}): running against bundler {}",
        bundler.version
    );
    Some(bundler)
}

/// Runs in every suite that includes this module (no `#[cfg(test)]`: an
/// integration crate does not set it, so the gate would compile the test
/// out).
mod bundler_e2e_selftest {
    use super::*;

    #[test]
    fn version_grammar() {
        let b = parse_version("Bundler version 1.17.3\n").unwrap();
        assert_eq!((b.major, b.minor, b.version.as_str()), (1, 17, "1.17.3"));
        let b = parse_version("4.0.15\n").unwrap();
        assert_eq!((b.major, b.minor), (4, 0));
        assert!(parse_version("").is_none());
        assert!(version_matches("2.5.23", "2.5"));
        assert!(version_matches("2.5.23", "2.5.23"));
        assert!(!version_matches("2.50.0", "2.5"));
        assert!(b.at_least(2, 6) && !b.at_least(4, 1));
        let old = parse_version("Bundler version 2.0.2").unwrap();
        assert_eq!(
            old.config_local_args("path", "vendor/bundle"),
            ["config", "--local", "path", "vendor/bundle"]
        );
        assert_eq!(
            b.config_local_args("path", "vendor/bundle"),
            ["config", "set", "--local", "path", "vendor/bundle"]
        );
    }
}
