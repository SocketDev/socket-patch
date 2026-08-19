//! Bundler version floor for the generated plugin wiring.
//!
//! The `plugin "socket-patch", path: ...` directive `setup` writes needs
//! bundler >= 2.2. Bundler 1.x cannot load it: `Plugin::DSL` undef_methods
//! `:path` and the 1.x plugin installer supports only git/rubygems sources,
//! so the directive is resolved as an ORDINARY GEM and every later
//! `bundle install` dies with exit 7 ("Could not find gem 'socket-patch'
//! ...") BEFORE plugin registration — an error that never names
//! socket-patch, and in deployment mode adds a misleading "Perhaps the
//! lockfile is corrupted?" line (reproduced on bundler 1.17.3). Wiring such
//! a project is strictly worse than refusing.
//!
//! The probe reads, in order:
//!   1. the lock's `BUNDLED WITH` section (`Gemfile.lock`, or `gems.locked`
//!      for a `gems.rb` project) — deterministic, present even where
//!      `bundle` is not on PATH, and the best predictor of the bundler that
//!      will actually run installs (RubyGems' version switching selects the
//!      locked bundler when installed; bundler >= 2.3 auto-installs it);
//!   2. `bundle --version` in the project root — the machine's bundler,
//!      for lock-less projects. Bundler 4 dropped the "Bundler version "
//!      prefix and prints the bare version, so both spellings parse.
//!
//! When NEITHER source yields a version the probe reports [`BundlerProbe::
//! Unknown`] and callers fail OPEN (wire as before): a machine without
//! bundler may be preparing a repo whose CI has a modern bundler, and
//! refusing there would block every such setup on a guess.

use std::path::PathBuf;
use std::time::Duration;

use tokio::fs;

use super::BundlerProject;

/// Upper bound on the `bundle --version` fallback probe. A wedged bundler
/// (broken RubyGems install, hung shim) must degrade to [`BundlerProbe::
/// Unknown`] — fail open — rather than hang `setup`/`setup --check` forever.
const BUNDLE_VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum bundler `(major, minor)` able to load a `plugin ... path:`
/// directive.
pub const MIN_BUNDLER: (u64, u64) = (2, 2);

/// Outcome of probing the project's bundler version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundlerProbe {
    /// A version at or above [`MIN_BUNDLER`] was detected.
    Supported,
    /// A version below [`MIN_BUNDLER`] was detected. `version` is the
    /// detected version string; `source` names where it was read from
    /// (for the refusal message).
    Unsupported { version: String, source: String },
    /// No version could be determined (no lock, no `bundle` on PATH, or
    /// unparseable output). Callers fail open.
    Unknown,
}

/// The lockfile paired with the project's manifest name: `gems.rb` locks to
/// `gems.locked`, `Gemfile` to `Gemfile.lock` (Bundler's own pairing).
fn lockfile_path(project: &BundlerProject) -> PathBuf {
    let lock_name = match project.gemfile.file_name().and_then(|n| n.to_str()) {
        Some("gems.rb") => "gems.locked",
        _ => "Gemfile.lock",
    };
    project.root.join(lock_name)
}

/// Extract the version under a lock's `BUNDLED WITH` section: the first
/// non-empty line after the header, trimmed.
fn parse_bundled_with(lock: &str) -> Option<String> {
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "BUNDLED WITH" {
            continue;
        }
        for candidate in lines.by_ref() {
            let candidate = candidate.trim();
            if !candidate.is_empty() {
                return looks_like_version(candidate).then(|| candidate.to_string());
            }
        }
        return None;
    }
    None
}

/// Extract a version from `bundle --version` output. Bundler <= 3 prints
/// "Bundler version 2.7.2"; bundler 4 prints the bare "4.0.18". Take the
/// first whitespace token that parses as a dotted version.
fn parse_bundle_version_output(out: &str) -> Option<String> {
    out.split_whitespace()
        .find(|tok| looks_like_version(tok))
        .map(str::to_string)
}

/// A token counts as a version when it is `digits.digits[...]` — enough to
/// reject prose without a full semver parser.
fn looks_like_version(tok: &str) -> bool {
    let mut parts = tok.split('.');
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        return false;
    };
    !major.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && !minor.is_empty()
        && minor.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `version` (a `major.minor[...]` string) meets [`MIN_BUNDLER`].
/// `None` when the leading components don't parse.
fn meets_floor(version: &str) -> Option<bool> {
    let mut parts = version.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    Some((major, minor) >= MIN_BUNDLER)
}

/// Classify one detected `(version, source)` pair.
fn classify(version: String, source: String) -> BundlerProbe {
    match meets_floor(&version) {
        Some(true) => BundlerProbe::Supported,
        Some(false) => BundlerProbe::Unsupported { version, source },
        // Unparseable leading components: treat as unknown, fail open.
        None => BundlerProbe::Unknown,
    }
}

/// Probe the bundler version that will run this project's installs. See the
/// module docs for the source order and the fail-open contract.
pub async fn probe_bundler(project: &BundlerProject) -> BundlerProbe {
    let lock_path = lockfile_path(project);
    if let Ok(lock) = fs::read_to_string(&lock_path).await {
        if let Some(version) = parse_bundled_with(&lock) {
            let lock_name = lock_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Gemfile.lock".to_string());
            return classify(version, format!("{lock_name} BUNDLED WITH"));
        }
    }
    // No lock (or no BUNDLED WITH): ask the machine's bundler. stdin nulled
    // so the child can never block waiting for input; bounded by
    // [`BUNDLE_VERSION_TIMEOUT`] (with `kill_on_drop` so a timed-out child is
    // reaped, not leaked) so a wedged bundler degrades to `Unknown`.
    let output = tokio::time::timeout(
        BUNDLE_VERSION_TIMEOUT,
        tokio::process::Command::new("bundle")
            .arg("--version")
            .current_dir(&project.root)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    if let Ok(Ok(out)) = output {
        if out.status.success() {
            if let Some(version) =
                parse_bundle_version_output(&String::from_utf8_lossy(&out.stdout))
            {
                return classify(version, "`bundle --version`".to_string());
            }
        }
    }
    BundlerProbe::Unknown
}

/// The refusal message for an [`BundlerProbe::Unsupported`] project — shared
/// by `setup` (which refuses to wire) so the wording stays consistent.
pub fn unsupported_bundler_message(version: &str, source: &str) -> String {
    format!(
        "bundler {version} (from {source}) cannot load the socket-patch Bundler \
         plugin: the `plugin ... path:` directive needs bundler >= {}.{}, and on \
         1.x every later `bundle install` fails resolving 'socket-patch' as an \
         ordinary gem (exit 7) before the plugin registers. Not wiring this \
         project. Upgrade bundler (`gem install bundler`, then `bundle update \
         --bundler`) and re-run `socket-patch setup`",
        MIN_BUNDLER.0, MIN_BUNDLER.1
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK_1X: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
                           colorize (1.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
                           colorize (= 1.1.0)\n\nBUNDLED WITH\n   1.17.3\n";

    async fn project_with(files: &[(&str, &str)]) -> (tempfile::TempDir, BundlerProject) {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            fs::write(dir.path().join(name), body).await.unwrap();
        }
        let project = super::super::discover_bundler_project(dir.path())
            .await
            .expect("fixture project must be discoverable");
        (dir, project)
    }

    #[test]
    fn test_parse_bundled_with() {
        assert_eq!(parse_bundled_with(LOCK_1X).as_deref(), Some("1.17.3"));
        assert_eq!(
            parse_bundled_with("BUNDLED WITH\n   2.7.2\n").as_deref(),
            Some("2.7.2")
        );
        // No section, or a section followed by garbage → None.
        assert_eq!(parse_bundled_with("GEM\n  specs:\n"), None);
        assert_eq!(parse_bundled_with("BUNDLED WITH\n   not-a-version\n"), None);
        assert_eq!(parse_bundled_with("BUNDLED WITH\n"), None);
    }

    #[test]
    fn test_parse_bundle_version_output_both_spellings() {
        // bundler <= 3 prefix form and bundler 4's bare form.
        assert_eq!(
            parse_bundle_version_output("Bundler version 2.7.2\n").as_deref(),
            Some("2.7.2")
        );
        assert_eq!(
            parse_bundle_version_output("4.0.18\n").as_deref(),
            Some("4.0.18")
        );
        assert_eq!(parse_bundle_version_output("command not found\n"), None);
    }

    #[test]
    fn test_meets_floor_boundaries() {
        assert_eq!(meets_floor("1.17.3"), Some(false));
        assert_eq!(meets_floor("2.1.4"), Some(false));
        assert_eq!(meets_floor("2.2.0"), Some(true));
        assert_eq!(meets_floor("2.7.2"), Some(true));
        assert_eq!(meets_floor("4.0.18"), Some(true));
        // Bare major (no minor) or garbage: unknown, never a refusal.
        assert_eq!(meets_floor("2"), None);
        assert_eq!(meets_floor("abc"), None);
    }

    #[tokio::test]
    async fn test_probe_reads_gemfile_lock_bundled_with() {
        let (_dir, project) =
            project_with(&[("Gemfile", "source 'x'\n"), ("Gemfile.lock", LOCK_1X)]).await;
        assert_eq!(
            probe_bundler(&project).await,
            BundlerProbe::Unsupported {
                version: "1.17.3".to_string(),
                source: "Gemfile.lock BUNDLED WITH".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn test_probe_supported_lock() {
        let (_dir, project) = project_with(&[
            ("Gemfile", "source 'x'\n"),
            ("Gemfile.lock", "BUNDLED WITH\n   2.7.2\n"),
        ])
        .await;
        assert_eq!(probe_bundler(&project).await, BundlerProbe::Supported);
    }

    #[tokio::test]
    async fn test_probe_gems_rb_pairs_with_gems_locked() {
        // A gems.rb project locks to gems.locked — a stray Gemfile.lock (from
        // before a rename) must NOT be consulted for it.
        let (_dir, project) = project_with(&[
            ("gems.rb", "source 'x'\n"),
            ("gems.locked", LOCK_1X),
            ("Gemfile.lock", "BUNDLED WITH\n   2.7.2\n"),
        ])
        .await;
        assert_eq!(
            probe_bundler(&project).await,
            BundlerProbe::Unsupported {
                version: "1.17.3".to_string(),
                source: "gems.locked BUNDLED WITH".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn test_probe_lock_beats_machine_bundler() {
        // With a lock present the machine's `bundle --version` is never
        // consulted: RubyGems' version switching makes the LOCKED bundler the
        // one that runs installs. (This also keeps the probe deterministic on
        // hosts whose bundler differs from the project's.)
        let (_dir, project) = project_with(&[
            ("Gemfile", "source 'x'\n"),
            ("Gemfile.lock", "BUNDLED WITH\n   1.17.3\n"),
        ])
        .await;
        // Host bundler (if any) is >= 2.x on every dev/CI machine this suite
        // runs on; the probe must still report the lock's 1.17.3.
        assert!(matches!(
            probe_bundler(&project).await,
            BundlerProbe::Unsupported { .. }
        ));
    }

    #[test]
    fn test_unsupported_message_names_version_floor_and_remedy() {
        let msg = unsupported_bundler_message("1.17.3", "Gemfile.lock BUNDLED WITH");
        assert!(msg.contains("1.17.3"));
        assert!(msg.contains(">= 2.2"));
        assert!(msg.contains("gem install bundler"));
        assert!(msg.contains("socket-patch setup"));
    }
}
