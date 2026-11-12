//! Suite configuration: the `SOCKET_PATCH_BAZEL_E2E_*` variables, the Bazel
//! version a cell drives and the flags that differ per Bazel line.

use std::ffi::OsString;

/// The Bazel binary to drive, or a launcher; unset = `bazel` on `PATH`.
pub const BAZEL: &str = "SOCKET_PATCH_BAZEL_E2E_BAZEL";
/// `bazel --version` must print exactly this. Exported to the child as
/// `USE_BAZEL_VERSION`, so a launcher selects it.
pub const VERSION: &str = "SOCKET_PATCH_BAZEL_E2E_VERSION";
/// Non-empty: a missing Bazel or an unreachable origin fails instead of SKIP.
pub const REQUIRED: &str = "SOCKET_PATCH_BAZEL_E2E_REQUIRED";
/// `core` / `light` / `heavy`: tests of another group print `SKIP (n/a)`.
pub const GROUP: &str = "SOCKET_PATCH_BAZEL_E2E_GROUP";
/// `bzlmod` / `workspace` / `hybrid`: tests of another system print `SKIP (n/a)`.
pub const SYSTEM: &str = "SOCKET_PATCH_BAZEL_E2E_SYSTEM";
/// The launcher cell: the pinned bazelisk, run with `USE_BAZEL_VERSION` set
/// to the absolute path in [`BINARY`], which it uses with no download.
pub const BAZELISK: &str = "SOCKET_PATCH_BAZEL_E2E_BAZELISK";
pub const BINARY: &str = "SOCKET_PATCH_BAZEL_E2E_BINARY";
/// Where the per-cell JSON reports go.
pub const PROBE_DIR: &str = "SOCKET_PATCH_BAZEL_E2E_PROBE_DIR";
/// A persistent repository cache (`<root>/repos`) shared by every cell.
pub const CACHE_ROOT: &str = "SOCKET_PATCH_BAZEL_E2E_CACHE_ROOT";
/// A short directory for output user roots (Windows path limits).
pub const OUTPUT_ROOT: &str = "SOCKET_PATCH_BAZEL_E2E_OUTPUT_ROOT";
/// Extra whitespace-separated command options for every Bazel command.
pub const ARGS: &str = "SOCKET_PATCH_BAZEL_E2E_ARGS";
/// The offline phase: every download is rewritten to a fixture server with
/// an empty store, with the proxies at a closed port (see `workspace`).
pub const OFFLINE: &str = "SOCKET_PATCH_BAZEL_E2E_OFFLINE";
/// The real-registry cell: tests with such a variant skip the fixture server.
pub const REAL_REGISTRIES: &str = "SOCKET_PATCH_BAZEL_E2E_REAL_REGISTRIES";

/// Removed from every Bazel child. `TEST_TMPDIR` puts a Bazel server in
/// test mode, where a failing extension on 7.x is a crash (exit 37) and
/// not an error; `USE_BAZEL_VERSION` is set again from [`VERSION`]; the
/// tool homes would let a ruleset's package manager read or write the
/// developer's caches; the CI markers change what some rulesets log.
pub const REMOVED: &[&str] = &[
    "TEST_TMPDIR",
    "NETRC",
    "XDG_CACHE_HOME",
    "USE_BAZEL_VERSION",
    "CI",
    "GITHUB_ACTIONS",
    "CARGO_HOME",
    "GOFLAGS",
    "GOENV",
    "GOMODCACHE",
    "NUGET_PACKAGES",
    "GEM_HOME",
];

/// The proxy variables Bazel's downloader and the ruleset tools honour.
pub const PROXY: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// `name`'s value when it is set and non-empty.
pub fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

pub fn flag(name: &str) -> bool {
    var(name).is_some()
}

/// CI cells set [`REQUIRED`]: never skip there.
pub fn required() -> bool {
    flag(REQUIRED)
}

pub fn offline() -> bool {
    flag(OFFLINE)
}

pub fn real_registries() -> bool {
    flag(REAL_REGISTRIES)
}

/// [`ARGS`], split on whitespace.
pub fn extra_args() -> Vec<String> {
    let args = std::env::var(ARGS).unwrap_or_default();
    args.split_whitespace().map(str::to_string).collect()
}

/// The fixture group a test belongs to (the directory under
/// `fixtures/bazel/`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Core,
    Light,
    Heavy,
}

impl Group {
    pub fn name(self) -> &'static str {
        match self {
            Group::Core => "core",
            Group::Light => "light",
            Group::Heavy => "heavy",
        }
    }

    pub fn parse(text: &str) -> Option<Group> {
        [Group::Core, Group::Light, Group::Heavy]
            .into_iter()
            .find(|g| g.name() == text)
    }
}

/// How a workspace declares its external dependencies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum System {
    Bzlmod,
    Workspace,
    Hybrid,
}

impl System {
    pub fn name(self) -> &'static str {
        match self {
            System::Bzlmod => "bzlmod",
            System::Workspace => "workspace",
            System::Hybrid => "hybrid",
        }
    }

    pub fn parse(text: &str) -> Option<System> {
        [System::Bzlmod, System::Workspace, System::Hybrid]
            .into_iter()
            .find(|s| s.name() == text)
    }
}

/// What a [`GROUP`] value selects: `None` (unset) = every group. A value
/// that names no group is an error, not "every group": a typo in a CI cell
/// must not turn into a run that skips everything it was meant to cover.
pub fn parse_group(value: Option<&str>) -> Result<Option<Group>, String> {
    let Some(text) = value else { return Ok(None) };
    let group = Group::parse(text);
    group
        .map(Some)
        .ok_or_else(|| format!("{GROUP}={text} names no fixture group (core, light, heavy)"))
}

/// What a [`SYSTEM`] value selects: `None` (unset) = every system. An
/// unknown value is an error, as for [`parse_group`].
pub fn parse_system(value: Option<&str>) -> Result<Option<System>, String> {
    let Some(text) = value else { return Ok(None) };
    let system = System::parse(text);
    system.map(Some).ok_or_else(|| {
        format!("{SYSTEM}={text} names no dependency system (bzlmod, workspace, hybrid)")
    })
}

/// The group [`GROUP`] selects; `None` = every group. Panics on a value
/// [`parse_group`] refuses.
pub fn selected_group() -> Option<Group> {
    let text = var(GROUP).map(|v| v.to_string_lossy().into_owned());
    parse_group(text.as_deref()).unwrap_or_else(|why| panic!("{why}"))
}

/// The dependency system [`SYSTEM`] selects; `None` = every system. Panics
/// on a value [`parse_system`] refuses.
pub fn selected_system() -> Option<System> {
    let text = var(SYSTEM).map(|v| v.to_string_lossy().into_owned());
    parse_system(text.as_deref()).unwrap_or_else(|why| panic!("{why}"))
}

/// A Bazel release as `bazel --version` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub text: String,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// `10.0.0rc3`, `9.0.0-pre.20250101.1`: anything after the three numbers.
    pub prerelease: bool,
}

impl Version {
    /// `None` for anything that is not three dotted numbers with an optional
    /// suffix: a version the harness cannot order gets no per-line flags.
    pub fn parse(text: &str) -> Option<Version> {
        let core_len = text
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len());
        let (core, suffix) = text.split_at(core_len);
        let parts: Vec<u32> = core
            .split('.')
            .map(|p| p.parse().ok())
            .collect::<Option<_>>()?;
        let [major, minor, patch] = parts[..] else {
            return None;
        };
        Some(Version {
            text: text.to_string(),
            major,
            minor,
            patch,
            prerelease: !suffix.is_empty(),
        })
    }

    /// Whether this release is `major.minor.patch` or later. A pre-release
    /// of a threshold is below it (`10.0.0rc3` is not yet `10.0.0`).
    pub fn at_least(&self, major: u32, minor: u32, patch: u32) -> bool {
        let own = (self.major, self.minor, self.patch);
        let threshold = (major, minor, patch);
        own > threshold || (own == threshold && !self.prerelease)
    }

    /// The command options that select `system` on this line, or `None`
    /// when the line does not have it: Bzlmod on 5.x is a refused tier,
    /// and 9.x removed WORKSPACE. An empty list means the line's default
    /// flags already select it, given the files the fixture carries.
    pub fn system_flags(&self, system: System) -> Option<&'static [&'static str]> {
        Some(match (self.major, system) {
            (0..=5, System::Workspace) => &[],
            (0..=5, _) => return None,
            // 6.x has no --enable_workspace: Bzlmod there always reads WORKSPACE too.
            (6, System::Workspace) => &[],
            (6, _) => &["--enable_bzlmod"],
            // --enable_workspace arrived in 7.1 and defaults to on.
            (7, System::Workspace) => &["--noenable_bzlmod"],
            (7, _) => &[],
            (8, System::Bzlmod) => &[],
            (8, System::Workspace) => &["--enable_workspace", "--noenable_bzlmod"],
            (8, System::Hybrid) => &["--enable_workspace"],
            (_, System::Bzlmod) => &[],
            (_, _) => return None,
        })
    }

    /// `--lockfile_mode` exists from 6.2.
    pub fn has_lockfile_mode(&self) -> bool {
        self.at_least(6, 2, 0)
    }

    /// `--repo_contents_cache` exists from 8.3 (and is on by default in 9.x).
    pub fn has_contents_cache(&self) -> bool {
        self.at_least(8, 3, 0)
    }

    /// 8.2.0 renamed the flag: 8.0.x and 8.1.x know only the experimental
    /// spelling (`Unrecognized option` for the new one), and from 8.2.0 the
    /// old name still works but prints a deprecation warning on every
    /// command.
    pub fn downloader_config_flag(&self) -> &'static str {
        if self.at_least(8, 2, 0) {
            "--downloader_config"
        } else {
            "--experimental_downloader_config"
        }
    }
}
