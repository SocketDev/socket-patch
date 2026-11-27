//! RubyGems platform names (`x86_64-linux-gnu`, `arm64-darwin`), and which
//! locked platform a platform gem serves.
//!
//! Bundler locks one build of a gem per platform under `PLATFORMS`, and
//! keeps the plain `name (version)` entry (the ruby gem) for every locked
//! platform that none of the gem's platform builds serves. Which build
//! serves which platform is RubyGems' `Gem::Platform#===`, with the gem's
//! platform as the receiver and the locked one as the argument. This module
//! ports that match for the operating systems whose names it can read
//! (Linux, macOS, Windows, Java) so a message can name the platforms that
//! keep a plain entry. It is used for wording only: nothing is wired or
//! refused because of it, and a platform it cannot read is never named.

/// A RubyGems platform, split the way `Gem::Platform.new` splits its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GemPlatform {
    cpu: Option<String>,
    os: &'static str,
    version: Option<String>,
}

impl GemPlatform {
    /// `name` as RubyGems reads it. `None` for `ruby` (no platform at all)
    /// and for an operating system this module does not know: the caller
    /// cannot tell what such a platform serves.
    pub(crate) fn parse(name: &str) -> Option<GemPlatform> {
        if name == "ruby" || name.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = name.split('-').map(str::to_string).collect();
        // `x86_64-linux-musl`: the libc belongs to the OS part. A trailing
        // number is a version of its own (`arm64-darwin-23`).
        if parts.len() > 2 && !parts.last().is_some_and(|last| ends_with_digit(last)) {
            let extra = parts.pop()?;
            let last = parts.last_mut()?;
            last.push('-');
            last.push_str(&extra);
        }
        let first = parts.remove(0);
        let cpu = match is_ix86(&first) {
            true => "x86".to_string(),
            false => first,
        };
        if parts.len() == 2 && is_number(&parts[1]) {
            let os = known_os(&parts[0])?.0;
            return Some(GemPlatform {
                cpu: Some(cpu),
                os,
                version: Some(parts[1].clone()),
            });
        }
        // A lone word is an OS without a CPU (`java`).
        let (cpu, os_part) = match parts.first() {
            Some(os_part) => (Some(cpu), os_part.clone()),
            None => (None, cpu),
        };
        let (os, version) = known_os(&os_part)?;
        Some(GemPlatform { cpu, os, version })
    }

    /// Whether a gem built for `self` is one Bundler installs on the locked
    /// platform `locked`: `Gem::Platform#===`. Not symmetric: on Linux a
    /// gem without a libc serves every libc, and a locked platform without
    /// one means glibc.
    pub(crate) fn serves(&self, locked: &GemPlatform) -> bool {
        let universal = |cpu: &Option<String>| cpu.as_deref() == Some("universal");
        if (universal(&self.cpu) || universal(&locked.cpu))
            && self.os.starts_with("mingw")
            && locked.os.starts_with("mingw")
        {
            return true;
        }
        let any_cpu = |cpu: &Option<String>| cpu.is_none() || universal(cpu);
        let cpu = any_cpu(&self.cpu)
            || any_cpu(&locked.cpu)
            || self.cpu == locked.cpu
            || (self.cpu.as_deref() == Some("arm")
                && locked.cpu.as_deref().is_some_and(|c| c.starts_with("armv")));
        if !cpu || self.os != locked.os {
            return false;
        }
        if self.version == locked.version {
            return true;
        }
        if self.os != "linux" {
            return self.version.is_none() || locked.version.is_none();
        }
        if self.linux_libc() == locked.linux_libc() {
            return true;
        }
        let own = self.version.as_deref().unwrap_or_default();
        locked.version.as_deref().is_some_and(|theirs| {
            ["musl", "musleabi", "musleabihf"]
                .iter()
                .any(|libc| theirs.strip_prefix(libc) == Some(own))
        })
    }

    /// The libc of a Linux platform without the `gnu` prefix and the ABI
    /// suffix (`normalized_linux_version`): `None` for glibc.
    fn linux_libc(&self) -> Option<&str> {
        let version = self.version.as_deref()?;
        let version = version.strip_prefix("gnu").unwrap_or(version);
        let version = version
            .strip_suffix("eabihf")
            .or_else(|| version.strip_suffix("eabi"))
            .unwrap_or(version);
        (!version.is_empty()).then_some(version)
    }
}

/// The locked platforms of `locked` that keep the plain entry of a gem
/// whose platform builds are `builds`: `ruby`, and each one that no build
/// [serves](GemPlatform::serves). In the order of `locked`. A platform this
/// module cannot read is left out, and so is every platform when one of the
/// builds cannot be read (what it serves is not known).
pub(crate) fn unserved_platforms<'a>(locked: &[&'a str], builds: &[String]) -> Vec<&'a str> {
    let Some(builds) = builds
        .iter()
        .map(|build| GemPlatform::parse(build))
        .collect::<Option<Vec<_>>>()
    else {
        return locked.iter().copied().filter(|p| *p == "ruby").collect();
    };
    locked
        .iter()
        .copied()
        .filter(|platform| match GemPlatform::parse(platform) {
            Some(parsed) => !builds.iter().any(|build| build.serves(&parsed)),
            None => *platform == "ruby",
        })
        .collect()
}

/// The OS and version of the OS part of a platform name, for the operating
/// systems read here. RubyGems matches these names anywhere in the part.
fn known_os(part: &str) -> Option<(&'static str, Option<String>)> {
    let after = |word: &str| part.find(word).map(|at| &part[at + word.len()..]);
    let digits = |rest: &str| {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        (end > 0).then(|| rest[..end].to_string())
    };
    let word = |rest: &str| {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        (end > 0).then(|| rest[..end].to_string())
    };
    if let Some(rest) = after("darwin") {
        return Some(("darwin", digits(rest)));
    }
    if part == "java" || part == "jruby" {
        return Some(("java", None));
    }
    if let Some(rest) = after("linux") {
        return Some(("linux", word(rest)));
    }
    if part.contains("mingw32") {
        return Some(("mingw32", None));
    }
    if let Some(rest) = after("mingw") {
        return Some(("mingw", word(rest)));
    }
    None
}

/// `i386` … `i686`, which RubyGems reads as `x86`.
fn is_ix86(cpu: &str) -> bool {
    let bytes = cpu.as_bytes();
    bytes.len() == 4 && bytes[0] == b'i' && bytes[1].is_ascii_digit() && &bytes[2..] == b"86"
}

fn ends_with_digit(part: &str) -> bool {
    part.chars().last().is_some_and(|c| c.is_ascii_digit())
}

/// `23` or `23.1`.
fn is_number(part: &str) -> bool {
    let mut halves = part.splitn(2, '.');
    let whole = |half: Option<&str>| {
        half.is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_digit()))
    };
    let first = whole(halves.next());
    match halves.next() {
        None => first,
        fraction => first && whole(fraction),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `Gem::Platform.new(gem) === Gem::Platform.new(locked)` answers
    /// in RubyGems 3.5.22, for every pair of these names: each row is a
    /// gem platform and the locked platforms it serves.
    const RUBYGEMS_SERVES: &[(&str, &[&str])] = &[
        (
            "aarch64-linux",
            &["aarch64-linux", "aarch64-linux-gnu", "aarch64-linux-musl"],
        ),
        (
            "x86_64-linux",
            &["x86_64-linux", "x86_64-linux-gnu", "x86_64-linux-musl"],
        ),
        ("x86_64-linux-gnu", &["x86_64-linux", "x86_64-linux-gnu"]),
        ("x86_64-linux-musl", &["x86_64-linux-musl"]),
        ("aarch64-linux-gnu", &["aarch64-linux", "aarch64-linux-gnu"]),
        ("aarch64-linux-musl", &["aarch64-linux-musl"]),
        ("arm-linux-gnu", &["arm-linux-gnu", "arm-linux-gnueabihf"]),
        (
            "arm-linux-musl",
            &["arm-linux-musl", "arm-linux-musleabihf"],
        ),
        (
            "arm64-darwin",
            &["arm64-darwin", "universal-darwin", "arm64-darwin-23"],
        ),
        ("x86_64-darwin", &["x86_64-darwin", "universal-darwin"]),
        (
            "universal-darwin",
            &[
                "arm64-darwin",
                "x86_64-darwin",
                "universal-darwin",
                "arm64-darwin-23",
            ],
        ),
        ("x64-mingw-ucrt", &["x64-mingw-ucrt", "universal-mingw32"]),
        ("x64-mingw32", &["x64-mingw32", "universal-mingw32"]),
        ("x86-mingw32", &["x86-mingw32", "universal-mingw32"]),
        ("java", &["java"]),
        (
            "arm-linux-gnueabihf",
            &["arm-linux-gnu", "arm-linux-gnueabihf"],
        ),
        (
            "arm-linux-musleabihf",
            &["arm-linux-musl", "arm-linux-musleabihf"],
        ),
        ("x86-linux-gnu", &["x86-linux-gnu", "i686-linux"]),
        ("i686-linux", &["x86-linux-gnu", "i686-linux"]),
        (
            "arm64-darwin-23",
            &["arm64-darwin", "universal-darwin", "arm64-darwin-23"],
        ),
        (
            "universal-mingw32",
            &[
                "x64-mingw-ucrt",
                "x64-mingw32",
                "x86-mingw32",
                "universal-mingw32",
            ],
        ),
    ];

    #[test]
    fn serves_agrees_with_rubygems_on_every_pair() {
        for (gem, served) in RUBYGEMS_SERVES {
            let build = GemPlatform::parse(gem).unwrap_or_else(|| panic!("{gem} must parse"));
            for (locked, _) in RUBYGEMS_SERVES {
                let platform = GemPlatform::parse(locked).unwrap();
                assert_eq!(
                    build.serves(&platform),
                    served.contains(locked),
                    "a {gem} gem on the locked platform {locked}"
                );
            }
        }
    }

    #[test]
    fn names_split_the_way_rubygems_splits_them() {
        let split = |name: &str| {
            let p = GemPlatform::parse(name).unwrap();
            (p.cpu, p.os, p.version)
        };
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            split("arm-linux-gnueabihf"),
            (some("arm"), "linux", some("gnueabihf"))
        );
        assert_eq!(
            split("x64-mingw-ucrt"),
            (some("x64"), "mingw", some("ucrt"))
        );
        assert_eq!(split("x86-mingw32"), (some("x86"), "mingw32", None));
        assert_eq!(split("java"), (None, "java", None));
        assert_eq!(
            split("universal-darwin"),
            (some("universal"), "darwin", None)
        );
        assert_eq!(
            split("arm64-darwin-23"),
            (some("arm64"), "darwin", some("23"))
        );
        assert_eq!(
            split("x86_64-darwin22"),
            (some("x86_64"), "darwin", some("22"))
        );
        assert_eq!(split("i686-linux"), (some("x86"), "linux", None));
    }

    #[test]
    fn ruby_and_unknown_systems_are_not_read() {
        for name in [
            "ruby",
            "",
            "x86_64-freebsd14",
            "wasm32-wasi",
            "x64-mswin64_140",
        ] {
            assert_eq!(GemPlatform::parse(name), None, "{name}");
        }
    }

    /// The lock of #2284: thruster ships no 32-bit ARM build, nokogiri
    /// ships one for every platform of the lock.
    #[test]
    fn unserved_platforms_are_the_ones_no_build_serves() {
        let locked = [
            "aarch64-linux",
            "aarch64-linux-gnu",
            "aarch64-linux-musl",
            "arm-linux-gnu",
            "arm-linux-musl",
            "arm64-darwin",
            "ruby",
            "x86_64-darwin",
            "x86_64-linux-gnu",
            "x86_64-linux-musl",
        ];
        let builds = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let thruster = builds(&[
            "aarch64-linux",
            "arm64-darwin",
            "x86_64-darwin",
            "x86_64-linux",
        ]);
        assert_eq!(
            unserved_platforms(&locked, &thruster),
            ["arm-linux-gnu", "arm-linux-musl", "ruby"]
        );
        let nokogiri = builds(&[
            "aarch64-linux-gnu",
            "aarch64-linux-musl",
            "arm-linux-gnu",
            "arm-linux-musl",
            "arm64-darwin",
            "x86_64-darwin",
            "x86_64-linux-gnu",
            "x86_64-linux-musl",
        ]);
        assert_eq!(unserved_platforms(&locked, &nokogiri), ["ruby"]);
    }

    /// What cannot be read is never named: a locked platform of an unknown
    /// system, and every platform when a build is of one.
    #[test]
    fn unreadable_platforms_are_never_named() {
        let builds = vec!["x86_64-linux".to_string()];
        assert_eq!(
            unserved_platforms(&["x86_64-freebsd14", "arm64-darwin", "ruby"], &builds),
            ["arm64-darwin", "ruby"]
        );
        let odd = vec!["x86_64-linux".to_string(), "x86_64-freebsd14".to_string()];
        assert_eq!(
            unserved_platforms(&["arm64-darwin", "ruby", "x86_64-freebsd14"], &odd),
            ["ruby"]
        );
    }
}
