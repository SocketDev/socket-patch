//! Bazel labels, as far as they name a file (design 2.7).
//!
//! A hub names its lock with a label, a `MODULE.bazel` names its segments
//! with one, and a `WORKSPACE` names its macro files with one. socket-patch
//! reads the file behind a label only when the label is one plain string
//! that names a file of the main repository; anything else leaves the
//! declaration incomplete.
//!
//! [`Label::parse`] follows Bazel's `LabelParser` and `LabelValidator`
//! (read at 9.3.2) and is stricter in two places, because its result is
//! joined to the Bazel root and read: a target name of `.` or one ending
//! in `/.` is refused (Bazel keeps both "for legacy reasons"), and so is
//! any byte outside printable ASCII. A label this parser accepts is one
//! Bazel accepts, and [`Label::path`] never leaves the root: no segment is
//! empty, `.` or `..`.

/// The repository part of a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repo {
    /// The main repository: `//pkg:name`, a relative label, `@//pkg:name`
    /// and `@@//pkg:name`.
    Main,
    /// `@name//pkg:name`: a name the repository mapping of the file that
    /// wrote the label resolves. It can be the main repository too (the
    /// root module's own name), which only the caller can tell.
    Apparent(String),
    /// `@@name//pkg:name`: a canonical name, which depends on the Bazel
    /// release and is never composed here.
    Canonical(String),
}

/// A parsed label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub repo: Repo,
    /// `""` for the root package.
    pub package: String,
    pub name: String,
}

/// Why a string is not a label that can be followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    Empty,
    /// A relative label (`:name`, `name`) where nothing says which package
    /// it is relative to, or the command-line form `pkg:name`.
    Relative,
    /// A repository name with a character Bazel rejects.
    Repository,
    /// A package with an empty or dot-only segment, a leading or trailing
    /// `/`, a `...` wildcard, or a character Bazel rejects.
    Package,
    /// An empty target name, one with an empty, `.` or `..` segment, or a
    /// character Bazel rejects.
    Target,
}

impl LabelError {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Empty => "the label is empty",
            Self::Relative => "the label is relative and no package gives it a meaning",
            Self::Repository => "the repository name is not one Bazel accepts",
            Self::Package => "the package is not one Bazel accepts",
            Self::Target => "the target name is not one Bazel accepts",
        }
    }
}

/// Printable ASCII but `:` and `\`: what Bazel allows in a package and,
/// between its `/` separators, in a target name.
fn label_byte(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) && byte != b':' && byte != b'\\'
}

/// The segments of a package or target path are all real names: a path
/// built from them stays below the directory it is joined to.
fn segments_ok(path: &str, dot_only_allowed: bool) -> bool {
    let dots = |segment: &str| segment.bytes().all(|b| b == b'.');
    let ok = |segment: &str| match segment {
        "" | "." | ".." => false,
        _ => dot_only_allowed || !dots(segment),
    };
    path.bytes().all(label_byte) && path.split('/').all(ok)
}

impl Label {
    /// Parses `text`. `package` is the package a relative label is
    /// relative to: `Some("")` in a `MODULE.bazel` and for the `load` of a
    /// `WORKSPACE` file (the root package), the file's own package in a
    /// `BUILD` or `.bzl` file, and `None` where a relative label names no
    /// file (an attribute of a `WORKSPACE` rule lives in `//external`).
    pub fn parse(text: &str, package: Option<&str>) -> Result<Self, LabelError> {
        if text.is_empty() {
            return Err(LabelError::Empty);
        }
        let canonical = text.starts_with("@@");
        let (repo, body, absolute) = match text.strip_prefix('@') {
            Some(rest) => {
                let rest = rest.strip_prefix('@').unwrap_or(rest);
                match rest.split_once("//") {
                    Some((repo, body)) => (Some(repo), body, true),
                    // `@foo` is `@foo//:foo`.
                    None => return Self::build(Some(rest), canonical, "", rest),
                }
            }
            None => match text.strip_prefix("//") {
                Some(body) => (None, body, true),
                None => (None, text, false),
            },
        };
        match (body.split_once(':'), absolute) {
            (Some((pkg, name)), true) => Self::build(repo, canonical, pkg, name),
            // `//foo/bar` is `//foo/bar:bar`.
            (None, true) => {
                let name = body.rsplit_once('/').map_or(body, |(_, last)| last);
                Self::build(repo, canonical, body, name)
            }
            // `pkg:name` is a command-line form: Bazel rejects it in a file.
            (Some((pkg, _)), false) if !pkg.is_empty() => Err(LabelError::Relative),
            (colon, false) => {
                let name = colon.map_or(body, |(_, name)| name);
                let package = package.ok_or(LabelError::Relative)?;
                Self::build(None, false, package, name)
            }
        }
    }

    fn build(
        repo: Option<&str>,
        canonical: bool,
        package: &str,
        name: &str,
    ) -> Result<Self, LabelError> {
        let repo_byte = |b: u8| b.is_ascii_alphanumeric() || b"_-.+~".contains(&b);
        let repo = match repo {
            None | Some("") => Repo::Main,
            Some(repo) if !repo.bytes().all(repo_byte) => return Err(LabelError::Repository),
            Some(repo) if canonical => Repo::Canonical(repo.to_string()),
            Some(repo) => Repo::Apparent(repo.to_string()),
        };
        // A dot-only segment is refused in a package (`...` is a wildcard
        // there); a target may have one that is not `.` or `..`.
        if !package.is_empty() && !segments_ok(package, false) {
            return Err(LabelError::Package);
        }
        if !segments_ok(name, true) {
            return Err(LabelError::Target);
        }
        Ok(Self {
            repo,
            package: package.to_string(),
            name: name.to_string(),
        })
    }

    /// The file the label names, relative to the root of its repository:
    /// forward slashes, no empty, `.` or `..` segment.
    pub fn file(&self) -> String {
        match self.package.as_str() {
            "" => self.name.clone(),
            package => format!("{package}/{}", self.name),
        }
    }

    /// The path, relative to the Bazel root, of the main-repository file
    /// the label names. `None` for a label into another repository, whose
    /// files socket-patch does not read.
    pub fn path(&self) -> Option<String> {
        (self.repo == Repo::Main).then(|| self.file())
    }
}

/// The root-relative path of the main-repository file `text` names, for a
/// label that must be one (a lock label, an `include`, a macro file).
pub fn main_repo_path(text: &str, package: Option<&str>) -> Option<String> {
    Label::parse(text, package).ok()?.path()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(repo: Repo, package: &str, name: &str) -> Label {
        Label {
            repo,
            package: package.to_string(),
            name: name.to_string(),
        }
    }

    /// The table in the doc comment of Bazel's `LabelParser.Parts.parse`
    /// (9.3.2), without its wildcard rows, which no file may write.
    #[test]
    fn labels_parse_as_bazel_parses_them() {
        let apparent = || Repo::Apparent("repo".to_string());
        let canonical = || Repo::Canonical("repo".to_string());
        for (text, want) in [
            ("//foo/bar", label(Repo::Main, "foo/bar", "bar")),
            ("//foo/all", label(Repo::Main, "foo/all", "all")),
            ("@repo", label(apparent(), "", "repo")),
            ("@@repo", label(canonical(), "", "repo")),
            ("@repo//foo/bar", label(apparent(), "foo/bar", "bar")),
            ("@@repo//foo/bar", label(canonical(), "foo/bar", "bar")),
            ("//foo/bar:quux", label(Repo::Main, "foo/bar", "quux")),
            ("@repo//foo/bar:quux", label(apparent(), "foo/bar", "quux")),
            ("//:quux", label(Repo::Main, "", "quux")),
            ("@//foo:quux", label(Repo::Main, "foo", "quux")),
            ("@@//foo:quux", label(Repo::Main, "foo", "quux")),
            (
                "@@rules_x+//:ext.bzl",
                label(Repo::Canonical("rules_x+".to_string()), "", "ext.bzl"),
            ),
            (
                "@@rules_x~//:ext.bzl",
                label(Repo::Canonical("rules_x~".to_string()), "", "ext.bzl"),
            ),
        ] {
            assert_eq!(Label::parse(text, None), Ok(want.clone()), "{text}");
            // An absolute label means the same in every package.
            assert_eq!(Label::parse(text, Some("pkg")), Ok(want), "{text}");
        }
        for wildcard in ["//foo/...", "//...", "//foo/...:all"] {
            let parsed = Label::parse(wildcard, Some(""));
            assert_eq!(parsed, Err(LabelError::Package), "{wildcard}");
        }
    }

    /// A relative label is a file only where a package gives it a meaning.
    #[test]
    fn a_relative_label_needs_its_package() {
        for text in [":quux", "quux", "sub/quux.txt", ":sub/quux.txt"] {
            assert_eq!(Label::parse(text, None), Err(LabelError::Relative));
            let name = text.trim_start_matches(':');
            assert_eq!(
                Label::parse(text, Some("")).unwrap().path().as_deref(),
                Some(name)
            );
            assert_eq!(
                Label::parse(text, Some("a/b")).unwrap().path(),
                Some(format!("a/b/{name}"))
            );
        }
        // Bazel: "absolute label must begin with '@' or '//'".
        let command_line = Label::parse("foo/bar:quux", Some(""));
        assert_eq!(command_line, Err(LabelError::Relative));
    }

    /// The label forms probe S1a ran through `include()` on 7.2.0 to
    /// 10.0.0rc3: each names the file Bazel read, or looked for.
    #[test]
    fn a_main_repository_label_is_its_file() {
        let segment = ".socket/bazel/socket-patch.MODULE.bazel";
        for (text, path) in [
            ("//.socket/bazel:socket-patch.MODULE.bazel", segment),
            ("//:.socket/bazel/socket-patch.MODULE.bazel", segment),
            ("//.socket:bazel/socket-patch.MODULE.bazel", segment),
            (
                "//svc:.socket/bazel/socket-patch.MODULE.bazel",
                "svc/.socket/bazel/socket-patch.MODULE.bazel",
            ),
            // No colon: the last segment is the package and the target,
            // which is why Bazel reports a missing BUILD file there.
            (
                "//.socket/bazel/socket-patch.MODULE.bazel",
                ".socket/bazel/socket-patch.MODULE.bazel/socket-patch.MODULE.bazel",
            ),
            ("//:pnpm-lock.yaml", "pnpm-lock.yaml"),
            (
                "@//third_party:maven_install.json",
                "third_party/maven_install.json",
            ),
            ("//a:b c/d+e.txt", "a/b c/d+e.txt"),
            ("//a:...", "a/..."),
        ] {
            assert_eq!(main_repo_path(text, None).as_deref(), Some(path), "{text}");
        }
        // Another repository's file is not read, whatever it is called.
        for external in ["@maven//:pin", "@@maven+//:pin", "@pip"] {
            assert!(Label::parse(external, None).is_ok(), "{external}");
            assert_eq!(main_repo_path(external, None), None, "{external}");
        }
        let hub = Label::parse("@maven//:defs.bzl", None).unwrap();
        assert_eq!(hub.file(), "defs.bzl");
    }

    /// The path of a label is joined to the Bazel root and read, so no
    /// label may climb out of it or name the root itself.
    #[test]
    fn a_label_that_could_leave_the_root_is_refused() {
        use LabelError::{Empty, Package, Repository, Target};
        for (text, want) in [
            ("", Empty),
            ("//a:../b", Target),
            ("//a:b/../c", Target),
            ("//a:b/..", Target),
            ("//a:..", Target),
            ("//a:.", Target),
            ("//a:b/.", Target),
            ("//a:./b", Target),
            ("//a:/etc/passwd", Target),
            ("//a:b//c", Target),
            ("//a:b/", Target),
            ("//a:", Target),
            ("//a:b:c", Target),
            ("//a:b\\c", Target),
            ("//a:b\tc", Target),
            ("//a:caf\u{e9}", Target),
            ("//", Target),
            ("@", Target),
            ("//../a:b", Package),
            ("//a/../b:c", Package),
            ("//a/./b:c", Package),
            ("///a:b", Package),
            ("//a//b:c", Package),
            ("//a/:b", Package),
            ("//a\\b:c", Package),
            ("@re po//a:b", Repository),
            ("@re/po", Repository),
            ("@@re$po//a:b", Repository),
        ] {
            assert_eq!(Label::parse(text, Some("")), Err(want), "{text:?}");
        }
        for error in [Empty, LabelError::Relative, Repository, Package, Target] {
            assert!(!error.describe().is_empty());
        }
    }
}
