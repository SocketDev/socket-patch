//! Pure `go.sum` line edits for the hosted Go redirect.
//!
//! The hosted redirect (`scan --mode hosted`) points a `replace` directive at
//! a Socket-published module (see `go_mod_edit::HOSTED_GO_MODULE_PREFIX`) and
//! must commit that module's two `go.sum` lines alongside it:
//!
//! ```text
//! patch.socket.dev/gopatch/<uuid> <version> h1:<base64>
//! patch.socket.dev/gopatch/<uuid> <version>/go.mod h1:<base64>
//! ```
//!
//! Both lines are load-bearing on day-2 machines (validated empirically —
//! see `docs/design/golang-hosted.md`): under the default `-mod=readonly` a
//! missing zip line fails resolution up front, a missing `/go.mod` line fails
//! after download, and a *present* line is verified against the fetched bytes
//! (a wrong hash is a hard `SECURITY ERROR`). Crucially, go consults the
//! checksum database (`GOSUMDB`) only for modules **absent** from `go.sum` —
//! committed lines mean fresh clones and CI never ask `sum.golang.org` about
//! the Socket module, which is what makes the hosted redirect committable.
//!
//! Everything here is a pure `&str` transform (the hosted rewriters operate on
//! in-memory file content, mirrored byte-identically by depscan's TS twins).
//! Unrelated lines are preserved verbatim; insertions keep go's lexicographic
//! line order so a later `go mod tidy` is a no-op, not a reshuffle. (Whole-line
//! byte order equals go's `(module, version)` sort because `' '` compares
//! below every module-path/version character, and the zip line sorts before
//! its `/go.mod` sibling because `' '` < `'/'`.)

/// The two `go.sum` lines for one module version.
fn module_lines(module: &str, version: &str, zip_h1: &str, gomod_h1: &str) -> [String; 2] {
    [
        format!("{module} {version} {zip_h1}"),
        format!("{module} {version}/go.mod {gomod_h1}"),
    ]
}

/// Upsert the two `go.sum` lines for `module@version`. Any existing lines for
/// exactly that module+version (either suffix form) are replaced; everything
/// else — including stale lines for the *replaced* original module, which go
/// tolerates and `go mod tidy` prunes — is preserved verbatim. `content` may
/// be empty (a project whose `go.sum` does not exist yet). Returns the new
/// content, or `None` when the file already carries exactly these lines.
pub fn upsert_module_lines(
    content: &str,
    module: &str,
    version: &str,
    zip_h1: &str,
    gomod_h1: &str,
) -> Option<String> {
    let want = module_lines(module, version, zip_h1, gomod_h1);
    let zip_key = format!("{module} {version} ");
    let gomod_key = format!("{module} {version}/go.mod ");

    let mut lines: Vec<&str> = content.lines().collect();
    let already = lines
        .iter()
        .filter(|l| **l == want[0] || **l == want[1])
        .count()
        == 2;
    if already {
        return None;
    }
    lines.retain(|l| !l.starts_with(&zip_key) && !l.starts_with(&gomod_key));

    // Insert both lines at their sorted position (stable against an unsorted
    // user file: first line strictly greater wins; ties cannot occur — the
    // exact-key duplicates were just removed).
    let mut out: Vec<&str> = Vec::with_capacity(lines.len() + 2);
    let mut pending = want.iter().map(String::as_str).peekable();
    for line in lines {
        while pending.peek().is_some_and(|w| *w < line) {
            out.push(
                pending
                    .next()
                    .expect("peek() just confirmed a pending element"),
            );
        }
        out.push(line);
    }
    out.extend(pending);

    let mut joined = out.join("\n");
    joined.push('\n');
    Some(joined)
}

/// Remove the lines for exactly `module@version` (both the zip and `/go.mod`
/// forms). Used to prune the REPLACED original's lines: once a version-pinned
/// `replace` covers the resolved version, go never fetches (or verifies) the
/// original at all, and `go mod tidy` prunes exactly these lines — writing
/// that state up front keeps the first day-2 tidy a byte-level no-op. Returns
/// `(new_content, removed_lines)`, or `None` when nothing matched.
pub fn remove_exact_module_version_lines(
    content: &str,
    module: &str,
    version: &str,
) -> Option<(String, Vec<String>)> {
    let zip_key = format!("{module} {version} ");
    let gomod_key = format!("{module} {version}/go.mod ");
    let mut removed: Vec<String> = Vec::new();
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| {
            if l.starts_with(&zip_key) || l.starts_with(&gomod_key) {
                removed.push((*l).to_string());
                false
            } else {
                true
            }
        })
        .collect();
    if removed.is_empty() {
        return None;
    }
    if kept.is_empty() {
        return Some((String::new(), removed));
    }
    let mut joined = kept.join("\n");
    joined.push('\n');
    Some((joined, removed))
}

/// Remove every `go.sum` line whose module path starts with `module_prefix`
/// (both the zip and `/go.mod` forms, any version). `go.sum` lines carry no
/// ownership markers, so removal — like ownership — keys on the socket-hosted
/// module namespace. Returns the new content, or `None` when nothing matched.
pub fn remove_module_prefix_lines(content: &str, module_prefix: &str) -> Option<String> {
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .next()
                .is_none_or(|m| !m.starts_with(module_prefix))
        })
        .collect();
    if kept.len() == content.lines().count() {
        return None;
    }
    if kept.is_empty() {
        return Some(String::new());
    }
    let mut joined = kept.join("\n");
    joined.push('\n');
    Some(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOD: &str = "patch.socket.dev/gopatch/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const VER: &str = "v1.4.2-socketpatch.1";
    const ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
    const GOMOD_H1: &str = "h1:XgagPTRZSCprrzR+3Ro36/XJpibdovhAbsKThYI8bxg=";

    #[test]
    fn creates_from_empty_and_is_idempotent() {
        let out = upsert_module_lines("", MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert_eq!(
            out,
            format!("{MOD} {VER} {ZIP_H1}\n{MOD} {VER}/go.mod {GOMOD_H1}\n")
        );
        assert!(upsert_module_lines(&out, MOD, VER, ZIP_H1, GOMOD_H1).is_none());
    }

    #[test]
    fn inserts_in_sorted_position_preserving_neighbors() {
        // `github.com/... < patch.socket.dev/... < sigs.k8s.io/...`
        let existing = "github.com/foo/bar v1.4.2 h1:AAA=\n\
                        github.com/foo/bar v1.4.2/go.mod h1:BBB=\n\
                        sigs.k8s.io/yaml v1.3.0 h1:CCC=\n";
        let out = upsert_module_lines(existing, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].starts_with("github.com/foo/bar v1.4.2 h1:"));
        assert!(lines[1].starts_with("github.com/foo/bar v1.4.2/go.mod"));
        assert_eq!(lines[2], format!("{MOD} {VER} {ZIP_H1}"));
        assert_eq!(lines[3], format!("{MOD} {VER}/go.mod {GOMOD_H1}"));
        assert!(lines[4].starts_with("sigs.k8s.io/yaml"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn zip_line_sorts_before_gomod_line_between_versions() {
        // Same module, an OLDER socket version already recorded: both new
        // lines land after both old ones (version string sort), interleaved
        // correctly.
        let old = format!(
            "{MOD} v1.0.0-socketpatch.1 h1:OLD=\n{MOD} v1.0.0-socketpatch.1/go.mod h1:OLDM=\n"
        );
        let out = upsert_module_lines(&old, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("v1.0.0-socketpatch.1 h1:"));
        assert!(lines[1].contains("v1.0.0-socketpatch.1/go.mod"));
        assert!(lines[2].contains(&format!("{VER} {ZIP_H1}")));
        assert!(lines[3].contains(&format!("{VER}/go.mod")));
    }

    #[test]
    fn replaces_stale_hashes_for_same_version() {
        let stale = format!("{MOD} {VER} h1:STALE=\n{MOD} {VER}/go.mod h1:STALEM=\n");
        let out = upsert_module_lines(&stale, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert!(!out.contains("STALE"));
        assert_eq!(out.lines().count(), 2);
        assert!(out.contains(ZIP_H1) && out.contains(GOMOD_H1));
    }

    /// `v1.0.0 ` vs `v1.0.0/go.mod `: the version key must not prefix-match a
    /// longer version (`v1.0.0-socketpatch.1`) — the trailing space/`/go.mod`
    /// in the removal keys guards that.
    #[test]
    fn does_not_clobber_longer_version_of_same_module() {
        let other = format!("{MOD} {VER}.2 h1:KEEP=\n{MOD} {VER}.2/go.mod h1:KEEPM=\n");
        let out = upsert_module_lines(&other, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert_eq!(out.lines().count(), 4);
        assert!(out.contains("KEEP="));
        assert!(out.contains("KEEPM="));
    }

    #[test]
    fn remove_exact_version_lines_only() {
        let content = format!(
            "example.com/lib v1.0.0 h1:OLD=\n\
             example.com/lib v1.0.0/go.mod h1:OLDM=\n\
             example.com/lib v1.0.1 h1:KEEP=\n\
             {MOD} {VER} {ZIP_H1}\n"
        );
        let (out, removed) =
            remove_exact_module_version_lines(&content, "example.com/lib", "v1.0.0").unwrap();
        assert_eq!(removed.len(), 2);
        assert!(removed[0].contains("OLD=") && removed[1].contains("OLDM="));
        assert!(out.contains("v1.0.1 h1:KEEP="), "other versions kept");
        assert!(out.contains(ZIP_H1), "unrelated modules kept");
        assert!(
            remove_exact_module_version_lines(&out, "example.com/lib", "v1.0.0").is_none(),
            "idempotent"
        );
    }

    #[test]
    fn remove_by_prefix() {
        let content = format!(
            "github.com/foo/bar v1.4.2 h1:AAA=\n{MOD} {VER} {ZIP_H1}\n{MOD} {VER}/go.mod {GOMOD_H1}\n"
        );
        let out = remove_module_prefix_lines(&content, "patch.socket.dev/gopatch/").unwrap();
        assert_eq!(out, "github.com/foo/bar v1.4.2 h1:AAA=\n");
        assert!(remove_module_prefix_lines(&out, "patch.socket.dev/gopatch/").is_none());
    }

    #[test]
    fn remove_everything_yields_empty() {
        let content = format!("{MOD} {VER} {ZIP_H1}\n");
        assert_eq!(
            remove_module_prefix_lines(&content, "patch.socket.dev/gopatch/").unwrap(),
            ""
        );
    }
}
