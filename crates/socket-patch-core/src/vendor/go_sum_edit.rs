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
    // "Already applied" means the key-matching lines are exactly the two
    // wanted ones — a bare match count is not enough: a stale same-key line
    // with a different hash (a union-merged go.sum straddling a republish) is
    // a hard go `SECURITY ERROR`, and a duplicated zip line can stand in for
    // a missing /go.mod line. Both still need the rewrite below.
    let mut want_seen = [0usize; 2];
    let mut stale_key_line = false;
    for l in &lines {
        if **l == want[0] {
            want_seen[0] += 1;
        } else if **l == want[1] {
            want_seen[1] += 1;
        } else if l.starts_with(&zip_key) || l.starts_with(&gomod_key) {
            stale_key_line = true;
        }
    }
    if want_seen == [1, 1] && !stale_key_line {
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

    let eol = super::common::detect_eol(content);
    let mut joined = out.join(eol);
    joined.push_str(eol);
    Some(joined)
}

/// True when `go.sum` carries a line (zip or `/go.mod` form) for exactly
/// `module@version` — go records one for every module version its build
/// graph loads.
pub fn has_module_version(content: &str, module: &str, version: &str) -> bool {
    let zip_key = format!("{module} {version} ");
    let gomod_key = format!("{module} {version}/go.mod ");
    content
        .lines()
        .any(|l| l.starts_with(&zip_key) || l.starts_with(&gomod_key))
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
    let eol = super::common::detect_eol(content);
    let mut joined = kept.join(eol);
    joined.push_str(eol);
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
    let eol = super::common::detect_eol(content);
    let mut joined = kept.join(eol);
    joined.push_str(eol);
    Some(joined)
}

/// go's go.sum line order, as `go mod tidy` writes it (`module.Sort`, then
/// the hashes sorted): module path bytewise, then the version by semver
/// (`v1.9.0` before `v1.10.0`), then the `/go.mod` suffix, then the hash.
fn go_sum_line_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(line: &str) -> (&str, &str, &str, &str) {
        let mut fields = line.splitn(3, ' ');
        let path = fields.next().unwrap_or_default();
        let version = fields.next().unwrap_or_default();
        let hash = fields.next().unwrap_or_default();
        let (version, file) = version.split_at(version.find('/').unwrap_or(version.len()));
        (path, version, file, hash)
    }
    let (path_a, version_a, file_a, hash_a) = split(a);
    let (path_b, version_b, file_b, hash_b) = split(b);
    path_a
        .cmp(path_b)
        .then_with(|| go_semver_cmp(version_a, version_b))
        .then_with(|| file_a.cmp(file_b))
        .then_with(|| hash_a.cmp(hash_b))
}

/// `golang.org/x/mod/semver.Compare`: build metadata (`+incompatible`) is
/// ignored and an invalid version sorts before every valid one.
fn go_semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| {
        v.strip_prefix('v')
            .and_then(|s| semver::Version::parse(s).ok())
    };
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => (x.major, x.minor, x.patch)
            .cmp(&(y.major, y.minor, y.patch))
            .then_with(|| x.pre.cmp(&y.pre)),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

/// Put previously removed `go.sum` lines (`\n`-joined) back at go's sorted
/// position, keeping the file's line endings, so a revert restores the
/// bytes go wrote. Lines already present are skipped. Returns `None` when
/// nothing was missing.
pub fn reinsert_lines(content: &str, removed: &str) -> Option<String> {
    let mut lines: Vec<&str> = content.lines().collect();
    let mut changed = false;
    for line in removed.lines().filter(|l| !l.is_empty()) {
        if lines.contains(&line) {
            continue;
        }
        let at = lines
            .iter()
            .position(|l| go_sum_line_cmp(line, l).is_lt())
            .unwrap_or(lines.len());
        lines.insert(at, line);
        changed = true;
    }
    if !changed {
        return None;
    }
    let eol = super::common::detect_eol(content);
    let mut joined = lines.join(eol);
    joined.push_str(eol);
    Some(joined)
}

/// Remove each of `added` (`\n`-joined lines) where it appears as a whole
/// line, whatever the file's line endings. Returns `None` when none did.
pub fn remove_lines(content: &str, added: &str) -> Option<String> {
    let drop: Vec<&str> = added.lines().filter(|l| !l.is_empty()).collect();
    let kept: Vec<&str> = content.lines().filter(|l| !drop.contains(l)).collect();
    if kept.len() == content.lines().count() {
        return None;
    }
    if kept.is_empty() {
        return Some(String::new());
    }
    let eol = super::common::detect_eol(content);
    let mut joined = kept.join(eol);
    joined.push_str(eol);
    Some(joined)
}

/// A `go.sum` edited by a sequence of the transforms above without splitting
/// and re-joining the whole file for every one: the hosted rewriter upserts
/// and prunes two modules' lines per dep, which on a large go.sum made every
/// dep cost two full-file copies.
///
/// The content is always exactly what applying the text transforms in the
/// same order would give. Once a transform changes it, the file is held as
/// its lines: every transform ends with `lines.join(eol) + eol`, whose
/// `str::lines` are those lines again and whose `detect_eol` is `eol` again —
/// except when a line ends in a bare `\r` under an LF file (a joined `\r\n`
/// would then split differently), which is kept as text instead.
pub(crate) struct GoSumEditor {
    state: GoSumState,
}

enum GoSumState {
    /// The exact content.
    Text(String),
    /// Content `lines.join(eol) + eol`; never empty.
    Lines {
        lines: Vec<String>,
        eol: &'static str,
    },
}

impl GoSumEditor {
    pub(crate) fn new(content: String) -> Self {
        Self {
            state: GoSumState::Text(content),
        }
    }

    fn take_lines(&mut self) -> (Vec<String>, &'static str) {
        match std::mem::replace(&mut self.state, GoSumState::Text(String::new())) {
            GoSumState::Text(text) => {
                let lines = text.lines().map(str::to_string).collect();
                let eol = super::common::detect_eol(&text);
                self.state = GoSumState::Text(text);
                (lines, eol)
            }
            GoSumState::Lines { lines, eol } => (lines, eol),
        }
    }

    /// Store the transform result `lines.join(eol) + eol` (`""` when empty).
    fn commit(&mut self, lines: Vec<String>, eol: &'static str) {
        self.state = if lines.is_empty() {
            GoSumState::Text(String::new())
        } else if eol == "\n" && lines.iter().any(|l| l.ends_with('\r')) {
            let mut text = lines.join(eol);
            text.push_str(eol);
            GoSumState::Text(text)
        } else {
            GoSumState::Lines { lines, eol }
        };
    }

    /// [`upsert_module_lines`] in place; `true` when it changed the content.
    pub(crate) fn upsert_module_lines(
        &mut self,
        module: &str,
        version: &str,
        zip_h1: &str,
        gomod_h1: &str,
    ) -> bool {
        let want = module_lines(module, version, zip_h1, gomod_h1);
        let zip_key = format!("{module} {version} ");
        let gomod_key = format!("{module} {version}/go.mod ");
        let is_key = |l: &str| l.starts_with(&zip_key) || l.starts_with(&gomod_key);
        let applied = {
            let mut want_seen = [0usize; 2];
            let mut stale_key_line = false;
            let mut scan = |l: &str| {
                if l == want[0] {
                    want_seen[0] += 1;
                } else if l == want[1] {
                    want_seen[1] += 1;
                } else if is_key(l) {
                    stale_key_line = true;
                }
            };
            match &self.state {
                GoSumState::Text(text) => text.lines().for_each(&mut scan),
                GoSumState::Lines { lines, .. } => {
                    lines.iter().map(String::as_str).for_each(&mut scan)
                }
            }
            want_seen == [1, 1] && !stale_key_line
        };
        if applied {
            return false;
        }
        let (mut lines, eol) = self.take_lines();
        lines.retain(|l| !is_key(l));
        let mut out: Vec<String> = Vec::with_capacity(lines.len() + 2);
        let mut pending = want.into_iter().peekable();
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
        self.commit(out, eol);
        true
    }

    /// [`has_module_version`] over the current content.
    pub(crate) fn has_module_version(&self, module: &str, version: &str) -> bool {
        let zip_key = format!("{module} {version} ");
        let gomod_key = format!("{module} {version}/go.mod ");
        let is_key = |l: &str| l.starts_with(&zip_key) || l.starts_with(&gomod_key);
        match &self.state {
            GoSumState::Text(text) => text.lines().any(is_key),
            GoSumState::Lines { lines, .. } => lines.iter().any(|l| is_key(l)),
        }
    }

    /// [`remove_exact_module_version_lines`] in place: the removed lines, or
    /// `None` when nothing matched.
    pub(crate) fn remove_exact_module_version_lines(
        &mut self,
        module: &str,
        version: &str,
    ) -> Option<Vec<String>> {
        let zip_key = format!("{module} {version} ");
        let gomod_key = format!("{module} {version}/go.mod ");
        let is_key = |l: &str| l.starts_with(&zip_key) || l.starts_with(&gomod_key);
        let any = match &self.state {
            GoSumState::Text(text) => text.lines().any(is_key),
            GoSumState::Lines { lines, .. } => lines.iter().any(|l| is_key(l)),
        };
        if !any {
            return None;
        }
        let (lines, eol) = self.take_lines();
        let (removed, kept): (Vec<String>, Vec<String>) =
            lines.into_iter().partition(|l| is_key(l));
        self.commit(kept, eol);
        Some(removed)
    }

    /// [`remove_module_prefix_lines`] in place; `true` when it changed the
    /// content.
    pub(crate) fn remove_module_prefix_lines(&mut self, module_prefix: &str) -> bool {
        let new = match &self.state {
            GoSumState::Text(text) => remove_module_prefix_lines(text, module_prefix),
            GoSumState::Lines { lines, eol } => {
                let mut text = lines.join(eol);
                text.push_str(eol);
                remove_module_prefix_lines(&text, module_prefix)
            }
        };
        match new {
            Some(new) => {
                self.state = GoSumState::Text(new);
                true
            }
            None => false,
        }
    }

    pub(crate) fn into_string(self) -> String {
        match self.state {
            GoSumState::Text(text) => text,
            GoSumState::Lines { lines, eol } => {
                let mut text = lines.join(eol);
                text.push_str(eol);
                text
            }
        }
    }
}

// ── pure reader ──────────────────────────────────────────────────────────────
// The line reader lockfile discovery (`vex::discover::golang`) and the lock
// inventory share, and the `h1:` shape the hosted rewriter and discovery
// both require.

/// One `go.sum` line of at least three whitespace-separated tokens,
/// `<module> <version>[/go.mod] <hash>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoSumLine<'a> {
    pub(crate) module: &'a str,
    /// The version, without the `/go.mod` suffix of a manifest line.
    pub(crate) version: &'a str,
    /// A `/go.mod` line (hashes only the module's go.mod), not the zip line.
    pub(crate) go_mod: bool,
    pub(crate) hash: &'a str,
    /// The line carries more than three tokens (not a line go writes).
    pub(crate) extra_tokens: bool,
}

/// Every line of `text` with at least three tokens, in file order; shorter
/// lines are skipped. Each caller keeps its own token rule
/// ([`GoSumLine::extra_tokens`]) and hash filter.
pub(crate) fn go_sum_lines(text: &str) -> impl Iterator<Item = GoSumLine<'_>> {
    text.lines().filter_map(|line| {
        let mut tokens = line.split_whitespace();
        let (module, version, hash) = (tokens.next()?, tokens.next()?, tokens.next()?);
        let (version, go_mod) = match version.strip_suffix("/go.mod") {
            Some(version) => (version, true),
            None => (version, false),
        };
        Some(GoSumLine {
            module,
            version,
            go_mod,
            hash,
            extra_tokens: tokens.next().is_some(),
        })
    })
}

/// Strict `h1:` dirhash shape: exactly `h1:` + the 44-char standard base64
/// of a sha256 — the only shape the hosted rewriter writes. Anything else
/// (wrong algorithm, embedded whitespace, truncation) must not reach go.sum:
/// a malformed line poisons the whole file.
pub(crate) fn is_h1_dirhash(s: &str) -> bool {
    s.strip_prefix("h1:").is_some_and(|b| {
        b.len() == 44
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    })
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

    /// Both fresh lines present PLUS a stale same-key line (e.g. a
    /// union-merged go.sum across a republish): go fatals on the conflicting
    /// hash, so upsert must still rewrite — "already applied" requires the
    /// key-matching lines to be exactly the two wanted ones.
    #[test]
    fn upsert_rewrites_when_stale_duplicate_key_line_coexists() {
        let content =
            format!("{MOD} {VER} {ZIP_H1}\n{MOD} {VER} h1:STALE=\n{MOD} {VER}/go.mod {GOMOD_H1}\n");
        let out = upsert_module_lines(&content, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert!(!out.contains("STALE"));
        assert_eq!(out.lines().count(), 2);

        // A duplicated zip line with the /go.mod line missing is not "already
        // applied" either, even though two lines match the wanted set.
        let dup = format!("{MOD} {VER} {ZIP_H1}\n{MOD} {VER} {ZIP_H1}\n");
        let out = upsert_module_lines(&dup, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert_eq!(
            out,
            format!("{MOD} {VER} {ZIP_H1}\n{MOD} {VER}/go.mod {GOMOD_H1}\n")
        );
    }

    /// CRLF go.sum (git autocrlf on Windows): edits must preserve the file's
    /// line terminator — joining with bare `\n` would churn every line.
    #[test]
    fn crlf_go_sum_preserves_line_endings() {
        let existing = "github.com/foo/bar v1.4.2 h1:AAA=\r\nsigs.k8s.io/yaml v1.3.0 h1:CCC=\r\n";
        let out = upsert_module_lines(existing, MOD, VER, ZIP_H1, GOMOD_H1).unwrap();
        assert_eq!(
            out,
            format!(
                "github.com/foo/bar v1.4.2 h1:AAA=\r\n\
                 {MOD} {VER} {ZIP_H1}\r\n\
                 {MOD} {VER}/go.mod {GOMOD_H1}\r\n\
                 sigs.k8s.io/yaml v1.3.0 h1:CCC=\r\n"
            )
        );
        assert!(
            upsert_module_lines(&out, MOD, VER, ZIP_H1, GOMOD_H1).is_none(),
            "idempotency unaffected by the terminator"
        );

        let (kept, removed) =
            remove_exact_module_version_lines(&out, "github.com/foo/bar", "v1.4.2").unwrap();
        assert_eq!(removed.len(), 1);
        assert!(kept.starts_with(&format!("{MOD} {VER} {ZIP_H1}\r\n")));
        assert!(kept.ends_with("\r\n"));

        let pruned = remove_module_prefix_lines(&out, "patch.socket.dev/gopatch/").unwrap();
        assert_eq!(
            pruned,
            "github.com/foo/bar v1.4.2 h1:AAA=\r\nsigs.k8s.io/yaml v1.3.0 h1:CCC=\r\n"
        );
    }

    #[test]
    fn remove_everything_yields_empty() {
        let content = format!("{MOD} {VER} {ZIP_H1}\n");
        assert_eq!(
            remove_module_prefix_lines(&content, "patch.socket.dev/gopatch/").unwrap(),
            ""
        );
    }

    /// Random go.sum-ish text: matching and near-miss lines for a few
    /// modules, blank lines, unsorted order, CRLF / mixed / bare-`\r`
    /// endings, a missing final newline, or nothing at all.
    fn random_go_sum(rng: &mut impl FnMut(usize) -> usize) -> String {
        const MODS: &[&str] = &[
            "a.com/x",
            "a.com/x/y",
            "b.com/z",
            "patch.socket.dev/gopatch/u1",
        ];
        const VERS: &[&str] = &["v1.0.0", "v1.0.0/go.mod", "v1.0.01", "v2.0.0"];
        let mut out = String::new();
        for _ in 0..rng(12) {
            match rng(10) {
                0 => {}
                1 => out.push_str("junk"),
                _ => out.push_str(&format!(
                    "{} {} h1:{}",
                    MODS[rng(MODS.len())],
                    VERS[rng(VERS.len())],
                    ["A=", "B=", "C="][rng(3)]
                )),
            }
            out.push_str(["\n", "\n", "\r\n", "\r", "\r\r\n"][rng(5)]);
        }
        if rng(4) == 0 {
            out.pop();
        }
        out
    }

    #[test]
    fn editor_matches_the_text_transforms_step_by_step() {
        for seed in 1..=3000u64 {
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut rng = move |n: usize| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % n as u64) as usize
            };
            let start = random_go_sum(&mut rng);
            let mut text = start.clone();
            let mut editor = GoSumEditor::new(start.clone());
            for step in 0..rng(8) {
                let module = ["a.com/x", "b.com/z", "patch.socket.dev/gopatch/u1"][rng(3)];
                let version = ["v1.0.0", "v2.0.0"][rng(2)];
                match rng(3) {
                    0 => {
                        let (zip, gomod) = [("h1:A=", "h1:B="), ("h1:C=", "h1:A=")][rng(2)];
                        let want = upsert_module_lines(&text, module, version, zip, gomod);
                        let got = editor.upsert_module_lines(module, version, zip, gomod);
                        assert_eq!(got, want.is_some(), "seed {seed} step {step}");
                        if let Some(new) = want {
                            text = new;
                        }
                    }
                    1 => {
                        let want = remove_exact_module_version_lines(&text, module, version);
                        let got = editor.remove_exact_module_version_lines(module, version);
                        assert_eq!(
                            got,
                            want.as_ref().map(|(_, removed)| removed.clone()),
                            "seed {seed} step {step}"
                        );
                        if let Some((new, _)) = want {
                            text = new;
                        }
                    }
                    _ => {
                        let want = remove_module_prefix_lines(&text, "patch.socket.dev/gopatch/");
                        let got = editor.remove_module_prefix_lines("patch.socket.dev/gopatch/");
                        assert_eq!(got, want.is_some(), "seed {seed} step {step}");
                        if let Some(new) = want {
                            text = new;
                        }
                    }
                }
                let snapshot = GoSumEditor {
                    state: match &editor.state {
                        GoSumState::Text(t) => GoSumState::Text(t.clone()),
                        GoSumState::Lines { lines, eol } => GoSumState::Lines {
                            lines: lines.clone(),
                            eol,
                        },
                    },
                };
                assert_eq!(
                    snapshot.into_string(),
                    text,
                    "seed {seed} step {step}: {start:?}"
                );
            }
        }
    }
}
