//! Go modules — root `go.mod` (and `go.work`) `replace` directives, pinned by
//! `go.sum` (`go.work.sum`).
//!
//! Both Socket backends wire a Go patch the
//! same way — a `replace` keyed on the ORIGINAL module + version — and differ
//! only in the right-hand side, which [`go_mod_edit::parse_replace_entries`]
//! classifies ([`ReplaceOwner`], go_mod_edit.rs:63-90):
//!
//! | owner | what our tools write | ref |
//! |---|---|---|
//! | [`ReplaceOwner::Hosted`] (`scan --mode hosted`, `rewrite_golang`) | `replace M v => patch.socket.dev/gopatch/<uuid> <sver>` + go.sum `patch.socket.dev/gopatch/<uuid> <sver> h1:…` and `…<sver>/go.mod h1:…` | hosted, `integrity_required = true` |
//! | [`ReplaceOwner::Vendor`] (`vendor`, `vendor_go_module`) | `replace M v => ./.socket/vendor/golang/<uuid>/M@v` | vendored |
//! | [`ReplaceOwner::GoPatches`] (`apply`'s redirect) | `replace M v => ./.socket/go-patches/M@v` | none — no uuid; the CLI's `synthesize_go_patches` verifies those |
//!
//! Both writers emit the single-line form or rewrite an existing socket
//! line in place (so block members `\tM v => …` occur too), always with the
//! LEFT version and always `./`-prefixed, forward-slashed paths. The purl is
//! the LEFT side — `pkg:golang/<M>@<v>`, the module the build no longer
//! fetches — never the right-hand module.
//!
//! # What counts (rule 10: what the go command READS)
//!
//! * **Hosted identity** is the module path itself (not a URL, so not
//!   [`super::DiscoverCtx::hosted_uuid`]): exactly
//!   [`HOSTED_GO_MODULE_PREFIX`]`<uuid>`, optionally followed by one Go
//!   major-version suffix `/v<N>` (`N >= 2`; the design doc reserves it for
//!   v2+ originals, nothing ships it yet). The namespace is grant-free, so
//!   any other segment — a (uuid-shaped) grant token before the uuid, a
//!   placeholder, an uppercase uuid — is not something we write and is
//!   diagnosed, never "last uuid wins". The host is fixed: the hosted
//!   rewriter refuses module paths outside this namespace, and a
//!   `--patch-server-url` deployment does not change Go module paths, so
//!   the origin allowlist does not apply here.
//! * **Pin.** The hosted rewriter refuses to write the replace without BOTH
//!   go.sum lines, so `integrity_required = true`; the ref's
//!   `locked_integrity` is the zip line's `h1:` dirhash
//!   ([`LockIntegrity::GoH1`]) and is set only when the sum file carries
//!   exactly one well-formed zip hash AND the `/go.mod` line for the Socket
//!   module+version (anything else is not what the rewriter wrote — and a
//!   conflicting pair is a go `SECURITY ERROR`). NB for the CLI's
//!   installed-tree basis: under a hosted replace the module cache's
//!   `M@v` (if any, e.g. from before the redirect) is pristine BY
//!   CONSTRUCTION — the build consumes `patch.socket.dev/gopatch/<uuid>@<sver>`.
//! * **Vendored identity** comes from [`vendor_ref`] over the replace PATH
//!   (root-anchored: a `../…/.socket/vendor/golang/…` or absolute target —
//!   which `detect_owner` still classifies as `Vendor` — points the build at
//!   another tree and is diagnosed). The leaf must name the SAME module and
//!   version as the left side ([`vendored_leaf_purl`]): `vendor` always
//!   writes `M v => …/<uuid>/M@v`, and a drifted pair is exactly the case
//!   `vendor` itself refuses to call "already patched".
//! * **Stale pins are inert.** `replace M v` applies only when the build
//!   selects `M@v`; a `require M v'` with `v' != v` (a `go get -u` after the
//!   redirect — the design doc's "upgrade drift") silently builds the
//!   unpatched module, which is why the hosted rewriter refuses to write
//!   one (`redirect_golang_version_mismatch`). Such a directive is
//!   diagnosed ([`DIAG_REF_INVALID`]), not emitted. A module absent from
//!   `require` (pre-1.17 go.mod omitting indirect deps) is not provably
//!   inert and is emitted.
//! * **Version-less replaces** (`replace M => …`, hand edits — neither
//!   writer emits them) apply to whatever version is selected: the version
//!   is taken from `require`; with no `require` for `M` the patched version
//!   is unknown ([`DIAG_REF_UNATTRIBUTABLE`]). A versioned replace for the
//!   same `M@<required>` in the same file takes precedence in Go, so the
//!   version-less one is then inert too.
//! * **`go.work`** (hand-written — no Socket tool writes it) uses the same
//!   `replace` grammar and paths relative to the (root) workspace dir; its
//!   refs are emitted with `source_file = "go.work"`, versions checked
//!   against the ROOT `go.mod`'s `require` (the only one discovery reads),
//!   and hosted pins looked up in `go.work.sum`, then `go.sum`. go.work
//!   replaces override go.mod replaces in Go, but rule 10 leaves
//!   cross-file precedence to the CLI's `wiring_conflict` gate. Nested
//!   workspace members' go.mod files are not read (root-only, rule 1).
//! * **Hand-edit tolerance**: a UTF-8 BOM, CRLF line ends, tab-separated
//!   tokens, `replace(` without a space, `// comments`, and Go string
//!   literals (`"github.com/foo/bar"`, `` `…` ``) around escape- and
//!   whitespace-free tokens are all read as the go command would. A
//!   `( … )` block that is never closed (or a stray `)` / nested block)
//!   makes the whole file unparseable to go, so it yields
//!   [`DIAG_LOCKFILE_UNPARSEABLE`] and no refs.
//! * `vendor/modules.txt` (`go mod vendor`) only mirrors go.mod's replaces
//!   and is not read.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::{
    golang_purl, vendor_ref, vendored_leaf_purl, DiscoverCtx, Discovery, PatchedRef,
    DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::patch::path_safety::is_safe_single_segment;
use crate::vendor::go_mod_edit::{
    self, block_structure_error, hosted_module_uuid, normalize_for_read, ReplaceEntry,
    ReplaceOwner, HOSTED_GO_MODULE_PREFIX,
};
use crate::vendor::go_sum_edit::{go_sum_lines, is_h1_dirhash};
use crate::vendor::lock_inventory::LockIntegrity;

const GO_MOD: &str = "go.mod";
const GO_SUM: &str = "go.sum";
const GO_WORK: &str = "go.work";
const GO_WORK_SUM: &str = "go.work.sum";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let go_mod = match ctx.read_text(GO_MOD, out).await {
        Some(text) => parse_go_file(GO_MOD, &text, out),
        None => None,
    };
    // `require` of the root module: the version the build selects (as far
    // as a root-only reader can tell).
    let required: HashMap<String, String> = go_mod
        .as_deref()
        .map(go_mod_edit::parse_required_versions)
        .unwrap_or_default();

    if let Some(text) = go_mod.as_deref() {
        extract_file(ctx, out, GO_MOD, text, &required, &[GO_SUM]).await;
    }
    if let Some(text) = ctx.read_text(GO_WORK, out).await {
        if let Some(text) = parse_go_file(GO_WORK, &text, out) {
            extract_file(ctx, out, GO_WORK, &text, &required, &[GO_WORK_SUM, GO_SUM]).await;
        }
    }
}

/// Normalize a go.mod-grammar file (BOM, simple string literals) and check
/// its block structure; `None` (with a diagnostic) when go could not parse
/// it at all.
fn parse_go_file(file: &str, text: &str, out: &mut Discovery) -> Option<String> {
    let text = normalize_for_read(text);
    if let Some(problem) = block_structure_error(&text) {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file}: {problem}; no patched modules read from it"),
        );
        return None;
    }
    Some(text)
}

/// Emit the refs of one parsed file's Socket-owned `replace` directives.
async fn extract_file(
    ctx: &DiscoverCtx<'_>,
    out: &mut Discovery,
    file: &str,
    text: &str,
    required: &HashMap<String, String>,
    sum_files: &[&str],
) {
    let entries = go_mod_edit::parse_replace_entries(text);
    // Versioned directives of ANY owner: they shadow a version-less replace
    // of the same module at that version.
    let versioned: HashSet<(&str, &str)> = entries
        .iter()
        .filter_map(|e| Some((e.module.as_str(), e.version.as_deref()?)))
        .collect();
    let mut sums: Option<SumPins> = None;

    for entry in &entries {
        match entry.owner {
            Some(ReplaceOwner::Hosted) => {
                let Some(rhs) = entry.rhs_module.as_deref() else {
                    continue;
                };
                let Some(uuid) = hosted_module_uuid(rhs) else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {}: `{rhs}` is not a Socket patch module \
                             (`{HOSTED_GO_MODULE_PREFIX}<patch-uuid>`)",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(rhs_version) = entry
                    .rhs_version
                    .as_deref()
                    .filter(|v| is_safe_single_segment(v))
                else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {rhs}: missing or unsafe replacement version",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(purl) = replaced_purl(entry, required, &versioned, file, out) else {
                    continue;
                };
                if sums.is_none() {
                    let mut pins = SumPins::default();
                    for sum in sum_files {
                        if let Some(sum_text) = ctx.read_text(sum, out).await {
                            pins.add(&sum_text);
                        }
                    }
                    sums = Some(pins);
                }
                let integrity = sums
                    .as_ref()
                    .and_then(|s| s.pin(rhs, rhs_version))
                    .map(LockIntegrity::GoH1);
                let url = format!("{rhs}@{rhs_version}");
                out.push(PatchedRef::hosted(
                    purl,
                    uuid,
                    file,
                    Some(url.as_str()),
                    integrity,
                    true,
                ));
            }
            Some(ReplaceOwner::Vendor) => {
                let Some(path) = entry.path.as_deref() else {
                    continue;
                };
                let Some(vref) = vendor_ref(path).filter(|v| v.eco == "golang") else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {path}: not a project-root \
                             `./.socket/vendor/golang/<patch-uuid>/<module>@<version>` path",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(purl) = replaced_purl(entry, required, &versioned, file, out) else {
                    continue;
                };
                if vendored_leaf_purl("golang", &vref.leaf).as_deref() != Some(purl.as_str()) {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {path}: the vendored copy does not name {purl}",
                            entry.module
                        ),
                    );
                    continue;
                }
                out.push(PatchedRef::vendored(purl, &vref, file, None));
            }
            // Socket-shaped but not something we write (another tree's copy,
            // an absolute path, a malformed hosted module): diagnosed, never a ref.
            None if is_foreign_socket_target(entry) => {
                let target = entry
                    .path
                    .as_deref()
                    .or(entry.rhs_module.as_deref())
                    .unwrap_or_default();
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: replace {} => {target}: not a project-root \
                         `./.socket/vendor/golang/<patch-uuid>/<module>@<version>` path or \
                         `{HOSTED_GO_MODULE_PREFIX}<patch-uuid>` module",
                        entry.module
                    ),
                );
            }
            // `.socket/go-patches/` carries no uuid; user replaces are not ours.
            Some(ReplaceOwner::GoPatches) | None => {}
        }
    }
}

/// A replace target no socket backend owns that still names Socket's vendor
/// tree or hosted module namespace.
fn is_foreign_socket_target(entry: &ReplaceEntry) -> bool {
    entry
        .path
        .as_deref()
        .is_some_and(|p| p.replace('\\', "/").contains(".socket/vendor/golang/"))
        || entry
            .rhs_module
            .as_deref()
            .is_some_and(|m| m.starts_with(HOSTED_GO_MODULE_PREFIX))
}

/// `pkg:golang/<M>@<v>` for the module a Socket `replace` substitutes, with
/// the version the build actually applies it at — or `None` (diagnosed)
/// when the directive is inert or its version is unknowable.
fn replaced_purl(
    entry: &ReplaceEntry,
    required: &HashMap<String, String>,
    versioned: &HashSet<(&str, &str)>,
    file: &str,
    out: &mut Discovery,
) -> Option<String> {
    let module = entry.module.as_str();
    let req = required.get(module).map(String::as_str);
    let version = match (entry.version.as_deref(), req) {
        (Some(v), Some(r)) if v != r => {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: replace {module} {v} is inert: go.mod requires {module} {r}, \
                     so the build uses the unpatched module"
                ),
            );
            return None;
        }
        (Some(v), _) => v,
        (None, Some(r)) if versioned.contains(&(module, r)) => {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: version-less replace {module} is inert: another replace pins \
                     {module} {r}, the required version"
                ),
            );
            return None;
        }
        (None, Some(r)) => r,
        (None, None) => {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                file,
                format!(
                    "{file}: version-less replace {module} and no require for it: cannot tell \
                     which version is patched"
                ),
            );
            return None;
        }
    };
    let purl = golang_purl(module, version);
    if purl.is_none() {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: replace {module} {version}: unsafe module coordinates"),
        );
    }
    purl
}

/// go.sum pins of Socket hosted modules, keyed `(module, version)`.
#[derive(Default)]
struct SumPins {
    /// Zip-line `h1:` hashes.
    zip: HashMap<(String, String), BTreeSet<String>>,
    /// `(module, version)`s with a `/go.mod` line.
    gomod: HashSet<(String, String)>,
}

impl SumPins {
    fn add(&mut self, text: &str) {
        for line in go_sum_lines(text) {
            if line.extra_tokens
                || !line.module.starts_with(HOSTED_GO_MODULE_PREFIX)
                || !is_h1_dirhash(line.hash)
            {
                continue;
            }
            let key = (line.module.to_string(), line.version.to_string());
            if line.go_mod {
                self.gomod.insert(key);
            } else {
                self.zip
                    .entry(key)
                    .or_default()
                    .insert(line.hash.to_string());
            }
        }
    }

    /// The zip `h1:` of `module@version` iff the rewriter's full pin is
    /// present: one unambiguous zip hash plus the `/go.mod` line.
    fn pin(&self, module: &str, version: &str) -> Option<String> {
        let key = (module.to_string(), version.to_string());
        let hashes = self.zip.get(&key)?;
        (hashes.len() == 1 && self.gomod.contains(&key))
            .then(|| hashes.iter().next().cloned())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;
    use crate::vendor::go_mod_edit::{
        ensure_replace_entry, replace_target_path, upsert_hosted_replace_entry,
        HOSTED_GO_MODULE_PREFIX,
    };

    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
    /// The committed hosted fixture's patch uuid (grant token `1111…`).
    const FIXTURE_UUID: &str = "55555555-5555-5555-5555-555555555555";
    const FIXTURE_ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
    const ZIP_H1: &str = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const MOD_H1: &str = "h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    const BASE_GO_MOD: &str =
        "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n";

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    fn gopatch(uuid: &str) -> String {
        format!("{HOSTED_GO_MODULE_PREFIX}{uuid}")
    }

    fn go_sum_for(uuid: &str, sver: &str) -> String {
        let m = gopatch(uuid);
        format!("{m} {sver} {ZIP_H1}\n{m} {sver}/go.mod {MOD_H1}\n")
    }

    fn vendored_rel(uuid: &str) -> String {
        format!(".socket/vendor/golang/{uuid}/{MODULE}@{VERSION}")
    }

    /// Exactly the go.mod the `vendor` backend writes (its own upsert).
    async fn vendored_project(uuid: &str, base: &str) -> Project {
        let p = Project::new();
        p.write("go.mod", base);
        let base_rel = format!(".socket/vendor/golang/{uuid}");
        assert!(
            ensure_replace_entry(p.root(), MODULE, VERSION, &base_rel, false)
                .await
                .expect("vendor upsert")
        );
        p
    }

    #[tokio::test]
    async fn golden_hosted_fixture_yields_the_patch_uuid_with_its_go_sum_pin() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/expected");
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, FIXTURE_UUID, WiringMode::Hosted)]);
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("go.mod"));
        assert!(r.integrity_required);
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::GoH1(FIXTURE_ZIP_H1.to_string()))
        );
        assert!(r.lockfile_basis_ok());
        assert_eq!(
            r.url.as_deref(),
            Some(format!("{}@v1.4.2-socketpatch.1", gopatch(FIXTURE_UUID)).as_str())
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn golden_hosted_input_has_no_refs() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/input");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn hosted_rewriter_output_is_recognized_single_line_and_in_block() {
        // The rewriter's own upsert, appended and refreshed inside a block.
        let appended = upsert_hosted_replace_entry(
            BASE_GO_MOD,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.2",
        )
        .unwrap()
        .unwrap();
        let in_block = format!(
            "{BASE_GO_MOD}\nreplace (\n\tgithub.com/x/y v1.0.0 => ../y\n\t{MODULE} {VERSION} => ./.socket/go-patches/{MODULE}@{VERSION}\n)\n"
        );
        let refreshed = upsert_hosted_replace_entry(
            &in_block,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.2",
        )
        .unwrap()
        .unwrap();
        assert!(refreshed.contains(&format!("\t{MODULE} {VERSION} => {}", gopatch(UUID_A))));
        for go_mod in [appended, refreshed] {
            let p = Project::new();
            p.write("go.mod", &go_mod)
                .write("go.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.2"));
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            assert!(out.refs[0].lockfile_basis_ok(), "{go_mod}");
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    /// A go.sum line of fewer or more than three tokens is not a line go
    /// (or the rewriter) writes, so it is never the pin.
    #[tokio::test]
    async fn go_sum_lines_with_the_wrong_token_count_are_not_the_pin() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n");
        for go_sum in [
            format!("{m} {sver} {ZIP_H1} extra\n{m} {sver}/go.mod {MOD_H1}\n"),
            format!("{m} {sver}\n{m} {sver}/go.mod {MOD_H1}\n"),
            format!("{m} {sver} {ZIP_H1}\n{m} {sver}/go.mod {MOD_H1} // x\n"),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod).write("go.sum", &go_sum);
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.refs[0].locked_integrity, None, "{go_sum:?}");
        }
    }

    #[tokio::test]
    async fn hosted_pin_requires_both_go_sum_lines_and_one_hash() {
        let m = gopatch(UUID_A);
        let go_mod =
            format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} v1.4.2-socketpatch.1\n");
        for go_sum in [
            // No go.sum at all.
            None,
            // Zip line only / go.mod line only.
            Some(format!("{m} v1.4.2-socketpatch.1 {ZIP_H1}\n")),
            Some(format!("{m} v1.4.2-socketpatch.1/go.mod {MOD_H1}\n")),
            // Conflicting zip hashes (a union-merged go.sum).
            Some(format!(
                "{}{m} v1.4.2-socketpatch.1 {MOD_H1}\n",
                go_sum_for(UUID_A, "v1.4.2-socketpatch.1")
            )),
            // Pinned at another socket version.
            Some(go_sum_for(UUID_A, "v1.4.2-socketpatch.9")),
            // Malformed hash.
            Some(format!(
                "{m} v1.4.2-socketpatch.1 h1:short\n{m} v1.4.2-socketpatch.1/go.mod {MOD_H1}\n"
            )),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            if let Some(sum) = &go_sum {
                p.write("go.sum", sum);
            }
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            let r = &out.refs[0];
            assert_eq!(r.locked_integrity, None, "{go_sum:?}");
            assert!(r.integrity_required);
            assert!(!r.lockfile_basis_ok(), "{go_sum:?}");
        }
    }

    #[tokio::test]
    async fn vendored_backend_output_is_recognized() {
        let p = vendored_project(UUID_B, BASE_GO_MOD).await;
        let go_mod = std::fs::read_to_string(p.root().join("go.mod")).unwrap();
        assert!(go_mod.contains(&format!(
            "replace {MODULE} {VERSION} => ./{}",
            vendored_rel(UUID_B)
        )));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
        let r = &out.refs[0];
        assert_eq!(
            r.artifact_rel.as_deref(),
            Some(vendored_rel(UUID_B).as_str())
        );
        assert_eq!(r.source_file, std::path::PathBuf::from("go.mod"));
        assert!(!r.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        // `replace_target_path` is the one shape both agree on.
        assert_eq!(
            replace_target_path(&format!(".socket/vendor/golang/{UUID_B}"), MODULE, VERSION),
            format!("./{}", vendored_rel(UUID_B))
        );
    }

    #[tokio::test]
    async fn vendor_takeover_of_hosted_replace_leaves_only_the_vendored_ref() {
        let hosted = upsert_hosted_replace_entry(
            BASE_GO_MOD,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.1",
        )
        .unwrap()
        .unwrap();
        let p = vendored_project(UUID_B, &hosted).await;
        // The stale go.sum lines survive a takeover; they pin nothing.
        p.write("go.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.1"));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn crlf_bom_tabs_quotes_and_block_members_are_tolerated() {
        let a = gopatch(UUID_A);
        let go_mod = format!(
            "\u{feff}module example.com/app\r\n\r\ngo 1.21\r\n\r\nrequire (\r\n\t{MODULE} {VERSION} // indirect\r\n\tgithub.com/b/c v0.1.0\r\n)\r\n\r\nreplace(\r\n\t\"{MODULE}\"\t{VERSION}\t=>\t`{a}` \"v1.4.2-socketpatch.1\" // socket\r\n\tgithub.com/b/c v0.1.0 => .\\.socket\\vendor\\golang\\{UUID_B}\\github.com\\b\\c@v0.1.0\r\n)\r\n"
        );
        let p = Project::new();
        p.write("go.mod", go_mod).write(
            "go.sum",
            go_sum_for(UUID_A, "v1.4.2-socketpatch.1").replace('\n', "\r\n"),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (PURL, UUID_A, WiringMode::Hosted),
                (
                    "pkg:golang/github.com/b/c@v0.1.0",
                    UUID_B,
                    WiringMode::Vendored,
                ),
            ],
        );
        let hosted = out
            .refs
            .iter()
            .find(|r| r.mode == WiringMode::Hosted)
            .unwrap();
        assert!(hosted.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn go_work_replaces_are_read_with_go_work_sum_pins() {
        let p = Project::new();
        p.write("go.mod", BASE_GO_MOD)
            .write(
                "go.work",
                format!(
                    "go 1.21\n\nuse .\n\nreplace {MODULE} {VERSION} => {} v1.4.2-socketpatch.1\n",
                    gopatch(UUID_A)
                ),
            )
            .write("go.work.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.1"));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("go.work"));
        assert!(r.lockfile_basis_ok());
    }

    #[tokio::test]
    async fn go_mod_and_go_work_both_wiring_emit_both_refs() {
        // Rule 10: no cross-file precedence — the CLI gates the conflict.
        let p = vendored_project(UUID_B, BASE_GO_MOD).await;
        p.write(
            "go.work",
            format!(
                "go 1.21\nuse .\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (PURL, UUID_A, WiringMode::Hosted),
                (PURL, UUID_B, WiringMode::Vendored),
            ],
        );
    }

    #[tokio::test]
    async fn stale_pin_after_a_require_bump_is_inert() {
        let bumped = BASE_GO_MOD.replace("bar v1.4.2", "bar v1.5.0");
        let hosted = format!(
            "{bumped}\nreplace {MODULE} {VERSION} => {} v1.4.2-socketpatch.1\n",
            gopatch(UUID_A)
        );
        let vendored = format!(
            "{bumped}\nreplace {MODULE} {VERSION} => ./{}\n",
            vendored_rel(UUID_B)
        );
        for (go_mod, is_hosted) in [(hosted, true), (vendored, false)] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{go_mod}");
            assert!(out.diagnostics[0].detail.contains("inert"));
            assert!(out.diagnostics[0].detail.starts_with("go.mod: "));
            // The inert directive's patch is RECOGNIZED, so a ledger claim
            // for it is dead — the CLI must not re-derive "live" from the
            // uuid still sitting in go.mod's text (rule 11).
            let claim = if is_hosted {
                out.hosted_claim(PURL, UUID_A)
            } else {
                out.vendored_claim(PURL, UUID_B, &vendored_rel(UUID_B))
            };
            assert_eq!(claim, Some(false), "{go_mod}");
        }
    }

    #[tokio::test]
    async fn module_missing_from_require_is_still_emitted() {
        let go_mod = format!(
            "module example.com/app\n\ngo 1.16\n\nreplace {MODULE} {VERSION} => ./{}\n",
            vendored_rel(UUID_B)
        );
        let p = Project::new();
        p.write("go.mod", go_mod);
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn versionless_replace_takes_the_required_version() {
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} => ./{}\n",
                vendored_rel(UUID_B)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);

        // No require → unknowable version.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "module example.com/app\n\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);

        // A versioned (user) replace for the required version wins in Go.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => ../fork\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn vendored_leaf_must_name_the_replaced_module_and_version() {
        for target in [
            format!("./.socket/vendor/golang/{UUID_B}/{MODULE}@v1.0.0"),
            format!("./.socket/vendor/golang/{UUID_B}/github.com/foo/other@{VERSION}"),
            format!("./.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}/sub"),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {target}\n"),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{target}");
        }
    }

    #[tokio::test]
    async fn path_traversal_and_out_of_root_targets_are_rejected() {
        let cases = [
            // Traversal inside the leaf.
            format!("replace {MODULE} {VERSION} => ./.socket/vendor/golang/{UUID_B}/../../../../etc@{VERSION}"),
            // An artifact outside the project root (detect_owner still says Vendor).
            format!("replace {MODULE} {VERSION} => ../other/.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}"),
            format!("replace {MODULE} {VERSION} => /abs/app/.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}"),
            // Non-canonical uuid dir.
            format!("replace {MODULE} {VERSION} => ./.socket/vendor/golang/{}/{MODULE}@{VERSION}", UUID_B.to_uppercase()),
            // Traversal in the replaced module path.
            format!("replace github.com/../../evil {VERSION} => ./.socket/vendor/golang/{UUID_B}/github.com/../../evil@{VERSION}"),
            format!("replace github.com/../evil {VERSION} => {} v1.4.2-socketpatch.1", gopatch(UUID_A)),
        ];
        for line in cases {
            let p = Project::new();
            p.write("go.mod", format!("module example.com/app\n\n{line}\n"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(
                !out.diagnostics.is_empty()
                    && out.diagnostics.iter().all(|d| d.code == DIAG_REF_INVALID),
                "{line}: {:?}",
                out.diagnostics
            );
        }
    }

    #[tokio::test]
    async fn only_the_exact_socket_module_namespace_is_hosted() {
        let a = UUID_A;
        // Not ours at all: silent.
        for rhs in [
            format!("evil.example/gopatch/{a}"),
            format!("patch.socket.dev.evil.example/gopatch/{a}"),
            format!("evil.example/patch.socket.dev/gopatch/{a}"),
            "github.com/fork/bar".to_string(),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {rhs} v1.4.2\n"),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{rhs}: {:?}", out.diagnostics);
        }
        // Socket-namespaced but not something we write: diagnosed, and the
        // uuid-shaped grant token is never elected.
        for rhs in [
            format!("patch.socket.dev/gopatch/{TOKEN}/{a}"),
            format!("patch.socket.dev/gopatch/{a}/{TOKEN}"),
            "patch.socket.dev/gopatch/{{PATCH_UUID}}".to_string(),
            "patch.socket.dev/gopatch/".to_string(),
            format!("patch.socket.dev/gopatch/{}", a.to_uppercase()),
            format!("patch.socket.dev/gopatch/{a}/v1"),
            format!("patch.socket.dev/gopatch/{a}/v02"),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!(
                    "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {rhs} v1.4.2-socketpatch.1\n"
                ),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{rhs}");
        }
        // Major-version suffix for v2+ originals.
        let p = Project::new();
        p.write(
            "go.mod",
            "module example.com/app\n\nrequire github.com/foo/bar/v3 v3.0.1\n\n\
             replace github.com/foo/bar/v3 v3.0.1 => patch.socket.dev/gopatch/"
                .to_string()
                + a
                + "/v3 v3.0.1-socketpatch.1\n",
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:golang/github.com/foo/bar/v3@v3.0.1",
                a,
                WiringMode::Hosted,
            )],
        );
        // Missing replacement version (invalid go.mod) is diagnosed.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {}\n",
                gopatch(a)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn registry_deps_user_replaces_and_go_patches_yield_nothing() {
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}require github.com/x/y v1.0.0\n\nreplace (\n\tgithub.com/x/y v1.0.0 => ../y\n\t{MODULE} {VERSION} => ./.socket/go-patches/{MODULE}@{VERSION}\n)\n// replace {MODULE} {VERSION} => {} v1\n",
                gopatch(UUID_A)
            ),
        )
        .write(
            "go.sum",
            "github.com/x/y v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn malformed_go_mod_is_a_diagnostic_not_a_panic() {
        let a = gopatch(UUID_A);
        for (go_mod, code) in [
            (
                format!("module m\n\nreplace (\n\t{MODULE} {VERSION} => {a} v1\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
            (
                format!("module m\n)\nreplace {MODULE} {VERSION} => {a} v1\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
            (
                format!("module m\nreplace (\nrequire (\n{MODULE} {VERSION} => {a} v1\n)\n)\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![code], "{go_mod}");
            assert!(out.diagnostics[0].detail.starts_with("go.mod: "));
        }
        // Non-UTF-8 bytes: unreadable, not a panic.
        let p = Project::new();
        p.write("go.mod", b"module m\n\xff\xfe replace\n".as_slice());
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
        // Garbage that happens to be UTF-8: nothing, silently.
        let p = Project::new();
        p.write("go.mod", "=> => replace => \"\"\" `` \u{0}\n");
        let out = run(&p).await;
        assert_refs(&out, &[]);
    }

    #[tokio::test]
    async fn orchestrator_runs_the_golang_extractor() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/expected");
        let out = p.discover().await;
        assert!(out.wires(PURL, FIXTURE_UUID, WiringMode::Hosted));
    }
}
