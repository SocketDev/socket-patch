//! Bun lockfiles: `bun.lock` (text, lockfileVersion 0/1/2) and `bun.lockb`
//! (binary, every codec-supported format).
//!
//! ## Which lock
//!
//! Exactly ONE of the two is read, because bun itself reads exactly one:
//! `bun.lock` whenever it exists (lstat — a squatting FIFO / dangling link
//! still counts, and is then diagnosed unreadable), else `bun.lockb`. A
//! stale binary lock left beside a text lock wires nothing, so it must not
//! become a ref (rule 10 — the same gate `vendor::bun_workspace` and
//! `lock_inventory::wired_vendor_integrity` apply).
//!
//! ## Shapes recognized
//!
//! | lock | mode | written by | recognized entry |
//! |---|---|---|---|
//! | `bun.lock` | hosted | `patch::redirect` `rewrite_bun_lock` | `"k": ["<name>@<socket url>", {meta}, "sha512-…"]` |
//! | `bun.lock` | hosted | bun < 1.3.10 re-save of the above | `"k": ["<name>@<socket url>", {meta}]` (digest dropped) |
//! | `bun.lock` | vendored | `vendor::bun_lock` | `"k": ["<name>@.socket/vendor/npm/<uuid>/<leaf>.tgz", {meta}, "sha512-…"]` |
//! | `bun.lock` | vendored | bun < 1.3.10 re-save | the same 2-tuple without the digest |
//! | `bun.lockb` | hosted | `patch::redirect::rewrite_bun_binary` | remote-tarball resolution = the socket url, sha512 integrity |
//! | `bun.lockb` | vendored | `vendor::bun_binary` | local-tarball resolution `.socket/vendor/npm/<uuid>/<leaf>.tgz`, sha512 integrity |
//!
//! The map key (`k`) is ignored: it is the ALIAS for an aliased install and
//! `parent/child` for a nested instance, while the tuple's spec always names
//! the real package — the name comes from the spec, split with
//! [`split_name_spec`] (a scope `@` is at index 0, a vendored spec keeps
//! the scope dir in its leaf). A binary record carries the real name.
//!
//! **Version comes ONLY from the artifact leaf.** A URL / tarball tuple has
//! no version element and a tarball binary resolution has none either, so:
//!
//! * hosted: the url's last path segment must be `<bare>-<version>.tgz`
//!   (`<bare>` = the name without its `@scope/`), `<version>` must be
//!   semver, and `hosted_url_names` must agree ([`hosted_url_version`]) —
//!   the same function the hosted rollback (`redirect::bun_binary::names`)
//!   uses to recover the version of a binary redirect;
//! * vendored: the leaf must be `[@scope/]<bare>-<version>.tgz` — i.e.
//!   `<name>-<version>.tgz`, the `tgz_rel_leaf` the vendor backend names it
//!   after the entry it rewires ([`tgz_leaf_version`]) — with a semver
//!   `<version>`. The split is
//!   anchored on the spec's name, never guessed from the leaf alone
//!   (`vendored_leaf_purl` splits at the LAST `-<digit>`, which misreads
//!   prerelease versions such as `1.0.0-2`).
//!
//! A leaf naming a DIFFERENT package than the spec (or a binary record whose
//! own npm version disagrees with the leaf) is not Socket-written and is
//! diagnosed ([`DIAG_REF_INVALID`]), never trusted.
//!
//! Tuple arity: our writers emit the 3-tuple and bun < 1.3.10 re-saves it
//! as the 2-tuple (spec + meta intact — the hosted rewriter heals it on the
//! next run, and the vendored backend treats it as still-ours); element 1
//! must be the `{meta}` object. A Socket spec in any other tuple shape is
//! diagnosed: bun would not read it as a tarball tuple.
//!
//! ## Integrity (`integrity_required`)
//!
//! Both hosted rewriters REFUSE a dependency without a sha512
//! (`redirect_bun_missing_sha512`) and always write it, so hosted refs set
//! `integrity_required = true` for BOTH locks. The digest-less 2-tuple is
//! still a ref (an installed tree verifies it, and it proves a redirect
//! ledger live) but is not attestable from the lockfile alone: bun < 1.3.10
//! dropped the pin we wrote, and nothing else in the lock fixes WHICH bytes
//! the url serves. Vendored refs carry the pin when present; their artifact
//! is hashed regardless.
//!
//! ## Parsing
//!
//! `bun.lock` is JSONC (trailing commas), read with the lock inventory's
//! entry model ([`bun_text_entries`]) — the ONE fail-closed line grammar
//! the hosted and vendored backends and `scan` / `get` / `vendor` share
//! (`vendor::bun_lock_text`): the version head gated by
//! `check_lock_version` (a lock this release cannot write is one it does
//! not read either), then bun's byte-exact single-line `packages` entries.
//! A lock that grammar refuses (a hand re-indented or re-wrapped one
//! included) records [`DIAG_LOCKFILE_UNPARSEABLE`] and yields nothing, so
//! `vex` never attests from a lock every other command treats as
//! unreadable. A lock with no `"packages": {` section resolves nothing.
//!
//! `bun.lockb` goes through the native codec
//! ([`BunLockb::parse_packages`]), never a text scan: its append-only string pool retains
//! paths from earlier patch generations. A lock the codec rejects records
//! [`DIAG_LOCKFILE_UNPARSEABLE`].
//!
//! Non-goals: nested workspace-member locks (bun keeps one lock at the
//! workspace root); git / github / workspace / folder entries (never
//! Socket-written).

use super::{
    npm_purl, DiscoverCtx, Discovery, LocateOpts, Located, PatchedRef, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_REF_INVALID,
};
use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB};
use crate::patch::redirect::hosted_url_version;
use crate::utils::digest::is_sri_pin;
use crate::vendor::bun_lock_text::{decode_json_string, split_name_spec};
use crate::vendor::bun_lockb::BunLockb;
use crate::vendor::lock_inventory::bun::bun_text_entries;
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::npm_common::tgz_leaf_version;

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    if ctx.exists(BUN_LOCK).await {
        extract_text(ctx, out).await;
        // bun reads bun.lock whenever it exists: whatever a leftover
        // bun.lockb still names is recognized as unwired (rule 11).
        ctx.recognize_ignored(BUN_LOCKB).await;
    } else {
        extract_binary(ctx, out).await;
    }
}

// ── bun.lock ─────────────────────────────────────────────────────────────

async fn extract_text(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(text) = ctx.read_text(BUN_LOCK, out).await else {
        return;
    };
    let entries = match bun_text_entries(&text) {
        Ok(entries) => entries,
        Err(detail) => {
            out.diag(DIAG_LOCKFILE_UNPARSEABLE, BUN_LOCK, detail);
            return;
        }
    };
    for entry in &entries {
        let elems = &entry.elems;
        let Some(spec) = elems.first().and_then(|e| decode_json_string(e)) else {
            continue;
        };
        let Some((name, target)) = split_name_spec(&spec) else {
            continue;
        };
        // Our tarball tuple: `[spec, {meta}, "sha512-…"]`, or bun < 1.3.10's
        // digest-less re-save `[spec, {meta}]` (elements are raw JSON).
        let tarball_tuple = matches!(elems.len(), 2 | 3)
            && elems[1].starts_with('{')
            && elems.get(2).is_none_or(|e| e.starts_with('"'));
        let integrity = elems
            .get(2)
            .and_then(|e| decode_json_string(e))
            .filter(|sri| is_sri_pin(sri))
            .map(LockIntegrity::Sri);
        classify(
            ctx,
            BUN_LOCK,
            Entry {
                label: &entry.key,
                name,
                target,
                recorded_version: None,
                integrity,
                shape_ok: tarball_tuple,
            },
            out,
        );
    }
}

// ── bun.lockb ────────────────────────────────────────────────────────────

async fn extract_binary(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(bytes) = ctx.read_bytes(BUN_LOCKB, out).await else {
        return;
    };
    let packages = match BunLockb::parse_packages(&bytes) {
        Ok(packages) => packages,
        Err(e) => {
            out.diag(
                DIAG_LOCKFILE_UNPARSEABLE,
                BUN_LOCKB,
                format!("{BUN_LOCKB} is not a readable Bun binary lockfile: {e}"),
            );
            return;
        }
    };
    for p in &packages {
        let integrity = p
            .integrity
            .as_deref()
            .filter(|sri| is_sri_pin(sri))
            .map(|sri| LockIntegrity::Sri(sri.to_string()));
        classify(
            ctx,
            BUN_LOCKB,
            Entry {
                label: &format!("package #{}", p.id),
                name: &p.name,
                target: &p.resolution,
                recorded_version: p.version.as_deref(),
                integrity,
                // The codec only yields a resolution STRING for registry and
                // tarball-like records; git records come back empty.
                shape_ok: true,
            },
            out,
        );
    }
}

// ── shared classification ────────────────────────────────────────────────

/// One lock entry, format-neutral.
struct Entry<'a> {
    /// How the diagnostics name the entry (the text map key / binary id).
    label: &'a str,
    /// The package name the entry resolves (spec name / binary name).
    name: &'a str,
    /// What bun resolves it FROM: the spec after `name@` (text) or the
    /// resolution string (binary).
    target: &'a str,
    /// An npm version the lock records for the entry itself (binary
    /// registry records only); must agree with the leaf.
    recorded_version: Option<&'a str>,
    integrity: Option<LockIntegrity>,
    /// The entry is in a shape bun reads as a tarball tuple.
    shape_ok: bool,
}

/// Push `entry`'s ref when it is Socket-wired (see the module docs); stay
/// silent for anything else.
fn classify(ctx: &DiscoverCtx<'_>, file: &str, entry: Entry<'_>, out: &mut Discovery) {
    let Entry {
        label,
        name,
        target,
        recorded_version,
        integrity,
        shape_ok,
    } = entry;
    let Located {
        vendored,
        hosted,
        decorated_leaf,
    } = ctx.locate(target, LocateOpts::LITERAL_CHECKED);
    let hosted_uuid = if vendored.is_none() { hosted } else { None };
    if decorated_leaf {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: {label}: {name}@{target} is not a literal \
                 .socket/vendor/npm/<uuid>/<tarball> path; it is ignored"
            ),
        );
        return;
    }
    if vendored.is_none() && hosted_uuid.is_none() {
        // Registry / git / workspace / user tarball dependency: not ours. A
        // registry entry (an exact version) is evidence against another
        // lock's wiring of the same package.
        let version = recorded_version.or_else(|| {
            target
                .starts_with(|c: char| c.is_ascii_digit())
                .then_some(target)
        });
        if let Some(version) = version {
            out.resolved_elsewhere(file, npm_purl(name, version));
        }
        return;
    }
    let invalid = |out: &mut Discovery, why: String| {
        out.diag(DIAG_REF_INVALID, file, format!("{file}: {label}: {why}"));
    };
    if !shape_ok {
        invalid(
            out,
            format!(
                "{name}@{target} is not in bun's tarball tuple shape [spec, {{meta}}, integrity]"
            ),
        );
        return;
    }
    let version = match &vendored {
        Some(vref) if vref.eco != "npm" => {
            invalid(out, format!("{target:?} is not a vendored npm tarball"));
            return;
        }
        Some(vref) => tgz_leaf_version(name, &vref.leaf)
            .filter(|version| semver::Version::parse(version).is_ok()),
        None => hosted_url_version(target, name),
    };
    let Some(version) = version else {
        invalid(
            out,
            format!("{target:?} is not an artifact of {name:?} (its leaf must be the package's own <name>-<version>.tgz)"),
        );
        return;
    };
    if recorded_version.is_some_and(|recorded| recorded != version) {
        invalid(
            out,
            format!(
                "records version {:?} but is wired to {target:?}",
                recorded_version.unwrap_or_default()
            ),
        );
        return;
    }
    let Some(purl) = npm_purl(name, version) else {
        invalid(
            out,
            format!("Socket-wired entry {name:?}@{version:?} has unsafe coordinates"),
        );
        return;
    };
    // Hosted: both bun rewriters always write the sha512 (see module docs).
    if let Some(vref) = vendored {
        out.push(PatchedRef::vendored(purl, &vref, file, integrity));
    } else if let Some(uuid) = hosted_uuid {
        out.push(PatchedRef::hosted(
            purl,
            uuid,
            file,
            Some(target),
            integrity,
            true,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{testing::*, *};
    use crate::patch::redirect::{rewrite_bun_binary, DepOverride, Integrity, RewriteResult};

    const SRI: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    /// The patch uuid every `redirect/npm/bun` fixture wires.
    const FIXTURE_UUID: &str = "77777777-7777-7777-7777-777777777777";
    /// The uuid the stale-url fixtures' INPUT locks still carry.
    const STALE_UUID: &str = "66666666-6666-6666-6666-666666666666";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    fn fixture(case: &str, side: &str) -> Project {
        let p = Project::new();
        p.copy_fixture(&format!("redirect/npm/bun/{case}/{side}"));
        p
    }

    /// A text lock with the given `packages` entry lines.
    fn text_lock(version: u32, entries: &[String]) -> String {
        let mut s = format!(
            "{{\n  \"lockfileVersion\": {version},\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"app\",\n    }},\n  }},\n  \"packages\": {{\n"
        );
        for e in entries {
            s.push_str("    ");
            s.push_str(e);
            s.push_str(",\n");
        }
        s.push_str("  }\n}\n");
        s
    }

    fn tuple(key: &str, spec: &str, integrity: Option<&str>) -> String {
        match integrity {
            Some(sri) => format!("\"{key}\": [\"{spec}\", {{}}, \"{sri}\"]"),
            None => format!("\"{key}\": [\"{spec}\", {{}}]"),
        }
    }

    // ── bun.lock: the hosted rewriter's committed outputs ───────────────

    /// Every committed hosted-rewriter OUTPUT (lock v0 / v1 / v2, CRLF,
    /// alias key, nested `parent/child` key, workspace-nested instance, a
    /// custom registry, healed digest-less re-saves, a re-pinned stale url)
    /// wires `left-pad@1.3.0` to the fixture uuid with its sha512 pin.
    #[tokio::test]
    async fn every_hosted_rewriter_output_is_discovered() {
        for case in [
            "alias",
            "basic",
            "custom-registry",
            "digestless-hosted-already-wired",
            "digestless-hosted-stale-url-repin",
            "lock-v0",
            "lock-v1-workspace",
            "lock-v2",
            "lock-v2-crlf",
            "lock-v2-workspace-nested",
            "nested-entry",
            "re-redirect-stale-url",
        ] {
            let out = run(&fixture(case, "expected")).await;
            assert_refs(&out, &[(LEFT_PAD, FIXTURE_UUID, WiringMode::Hosted)]);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
            for r in &out.refs {
                assert_eq!(r.source_file, Path::new("bun.lock"), "{case}");
                assert_eq!(
                    r.locked_integrity,
                    Some(LockIntegrity::Sri(SRI.to_string())),
                    "{case}"
                );
                assert!(r.integrity_required && r.lockfile_basis_ok(), "{case}");
                assert!(
                    r.url.as_deref().is_some_and(|u| u.contains(FIXTURE_UUID)),
                    "{case}: {:?}",
                    r.url
                );
            }
        }
    }

    /// The rewriter's INPUTS: registry-only locks wire nothing (silently);
    /// already-wired inputs are refs — including the digest-less 2-tuple a
    /// Bun < 1.3.10 re-save leaves, which keeps its ref but loses the
    /// lockfile basis — and a stale-url input names the OLD uuid.
    #[tokio::test]
    async fn rewriter_inputs_registry_only_and_already_wired() {
        for case in [
            "alias",
            "basic",
            "custom-registry",
            "lock-v0",
            "lock-v0-workspace-refusal",
            "lock-v1-workspace",
            "lock-v2",
            "lock-v2-crlf",
            "lock-v2-workspace-nested",
            "missing-sha512",
            "nested-entry",
            "scoped-package",
        ] {
            let out = run(&fixture(case, "input")).await;
            assert!(out.refs.is_empty(), "{case}: {:#?}", out.refs);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }

        let out = run(&fixture("rerun-noop", "input")).await;
        assert_refs(&out, &[(LEFT_PAD, FIXTURE_UUID, WiringMode::Hosted)]);
        assert!(out.refs[0].lockfile_basis_ok());

        let out = run(&fixture("digestless-hosted-already-wired", "input")).await;
        assert_refs(&out, &[(LEFT_PAD, FIXTURE_UUID, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(!out.refs[0].lockfile_basis_ok());

        let out = run(&fixture("digestless-hosted-stale-url-repin", "input")).await;
        assert_refs(&out, &[(LEFT_PAD, STALE_UUID, WiringMode::Hosted)]);
        assert!(!out.refs[0].lockfile_basis_ok());

        let out = run(&fixture("re-redirect-stale-url", "input")).await;
        assert_refs(&out, &[(LEFT_PAD, STALE_UUID, WiringMode::Hosted)]);
        assert!(out.refs[0].lockfile_basis_ok());
    }

    /// The `scoped-package` fixture wires `@babel/core@7.0.0`'s entry to an
    /// artifact whose leaf is `left-pad-1.3.0.tgz`: the version cannot be
    /// recovered from a leaf naming another package, so it is diagnosed,
    /// never attributed.
    #[tokio::test]
    async fn leaf_naming_another_package_is_diagnosed() {
        let out = run(&fixture("scoped-package", "expected")).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert!(out.diagnostics[0].detail.contains("bun.lock"));
    }

    /// A realistic scoped hosted url (`<bare>-<version>.tgz` leaf) resolves
    /// to the scoped purl; a prerelease version is read whole.
    #[tokio::test]
    async fn scoped_and_prerelease_hosted_entries() {
        let scoped = hosted_url("npm", "@babel/core", "7.0.0", UUID_A, "core-7.0.0.tgz");
        let pre = hosted_url("npm", "left-pad", "1.3.0-2", UUID_B, "left-pad-1.3.0-2.tgz");
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[
                    tuple("@babel/core", &format!("@babel/core@{scoped}"), Some(SRI)),
                    tuple("left-pad", &format!("left-pad@{pre}"), Some(SRI)),
                ],
            ),
        );
        assert_refs(
            &run(&p).await,
            &[
                ("pkg:npm/@babel/core@7.0.0", UUID_A, WiringMode::Hosted),
                ("pkg:npm/left-pad@1.3.0-2", UUID_B, WiringMode::Hosted),
            ],
        );
    }

    // ── bun.lock: vendored ──────────────────────────────────────────────

    /// The vendored backend's shapes (`vendor::bun_lock` BN3 fixture line,
    /// nested key, scoped leaf with its scope dir, digest-less re-save) plus
    /// the hand-edit spellings `vendor_ref` tolerates.
    #[tokio::test]
    async fn vendored_text_entries_are_discovered() {
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[
                    tuple(
                        "left-pad",
                        &format!("left-pad@.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz"),
                        Some(SRI),
                    ),
                    tuple(
                        "haspad/left-pad",
                        &format!("left-pad@.socket/vendor/npm/{UUID_A}/left-pad-1.3.0.tgz"),
                        Some(SRI),
                    ),
                    tuple(
                        "@scope/pkg",
                        &format!("@scope/pkg@.socket/vendor/npm/{UUID_B}/@scope/pkg-1.0.0.tgz"),
                        Some(SRI),
                    ),
                    // Bun < 1.3.10 digest-less re-save.
                    tuple(
                        "minimist",
                        &format!("minimist@.socket/vendor/npm/{UUID_B}/minimist-1.2.2.tgz"),
                        None,
                    ),
                    // Hand-edit spellings.
                    tuple(
                        "is-number",
                        &format!(
                            "is-number@file:./.socket/vendor/npm/{UUID_A}/is-number-7.0.0.tgz"
                        ),
                        Some(SRI),
                    ),
                ],
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (LEFT_PAD, UUID_A, WiringMode::Vendored),
                ("pkg:npm/@scope/pkg@1.0.0", UUID_B, WiringMode::Vendored),
                ("pkg:npm/minimist@1.2.2", UUID_B, WiringMode::Vendored),
                ("pkg:npm/is-number@7.0.0", UUID_A, WiringMode::Vendored),
            ],
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        let scoped = out
            .refs
            .iter()
            .find(|r| r.purl == "pkg:npm/@scope/pkg@1.0.0")
            .expect("scoped ref");
        assert_eq!(
            scoped.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/npm/{UUID_B}/@scope/pkg-1.0.0.tgz").as_str())
        );
        assert_eq!(
            scoped.locked_integrity,
            Some(LockIntegrity::Sri(SRI.into()))
        );
        let minimist = out
            .refs
            .iter()
            .find(|r| r.purl == "pkg:npm/minimist@1.2.2")
            .expect("digest-less ref");
        assert_eq!(minimist.locked_integrity, None);
    }

    /// Hosted and vendored entries in one lock are all discovered (a mixed
    /// project), and the lockfileVersion 2 head is accepted.
    #[tokio::test]
    async fn mixed_modes_in_a_v2_lock() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                2,
                &[
                    tuple("left-pad", &format!("left-pad@{url}"), Some(SRI)),
                    tuple(
                        "minimist",
                        &format!("minimist@.socket/vendor/npm/{UUID_B}/minimist-1.2.2.tgz"),
                        Some(SRI),
                    ),
                    "\"is-number\": [\"is-number@7.0.0\", \"\", {}, \"sha512-X==\"]".to_string(),
                ],
            ),
        );
        assert_refs(
            &run(&p).await,
            &[
                (LEFT_PAD, UUID_A, WiringMode::Hosted),
                ("pkg:npm/minimist@1.2.2", UUID_B, WiringMode::Vendored),
            ],
        );
    }

    // ── bun.lock: negatives ─────────────────────────────────────────────

    /// Not refs, silently: a uuid in a foreign host's url, a Socket url with
    /// a placeholder (non-uuid) token and uuid, workspace / git / registry
    /// entries, and vendored paths that escape the root or traverse inside
    /// the uuid dir (`vendor_ref` rejects them — the same silence as npm).
    #[tokio::test]
    async fn non_socket_entries_are_silent() {
        let foreign = format!("https://evil.example/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        let placeholder = "https://patch.socket.dev/patch/npm/tok/uuid/left-pad-1.3.0.tgz";
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[
                    tuple("a", &format!("left-pad@{foreign}"), Some(SRI)),
                    tuple("b", &format!("left-pad@{placeholder}"), Some(SRI)),
                    tuple(
                        "c",
                        &format!("left-pad@../.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz"),
                        Some(SRI),
                    ),
                    tuple(
                        "d",
                        &format!("left-pad@/abs/.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz"),
                        Some(SRI),
                    ),
                    tuple(
                        "e",
                        &format!("left-pad@.socket/vendor/npm/{UUID_B}/../left-pad-1.3.0.tgz"),
                        Some(SRI),
                    ),
                    "\"member\": [\"member@workspace:packages/member\"]".to_string(),
                    "\"gitdep\": [\"gitdep@github:o/r#abc\", {}, \"o-r-abc\"]".to_string(),
                    "\"is-number\": [\"is-number@7.0.0\", \"\", {}, \"sha512-X==\"]".to_string(),
                ],
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The patch uuid is the LAST canonical-uuid segment — a uuid-shaped
    /// grant token before it is never elected.
    #[tokio::test]
    async fn uuid_shaped_grant_token_is_not_the_patch() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        assert!(url.contains(TOKEN));
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[tuple("left-pad", &format!("left-pad@{url}"), Some(SRI))],
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(LEFT_PAD, UUID_A, WiringMode::Hosted)]);
    }

    /// Socket-shaped entries that fail validation are DIAGNOSED, never
    /// attested: traversal / malformed names, a vendored artifact of another
    /// ecosystem, a leaf naming another package or version, and a Socket
    /// spec outside bun's tarball-tuple shape.
    #[tokio::test]
    async fn invalid_socket_entries_are_diagnosed() {
        let url = |name: &str, leaf: &str| hosted_url("npm", name, "1.0.0", UUID_A, leaf);
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[
                    // Traversal in the spec name (leaf matches it).
                    tuple(
                        "x",
                        &format!("../../etc@{}", url("etc", "etc-1.0.0.tgz")),
                        Some(SRI),
                    ),
                    tuple(
                        "z",
                        &format!("a/b/c@.socket/vendor/npm/{UUID_B}/a/b/c-1.0.0.tgz"),
                        Some(SRI),
                    ),
                    // Vendored path into another ecosystem's dir.
                    tuple(
                        "six",
                        &format!("six@.socket/vendor/pypi/{UUID_B}/six-1.16.0-py3-none-any.whl"),
                        Some(SRI),
                    ),
                    // Leaf names a different package / a non-semver tail.
                    tuple(
                        "lodash",
                        &format!("lodash@{}", url("lodash", "minimist-1.2.2.tgz")),
                        Some(SRI),
                    ),
                    tuple(
                        "foo",
                        &format!("foo@{}", url("foo", "foo-bar-1.0.0.tgz")),
                        Some(SRI),
                    ),
                    tuple(
                        "qs",
                        &format!("qs@.socket/vendor/npm/{UUID_B}/minimist-1.2.2.tgz"),
                        Some(SRI),
                    ),
                    // Registry-4-tuple shape carrying a Socket spec.
                    format!(
                        "\"left-pad\": [\"left-pad@{}\", \"\", {{}}, \"{SRI}\"]",
                        url("left-pad", "left-pad-1.0.0.tgz")
                    ),
                ],
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 7],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("bun.lock: ")));
    }

    /// A pin that is not an SRI string is no pin: still a ref, no basis.
    #[tokio::test]
    async fn non_sri_integrity_is_no_pin() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[tuple(
                    "left-pad",
                    &format!("left-pad@{url}"),
                    Some("garbage"),
                )],
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(LEFT_PAD, UUID_A, WiringMode::Hosted)]);
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    /// `--patch-server-url` deployments count as hosted origins.
    #[tokio::test]
    async fn configured_patch_server_origin_is_accepted() {
        let url = format!("http://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        let lock = text_lock(
            1,
            &[tuple("left-pad", &format!("left-pad@{url}"), Some(SRI))],
        );
        let without = Project::new();
        without.write("bun.lock", &lock);
        assert!(run(&without).await.refs.is_empty());
        let with = Project::new().with_origin("http://127.0.0.1:4545");
        with.write("bun.lock", &lock);
        assert_refs(&run(&with).await, &[(LEFT_PAD, UUID_A, WiringMode::Hosted)]);
    }

    /// ONE bun.lock grammar: a re-indented, re-wrapped lock (bun itself
    /// accepts it) is refused by the shared fail-closed line reader the
    /// inventory and both backends use, so discovery diagnoses it instead of
    /// attesting from a lock `scan` / `get` / `vendor` cannot read. The same
    /// entries in bun's emitted layout, with a BOM and a string containing
    /// `,]`, are read.
    #[tokio::test]
    async fn reformatted_lock_is_refused_like_every_other_reader() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let p = Project::new();
        p.write(
            "bun.lock",
            format!(
                "\u{feff}{{\n  \"lockfileVersion\": 1,\n\t\"workspaces\": {{ \"\": {{ \"name\": \"a,]b\", }}, }},\n\t\"packages\": {{\n\t\t\"left-pad\": [\n\t\t\t\"left-pad@{url}\",\n\t\t\t{{ \"dependencies\": {{ \"x\": \"1\", }}, }},\n\t\t\t\"{SRI}\",\n\t\t],\n\t}},\n}}\n"
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
        assert!(
            out.diagnostics[0]
                .detail
                .contains("not in bun's emitted shape"),
            "{:?}",
            out.diagnostics
        );
        let text = std::fs::read_to_string(p.root().join("bun.lock")).unwrap();
        assert!(crate::vendor::lock_inventory::bun::bun_text_entries(&text).is_err());

        let canonical = Project::new();
        canonical.write(
            "bun.lock",
            format!(
                "\u{feff}{}",
                text_lock(
                    1,
                    &[tuple("left-pad", &format!("left-pad@{url}"), Some(SRI))]
                )
                .replacen("\"name\": \"app\"", "\"name\": \"a,]b\"", 1)
            ),
        );
        let out = run(&canonical).await;
        assert_refs(&out, &[(LEFT_PAD, UUID_A, WiringMode::Hosted)]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Malformed text locks are diagnosed, never fatal: unsupported
    /// lockfileVersion (the committed fixture), no version head, and a
    /// `packages` header outside bun's emitted shape. A lock with no
    /// `"packages": {` section at all resolves nothing, as it does for the
    /// inventory and both backends — including a non-object `packages`, or
    /// a body that never reaches one.
    #[tokio::test]
    async fn malformed_text_locks_are_diagnosed() {
        let out = run(&fixture("lock-version-unsupported", "input")).await;
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
        for body in [
            "{ \"packages\": {} }".to_string(),
            "{\n  \"lockfileVersion\": 1,\n  \"packages\": { \"a\": [\"a@x\" \n".to_string(),
            "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"a\": [\"a@x\"\n  }\n}\n"
                .to_string(),
        ] {
            let p = Project::new();
            p.write("bun.lock", &body);
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{body:.60}");
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_LOCKFILE_UNPARSEABLE],
                "{body:.60}"
            );
            assert!(out.diagnostics[0].detail.contains("bun.lock"));
        }
        for body in [
            "{\n  \"lockfileVersion\": 1,\n}\n".to_string(),
            "{\n  \"lockfileVersion\": 1,\n  \"packages\": [],\n}\n".to_string(),
            "{\n  \"lockfileVersion\": 1,\n".to_string() + &"[".repeat(100_000),
        ] {
            let p = Project::new();
            p.write("bun.lock", &body);
            let out = run(&p).await;
            assert!(
                out.refs.is_empty() && out.diagnostics.is_empty(),
                "{body:.60}"
            );
        }
    }

    // ── bun.lockb ───────────────────────────────────────────────────────

    /// Every committed real-Bun binary lock (formats 1–3, 0.1.1 … 1.4.2,
    /// production-filter and extension layouts).
    fn lockb_fixtures() -> Vec<(String, Vec<u8>)> {
        let dir = fixture_path("bun-lockb");
        let mut out: Vec<_> = std::fs::read_dir(&dir)
            .expect("bun-lockb fixture dir")
            .filter_map(|e| {
                let path = e.expect("fixture entry").path().join("bun.lockb");
                path.is_file().then(|| {
                    let name = path
                        .parent()
                        .and_then(|d| d.file_name())
                        .expect("fixture dir name")
                        .to_string_lossy()
                        .into_owned();
                    (name, std::fs::read(&path).expect("read fixture lock"))
                })
            })
            .collect();
        out.sort();
        assert!(
            out.len() >= 20,
            "fixtures: {:?}",
            out.iter().map(|f| &f.0).collect::<Vec<_>>()
        );
        out
    }

    fn minimist_override(version: &str, uuid: &str, artifact_url: String) -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: "minimist".into(),
            namespace: None,
            version: version.into(),
            token: TOKEN.into(),
            patch_uuid: uuid.into(),
            artifact_url,
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: Some(SRI.into()),
                ..Default::default()
            },
        }
    }

    /// `fixture` rewired by the production binary rewriter.
    fn rewire(fixture: &[u8], deps: &[DepOverride]) -> Vec<u8> {
        let mut result = RewriteResult::default();
        rewrite_bun_binary(fixture, deps, &mut result);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        result
            .binary_files
            .remove("bun.lockb")
            .expect("the rewriter changed the lock")
    }

    fn hosted_minimist(version: &str, uuid: &str) -> DepOverride {
        let leaf = format!("minimist-{version}.tgz");
        minimist_override(
            version,
            uuid,
            hosted_url("npm", "minimist", version, uuid, &leaf),
        )
    }

    fn vendored_minimist(version: &str, uuid: &str) -> DepOverride {
        minimist_override(
            version,
            uuid,
            format!(".socket/vendor/npm/{uuid}/minimist-{version}.tgz"),
        )
    }

    /// Pristine real-Bun locks wire nothing and parse cleanly.
    #[tokio::test]
    async fn pristine_binary_locks_wire_nothing() {
        for (version, bytes) in lockb_fixtures() {
            let p = Project::new();
            p.write("bun.lockb", &bytes);
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{version}: {:#?}", out.refs);
            assert!(
                out.diagnostics.is_empty(),
                "{version}: {:?}",
                out.diagnostics
            );
        }
    }

    /// Every binary format the codec writes: a hosted redirect and a
    /// vendored rewire of `minimist@1.2.2`, each written by the production
    /// binary rewriter, are discovered with their sha512 pin.
    #[tokio::test]
    async fn binary_hosted_and_vendored_across_every_bun_release() {
        for (version, bytes) in lockb_fixtures() {
            for (dep, mode) in [
                (hosted_minimist("1.2.2", UUID_A), WiringMode::Hosted),
                (vendored_minimist("1.2.2", UUID_A), WiringMode::Vendored),
            ] {
                let p = Project::new();
                p.write("bun.lockb", rewire(&bytes, &[dep]));
                let out = run(&p).await;
                assert_refs(&out, &[("pkg:npm/minimist@1.2.2", UUID_A, mode)]);
                assert!(
                    out.diagnostics.is_empty(),
                    "{version}: {:?}",
                    out.diagnostics
                );
                let r = &out.refs[0];
                assert_eq!(r.source_file, Path::new("bun.lockb"), "{version}");
                assert_eq!(
                    r.locked_integrity,
                    Some(LockIntegrity::Sri(SRI.into())),
                    "{version}"
                );
                match mode {
                    WiringMode::Hosted => assert!(r.lockfile_basis_ok(), "{version}"),
                    WiringMode::Vendored => assert_eq!(
                        r.artifact_rel.as_deref(),
                        Some(format!(".socket/vendor/npm/{UUID_A}/minimist-1.2.2.tgz").as_str()),
                        "{version}"
                    ),
                }
            }
        }
    }

    /// Two versions of one package wired to two patches (the `two-versions`
    /// fixture's `minimist` + its `newer` alias) are two refs.
    #[tokio::test]
    async fn binary_two_versions_two_patches() {
        let bytes = std::fs::read(fixture_path("bun-lockb/two-versions/bun.lockb"))
            .expect("two-versions fixture");
        let p = Project::new();
        p.write(
            "bun.lockb",
            rewire(
                &bytes,
                &[
                    hosted_minimist("1.2.2", UUID_A),
                    vendored_minimist("1.2.8", UUID_B),
                ],
            ),
        );
        assert_refs(
            &run(&p).await,
            &[
                ("pkg:npm/minimist@1.2.2", UUID_A, WiringMode::Hosted),
                ("pkg:npm/minimist@1.2.8", UUID_B, WiringMode::Vendored),
            ],
        );
    }

    /// Binary negatives: a non-Socket tarball url is silently not a ref; a
    /// leaf naming another package is diagnosed.
    #[tokio::test]
    async fn binary_foreign_and_mismatched_resolutions() {
        let bytes = std::fs::read(fixture_path("bun-lockb/1.4.2/bun.lockb")).expect("fixture");
        let foreign = minimist_override(
            "1.2.2",
            UUID_A,
            format!("https://evil.example/{TOKEN}/{UUID_A}/minimist-1.2.2.tgz"),
        );
        let p = Project::new();
        p.write("bun.lockb", rewire(&bytes, &[foreign]));
        let out = run(&p).await;
        assert!(
            out.refs.is_empty() && out.diagnostics.is_empty(),
            "{out:#?}"
        );

        let wrong_leaf = minimist_override(
            "1.2.2",
            UUID_A,
            hosted_url("npm", "minimist", "1.2.2", UUID_A, "left-pad-1.2.2.tgz"),
        );
        let p = Project::new();
        p.write("bun.lockb", rewire(&bytes, &[wrong_leaf]));
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
        assert!(out.diagnostics[0].detail.starts_with("bun.lockb: "));
    }

    /// A malformed binary lock (the committed placeholder, truncation) is
    /// diagnosed, never fatal.
    #[tokio::test]
    async fn malformed_binary_lock_is_diagnosed() {
        let good = std::fs::read(fixture_path("bun-lockb/1.4.2/bun.lockb")).expect("fixture");
        for bytes in [
            std::fs::read(fixture_path(
                "redirect/npm/bun/lockb-only-refusal/input/bun.lockb",
            ))
            .expect("placeholder fixture"),
            good[..good.len() / 2].to_vec(),
            Vec::new(),
        ] {
            let p = Project::new();
            p.write("bun.lockb", &bytes);
            let out = run(&p).await;
            assert!(out.refs.is_empty());
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE]);
            assert!(out.diagnostics[0].detail.contains("bun.lockb"));
        }
    }

    /// bun reads `bun.lock` whenever it exists, so a stale Socket-wired
    /// `bun.lockb` beside it wires nothing — and is not even parsed.
    #[tokio::test]
    async fn binary_lock_is_ignored_beside_a_text_lock() {
        let bytes = std::fs::read(fixture_path("bun-lockb/1.4.2/bun.lockb")).expect("fixture");
        let p = Project::new();
        p.write(
            "bun.lockb",
            rewire(&bytes, &[hosted_minimist("1.2.2", UUID_A)]),
        );
        p.copy_fixture("redirect/npm/bun/basic/input");
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        // Swept though not parsed: the shadowed binary's patch is
        // RECOGNIZED, so a ledger claim it alone mentions is dead (rule 11).
        assert_eq!(
            out.hosted_claim("pkg:npm/minimist@1.2.2", UUID_A),
            Some(false)
        );
        assert_eq!(
            out.recognized_files(UUID_A, WiringMode::Hosted),
            vec![std::path::Path::new("bun.lockb")]
        );
    }

    /// A FIFO squatting `bun.lock` fails fast (guarded read) — and still
    /// shadows the binary lock, like bun.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_text_lock_is_unreadable_not_a_hang() {
        let bytes = std::fs::read(fixture_path("bun-lockb/1.4.2/bun.lockb")).expect("fixture");
        let p = Project::new();
        p.write(
            "bun.lockb",
            rewire(&bytes, &[hosted_minimist("1.2.2", UUID_A)]),
        );
        let path = p.root().join("bun.lock");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    /// The full orchestrator picks the bun refs up.
    #[tokio::test]
    async fn orchestrator_includes_bun() {
        let out = fixture("basic", "expected").discover().await;
        assert_refs(&out, &[(LEFT_PAD, FIXTURE_UUID, WiringMode::Hosted)]);
    }

    // ── edge shapes no other test reaches ────────────────────────────────

    /// A `#` in a vendored bun.lock target names another file to bun (a
    /// literal path): diagnosed, not a ref.
    #[tokio::test]
    async fn decorated_vendored_target_is_diagnosed() {
        let p = Project::new();
        p.write(
            "bun.lock",
            text_lock(
                1,
                &[tuple(
                    "left-pad",
                    &format!("left-pad@.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz#evil.tgz"),
                    Some(SRI),
                )],
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID],
            "{:#?}",
            out.diagnostics
        );
    }
}
