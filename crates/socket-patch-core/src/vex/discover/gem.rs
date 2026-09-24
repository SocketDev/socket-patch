//! Bundler lockfiles: `Gemfile.lock` and `gems.locked` (bundler's modern
//! spelling, which the hosted rewriter edits instead of `Gemfile.lock` when
//! `gems.rb` is present). BOTH are read when both exist (contract rule 1:
//! no precedence between files). The Gemfile / `gems.rb` is NOT read: it is
//! Ruby source whose `source … do` blocks and `path:` options only become
//! what bundler installs once they are locked, and every wiring our tools
//! write lands in the lock as well (see below). A Gemfile-only wiring (the
//! pre-2.6 "mixed" hosted pair the rewriter warns about) is left to the
//! ledger fallback [`super::hosted_wiring_in_files`].
//!
//! ## Lock grammar
//!
//! Read with the lock inventory's own model ([`gemfile_lock`]): column-0
//! section headers, 2-space `remote:` keys, 4-space `specs:` entries,
//! `CHECKSUMS` and `DEPENDENCIES` pins, CRLF tolerated. A file the model
//! flags — conflict markers, indented text before the first header, or no
//! bundler section at all — is [`DIAG_LOCKFILE_UNPARSEABLE`] (bundler itself
//! refuses the first two).
//!
//! ## Hosted (`patch::redirect::rewrite_gem` / `converge_gem_lock_source`)
//!
//! The rewriter moves the patched gem's spec block out of its upstream
//! `GEM` section into a `GEM` section of its own:
//!
//! ```text
//! GEM
//!   remote: https://patch.socket.dev/patch-registry/gem/<token>/<uuid>/
//!   specs:
//!     rails (7.0.0)
//! ```
//!
//! A `GEM` section whose (single) remote is Socket-hosted
//! ([`DiscoverCtx::hosted_uuid`]) makes every spec under it a ref for that
//! uuid (the section is the patch's own compact index, which serves only the
//! patched gem — an extra spec there gets a ref too, and the CLI's record
//! match rejects it as `record_mismatch`). Stricter than the host allowlist:
//! the remote must END with `patch-registry/gem/<token>/<uuid>` (the compact
//! index root the rewriter writes), so a URL carrying only a uuid-SHAPED
//! grant token (`…/gem/<token>/`) is diagnosed rather than read as that
//! token's patch. Fail-closed cases, each a diagnostic and no ref:
//!
//! * several `remote:` lines in the section (a merged multi-source section)
//!   UNLESS the gem is source-pinned to the Socket remote — see "Merged
//!   sections" below;
//! * a platform-suffixed spec (`nokogiri (1.16.0-x86_64-linux)`): the patch
//!   registry serves only the ruby-platform gem, and the rewriter refuses
//!   deps with platform variants;
//! * the same gem name locked in ANOTHER source section as well (the
//!   rewriter MOVES the spec; a duplicate is a hand-edit bundler would
//!   resolve ambiguously).
//!
//! **Integrity.** `CHECKSUMS` `  name (version) sha256=<hex>` becomes
//! [`Sha256Hex`](crate::vendor::lock_inventory::LockIntegrity::Sha256Hex).
//! `integrity_required` is true iff the lock HAS a `CHECKSUMS` section: in
//! that era (bundler ≥ 2.6) the rewriter only converges the lock after
//! writing the patched gem's sha256, so a pin-less
//! Socket spec there is not Socket-written. A lock without `CHECKSUMS`
//! (bundler < 2.6) never carries a pin — there the rewriter leaves the lock
//! mixed and bundler writes the Socket section itself on the next unfrozen
//! install — so its refs may use the host-allowlist lockfile basis alone.
//!
//! ## Merged sections (bundler ≤ 2.1 and locks that started there)
//!
//! Bundler 1.17, 2.0 and 2.1 write every rubygems source into ONE `GEM`
//! section (`SourceList#combine_rubygems_sources`), and bundler 2.2+ keeps
//! a lock that already has that shape merged. After the prescribed unfrozen
//! install over the rewriter's Gemfile source block, such a lock reads
//! (verified on 1.17.3 / 2.0.2 / 2.1.4):
//!
//! ```text
//! GEM
//!   remote: https://rubygems.org/
//!   remote: https://patch.socket.dev/patch-registry/gem/<token>/<uuid>/
//!   specs:
//!     tiny-dep (1.0.0)
//!     vuln-gem (1.0.0)
//!       tiny-dep
//! ...
//! DEPENDENCIES
//!   vuln-gem (= 1.0.0)!
//! ```
//!
//! The section alone cannot say which remote served which spec, but bundler
//! resolves a gem declared inside a `source "<url>" do` block ONLY from that
//! source, and marks it source-pinned (`!`) in `DEPENDENCIES`. So a spec in
//! a merged section with exactly one Socket patch-registry remote is a
//! hosted ref when BOTH hold: `DEPENDENCIES` pins it (`name …!`) and the
//! sibling manifest (`Gemfile` for `Gemfile.lock`, `gems.rb` for
//! `gems.locked`) declares it inside a `source` block whose URL is that
//! remote. That manifest is read ONLY for this cross-check — i.e. only when
//! the lock has a merged section, whose own Socket remote already names the
//! uuid — so a Gemfile-only wiring (lock not merged) stays with the ledger
//! fallback.
//! The manifest is read as text, not run as Ruby, so the cross-check fails
//! closed on what text cannot settle: `=begin` … `=end` block comments are
//! skipped, and a gem the manifest ALSO declares in a block for another
//! source (dead code, a conditional branch) is not attributed.
//! The section's other specs (upstream gems) are silent; a merged Socket
//! section with no such pinned gem is [`DIAG_REF_UNATTRIBUTABLE`].
//!
//! ## Vendored (`vendor::gem` module docs)
//!
//! ```text
//! PATH
//!   remote: .socket/vendor/gem/<uuid>/<name>-<version>
//!   specs:
//!     <name> (<version>)
//! ```
//!
//! A `PATH` section whose remote points into `.socket/vendor/` must be a
//! root-anchored `.socket/vendor/gem/<uuid>/<name>-<version>` dir
//! ([`vendor_ref`]; `./` and a trailing `/` tolerated), and each spec under
//! it must be exactly the gem that leaf names (the vendor backend names the
//! dir after the gem it replaces; [`vendored_leaf_purl`] must agree). An
//! escaping (`../`, absolute), leaf-less, non-gem, or mismatched remote is
//! [`DIAG_REF_INVALID`]. Path gems carry no sha256 (bundler writes a BARE
//! `CHECKSUMS` entry for them), so vendored refs never set
//! `locked_integrity` — the committed artifact is hashed instead.
//!
//! `GIT` / `PLUGIN SOURCE` sections are never Socket wiring and are ignored.

use std::collections::{BTreeSet, HashMap};

use super::{
    names_vendor_dir, simple_purl, vendor_ref, vendored_leaf_purl, DiscoverCtx, Discovery,
    PatchedRef, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::vendor::gem::{gem_declaration_any, quoted_literal};
use crate::vendor::gemfile_lock::{
    self, bundler_manifest_for, same_remote, GemfileLock, Section, SpecLine, BUNDLER_LOCKS,
};

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    // Both locks, legacy spelling first (order only affects diagnostics).
    for file in BUNDLER_LOCKS {
        let Some(text) = ctx.read_text(file, out).await else {
            continue;
        };
        let lock = gemfile_lock::parse(&text);
        // A readable lock with a `GEM` section listing several remotes.
        let merged = lock.problems.is_empty() && lock.gem_sections().any(|s| s.remotes.len() > 1);
        let blocks = if merged {
            source_block_gems(ctx, bundler_manifest_for(file), out).await
        } else {
            Vec::new()
        };
        extract_lock(ctx, file, &lock, &blocks, out);
    }
}

/// `(source URL, gem name)` for every `gem` declared inside a `source "<url>"
/// do … end` block of the root manifest `rel` (see "Merged sections").
/// Missing => empty; unreadable => empty + the usual unreadable diagnostic.
async fn source_block_gems(
    ctx: &DiscoverCtx<'_>,
    rel: &str,
    out: &mut Discovery,
) -> Vec<(String, String)> {
    ctx.read_text(rel, out)
        .await
        .map(|text| parse_source_blocks(&text))
        .unwrap_or_default()
}

/// The Gemfile grammar [`source_block_gems`] reads: a line
/// `source "<url>" do` / `source('<url>') do` opens a block, a line starting
/// with `end` closes it, and each `gem "<name>"` / `gem('<name>'…` line in
/// between (the vendor backend's own [`gem_declaration_any`] grammar)
/// declares a block-scoped gem. Anything else (nested blocks,
/// `source` with a block argument, `#` comments, and Ruby's column-0
/// `=begin` … `=end` block comments) is ignored — this only ever ADDS a
/// cross-check to lock evidence, never creates a ref on its own.
fn parse_source_blocks(gemfile: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut open: Option<String> = None;
    let mut block_comment = false;
    for raw in gemfile.lines() {
        // `=begin` / `=end` must start at column 0 and be followed by
        // whitespace or the end of the line (Ruby's own rule).
        let marker = |word: &str| {
            raw.strip_prefix(word)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        };
        if block_comment {
            block_comment = !marker("=end");
            continue;
        }
        if marker("=begin") {
            block_comment = true;
            continue;
        }
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        match &open {
            None => {
                let Some(rest) = line.strip_prefix("source") else {
                    continue;
                };
                let rest = rest.trim_start();
                let (rest, paren) = match rest.strip_prefix('(') {
                    Some(r) => (r.trim_start(), true),
                    None => (rest, false),
                };
                let Some((_, url, tail)) = quoted_literal(rest) else {
                    continue;
                };
                let tail = tail.trim_start();
                let tail = if paren {
                    match tail.strip_prefix(')') {
                        Some(t) => t.trim_start(),
                        None => continue,
                    }
                } else {
                    tail
                };
                let tail = tail.split('#').next().unwrap_or_default().trim_end();
                if tail == "do" {
                    open = Some(url.to_string());
                }
            }
            Some(url) => {
                if line == "end" || line.starts_with("end ") || line.starts_with("end#") {
                    open = None;
                    continue;
                }
                if let Some(decl) = gem_declaration_any(line) {
                    out.push((url.clone(), decl.name.to_string()));
                }
            }
        }
    }
    out
}

/// Whether the bundler manifest text `gemfile` still routes a gem to patch
/// `uuid`'s registry: a `source "<…/patch-registry/gem/<token>/<uuid>>" do`
/// block ([`is_patch_registry_index`], host-agnostic) declaring `gem_name`
/// (any gem when `None`), read with the ONE Gemfile grammar
/// ([`parse_source_blocks`] — `#` and `=begin` … `=end` comments are not
/// wiring). Ledger liveness asks it for records whose host is outside the
/// discovery allowlist, so a commented-out block never keeps one alive.
pub(crate) fn gemfile_source_block_pins(gemfile: &str, uuid: &str, gem_name: Option<&str>) -> bool {
    parse_source_blocks(gemfile)
        .iter()
        .any(|(url, name)| gem_name.is_none_or(|g| g == name) && is_patch_registry_index(url, uuid))
}

/// Whether hosted `remote` is the patch's compact-index root:
/// `…/patch-registry/gem/<token>/<uuid>[/]`, `uuid` the LAST path level,
/// no query or fragment.
fn is_patch_registry_index(remote: &str, uuid: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(remote) else {
        return false;
    };
    if url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(segments) = url.path_segments() else {
        return false;
    };
    let segments: Vec<&str> = segments.filter(|s| !s.is_empty()).collect();
    matches!(
        segments.as_slice(),
        [.., "patch-registry", "gem", token, last] if *last == uuid && !token.is_empty()
    )
}

/// One lock file: every Socket-wired `GEM` (hosted) and `PATH` (vendored)
/// section, see the module docs.
fn extract_lock(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    lock: &GemfileLock<'_>,
    blocks: &[(String, String)],
    out: &mut Discovery,
) {
    if let Some(why) = lock.problems.first() {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file} is not a readable Bundler lockfile: {why}"),
        );
        return;
    }
    // Gem name -> the source sections locking it (a patched gem must be
    // locked by exactly one).
    let mut owners: HashMap<&str, BTreeSet<usize>> = HashMap::new();
    for (idx, sec) in lock.sections.iter().enumerate() {
        for spec in sec.specs.iter().filter_map(|s| s.parsed) {
            owners.entry(spec.name).or_default().insert(idx);
        }
    }
    for sec in &lock.sections {
        let wiring = match sec.header {
            "GEM" => hosted_wiring(ctx, file, lock, sec, blocks, out),
            "PATH" => vendored_wiring(file, sec, out),
            _ => None,
        };
        let Some(wiring) = wiring else {
            continue;
        };
        if sec.specs.is_empty() {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                file,
                format!(
                    "{file}: line {}: {} section for Socket patch {} locks no gems",
                    sec.line_no,
                    sec.header,
                    wiring.uuid()
                ),
            );
            continue;
        }
        for line in &sec.specs {
            if let Wiring::Hosted {
                only: Some(only), ..
            } = &wiring
            {
                // Merged section: only the gems source-pinned to the Socket
                // remote are its; the rest came from the other remotes.
                if !line.parsed.is_some_and(|s| only.contains(s.name)) {
                    continue;
                }
            }
            spec_ref(file, lock, &owners, line, &wiring, out);
        }
    }
}

/// What a Socket-wired source section resolves its specs to.
enum Wiring<'t> {
    /// `only`: in a merged multi-remote section, the gem names attributed
    /// to the Socket remote (`None` = the section's own single remote).
    Hosted {
        remote: &'t str,
        uuid: String,
        only: Option<BTreeSet<String>>,
    },
    Vendored(super::VendorRef),
}

impl Wiring<'_> {
    fn uuid(&self) -> &str {
        match self {
            Wiring::Hosted { uuid, .. } => uuid,
            Wiring::Vendored(vref) => &vref.uuid,
        }
    }
}

/// A `GEM` section's Socket-hosted wiring, or `None` (diagnosed when it is
/// Socket-shaped but unusable).
fn hosted_wiring<'t>(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    lock: &GemfileLock<'t>,
    sec: &Section<'t>,
    blocks: &[(String, String)],
    out: &mut Discovery,
) -> Option<Wiring<'t>> {
    for remote in sec.remotes.iter().filter(|r| names_vendor_dir(r)) {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: line {}: GEM remote {remote:?} names a vendored path; vendored gems \
                 are wired through a PATH section",
                sec.line_no
            ),
        );
    }
    let socket: Vec<(&'t str, String)> = sec
        .remotes
        .iter()
        .filter_map(|r| ctx.hosted_uuid(r).map(|uuid| (*r, uuid)))
        .collect();
    let socket_count = socket.len();
    let (remote, uuid) = socket.into_iter().next()?;
    let mut only = None;
    if sec.remotes.len() != 1 {
        // A merged section (module docs): attributable only per gem, through
        // the source pin, and only with a single Socket remote in it. A gem
        // the manifest ALSO declares in a block for another source is
        // ambiguous (the reader sees text, not which branch Ruby runs), so it
        // is not attributed to the Socket remote.
        let pinned: BTreeSet<String> =
            if socket_count == 1 && is_patch_registry_index(remote, &uuid) {
                blocks
                    .iter()
                    .filter(|(url, name)| {
                        same_remote(url, remote)
                            && lock.pinned.contains(name.as_str())
                            && blocks
                                .iter()
                                .all(|(u, n)| n != name || same_remote(u, remote))
                    })
                    .map(|(_, name)| name.clone())
                    .collect()
            } else {
                BTreeSet::new()
            };
        if pinned.is_empty() {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                file,
                format!(
                    "{file}: line {}: GEM section lists {} remotes (a merged multi-source \
                     lock), and no gem in it is source-pinned to Socket patch {uuid} ({remote}) \
                     by both DEPENDENCIES (`!`) and a {} `source … do` block, so its gems cannot \
                     be tied to the patch",
                    sec.line_no,
                    sec.remotes.len(),
                    bundler_manifest_for(file)
                ),
            );
            return None;
        }
        only = Some(pinned);
    }
    if !is_patch_registry_index(remote, &uuid) {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: line {}: GEM remote {remote:?} is on the Socket patch server but is not \
                 a patch-registry/gem/<token>/<uuid>/ index",
                sec.line_no
            ),
        );
        return None;
    }
    Some(Wiring::Hosted { remote, uuid, only })
}

/// A `PATH` section's vendored wiring, or `None` (diagnosed when it points
/// into `.socket/vendor/` but is not a usable gem artifact dir).
fn vendored_wiring<'t>(file: &str, sec: &Section<'t>, out: &mut Discovery) -> Option<Wiring<'t>> {
    let remote = *sec.remotes.iter().find(|r| names_vendor_dir(r))?;
    if sec.remotes.len() != 1 {
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            file,
            format!(
                "{file}: line {}: PATH section lists {} remotes, so its gems cannot be tied to \
                 the vendored dir {remote:?}",
                sec.line_no,
                sec.remotes.len()
            ),
        );
        return None;
    }
    match vendor_ref(remote).filter(|v| v.eco == "gem" && !v.leaf.contains('/')) {
        Some(vref) => Some(Wiring::Vendored(vref)),
        None => {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: line {}: PATH remote {remote:?} is not a \
                     .socket/vendor/gem/<uuid>/<name>-<version> dir inside the project",
                    sec.line_no
                ),
            );
            None
        }
    }
}

/// Validate one spec under a Socket-wired section and push its ref.
fn spec_ref(
    file: &str,
    lock: &GemfileLock<'_>,
    owners: &HashMap<&str, BTreeSet<usize>>,
    line: &SpecLine<'_>,
    wiring: &Wiring<'_>,
    out: &mut Discovery,
) {
    let uuid = wiring.uuid();
    let at = format!("{file}: line {}", line.line_no);
    let Some(spec) = line.parsed else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{at}: spec {:?} wired to Socket patch {uuid} is not a `name (version)` entry",
                line.raw
            ),
        );
        return;
    };
    if let Some(platform) = spec.platform {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{at}: {} {} is locked for platform {platform:?}; Socket patches wire only the \
                 ruby-platform gem",
                spec.name, spec.version
            ),
        );
        return;
    }
    if owners.get(spec.name).is_some_and(|o| o.len() > 1) {
        out.diag(
            DIAG_REF_UNATTRIBUTABLE,
            file,
            format!(
                "{at}: {} is locked by more than one source section, so Socket patch {uuid} \
                 cannot be tied to the gem bundler installs",
                spec.name
            ),
        );
        return;
    }
    let Some(purl) = simple_purl("gem", spec.name, spec.version) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{at}: spec {:?} wired to Socket patch {uuid} has unsafe coordinates",
                line.raw
            ),
        );
        return;
    };
    match wiring {
        Wiring::Hosted { remote, uuid, .. } => {
            out.push(PatchedRef::hosted(
                purl,
                uuid.clone(),
                file,
                Some(*remote),
                lock.integrity(spec.name, spec.version),
                lock.checksums.is_some(),
            ));
        }
        Wiring::Vendored(vref) => {
            let leaf = format!("{}-{}", spec.name, spec.version);
            if vref.leaf != leaf
                || vendored_leaf_purl("gem", &vref.leaf).as_deref() != Some(purl.as_str())
            {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{at}: {purl} is locked from {:?}, which is not that gem's vendored dir",
                        vref.artifact_rel
                    ),
                );
                return;
            }
            out.push(PatchedRef::vendored(purl, vref, file, None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{testing::*, *};

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    const SHA_A: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const SHA_UP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// `https://patch.socket.dev/patch-registry/gem/<TOKEN>/<uuid>/` — the
    /// production compact-index root (uuid-shaped grant token first).
    fn index(uuid: &str) -> String {
        format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/{uuid}/")
    }

    fn vendored_rel(uuid: &str, leaf: &str) -> String {
        format!(".socket/vendor/gem/{uuid}/{leaf}")
    }

    /// `is_patch_registry_index` reads URL path segments while the
    /// rewriter's `grant_token_path_segment` reads the raw string, and they
    /// disagree on an empty path level before the uuid — so the index check
    /// is its own rule, not the grant-token one.
    #[test]
    fn patch_registry_index_is_not_the_grant_token_rule() {
        let url = format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}//{UUID_A}/");
        assert!(super::is_patch_registry_index(&url, UUID_A));
        assert_eq!(
            crate::patch::redirect::grant_token_path_segment(&url, UUID_A),
            None
        );
    }

    fn only(out: &Discovery) -> &PatchedRef {
        assert_eq!(out.refs.len(), 1, "{:#?}", out.refs);
        &out.refs[0]
    }

    /// The committed golden fixture (the redirect engine's own output for a
    /// bundler 2.6 CHECKSUMS lock): the patch uuid, not the grant token, and
    /// the patched sha256 as the pin. The upstream `puma` is silent.
    #[tokio::test]
    async fn golden_hosted_fixture_yields_the_patch_uuid_and_its_pin() {
        let p = Project::new();
        p.copy_fixture("redirect/gem/bundler/basic/expected");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:gem/rails@7.0.0",
                "77777777-7777-7777-7777-777777777777",
                WiringMode::Hosted,
            )],
        );
        let r = only(&out);
        assert_eq!(r.source_file, std::path::PathBuf::from("Gemfile.lock"));
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA_A.to_string()))
        );
        assert!(r.integrity_required);
        assert!(r.lockfile_basis_ok());
        assert!(r
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://patch.socket.dev/patch-registry/gem/"));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The fixture's INPUT (pre-redirect) lock wires nothing.
    #[tokio::test]
    async fn registry_only_lock_discovers_nothing() {
        let p = Project::new();
        p.copy_fixture("redirect/gem/bundler/basic/input");
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// `vendor::gem`'s direct-dependency pair edit (bundler 2.5, no
    /// CHECKSUMS): PATH before GEM, bare relative remote, spec block moved
    /// with its dependency sublines, `(= v)!` pin.
    #[tokio::test]
    async fn vendored_path_section_bundler_2_5() {
        let rel = vendored_rel(UUID_A, "rack-3.2.6");
        let lock = format!(
            "PATH\n  remote: {rel}\n  specs:\n    rack (3.2.6)\n      base64 (>= 0.1.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\n\
             PLATFORMS\n  arm64-darwin-23\n  ruby\n\n\
             DEPENDENCIES\n  puma\n  rack (= 3.2.6)!\n\nBUNDLED WITH\n   2.5.22\n"
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:gem/rack@3.2.6", UUID_A, WiringMode::Vendored)],
        );
        let r = only(&out);
        assert_eq!(r.artifact_rel.as_deref(), Some(rel.as_str()));
        assert_eq!(r.locked_integrity, None);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// bundler 2.7 with `lockfile_checksums`: the path gem keeps a BARE
    /// CHECKSUMS entry; the transitive-gem shape leaves an empty GEM specs
    /// stanza behind. `./` and a trailing `/` on the remote are tolerated.
    #[tokio::test]
    async fn vendored_path_section_bundler_2_7_checksums() {
        let rel = vendored_rel(UUID_A, "rack-3.1.8");
        let lock = format!(
            "PATH\n  remote: ./{rel}/\n  specs:\n    rack (3.1.8)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             PLATFORMS\n  aarch64-linux\n  ruby\n\n\
             DEPENDENCIES\n  rack (= 3.1.8)!\n\nCHECKSUMS\n  rack (3.1.8)\n\nBUNDLED WITH\n   2.7.2\n"
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:gem/rack@3.1.8", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(only(&out).artifact_rel.as_deref(), Some(rel.as_str()));
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Several vendored gems (bundler sorts PATH sections by remote), a
    /// hyphenated gem name, a hosted section, and a CRLF checkout — all in
    /// one lock.
    #[tokio::test]
    async fn mixed_hosted_and_vendored_crlf_lock() {
        let lock = format!(
            "PATH\n  remote: {}\n  specs:\n    puma (6.4.2)\n      nio4r (~> 2.0)\n\n\
             PATH\n  remote: {}\n  specs:\n    rack-test (2.1.0)\n      rack (>= 1.3)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.6)\n\n\
             GEM\n  remote: {}\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  puma (= 6.4.2)!\n  rack-test (= 2.1.0)!\n  rails (= 7.0.0)!\n\n\
             CHECKSUMS\n  puma (6.4.2)\n  rack (3.2.6) sha256={SHA_UP}\n  rack-test (2.1.0)\n  \
             rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   2.6.2\n",
            vendored_rel(UUID_A, "puma-6.4.2"),
            vendored_rel(UUID_B, "rack-test-2.1.0"),
            index(UUID_B),
            SHA_A.to_ascii_uppercase(),
        )
        .replace('\n', "\r\n");
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:gem/puma@6.4.2", UUID_A, WiringMode::Vendored),
                ("pkg:gem/rack-test@2.1.0", UUID_B, WiringMode::Vendored),
                ("pkg:gem/rails@7.0.0", UUID_B, WiringMode::Hosted),
            ],
        );
        let hosted = out
            .refs
            .iter()
            .find(|r| r.mode == WiringMode::Hosted)
            .unwrap();
        assert_eq!(
            hosted.locked_integrity,
            Some(LockIntegrity::Sha256Hex(SHA_A.to_string())),
            "uppercase hex is normalized"
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// bundler < 2.6 has no CHECKSUMS: after the unfrozen install bundler
    /// writes the Socket GEM section itself with no pin, so the ref may use
    /// the lockfile basis. In the CHECKSUMS era a pin-less Socket spec is not
    /// Socket-written and may not.
    #[tokio::test]
    async fn pin_requirement_follows_the_checksums_era() {
        let pre = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n\n\
             GEM\n  remote: {}\n  specs:\n    rails (7.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma (= 6.0.0)\n  rails (= 7.0.0)!\n\n\
             BUNDLED WITH\n   2.4.22\n",
            index(UUID_A)
        );
        let p = Project::new();
        p.write("Gemfile.lock", &pre);
        let out = run(&p).await;
        let r = only(&out);
        assert_eq!(r.locked_integrity, None);
        assert!(!r.integrity_required);
        assert!(r.lockfile_basis_ok());

        let era = pre.replace(
            "BUNDLED WITH",
            &format!("CHECKSUMS\n  puma (6.0.0) sha256={SHA_UP}\n  rails (7.0.0)\n\nBUNDLED WITH"),
        );
        let p = Project::new();
        p.write("Gemfile.lock", era);
        let out = run(&p).await;
        let r = only(&out);
        assert_eq!(r.locked_integrity, None);
        assert!(r.integrity_required);
        assert!(!r.lockfile_basis_ok());
    }

    /// `gems.locked` (the `gems.rb` spelling the rewriter edits instead) is
    /// read, and so is a `Gemfile.lock` beside it — no precedence.
    #[tokio::test]
    async fn gems_locked_and_gemfile_lock_are_both_read() {
        let lock = |uuid: &str| {
            format!(
                "GEM\n  remote: {}\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n",
                index(uuid)
            )
        };
        let p = Project::new();
        p.write("gems.locked", lock(UUID_A));
        p.write("Gemfile.lock", lock(UUID_B));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:gem/rails@7.0.0", UUID_A, WiringMode::Hosted),
                ("pkg:gem/rails@7.0.0", UUID_B, WiringMode::Hosted),
            ],
        );
        let files: Vec<_> = out
            .refs
            .iter()
            .map(|r| (r.source_file.to_string_lossy().into_owned(), r.uuid.clone()))
            .collect();
        assert!(files.contains(&("gems.locked".into(), UUID_A.into())));
        assert!(files.contains(&("Gemfile.lock".into(), UUID_B.into())));
    }

    /// `--patch-server-url` deployments count (the e2e mock-server shape).
    #[tokio::test]
    async fn configured_patch_server_origin_is_accepted() {
        let lock = format!(
            "GEM\n  remote: http://127.0.0.1:4545/patch-registry/gem/tok/{UUID_A}/\n  specs:\n    \
             rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n"
        );
        let without = Project::new();
        without.write("Gemfile.lock", &lock);
        let out = run(&without).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
        let with = Project::new().with_origin("http://127.0.0.1:4545");
        with.write("Gemfile.lock", &lock);
        assert_refs(
            &run(&with).await,
            &[("pkg:gem/rails@7.0.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Non-Socket shapes are silent: a uuid-carrying remote on a foreign
    /// host, a placeholder token/uuid on the Socket host, GIT and PLUGIN
    /// sources, and a non-vendor PATH gem.
    #[tokio::test]
    async fn non_socket_sources_are_silent() {
        let lock = format!(
            "GIT\n  remote: https://patch.socket.dev/patch-registry/gem/{TOKEN}/{UUID_A}/\n  \
             revision: abc\n  specs:\n    a (1.0.0)\n\n\
             PATH\n  remote: vendor/local-gem\n  specs:\n    local-gem (0.1.0)\n\n\
             GEM\n  remote: https://evil.example/patch-registry/gem/{TOKEN}/{UUID_A}/\n  specs:\n    \
             b (1.0.0)\n\n\
             GEM\n  remote: https://patch.socket.dev/patch-registry/gem/tok/uuid/\n  specs:\n    \
             c (1.0.0)\n\n\
             DEPENDENCIES\n  a!\n  b\n  c\n  local-gem!\n"
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A uuid-SHAPED grant token with no patch-uuid level after it must not
    /// be read as a patch uuid; nor may an index with a query or a URL that
    /// is not a gem patch-registry root.
    #[tokio::test]
    async fn socket_remotes_that_are_not_a_patch_index_are_diagnosed() {
        for remote in [
            format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/"),
            format!(
                "https://patch.socket.dev/patch/gem/rails/7.0.0/{TOKEN}/{UUID_A}/rails-7.0.0.gem"
            ),
            format!("{}?x=1", index(UUID_A)),
            format!("https://patch.socket.dev/patch-registry/npm/{TOKEN}/{UUID_A}/"),
        ] {
            let p = Project::new();
            p.write(
                "Gemfile.lock",
                format!("GEM\n  remote: {remote}\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails\n"),
            );
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{remote}: {:#?}", out.refs);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{remote}");
        }
    }

    /// Socket-wired but unusable specs are DIAGNOSED, never attested.
    #[tokio::test]
    async fn invalid_socket_specs_are_diagnosed() {
        let lock = format!(
            "GEM\n  remote: {}\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n    \
             bad name (1.0.0)\n    ../x (1.0.0)\n    .. (1.0.0)\n    weird (abc)\n\n\
             PATH\n  remote: {}\n  specs:\n    rack (3.2.6)\n\n\
             PATH\n  remote: ../.socket/vendor/gem/{UUID_B}/puma-6.4.2\n  specs:\n    puma (6.4.2)\n\n\
             PATH\n  remote: .socket/vendor/gem/{UUID_B}/../../x-1.0.0\n  specs:\n    x (1.0.0)\n\n\
             PATH\n  remote: .socket/vendor/gem/{UUID_B}\n  specs:\n    y (1.0.0)\n\n\
             PATH\n  remote: .socket/vendor/npm/{UUID_B}/z-1.0.0\n  specs:\n    z (1.0.0)\n\n\
             DEPENDENCIES\n  nokogiri\n",
            index(UUID_A),
            vendored_rel(UUID_B, "minimist-1.2.5"),
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 10],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("Gemfile.lock")));
    }

    /// Ambiguous attributions: a legacy multi-remote GEM section, a patched
    /// gem ALSO locked by the upstream section, and a Socket section with no
    /// specs.
    #[tokio::test]
    async fn ambiguous_socket_sections_are_unattributable() {
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  remote: {}\n  specs:\n    a (1.0.0)\n\n\
             GEM\n  remote: https://gems.example/\n  specs:\n    rails (7.0.0)\n\n\
             GEM\n  remote: {}\n  specs:\n    rails (7.0.0)\n\n\
             GEM\n  remote: {}\n  specs:\n\n\
             DEPENDENCIES\n  a\n  rails\n",
            index(UUID_A),
            index(UUID_B),
            index("22222222-3333-4444-8555-666666666666"),
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_UNATTRIBUTABLE; 3],
            "{:#?}",
            out.diagnostics
        );
        // Unattributable, but RECOGNIZED: a redirect ledger record for any
        // of these patches is dead, not revived from the remotes' text.
        assert_eq!(out.hosted_claim("pkg:gem/a@1.0.0", UUID_A), Some(false));
        assert_eq!(out.hosted_claim("pkg:gem/rails@7.0.0", UUID_B), Some(false));
    }

    /// The bundler 1.17 / 2.0 / 2.1 lock after the prescribed unfrozen
    /// install over the rewriter's Gemfile source block (byte shape captured
    /// from real bundler 1.17.3 — e2e_redirect_gem_build): ONE merged GEM
    /// section with both remotes.
    fn merged_lock(remote: &str, pin: &str) -> String {
        format!(
            "GEM\n  remote: https://rubygems.org/\n  remote: {remote}\n  specs:\n    \
             tiny-dep (1.0.0)\n    vuln-gem (1.0.0)\n      tiny-dep\n\nPLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  vuln-gem (= 1.0.0){pin}\n\nBUNDLED WITH\n   1.17.3\n"
        )
    }

    fn block_gemfile(url: &str) -> String {
        format!(
            "source \"https://rubygems.org\"\n\nsource \"{url}\" do\n  gem \"vuln-gem\", \"1.0.0\"\nend\n"
        )
    }

    /// REGRESSION: a merged section (bundler <= 2.1) used to be flatly
    /// unattributable — and, being RECOGNIZED, it killed the redirect
    /// ledger's claim too, so a correctly patched bundler 1.17-2.1 project
    /// could not attest its hosted patch at all, ledger or not. The source
    /// pin (DEPENDENCIES `!` + the Gemfile block on that remote) attributes
    /// the gem; the upstream spec in the same section stays silent.
    #[tokio::test]
    async fn merged_section_source_pinned_gem_is_hosted() {
        for (lock, manifest) in [("Gemfile.lock", "Gemfile"), ("gems.locked", "gems.rb")] {
            let p = Project::new();
            p.write(lock, merged_lock(&index(UUID_A), "!"));
            p.write(manifest, block_gemfile(&index(UUID_A)));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[("pkg:gem/vuln-gem@1.0.0", UUID_A, WiringMode::Hosted)],
            );
            let r = only(&out);
            assert_eq!(r.source_file, std::path::PathBuf::from(lock));
            assert_eq!(r.locked_integrity, None);
            assert!(!r.integrity_required, "pre-2.6 locks never pin");
            assert!(out.diagnostics.is_empty(), "{lock}: {:?}", out.diagnostics);
            assert_eq!(
                out.hosted_claim("pkg:gem/vuln-gem@1.0.0", UUID_A),
                Some(true)
            );
        }
        // The trailing slash is bundler's normalization, not evidence.
        let p = Project::new();
        p.write("Gemfile.lock", merged_lock(&index(UUID_A), "!"));
        p.write(
            "Gemfile",
            block_gemfile(index(UUID_A).trim_end_matches('/')),
        );
        assert_eq!(run(&p).await.refs.len(), 1);
    }

    /// Each half of the source pin is required, the block must name THIS
    /// remote, and a merged section with two Socket remotes stays ambiguous.
    #[tokio::test]
    async fn merged_section_without_a_full_source_pin_is_unattributable() {
        let other = index(UUID_B);
        let cases: Vec<(&str, String, Option<String>)> = vec![
            (
                "no DEPENDENCIES pin",
                merged_lock(&index(UUID_A), ""),
                Some(block_gemfile(&index(UUID_A))),
            ),
            ("no Gemfile", merged_lock(&index(UUID_A), "!"), None),
            (
                "gem outside the block",
                merged_lock(&index(UUID_A), "!"),
                Some(format!(
                    "source \"{}\" do\nend\ngem \"vuln-gem\", \"1.0.0\"\n",
                    index(UUID_A)
                )),
            ),
            (
                "block on another remote",
                merged_lock(&index(UUID_A), "!"),
                Some(block_gemfile(&other)),
            ),
            (
                "commented-out block",
                merged_lock(&index(UUID_A), "!"),
                Some(
                    block_gemfile(&index(UUID_A))
                        .replace("source \"https://patch", "# source \"https://patch"),
                ),
            ),
            (
                "two Socket remotes",
                merged_lock(&index(UUID_A), "!")
                    .replace("  specs:\n", &format!("  remote: {other}\n  specs:\n")),
                Some(block_gemfile(&index(UUID_A))),
            ),
        ];
        for (case, lock, gemfile) in cases {
            let p = Project::new();
            p.write("Gemfile.lock", lock);
            if let Some(g) = gemfile {
                p.write("Gemfile", g);
            }
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{case}: {:#?}", out.refs);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_REF_UNATTRIBUTABLE],
                "{case}: {:#?}",
                out.diagnostics
            );
        }
    }

    /// The Gemfile is read only to cross-check a merged Socket section, so a
    /// Gemfile-only wiring (the pre-2.6 mixed pair, lock not merged) is never
    /// recognized: it stays a ledger-fallback decision, not a discovery
    /// verdict.
    #[tokio::test]
    async fn gemfile_only_wiring_is_not_recognized() {
        let p = Project::new();
        p.write(
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    vuln-gem (1.0.0)\n\n\
             DEPENDENCIES\n  vuln-gem (= 1.0.0)\n",
        );
        p.write("Gemfile", block_gemfile(&index(UUID_A)));
        let out = run(&p).await;
        assert!(
            out.refs.is_empty() && out.diagnostics.is_empty(),
            "{out:#?}"
        );
        assert_eq!(out.hosted_claim("pkg:gem/vuln-gem@1.0.0", UUID_A), None);
    }

    /// The Gemfile cross-check reads text, not Ruby: a Socket `source … do`
    /// block inside a `=begin` / `=end` comment declares nothing, and a gem
    /// the manifest declares in a Socket block AND a block for another
    /// source is ambiguous — neither may attribute the merged section's spec
    /// to the Socket patch.
    #[tokio::test]
    async fn merged_section_ignores_block_comments_and_ambiguous_declarations() {
        let socket = index(UUID_A);
        let evil = "https://gems.evil.example";
        let three_remotes = merged_lock(&socket, "!")
            .replace("  specs:\n", &format!("  remote: {evil}/\n  specs:\n"));
        let socket_block = format!("source \"{socket}\" do\n  gem \"vuln-gem\", \"1.0.0\"\nend\n");
        let evil_block = format!("source \"{evil}\" do\n  gem \"vuln-gem\"\nend\n");
        for gemfile in [
            format!("source \"https://rubygems.org\"\n=begin\n{socket_block}=end\n{evil_block}"),
            format!("source \"https://rubygems.org\"\n{socket_block}{evil_block}"),
        ] {
            let p = Project::new();
            p.write("Gemfile.lock", &three_remotes);
            p.write("Gemfile", &gemfile);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_REF_UNATTRIBUTABLE],
                "{gemfile}\n{:?}",
                out.diagnostics
            );
            assert_eq!(
                out.hosted_claim("pkg:gem/vuln-gem@1.0.0", UUID_A),
                Some(false)
            );
        }
    }

    /// A non-`gem` line inside the Socket `source … do` block (a blank line,
    /// an assignment) is skipped, and a malformed `CHECKSUMS` entry (text
    /// after the `)`, an empty version) pins nothing — so the CHECKSUMS-era
    /// hosted ref carries no locked integrity.
    #[tokio::test]
    async fn merged_section_skips_non_gem_block_lines_and_malformed_checksums() {
        let sha = "a".repeat(64);
        let lock = merged_lock(&index(UUID_A), "!").replace(
            "BUNDLED WITH",
            &format!(
                "CHECKSUMS\n  vuln-gem (1.0.0)x sha256={sha}\n  tiny-dep () sha256={sha}\n\n\
                 BUNDLED WITH"
            ),
        );
        let gemfile = format!(
            "source \"https://rubygems.org\"\n\nsource \"{}\" do\n\n  ruby_version = \"3\"\n  \
             gem \"vuln-gem\", \"1.0.0\"\nend\n",
            index(UUID_A)
        );
        let p = Project::new();
        p.write("Gemfile.lock", lock);
        p.write("Gemfile", gemfile);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:gem/vuln-gem@1.0.0", UUID_A, WiringMode::Hosted)],
        );
        let r = only(&out);
        assert_eq!(r.locked_integrity, None);
        assert!(r.integrity_required, "the lock has a CHECKSUMS section");
    }

    #[test]
    fn source_block_grammar() {
        let got = super::parse_source_blocks(
            "source 'https://rubygems.org'\n\
             gem 'rake'\n\
             source \"https://a.example/\" do # patched\n\
             \tgem \"one\", \"1.0\"\n\
             \tgem('two', '2.0')\n\
             \tgemspec\n\
             \t# gem \"commented\"\n\
             end\n\
             source('https://b.example/') do\n  gem 'three'\nend # b\n\
             source \"https://c.example/\" do |s|\n  gem 'nope'\nend\n\
             =begin\n\
             source \"https://d.example/\" do\n  gem 'ghost'\nend\n\
             =end\n\
             =beginning is not a marker\n\
             gem 'after'\n",
        );
        let got: Vec<(&str, &str)> = got.iter().map(|(u, g)| (u.as_str(), g.as_str())).collect();
        assert_eq!(
            got,
            [
                ("https://a.example/", "one"),
                ("https://a.example/", "two"),
                ("https://b.example/", "three"),
            ]
        );
    }

    #[tokio::test]
    async fn malformed_locks_are_diagnosed_not_fatal() {
        for text in [
            "not a lockfile at all\n".to_string(),
            "  remote: https://rubygems.org/\nGEM\n".to_string(),
            format!(
                "<<<<<<< HEAD\nGEM\n  remote: {}\n  specs:\n    rails (7.0.0)\n=======\n>>>>>>> x\n",
                index(UUID_A)
            ),
        ] {
            let p = Project::new();
            p.write("Gemfile.lock", &text);
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{text:?}: {:#?}", out.refs);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text:?}");
        }
        // Empty lock and non-UTF-8 bytes: fail soft too.
        let p = Project::new();
        p.write("Gemfile.lock", "");
        assert_eq!(diag_codes(&run(&p).await), vec![DIAG_LOCKFILE_UNPARSEABLE]);
        let p = Project::new();
        p.write("gems.locked", [0xff, 0xfe, 0x00, b'G']);
        let out = run(&p).await;
        assert!(out.refs.is_empty());
        assert_eq!(out.diagnostics.len(), 1, "{:?}", out.diagnostics);
    }

    /// A FIFO squatting the lock name fails fast instead of wedging.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_is_unreadable_not_a_hang() {
        let p = Project::new();
        let path = p.root().join("Gemfile.lock");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    /// Through the full orchestrator: the gem ref comes out of discovery.
    #[tokio::test]
    async fn orchestrator_includes_gem_refs() {
        let p = Project::new();
        p.copy_fixture("redirect/gem/bundler/basic/expected");
        let out = p.discover().await;
        assert!(out.wires(
            "pkg:gem/rails@7.0.0",
            "77777777-7777-7777-7777-777777777777",
            WiringMode::Hosted
        ));
    }
}
