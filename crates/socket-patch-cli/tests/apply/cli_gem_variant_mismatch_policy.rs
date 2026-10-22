//! Mismatch-policy contract for release-variant (gem) packages.
//!
//! For npm, a locally-modified file is handled by the explicitly approved
//! mismatch policy: warn + apply the full verified patched content,
//! `--strict` refuses, `--force` also skips missing files (see
//! `apply_network.rs::apply_hash_mismatch_opt_in_warns_and_applies_strict_fails`).
//! Release-variant ecosystems (gem/pypi/maven) route through the variant
//! loop instead, whose installed-distribution gate must still let the
//! opt-in policy reach an UNQUALIFIED SINGLETON base (one bare manifest
//! record for the `package@version`, the common case) with a
//! locally-modified file: warn-overwrite, not "no matching variant found".
//!
//! Behaviors pinned (all offline, real binary, synthetic gem trees):
//!   * unqualified singleton + locally-modified file: opted-in apply warns
//!     (`content_mismatch_overwritten`) AND applies the full afterHash
//!     bytes; `--strict` refuses (file untouched, exit 1); `--force`
//!     keeps applying as before.
//!   * QUALIFIED singleton (`?platform=`…): UNCHANGED — it names one
//!     specific distribution and the representative-hash gate is the only
//!     platform resolution (the crawler drops the gem dir's platform
//!     suffix), so a wrong-platform install still fails closed with
//!     "no matching variant found" and the file stays untouched.
//!   * multi-variant base: UNCHANGED — only the installed variant is
//!     applied; the mismatched sibling is skipped, never warn-overwritten
//!     (a sibling mismatch means "different distribution", not "locally
//!     modified"). When NO variant matches, the base still fails with
//!     "no matching variant found" and the file stays untouched.
//!
//! Behavior is asserted through the `--json` envelope (exit code,
//! `status`, event actions and `errorCode`s) and the bytes on disk. The
//! human wording of each case lives in `apply_render.rs` (#1089); both
//! files share the fixtures in `apply_fixture.rs`. In `--json` a no-matching-variant miss
//! shows as exit 1 with `status: partialFailure` and no `applied` or
//! `failed` event for the base.

use crate::apply_fixture::{
    gem_multi_variant_fixture, gem_singleton_mismatch_fixture, gem_wrong_platform_fixture,
    nokogiri_purl, run_gem_apply, GEM_BASE_PURL, GEM_LOCAL, NOKOGIRI_DARWIN_BEFORE,
    NOKOGIRI_DARWIN_MARKER, NOKOGIRI_LINUX_PRISTINE,
};
use crate::common::envelope::{
    assert_envelope_invariants, event_codes, event_purls, find_event, has_event,
    parse_json_envelope,
};
use crate::common::git_sha256;

/// The per-file warning code of a default-policy overwrite.
const OVERWRITTEN: &str = "content_mismatch_overwritten";

/// Default policy: the singleton's local modification is overwritten with
/// the full verified patched content and surfaced as a warning — the same
/// npm contract, not "no matching variant found" with the file untouched.
#[test]
fn singleton_mismatch_opt_in_warns_and_applies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, patched) = gem_singleton_mismatch_fixture(tmp.path());

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--json", "--allow-patch-conflicts"]);
    assert_eq!(
        code, 0,
        "opted-in mismatch on a singleton variant is a warning, not an error; stdout={stdout}"
    );
    assert_eq!(
        std::fs::read(&file).expect("read patched file"),
        patched,
        "the file must carry exactly the verified patched bytes"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(
        event_purls(&v, "applied"),
        [GEM_BASE_PURL],
        "singleton must be reported applied: {v:#}"
    );
    // The overwrite rides as the npm-family per-file warning event, the
    // same shape apply_network pins for npm, naming the package.
    assert!(
        has_event(&v, "skipped", OVERWRITTEN, GEM_BASE_PURL),
        "the overwrite must ride as a warning event: {v:#}"
    );
}

/// `--strict` restores the fail-closed contract for the singleton: exit 1
/// with the per-file hash-mismatch error and the file byte-identical.
#[test]
fn singleton_mismatch_strict_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, _patched) = gem_singleton_mismatch_fixture(tmp.path());

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--strict", "--json"]);
    assert_eq!(
        code, 1,
        "--strict must refuse the mismatch; stdout={stdout}"
    );
    assert_eq!(
        std::fs::read(&file).expect("read file"),
        GEM_LOCAL,
        "--strict must not modify the file"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    // The package fails on the per-file hash refusal (`apply_failed`),
    // not the no-matching-variant miss, which reports no `failed` event.
    let failed = find_event(&v, "failed", Some("apply_failed"));
    assert_eq!(failed["purl"], GEM_BASE_PURL, "{v:#}");
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|e| e.contains("lib/rack.rb")),
        "the refusal must name the mismatched file: {v:#}"
    );
    assert!(
        !event_codes(&v).iter().any(|c| c == OVERWRITTEN),
        "--strict must not claim an overwrite happened: {v:#}"
    );
}

/// `--force` behavior is unchanged by the singleton fall-through: it
/// bypassed the gate before and still applies the full patched bytes.
#[test]
fn singleton_mismatch_force_still_applies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, patched) = gem_singleton_mismatch_fixture(tmp.path());

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--force", "--json"]);
    assert_eq!(code, 0, "--force must keep applying; stdout={stdout}");
    assert_eq!(
        std::fs::read(&file).expect("read patched file"),
        patched,
        "--force must overwrite with the verified patched bytes"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(event_purls(&v, "applied"), [GEM_BASE_PURL], "{v:#}");
    assert!(
        has_event(&v, "skipped", OVERWRITTEN, GEM_BASE_PURL),
        "{v:#}"
    );
}

/// A QUALIFIED singleton keeps the fail-closed gate: a lone
/// `?platform=x86_64-linux` record names one specific distribution, and
/// the representative-hash check is the ONLY thing resolving whether that
/// distribution is the one on disk (the crawler drops the gem dir's
/// platform suffix). With an arm64-darwin gem installed, the default
/// apply must NOT overwrite it with the linux variant's bytes — the
/// Bundler plugin auto-applies with `--silent`, where the warn half of
/// warn-and-apply is invisible, and a later rollback would restore the
/// LINUX before-bytes onto the darwin install. It fails exactly like a
/// multi-variant base with no matching variant.
#[test]
fn qualified_singleton_wrong_platform_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = gem_wrong_platform_fixture(tmp.path());

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--json"]);
    assert_eq!(
        code, 1,
        "a qualified singleton whose distribution is not on disk must fail closed; stdout={stdout}"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    assert!(event_purls(&v, "applied").is_empty(), "{v:#}");
    // No variant was attempted, so no `failed` event either: that tells
    // this miss apart from a variant that was tried and refused.
    assert!(event_purls(&v, "failed").is_empty(), "{v:#}");
    assert!(
        !event_codes(&v).iter().any(|c| c == OVERWRITTEN),
        "a wrong-distribution record must never be surfaced as a \
         local-modification overwrite: {v:#}"
    );
    assert_eq!(
        std::fs::read(&file).expect("read file"),
        NOKOGIRI_DARWIN_BEFORE,
        "the installed distribution's bytes must be untouched"
    );
}

/// Over-broadening guard: a MULTI-variant base keeps the current
/// behavior. The installed variant applies; the mismatched sibling means
/// "different distribution" and is skipped — its bytes must never be
/// warn-overwritten onto the installed gem, and no mismatch warning may
/// fire.
#[test]
fn multi_variant_mismatched_sibling_is_skipped_not_overwritten() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, linux_patched, _darwin_patched) =
        gem_multi_variant_fixture(tmp.path(), NOKOGIRI_LINUX_PRISTINE);

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--json"]);
    assert_eq!(
        code, 0,
        "the installed variant must apply cleanly; stdout={stdout}"
    );
    let after = std::fs::read(&file).expect("read patched file");
    assert_eq!(
        after, linux_patched,
        "the file must carry exactly the installed platform's patched bytes"
    );
    assert!(
        !after
            .windows(NOKOGIRI_DARWIN_MARKER.len())
            .any(|w| w == NOKOGIRI_DARWIN_MARKER),
        "the sibling distribution's bytes must never be written"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(
        event_purls(&v, "applied"),
        [nokogiri_purl("x86_64-linux")],
        "{v:#}"
    );
    assert!(
        !event_codes(&v).iter().any(|c| c == OVERWRITTEN),
        "a sibling-variant mismatch is a skip, not an overwrite warning: {v:#}"
    );
}

/// Second guard: when NO variant of a multi-variant base matches the
/// on-disk bytes (locally-modified file), the base still fails with the
/// no-matching-variant error and the file stays untouched — the
/// mismatch-policy fall-through is singleton-only.
#[test]
fn multi_variant_none_matching_still_fails_closed() {
    let local = [NOKOGIRI_LINUX_PRISTINE, b"# local tweak\n"].concat();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (file, linux_patched, darwin_patched) = gem_multi_variant_fixture(tmp.path(), &local);
    assert_ne!(git_sha256(&local), git_sha256(NOKOGIRI_LINUX_PRISTINE));
    assert_ne!(git_sha256(&local), git_sha256(NOKOGIRI_DARWIN_BEFORE));

    let (code, stdout, _stderr) = run_gem_apply(tmp.path(), &["--json"]);
    assert_eq!(
        code, 1,
        "a multi-variant base with no matching variant must keep failing; stdout={stdout}"
    );
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "apply");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    assert!(event_purls(&v, "applied").is_empty(), "{v:#}");
    // No variant was attempted, so no `failed` event either: that tells
    // this miss apart from a variant that was tried and refused.
    assert!(event_purls(&v, "failed").is_empty(), "{v:#}");
    assert!(!event_codes(&v).iter().any(|c| c == OVERWRITTEN), "{v:#}");
    let after = std::fs::read(&file).expect("read file");
    assert_eq!(
        after, local,
        "no variant matched, so nothing may be written"
    );
    assert_ne!(after, linux_patched);
    assert_ne!(after, darwin_patched);
}
