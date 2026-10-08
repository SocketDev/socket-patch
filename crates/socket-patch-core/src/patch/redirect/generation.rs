//! Owned-pin generations: the supersede policy the hosted writers and
//! restores share (audit B07), and the one home of the `socket-patch-<uuid>`
//! name grammar.
//!
//! A package release (ecosystem, name, version) has at most ONE live
//! socket-owned pin. The patch uuid it carries is that pin's generation: a
//! superseding patch, or the same patch republished, is a new generation of
//! the same pin, never a second pin beside it. So:
//!
//! - a hosted re-pin (cargo, Go, Maven) replaces the previous generation in
//!   place, and drops every piece of wiring only that generation used (a
//!   cargo `[registries.…]` block, a Go module's go.sum pair, a Maven
//!   `<repository>` and its trusted checksums), the way a fresh pin would
//!   never have written it;
//! - the cargo restore (`remove` / `rollback`) also unwinds every
//!   `[registries.socket-patch-<uuid>]` block nothing references any more,
//!   including residue an older CLI left behind on re-pin. The Go and Maven
//!   restores remove only the selected pins' wiring: residue an older CLI
//!   left there (an old socket module's go.sum pair, a superseded
//!   repository) is not swept yet;
//! - matching a remove/rollback identifier across the stores treats a
//!   manifest record, the vendored entry it claims and the hosted pin of the
//!   same release as one owned pin ([`crate::ledgers::Ledgers::matching`],
//!   [`crate::ledgers::hosted_pins_matching`]).
//!
//! Hosted writers name a generation's wiring `socket-patch-<uuid>` (a cargo
//! registry, a Maven repository id, a NuGet source key). Vendored NuGet uses
//! the same `socket-patch-<uuid>` source key for its local feed; vendored
//! Maven's `socket-patch-vendor-<uuid>` repository id is a different grammar
//! ([`pin_name_uuid`] with `vendored`), which [`named_generations`] never
//! matches.

use std::collections::BTreeSet;

use crate::patch::path_safety::is_canonical_uuid;

/// The prefix every Socket-owned registry / repository / source name
/// carries: `socket-patch-<uuid>`.
pub(crate) const PIN_NAME_PREFIX: &str = "socket-patch-";

/// The prefix of vendored Maven's repository id: `socket-patch-vendor-<uuid>`.
const VENDOR_PIN_NAME_PREFIX: &str = "socket-patch-vendor-";

/// The name hosted mode gives a generation's wiring: `socket-patch-<uuid>`.
pub(crate) fn hosted_pin_name(uuid: &str) -> String {
    format!("{PIN_NAME_PREFIX}{uuid}")
}

/// The uuid of a Socket-owned registry / repository / source NAME in its
/// EXACT grammar: `socket-patch-<canonical-uuid>`, or with `vendored`
/// `socket-patch-vendor-<canonical-uuid>` (maven's vendored repository id).
/// No trimming: the rewriter must never treat a user's padded pin as its
/// own, while lockfile discovery trims at its call site
/// (`vex::discover::socket_patch_name_uuid`).
pub(crate) fn pin_name_uuid(name: &str, vendored: bool) -> Option<&str> {
    let prefix = if vendored {
        VENDOR_PIN_NAME_PREFIX
    } else {
        PIN_NAME_PREFIX
    };
    name.strip_prefix(prefix)
        .filter(|uuid| is_canonical_uuid(uuid))
}

/// Every generation (patch uuid) `text` names as `socket-patch-<uuid>`, in
/// any position (a `registry = "…"` value, an `<id>`, a section header). A
/// comment that names one counts too, which only ever keeps wiring alive.
pub(crate) fn named_generations(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find(PIN_NAME_PREFIX) {
        let tail = &rest[at + PIN_NAME_PREFIX.len()..];
        if let Some(uuid) = tail.get(..36).filter(|u| is_canonical_uuid(u)) {
            // A longer token (`…-<uuid>x`) is not this grammar.
            let boundary = tail[36..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            if boundary {
                out.insert(uuid.to_string());
            }
        }
        rest = tail;
    }
    out
}

/// The generations the `before` texts name that the `after` texts no longer
/// do: this run moved their pins to another generation, so the wiring only
/// they used is the re-pin's to drop.
pub(crate) fn superseded_generations<'a>(
    before: impl IntoIterator<Item = &'a str>,
    after: impl IntoIterator<Item = &'a str>,
) -> BTreeSet<String> {
    let after: BTreeSet<String> = after.into_iter().flat_map(named_generations).collect();
    before
        .into_iter()
        .flat_map(named_generations)
        .filter(|uuid| !after.contains(uuid))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";

    #[test]
    fn names_only_canonical_hosted_generations() {
        let text = format!(
            "x = {{ registry = \"socket-patch-{A}\" }}\n\
             [registries.socket-patch-vendor-{B}]\n\
             <id>socket-patch-{B}x</id>\n\
             socket-patch-not-a-uuid\n"
        );
        assert_eq!(named_generations(&text), BTreeSet::from([A.to_string()]));
        assert_eq!(hosted_pin_name(A), format!("socket-patch-{A}"));
    }

    #[test]
    fn pin_name_uuid_is_exact() {
        assert_eq!(pin_name_uuid(&hosted_pin_name(A), false), Some(A));
        assert_eq!(
            pin_name_uuid(&format!("socket-patch-vendor-{A}"), true),
            Some(A)
        );
        assert_eq!(
            pin_name_uuid(&format!("socket-patch-vendor-{A}"), false),
            None
        );
        assert_eq!(pin_name_uuid(&format!(" socket-patch-{A}"), false), None);
        assert_eq!(pin_name_uuid(&format!("socket-patch-{A}x"), false), None);
    }

    #[test]
    fn superseded_is_named_before_and_not_after() {
        let before = format!("registry = \"socket-patch-{A}\"");
        let after = format!("registry = \"socket-patch-{B}\"");
        assert_eq!(
            superseded_generations([before.as_str()], [after.as_str()]),
            BTreeSet::from([A.to_string()])
        );
        // Still named by any after-text: not superseded.
        assert!(
            superseded_generations([before.as_str()], [after.as_str(), before.as_str()]).is_empty()
        );
    }
}
