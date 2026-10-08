//! Which hosted candidates a vendored → hosted mode takeover covers.
//!
//! One predicate for both hosted engines: the disk flow (`scan --mode
//! hosted`) reverts the vendored wiring of exactly these purls before it
//! pins them, and the in-memory engine, which performs no takeover, refuses
//! exactly these purls instead. Keeping the two lists in one place stops them
//! drifting apart.

use crate::vendor::VendorEntry;

/// The ecosystems whose hosted rewriters cannot pin a purl that is still
/// vendored, so a takeover must revert the vendored wiring first:
///
/// * cargo: `--locked` builds refuse over the unused `[patch]` entry;
/// * npm: yarn classic would hijack a resolution the vendored ledger still
///   claims, and yarn berry refuses `file:` outright;
/// * golang: the vendor-owned go.mod `replace` shadows the hosted one;
/// * pypi: every Python rewriter refuses a non-registry source, including
///   the vendored one socket-patch wrote itself (#328);
/// * maven: only a Gradle build's vendored JVM entry (see
///   [`is_gradle_jvm_entry`]); a pom-only vendored entry stays.
fn takeover_ecosystem(purl: &str) -> bool {
    [
        "pkg:cargo/",
        "pkg:npm/",
        "pkg:golang/",
        "pkg:pypi/",
        "pkg:maven/",
    ]
    .iter()
    .any(|prefix| purl.starts_with(prefix))
}

/// Whether any of `purls` could be taken over (a cheap pre-check before the
/// vendored ledger is consulted).
pub fn any_takeover_ecosystem<'a>(mut purls: impl Iterator<Item = &'a str>) -> bool {
    purls.any(takeover_ecosystem)
}

/// A vendored JVM entry wired into a Gradle build (its revert unplans the
/// vendored Gradle wiring), as opposed to a pom-only entry.
pub fn is_gradle_jvm_entry(entry: &VendorEntry) -> bool {
    entry.ecosystem == crate::vendor::jvm::layout::LEDGER_ECOSYSTEM
        && entry.wiring.iter().any(|w| {
            w.file.ends_with(".gradle")
                || w.file.ends_with(".gradle.kts")
                || w.file == crate::vendor::jvm::gradle::INDEX_REL
        })
}

/// Whether the hosted candidate `purl`, with its vendored ledger entry (if
/// any), is in a takeover's reach. A purl with no entry is in reach for the
/// ecosystems whose vendored wiring can exist without one (a cargo
/// `[patch.crates-io]` entry whose ledger was lost); the callers probe that
/// wiring themselves.
pub fn in_reach(purl: &str, entry: Option<&VendorEntry>) -> bool {
    if !takeover_ecosystem(purl) {
        return false;
    }
    !purl.starts_with("pkg:maven/") || entry.is_some_and(is_gradle_jvm_entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ecosystem: &str, files: &[&str]) -> VendorEntry {
        let wiring: Vec<serde_json::Value> = files
            .iter()
            .map(|f| serde_json::json!({ "file": f, "kind": "k", "action": "rewritten" }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "ecosystem": ecosystem,
            "basePurl": "pkg:maven/g/a@1",
            "uuid": "00000000-0000-4000-8000-000000000000",
            "artifact": { "path": ".socket/vendor/jvm/x" },
            "wiring": wiring,
        }))
        .expect("a minimal ledger entry")
    }

    #[test]
    fn the_takeover_ecosystems_are_in_reach() {
        for purl in [
            "pkg:cargo/a@1",
            "pkg:npm/a@1",
            "pkg:golang/a@v1",
            "pkg:pypi/a@1",
        ] {
            assert!(in_reach(purl, None), "{purl}");
        }
        for purl in ["pkg:gem/a@1", "pkg:composer/a/b@1", "pkg:nuget/a@1"] {
            assert!(!in_reach(purl, None), "{purl}");
        }
    }

    #[test]
    fn maven_is_in_reach_only_through_a_gradle_entry() {
        let purl = "pkg:maven/g/a@1";
        assert!(!in_reach(purl, None));
        assert!(!in_reach(purl, Some(&entry("jvm", &["pom.xml"]))));
        assert!(in_reach(purl, Some(&entry("jvm", &["build.gradle.kts"]))));
        assert!(in_reach(
            purl,
            Some(&entry("jvm", &[crate::vendor::jvm::gradle::INDEX_REL]))
        ));
    }
}
