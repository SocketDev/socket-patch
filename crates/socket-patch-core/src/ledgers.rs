//! The project's patch stores read as one view: the agent manifest
//! (`.socket/manifest.json`), the vendored ledger
//! (`.socket/vendor/state.json`) and the hosted records. v5 hosted mode
//! keeps no ledger, so the hosted records are the lockfiles' hosted pins
//! (shaped as uuid-only records) or a run's fetched records, plus a pre-v5
//! redirect ledger (`.socket/vendor/redirect-state.json`) read, never
//! written, for migration.
//!
//! One owner-precedence rule decides which store owns a purl every reader
//! merges ([`Ledgers::owned`], [`Ledgers::listed`], [`Ledgers::matching`]):
//!
//! 1. A manifest key is owned by the manifest. It claims every vendored
//!    entry filed under that key or whose `base_purl` it names; a claimed
//!    entry's embedded record is a fallback copy. The group's vendored
//!    entry is the one filed under the key, else the lowest-keyed entry
//!    naming it as `base_purl` (so `HashMap` order never decides).
//! 2. Every unclaimed vendored entry owns its ledger key.
//! 3. A hosted record owns its key when neither of the above does.
//!
//! So: manifest > vendored > hosted, by ledger key. The losing copies stay
//! reachable as alternates ([`Owned::alts`]) for readers that decide by
//! lockfile evidence (`vex`). The hosted records only ever join as the
//! last store.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::manifest::schema::{PatchManifest, PatchRecord};
use crate::patch::redirect::{CorruptRedirectState, RedirectState};
use crate::utils::purl::{canonical_purl, patch_matches};
use crate::vendor::{VendorEntry, VendorState};

/// A patch store, in owner-precedence order (a lower store wins a key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Store {
    /// `.socket/manifest.json` (agent mode).
    Manifest,
    /// `.socket/vendor/state.json` (vendored mode).
    Vendored,
    /// The hosted records (lockfile pins, a run's fetched records, or a
    /// pre-v5 redirect ledger read for migration).
    Hosted,
}

/// The three stores as loaded, each with its own outcome so every caller
/// keeps its error posture (strict, lenient, per-leg).
pub struct LoadedLedgers {
    /// `Ok(None)`: absent; `Err(InvalidData)`: unparseable; other `Err`: I/O.
    pub manifest: std::io::Result<Option<PatchManifest>>,
    /// Absent is `Ok(empty)`; `Err` is unreadable or malformed.
    pub vendor: std::io::Result<VendorState>,
    /// The pre-v5 redirect ledger, read only (absent is `Ok(None)`).
    pub redirect: Result<Option<RedirectState>, CorruptRedirectState>,
}

impl LoadedLedgers {
    /// Load the manifest at `manifest_path`, the vendored ledger and any
    /// pre-v5 redirect ledger of `project_root`, concurrently.
    pub async fn load(project_root: &Path, manifest_path: &Path) -> Self {
        let (manifest, vendor, redirect) = tokio::join!(
            crate::manifest::operations::read_manifest(manifest_path),
            crate::vendor::load_state(project_root),
            crate::patch::redirect::load_redirect_state(project_root),
        );
        Self {
            manifest,
            vendor,
            redirect,
        }
    }

    /// The readable stores (a failed store reads as absent).
    pub fn view(&self) -> Ledgers<'_> {
        Ledgers {
            manifest: self.manifest.as_ref().ok().and_then(Option::as_ref),
            vendor: self.vendor.as_ref().ok(),
            redirect: self.redirect.as_ref().ok().and_then(Option::as_ref),
        }
    }
}

/// A borrowed view over whichever stores a caller has.
#[derive(Clone, Copy, Default)]
pub struct Ledgers<'a> {
    pub manifest: Option<&'a PatchManifest>,
    pub vendor: Option<&'a VendorState>,
    pub redirect: Option<&'a RedirectState>,
}

/// One owner key with the store that owns it and every copy under it.
#[derive(Debug, Clone)]
pub struct Owned<'a> {
    pub key: &'a str,
    pub store: Store,
    pub uuid: &'a str,
    /// The owner's record; `None` for a legacy vendored entry that embeds
    /// none.
    pub record: Option<&'a PatchRecord>,
    /// The vendored entry in this group (the owner itself, or the one the
    /// manifest key claimed), with its ledger key.
    pub vendor: Option<(&'a str, &'a VendorEntry)>,
    /// Whether the hosted records hold one under this key.
    pub hosted: bool,
    /// The losing copies' records, in precedence order.
    pub alts: Vec<&'a PatchRecord>,
}

/// One copy [`Ledgers::listed`] shows.
#[derive(Debug, Clone, Copy)]
pub struct Listed<'a> {
    pub key: &'a str,
    pub record: &'a PatchRecord,
    pub store: Store,
}

/// Every store's entries a remove/rollback identifier matches, each sorted
/// by key.
#[derive(Debug, Clone, Default)]
pub struct Matches {
    pub manifest: Vec<String>,
    pub vendor: Vec<(String, VendorEntry)>,
    pub hosted: Vec<String>,
}

impl Matches {
    pub fn is_empty(&self) -> bool {
        self.manifest.is_empty() && self.vendor.is_empty() && self.hosted.is_empty()
    }
}

fn sorted_keys<V>(map: &HashMap<String, V>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    keys
}

impl<'a> Ledgers<'a> {
    /// Every vendored entry grouped under the manifest key that claims it
    /// (rule 1 of the module docs), each group sorted by ledger key. Built
    /// in one pass over the sorted ledger, so the views stay O(V log V + M).
    fn claims(&self) -> HashMap<&'a str, Vec<(&'a String, &'a VendorEntry)>> {
        let mut claims: HashMap<&'a str, Vec<(&'a String, &'a VendorEntry)>> = HashMap::new();
        if let Some(vendor) = self.vendor {
            for key in sorted_keys(&vendor.entries) {
                let entry = &vendor.entries[key];
                if let Some(owner) = self.claimant(key, entry) {
                    claims.entry(owner).or_default().push((key, entry));
                }
            }
        }
        claims
    }

    /// A claim group's representative entry: the one filed under the
    /// manifest key itself, else the lowest-keyed.
    fn primary<'c>(
        key: &str,
        group: &'c [(&'a String, &'a VendorEntry)],
    ) -> Option<&'c (&'a String, &'a VendorEntry)> {
        group
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .or_else(|| group.first())
    }

    /// The manifest key that claims the vendored entry filed under `key`
    /// (rule 1 of the module docs): `key` itself, else its `base_purl`.
    fn claimant(&self, key: &str, entry: &VendorEntry) -> Option<&'a str> {
        let manifest = self.manifest?;
        manifest
            .patches
            .get_key_value(key)
            .or_else(|| manifest.patches.get_key_value(&entry.base_purl))
            .map(|(k, _)| k.as_str())
    }

    /// Whether the vendored entry filed under `key` has a manifest owner.
    pub fn vendor_claimed(&self, key: &str) -> bool {
        self.vendor
            .and_then(|v| v.entries.get(key))
            .is_some_and(|entry| self.claimant(key, entry).is_some())
    }

    /// One group per owner key: the manifest's keys (sorted), then the
    /// unclaimed vendored keys (sorted), then the hosted keys neither owns
    /// (sorted).
    pub fn owned(&self) -> Vec<Owned<'a>> {
        let hosted_records = self.redirect.map(|r| &r.records);
        let hosted_record = |key: &str| hosted_records.and_then(|r| r.get(key));
        let mut out: Vec<Owned<'a>> = Vec::new();
        let claims = self.claims();
        if let Some(manifest) = self.manifest {
            for key in sorted_keys(&manifest.patches) {
                let record = &manifest.patches[key];
                let group = claims
                    .get(key.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let vendor = Self::primary(key, group).copied();
                let mut alts: Vec<&'a PatchRecord> = Vec::new();
                alts.extend(vendor.and_then(|(_, e)| e.record.as_ref()));
                // Any further entry this key claims (another variant of
                // the same base purl) is a fallback copy too.
                alts.extend(
                    group
                        .iter()
                        .filter(|(k, _)| vendor.is_none_or(|(vk, _)| vk != *k))
                        .filter_map(|(_, e)| e.record.as_ref()),
                );
                alts.extend(hosted_record(key));
                out.push(Owned {
                    key,
                    store: Store::Manifest,
                    uuid: &record.uuid,
                    record: Some(record),
                    vendor: vendor.map(|(k, e)| (k.as_str(), e)),
                    hosted: hosted_record(key).is_some(),
                    alts,
                });
            }
        }
        if let Some(vendor) = self.vendor {
            for key in sorted_keys(&vendor.entries) {
                let entry = &vendor.entries[key];
                if self.claimant(key, entry).is_some() {
                    continue;
                }
                out.push(Owned {
                    key,
                    store: Store::Vendored,
                    uuid: &entry.uuid,
                    record: entry.record.as_ref(),
                    vendor: Some((key.as_str(), entry)),
                    hosted: hosted_record(key).is_some(),
                    alts: hosted_record(key).into_iter().collect(),
                });
            }
        }
        if let Some(records) = hosted_records {
            let taken: HashSet<&str> = out.iter().map(|o| o.key).collect();
            for (key, record) in records {
                if taken.contains(key.as_str()) {
                    continue;
                }
                out.push(Owned {
                    key,
                    store: Store::Hosted,
                    uuid: &record.uuid,
                    record: Some(record),
                    vendor: None,
                    hosted: true,
                    alts: Vec::new(),
                });
            }
        }
        out
    }

    /// Every record copy worth showing, sorted by key then store: all
    /// manifest and hosted records, and every vendored record except a
    /// claimed non-`detached` entry's (a standalone `vendor` entry's
    /// fallback copy of the manifest record it is claimed by). A `detached`
    /// entry is the only copy of its record, so it shows even beside a
    /// manifest entry — coexistence is real state, labeled apart.
    pub fn listed(&self) -> Vec<Listed<'a>> {
        let mut out: Vec<Listed<'a>> = Vec::new();
        if let Some(manifest) = self.manifest {
            out.extend(manifest.patches.iter().map(|(key, record)| Listed {
                key,
                record,
                store: Store::Manifest,
            }));
        }
        if let Some(vendor) = self.vendor {
            out.extend(vendor.entries.iter().filter_map(|(key, entry)| {
                let record = entry.record.as_ref()?;
                (entry.detached || self.claimant(key, entry).is_none()).then_some(Listed {
                    key,
                    record,
                    store: Store::Vendored,
                })
            }));
        }
        if let Some(redirect) = self.redirect {
            out.extend(redirect.records.iter().map(|(key, record)| Listed {
                key,
                record,
                store: Store::Hosted,
            }));
        }
        out.sort_by(|a, b| a.key.cmp(b.key).then(a.store.cmp(&b.store)));
        out
    }

    /// Every entry a remove/rollback `identifier` (purl or uuid) matches:
    /// manifest and hosted records by [`patch_matches`] on their key,
    /// vendored entries by [`VendorEntry::matches_identifier`] (key or base
    /// purl).
    pub fn matching(&self, identifier: &str) -> Matches {
        let mut manifest: Vec<String> = self
            .manifest
            .into_iter()
            .flat_map(|m| m.patches.iter())
            .filter(|(key, rec)| patch_matches(key, &rec.uuid, identifier))
            .map(|(key, _)| key.clone())
            .collect();
        manifest.sort();
        let mut vendor: Vec<(String, VendorEntry)> = self
            .vendor
            .into_iter()
            .flat_map(|s| s.entries.iter())
            .filter(|(key, entry)| entry.matches_identifier(key, identifier))
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        vendor.sort_by(|a, b| a.0.cmp(&b.0));
        let hosted: Vec<String> = self
            .redirect
            .into_iter()
            .flat_map(|r| r.records.iter())
            .filter(|(key, rec)| patch_matches(key, &rec.uuid, identifier))
            .map(|(key, _)| key.clone())
            .collect();
        Matches {
            manifest,
            vendor,
            hosted,
        }
    }

    /// The purls both the hosted records and the vendored ledger claim, in
    /// the records' display spelling ([`canonical_purl`]: qualifiers
    /// dropped, percent-decoded), sorted and deduplicated: each is stale in
    /// exactly one store, which only the live lockfile can tell.
    pub fn hosted_vendored_overlap(&self) -> Vec<String> {
        let (Some(redirect), Some(vendor)) = (self.redirect, self.vendor) else {
            return Vec::new();
        };
        if vendor.entries.is_empty() {
            return Vec::new();
        }
        // Match by `PurlKey`, so the API purl form the redirect records carry
        // matches the vendor entry's key or base purl in any spelling.
        // Two spellings of one release (composer `@3.0.2` and
        // `@3.0.2.0`, NuGet case twins) are ONE overlap: deduplicate by
        // `PurlKey`, reporting the smallest display spelling.
        let vendor_purls = vendor.purl_keys();
        let mut overlap: std::collections::BTreeMap<crate::utils::purl_key::PurlKey, String> =
            std::collections::BTreeMap::new();
        for purl in redirect
            .records
            .keys()
            .filter(|p| crate::vendor::purl_keys_cover(&vendor_purls, p))
        {
            let display = canonical_purl(purl);
            overlap
                .entry(crate::utils::purl_key::PurlKey::new(purl))
                .and_modify(|kept| {
                    if display < *kept {
                        *kept = display.clone();
                    }
                })
                .or_insert(display);
        }
        let mut out: Vec<String> = overlap.into_values().collect();
        out.sort();
        out
    }
}

/// A uuid-only stand-in record (a legacy vendored entry that embeds no
/// record, or a lockfile pin with no store record).
pub fn uuid_only_record(uuid: &str) -> PatchRecord {
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: String::new(),
        files: HashMap::new(),
        vulnerabilities: HashMap::new(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    }
}

/// Fold the hosted pins and the vendor ledger's patch records into the
/// manifest view update detection consults. Hosted mode records purl→uuid
/// ONLY in the lockfiles (`hosted_pins`, uuid only; v5 keeps no hosted
/// ledger) and vendored mode ONLY in `.socket/vendor/state.json`, so without
/// this fold a pure hosted or vendored project's `updates[]` would always
/// be empty. Precedence on a collision: manifest > hosted pins > vendor
/// ledger (the live lock over a possibly superseded vendored entry); the
/// vendor entries fold under the shared owner rule
/// ([`Ledgers::owned`]), so one the manifest
/// claims (its key or base purl) stays behind the manifest's record.
/// Vendor entries are keyed by their ledger key (`detect_updates` bridges
/// the spellings); a legacy entry without an embedded record contributes
/// its uuid alone. Borrows the manifest untouched when nothing else
/// contributes.
pub fn merge_ledger_records_for_updates<'a>(
    manifest: Option<&'a PatchManifest>,
    vendor: Option<&VendorState>,
    hosted_pins: &[(String, String)],
) -> Option<Cow<'a, PatchManifest>> {
    let vendor = vendor.filter(|s| !s.entries.is_empty());
    if vendor.is_none() && hosted_pins.is_empty() {
        return manifest.map(Cow::Borrowed);
    }
    let mut merged = manifest.cloned().unwrap_or_default();
    for (purl, uuid) in hosted_pins {
        merged
            .patches
            .entry(purl.clone())
            .or_insert_with(|| uuid_only_record(uuid));
    }
    let ledgers = Ledgers {
        manifest,
        vendor,
        redirect: None,
    };
    for owned in ledgers.owned() {
        if owned.store == Store::Manifest {
            continue;
        }
        merged
            .patches
            .entry(owned.key.to_string())
            .or_insert_with(|| {
                owned
                    .record
                    .cloned()
                    .unwrap_or_else(|| uuid_only_record(owned.uuid))
            });
    }
    Some(Cow::Owned(merged))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(uuid: &str) -> PatchRecord {
        uuid_only_record(uuid)
    }

    fn entry(uuid: &str, base: &str, detached: bool, rec: Option<&str>) -> VendorEntry {
        let mut value = serde_json::json!({
            "uuid": uuid,
            "basePurl": base,
            "ecosystem": "npm",
            "artifact": { "path": "", "sha256": "" },
            "wiring": [],
            "detached": detached,
        });
        if let Some(r) = rec {
            value["record"] = serde_json::to_value(record(r)).unwrap();
        }
        serde_json::from_value(value).expect("vendor entry fixture")
    }

    fn manifest(pairs: &[(&str, &str)]) -> PatchManifest {
        let mut m = PatchManifest::new();
        for (k, u) in pairs {
            m.patches.insert(k.to_string(), record(u));
        }
        m
    }

    fn vendor(pairs: Vec<(&str, VendorEntry)>) -> VendorState {
        let mut s = VendorState::new();
        for (k, e) in pairs {
            s.entries.insert(k.to_string(), e);
        }
        s
    }

    fn redirect(pairs: &[(&str, &str)]) -> RedirectState {
        let mut r = RedirectState::new();
        for (k, u) in pairs {
            r.records.insert(k.to_string(), record(u));
        }
        r
    }

    #[test]
    fn manifest_beats_vendored_beats_hosted() {
        let m = manifest(&[("pkg:npm/a@1", "m")]);
        let v = vendor(vec![
            ("pkg:npm/a@1", entry("v", "pkg:npm/a@1", true, Some("v"))),
            ("pkg:npm/b@1", entry("vb", "pkg:npm/b@1", true, Some("vb"))),
        ]);
        let r = redirect(&[
            ("pkg:npm/a@1", "h"),
            ("pkg:npm/b@1", "hb"),
            ("pkg:npm/c@1", "hc"),
        ]);
        let l = Ledgers {
            manifest: Some(&m),
            vendor: Some(&v),
            redirect: Some(&r),
        };
        let owned = l.owned();
        let got: Vec<(&str, Store, &str, Vec<&str>)> = owned
            .iter()
            .map(|o| {
                (
                    o.key,
                    o.store,
                    o.uuid,
                    o.alts.iter().map(|a| a.uuid.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("pkg:npm/a@1", Store::Manifest, "m", vec!["v", "h"]),
                ("pkg:npm/b@1", Store::Vendored, "vb", vec!["hb"]),
                ("pkg:npm/c@1", Store::Hosted, "hc", vec![]),
            ]
        );
    }

    #[test]
    fn a_manifest_key_claims_the_entry_naming_it_as_base_purl() {
        let m = manifest(&[("pkg:npm/a@1", "m")]);
        let v = vendor(vec![
            (
                "pkg:npm/a@1?x=2",
                entry("v2", "pkg:npm/a@1", false, Some("v2")),
            ),
            (
                "pkg:npm/a@1?x=1",
                entry("v1", "pkg:npm/a@1", false, Some("v1")),
            ),
        ]);
        let l = Ledgers {
            manifest: Some(&m),
            vendor: Some(&v),
            redirect: None,
        };
        let owned = l.owned();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].vendor.map(|(k, _)| k), Some("pkg:npm/a@1?x=1"));
        let alts: Vec<&str> = owned[0].alts.iter().map(|a| a.uuid.as_str()).collect();
        assert_eq!(alts, vec!["v1", "v2"]);
        assert!(l.vendor_claimed("pkg:npm/a@1?x=1"));
        assert!(l.vendor_claimed("pkg:npm/a@1?x=2"));
        // Claimed fallback copies are not listed.
        let listed: Vec<(&str, Store)> = l.listed().iter().map(|e| (e.key, e.store)).collect();
        assert_eq!(listed, vec![("pkg:npm/a@1", Store::Manifest)]);
    }

    #[test]
    fn a_detached_claimed_entry_still_lists() {
        let m = manifest(&[("pkg:npm/a@1", "m")]);
        let v = vendor(vec![(
            "pkg:npm/a@1",
            entry("v", "pkg:npm/a@1", true, Some("v")),
        )]);
        let l = Ledgers {
            manifest: Some(&m),
            vendor: Some(&v),
            redirect: None,
        };
        assert_eq!(l.listed().len(), 2);
        assert_eq!(l.owned().len(), 1);
    }

    #[test]
    fn matching_spans_every_store() {
        let m = manifest(&[("pkg:npm/a@1", "m")]);
        let v = vendor(vec![(
            "pkg:npm/a@1?q=1",
            entry("v", "pkg:npm/a@1", true, None),
        )]);
        let r = redirect(&[("pkg:npm/a@1", "h"), ("pkg:npm/b@1", "hb")]);
        let l = Ledgers {
            manifest: Some(&m),
            vendor: Some(&v),
            redirect: Some(&r),
        };
        let found = l.matching("pkg:npm/a@1");
        assert_eq!(found.manifest, vec!["pkg:npm/a@1"]);
        assert_eq!(found.vendor.len(), 1);
        assert_eq!(found.hosted, vec!["pkg:npm/a@1"]);
        assert!(l.matching("nope").is_empty());
        assert_eq!(l.matching("hb").hosted, vec!["pkg:npm/b@1"]);
    }

    #[test]
    fn overlap_reports_one_entry_per_release_across_spellings() {
        let v = vendor(vec![
            (
                "pkg:nuget/newtonsoft.json@13.0.1",
                entry("v", "pkg:nuget/newtonsoft.json@13.0.1", true, None),
            ),
            (
                "pkg:composer/acme/lib@3.0.2",
                entry("c", "pkg:composer/acme/lib@3.0.2", true, None),
            ),
        ]);
        let r = redirect(&[
            ("pkg:nuget/Newtonsoft.Json@13.0.1", "h1"),
            ("pkg:nuget/newtonsoft.json@13.0.1", "h2"),
            ("pkg:composer/acme/lib@3.0.2", "h3"),
            ("pkg:composer/acme/lib@3.0.2.0", "h4"),
        ]);
        let l = Ledgers {
            manifest: None,
            vendor: Some(&v),
            redirect: Some(&r),
        };
        assert_eq!(
            l.hosted_vendored_overlap(),
            vec![
                "pkg:composer/acme/lib@3.0.2".to_string(),
                "pkg:nuget/Newtonsoft.Json@13.0.1".to_string(),
            ]
        );
    }
}
