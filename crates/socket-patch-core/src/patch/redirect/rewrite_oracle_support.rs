//! Shared support for the hosted rewriters' equivalence oracles.
//!
//! One deterministic RNG and ONE snapshot, so the two sweeps cannot drift
//! apart: the snapshot covers every `RewriteResult` channel, not only the
//! ones a particular rewriter is known to touch, so a rewriter that starts
//! writing a new channel is compared there from the first run.

use super::*;

/// Deterministic xorshift64* — no `rand` dev-dependency.
pub(super) struct Rng(pub u64);

impl Rng {
    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub(super) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub(super) fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// The uuid sets, each under its field name so a mismatch says which.
type UuidSets = Vec<(&'static str, std::collections::BTreeSet<String>)>;

/// Every output channel of a [`RewriteResult`], in a comparable shape.
pub(super) struct Snapshot {
    files: BTreeMap<String, String>,
    binary_files: BTreeMap<String, Vec<u8>>,
    edits: Vec<FileEdit>,
    warnings: Vec<(String, String)>,
    uuids: UuidSets,
}

pub(super) fn snapshot(r: &RewriteResult) -> Snapshot {
    Snapshot {
        files: r.files.clone(),
        binary_files: r.binary_files.clone(),
        edits: r.edits.clone(),
        warnings: r
            .warnings
            .iter()
            .map(|w| (w.code.clone(), w.detail.clone()))
            .collect(),
        uuids: vec![
            (
                "confirmed_bun_binary_uuids",
                r.confirmed_bun_binary_uuids.clone(),
            ),
            ("confirmed_cargo_uuids", r.confirmed_cargo_uuids.clone()),
            ("confirmed_pipenv_uuids", r.confirmed_pipenv_uuids.clone()),
            ("refused_pipenv_uuids", r.refused_pipenv_uuids.clone()),
            ("confirmed_pdm_uuids", r.confirmed_pdm_uuids.clone()),
            ("refused_pdm_uuids", r.refused_pdm_uuids.clone()),
            ("refused_pnpm_uuids", r.refused_pnpm_uuids.clone()),
            ("python_lock_uuids", r.python_lock_uuids.clone()),
            (
                "confirmed_python_lock_uuids",
                r.confirmed_python_lock_uuids.clone(),
            ),
            (
                "refused_python_lock_uuids",
                r.refused_python_lock_uuids.clone(),
            ),
            ("hatch_uuids", r.hatch_uuids.clone()),
            ("confirmed_hatch_uuids", r.confirmed_hatch_uuids.clone()),
            (
                "confirmed_requirements_uuids",
                r.confirmed_requirements_uuids.clone(),
            ),
        ],
    }
}

/// Assert the production rewriter's `got` equals the oracle's `want` on
/// every channel, naming the first file byte / edit / set that differs.
pub(super) fn assert_same(want: &RewriteResult, got: &RewriteResult, what: &str) {
    let (want, got) = (snapshot(want), snapshot(got));
    for (path, want_text) in &want.files {
        let got_text = got.files.get(path);
        assert!(
            got_text == Some(want_text),
            "{what}: rewritten bytes differ for {path} (first diff at byte {:?})",
            got_text.map(|g| g
                .bytes()
                .zip(want_text.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(g.len().min(want_text.len())))
        );
    }
    assert_eq!(
        got.files.keys().collect::<Vec<_>>(),
        want.files.keys().collect::<Vec<_>>(),
        "{what}: rewritten file set"
    );
    assert_eq!(
        got.binary_files.keys().collect::<Vec<_>>(),
        want.binary_files.keys().collect::<Vec<_>>(),
        "{what}: rewritten binary file set"
    );
    for (path, want_bytes) in &want.binary_files {
        assert!(
            got.binary_files.get(path) == Some(want_bytes),
            "{what}: rewritten bytes differ for binary {path}"
        );
    }
    assert_eq!(got.edits.len(), want.edits.len(), "{what}: edit count");
    for (i, (g, w)) in got.edits.iter().zip(&want.edits).enumerate() {
        assert_eq!(g, w, "{what}: edit #{i}");
    }
    assert_eq!(
        got.warnings, want.warnings,
        "{what}: warnings (code, detail) in order"
    );
    for ((field, got_set), (_, want_set)) in got.uuids.iter().zip(&want.uuids) {
        assert_eq!(got_set, want_set, "{what}: {field}");
    }
}
