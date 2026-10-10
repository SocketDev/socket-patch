//! #982: CLI_CONTRACT.md's paid-plan contract matches what ships.
//!
//! `get --json` reports a paid-only result through its legacy top-level
//! `status: "paid_required"` (one emitter), and no command emits the
//! envelope status `paidRequired`, so the contract must neither list that
//! status nor describe `paid_required` as an event tag `scan` emits. The
//! emitted shape itself is pinned by the `--test get paid` tests.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn contract_paid_required_row_matches_get() {
    let contract = read("CLI_CONTRACT.md");
    let row = contract
        .lines()
        .find(|l| l.starts_with("| `paid_required`"))
        .expect("CLI_CONTRACT.md documents `paid_required`");
    assert!(
        row.contains(r#""status": "paid_required""#),
        "the row names the status spelling `get` emits: {row}"
    );
    assert!(
        !row.contains("paidRequired"),
        "no command emits the envelope status `paidRequired`: {row}"
    );
    assert!(
        row.contains("`scan` never reports it"),
        "scan has no paid_required outcome: {row}"
    );
    assert!(
        !contract.contains("\"paidRequired\""),
        "the envelope status enum must not list `paidRequired`"
    );
}

#[test]
fn get_writes_the_paid_required_shape_once() {
    let get = read("src/commands/get.rs");
    assert_eq!(
        get.matches(r#""status": "paid_required""#).count(),
        1,
        "both paid paths share one emitter"
    );
    let envelope = read("src/json_envelope.rs");
    assert!(
        !envelope.contains("PaidRequired"),
        "the envelope has no paid status variant"
    );
}
