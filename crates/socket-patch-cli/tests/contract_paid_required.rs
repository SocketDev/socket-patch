//! #982: CLI_CONTRACT.md's paid-plan contract matches what ships.
//!
//! v5.0: `get --json` reports a paid-only result on the shared envelope,
//! `status: "paidRequired"` with one `skipped` / `paid_required` event per
//! patch (exit 0). The legacy top-level `status: "paid_required"` shape is
//! retired, and `scan` never reports the outcome. The emitted shape itself
//! is pinned by the `--test get paid` tests.

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
        row.contains("`paidRequired`"),
        "the row names the envelope status `get` emits: {row}"
    );
    assert!(
        !row.contains(r#""status": "paid_required""#),
        "the legacy top-level shape is retired: {row}"
    );
    assert!(
        row.contains("`scan` never reports it"),
        "scan has no paid_required outcome: {row}"
    );
    assert!(
        contract.contains("\"paidRequired\""),
        "the envelope status enum lists `paidRequired`"
    );
}

#[test]
fn get_emits_the_paid_required_envelope_status() {
    let get = read("src/commands/get.rs");
    assert!(
        !get.contains(r#""status": "paid_required""#),
        "get no longer prints the legacy paid shape"
    );
    assert!(
        get.contains("Status::PaidRequired"),
        "get reports paid-only results through the envelope status"
    );
    let envelope = read("src/json_envelope.rs");
    assert!(
        envelope.contains("PaidRequired"),
        "the envelope carries the paid status variant"
    );
}
