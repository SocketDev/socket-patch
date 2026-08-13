//! Small structured-TOML helpers shared by every module that edits or sniffs
//! TOML (`setup::pypi`, `vendor::cargo_config`, `vendor::pypi`,
//! `vendor::pypi_uv`). Extracted from the pypi setup backend (now `setup::pypi`) so it no
//! longer owns the crate's generic TOML seam.

use toml_edit::{Item, Table};

/// Ensure `parent[key]` is a table, creating it if absent. Errors if present
/// but a non-table.
pub(crate) fn ensure_table<'a>(
    parent: &'a mut Table,
    key: &str,
    implicit: bool,
) -> Result<&'a mut Table, String> {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(implicit);
        parent.insert(key, Item::Table(t));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

/// True if a `[prefix]` or `[prefix.*]` table header appears in the TOML text.
pub(crate) fn has_table(content: &str, prefix: &str) -> bool {
    content.lines().any(|line| {
        let l = line.trim();
        let Some(rest) = l.strip_prefix('[') else {
            return false;
        };
        // Tolerate array-of-tables (`[[..]]`) by dropping a second opening
        // bracket, then take everything up to the closing `]` so a trailing
        // inline comment (`[tool.uv] # note`) or interior padding
        // (`[ tool.uv ]`) — both valid TOML — doesn't defeat the match.
        let rest = rest.trim_start_matches('[');
        let Some(end) = rest.find(']') else {
            return false;
        };
        let header = rest[..end].trim();
        header == prefix || header.starts_with(&format!("{prefix}."))
    })
}
