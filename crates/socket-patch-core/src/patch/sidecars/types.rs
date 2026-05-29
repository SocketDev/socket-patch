//! Typed schema for the JSON-envelope `sidecars[]` field.
//!
//! These types are the canonical shape of every ecosystem's
//! post-apply integrity fixup outcome. They live in `socket-patch-core`
//! (rather than the CLI crate) so the core, which produces the data,
//! owns the definitions; the CLI just embeds them in its envelope
//! via `Envelope.sidecars: Vec<SidecarRecord>`.
//!
//! Every struct/enum derives `serde::Serialize` with stable JSON
//! key conventions:
//!   * structs serialize with `#[serde(rename_all = "camelCase")]`;
//!   * enums serialize as `#[serde(rename_all = "snake_case")]`
//!     strings.
//!
//! Downstream consumers (CI bots, dashboards, jq pipelines,
//! telemetry) can rely on the field set and tag spelling — see the
//! unit tests below which lock the JSON contract in place.

use serde::Serialize;

/// Per-package sidecar fixup outcome. Emitted under
/// `Envelope.sidecars[]` one entry per package whose apply produced
/// a fixup result (touched files or advisory).
///
/// Joins to `Envelope.events[].purl` for per-event context. The
/// `ecosystem` field is denormalized so jq-style filters (`select(
/// .ecosystem == "cargo")`) work without first looking the PURL up.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarRecord {
    /// PURL of the package this fixup applied to.
    pub purl: String,
    /// Lowercase ecosystem identifier (`npm`, `pypi`, `cargo`,
    /// `gem`, `golang`, `maven`, `composer`, `nuget`). Matches
    /// `Ecosystem::cli_name()`.
    pub ecosystem: String,
    /// Files touched by the fixup, in declaration order. Empty
    /// (but always present) for advisory-only ecosystems.
    pub files: Vec<SidecarFile>,
    /// Operator advisory about post-apply tooling consequences.
    /// `None` (omitted from JSON) on the success path with no
    /// warnings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<SidecarAdvisory>,
}

/// One file the fixup rewrote or deleted. Paths are relative to the
/// package directory the patch landed in. (There is deliberately no
/// "created" action — see [`SidecarFileAction`], which reserves no
/// variants ahead of an ecosystem that actually produces them.)
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarFile {
    pub path: String,
    pub action: SidecarFileAction,
}

/// What the fixup did with a sidecar file. Stable snake_case JSON
/// tag — consumers branch on this without parsing free-form text.
///
/// Variants are added only when an ecosystem actually produces them
/// (rather than reserved up front). Adding a variant is a
/// non-breaking change to the JSON contract; renaming or removing
/// one is breaking.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SidecarFileAction {
    Rewritten,
    Deleted,
}

/// Structured operator advisory. Replaces the previous free-form
/// `Option<String>` field so consumers can switch on `code` and
/// route on `severity` without regex-matching `message`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarAdvisory {
    /// Stable enum tag for programmatic dispatch.
    pub code: SidecarAdvisoryCode,
    /// Severity hint for UI rendering.
    pub severity: SidecarSeverity,
    /// Human-readable message. Stable in spirit but consumers
    /// that need to branch should use `code`.
    pub message: String,
}

/// Stable enum tag for the kind of advisory. Adding a variant is
/// a non-breaking change; renaming or removing one is breaking.
///
/// Current set (one per real-world scenario we surface):
/// * `PypiRecordStale` — we didn't rewrite `.dist-info/RECORD`;
///   `pip check` may flag inconsistency.
/// * `GemBundleInstallReverts` — `bundle install --redownload`
///   will overwrite patched gem files with the cached `.gem`.
/// * `GoModVerifyFails` — `go mod verify` will report a hash
///   mismatch against `go.sum`. `go build` still works.
/// * `NugetSignedPackageTampered` — package has a `.nupkg.sha512`
///   signature sidecar we cannot honestly recompute; `dotnet
///   restore` may flag.
/// * `SidecarFixupFailed` — the fixup itself raised an error
///   (I/O, parse). The patch is on disk; the sidecar is not.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SidecarAdvisoryCode {
    PypiRecordStale,
    GemBundleInstallReverts,
    GoModVerifyFails,
    NugetSignedPackageTampered,
    SidecarFixupFailed,
}

/// Severity bucket. UI consumers use this for badge color; jq
/// pipelines filter by it. `Error` is reserved for the fixup
/// itself failing — informational consequences of the apply use
/// `Info` or `Warning`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SidecarSeverity {
    Info,
    Warning,
    Error,
}

#[cfg(test)]
mod tests {
    //! These tests lock the JSON contract that downstream
    //! consumers (CI bots, dashboards, jq pipelines, telemetry)
    //! rely on. Renaming a key or changing a tag spelling here is
    //! a breaking change — bump the CLI version and update
    //! consumers accordingly.
    use super::*;

    #[test]
    fn record_serializes_camel_case_keys() {
        let r = SidecarRecord {
            purl: "pkg:cargo/x@1.0.0".to_string(),
            ecosystem: "cargo".to_string(),
            files: vec![SidecarFile {
                path: ".cargo-checksum.json".to_string(),
                action: SidecarFileAction::Rewritten,
            }],
            advisory: None,
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        // Top-level keys.
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert!(keys.contains(&"purl"));
        assert!(keys.contains(&"ecosystem"));
        assert!(keys.contains(&"files"));
        // `advisory` is None — must be omitted.
        assert!(!keys.contains(&"advisory"));
    }

    #[test]
    fn record_serializes_advisory_when_present() {
        let r = SidecarRecord {
            purl: "pkg:pypi/requests@2.28.0".to_string(),
            ecosystem: "pypi".to_string(),
            files: Vec::new(),
            advisory: Some(SidecarAdvisory {
                code: SidecarAdvisoryCode::PypiRecordStale,
                severity: SidecarSeverity::Warning,
                message: "PyPI: run `pip check`...".to_string(),
            }),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        let adv = v.get("advisory").expect("advisory should be present");
        assert_eq!(adv["code"], "pypi_record_stale");
        assert_eq!(adv["severity"], "warning");
        assert_eq!(adv["message"], "PyPI: run `pip check`...");
    }

    #[test]
    fn file_action_tags_are_snake_case() {
        let cases = [
            (SidecarFileAction::Rewritten, "rewritten"),
            (SidecarFileAction::Deleted, "deleted"),
        ];
        for (variant, expected) in cases {
            let v = serde_json::to_value(variant).unwrap();
            assert_eq!(v.as_str().unwrap(), expected);
        }
    }

    #[test]
    fn advisory_code_tags_are_snake_case() {
        let cases = [
            (SidecarAdvisoryCode::PypiRecordStale, "pypi_record_stale"),
            (
                SidecarAdvisoryCode::GemBundleInstallReverts,
                "gem_bundle_install_reverts",
            ),
            (SidecarAdvisoryCode::GoModVerifyFails, "go_mod_verify_fails"),
            (
                SidecarAdvisoryCode::NugetSignedPackageTampered,
                "nuget_signed_package_tampered",
            ),
            (
                SidecarAdvisoryCode::SidecarFixupFailed,
                "sidecar_fixup_failed",
            ),
        ];
        for (variant, expected) in cases {
            let v = serde_json::to_value(variant).unwrap();
            assert_eq!(v.as_str().unwrap(), expected);
        }
    }

    #[test]
    fn severity_tags_are_snake_case() {
        assert_eq!(
            serde_json::to_value(SidecarSeverity::Info).unwrap(),
            serde_json::Value::String("info".to_string())
        );
        assert_eq!(
            serde_json::to_value(SidecarSeverity::Warning).unwrap(),
            serde_json::Value::String("warning".to_string())
        );
        assert_eq!(
            serde_json::to_value(SidecarSeverity::Error).unwrap(),
            serde_json::Value::String("error".to_string())
        );
    }

    /// Contract: `files` is ALWAYS present in the serialized record,
    /// even for advisory-only ecosystems (PyPI / gem / Go) whose record
    /// carries an empty file list. Consumers iterate `.sidecars[].files[]`
    /// unconditionally; dropping the key — e.g. via a stray
    /// `skip_serializing_if = "Vec::is_empty"` copied from
    /// `Envelope.sidecars` one layer up — would silently force every
    /// consumer to null-guard. Locks the "Empty (but always present)"
    /// guarantee documented on `SidecarRecord::files`.
    #[test]
    fn files_always_present_even_when_empty() {
        let r = SidecarRecord {
            purl: "pkg:pypi/requests@2.28.0".to_string(),
            ecosystem: "pypi".to_string(),
            files: Vec::new(),
            advisory: Some(SidecarAdvisory {
                code: SidecarAdvisoryCode::PypiRecordStale,
                severity: SidecarSeverity::Warning,
                message: "advisory only".to_string(),
            }),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("files"),
            "`files` must always serialize, even when empty"
        );
        assert_eq!(
            obj["files"],
            serde_json::Value::Array(Vec::new()),
            "empty file list must serialize as `[]`, not be omitted"
        );
    }

    /// Contract: the fixup-failed path — the only scenario that emits
    /// `SidecarSeverity::Error` (see `apply.rs`) — pairs the `Error`
    /// severity with the `SidecarFixupFailed` code, an empty `files`
    /// list, and an advisory. Pins the exact JSON a consumer branches
    /// on to distinguish "the patch landed but the sidecar fixup blew
    /// up" from an informational advisory.
    #[test]
    fn fixup_failed_serializes_error_severity_and_code() {
        let r = SidecarRecord {
            purl: "pkg:cargo/x@1.0.0".to_string(),
            ecosystem: "cargo".to_string(),
            files: Vec::new(),
            advisory: Some(SidecarAdvisory {
                code: SidecarAdvisoryCode::SidecarFixupFailed,
                severity: SidecarSeverity::Error,
                message: "sidecar fixup failed (patch still applied): boom".to_string(),
            }),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["advisory"]["code"], "sidecar_fixup_failed");
        assert_eq!(v["advisory"]["severity"], "error");
        assert_eq!(v["files"], serde_json::Value::Array(Vec::new()));
    }

    /// Multi-file record + advisory together — the NuGet
    /// signed-package case that the old design lost. Verify both
    /// surface in the JSON simultaneously.
    #[test]
    fn nuget_signed_case_carries_files_and_advisory() {
        let r = SidecarRecord {
            purl: "pkg:nuget/Foo@1.0.0".to_string(),
            ecosystem: "nuget".to_string(),
            files: vec![SidecarFile {
                path: ".nupkg.metadata".to_string(),
                action: SidecarFileAction::Deleted,
            }],
            advisory: Some(SidecarAdvisory {
                code: SidecarAdvisoryCode::NugetSignedPackageTampered,
                severity: SidecarSeverity::Warning,
                message: "package has a .nupkg.sha512 signature sidecar".to_string(),
            }),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["files"][0]["path"], ".nupkg.metadata");
        assert_eq!(v["files"][0]["action"], "deleted");
        assert_eq!(v["advisory"]["code"], "nuget_signed_package_tampered");
    }
}
