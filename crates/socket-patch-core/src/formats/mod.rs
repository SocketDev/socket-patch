//! One model per lockfile format.
//!
//! Each submodule owns everything the modes read from (and plan against)
//! one lock format: the entry grammar, the key rules, the version sniff and
//! the planners that splice it. A model parses a lock text once and answers
//! from that parse:
//!
//! * `entries()` — the registry inventory (`vendor::lock_inventory`'s
//!   per-format views wrap it with their I/O);
//! * `wired_refs()` — the entries that name a Socket-hosted or vendored
//!   artifact, the raw material of lockfile discovery (`vex::discover`) and
//!   `repair`'s trust anchors;
//! * `plan_hosted()` / the vendored planners — the edits `scan --mode
//!   hosted` and `vendor` make;
//! * `in_use()` — whether a vendored artifact is still consumed;
//! * [`LockModel::restore_upstream`] — the hosted-rollback hook.
//!
//! Models are PURE: text (or a parsed document) in, answers out. Every read
//! stays with the caller, so the disk engines and the in-memory hosted
//! engine (`MemoryProject`) share one parse per format. An architecture
//! test below enforces it.
//!
//! [`registry()`] is the one table of which project files carry a lock or
//! its wiring, and in which roles.

pub mod cargo;
pub mod composer;
pub mod gem;
pub mod pnpm;
pub(crate) mod bun;
pub mod registry;
pub mod yarn;

pub use registry::registry;

/// The default upstream resolution a hosted pin is restored to: the
/// registry artifact of `name@version` as the package manager itself
/// would lock it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamPin<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// The registry artifact URL, when the format records one.
    pub resolved: Option<&'a str>,
    /// The format's content verifier for that artifact (an SRI, a hex
    /// sha256, …).
    pub integrity: Option<&'a str>,
}

/// What [`LockModel::restore_upstream`] did with a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreUpstream {
    /// The lock text with every named pin restored.
    Rewritten(String),
    /// No entry of the lock is pinned to any of the named patches.
    Unchanged,
    /// The format cannot restore the pins in place; `remedy` tells the user
    /// how to (`git checkout -- <lockfile>`, a re-lock).
    Unsupported { remedy: String },
}

/// The contract every per-format model implements.
pub trait LockModel {
    /// The lock's canonical file name, for diagnostics.
    const FORMAT: &'static str;

    /// Rewrite every hosted pin of the named patches back to its default
    /// upstream entry with the same writer the hosted planner uses. The
    /// hosted-rollback workstream fills this in per format; until then
    /// every format refuses with the checkout remedy.
    fn restore_upstream(&self, _pins: &[UpstreamPin<'_>]) -> RestoreUpstream {
        RestoreUpstream::Unsupported {
            remedy: format!(
                "restore {} from version control (`git checkout -- {}`)",
                Self::FORMAT,
                Self::FORMAT
            ),
        }
    }
}

/// ARCHITECTURE GUARD (module docs): format models do no I/O and apply no
/// host policy.
#[cfg(test)]
mod architecture_tests {
    use std::path::Path;

    const IMPURE: [&str; 9] = [
        "tokio::fs",
        "std::fs",
        "read_regular_",
        "File::open",
        "OpenOptions",
        "hosted_patch_uuid",
        "hosted_patch_url_uuids",
        "async fn",
        ".await",
    ];

    fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read formats dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn format_models_are_pure() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/formats");
        let mut files = Vec::new();
        rs_files(&dir, &mut files);
        assert!(files.len() >= 4, "only {} format files found", files.len());
        for path in files {
            let src = std::fs::read_to_string(&path).expect("read format source");
            let prod = src.split("#[cfg(test)]").next().unwrap_or_default();
            let code: String = prod
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let used: Vec<&str> = IMPURE.iter().copied().filter(|n| code.contains(n)).collect();
            assert!(
                used.is_empty(),
                "{}: a format model uses {used:?} — models are pure (module docs)",
                path.display()
            );
        }
    }
}
