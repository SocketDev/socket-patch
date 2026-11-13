//! A vendored lane for the tests of the vendored seam, and the workspace
//! it serves. No production lane is enabled, so the built binary never
//! plans a vendored write under a Bazel hub: these tests hand the seam a
//! lane table of their own, in process.
//!
//! The lane pins a package in the `pnpm-lock.yaml` a rules_js hub reads,
//! by replacing the value of its `resolution:` line with the path and the
//! SHA-256 of the vendored artifact. It records the value it replaced as
//! a generated value (a `pins` row), so the executor can undo it, and it
//! names the artifact in an `ArtifactSpec`. It is a test double of a lane,
//! not a claim about what rules_js builds.
//!
//! One file for both suites: the unit tests of
//! `src/bazel_gate/vendored.rs` include it by path, and
//! `tests/e2e_bazel/vendored.rs` as its submodule.

use serde_json::json;
use socket_patch_core::bazel::lanes::Proofs;
use socket_patch_core::bazel::model::{
    Anchor, ArtifactForm, ArtifactSpec, AttestBasis, BazelRef, CellClaim, ClaimOs, ClaimSystem,
    Digest, Files, GateOutcome, IndexRow, LaneCx, LaneId, LaneOps, LaneSpec, LaneTable, Mode,
    OwnedWrite, PatchRequest, PinSource, Plan, PlannedWrite, RestoreOutcome, Ruleset, TextRead,
    VexWithhold, WithholdKind, WriteClass,
};
use socket_patch_core::patch::redirect::{FileEdit, RewriteResult};
use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

pub const LANE: LaneId = LaneId("V-TOY1");
pub const LOCK: &str = "pnpm-lock.yaml";
pub const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
pub const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// A package the lane asks for in a form no release can build yet.
pub const ZIPPED_PURL: &str = "pkg:npm/is-odd@3.0.1";
/// The bytes the fake patch service serves for [`UUID`].
pub const ARTIFACT: &[u8] = b"left-pad 1.3.0, patched\n";
/// The artifact's file name. No archive suffix: the engine verifies the
/// members of an archive against the patch record, and this is no archive.
pub const LEAF: &str = "left-pad-1.3.0.bin";
pub const UPSTREAM: &str = "{integrity: sha512-upstream-left-pad}";

pub const BAZELVERSION: &str = "9.3.2\n";
pub const MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
    use_repo(npm, \"npm\")\n";
pub const LOCK_TEXT: &str = "lockfileVersion: '9.0'\n\npackages:\n\n  is-odd@3.0.1:\n    \
    resolution: {integrity: sha512-upstream-is-odd}\n\n  left-pad@1.3.0:\n    \
    resolution: {integrity: sha512-upstream-left-pad}\n\nsnapshots:\n\n  is-odd@3.0.1: {}\n\n  \
    left-pad@1.3.0: {}\n";

const CLAIMS: &[CellClaim] = &[CellClaim {
    lo: "7.2.0",
    hi: "9.3.2",
    system: ClaimSystem::Bzlmod,
}];
const SPEC: LaneSpec = LaneSpec {
    enabled: true,
    supported: CLAIMS,
    classes: &[WriteClass::GeneratedValue, WriteClass::Owned],
    ..LaneSpec::stub("V-TOY1", Mode::Vendored, &[])
};
const OPS: LaneOps = LaneOps {
    lanes: &[SPEC],
    gate: toy_gate,
    rewrite_owned: toy_rewrite,
    fixups: |_, _, _, _| {},
    discover: toy_discover,
    attest: toy_attest,
    restore: toy_restore,
    inventory: toy_inventory,
};
/// The table the tests hand the seam in place of `lanes::PRODUCTION`.
pub const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &OPS)]);
/// A vendored lane wires a path, so the gate asks for a cell of it on the
/// host. The fabricated lane claims every system the suites run on.
pub const PROOFS: Proofs = Proofs {
    os: &[
        (LANE, ClaimOs::Linux),
        (LANE, ClaimOs::Macos),
        (LANE, ClaimOs::Windows),
    ],
    ..Proofs::PRODUCTION
};

/// The digest the lane pins: the fake service's artifact.
pub fn digest() -> Digest {
    Digest::Sha256(Digest::sha256_hex(ARTIFACT))
}

/// The value the lane writes into the `resolution:` line for an artifact
/// at the root-relative `path`.
pub fn pinned(path: &str, digest: &Digest) -> String {
    let hex = match digest {
        Digest::Sha256(hex) | Digest::Sha512(hex) => hex,
    };
    format!("{{tarball: file:{path}, integrity: sha256-{hex}}}")
}

fn key(name: &str, version: &str) -> String {
    format!("packages/{name}@{version}/resolution")
}

/// The byte range of the value of a package's `resolution:` line.
fn resolution(text: &str, name: &str, version: &str) -> Option<std::ops::Range<usize>> {
    let head = format!("\n  {name}@{version}:\n    resolution: ");
    let start = text.find(&head)? + head.len();
    let end = start + text[start..].find('\n')?;
    Some(start..end)
}

fn lock_of(cx: &LaneCx<'_>) -> Option<String> {
    cx.ws.hubs.get(cx.hub.0)?.locks.first()?.path.clone()
}

fn toy_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let lock = lock_of(cx).unwrap_or_default();
    let found = cx.files.read(&lock);
    let resolves = |text: &str| resolution(text, req.name, req.version).is_some();
    if !found.as_str().is_some_and(resolves) {
        // The lock of this hub does not resolve the release.
        return GateOutcome::NotBazel;
    }
    let project = cx.ws.root.project_rel.as_str();
    let unit = format!(".socket/vendor/npm/{}", req.uuid);
    let dir = match project.is_empty() {
        true => unit,
        false => format!("{project}/{unit}"),
    };
    let form = match req.name {
        "is-odd" => ArtifactForm::ZipOfTree,
        _ => ArtifactForm::NativeFile,
    };
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: LANE,
        writes: vec![
            PlannedWrite::GeneratedValue {
                path: lock,
                key: key(req.name, req.version),
            },
            PlannedWrite::Owned(OwnedWrite::Index),
        ],
        repositories: Vec::new(),
        artifacts: vec![ArtifactSpec {
            uuid: req.uuid.to_string(),
            form,
            dir,
            leaf: format!("{}-{}.bin", req.name, req.version),
            digest: digest(),
        }],
        advisories: Vec::new(),
        attest: AttestBasis::LockPath,
        anchor: Anchor::Digest,
    })
}

/// The pin: the package's `resolution:` value becomes the artifact's path
/// and digest. A value that is the pin already is left as it is.
fn toy_rewrite(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
    let Some(lock) = lock_of(cx) else { return };
    let Some(mut text) = files.get(&lock).cloned() else {
        return;
    };
    for pin in pins {
        // A vendored lane: a hosted override is not this writer's.
        let PinSource::Vendored(pin) = pin else {
            continue;
        };
        let Some(at) = resolution(&text, &pin.name, &pin.version) else {
            continue;
        };
        let (old, new) = (text[at.clone()].to_string(), pinned(&pin.path, &pin.digest));
        if old == new {
            continue;
        }
        text.replace_range(at, &new);
        result.edits.push(FileEdit {
            path: lock.clone(),
            kind: "toy-lock".to_string(),
            action: "set".to_string(),
            key: Some(key(&pin.name, &pin.version)),
            original: Some(json!(old)),
            new: Some(json!(new)),
        });
    }
    if files.get(&lock) != Some(&text) {
        result.files.insert(lock.clone(), text.clone());
        files.insert(lock, text);
    }
}

/// The rows of this lane whose value the lock still holds.
fn held<'a>(cx: &'a LaneCx<'_>, text: &'a str) -> impl Iterator<Item = &'a IndexRow> {
    let rows = cx.index.pins.iter().filter(|row| row.lane == LANE.0);
    rows.filter(|row| row.edits.iter().all(|edit| text.contains(&edit.new)))
}

fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let lock = lock_of(cx)?;
    let text = read(&lock)?;
    let pin = |row: &IndexRow| BazelRef {
        lane: LANE,
        purl: row.purl.clone(),
        uuid: row.uuid.clone(),
        file: lock.clone(),
        basis: AttestBasis::LockPath,
    };
    Some(held(cx, &text).map(pin).collect())
}

fn toy_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
    let found = cx.files.read(&pin.file);
    let text = found.as_str().unwrap_or_default();
    let pinned = held(cx, text).any(|row| row.uuid == pin.uuid);
    pinned.then_some(()).ok_or_else(|| VexWithhold {
        kind: WithholdKind::NotConsumed,
        token: None,
        detail: "the lock no longer holds the vendored pin".to_string(),
    })
}

/// The undo of one row: each value goes back only from the value the row
/// wrote. A lock that holds it in any other form has drifted.
fn toy_restore(_: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let Some(mut text) = files.get(&row.file).cloned() else {
        return RestoreOutcome::Drifted(format!("{}: the lock is gone", row.file));
    };
    for edit in row.edits.iter().rev() {
        if text.matches(&edit.new).count() != 1 {
            let why = format!(
                "{}: `{}` is no longer the value socket-patch wrote",
                row.file, edit.key
            );
            return RestoreOutcome::Drifted(why);
        }
        text = text.replacen(&edit.new, &edit.original, 1);
    }
    files.insert(row.file.clone(), text);
    RestoreOutcome::Restored
}

fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    let text = read(&lock_of(cx)?)?;
    let packages = text.split("\npackages:\n").nth(1)?;
    let packages = packages.split("\nsnapshots:\n").next()?;
    let entry = |line: &str| {
        let (name, version) = line
            .strip_prefix("  ")?
            .strip_suffix(':')?
            .rsplit_once('@')?;
        (!name.starts_with(' ')).then(|| LockfileEntry {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.to_string(),
            purl: format!("pkg:npm/{name}@{version}"),
            resolved: None,
            integrity: LockIntegrity::None,
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        })
    };
    Some(packages.lines().filter_map(entry).collect())
}

/// Lands what a transaction staged under `root`, as the commit of a build
/// that has one under a Bazel root does: `Some` bytes are written, `None`
/// is a removal, and a directory a removal leaves empty goes with it.
pub fn land(
    root: &std::path::Path,
    changes: &std::collections::BTreeMap<String, Option<Vec<u8>>>,
) -> std::io::Result<()> {
    for (rel, bytes) in changes {
        let levels = rel.split('/').filter(|level| !level.is_empty());
        let path = levels.fold(root.to_path_buf(), |at, level| at.join(level));
        match bytes {
            Some(bytes) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, bytes)?;
            }
            None => {
                std::fs::remove_file(&path)?;
                // Only an empty directory is removed, and never the root.
                let mut dir = path.parent();
                while let Some(empty) = dir.filter(|dir| *dir != root) {
                    if std::fs::remove_dir(empty).is_err() {
                        break;
                    }
                    dir = empty.parent();
                }
            }
        }
    }
    Ok(())
}
