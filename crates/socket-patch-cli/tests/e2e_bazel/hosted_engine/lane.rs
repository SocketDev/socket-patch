//! A hosted lane for the tests of the hosted seam, and the workspace it
//! serves. No production lane is enabled, so the built binary never plans
//! a hosted write under a Bazel hub: these tests hand the seam a lane
//! table of their own, in process.
//!
//! The lane pins a package in the `pnpm-lock.yaml` a rules_js hub reads,
//! by replacing the digest of its `resolution:` line with the grant's. It
//! records the digest it replaced as a generated value (a `pins` row,
//! which holds digests and never a URL), so the executor can undo it and
//! the change set of a run holds the lock and the owned index together.
//! It is a test double of a lane, not a claim about what rules_js builds.
//!
//! A second lane, [`NATIVE`], plans the same lock as a native lock: the
//! native pnpm rewriter pins it and no row records the digest, which is
//! the shape of the designed hosted lanes over a package manager's own
//! lock. Its pin is known again only from the lock line.
//!
//! One file for both suites: the unit tests of `src/bazel_gate/hosted.rs`
//! include it by path, and `tests/e2e_bazel/hosted_engine.rs` as its
//! submodule.

use serde_json::json;
use socket_patch_core::bazel::lanes::Proofs;
use socket_patch_core::bazel::model::{
    Anchor, AttestBasis, BazelRef, CellClaim, ClaimSystem, Files, GateOutcome, IndexRow, LaneCx,
    LaneId, LaneOps, LaneSpec, LaneTable, Mode, OwnedWrite, PatchRequest, PinSource, Plan,
    PlannedWrite, RestoreOutcome, Ruleset, TextRead, TokenSurface, VexWithhold, WithholdKind,
    WriteClass,
};
use socket_patch_core::patch::redirect::{DepOverride, FileEdit, Integrity, RewriteResult};
use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

pub const LANE: LaneId = LaneId("H-TOY1");
pub const LOCK: &str = "pnpm-lock.yaml";
pub const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
pub const PURL: &str = "pkg:npm/left-pad@1.3.0";
pub const URL: &str = "https://patch.socket.dev/patch/npm/tok_fixture_4f1c/\
    9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
/// The digest the patch service grants for [`URL`].
pub const PATCHED: &str =
    "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+\
    SfaPg==";
/// The digest of the upstream release, as both locks hold it.
pub const UPSTREAM_SRI: &str =
    "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bzwSkHt2jI5h0c2Mj4bO+\
    A+JX4m7xH1Yr+w==";
/// The value of the upstream `resolution:` line.
pub const UPSTREAM: &str =
    "{integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bzwSkHt2jI5h0c2Mj4bO+\
    A+JX4m7xH1Yr+w==}";

pub const BAZELVERSION: &str = "9.3.2\n";
/// A rules_js hub over the lock at the label `LOCK_LABEL`.
pub const MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"LOCK_LABEL\")\n\
    use_repo(npm, \"npm\")\n";
pub const LOCK_TEXT: &str = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  \
    excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n      \
    left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  \
    left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bzwSkHt2jI5h0c2Mj4bO+\
    A+JX4m7xH1Yr+w==}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
/// A lock of the same ecosystem beside the governed one, which no hub
/// reads: native hosted mode rewrites it and creates `.npmrc` for it.
pub const NPM_LOCK_TEXT: &str = "{\n  \"name\": \"p\",\n  \"version\": \"0.0.0\",\n  \
    \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {\n    \"\": {\n      \
    \"name\": \"p\",\n      \"version\": \"0.0.0\",\n      \"dependencies\": {\n        \
    \"left-pad\": \"1.3.0\"\n      }\n    },\n    \"node_modules/left-pad\": {\n      \
    \"version\": \"1.3.0\",\n      \
    \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\",\n      \
    \"integrity\": \"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bzwSkHt2jI5h0c2Mj4bO+\
    A+JX4m7xH1Yr+w==\"\n    }\n  }\n}\n";

const CLAIMS: &[CellClaim] = &[CellClaim {
    lo: "7.2.0",
    hi: "9.3.2",
    system: ClaimSystem::Bzlmod,
}];
const SPEC: LaneSpec = LaneSpec {
    enabled: true,
    supported: CLAIMS,
    token_surfaces: &[TokenSurface::LockFile],
    classes: &[WriteClass::GeneratedValue, WriteClass::Owned],
    ..LaneSpec::stub("H-TOY1", Mode::Hosted, &[])
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
pub const PROOFS: Proofs = Proofs::PRODUCTION;

/// The grant of the patch of `left-pad`, as the patch service names it.
pub fn grant() -> DepOverride {
    DepOverride {
        ecosystem: "npm".to_string(),
        name: "left-pad".to_string(),
        namespace: None,
        version: "1.3.0".to_string(),
        token: "tok_fixture_4f1c".to_string(),
        patch_uuid: UUID.to_string(),
        artifact_url: URL.to_string(),
        registry_override: None,
        integrity: Integrity {
            sha512: Some(PATCHED.to_string()),
            ..Integrity::default()
        },
    }
}

/// The value of the `resolution:` line once the lane has pinned it.
pub fn pinned() -> String {
    format!("{{integrity: {PATCHED}}}")
}

/// The value native hosted mode writes into the `resolution:` line: the
/// grant's digest and the hosted artifact URL.
pub fn native_pin() -> String {
    format!("{{integrity: {PATCHED}, tarball: {URL}}}")
}

fn key(name: &str, version: &str) -> String {
    format!("packages/{name}@{version}/resolution")
}

/// The byte range of the digest on a package's `resolution:` line.
fn resolution(text: &str, name: &str, version: &str) -> Option<std::ops::Range<usize>> {
    let head = format!("\n  {name}@{version}:\n    resolution: {{integrity: ");
    let start = text.find(&head)? + head.len();
    let end = start + text[start..].find([',', '}', '\r', '\n'])?;
    Some(start..end)
}

/// Whether the lock lists the release among its packages.
fn listed(text: &str, name: &str, version: &str) -> bool {
    text.replace("\r\n", "\n")
        .contains(&format!("\n  {name}@{version}:\n    resolution: "))
}

fn lock_of(cx: &LaneCx<'_>) -> Option<String> {
    cx.ws.hubs.get(cx.hub.0)?.locks.first()?.path.clone()
}

fn toy_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let lock = lock_of(cx).unwrap_or_default();
    let found = cx.files.read(&lock);
    let resolves = |text: &str| listed(text, req.name, req.version);
    if !found.as_str().is_some_and(resolves) {
        // The lock of this hub does not resolve the release.
        return GateOutcome::NotBazel;
    }
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
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::LockUrl,
        anchor: Anchor::Digest,
    })
}

/// The pin: the digest of the package's `resolution:` line becomes the
/// grant's. A line that holds it already is left as it is.
fn toy_rewrite(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
    let Some(lock) = lock_of(cx) else { return };
    let Some(mut text) = files.get(&lock).cloned() else {
        return;
    };
    for pin in pins {
        // A hosted lane: a vendored artifact is not this writer's.
        let PinSource::Hosted(dep) = pin else {
            continue;
        };
        let Some(at) = resolution(&text, &dep.name, &dep.version) else {
            continue;
        };
        let new = dep.integrity.sha512.clone().unwrap_or_default();
        let old = text[at.clone()].to_string();
        if old == new {
            continue;
        }
        text.replace_range(at, &new);
        result.edits.push(FileEdit {
            path: lock.clone(),
            kind: "toy-lock".to_string(),
            action: "set".to_string(),
            key: Some(key(&dep.name, &dep.version)),
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
        basis: AttestBasis::LockUrl,
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
        detail: "the lock no longer holds the hosted pin".to_string(),
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

/// What the lock resolves, each release with the digest its `resolution:`
/// line holds: the digest the build enforces at fetch.
fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    let text = read(&lock_of(cx)?)?.replace("\r\n", "\n");
    let packages = text.split("\npackages:\n").nth(1)?;
    let packages = packages.split("\nsnapshots:\n").next()?;
    let mut entries: Vec<LockfileEntry> = Vec::new();
    for line in packages.lines() {
        let release = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '));
        if let Some((name, version)) = release.and_then(|r| r.strip_suffix(':')?.rsplit_once('@')) {
            entries.push(LockfileEntry {
                ecosystem: "npm",
                name: name.to_string(),
                version: version.to_string(),
                purl: format!("pkg:npm/{name}@{version}"),
                resolved: None,
                integrity: LockIntegrity::None,
                source_kind: SourceKind::Unspecified,
                pnpm_env: false,
            });
            continue;
        }
        let digest = line
            .trim()
            .strip_prefix("resolution: {integrity: ")
            .map(|rest| rest.split([',', '}']).next().unwrap_or_default().trim());
        if let (Some(digest), Some(entry)) = (digest, entries.last_mut()) {
            entry.integrity = LockIntegrity::Sri(digest.to_string());
        }
    }
    Some(entries)
}

// ── A lane over the native lock ──────────────────────────────────────

pub const NATIVE_LANE: LaneId = LaneId("H-TOY2");
const NATIVE_SPEC: LaneSpec = LaneSpec {
    enabled: true,
    supported: CLAIMS,
    token_surfaces: &[TokenSurface::LockFile],
    classes: &[WriteClass::NativeLock],
    ..LaneSpec::stub("H-TOY2", Mode::Hosted, &[])
};
const NATIVE_OPS: LaneOps = LaneOps {
    lanes: &[NATIVE_SPEC],
    gate: native_gate,
    rewrite_owned: |_, _, _, _| {},
    fixups: |_, _, _, _| {},
    discover: native_discover,
    attest: native_attest,
    restore: toy_restore,
    inventory: toy_inventory,
};
/// A table whose one lane leaves the pin to the native pnpm rewriter.
pub const NATIVE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &NATIVE_OPS)]);

fn native_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let lock = lock_of(cx).unwrap_or_default();
    let found = cx.files.read(&lock);
    let resolves = |text: &str| listed(text, req.name, req.version);
    if !found.as_str().is_some_and(resolves) {
        return GateOutcome::NotBazel;
    }
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: NATIVE_LANE,
        writes: vec![PlannedWrite::NativeLock { path: lock }],
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::LockUrl,
        anchor: Anchor::Digest,
    })
}

/// The pins the lock holds: each release whose `resolution:` line names a
/// tarball of the patch service, by the patch UUID in that URL's path.
fn native_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let lock = lock_of(cx)?;
    let text = read(&lock)?.replace("\r\n", "\n");
    let mut pins: Vec<BazelRef> = Vec::new();
    let mut release: Option<(&str, &str)> = None;
    for line in text.lines() {
        let named = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '));
        if let Some(found) = named.and_then(|r| r.strip_suffix(':')?.rsplit_once('@')) {
            release = Some(found);
            continue;
        }
        let url = line.trim().strip_prefix("resolution: {");
        let url = url.and_then(|rest| rest.split("tarball: ").nth(1));
        let url = url.and_then(|rest| rest.split([',', '}']).next());
        let Some(url) = url.map(str::trim) else {
            continue;
        };
        let mut levels = url.rsplit('/');
        if let (Some(_), Some(uuid), Some((name, version))) =
            (levels.next(), levels.next(), release)
        {
            pins.push(BazelRef {
                lane: NATIVE_LANE,
                purl: format!("pkg:npm/{name}@{version}"),
                uuid: uuid.to_string(),
                file: lock.clone(),
                basis: AttestBasis::LockUrl,
            });
        }
    }
    Some(pins)
}

fn native_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
    let read = |rel: &str| cx.files.read(rel).as_str().map(String::from);
    let pins = native_discover(cx, &read).unwrap_or_default();
    let pinned = pins.iter().any(|found| found.uuid == pin.uuid);
    pinned.then_some(()).ok_or_else(|| VexWithhold {
        kind: WithholdKind::NotConsumed,
        token: None,
        detail: "the lock no longer holds the hosted pin".to_string(),
    })
}
