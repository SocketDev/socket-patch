//! Docker build-proof capstone for `socket-patch vendor` — nuget flavor.
//!
//! Proves the vendor "NuGet feed" row end to end against the REAL .NET SDK 8.0
//! inside `socket-patch-test-nuget:latest`, with state carried across
//! containers via a bind-mounted host tempdir (see `docker_vendor_common/`):
//!
//!   stage 1 (networked): a net8.0 project with
//!     `RestorePackagesWithLockFile=true` referencing Newtonsoft.Json 13.0.3 →
//!     `dotnet restore` resolves it from nuget.org and writes
//!     `packages.lock.json` → a marker patch on the extracted `LICENSE.md` is
//!     hand-staged (manifest + blob; git-blob sha256 from the ACTUAL installed
//!     bytes) → `socket-patch vendor --json --offline` (the baked binary, with
//!     `SOCKET_EXPERIMENTAL_NUGET=1`) → asserts: the rebuilt `.nupkg` under
//!     `.socket/vendor/nuget/<uuid>/`, `socket-patch.vendor.json`, `state.json`,
//!     the created `nuget.config` (our source + a `packageSourceMapping` for
//!     the id), and `packages.lock.json` repinned to `base64(sha512(nupkg))`;
//!     then `socket-patch vex` attests the vendored patch. Host-side oracles
//!     re-check the config, the lock contentHash, and the VEX document.
//!   stage 2 (`--network none`, cold `NUGET_PACKAGES`): ONLY the committable
//!     files (csproj + packages.lock.json + nuget.config + .socket/) are copied
//!     to a fresh dir; `dotnet restore --locked-mode` must succeed cold+offline
//!     (the vendored feed is the only Newtonsoft.Json source) and the extracted
//!     `LICENSE.md` must be byte-identical to the patch blob. A RED probe
//!     (delete `.socket/vendor` → restore MUST fail) proves the install
//!     genuinely depends on the vendored feed, and a TAMPER probe (append bytes
//!     to the vendored nupkg, cold restore) must fail NU1403 (the contentHash
//!     pin catches it).
//!   stage 3 (`--network none`): re-vendor is idempotent (already_vendored,
//!     lock + nupkg byte-stable) → `vendor --revert` restores
//!     `packages.lock.json` byte-identical, DELETES the created `nuget.config`,
//!     and removes `.socket/vendor` → a re-vendor succeeds again.

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image, run_in_image_network_none,
    skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-nuget:latest";
/// Canonical lowercase patch uuid — a dedicated path level under
/// `.socket/vendor/nuget/` and the suffix of the created source key.
const UUID: &str = "19191919-1919-4191-8191-191919191919";
/// The staged patch's vulnerability id — the stage-1 VEX leg must attest
/// exactly this (mirrors GHSA-vend-composer-real in the composer capstone).
const GHSA: &str = "GHSA-vend-nuget-real";

/// Glue the shared bash helpers onto a stage body and pin the uuid + ghsa.
fn render(stage_body: &str) -> String {
    format!(
        "{}{}{}{}",
        bash_prelude(),
        stage_patch_fn(),
        json_assert_fns(),
        stage_body
    )
    .replace("__UUID__", UUID)
    .replace("__GHSA__", GHSA)
}

/// Stage 1: real fixture restore (network OK) + staged marker patch +
/// `vendor --json --offline` + artifact/config/lock asserts + VEX + fresh
/// staging of ONLY the committable files.
const STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
# Keep the in-container socket-patch fully offline (also gates telemetry) and
# opt in to the experimental NuGet dispatch tier.
export SOCKET_OFFLINE=1
export SOCKET_EXPERIMENTAL_NUGET=1
# Project-local global package cache so the crawler + rebuild find the nupkg
# deterministically; stage 2 uses a DIFFERENT cold dir.
export NUGET_PACKAGES="$PWD/.nuget-packages"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

cat > app.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
EOF

# 1. REAL fixture: dotnet restore resolves + caches Newtonsoft.Json + writes lock.
dotnet restore > /tmp/restore.log 2>&1 || { cat /tmp/restore.log >&2; fail "dotnet restore (fixture) failed"; }
[ -f packages.lock.json ] || { cat /tmp/restore.log >&2; fail "no packages.lock.json after restore"; }

ORIG=.nuget-packages/newtonsoft.json/13.0.3/LICENSE.md
[ -f "$ORIG" ] || { ls -R .nuget-packages/newtonsoft.json >&2 || true; fail "$ORIG missing after restore"; }

# Pristine pre-check: without this the post-vendor marker asserts are circular.
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$ORIG" \
  && fail "marker already in $ORIG BEFORE patching — fixture not pristine"

# 2. Marker patch = the ACTUAL cached LICENSE.md + a trailing marker line.
#    before/after git-blob hashes computed in-container.
cp "$ORIG" /tmp/patched.md
printf '\nSOCKET-PATCH-VENDOR-E2E-MARKER patch=__UUID__\n' >> /tmp/patched.md
PURL="pkg:nuget/Newtonsoft.Json@13.0.3"
stage_patch "$PURL" "__UUID__" "LICENSE.md" "$ORIG" /tmp/patched.md \
  "__GHSA__" "CVE-2024-77777"

# Pre-vendor snapshots: consumed by stage 2/3 byte-identity asserts.
mkdir -p /workspace/snap
cp packages.lock.json /workspace/snap/packages.lock.prevendor
sha256sum /tmp/patched.md | cut -d' ' -f1 > /workspace/snap/patched.sha

# 3. Vendor (fully offline: the blob is staged locally; nupkg rebuilt from cache).
socket-patch vendor --json --offline > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_json_field /tmp/vendor.json '"action": "applied"'
assert_json_field /tmp/vendor.json "$PURL"
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
echo "===VENDOR RUN VERIFIED==="

# 4. Artifact: rebuilt nupkg at the stable path, plus the informational marker
#    + committed ledger. (The dotnet SDK image has no unzip/python, so the
#    patched-content-INSIDE-the-nupkg proof is deferred to stage 2's real
#    offline `dotnet restore` extraction; the contentHash host oracle below
#    ties the lock to these exact bytes, and the signature-drop is covered by
#    the Rust unit tests.)
NUPKG=".socket/vendor/nuget/__UUID__/newtonsoft.json.13.0.3.nupkg"
[ -f "$NUPKG" ] || { ls -R .socket/vendor >&2 || true; fail "vendored nupkg missing at $NUPKG"; }
[ -f ".socket/vendor/nuget/__UUID__/socket-patch.vendor.json" ] \
  || fail "informational socket-patch.vendor.json marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (.socket/vendor/state.json) missing"
echo "===ARTIFACT VERIFIED==="

# 5. nuget.config wiring: our source + a packageSourceMapping for the id.
[ -f nuget.config ] || fail "vendor did not create nuget.config"
grep -q "socket-patch-__UUID__" nuget.config || { cat nuget.config >&2; fail "nuget.config missing our source key"; }
grep -q 'pattern="Newtonsoft.Json"' nuget.config || { cat nuget.config >&2; fail "nuget.config missing the id mapping"; }

# 6. packages.lock.json repinned to base64(sha512(vendored nupkg)).
WANT_HASH=$(openssl dgst -sha512 -binary "$NUPKG" | openssl base64 -A)
echo "$WANT_HASH" > /workspace/snap/content-hash
grep -qF "$WANT_HASH" packages.lock.json \
  || { cat packages.lock.json >&2; fail "packages.lock.json contentHash not repinned to the vendored nupkg"; }
echo "===LOCK WIRING VERIFIED==="

# 7. Real-toolchain VEX: attest the vendored patch (nuget has no product
#    auto-detect — the product purl is explicit).
socket-patch vex --cwd "$PWD" --output out.vex.json \
  --product "pkg:nuget/app@1.0.0" > /tmp/vex.out 2>/tmp/vex.err
RC=$?; cat /tmp/vex.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vex.out >&2; fail "vex exited $RC (expected 0)"; }
[ -s out.vex.json ] || fail "vex did not write out.vex.json"
echo "===VEX RUN VERIFIED==="

# 8. Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp app.csproj packages.lock.json nuget.config /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Stage 2 (`--network none`): strictest consumption proof — cold
/// `NUGET_PACKAGES`, no registry — the vendored feed is the only source of
/// Newtonsoft.Json. Includes a RED probe (feed removed → fail) and a TAMPER
/// probe (nupkg mutated → NU1403).
const STAGE2: &str = r#"
cd /workspace/fresh
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# The committable set must not have leaked a restore/output tree.
[ ! -e obj ] || fail "fresh checkout already has obj/ (test bug: uncommittable file copied)"
[ ! -e .nuget-packages ] || fail "fresh checkout carried the project-local package cache (should be gitignored)"

# RED PROBE: with the vendored feed removed, the strictest restore MUST fail
# (Newtonsoft.Json is mapped ONLY to the now-missing source).
mv .socket/vendor /tmp/vendor-stash
export NUGET_PACKAGES=/tmp/cold-nuget-red
rm -rf obj
dotnet restore --locked-mode > /tmp/red.log 2>&1
RED_RC=$?
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: restore SUCCEEDED with .socket/vendor removed"; }
# NU1301 = the vendored local source folder is gone; NU110x = the package
# can't be found anywhere (mapped only to that now-missing source). Either is
# the expected consequence of deleting the feed — a different error would be a
# false-negative probe.
grep -qE 'NU1301|NU110[0-9]|doesn.t exist|Unable to find|Unable to load' /tmp/red.log \
  || { cat /tmp/red.log >&2; fail "RED PROBE: restore failed for an unexpected reason"; }
mv /tmp/vendor-stash .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: cold cache, network cut, the vendored feed is the only source.
export NUGET_PACKAGES=/tmp/cold-nuget-green
rm -rf obj
dotnet restore --locked-mode > /tmp/restore.log 2>&1 || { cat /tmp/restore.log >&2; fail "cold-cache offline dotnet restore --locked-mode failed"; }
cat /tmp/restore.log >&2

# The extracted LICENSE.md must be the PATCHED bytes.
F="$NUGET_PACKAGES/newtonsoft.json/13.0.3/LICENSE.md"
[ -f "$F" ] || { ls -R "$NUGET_PACKAGES/newtonsoft.json" >&2 || true; fail "$F missing after restore"; }
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$F" || { head -5 "$F" >&2; fail "installed LICENSE.md is not patched"; }
[ "$(sha256sum "$F" | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "installed LICENSE.md not byte-identical to the patched blob"
echo "===FRESH INSTALL VERIFIED==="

# TAMPER PROBE: mutate the vendored nupkg → the contentHash pin must reject it
# (NU1403) on a cold restore.
printf 'TAMPER' >> .socket/vendor/nuget/__UUID__/newtonsoft.json.13.0.3.nupkg
export NUGET_PACKAGES=/tmp/cold-nuget-tamper
rm -rf obj
dotnet restore --locked-mode > /tmp/tamper.log 2>&1
TAMPER_RC=$?
[ "$TAMPER_RC" -ne 0 ] || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE VACUOUS: restore SUCCEEDED on a mutated nupkg"; }
grep -q 'NU1403' /tmp/tamper.log \
  || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE: expected NU1403 content-hash failure"; }
echo "===TAMPER NU1403 VERIFIED==="
exit 0
"#;

/// Stage 3 (`--network none`): idempotent re-vendor → revert (byte-identical
/// lock restore + created-config deletion + full `.socket/vendor` removal) →
/// re-vendor works again.
const STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1
export SOCKET_EXPERIMENTAL_NUGET=1
export NUGET_PACKAGES="$PWD/.nuget-packages"
NUPKG=".socket/vendor/nuget/__UUID__/newtonsoft.json.13.0.3.nupkg"

# 1. Idempotency: a re-run reports already_vendored and leaves the lock + nupkg
#    byte-stable.
LOCK_SHA_BEFORE=$(sha256sum packages.lock.json | cut -d' ' -f1)
NUPKG_SHA_BEFORE=$(sha256sum "$NUPKG" | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA_BEFORE" = "$(sha256sum packages.lock.json | cut -d' ' -f1)" ] || fail "re-vendor churned packages.lock.json"
[ "$NUPKG_SHA_BEFORE" = "$(sha256sum "$NUPKG" | cut -d' ' -f1)" ] || fail "re-vendor churned the vendored nupkg"
echo "===IDEMPOTENT VERIFIED==="

# 2. Revert: packages.lock.json byte-identical to the pre-vendor snapshot, the
#    created nuget.config deleted, .socket/vendor fully gone.
socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s packages.lock.json /workspace/snap/packages.lock.prevendor \
  || { diff /workspace/snap/packages.lock.prevendor packages.lock.json >&2 || true; fail "revert did not byte-restore packages.lock.json"; }
[ ! -e nuget.config ] || fail "revert must delete the created nuget.config"
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert succeeds and rewires again.
socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -f "$NUPKG" ] || fail "re-vendor did not recreate $NUPKG"
[ -f nuget.config ] || fail "re-vendor did not recreate nuget.config"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side independent oracles on the bind-mounted project: the nuget.config
/// wiring and the packages.lock.json contentHash pin (== base64(sha512) of the
/// mounted vendored nupkg). The in-container asserts and these would both have
/// to be wrong in the same way for a mis-wired project to pass.
fn assert_config_and_lock_from_host(host_dir: &std::path::Path) {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha512};

    let proj = host_dir.join("proj");
    let config =
        std::fs::read_to_string(proj.join("nuget.config")).expect("read mounted nuget.config");
    assert!(
        config.contains(&format!("socket-patch-{UUID}")),
        "host oracle: nuget.config source key\n{config}"
    );
    assert!(
        config.contains("pattern=\"Newtonsoft.Json\""),
        "host oracle: nuget.config id mapping\n{config}"
    );

    let nupkg = std::fs::read(proj.join(format!(
        ".socket/vendor/nuget/{UUID}/newtonsoft.json.13.0.3.nupkg"
    )))
    .expect("read mounted vendored nupkg");
    let want = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&nupkg));

    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("packages.lock.json")).expect("read lock"))
            .expect("mounted packages.lock.json parses");
    let deps = lock["dependencies"].as_object().expect("dependencies{}");
    let mut checked = 0usize;
    for framework in deps.values() {
        let Some(pkgs) = framework.as_object() else {
            continue;
        };
        for (name, entry) in pkgs {
            if !name.eq_ignore_ascii_case("Newtonsoft.Json") {
                continue;
            }
            assert_eq!(
                entry["contentHash"].as_str(),
                Some(want.as_str()),
                "host oracle: contentHash pinned to the vendored nupkg for {name}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "host oracle: no Newtonsoft.Json lock entry found"
    );
}

/// Host-side oracle on the bind-mounted `out.vex.json`: exactly one statement
/// attesting the vendored nuget patch as `not_affected` with the `(vendored)`
/// impact marker (mirrors the composer capstone).
fn assert_vex_attested_from_host(host_dir: &std::path::Path) {
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host_dir.join("proj/out.vex.json")).expect("read mounted out.vex.json"),
    )
    .expect("mounted out.vex.json parses");
    let stmts = doc["statements"].as_array().expect("statements[]");
    assert_eq!(
        stmts.len(),
        1,
        "the vendored nuget patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"],
        "pkg:nuget/Newtonsoft.Json@13.0.3"
    );
    let impact = stmts[0]["impact_statement"]
        .as_str()
        .expect("impact_statement");
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );
}

#[test]
fn nuget_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize so the macOS `/var` → `/private/var` symlink doesn't confuse
    // Docker Desktop's file-sharing allowlist.
    let host_dir = tmp.path().canonicalize().expect("canonicalize tempdir");

    // Stage 1 — networked fixture restore + offline vendor + wiring + VEX.
    let out = run_in_image(IMAGE, &host_dir, &render(STAGE1));
    assert_stage_markers(
        "nuget stage 1 (restore+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "LOCK WIRING", "VEX RUN", "STAGE1"],
    );
    assert_config_and_lock_from_host(&host_dir);
    assert_vex_attested_from_host(&host_dir);

    // Stage 2 — fresh checkout, cold cache, network cut (+ RED + TAMPER probes).
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE2));
    assert_stage_markers(
        "nuget stage 2 (fresh checkout, --network none)",
        &out,
        &["RED PROBE", "FRESH INSTALL", "TAMPER NU1403"],
    );

    // Stage 3 — idempotency, revert, re-vendor (still no network).
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE3));
    assert_stage_markers(
        "nuget stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    // Suite leaves the project re-vendored; the host oracle must hold again.
    assert_config_and_lock_from_host(&host_dir);
}
