//! Docker build-proof capstone for `socket-patch vendor` — composer flavor.
//!
//! Proves the CLI_CONTRACT "Vendor command contract" composer row end to end
//! against the REAL composer 2 inside `socket-patch-test-composer:latest`,
//! with state carried across containers via a bind-mounted host tempdir
//! (see `docker_vendor_common/mod.rs`):
//!
//!   stage 1 (networked): `composer update` resolves a real psr/log 3.0.x
//!     from packagist → a marker patch is hand-staged in-container (manifest
//!     + blob; git-blob sha256 computed from the ACTUAL installed bytes) →
//!     `socket-patch vendor --json --offline` (the binary baked into the
//!     image) → asserts: artifact dir + `socket-patch.vendor.json` +
//!     `state.json`, and the composer.lock entry rewired to
//!     `dist: {type: path, url: <copy>, reference: <patch-uuid>}` +
//!     `transport-options: {symlink: false}` + `source` removed, with
//!     composer.json untouched; then `socket-patch vex` attests the vendored
//!     patch (composer has no product auto-detect, so `--product` is
//!     explicit) — exit 0 in-container, the statement body re-asserted
//!     host-side from the mounted out.vex.json.
//!   stage 2 (`--network none`, empty COMPOSER_HOME): ONLY the committable
//!     files (composer.json + composer.lock + .socket/) are copied to a
//!     fresh dir; `composer install` must succeed cold+offline, materialize
//!     `vendor/psr/log` as a REAL directory (not a symlink) whose patched
//!     file is byte-identical to the blob, and propagate the patch uuid
//!     into `vendor/composer/installed.json` (`dist.reference`).
//!   stage 3 (`--network none`): re-vendor is idempotent (already_vendored,
//!     lock sha256-stable) → `vendor --revert` restores composer.lock
//!     byte-identical to the pre-vendor snapshot and removes `.socket/vendor`
//!     entirely → a re-vendor succeeds again.
//!
//! The host side re-asserts the lock wiring independently (serde_json over
//! the mounted composer.lock) so a broken in-container php oracle can't
//! green-light a wrong lock.

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image, run_in_image_network_none,
    skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-composer:latest";
/// Canonical lowercase patch uuid — a dedicated path level under
/// `.socket/vendor/composer/`, and the value `dist.reference` must carry.
const UUID: &str = "21212121-2121-4121-8121-212121212121";
/// The staged patch's vulnerability id — the stage-1 VEX leg must attest
/// exactly this (mirrors GHSA-vend-npm-real / GHSA-vend-cargo-real in the
/// host capstones).
const GHSA: &str = "GHSA-vend-composer-real";

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

/// Stage 1: real fixture install (network OK) + staged marker patch +
/// `vendor --json --offline` + artifact/wiring asserts + fresh-checkout
/// staging of ONLY the committable files.
const STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
# Keep the in-container socket-patch fully offline (also gates telemetry,
# which keys off the env var rather than the --offline flag).
export SOCKET_OFFLINE=1

cat > composer.json <<'EOF'
{
    "name": "socket/vendor-capstone",
    "description": "socket-patch vendor docker capstone fixture",
    "require": {
        "psr/log": "3.0.*"
    }
}
EOF

# 1. REAL fixture: composer update resolves + installs psr/log from packagist.
composer update --no-interaction > /tmp/install.log 2>&1 || {
  cat /tmp/install.log >&2; fail "composer update (fixture install) failed"; }

PSR_VER=$(php -r '
  $l = json_decode(file_get_contents("composer.lock"), true);
  foreach ($l["packages"] as $p) {
    if ($p["name"] === "psr/log") { echo ltrim($p["version"], "v"); exit(0); }
  }
  exit(1);
') || fail "psr/log not present in composer.lock after update"
echo "resolved psr/log version: $PSR_VER" >&2
case "$PSR_VER" in 3.0.*) ;; *) fail "expected a psr/log 3.0.x, got $PSR_VER" ;; esac

ORIG=vendor/psr/log/src/LoggerInterface.php
[ -f "$ORIG" ] || fail "$ORIG missing after composer update"

# Pristine pre-check: without this the post-vendor marker asserts are circular.
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$ORIG" \
  && fail "marker already in $ORIG BEFORE patching — fixture not pristine"

# 2. Marker patch = the ACTUAL installed bytes + a trailing marker comment
#    (still valid php). before/after git-blob hashes computed in-container.
cp "$ORIG" /tmp/patched.php
printf '\n// SOCKET-PATCH-VENDOR-E2E-MARKER patch=__UUID__\n' >> /tmp/patched.php
PURL="pkg:composer/psr/log@$PSR_VER"
stage_patch "$PURL" "__UUID__" "src/LoggerInterface.php" "$ORIG" /tmp/patched.php \
  "__GHSA__" "CVE-2024-66666"

# Pre-vendor snapshots: consumed by stage 2/3 byte-identity asserts.
mkdir -p /workspace/snap
cp composer.json /workspace/snap/composer.json.prevendor
cp composer.lock /workspace/snap/composer.lock.prevendor
sha256sum /tmp/patched.php | cut -d' ' -f1 > /workspace/snap/patched.sha
echo "$PSR_VER" > /workspace/snap/psr-ver

# 3. Vendor (fully offline: the blob is staged locally).
socket-patch vendor --json --offline > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_json_field /tmp/vendor.json '"action": "applied"'
assert_json_field /tmp/vendor.json "$PURL"
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
echo "===VENDOR RUN VERIFIED==="

# 4. Artifact under the stable path convention, patched byte-for-byte,
#    plus the informational marker and the committed ledger.
COPY_REL=".socket/vendor/composer/__UUID__/psr/log@$PSR_VER"
[ -d "$COPY_REL" ] || fail "vendored copy missing at $COPY_REL"
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$COPY_REL/src/LoggerInterface.php" \
  || fail "patched marker missing in the vendored copy"
ACTUAL_SHA=$(sha256sum "$COPY_REL/src/LoggerInterface.php" | cut -d' ' -f1)
[ "$ACTUAL_SHA" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "vendored LoggerInterface.php is not byte-identical to the patch blob"
[ -f ".socket/vendor/composer/__UUID__/socket-patch.vendor.json" ] \
  || fail "informational socket-patch.vendor.json marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (.socket/vendor/state.json) missing"
echo "===ARTIFACT VERIFIED==="

# 5. Lock wiring (the composer contract row): dist → {type: path, url,
#    reference: <patch-uuid>}, transport-options.symlink === false (forces a
#    real copy), source REMOVED; composer.json byte-untouched.
php -r '
  $l = json_decode(file_get_contents("composer.lock"), true);
  [$uuid, $rel] = [$argv[1], $argv[2]];
  foreach ($l["packages"] as $p) {
    if ($p["name"] !== "psr/log") continue;
    if (($p["dist"]["type"] ?? "") !== "path") { fwrite(STDERR, "dist.type != path\n"); exit(1); }
    if (($p["dist"]["url"] ?? "") !== $rel) { fwrite(STDERR, "dist.url=".json_encode($p["dist"]["url"] ?? null)." != $rel\n"); exit(1); }
    if (($p["dist"]["reference"] ?? "") !== $uuid) { fwrite(STDERR, "dist.reference != patch uuid\n"); exit(1); }
    if (array_key_exists("source", $p)) { fwrite(STDERR, "source not removed\n"); exit(1); }
    if (($p["transport-options"]["symlink"] ?? null) !== false) { fwrite(STDERR, "transport-options.symlink !== false\n"); exit(1); }
    exit(0);
  }
  fwrite(STDERR, "psr/log entry not found in composer.lock packages[]\n"); exit(1);
' "__UUID__" "$COPY_REL" || { cat composer.lock >&2; fail "composer.lock wiring wrong"; }
cmp -s composer.json /workspace/snap/composer.json.prevendor \
  || fail "vendor must NOT touch composer.json (lock-only wiring)"
echo "===LOCK WIRING VERIFIED==="

# 6. Real-toolchain VEX: attest the vendored patch against the vendored copy
#    (composer has no product auto-detect — the product purl is explicit).
#    Exit 0 + a non-empty document are asserted here; the statement body is
#    re-asserted host-side (assert_vex_attested_from_host) via serde_json.
socket-patch vex --cwd "$PWD" --output out.vex.json \
  --product "pkg:composer/app@1.0.0" > /tmp/vex.out 2>/tmp/vex.err
RC=$?; cat /tmp/vex.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vex.out >&2; fail "vex exited $RC (expected 0)"; }
[ -s out.vex.json ] || fail "vex did not write out.vex.json"
echo "===VEX RUN VERIFIED==="

# 7. Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp composer.json composer.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Stage 2 (`--network none`): strictest consumption proof. Cold composer
/// home/cache, no registry — the vendored path dist is the only possible
/// source of psr/log.
const STAGE2: &str = r#"
cd /workspace/fresh

# Cold caches: empty COMPOSER_HOME + cache dir, fresh container.
export COMPOSER_HOME=/tmp/cold-composer-home
export COMPOSER_CACHE_DIR=/tmp/cold-composer-cache
mkdir -p "$COMPOSER_HOME" "$COMPOSER_CACHE_DIR"

# The committable set must not have leaked an installed tree.
[ ! -e vendor ] || fail "fresh checkout already has vendor/ (test bug: uncommittable file copied)"

composer install --no-interaction > /tmp/install.log 2>&1 || {
  cat /tmp/install.log >&2; fail "cold-cache offline composer install failed"; }
cat /tmp/install.log >&2

# Real COPY, not a symlink (transport-options symlink:false is load-bearing).
[ -d vendor/psr/log ] || fail "vendor/psr/log missing after install"
[ ! -L vendor/psr/log ] || fail "vendor/psr/log is a SYMLINK — symlink:false not honored"

F=vendor/psr/log/src/LoggerInterface.php
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$F" || { head -5 "$F" >&2; fail "patched marker missing in the installed copy"; }
ACTUAL_SHA=$(sha256sum "$F" | cut -d' ' -f1)
[ "$ACTUAL_SHA" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "installed $F not byte-identical to the patched blob (got $ACTUAL_SHA)"
echo "===FRESH INSTALL VERIFIED==="

# In-tree traceability: composer preserves dist.reference verbatim into
# vendor/composer/installed.json — the patch uuid must survive there.
php -r '
  $i = json_decode(file_get_contents("vendor/composer/installed.json"), true);
  $pkgs = $i["packages"] ?? $i;
  foreach ($pkgs as $p) {
    if (($p["name"] ?? "") !== "psr/log") continue;
    if (($p["dist"]["reference"] ?? "") !== $argv[1]) {
      fwrite(STDERR, "installed.json dist.reference=".json_encode($p["dist"]["reference"] ?? null)." != patch uuid\n"); exit(1);
    }
    exit(0);
  }
  fwrite(STDERR, "psr/log not found in vendor/composer/installed.json\n"); exit(1);
' "__UUID__" || fail "installed.json must carry dist.reference == patch uuid"
echo "===INSTALLED JSON VERIFIED==="
exit 0
"#;

/// Stage 3 (`--network none`): idempotent re-vendor → revert (byte-identical
/// lock restore + full `.socket/vendor` removal) → re-vendor works again.
const STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1
PSR_VER=$(cat /workspace/snap/psr-ver)
COPY_REL=".socket/vendor/composer/__UUID__/psr/log@$PSR_VER"

# 1. Idempotency: a re-run reports already_vendored and leaves the lock
#    byte-stable (sha oracle).
LOCK_SHA_BEFORE=$(sha256sum composer.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA_BEFORE" = "$(sha256sum composer.lock | cut -d' ' -f1)" ] \
  || fail "re-vendor churned composer.lock"
echo "===IDEMPOTENT VERIFIED==="

# 2. Revert: composer.lock byte-identical to the pre-vendor snapshot,
#    .socket/vendor (artifacts + ledger) fully gone.
socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s composer.lock /workspace/snap/composer.lock.prevendor \
  || fail "revert did not restore composer.lock byte-identical to the pre-vendor snapshot"
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert succeeds and rewires again.
socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -d "$COPY_REL" ] || fail "re-vendor did not recreate $COPY_REL"
grep -qF '"type": "path"' composer.lock || fail "re-vendor did not rewire composer.lock"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side independent oracle on the bind-mounted composer.lock: the
/// in-container php asserts and this serde_json check would both have to be
/// wrong in the same way for a mis-wired lock to pass.
fn assert_lock_wired_from_host(host_dir: &std::path::Path) {
    let lock_path = host_dir.join("proj/composer.lock");
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock_path).expect("read mounted composer.lock"))
            .expect("mounted composer.lock parses");
    let psr_ver = std::fs::read_to_string(host_dir.join("snap/psr-ver"))
        .expect("snap/psr-ver")
        .trim()
        .to_string();
    let entry = lock["packages"]
        .as_array()
        .expect("packages[]")
        .iter()
        .find(|p| p["name"] == "psr/log")
        .expect("psr/log entry in mounted composer.lock");
    assert_eq!(
        entry["dist"]["type"], "path",
        "host oracle: dist.type\n{entry}"
    );
    assert_eq!(
        entry["dist"]["url"],
        format!(".socket/vendor/composer/{UUID}/psr/log@{psr_ver}"),
        "host oracle: dist.url\n{entry}"
    );
    assert_eq!(
        entry["dist"]["reference"], UUID,
        "host oracle: dist.reference\n{entry}"
    );
    assert_eq!(
        entry["transport-options"]["symlink"],
        serde_json::Value::Bool(false),
        "host oracle: transport-options.symlink\n{entry}"
    );
    assert!(
        entry.get("source").is_none(),
        "host oracle: source must be removed\n{entry}"
    );
}

/// Host-side oracle on the bind-mounted `out.vex.json` the stage-1 VEX leg
/// wrote: exactly one statement attesting the vendored composer patch as
/// `not_affected` with the `(vendored)` impact marker (mirrors
/// `e2e_vendor_npm_build.rs::npm_vendor_vex_attests_against_vendored_tarball`).
fn assert_vex_attested_from_host(host_dir: &std::path::Path) {
    let psr_ver = std::fs::read_to_string(host_dir.join("snap/psr-ver"))
        .expect("snap/psr-ver")
        .trim()
        .to_string();
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host_dir.join("proj/out.vex.json")).expect("read mounted out.vex.json"),
    )
    .expect("mounted out.vex.json parses");
    let stmts = doc["statements"].as_array().expect("statements[]");
    assert_eq!(
        stmts.len(),
        1,
        "the vendored composer patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"],
        format!("pkg:composer/psr/log@{psr_ver}")
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
fn composer_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize so the macOS `/var` → `/private/var` symlink doesn't
    // confuse Docker Desktop's file-sharing allowlist.
    let host_dir = tmp.path().canonicalize().expect("canonicalize tempdir");

    // Stage 1 — networked fixture install + offline vendor + wiring + VEX
    // asserts.
    let out = run_in_image(IMAGE, &host_dir, &render(STAGE1));
    assert_stage_markers(
        "composer stage 1 (install+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "LOCK WIRING", "VEX RUN", "STAGE1"],
    );
    assert_lock_wired_from_host(&host_dir);
    assert_vex_attested_from_host(&host_dir);

    // Stage 2 — fresh checkout, cold caches, network cut.
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE2));
    assert_stage_markers(
        "composer stage 2 (fresh checkout, --network none)",
        &out,
        &["FRESH INSTALL", "INSTALLED JSON"],
    );

    // Stage 3 — idempotency, revert, re-vendor (still no network).
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE3));
    assert_stage_markers(
        "composer stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    // Suite leaves the project re-vendored; the host oracle must hold again.
    assert_lock_wired_from_host(&host_dir);
}
