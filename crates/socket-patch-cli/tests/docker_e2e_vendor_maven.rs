//! Docker build-proof capstone for `socket-patch vendor` — maven flavor.
//!
//! Proves the vendored Maven row end to end for a single-module project
//! (planned as a reactor of one, #973) against a REAL Apache Maven + JDK
//! inside `socket-patch-test-maven:latest` (Debian's Maven), with state
//! carried across containers via a bind-mounted host tempdir (see
//! `docker_vendor_common/`). The target is `commons-text:1.10.0`, chosen
//! because it declares exactly one TRANSITIVE dependency (`commons-lang3`) —
//! the leg that proves the vendored pom is the REAL upstream pom (only its
//! version suffixed).
//!
//!   stage 1 (networked): a project depending on commons-text →
//!     `mvn dependency:copy-dependencies` warms the local Maven repo
//!     (`$M2`, bind-mounted) with commons-text + commons-lang3 + the plugin
//!     machinery → a marker patch on the extracted-jar's `META-INF/NOTICE.txt`
//!     is hand-staged (manifest + blob; git-blob sha256 from the ACTUAL cached
//!     bytes) → `socket-patch vendor --json` (baked binary) →
//!     asserts: the patched jar, the suffixed upstream pom (carrying the
//!     commons-lang3 transitive), the `.sha1` sidecars and the ownership
//!     marker under `.socket/vendor/maven2/<g>/<a>/1.10.0-socket.<hex8>/`,
//!     `state.json`, the pinned `<version>` and `socket-patch-vendor`
//!     repository in `pom.xml`, `.mvn/maven.config`, and the wrapper-less
//!     `vendor_jvm_degraded` warnings; then `socket-patch vex` attests the
//!     vendored patch. The committable files (pom.xml + .mvn/ + .socket/)
//!     are staged for stage 2. `$M2` stays WARM: the cached 1.10.0 cannot
//!     shadow the suffixed pin.
//!   stage 2 (`--network none`): consumption proof without Central. Only the
//!     suffixed version is purged from `$M2` before each resolve (older Maven
//!     copies it there from the fallback file repository); the cached
//!     upstream 1.10.0 stays. A RED probe (tree removed → resolve fails)
//!     proves the tree is load-bearing; the GREEN resolve copies the
//!     committed jar byte for byte; a TAMPER probe (mutated jar + stale
//!     sidecar) must fail on the checksum where Maven reads the fallback
//!     `checksumPolicy=fail` repository (before 3.9.2), and is logged on
//!     Maven 3.9.2+ (the repository tail is a local repository).
//!   stage 3 (service available): idempotent re-vendor (`already_vendored`,
//!     every file byte-stable) → `vendor --revert` restores `pom.xml` byte
//!     for byte and removes `.mvn` and `.socket/vendor` → a re-vendor succeeds
//!     again.

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image_network_none,
    run_with_fixture, run_with_service, skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-maven:latest";
/// Canonical lowercase patch uuid; its first 8 hex digits suffix the
/// vendored version.
const UUID: &str = "16161616-1616-4161-8161-161616161616";
/// The suffixed version the planner pins.
const SV: &str = "1.10.0-socket.16161616";
/// The staged patch's vulnerability id — the stage-1 VEX leg must attest
/// exactly this (mirrors GHSA-vend-nuget-real in the nuget capstone).
const GHSA: &str = "GHSA-vend-maven-real";
/// The vendored artifact's PURL (a real Maven Central artifact WITH a
/// transitive dependency: commons-text → commons-lang3).
const PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";

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
    .replace("__SV__", SV)
    .replace("__GHSA__", GHSA)
}

/// Stage 1: real fixture warm (network OK) + staged marker patch inside the jar,
///   then `vendor --json`, artifact/pom/sidecar/pom.xml asserts, VEX,
///   and fresh staging of ONLY the committable files.
const STAGE1: &str = r#"
# The shared local Maven repo (bind-mounted, survives across stages). Both the
# in-container socket-patch crawler (MAVEN_REPO_LOCAL) and mvn (-Dmaven.repo.local)
# point at it so warming, vendoring, and consumption all agree on one cache.
export M2=/workspace/m2
export MAVEN_REPO_LOCAL="$M2"
# Disable telemetry independently of artifact download access.
export SOCKET_TELEMETRY_DISABLED=1
MVN="mvn -q -Dmaven.repo.local=$M2 -Dmaven.test.skip=true -Dstyle.color=never"

mkdir -p /workspace/proj && cd /workspace/proj
cat > pom.xml <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.10.0</version>
    </dependency>
  </dependencies>
</project>
EOF

# 1. REAL fixture: copy-dependencies warms $M2 with commons-text + the
#    commons-lang3 transitive + the plugin machinery, and writes them to disk.
$MVN dependency:copy-dependencies -DoutputDirectory=target/warm > /tmp/warm.log 2>&1 \
  || { cat /tmp/warm.log >&2; fail "mvn warm (fixture) failed"; }
[ -f target/warm/commons-text-1.10.0.jar ]  || { ls target/warm >&2 || true; fail "warm missing commons-text jar"; }
[ -f target/warm/commons-lang3-3.12.0.jar ] || { ls target/warm >&2 || true; fail "warm missing commons-lang3 (transitive) jar"; }

CACHED="$M2/org/apache/commons/commons-text/1.10.0"
CACHED_JAR="$CACHED/commons-text-1.10.0.jar"
CACHED_POM="$CACHED/commons-text-1.10.0.pom"
[ -f "$CACHED_JAR" ] || { ls -R "$CACHED" >&2 || true; fail "cached commons-text jar missing after warm"; }
[ -f "$CACHED_POM" ] || fail "cached commons-text pom missing after warm"
grep -q 'commons-lang3' "$CACHED_POM" || { cat "$CACHED_POM" >&2; fail "upstream pom does not declare the commons-lang3 transitive (fixture wrong)"; }

# 2. Marker patch: the ACTUAL NOTICE.txt inside the cached jar + a trailing
#    marker line. before/after git-blob hashes computed in-container.
rm -rf /tmp/jx && mkdir -p /tmp/jx && ( cd /tmp/jx && jar xf "$CACHED_JAR" )
ORIG=/tmp/jx/META-INF/NOTICE.txt
[ -f "$ORIG" ] || { ls -R /tmp/jx/META-INF >&2 || true; fail "$ORIG missing inside the jar"; }
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$ORIG" && fail "marker already in NOTICE.txt BEFORE patching — fixture not pristine"
cp "$ORIG" /tmp/patched.txt
printf '\nSOCKET-PATCH-VENDOR-E2E-MARKER patch=__UUID__\n' >> /tmp/patched.txt
stage_patch "$PURL_ENV" "__UUID__" "META-INF/NOTICE.txt" "$ORIG" /tmp/patched.txt \
  "__GHSA__" "CVE-2024-88888"

# Pre-vendor snapshots consumed by later stages.
mkdir -p /workspace/snap
cp pom.xml /workspace/snap/pom.prevendor
sha256sum /tmp/patched.txt | cut -d' ' -f1 > /workspace/snap/patched.sha

# 3. Download the artifact published from the staged fixture.
publish_fixture
socket-patch vendor --json > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_json_field /tmp/vendor.json '"action": "applied"'
assert_json_field /tmp/vendor.json "$PURL_ENV"
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
# No Maven Wrapper: both wrapper-less warnings; never the retired shadow one.
assert_json_field /tmp/vendor.json 'reason: maven_f_outside_root: '
assert_json_field /tmp/vendor.json 'reason: maven_mirror_of_all: '
grep -q 'vendor_maven_local_cache_shadow' /tmp/vendor.json && fail "retired shadow warning emitted"
echo "===VENDOR RUN VERIFIED==="

# 4. Artifact: patched jar + suffixed upstream pom + sha1 sidecars + the
#    ownership marker in the suffixed tree; committed ledger.
LEAF=".socket/vendor/maven2/org/apache/commons/commons-text/__SV__"
VJAR="$LEAF/commons-text-__SV__.jar"
VPOM="$LEAF/commons-text-__SV__.pom"
[ -f "$VJAR" ]      || { ls -R .socket/vendor >&2 || true; fail "vendored jar missing at $VJAR"; }
[ -f "$VPOM" ]      || fail "vendored upstream pom missing at $VPOM"
[ -f "$VJAR.sha1" ] || fail "vendored jar sha1 sidecar missing"
[ -f "$VPOM.sha1" ] || fail "vendored pom sha1 sidecar missing"
[ -f "$LEAF/socket-patch.vendor.json" ] || fail "ownership marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (state.json) missing"
[ ! -e ".socket/vendor/maven" ] || fail "the retired .socket/vendor/maven tree was written"
# The vendored pom is the REAL upstream one (carries the transitive), with
# only its version suffixed.
grep -q 'commons-lang3' "$VPOM" || { cat "$VPOM" >&2; fail "vendored pom dropped the commons-lang3 transitive"; }
grep -q '<version>__SV__</version>' "$VPOM" || { cat "$VPOM" >&2; fail "vendored pom is not suffixed"; }
# The patched marker really is inside the rebuilt jar.
rm -rf /tmp/vjx && mkdir -p /tmp/vjx && ( cd /tmp/vjx && jar xf "$OLDPWD/$VJAR" META-INF/NOTICE.txt 2>/dev/null || jar xf "$OLDPWD/$VJAR" )
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' /tmp/vjx/META-INF/NOTICE.txt || fail "rebuilt jar's NOTICE.txt is not patched"
[ "$(sha256sum /tmp/vjx/META-INF/NOTICE.txt | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "rebuilt jar's NOTICE.txt is not byte-identical to the staged patched bytes"
# The sidecar matches the jar bytes (what checksumPolicy=fail validates).
[ "$(sha1sum "$VJAR" | cut -d' ' -f1)" = "$(cat "$VJAR.sha1" | tr -d '[:space:]')" ] || fail "jar .sha1 sidecar does not match the jar bytes"
echo "===ARTIFACT VERIFIED==="

# 5. Wiring: the pinned version, the fallback repository and maven.config.
grep -q '<version>__SV__</version>' pom.xml || { cat pom.xml >&2; fail "pom.xml missing the suffixed pin"; }
grep -q '<id>socket-patch-vendor</id>' pom.xml || { cat pom.xml >&2; fail "pom.xml missing the fallback repository"; }
grep -q '<checksumPolicy>fail</checksumPolicy>' pom.xml || { cat pom.xml >&2; fail "pom.xml repository missing checksumPolicy=fail"; }
grep -q 'maven.repo.local.tail=' .mvn/maven.config || { cat .mvn/maven.config >&2 || true; fail ".mvn/maven.config missing the repository tail"; }
echo "===POM WIRING VERIFIED==="

# 6. Real-toolchain VEX: attest the vendored patch (maven has no product
#    auto-detect — the product purl is explicit).
socket-patch vex --cwd "$PWD" --output out.vex.json \
  --product "pkg:maven/com.example/app@1.0.0" > /tmp/vex.out 2>/tmp/vex.err
RC=$?; cat /tmp/vex.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vex.out >&2; fail "vex exited $RC (expected 0)"; }
[ -s out.vex.json ] || fail "vex did not write out.vex.json"
echo "===VEX RUN VERIFIED==="

# 7. Fresh-checkout staging: ONLY the committable files. $M2 stays warm
#    (the cached upstream 1.10.0 cannot shadow the suffixed pin).
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp pom.xml /workspace/fresh/
cp -R .mvn /workspace/fresh/.mvn
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Stage 2 (`--network none`): cold-for-the-target consumption proof + RED and
/// TAMPER probes. See the module doc for why `--network none` (not `mvn -o`) is
/// the offline lever here.
const STAGE2: &str = r#"
export M2=/workspace/m2
MVN="mvn -q -Dmaven.repo.local=$M2 -Dmaven.test.skip=true -Dstyle.color=never"
cd /workspace/fresh

# The committable set must not have leaked a build/output tree.
[ ! -e target ] || fail "fresh checkout already has target/ (test bug: uncommittable file copied)"

LEAF=".socket/vendor/maven2/org/apache/commons/commons-text/__SV__"
VJAR="$LEAF/commons-text-__SV__.jar"
SUFFIXED="$M2/org/apache/commons/commons-text/__SV__"
[ -f "$M2/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar" ] \
  || fail "the local repository must stay warm with the upstream 1.10.0"

# RED PROBE: with the vendored tree removed (and the suffixed version purged
# from $M2), the resolve MUST fail: the network is cut and no other
# repository has the suffixed version.
cp -r .socket/vendor /tmp/vendor-backup
rm -rf .socket/vendor "$SUFFIXED" target
$MVN dependency:copy-dependencies -DoutputDirectory=target/red > /tmp/red.log 2>&1
RED_RC=$?
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: resolve SUCCEEDED with .socket/vendor removed"; }
grep -qiE 'could not resolve|cannot access|transfer failed|non-resolvable|failure to find|could not find' /tmp/red.log \
  || { cat /tmp/red.log >&2; fail "RED PROBE: resolve failed for an unexpected reason"; }
rm -rf .socket/vendor
cp -r /tmp/vendor-backup .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: network cut, the WARM upstream 1.10.0 still cached: the patched
# suffixed jar can only come from the committed tree.
rm -rf "$SUFFIXED" target
$MVN dependency:copy-dependencies -DoutputDirectory=target/dep > /tmp/green.log 2>&1 \
  || { cat /tmp/green.log >&2; fail "offline resolve against the vendored tree failed"; }
[ -f target/dep/commons-text-__SV__.jar ] || { ls target/dep >&2 || true; fail "patched commons-text jar not copied from the vendored tree"; }
[ ! -e target/dep/commons-text-1.10.0.jar ] || fail "the cached upstream 1.10.0 shadowed the pin"
[ -f target/dep/commons-lang3-3.12.0.jar ] || { ls target/dep >&2 || true; fail "commons-lang3 transitive missing — the vendored pom did not declare it"; }
cmp -s target/dep/commons-text-__SV__.jar "$VJAR" \
  || fail "resolved commons-text jar is not byte-identical to the vendored jar"
rm -rf /tmp/cjx && mkdir -p /tmp/cjx && ( cd /tmp/cjx && jar xf "/workspace/fresh/target/dep/commons-text-__SV__.jar" META-INF/NOTICE.txt 2>/dev/null || jar xf "/workspace/fresh/target/dep/commons-text-__SV__.jar" )
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' /tmp/cjx/META-INF/NOTICE.txt || fail "consumed commons-text jar is not patched"
[ "$(sha256sum /tmp/cjx/META-INF/NOTICE.txt | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "consumed NOTICE.txt is not byte-identical to the staged patched bytes"
echo "===FRESH INSTALL VERIFIED==="

# TAMPER PROBE: mutate the vendored jar (leaving its .sha1 stale) and force a
# cold re-resolve. Before Maven 3.9.2 the fallback file repository
# (checksumPolicy=fail) serves it, so the resolve must fail on the checksum.
# 3.9.2+ reads the repository tail, a local repository Maven does not
# checksum; that outcome is logged (VEX never attests a tampered tree).
MVN_VERSION=$(mvn -v 2>/dev/null | head -1 | sed -E 's/^Apache Maven ([0-9.]+).*/\1/')
cp "$VJAR" /tmp/vjar.pristine
printf 'TAMPER' >> "$VJAR"
rm -rf "$SUFFIXED" target
$MVN dependency:copy-dependencies -DoutputDirectory=target/tamper > /tmp/tamper.log 2>&1
TAMPER_RC=$?
if [ "$(printf '%s\n3.9.2\n' "$MVN_VERSION" | sort -V | head -1)" != "3.9.2" ]; then
  [ "$TAMPER_RC" -ne 0 ] || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE VACUOUS: Maven $MVN_VERSION resolved a mutated jar"; }
  grep -qi 'checksum' /tmp/tamper.log || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE: expected a checksum validation failure"; }
else
  echo "TAMPER (Maven $MVN_VERSION, repository tail): exit $TAMPER_RC" >&2
fi
cp /tmp/vjar.pristine "$VJAR"
rm -rf "$SUFFIXED" target
echo "===TAMPER CHECKSUM VERIFIED==="
exit 0
"#;

/// Stage 3 (service available): re-warm the target from the project's own clean
/// vendored repo, then idempotent re-vendor → revert (byte-identical pom.xml
/// restore + full `.socket/vendor` removal) → re-vendor works again.
const STAGE3: &str = r#"
export M2=/workspace/m2
export MAVEN_REPO_LOCAL="$M2"
export SOCKET_TELEMETRY_DISABLED=1
MVN="mvn -q -Dmaven.repo.local=$M2 -Dmaven.test.skip=true -Dstyle.color=never"
cd /workspace/proj
LEAF=".socket/vendor/maven2/org/apache/commons/commons-text/__SV__"
VJAR="$LEAF/commons-text-__SV__.jar"
[ -f "$M2/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar" ] \
  || fail "the warm upstream 1.10.0 the crawler reads is gone"

# 1. Idempotency: a re-run reports already_vendored, pom.xml + jar byte-stable.
POM_SHA_BEFORE=$(sha256sum pom.xml | cut -d' ' -f1)
JAR_SHA_BEFORE=$(sha256sum "$VJAR" | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$POM_SHA_BEFORE" = "$(sha256sum pom.xml | cut -d' ' -f1)" ] || fail "re-vendor churned pom.xml"
[ "$JAR_SHA_BEFORE" = "$(sha256sum "$VJAR" | cut -d' ' -f1)" ] || fail "re-vendor churned the vendored jar"
echo "===IDEMPOTENT VERIFIED==="

# 2. Revert: pom.xml byte-identical to the pre-vendor snapshot, .socket/vendor
#    fully gone.
socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s pom.xml /workspace/snap/pom.prevendor \
  || { diff /workspace/snap/pom.prevendor pom.xml >&2 || true; fail "revert did not byte-restore pom.xml"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
[ ! -e .mvn ] || fail ".mvn must be removed after revert"
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert succeeds and rewires again.
socket-patch vendor --json > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -f "$VJAR" ] || fail "re-vendor did not recreate the vendored jar"
grep -q '<version>__SV__</version>' pom.xml || fail "re-vendor did not re-pin the version"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side independent oracle on the bind-mounted project: the pinned
/// `<version>` and fallback repository in `pom.xml`, `.mvn/maven.config`,
/// and the `.jar.sha1` sidecar (== sha1 of the mounted vendored jar). The
/// in-container asserts and these would both have to be wrong in the same
/// way for a mis-wired project to pass.
fn assert_pom_and_sidecar_from_host(host_dir: &std::path::Path) {
    use sha1::{Digest as _, Sha1};

    let proj = host_dir.join("proj");
    let pom = std::fs::read_to_string(proj.join("pom.xml")).expect("read mounted pom.xml");
    for needle in [
        format!("<version>{SV}</version>"),
        "<id>socket-patch-vendor</id>".to_string(),
        "<checksumPolicy>fail</checksumPolicy>".to_string(),
    ] {
        assert!(
            pom.contains(&needle),
            "host oracle: pom.xml lacks {needle}\n{pom}"
        );
    }
    let config =
        std::fs::read_to_string(proj.join(".mvn/maven.config")).expect("read .mvn/maven.config");
    assert!(
        config.contains("-Dmaven.repo.local.tail="),
        "host oracle: maven.config\n{config}"
    );

    let jar_rel =
        format!(".socket/vendor/maven2/org/apache/commons/commons-text/{SV}/commons-text-{SV}.jar");
    let jar = std::fs::read(proj.join(&jar_rel)).expect("read mounted vendored jar");
    let want = hex::encode(Sha1::digest(&jar));
    let sidecar = std::fs::read_to_string(proj.join(format!("{jar_rel}.sha1")))
        .expect("read mounted jar .sha1 sidecar");
    assert_eq!(
        sidecar.trim(),
        want,
        "host oracle: .jar.sha1 sidecar must equal sha1(vendored jar)"
    );
}

/// Host-side oracle on the bind-mounted `out.vex.json`: exactly one statement
/// attesting the vendored maven patch as `not_affected` with the `(vendored)`
/// impact marker (mirrors the nuget capstone).
fn assert_vex_attested_from_host(host_dir: &std::path::Path) {
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host_dir.join("proj/out.vex.json")).expect("read mounted out.vex.json"),
    )
    .expect("mounted out.vex.json parses");
    let stmts = doc["statements"].as_array().expect("statements[]");
    assert_eq!(
        stmts.len(),
        1,
        "the vendored maven patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL,
        "the attested subcomponent is the vendored maven purl"
    );
    let impact = stmts[0]["impact_statement"]
        .as_str()
        .expect("impact_statement");
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );
}

/// Host-side MANIFEST-LESS VEX over the stage-2 fresh checkout (the one real
/// Maven just consumed with the network cut). The bind-mounted tree is
/// root-owned on Linux, so only its committable files (`pom.xml` +
/// `.socket/`, never `target/`) are copied into a host-owned dir, where
/// the host binary runs against a wiremock patch API serving the SAME
/// record the ledger embedded:
///
/// * manifest deleted, ledger kept → attested `(vendored)` offline and
///   online, and by the embedded `vendor --vex` with no manifest;
/// * ledgers deleted → nothing is discovered (a planner pin is attributed
///   only through its ledger), online or offline;
/// * the pom reverted to its pre-vendor bytes (ledger + tree kept) →
///   `vendor_unwired`, with and without `--no-verify`.
fn assert_manifestless_vex_from_host(host_dir: &std::path::Path) {
    use vex_e2e_common::*;
    let src = host_dir.join("fresh");
    let copy = tempfile::tempdir().expect("host copy");
    let fresh = copy.path().join("fresh");
    copy_tree(&src.join(".socket"), &fresh.join(".socket"));
    copy_tree(&src.join(".mvn"), &fresh.join(".mvn"));
    std::fs::copy(src.join("pom.xml"), fresh.join("pom.xml")).expect("copy pom.xml");
    strip_manifest(&fresh);

    let ledger_path = fresh.join(".socket/vendor/state.json");
    let ledger_bytes = std::fs::read(&ledger_path).expect("vendor ledger");
    let ledger: serde_json::Value = serde_json::from_slice(&ledger_bytes).expect("ledger JSON");
    let record = &ledger["entries"][PURL]["record"];
    let after = record["files"]["META-INF/NOTICE.txt"]["afterHash"]
        .as_str()
        .unwrap_or_else(|| panic!("the ledger embeds the record: {ledger:#}"))
        .to_string();
    let vulns: [(&str, &[&str]); 1] = [(GHSA, &["CVE-2024-88888"])];
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(UUID, PURL, &[("META-INF/NOTICE.txt", &after)], &vulns),
    )]);
    let m2 = tempfile::tempdir().expect("empty maven repo");
    let run = VexRun {
        product: Some("pkg:maven/com.example/app@1.0.0".to_string()),
        ..VexRun::online(&api)
    }
    .env("MAVEN_REPO_LOCAL", m2.path().as_os_str());
    let offline = |no_verify: bool| {
        let quiet = PatchApi::empty();
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                offline: true,
                no_verify,
                proxy_url: Some(quiet.uri()),
                ..run.clone()
            },
        );
        quiet.assert_no_requests();
        out
    };

    let out = offline(false);
    assert_eq!(out.code, Some(0), "ledger, offline: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Vendored, &vulns);
    let out = run_vex(&binary(), &fresh, &run);
    assert_eq!(out.code, Some(0), "ledger, online: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Vendored, &vulns);

    let out = run_vex(
        &binary(),
        &fresh,
        &VexRun {
            via: VexVia::Vendor,
            ..run.clone()
        },
    );
    assert_eq!(out.code, Some(0), "vendor --vex, no manifest: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Vendored, &vulns);

    strip_ledgers(&fresh);
    for out in [run_vex(&binary(), &fresh, &run), offline(false)] {
        assert_eq!(out.code, Some(2), "no ledgers: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "manifest_not_found",
            "no ledgers: {out}"
        );
    }

    std::fs::copy(host_dir.join("snap/pom.prevendor"), fresh.join("pom.xml"))
        .expect("restore the pre-vendor pom");
    std::fs::remove_dir_all(fresh.join(".mvn")).expect("drop .mvn");
    std::fs::write(&ledger_path, &ledger_bytes).unwrap();
    for no_verify in [false, true] {
        let out = offline(no_verify);
        assert_eq!(out.code, Some(1), "reverted no_verify={no_verify}: {out}");
        assert_not_attested(&out.envelope, PURL, "vendor_unwired");
    }
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Export `PURL_ENV` into the stage script's shell (the purl carries an `@` the
/// bash body reads as a variable) — kept out of `render`'s literal replaces.
fn with_purl_env(body: &str) -> String {
    format!("export PURL_ENV='{PURL}'\n{body}")
}

#[test]
fn maven_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize so the macOS `/var` → `/private/var` symlink doesn't confuse
    // Docker Desktop's file-sharing allowlist.
    let host_dir = tmp.path().canonicalize().expect("canonicalize tempdir");

    // Stage 1 — networked fixture warm + service download + wiring + VEX.
    let (out, service) = run_with_fixture(IMAGE, &host_dir, &with_purl_env(&render(STAGE1)));
    assert_stage_markers(
        "maven stage 1 (warm+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "POM WIRING", "VEX RUN", "STAGE1"],
    );
    assert_pom_and_sidecar_from_host(&host_dir);
    assert_vex_attested_from_host(&host_dir);

    // Stage 2 — fresh checkout, network cut, the committed tree the only
    // source of the patched target (+ RED + TAMPER probes).
    let out = run_in_image_network_none(IMAGE, &host_dir, &with_purl_env(&render(STAGE2)));
    assert_stage_markers(
        "maven stage 2 (fresh checkout, --network none)",
        &out,
        &["RED PROBE", "FRESH INSTALL", "TAMPER CHECKSUM"],
    );
    // The consumed fresh checkout, attested with no manifest (host side).
    assert_manifestless_vex_from_host(&host_dir);

    // Stage 3 — idempotency, revert, redownload after revert.
    let out = run_with_service(
        IMAGE,
        &host_dir,
        &with_purl_env(&render(STAGE3)),
        &service.docker_uri(),
    );
    assert_stage_markers(
        "maven stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    // Suite leaves the project re-vendored; the host oracle must hold again.
    assert_pom_and_sidecar_from_host(&host_dir);
}
