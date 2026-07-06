//! Docker build-proof capstone for `socket-patch vendor` — maven flavor.
//!
//! Proves the vendor "maven2 file:// repository" row end to end against a REAL
//! Apache Maven + JDK inside `socket-patch-test-maven:latest`, with state
//! carried across containers via a bind-mounted host tempdir (see
//! `docker_vendor_common/`). The target is `commons-text:1.10.0`, chosen
//! because it declares exactly one TRANSITIVE dependency (`commons-lang3`) —
//! the leg that proves the vendored pom is the REAL upstream pom (a fabricated
//! minimal pom would silently drop the transitive).
//!
//!   stage 1 (networked): a project depending on commons-text →
//!     `mvn dependency:copy-dependencies` warms the local Maven repo
//!     (`$M2`, bind-mounted) with commons-text + commons-lang3 + the plugin
//!     machinery → a marker patch on the extracted-jar's `META-INF/NOTICE.txt`
//!     is hand-staged (manifest + blob; git-blob sha256 from the ACTUAL cached
//!     bytes) → `socket-patch vendor --json --offline` (baked binary,
//!     `SOCKET_EXPERIMENTAL_MAVEN=1`) → asserts: the rebuilt `.jar` under the
//!     maven2 leaf `.socket/vendor/maven/<uuid>/…`, the verbatim upstream pom
//!     beside it (carrying the commons-lang3 transitive), the `.sha1` sidecars,
//!     `socket-patch.vendor.json`, `state.json`, the `<repository>` inserted
//!     into `pom.xml` (id + file:// url + checksumPolicy=fail), and the
//!     ALWAYS-ON `vendor_maven_local_cache_shadow` advisory; then
//!     `socket-patch vex` attests the vendored patch. Finally commons-text is
//!     PURGED from `$M2` and only the committable files (pom.xml + .socket/)
//!     are staged for stage 2.
//!   stage 2 (`--network none`): strictest consumption proof. Maven checks the
//!     LOCAL repo before any `<repository>`, so `$M2` keeps the plugins + the
//!     commons-lang3 transitive but has commons-text PURGED — the vendored
//!     file:// repo is therefore the ONLY source of the patched commons-text.
//!     NOTE: `mvn -o` (offline mode) REFUSES file:// repositories outright
//!     ("Cannot access … in offline mode"); the vendored feed is exercised by
//!     CUTTING THE NETWORK at the container level (`--network none`) WITHOUT
//!     `-o`, so file:// stays usable while Maven Central is unreachable — the
//!     maven analog of the nuget capstone's `--network none` + local folder
//!     feed. A RED probe (feed removed → resolve fails) proves the feed is
//!     load-bearing; a TAMPER probe (mutated jar + stale sidecar → cold
//!     re-resolve) proves `checksumPolicy=fail` rejects it.
//!
//!     What offline CAN prove here: (a) the patched commons-text.jar is served
//!     from the file:// vendored repo (byte-identical to the committed jar, and
//!     it was PURGED from `$M2` so it can only have come from file://); (b) the
//!     vendored pom carries the REAL transitive declaration (commons-lang3
//!     lands in the copy-dependencies output). What offline CANNOT prove: that
//!     the transitive was freshly fetched — it is resolved from the warm `$M2`
//!     cache. That is the point: the pom must DECLARE it, which a minimal pom
//!     would not.
//!   stage 3 (`--network none`): re-warm commons-text into `$M2` from the
//!     project's own clean file:// repo (stage 2 left `$M2` cold for it) →
//!     idempotent re-vendor (`already_vendored`, pom.xml + jar byte-stable) →
//!     `vendor --revert` restores `pom.xml` byte-identical and removes
//!     `.socket/vendor` → a re-vendor succeeds again.

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image, run_in_image_network_none,
    skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-maven:latest";
/// Canonical lowercase patch uuid — a dedicated path level under
/// `.socket/vendor/maven/` and the suffix of the injected `<repository>` id.
const UUID: &str = "16161616-1616-4161-8161-161616161616";
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
    .replace("__GHSA__", GHSA)
}

/// Stage 1: real fixture warm (network OK) + staged marker patch inside the jar,
///   then `vendor --json --offline`, artifact/pom/sidecar/pom.xml asserts, VEX,
///   and fresh staging of ONLY the committable files.
const STAGE1: &str = r#"
# The shared local Maven repo (bind-mounted, survives across stages). Both the
# in-container socket-patch crawler (MAVEN_REPO_LOCAL) and mvn (-Dmaven.repo.local)
# point at it so warming, vendoring, and consumption all agree on one cache.
export M2=/workspace/m2
export MAVEN_REPO_LOCAL="$M2"
# Keep socket-patch fully offline (also gates telemetry) + opt into the
# experimental Maven dispatch tier (the crawler is runtime-gated).
export SOCKET_OFFLINE=1
export SOCKET_EXPERIMENTAL_MAVEN=1
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

# 3. Vendor (fully offline: blob staged locally, jar rebuilt from the cache).
socket-patch vendor --json --offline > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_json_field /tmp/vendor.json '"action": "applied"'
assert_json_field /tmp/vendor.json "$PURL_ENV"
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
# The always-on local-cache shadow advisory must be surfaced (commons-text is
# warm in $M2 at vendor time, so it WOULD shadow the vendored copy).
assert_json_field /tmp/vendor.json 'vendor_maven_local_cache_shadow'
echo "===VENDOR RUN VERIFIED==="

# 4. Artifact: rebuilt jar + verbatim upstream pom + sha1 sidecars at the
#    maven2 leaf; informational marker + committed ledger.
LEAF=".socket/vendor/maven/__UUID__/org/apache/commons/commons-text/1.10.0"
VJAR="$LEAF/commons-text-1.10.0.jar"
VPOM="$LEAF/commons-text-1.10.0.pom"
[ -f "$VJAR" ]      || { ls -R .socket/vendor >&2 || true; fail "vendored jar missing at $VJAR"; }
[ -f "$VPOM" ]      || fail "vendored upstream pom missing at $VPOM"
[ -f "$VJAR.sha1" ] || fail "vendored jar sha1 sidecar missing"
[ -f "$VPOM.sha1" ] || fail "vendored pom sha1 sidecar missing"
[ -f ".socket/vendor/maven/__UUID__/socket-patch.vendor.json" ] || fail "informational marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (state.json) missing"
# The vendored pom is the REAL upstream one (carries the transitive) — NOT a
# fabricated minimal stand-in.
grep -q 'commons-lang3' "$VPOM" || { cat "$VPOM" >&2; fail "vendored pom dropped the commons-lang3 transitive"; }
# The patched marker really is inside the rebuilt jar.
rm -rf /tmp/vjx && mkdir -p /tmp/vjx && ( cd /tmp/vjx && jar xf "$OLDPWD/$VJAR" META-INF/NOTICE.txt 2>/dev/null || jar xf "$OLDPWD/$VJAR" )
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' /tmp/vjx/META-INF/NOTICE.txt || fail "rebuilt jar's NOTICE.txt is not patched"
[ "$(sha256sum /tmp/vjx/META-INF/NOTICE.txt | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "rebuilt jar's NOTICE.txt is not byte-identical to the staged patched bytes"
# The sidecar matches the jar bytes (what checksumPolicy=fail validates).
[ "$(sha1sum "$VJAR" | cut -d' ' -f1)" = "$(cat "$VJAR.sha1" | tr -d '[:space:]')" ] || fail "jar .sha1 sidecar does not match the jar bytes"
echo "===ARTIFACT VERIFIED==="

# 5. pom.xml wiring: our <repository> (id + file:// url + checksumPolicy=fail).
grep -q "<id>socket-patch-vendor-__UUID__</id>" pom.xml || { cat pom.xml >&2; fail "pom.xml missing our <repository> id"; }
grep -q 'file://${project.basedir}/.socket/vendor/maven/__UUID__' pom.xml || { cat pom.xml >&2; fail "pom.xml missing the file:// vendored repo url"; }
grep -q '<checksumPolicy>fail</checksumPolicy>' pom.xml || { cat pom.xml >&2; fail "pom.xml repository missing checksumPolicy=fail"; }
echo "===POM WIRING VERIFIED==="

# 6. Real-toolchain VEX: attest the vendored patch (maven has no product
#    auto-detect — the product purl is explicit).
socket-patch vex --cwd "$PWD" --output out.vex.json \
  --product "pkg:maven/com.example/app@1.0.0" > /tmp/vex.out 2>/tmp/vex.err
RC=$?; cat /tmp/vex.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vex.out >&2; fail "vex exited $RC (expected 0)"; }
[ -s out.vex.json ] || fail "vex did not write out.vex.json"
echo "===VEX RUN VERIFIED==="

# 7. Purge commons-text from $M2 (keep commons-lang3 + the plugins) so stage 2's
#    consumption can ONLY come from the file:// vendored repo.
rm -rf "$CACHED"

# 8. Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp pom.xml /workspace/fresh/
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

LEAF=".socket/vendor/maven/__UUID__/org/apache/commons/commons-text/1.10.0"
VJAR="$LEAF/commons-text-1.10.0.jar"

# RED PROBE: with the vendored feed removed AND commons-text absent from $M2,
# the resolve MUST fail (network is cut, so Central is unreachable too).
# NOTE: Maven RECREATES the file:// repo's base dir (`.socket/vendor/...`)
# while probing it during the failed resolve, so the vendored repo is backed
# up with `cp` and restored with `rm -rf` + `cp` — a naive `mv` back would land
# INSIDE the dir Maven recreated and misplace the artifact.
cp -r .socket/vendor /tmp/vendor-backup
rm -rf .socket/vendor
rm -rf "$M2/org/apache/commons/commons-text"
rm -rf target
$MVN dependency:copy-dependencies -DoutputDirectory=target/red > /tmp/red.log 2>&1
RED_RC=$?
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: resolve SUCCEEDED with .socket/vendor removed"; }
grep -qiE 'could not resolve|cannot access|transfer failed|non-resolvable|failure to find' /tmp/red.log \
  || { cat /tmp/red.log >&2; fail "RED PROBE: resolve failed for an unexpected reason"; }
rm -rf .socket/vendor
cp -r /tmp/vendor-backup .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: network cut, commons-text purged from $M2 → the ONLY source of the
# patched commons-text is the file:// vendored repo. commons-lang3 (transitive)
# resolves from the warm $M2 cache.
rm -rf "$M2/org/apache/commons/commons-text"
rm -rf target
$MVN dependency:copy-dependencies -DoutputDirectory=target/dep > /tmp/green.log 2>&1 \
  || { cat /tmp/green.log >&2; fail "cold-target offline resolve against the file:// repo failed"; }
[ -f target/dep/commons-text-1.10.0.jar ]  || { ls target/dep >&2 || true; fail "patched commons-text jar not copied from the vendored repo"; }
[ -f target/dep/commons-lang3-3.12.0.jar ] || { ls target/dep >&2 || true; fail "commons-lang3 transitive missing — the vendored pom did not declare it"; }

# The copied jar is BYTE-IDENTICAL to our committed vendored jar (it came from
# the file:// repo, not Central).
cmp -s target/dep/commons-text-1.10.0.jar "$VJAR" \
  || fail "resolved commons-text jar is not byte-identical to the vendored jar"
# And it really carries the patched marker.
rm -rf /tmp/cjx && mkdir -p /tmp/cjx && ( cd /tmp/cjx && jar xf "/workspace/fresh/target/dep/commons-text-1.10.0.jar" META-INF/NOTICE.txt 2>/dev/null || jar xf "/workspace/fresh/target/dep/commons-text-1.10.0.jar" )
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' /tmp/cjx/META-INF/NOTICE.txt || fail "consumed commons-text jar is not patched"
[ "$(sha256sum /tmp/cjx/META-INF/NOTICE.txt | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "consumed NOTICE.txt is not byte-identical to the staged patched bytes"
echo "===FRESH INSTALL VERIFIED==="

# TAMPER PROBE: mutate the vendored jar (leaving its .sha1 stale), purge the
# target from $M2, and force a cold re-resolve → checksumPolicy=fail must reject
# it. Restore the pristine jar + re-warm $M2 afterward so stage 3 is clean.
cp "$VJAR" /tmp/vjar.pristine
printf 'TAMPER' >> "$VJAR"
rm -rf "$M2/org/apache/commons/commons-text"
rm -rf target
$MVN dependency:copy-dependencies -DoutputDirectory=target/tamper > /tmp/tamper.log 2>&1
TAMPER_RC=$?
[ "$TAMPER_RC" -ne 0 ] || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE VACUOUS: resolve SUCCEEDED on a mutated jar"; }
grep -qi 'checksum' /tmp/tamper.log || { cat /tmp/tamper.log >&2; fail "TAMPER PROBE: expected a checksum validation failure"; }
cp /tmp/vjar.pristine "$VJAR"
echo "===TAMPER CHECKSUM VERIFIED==="
exit 0
"#;

/// Stage 3 (`--network none`): re-warm the target from the project's own clean
/// vendored repo, then idempotent re-vendor → revert (byte-identical pom.xml
/// restore + full `.socket/vendor` removal) → re-vendor works again.
const STAGE3: &str = r#"
export M2=/workspace/m2
export MAVEN_REPO_LOCAL="$M2"
export SOCKET_OFFLINE=1
export SOCKET_EXPERIMENTAL_MAVEN=1
MVN="mvn -q -Dmaven.repo.local=$M2 -Dmaven.test.skip=true -Dstyle.color=never"
cd /workspace/proj
LEAF=".socket/vendor/maven/__UUID__/org/apache/commons/commons-text/1.10.0"
VJAR="$LEAF/commons-text-1.10.0.jar"

# Stage 2 left commons-text cold in $M2. Re-warm it from THIS project's own
# clean (untampered) file:// vendored repo (network cut, no -o) so the crawler
# can find the installed package again.
rm -rf "$M2/org/apache/commons/commons-text"
$MVN dependency:copy-dependencies -DoutputDirectory=/tmp/rewarm > /tmp/rewarm.log 2>&1 \
  || { cat /tmp/rewarm.log >&2; fail "re-warm from the vendored repo failed"; }
[ -f "$M2/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar" ] || fail "re-warm did not populate \$M2"

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
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert succeeds and rewires again.
socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -f "$VJAR" ] || fail "re-vendor did not recreate the vendored jar"
grep -q "<id>socket-patch-vendor-__UUID__</id>" pom.xml || fail "re-vendor did not re-add the <repository>"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side independent oracle on the bind-mounted project: the `pom.xml`
/// `<repository>` wiring and the `.jar.sha1` sidecar (== sha1 of the mounted
/// vendored jar). The in-container asserts and these would both have to be
/// wrong in the same way for a mis-wired project to pass.
fn assert_pom_and_sidecar_from_host(host_dir: &std::path::Path) {
    use sha1::{Digest as _, Sha1};

    let proj = host_dir.join("proj");
    let pom = std::fs::read_to_string(proj.join("pom.xml")).expect("read mounted pom.xml");
    assert!(
        pom.contains(&format!("<id>socket-patch-vendor-{UUID}</id>")),
        "host oracle: pom.xml <repository> id\n{pom}"
    );
    assert!(
        pom.contains(&format!(
            "file://${{project.basedir}}/.socket/vendor/maven/{UUID}"
        )),
        "host oracle: pom.xml file:// vendored url\n{pom}"
    );
    assert!(
        pom.contains("<checksumPolicy>fail</checksumPolicy>"),
        "host oracle: pom.xml checksumPolicy=fail\n{pom}"
    );

    let jar_rel = format!(
        ".socket/vendor/maven/{UUID}/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"
    );
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

    // Stage 1 — networked fixture warm + offline vendor + wiring + VEX.
    let out = run_in_image(IMAGE, &host_dir, &with_purl_env(&render(STAGE1)));
    assert_stage_markers(
        "maven stage 1 (warm+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "POM WIRING", "VEX RUN", "STAGE1"],
    );
    assert_pom_and_sidecar_from_host(&host_dir);
    assert_vex_attested_from_host(&host_dir);

    // Stage 2 — fresh checkout, network cut, file:// vendored repo the only
    // source of the patched target (+ RED + TAMPER probes).
    let out = run_in_image_network_none(IMAGE, &host_dir, &with_purl_env(&render(STAGE2)));
    assert_stage_markers(
        "maven stage 2 (fresh checkout, --network none)",
        &out,
        &["RED PROBE", "FRESH INSTALL", "TAMPER CHECKSUM"],
    );

    // Stage 3 — idempotency, revert, re-vendor (still no network).
    let out = run_in_image_network_none(IMAGE, &host_dir, &with_purl_env(&render(STAGE3)));
    assert_stage_markers(
        "maven stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    // Suite leaves the project re-vendored; the host oracle must hold again.
    assert_pom_and_sidecar_from_host(&host_dir);
}
