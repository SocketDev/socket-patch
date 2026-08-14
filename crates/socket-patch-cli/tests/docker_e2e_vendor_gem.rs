//! Docker build-proof capstone for `socket-patch vendor` — gem flavor.
//!
//! Proves the CLI_CONTRACT "Vendor command contract" gem row end to end
//! against the REAL bundler (pinned `~> 2.7` in `tests/docker/Dockerfile.gem`)
//! inside `socket-patch-test-gem:latest`, with state carried across
//! containers via a bind-mounted host tempdir (see
//! `docker_vendor_common/mod.rs`):
//!
//!   stage 1 (networked): Gemfile `gem "rack", "~> 3.1"` + `bundle config
//!     set --local path vendor/bundle` + `bundle install` resolve a real
//!     rack → a marker patch on `lib/rack.rb` is hand-staged in-container
//!     (manifest + blob; git-blob sha256 from the ACTUAL installed bytes;
//!     the marker reopens `module Rack` with a probe constant so the patch
//!     is observable at `require` time) → `socket-patch vendor --json
//!     --offline` → asserts: vendored gem dir + materialized `rack.gemspec`
//!     + `socket-patch.vendor.json` + `state.json`; the Gemfile line gained
//!     the exact pin + `path:`; the lock gained the canonical PATH section
//!     (before GEM) and the `rack (= <ver>)!` DEPENDENCIES pin; then
//!     `socket-patch vex` attests the vendored patch (gem has no product
//!     auto-detect, so `--product` is explicit) — exit 0 in-container, the
//!     statement body re-asserted host-side from the mounted out.vex.json.
//!   stage 2 (`--network none`, `BUNDLE_FROZEN=true`): ONLY the committable
//!     files (Gemfile, Gemfile.lock, .socket/, .bundle/config) in a fresh
//!     dir; `bundle install` exits 0 cold+offline with a byte-stable lock,
//!     and `bundle exec ruby -e 'require "rack"'` resolves the probe
//!     constant AND loads rack from the vendored path.
//!   stage 3 (`--network none`): re-vendor idempotent (already_vendored,
//!     Gemfile + lock byte-stable) → `vendor --revert` byte-restores BOTH
//!     Gemfile and Gemfile.lock and removes `.socket/vendor` entirely →
//!     re-vendor succeeds again.
//!
//! The first test runs against a lock WITHOUT a `CHECKSUMS` section (bundler
//! 2.7 keeps `lockfile_checksums` opt-in) — its stage 1 hard-asserts that
//! precondition. The `lockfile_checksums` twin covers the opt-in flavor: the
//! fixture lock gains `CHECKSUMS` via `bundle lock --add-checksums`
//! (supported by the image's bundler 2.7), vendor must rewrite the gem's
//! registry `sha256=` line to bundler's bare path-gem form (per
//! spikes/gem-checksums/ a leftover registry line on a path-sourced gem
//! makes `bundle install` fail — exit 16 under frozen mode), the frozen
//! offline install must accept the rewritten lock byte-stably, and revert
//! must restore the registry `sha256=` line VERBATIM (the recorded original
//! is the only offline path back).

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image, run_in_image_network_none,
    skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-gem:latest";
/// Canonical lowercase patch uuid — the dedicated path level under
/// `.socket/vendor/gem/` and the runtime probe constant's value.
const UUID: &str = "32323232-3232-4232-8232-323232323232";
/// The staged patch's vulnerability id — the stage-1 VEX leg must attest
/// exactly this (mirrors GHSA-vend-npm-real / GHSA-vend-cargo-real in the
/// host capstones).
const GHSA: &str = "GHSA-vend-gem-real";

/// The lockfile_checksums twin's identifiers — distinct so a leaked path or
/// vulnerability id from one flavor can never satisfy the other's asserts.
const CK_UUID: &str = "34343434-3434-4434-8434-343434343434";
const CK_GHSA: &str = "GHSA-vend-gem-ck";

/// Glue the shared bash helpers onto a stage body and pin a uuid + ghsa.
fn render_with(stage_body: &str, uuid: &str, ghsa: &str) -> String {
    format!(
        "{}{}{}{}",
        bash_prelude(),
        stage_patch_fn(),
        json_assert_fns(),
        stage_body
    )
    .replace("__UUID__", uuid)
    .replace("__GHSA__", ghsa)
}

fn render(stage_body: &str) -> String {
    render_with(stage_body, UUID, GHSA)
}

/// Stage 1: real bundler fixture (network OK) + staged marker patch +
/// `vendor --json --offline` + pair-edit asserts + fresh-checkout staging.
const STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
# Keep the in-container socket-patch fully offline (also gates telemetry,
# which keys off the env var rather than the --offline flag).
export SOCKET_OFFLINE=1
# The official ruby image points BUNDLE_APP_CONFIG at /usr/local/bundle,
# which would hijack `bundle config set --local`; pin it back to the
# project so .bundle/config is a real committable file.
export BUNDLE_APP_CONFIG="$PWD/.bundle"

cat > Gemfile <<'EOF'
source "https://rubygems.org"

gem "rack", "~> 3.1"
EOF

bundle config set --local path vendor/bundle || fail "bundle config set --local path"
[ -f .bundle/config ] || fail ".bundle/config not created (BUNDLE_APP_CONFIG override failed?)"

# 1. REAL fixture: bundle install resolves rack from rubygems.org into the
#    project-local vendor/bundle.
bundle install > /tmp/install.log 2>&1 || { cat /tmp/install.log >&2; fail "bundle install (fixture) failed"; }

RACK_VER=$(sed -n 's/^    rack (\([0-9][0-9.]*\))$/\1/p' Gemfile.lock | head -1)
[ -n "$RACK_VER" ] || { cat Gemfile.lock >&2; fail "could not read the resolved rack version from Gemfile.lock"; }
echo "resolved rack version: $RACK_VER" >&2

# Precondition this test is scoped to: NO CHECKSUMS section (bundler 2.7
# keeps lockfile_checksums opt-in; the CHECKSUMS flavor is the
# lockfile_checksums twin below).
grep -q '^CHECKSUMS' Gemfile.lock && fail "Gemfile.lock unexpectedly has a CHECKSUMS section — this test requires the default (no-CHECKSUMS) lock"

RUBY_API=$(ruby -e 'puts Gem.ruby_api_version') || fail "ruby api version probe"
GEM_DIR="vendor/bundle/ruby/$RUBY_API/gems/rack-$RACK_VER"
ORIG="$GEM_DIR/lib/rack.rb"
[ -f "$ORIG" ] || { ls -R vendor/bundle/ruby >&2 || true; fail "$ORIG missing after bundle install"; }

# Pristine pre-checks (file AND runtime): otherwise the post-vendor marker
# asserts are circular.
grep -q 'SOCKET_PATCH_VENDOR_E2E' "$ORIG" && fail "probe constant already in $ORIG — fixture not pristine"
bundle exec ruby -e 'require "rack"; exit(defined?(Rack::SOCKET_PATCH_VENDOR_E2E) ? 1 : 0)' \
  || fail "probe constant already defined at runtime — fixture not pristine"

# 2. Marker patch = the ACTUAL installed bytes + a reopened `module Rack`
#    defining a probe constant (observable via `require "rack"`).
cp "$ORIG" /tmp/patched.rb
cat >> /tmp/patched.rb <<'EOF'

# SOCKET-PATCH-VENDOR-E2E-MARKER
module Rack
  SOCKET_PATCH_VENDOR_E2E = "__UUID__"
end
EOF
PURL="pkg:gem/rack@$RACK_VER"
stage_patch "$PURL" "__UUID__" "lib/rack.rb" "$ORIG" /tmp/patched.rb \
  "__GHSA__" "CVE-2024-77777"

# Pre-vendor snapshots: consumed by stage 2/3 byte-identity asserts.
mkdir -p /workspace/snap
cp Gemfile /workspace/snap/Gemfile.prevendor
cp Gemfile.lock /workspace/snap/Gemfile.lock.prevendor
sha256sum /tmp/patched.rb | cut -d' ' -f1 > /workspace/snap/patched.sha
echo "$RACK_VER" > /workspace/snap/rack-ver

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

# 4. Artifact: gem dir under the stable path convention, patched
#    byte-for-byte, with the stub gemspec materialized next to it (a path
#    source needs one), plus the informational marker and the ledger.
COPY_REL=".socket/vendor/gem/__UUID__/rack-$RACK_VER"
[ -d "$COPY_REL" ] || fail "vendored gem dir missing at $COPY_REL"
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$COPY_REL/lib/rack.rb" || fail "marker missing in the vendored copy"
ACTUAL_SHA=$(sha256sum "$COPY_REL/lib/rack.rb" | cut -d' ' -f1)
[ "$ACTUAL_SHA" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "vendored lib/rack.rb is not byte-identical to the patch blob"
[ -f "$COPY_REL/rack.gemspec" ] || { ls "$COPY_REL" >&2; fail "stub gemspec not materialized into the vendored dir"; }
[ -f ".socket/vendor/gem/__UUID__/socket-patch.vendor.json" ] || fail "informational socket-patch.vendor.json marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (.socket/vendor/state.json) missing"
echo "===ARTIFACT VERIFIED==="

# 5. The MANDATORY pair edit (a lock-only edit is a silent unpatch):
#    Gemfile line gains the exact pin + path:, the lock gains a PATH section
#    (before GEM, relative remote, spec moved over) and the DEPENDENCIES
#    entry becomes the `<name> (= <ver>)!` pin.
grep -qF "gem \"rack\", \"$RACK_VER\", path: \"$COPY_REL\"" Gemfile \
  || { cat Gemfile >&2; fail "Gemfile line not rewritten to the exact-pin + path: form"; }
grep -q '^PATH$' Gemfile.lock || { cat Gemfile.lock >&2; fail "no PATH section in Gemfile.lock"; }
grep -qF "  remote: $COPY_REL" Gemfile.lock || { cat Gemfile.lock >&2; fail "PATH remote is not the relative vendored path"; }
grep -qF "    rack ($RACK_VER)" Gemfile.lock || { cat Gemfile.lock >&2; fail "rack spec block missing from PATH specs"; }
grep -qF "  rack (= $RACK_VER)!" Gemfile.lock || { cat Gemfile.lock >&2; fail "DEPENDENCIES pin '  rack (= $RACK_VER)!' missing"; }
awk '/^PATH$/{p=NR} /^GEM$/{g=NR} END{exit !(p && g && p<g)}' Gemfile.lock \
  || { cat Gemfile.lock >&2; fail "PATH section must precede GEM"; }
echo "===LOCK WIRING VERIFIED==="

# 6. Real-toolchain VEX: attest the vendored patch against the vendored gem
#    dir (gem has no product auto-detect — the product purl is explicit).
#    Exit 0 + a non-empty document are asserted here; the statement body is
#    re-asserted host-side (assert_vex_attested_from_host) via serde_json.
socket-patch vex --cwd "$PWD" --output out.vex.json \
  --product "pkg:gem/app@1.0.0" > /tmp/vex.out 2>/tmp/vex.err
RC=$?; cat /tmp/vex.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vex.out >&2; fail "vex exited $RC (expected 0)"; }
[ -s out.vex.json ] || fail "vex did not write out.vex.json"
echo "===VEX RUN VERIFIED==="

# 7. Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp Gemfile Gemfile.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
cp -R .bundle /workspace/fresh/.bundle
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Stage 2 (`--network none` + `BUNDLE_FROZEN=true`): strictest consumption
/// proof — cold caches, frozen lock, no registry; the vendored path source
/// is the only possible provider of rack, and the patched constant must be
/// visible at `require` time.
const STAGE2: &str = r#"
cd /workspace/fresh
export BUNDLE_APP_CONFIG="$PWD/.bundle"
export BUNDLE_FROZEN=true
RACK_VER=$(cat /workspace/snap/rack-ver)

# Cold-cache premise: the fresh container has no bundle cache, no project
# vendor/, and the image gem home must not already satisfy rack.
[ ! -e vendor ] || fail "fresh checkout already has vendor/ (test bug: uncommittable file copied)"
gem list -i '^rack$' > /dev/null && fail "rack pre-installed in the image gem home — cold-cache premise broken"

LOCK_SHA_BEFORE=$(sha256sum Gemfile.lock | cut -d' ' -f1)
bundle install > /tmp/install.log 2>&1 || { cat /tmp/install.log >&2; fail "frozen cold-cache offline bundle install failed"; }
cat /tmp/install.log >&2
[ "$LOCK_SHA_BEFORE" = "$(sha256sum Gemfile.lock | cut -d' ' -f1)" ] \
  || fail "bundle install churned the committed Gemfile.lock"
echo "===FRESH INSTALL VERIFIED==="

# Runtime proof: rack must load FROM the vendored path and expose the
# patched probe constant carrying the patch uuid.
OUT=$(bundle exec ruby -e '
  require "rack"
  abort "probe constant missing after require" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)
  puts Rack::SOCKET_PATCH_VENDOR_E2E
  puts $LOADED_FEATURES.grep(%r{/rack\.rb\z})
' 2>&1) || { echo "$OUT" >&2; fail "bundle exec runtime probe failed"; }
echo "$OUT" >&2
echo "$OUT" | grep -qF "__UUID__" || fail "probe constant does not carry the patch uuid"
echo "$OUT" | grep -qF ".socket/vendor/gem/__UUID__/rack-$RACK_VER/lib/rack.rb" \
  || fail "rack was not loaded from the vendored path"
echo "===RUNTIME MARKER VERIFIED==="
exit 0
"#;

/// Stage 3 (`--network none`): idempotent re-vendor → revert byte-restores
/// the Gemfile + lock pair and removes `.socket/vendor` → re-vendor again.
const STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1
export BUNDLE_APP_CONFIG="$PWD/.bundle"
RACK_VER=$(cat /workspace/snap/rack-ver)
COPY_REL=".socket/vendor/gem/__UUID__/rack-$RACK_VER"

# 1. Idempotency: re-run reports already_vendored, both files byte-stable.
GEMFILE_SHA=$(sha256sum Gemfile | cut -d' ' -f1)
LOCK_SHA=$(sha256sum Gemfile.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA" = "$(sha256sum Gemfile.lock | cut -d' ' -f1)" ] || fail "re-vendor churned Gemfile.lock"
[ "$GEMFILE_SHA" = "$(sha256sum Gemfile | cut -d' ' -f1)" ] || fail "re-vendor churned Gemfile"
echo "===IDEMPOTENT VERIFIED==="

# 2. Revert: BOTH halves of the pair edit byte-restored, artifacts gone.
socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s Gemfile /workspace/snap/Gemfile.prevendor \
  || { diff /workspace/snap/Gemfile.prevendor Gemfile >&2 || true; fail "revert did not byte-restore the Gemfile"; }
cmp -s Gemfile.lock /workspace/snap/Gemfile.lock.prevendor \
  || { diff /workspace/snap/Gemfile.lock.prevendor Gemfile.lock >&2 || true; fail "revert did not byte-restore Gemfile.lock"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert succeeds and re-wires the pair.
socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -d "$COPY_REL" ] || fail "re-vendor did not recreate $COPY_REL"
grep -qF "path: \"$COPY_REL\"" Gemfile || fail "re-vendor did not rewire the Gemfile"
grep -qF "  rack (= $RACK_VER)!" Gemfile.lock || fail "re-vendor did not rewire Gemfile.lock"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side independent oracle on the bind-mounted Gemfile + Gemfile.lock:
/// re-asserts the pair edit without trusting the in-container greps.
fn assert_pair_wired_from_host(host_dir: &std::path::Path) {
    let rack_ver = std::fs::read_to_string(host_dir.join("snap/rack-ver"))
        .expect("snap/rack-ver")
        .trim()
        .to_string();
    let copy_rel = format!(".socket/vendor/gem/{UUID}/rack-{rack_ver}");

    let gemfile =
        std::fs::read_to_string(host_dir.join("proj/Gemfile")).expect("read mounted Gemfile");
    assert!(
        gemfile.contains(&format!(
            "gem \"rack\", \"{rack_ver}\", path: \"{copy_rel}\""
        )),
        "host oracle: Gemfile not in the exact-pin + path: form:\n{gemfile}"
    );

    let lock = std::fs::read_to_string(host_dir.join("proj/Gemfile.lock"))
        .expect("read mounted Gemfile.lock");
    assert!(
        lock.contains(&format!(
            "PATH\n  remote: {copy_rel}\n  specs:\n    rack ({rack_ver})"
        )),
        "host oracle: canonical PATH section missing:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  rack (= {rack_ver})!")),
        "host oracle: DEPENDENCIES pin missing:\n{lock}"
    );
    assert!(
        !lock.contains("\nCHECKSUMS"),
        "host oracle: this suite must run against a no-CHECKSUMS lock:\n{lock}"
    );
}

/// Host-side oracle on the bind-mounted `out.vex.json` the stage-1 VEX leg
/// wrote: exactly one statement attesting the vendored gem patch as
/// `not_affected` with the `(vendored)` impact marker (mirrors
/// `e2e_vendor_npm_build.rs::npm_vendor_vex_attests_against_vendored_tarball`).
fn assert_vex_attested_from_host(host_dir: &std::path::Path) {
    let rack_ver = std::fs::read_to_string(host_dir.join("snap/rack-ver"))
        .expect("snap/rack-ver")
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
        "the vendored gem patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"],
        format!("pkg:gem/rack@{rack_ver}")
    );
    let impact = stmts[0]["impact_statement"]
        .as_str()
        .expect("impact_statement");
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );
}

/// Stage 1 of the lockfile_checksums twin: the fixture lock GAINS a
/// CHECKSUMS section (`bundle lock --add-checksums`, real bundler 2.7), the
/// upstream registry `sha256=` line is captured verbatim for the revert
/// oracle, and vendor must rewrite that line to bundler's bare path-gem form
/// while landing the same pair edit as the no-CHECKSUMS flavor.
const STAGE1_CK: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
export SOCKET_OFFLINE=1
export BUNDLE_APP_CONFIG="$PWD/.bundle"

cat > Gemfile <<'EOF'
source "https://rubygems.org"

gem "rack", "~> 3.1"
EOF

bundle config set --local path vendor/bundle || fail "bundle config set --local path"

# 1. REAL fixture: bundle install + an opt-in CHECKSUMS lock (bundler 2.7
#    does not write one by default — the twin suite pins that default).
bundle install > /tmp/install.log 2>&1 || { cat /tmp/install.log >&2; fail "bundle install (fixture) failed"; }
bundle lock --add-checksums > /tmp/lock.log 2>&1 || { cat /tmp/lock.log >&2; fail "bundle lock --add-checksums failed"; }

RACK_VER=$(sed -n 's/^    rack (\([0-9][0-9.]*\))$/\1/p' Gemfile.lock | head -1)
[ -n "$RACK_VER" ] || { cat Gemfile.lock >&2; fail "could not read the resolved rack version from Gemfile.lock"; }
echo "resolved rack version: $RACK_VER" >&2

grep -q '^CHECKSUMS$' Gemfile.lock || { cat Gemfile.lock >&2; fail "bundle lock --add-checksums did not add a CHECKSUMS section"; }
UPSTREAM_LINE=$(grep -E "^  rack \($RACK_VER\) sha256=[0-9a-f]{64}$" Gemfile.lock)
[ "$(echo "$UPSTREAM_LINE" | wc -l)" -eq 1 ] && [ -n "$UPSTREAM_LINE" ] \
  || { cat Gemfile.lock >&2; fail "expected exactly one registry sha256 CHECKSUMS line for rack"; }

RUBY_API=$(ruby -e 'puts Gem.ruby_api_version') || fail "ruby api version probe"
GEM_DIR="vendor/bundle/ruby/$RUBY_API/gems/rack-$RACK_VER"
ORIG="$GEM_DIR/lib/rack.rb"
[ -f "$ORIG" ] || { ls -R vendor/bundle/ruby >&2 || true; fail "$ORIG missing after bundle install"; }
grep -q 'SOCKET_PATCH_VENDOR_E2E' "$ORIG" && fail "probe constant already in $ORIG — fixture not pristine"

# 2. Marker patch on the ACTUAL installed bytes.
cp "$ORIG" /tmp/patched.rb
cat >> /tmp/patched.rb <<'EOF'

# SOCKET-PATCH-VENDOR-E2E-MARKER
module Rack
  SOCKET_PATCH_VENDOR_E2E = "__UUID__"
end
EOF
PURL="pkg:gem/rack@$RACK_VER"
stage_patch "$PURL" "__UUID__" "lib/rack.rb" "$ORIG" /tmp/patched.rb \
  "__GHSA__" "CVE-2024-88888"

mkdir -p /workspace/snap
cp Gemfile /workspace/snap/Gemfile.prevendor
cp Gemfile.lock /workspace/snap/Gemfile.lock.prevendor
printf '%s\n' "$UPSTREAM_LINE" > /workspace/snap/upstream-checksum-line
echo "$RACK_VER" > /workspace/snap/rack-ver

# 3. Vendor (fully offline).
socket-patch vendor --json --offline > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
echo "===VENDOR RUN VERIFIED==="

# 4. The CHECKSUMS rewrite: the registry sha256= line becomes bundler's bare
#    path-gem entry (a leftover registry line on a path-sourced gem fails
#    the next install — spikes/gem-checksums/).
grep -qxF "  rack ($RACK_VER)" Gemfile.lock \
  || { cat Gemfile.lock >&2; fail "CHECKSUMS entry not rewritten to the bare path-gem form"; }
grep -q "^  rack ($RACK_VER) sha256=" Gemfile.lock \
  && { cat Gemfile.lock >&2; fail "registry sha256 CHECKSUMS line still present after vendor"; }
grep -q '^CHECKSUMS$' Gemfile.lock || { cat Gemfile.lock >&2; fail "CHECKSUMS section lost by the vendor edit"; }
echo "===CHECKSUMS REWRITE VERIFIED==="

# 5. Same mandatory pair edit as the no-CHECKSUMS flavor.
COPY_REL=".socket/vendor/gem/__UUID__/rack-$RACK_VER"
[ -d "$COPY_REL" ] || fail "vendored gem dir missing at $COPY_REL"
grep -qF "gem \"rack\", \"$RACK_VER\", path: \"$COPY_REL\"" Gemfile \
  || { cat Gemfile >&2; fail "Gemfile line not rewritten to the exact-pin + path: form"; }
grep -qF "  remote: $COPY_REL" Gemfile.lock || { cat Gemfile.lock >&2; fail "PATH remote is not the relative vendored path"; }
grep -qF "  rack (= $RACK_VER)!" Gemfile.lock || { cat Gemfile.lock >&2; fail "DEPENDENCIES pin '  rack (= $RACK_VER)!' missing"; }
awk '/^PATH$/{p=NR} /^GEM$/{g=NR} END{exit !(p && g && p<g)}' Gemfile.lock \
  || { cat Gemfile.lock >&2; fail "PATH section must precede GEM"; }
echo "===LOCK WIRING VERIFIED==="

# 6. Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp Gemfile Gemfile.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
cp -R .bundle /workspace/fresh/.bundle
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Stage 2 of the twin (`--network none` + `BUNDLE_FROZEN=true`): the
/// exit-16 hazard proof — a FROZEN cold-cache offline install must accept
/// the CHECKSUMS lock whose entry for the vendored gem is the bare path-gem
/// form, byte-stably, and the probe constant must load from the vendored
/// path.
const STAGE2_CK: &str = r#"
cd /workspace/fresh
export BUNDLE_APP_CONFIG="$PWD/.bundle"
export BUNDLE_FROZEN=true
RACK_VER=$(cat /workspace/snap/rack-ver)

[ ! -e vendor ] || fail "fresh checkout already has vendor/ (test bug: uncommittable file copied)"
gem list -i '^rack$' > /dev/null && fail "rack pre-installed in the image gem home — cold-cache premise broken"
grep -q '^CHECKSUMS$' Gemfile.lock || fail "fresh checkout lost the CHECKSUMS section (test bug)"

LOCK_SHA_BEFORE=$(sha256sum Gemfile.lock | cut -d' ' -f1)
bundle install > /tmp/install.log 2>&1 || { cat /tmp/install.log >&2; fail "frozen cold-cache offline bundle install failed on the CHECKSUMS lock"; }
cat /tmp/install.log >&2
[ "$LOCK_SHA_BEFORE" = "$(sha256sum Gemfile.lock | cut -d' ' -f1)" ] \
  || fail "bundle install churned the committed CHECKSUMS Gemfile.lock"
echo "===FRESH INSTALL VERIFIED==="

OUT=$(bundle exec ruby -e '
  require "rack"
  abort "probe constant missing after require" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)
  puts Rack::SOCKET_PATCH_VENDOR_E2E
  puts $LOADED_FEATURES.grep(%r{/rack\.rb\z})
' 2>&1) || { echo "$OUT" >&2; fail "bundle exec runtime probe failed"; }
echo "$OUT" >&2
echo "$OUT" | grep -qF "__UUID__" || fail "probe constant does not carry the patch uuid"
echo "$OUT" | grep -qF ".socket/vendor/gem/__UUID__/rack-$RACK_VER/lib/rack.rb" \
  || fail "rack was not loaded from the vendored path"
echo "===RUNTIME MARKER VERIFIED==="
exit 0
"#;

/// Stage 3 of the twin (`--network none`): idempotent re-vendor → revert
/// restores the registry `sha256=` CHECKSUMS line VERBATIM (byte-identical
/// files) → re-vendor rewrites it back to the bare form.
const STAGE3_CK: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1
export BUNDLE_APP_CONFIG="$PWD/.bundle"
RACK_VER=$(cat /workspace/snap/rack-ver)
UPSTREAM_LINE=$(cat /workspace/snap/upstream-checksum-line)

# 1. Idempotency: re-run reports already_vendored, both files byte-stable.
GEMFILE_SHA=$(sha256sum Gemfile | cut -d' ' -f1)
LOCK_SHA=$(sha256sum Gemfile.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA" = "$(sha256sum Gemfile.lock | cut -d' ' -f1)" ] || fail "re-vendor churned Gemfile.lock"
[ "$GEMFILE_SHA" = "$(sha256sum Gemfile | cut -d' ' -f1)" ] || fail "re-vendor churned Gemfile"
echo "===IDEMPOTENT VERIFIED==="

# 2. Revert: byte-restore, INCLUDING the registry sha256= line verbatim
#    (the explicit grep keeps the exit-16 hazard documented even if the
#    byte-identity assert is ever loosened).
socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_summary /tmp/revert.json removed 1
cmp -s Gemfile /workspace/snap/Gemfile.prevendor \
  || { diff /workspace/snap/Gemfile.prevendor Gemfile >&2 || true; fail "revert did not byte-restore the Gemfile"; }
cmp -s Gemfile.lock /workspace/snap/Gemfile.lock.prevendor \
  || { diff /workspace/snap/Gemfile.lock.prevendor Gemfile.lock >&2 || true; fail "revert did not byte-restore Gemfile.lock"; }
grep -qxF "$UPSTREAM_LINE" Gemfile.lock \
  || { cat Gemfile.lock >&2; fail "revert did not restore the registry sha256= CHECKSUMS line verbatim"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

# 3. Re-vendor after revert: the CHECKSUMS entry goes bare again.
socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
grep -qxF "  rack ($RACK_VER)" Gemfile.lock || { cat Gemfile.lock >&2; fail "re-vendor did not re-bare the CHECKSUMS entry"; }
grep -q "^  rack ($RACK_VER) sha256=" Gemfile.lock && { cat Gemfile.lock >&2; fail "registry sha256 line back after re-vendor"; }
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Host-side oracle for the lockfile_checksums twin: the pair edit is wired
/// AND the CHECKSUMS section holds bundler's bare path-gem entry for rack
/// (no registry `sha256=` remnant) — asserted from the mounted files without
/// trusting the in-container greps.
fn assert_ck_pair_wired_from_host(host_dir: &std::path::Path) {
    let rack_ver = std::fs::read_to_string(host_dir.join("snap/rack-ver"))
        .expect("snap/rack-ver")
        .trim()
        .to_string();
    let copy_rel = format!(".socket/vendor/gem/{CK_UUID}/rack-{rack_ver}");

    let gemfile =
        std::fs::read_to_string(host_dir.join("proj/Gemfile")).expect("read mounted Gemfile");
    assert!(
        gemfile.contains(&format!(
            "gem \"rack\", \"{rack_ver}\", path: \"{copy_rel}\""
        )),
        "host oracle: Gemfile not in the exact-pin + path: form:\n{gemfile}"
    );

    let lock = std::fs::read_to_string(host_dir.join("proj/Gemfile.lock"))
        .expect("read mounted Gemfile.lock");
    assert!(
        lock.contains("\nCHECKSUMS\n"),
        "host oracle: this twin must run against a CHECKSUMS lock:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  rack ({rack_ver})\n")),
        "host oracle: bare path-gem CHECKSUMS entry missing:\n{lock}"
    );
    assert!(
        !lock.contains(&format!("  rack ({rack_ver}) sha256=")),
        "host oracle: registry sha256 CHECKSUMS line survived the vendor edit:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  rack (= {rack_ver})!")),
        "host oracle: DEPENDENCIES pin missing:\n{lock}"
    );
}

#[test]
fn gem_vendor_fresh_checkout_bundle_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize so the macOS `/var` → `/private/var` symlink doesn't
    // confuse Docker Desktop's file-sharing allowlist.
    let host_dir = tmp.path().canonicalize().expect("canonicalize tempdir");

    // Stage 1 — networked fixture install + offline vendor + pair-edit +
    // VEX asserts.
    let out = run_in_image(IMAGE, &host_dir, &render(STAGE1));
    assert_stage_markers(
        "gem stage 1 (install+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "LOCK WIRING", "VEX RUN", "STAGE1"],
    );
    assert_pair_wired_from_host(&host_dir);
    assert_vex_attested_from_host(&host_dir);

    // Stage 2 — fresh checkout, frozen + cold caches + network cut.
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE2));
    assert_stage_markers(
        "gem stage 2 (fresh checkout, --network none, BUNDLE_FROZEN)",
        &out,
        &["FRESH INSTALL", "RUNTIME MARKER"],
    );

    // Stage 3 — idempotency, revert, re-vendor (still no network).
    let out = run_in_image_network_none(IMAGE, &host_dir, &render(STAGE3));
    assert_stage_markers(
        "gem stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    // Suite leaves the project re-vendored; the host oracle must hold again.
    assert_pair_wired_from_host(&host_dir);
}

/// The `lockfile_checksums` twin (see the module doc): same lifecycle against
/// a lock WITH a CHECKSUMS section — the vendor edit must swap the registry
/// `sha256=` line for bundler's bare path-gem entry, the frozen offline
/// install must accept it byte-stably, and revert must restore the registry
/// line verbatim.
#[test]
fn gem_vendor_lockfile_checksums_fresh_checkout_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let host_dir = tmp.path().canonicalize().expect("canonicalize tempdir");

    // Stage 1 — networked fixture install + --add-checksums + offline vendor
    // + CHECKSUMS-rewrite + pair-edit asserts.
    let out = run_in_image(IMAGE, &host_dir, &render_with(STAGE1_CK, CK_UUID, CK_GHSA));
    assert_stage_markers(
        "gem ck stage 1 (install+add-checksums+vendor)",
        &out,
        &["VENDOR RUN", "CHECKSUMS REWRITE", "LOCK WIRING", "STAGE1"],
    );
    assert_ck_pair_wired_from_host(&host_dir);

    // Stage 2 — fresh checkout, frozen + cold caches + network cut: the
    // exit-16 hazard proof on the CHECKSUMS lock.
    let out =
        run_in_image_network_none(IMAGE, &host_dir, &render_with(STAGE2_CK, CK_UUID, CK_GHSA));
    assert_stage_markers(
        "gem ck stage 2 (fresh checkout, --network none, BUNDLE_FROZEN)",
        &out,
        &["FRESH INSTALL", "RUNTIME MARKER"],
    );

    // Stage 3 — idempotency, revert (verbatim sha256= restore), re-vendor.
    let out =
        run_in_image_network_none(IMAGE, &host_dir, &render_with(STAGE3_CK, CK_UUID, CK_GHSA));
    assert_stage_markers(
        "gem ck stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
    assert_ck_pair_wired_from_host(&host_dir);
}
