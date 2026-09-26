#!/bin/bash
# Rebuild the vendored-wiring fixtures with real vlt (the byte-stability
# oracle of tests/vlt_locks.rs). For each vlt version and target:
#   1. a cold `vlt install` of the project writes input/vlt-lock.json;
#   2. surgery.mjs wires the target to its D19 directory artifact;
#   3. `vlt ci` from a clean node_modules writes expected/vlt-lock.json.
# Inputs live once per project under <version>/projects/<project>/; each
# <version>/cases/<case>/ holds case.json and, unless refused, expected/.
# A lock ci rewrites is recorded in case.json `ciChurn` (pairs of the line
# surgery wrote and the line vlt wrote); the expected lock is then taken
# after a second `ci`, which must leave it unchanged. Every expected lock
# must also survive `vlt install --frozen-lockfile` byte for byte (warm,
# then from a clean node_modules), and `vlt install escape-html@1.0.3`
# must keep every entry of it unchanged, except the values of the vendored
# node's own edges (rc.14 rewrites their peer specs on every reify).
#
# usage: VLT_BIN_DIR=<dir holding <version>/node_modules/vlt/vlt.js> ./regenerate.sh
set -euo pipefail
export LANG=C LC_ALL=C VLT_TELEMETRY=0 DO_NOT_TRACK=1 CI=1 NO_COLOR=1
unset VLT_STORE_LINKER
HERE=$(cd "$(dirname "$0")" && pwd)
: "${VLT_BIN_DIR:?set VLT_BIN_DIR}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
UUID=11111111-2222-4333-8444-555555555555
VERSIONS=${VERSIONS:-"1.2.0 1.0.10 1.0.4 1.0.0-rc.32 1.0.0-rc.14"}

vlt() {
  local version=$1 xdg=$2
  shift 2
  mkdir -p "$xdg"/{cache,config,data,state,run}
  XDG_CACHE_HOME=$xdg/cache XDG_CONFIG_HOME=$xdg/config XDG_DATA_HOME=$xdg/data \
    XDG_STATE_HOME=$xdg/state XDG_RUNTIME_DIR=$xdg/run VLT_CACHE=$xdg/cache/vlt \
    node --no-warnings "$VLT_BIN_DIR/$version/node_modules/vlt/vlt.js" "$@" </dev/null
}

json() { node -e 'process.stdout.write(JSON.stringify(JSON.parse(process.argv[1]), null, 2) + "\n")' "$1"; }

write_project() {
  local project=$1 version=$2 dir=$3
  local cfg=''
  case $version in 1.*-rc.*) ;; 1.*) cfg='"config":{"registries":{"npm":"https://registry.npmjs.org/"}}' ;; esac
  mkdir -p "$dir"
  case $project in
    workspace)
      mkdir -p "$dir/packages/a"
      json "{${cfg:+$cfg,}\"workspaces\":\"packages/*\"}" >"$dir/vlt.json"
      json '{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0","ms":"2.1.3","supports-color":"7.2.0","@isaacs/string-locale-compare":"1.1.0","semver":"7.6.0","react":"18.2.0","use-sync-external-store":"1.2.0"},"devDependencies":{"is-number":"7.0.0"},"optionalDependencies":{"escape-string-regexp":"4.0.0"}}' >"$dir/package.json"
      json '{"name":"a","version":"1.0.0","dependencies":{"left-pad":"1.3.0","debug":"4.3.4"}}' >"$dir/packages/a/package.json"
      ;;
    peer-member)
      mkdir -p "$dir/packages/a"
      json "{${cfg:+$cfg,}\"workspaces\":\"packages/*\"}" >"$dir/vlt.json"
      json '{"name":"root","version":"1.0.0"}' >"$dir/package.json"
      json '{"name":"a","version":"1.0.0","dependencies":{"use-sync-external-store":"1.2.0","react":"18.2.0"}}' >"$dir/packages/a/package.json"
      ;;
    alias)
      json "{${cfg}}" >"$dir/vlt.json"
      json '{"name":"root","version":"1.0.0","dependencies":{"lp":"npm:left-pad@1.3.0","react":"18.2.0","usx":"npm:use-sync-external-store@1.2.0"}}' >"$dir/package.json"
      ;;
  esac
}

# case name, project, target
CASES="left-pad:workspace:left-pad@1.3.0
supports-color:workspace:supports-color@7.2.0
scoped:workspace:@isaacs/string-locale-compare@1.1.0
semver:workspace:semver@7.6.0
dev-edge:workspace:is-number@7.0.0
optional-edge:workspace:escape-string-regexp@4.0.0
member-only:workspace:debug@4.3.4
peer:workspace:use-sync-external-store@1.2.0
peer-member:peer-member:use-sync-external-store@1.2.0
transitive:workspace:has-flag@4.0.0
alias:alias:left-pad@1.3.0
alias-selfref-peer:alias:use-sync-external-store@1.2.0"

copy_inputs() {
  local from=$1 to=$2
  mkdir -p "$to"
  (cd "$from" && find . -name node_modules -prune -o -type f \( -name 'vlt-lock.json' -o -name 'vlt.json' -o -name 'package.json' \) -print) |
    while read -r f; do mkdir -p "$to/$(dirname "$f")"; cp "$from/$f" "$to/$f"; done
}

for version in $VERSIONS; do
  for project in workspace peer-member alias; do
    base=$WORK/$version/$project
    write_project "$project" "$version" "$base"
    (cd "$base" && vlt "$version" "$WORK/xdg-$version" install >"$WORK/$version-$project-install.log" 2>&1)
    rm -rf "$HERE/$version/projects/$project"
    copy_inputs "$base" "$HERE/$version/projects/$project"
  done
  echo "$CASES" | while IFS=: read -r case project target; do
    base=$WORK/$version/$project
    out=$HERE/$version/cases/$case
    rm -rf "$out"
    mkdir -p "$out"
    run=$WORK/$version/run-$case
    copy_inputs "$base" "$run"
    verdict=$(node "$HERE/surgery.mjs" "$run" "$target" "$UUID")
    refusal=$(node -e 'const v=JSON.parse(process.argv[1]); process.stdout.write(v.refusal ?? "")' "$verdict")
    if [ -n "$refusal" ]; then
      json "{\"project\":\"$project\",\"purl\":\"pkg:npm/$target\",\"uuid\":\"$UUID\",\"refusal\":\"$refusal\"}" >"$out/case.json"
      echo "$version $case: refused $refusal"
      continue
    fi
    rel=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).rel)' "$verdict")
    name=${target%@*}
    installed=$(node -e '
      const fs = require("fs"), path = require("path");
      const [store, name, version] = process.argv.slice(1);
      for (const id of fs.readdirSync(store)) {
        const dir = path.join(store, id, "node_modules", name);
        try {
          if (JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version === version) {
            process.stdout.write(dir);
            process.exit(0);
          }
        } catch {}
      }
      process.exit(1);
    ' "$base/node_modules/.vlt" "$name" "${target##*@}")
    mkdir -p "$run/$(dirname "$rel")"
    cp -R "$installed" "$run/$rel"
    rm -rf "$run/$rel/node_modules"
    node -e 'const f=process.argv[1]; const d=JSON.parse(require("fs").readFileSync(f,"utf8")); delete d.devDependencies; require("fs").writeFileSync(f, JSON.stringify(d,null,2)+"\n")' "$run/$rel/package.json"
    printf '!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n' >"$run/.socket/vendor/npm/$UUID/.gitignore"
    printf '* -text\n' >"$run/.socket/vendor/npm/$UUID/.gitattributes"
    cp "$run/vlt-lock.json" "$WORK/surgery.json"
    (cd "$run" && vlt "$version" "$WORK/xdg-$version" ci >"$WORK/$version-$case-ci.log" 2>&1)
    churn='[]'
    if ! cmp -s "$WORK/surgery.json" "$run/vlt-lock.json"; then
      churn=$(node -e '
        const fs = require("fs");
        const a = fs.readFileSync(process.argv[1], "utf8").split("\n");
        const b = fs.readFileSync(process.argv[2], "utf8").split("\n");
        if (a.length !== b.length) { console.error("line count changed"); process.exit(1) }
        const pairs = a.map((l, i) => [l, b[i]]).filter(([x, y]) => x !== y);
        process.stdout.write(JSON.stringify(pairs));
      ' "$WORK/surgery.json" "$run/vlt-lock.json")
      cp "$run/vlt-lock.json" "$WORK/ci1.json"
      (cd "$run" && rm -rf node_modules packages/a/node_modules && vlt "$version" "$WORK/xdg-$version" ci >"$WORK/$version-$case-ci2.log" 2>&1)
      cmp -s "$WORK/ci1.json" "$run/vlt-lock.json" || { echo "$version $case: second ci changed the lock" >&2; exit 1; }
      echo "$version $case: ci churn $churn"
    else
      echo "$version $case: byte-stable"
    fi
    json "{\"project\":\"$project\",\"purl\":\"pkg:npm/$target\",\"uuid\":\"$UUID\",\"refusal\":null,\"ciChurn\":$churn}" >"$out/case.json"
    copy_inputs "$run" "$out/expected"
    rm -f "$out/expected/vlt.json"
    cp "$run/vlt-lock.json" "$WORK/expected.json"
    (cd "$run" && vlt "$version" "$WORK/xdg-$version" install --frozen-lockfile >"$WORK/$version-$case-frozen.log" 2>&1)
    cmp -s "$WORK/expected.json" "$run/vlt-lock.json" || { echo "$version $case: install --frozen-lockfile changed the lock" >&2; exit 1; }
    (cd "$run" && rm -rf node_modules packages/a/node_modules && vlt "$version" "$WORK/xdg-$version" install --frozen-lockfile >"$WORK/$version-$case-frozen-cold.log" 2>&1)
    cmp -s "$WORK/expected.json" "$run/vlt-lock.json" || { echo "$version $case: a cold install --frozen-lockfile changed the lock" >&2; exit 1; }
    (cd "$run" && vlt "$version" "$WORK/xdg-$version" install escape-html@1.0.3 >"$WORK/$version-$case-new.log" 2>&1)
    node -e '
      const fs = require("fs");
      const entries = f => new Map(fs.readFileSync(f, "utf8").split("\n")
        .filter(l => l.startsWith("    \"")).map(l => l.replace(/,?\r?$/, ""))
        .map(l => [JSON.parse(l.slice(4, l.indexOf("\": ") + 1)), l]));
      const after = entries(process.argv[2]);
      const own = process.argv[3] + " ";
      const lost = [...entries(process.argv[1])].filter(([k, l]) =>
        after.get(k) !== l && !(k.startsWith(own) && after.has(k)));
      if (lost.length || !fs.readFileSync(process.argv[2], "utf8").includes("escape-html")) {
        console.error(JSON.stringify(lost)); process.exit(1);
      }
    ' "$WORK/expected.json" "$run/vlt-lock.json" "$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).fileId)' "$verdict")" || { echo "$version $case: vlt install <new> dropped the wiring" >&2; exit 1; }
    echo "$version $case: frozen-lockfile byte-stable, install <new> keeps the wiring"
  done
done
