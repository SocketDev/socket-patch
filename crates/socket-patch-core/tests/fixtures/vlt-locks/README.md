# Captured vlt locks

Each `<vlt-version>/vlt-lock.json` is the lock real vlt wrote on a cold
`vlt install` of one project (isolated XDG dirs and VLT_CACHE,
VLT_TELEMETRY=0, LANG=C, LC_ALL=C, CI=1, Node 24.21.0, public npm registry),
byte for byte. `<vlt-version>/vlt.json` is the config it ran with (0.0.0-1
has none).

Project (`package.json`):

- dependencies: "left-pad": "1.3.0", "debug": "4.3.4",
  "@isaacs/string-locale-compare": "1.1.0", "react": "18.2.0",
  "use-sync-external-store": "1.2.0", "lp-alias": "npm:left-pad@1.1.3",
  "semver": "7.6.0",
  "lp-remote": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
- optionalDependencies: "fsevents": "2.3.3" (captured on macOS)
- devDependencies: "ms": "2.1.2"

`vlt.json`: `{"modifiers": {":root > #debug > #ms": "2.1.3"}}`, plus
`{"config": {"registries": {"npm": "https://registry.npmjs.org/"}}}` from
1.0.0-rc.33 (which has no default registry).

The locks cover every era: no `lockfileVersion` (0.0.0-1, 0.0.0-16), `0`
with `··` and `·npm·` ids (0.0.0-19 to rc.14), `1` with `~` ids and
3-tuples (rc.15, rc.32), `1` with slot [3] (rc.33 on), and peer extras
(1.0.10 on), with dev/optional flags, platform [7], bins [8], a modifier,
an alias and a remote node. `tests/vlt_locks.rs` round-trips them, and the
`redirect/npm/vlt/capture-<version>` goldens are built from them.
