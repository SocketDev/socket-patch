# vlt 0.0.0-32 installed layout

`listing.json` is the on-disk layout real vlt 0.0.0-32 produced, captured with
`scripts/capture-vlt-tree.mjs` right after a cold `vlt install` (isolated
XDG dirs and VLT_CACHE, VLT_TELEMETRY=0, LANG=C, no lockfile). Store entry
names are byte-exact; the crawler tests in `crawler_npm_e2e.rs` stage the
listing as real directories, package.json files and relative symlinks.

Project (`package.json` dependencies):

- "left-pad": "1.3.0", "debug": "4.3.4", "@isaacs/string-locale-compare": "1.1.0"
- "react": "18.2.0", "use-sync-external-store": "1.2.0"
- "lp-alias": "npm:left-pad@1.1.3", "semver_x": "npm:semver@7.6.0"
- "slc-git": "github:isaacs/string-locale-compare#v1.1.0"
- "lp-remote": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
- "ms-tgz": "file:./vendor/ms-2.1.2.tgz"
- (no "localdir": 0.0.0-32 cannot link a file: directory dependency)

`vlt.json`: `{"config": {"registries": {}}, "modifiers": {":root > #debug > #ms": "2.1.3"}}`.

The git dependency's devDependencies account for most store entries.
