# vlt 1.0.0-rc.14 installed layout

`listing.json` is the on-disk layout real vlt 1.0.0-rc.14 produced, captured with
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
- "localdir": "file:./vendor/localdir" (a left-pad@1.3.0 copy renamed localdir)

`vlt.json`: `{"config": {"registries": {"npm": "https://registry.npmjs.org/"}}, "modifiers": {":root > #debug > #ms": "2.1.3"}}`.

The git dependency's devDependencies account for most store entries.
