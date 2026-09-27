# vlt 1.0.0-rc.22 workspace layout

`listing.json` is the on-disk layout real vlt 1.0.0-rc.22 produced for a
two-member workspace, captured with `scripts/capture-vlt-tree.mjs` after a
cold `vlt install` (isolated XDG dirs and VLT_CACHE, VLT_TELEMETRY=0,
LANG=C). rc.15 through 1.0.7 split peer contexts into numbered store
entries, so `use-sync-external-store@1.2.0` has two real copies,
`~peer.2` (react 18) and `~peer.3` (react 17). Members hold only links
into the root store.

- root `package.json`: `{"dependencies": {"debug": "4.3.4", "ms": "2.1.3"}}`
- `vlt.json`: `{"config": {"registries": {"npm": "https://registry.npmjs.org/"}}, "workspaces": "packages/*"}`
- `packages/a` (`@scope/a`): react 18.2.0, use-sync-external-store 1.2.0, `@scope/b: workspace:*`
- `packages/b` (`@scope/b`): react 17.0.2, use-sync-external-store 1.2.0
