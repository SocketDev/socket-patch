# Rush vendoring fixtures

Each case holds a Rush repository's wiring files `before` and `after`
`socket-patch scan --mode vendored` (2026-11-18, the real minimist patches
`8cccd65b-…` for 0.0.8 and `d8533454-…` for 0.0.10).

The `after` locks are byte-identical to what Rush 5.182.1 itself writes when
`rush update` resolves the `after` config and manifests from the `before`
lock (pnpm 10.34.9; pnpm 11.28.12 for the `pnpm11-…` case). The only bytes
that differ under test are the tarball's sha512, which depends on the pack.

`pnpm10` and `pnpm11-user-overrides` keep `rush init`'s `pnpm-config.json`
and `common-versions.json` whole. The other cases have those two files'
`/** … */` documentation blocks cut, the same way on both sides, to keep
the fixtures small; their locks and `package.json` files are untouched.

| case | what it pins |
|---|---|
| `pnpm10` | direct dependents at folder depth 1 and 2, one transitive parent; `overrides:` created |
| `pnpm10-user-overrides` | pnpm <= 10 keeps `globalOverrides`' own order in the lock |
| `pnpm11-user-overrides` | pnpm >= 11 keeps the lock's `overrides:` key-sorted; trailing-comma config |
| `sibling-versions` | two versions of one package vendored; a `~0.0.5` dependent stays on the version it is locked at |
| `sibling-sorts-after` | the rekeyed entry moves behind a sibling version to keep the keys sorted |
| `subspaces` | two subspace locks, paths three levels up, the shared `pnpm-config.json` |
| `new-dependents` | a later `rush update` brought the registry entry back for a new direct dependent and a new parent; the re-run moves both and drops it |
