# `bun.lockb` migrated to `bun.lock`

The `1.2.23` fixture lock (`../1.2.23/bun.lockb`) migrated to the text lock
with `bun install --save-text-lockfile --ignore-scripts` (macOS arm64, empty
`BUN_INSTALL_CACHE_DIR`, `node_modules` removed first), by the Bun release
named in each file:

- `pristine-<bun>.lock`: migrated straight from the fixture.
- `vendored-<bun>.lock`: migrated after socket-patch vendored
  `minimist@1.2.2` into the binary lock with the `rebuild_tests` patch in
  `src/vendor/bun_binary.rs` (uuid `11111111-1111-4111-8111-111111111111`).
  1.2.23 drops the local tarball's integrity; 1.4.2 keeps it.

A vendored revert after the migration must write the pristine lock (#784).
