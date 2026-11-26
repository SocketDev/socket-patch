# Bazel: ruled out, do not re-file

- 2026-11-26: `vex` exits 1 with `record_unavailable` after a hosted scan against a home-made stand-in API. The stand-in did not answer `GET /patches/view/<uuid>?include_blobs=false` (query string). Not a product bug.
- 2026-11-26: `rollback` says `manifest_not_found` after a hosted scan against a stand-in on loopback. A hosted pin is recognised by the patch host's origin: set `SOCKET_PATCH_SERVER_URL` (and `SOCKET_NPM_REGISTRY`) as `e2e_bazel_build/npm.rs` does.
- 2026-11-26: main and v5.1.0 print different output for a project in no Bazel workspace (`mergePendingIds`, `removedRegistryEntries`, a second product id in the VEX document, the human scan summary). These come from changes that are not Bazel's: main with `SOCKET_NO_BAZEL=1` prints the same as main without it.
