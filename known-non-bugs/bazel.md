# Bazel: ruled out, do not re-file

- 2026-11-26: `vex` exits 1 with `record_unavailable` after a hosted scan against a home-made stand-in API. The stand-in did not answer `GET /patches/view/<uuid>?include_blobs=false` (query string). Not a product bug.
- 2026-11-26: `rollback` says `manifest_not_found` after a hosted scan against a stand-in on loopback. A hosted pin is recognised by the patch host's origin: set `SOCKET_PATCH_SERVER_URL` (and `SOCKET_NPM_REGISTRY`) as `e2e_bazel_build/npm.rs` does.
- 2026-11-26: main and v5.1.0 print different output for a project in no Bazel workspace (`mergePendingIds`, `removedRegistryEntries`, a second product id in the VEX document, the human scan summary). These come from changes that are not Bazel's: main with `SOCKET_NO_BAZEL=1` prints the same as main without it.
- 2026-11-26: `vendor --revert` (and `rollback`) of a PyPI download cache removes a `.bazelrc` that was an empty file of the user's. Documented in "Bazel workspaces: PyPI vendored mode as a download cache" ("a `.bazelrc` left empty is removed, also when it was an empty file of yours").
- 2026-11-26: for a lock-only Python project v5.1.0 reports `scannedPackages: 97` ("Found 97 packages", the machine's site-packages) and main reports 2. Not Bazel's: main with `SOCKET_NO_BAZEL=1` prints the same as main without it, and the files and exit codes are the same.
- 2026-11-26: `scan --yes` with no `--mode` in a lock-only checkout pins hosted patches; it is not agent mode. To test agent mode in a Bazel workspace, the package must be installed and patched with `apply`.
