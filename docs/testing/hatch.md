# Hatch patch compatibility

Hatch 1.x projects support hosted wheels and vendored wheels through exact
PEP 508 declarations in `project.dependencies`, optional dependencies, and
Hatch environment `dependencies` / `extra-dependencies`. External
`hatch.toml` tables override the corresponding top-level `tool.hatch` keys.
Project references enable Hatchling's `allow-direct-references` setting.
Vendored references use `{root:uri}` so checkouts remain relocatable.
Both modes pin the wheel SHA-256, preserve extras, markers, comments and
line endings, and record reversible document edits.

Hatch 0.x continues to use the requirements/pip backend. Existing lockfile
and requirements routing retains precedence over Hatchling's build marker.
A build backend alone does not change which existing pip inputs are wired.

A range, transitive-only declaration, dynamic dependency metadata, custom
environment plugin, source table or conditional override is refused before
writing. Use the install hook for these shapes. Hosted PEP 735 groups are
supported; vendored groups are refused because Hatch does not expand
`{root:uri}` within dependency groups. Unknown direct sources require an
explicit revert before patching.

Repeated vendored scans compare the declared source with the committed
artifact path and digest, and verify an existing wheel's bytes. Missing
wheels may be rebuilt only against that recorded pin. Ledgerless direct
references and drifted sources are refused. Concurrent manifest edits and
symlinks are also refused. Revert later Hatch patches first when an older
patch owns a direct-reference permission that they still need; attempting
that selective rollback out of order leaves every file unchanged.

Focused Rust checks:

```sh
cargo test --locked -p socket-patch-core --lib hatch
```

The depscan companion PR runs real released Hatch binaries, actual CLI
scans, fresh native installs, installed patch-file hash verification,
wrong-digest rejection, repeated scans and rollback on Linux and Windows.
It also feeds captured manifests through the real SBOM pipeline and seeded
metadata service. Its runner is `tools/pipeline/hatch-patch-backtest.py`.
