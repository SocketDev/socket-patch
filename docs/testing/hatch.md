# Hatch patch compatibility

Hatch 1.x projects support hosted wheels and vendored wheels through exact
PEP 508 declarations in `project.dependencies`, optional dependencies, and
Hatch environment `dependencies` / `extra-dependencies`. External
`hatch.toml` tables override the corresponding top-level `tool.hatch` keys.
Project references enable Hatchling's `allow-direct-references` setting.
Vendored references use `{root:uri}` so checkouts remain relocatable.
Vendored environment references require Hatch >=1.2 on PATH; preflight verifies the
installed version because Hatch 1.0 and 1.1 do not expand that context.
Vendored Hatch requires the pip installer; uv currently ignores hash
fragments for local wheels. Hosted Hatch supports both pip and uv.
Both modes pin the wheel SHA-256, preserve extras, markers, comments and
line endings, and record reversible document edits.

Hatch 0.x continues to use the requirements/pip backend. Existing lockfile
and requirements routing retains precedence over Hatchling's build marker.
A build backend alone does not change which existing pip inputs are wired.

A range, transitive-only declaration, dynamic dependency metadata, custom
environment plugin, source table or conditional override is refused before
writing. Use agent mode (`scan --mode agent` + `socket-patch apply` in CI) for these shapes. Hosted PEP 735 groups are
supported; vendored groups are refused because Hatch does not expand
`{root:uri}` within dependency groups. Unknown direct sources require an
explicit revert before patching.

Repeated vendored scans compare the declared source with the committed
artifact path and digest, and verify an existing wheel's bytes. Missing
wheels may be rebuilt only against that recorded pin. Ledgerless direct
references and drifted sources are refused. Concurrent manifest edits and
symlinks are also refused. Each project patch records shared ownership of
the direct-reference permission. Selective and preserved rollback retain the setting while any
project direct reference remains, and restore its original value after the
last reference is unwired.

Existing environments: Hatch keeps a project's environments out of tree
(`<data dir>/env/virtual/<project>/<id>/<env>`, or `HATCH_DATA_DIR`,
`[dirs.env] virtual`, an env's `path`; Hatch 1.0-1.2 use
`<project>-<id>/<env>`), and on the next `hatch run` its pip installer (and
uv before Hatch 1.16) keeps the release already installed there. Socket
Patch finds those environments itself: a hosted scan warns
`redirect_pypi_stale_install`, a vendored one `pypi_hatch_stale_install`,
both naming `hatch env remove <env>` / `hatch env prune`; hosted `vex`
does not attest over a stale env, and vendored `vex` discloses it with
`vendored_tree_out_of_sync`. Agent mode crawls the same environments.

Focused Rust checks:

```sh
cargo test --locked -p socket-patch-core --lib hatch
# real Hatch, existing envs (needs uv + PyPI):
SOCKET_PATCH_HATCH_E2E_REQUIRED=1 cargo test -p socket-patch-cli --test e2e_vex_build -- hatch::hatch_existing_env --ignored
```

The depscan companion PR runs real released Hatch binaries, actual CLI
scans, fresh native installs, installed patch-file hash verification,
wrong-digest rejection, repeated scans and rollback on Linux and Windows.
It also feeds captured manifests through the real SBOM pipeline and seeded
metadata service. Its runner is `tools/pipeline/hatch-patch-backtest.py`.
