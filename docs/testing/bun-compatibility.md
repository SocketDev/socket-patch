# Bun patch compatibility

`scripts/backtest-bun.py` runs real Bun releases against the public free Socket patch for `minimist@1.2.2` (`80630680-4da6-45f9-bba8-b888e0ffd58c`). It uses the production CLI and patch service, without a token or substitute service.

```sh
cargo build --locked -p socket-patch-cli
python3 scripts/backtest-bun.py \
  --cli target/debug/socket-patch \
  --cli-revision "$(git rev-parse HEAD)" \
  --output /tmp/bun-compatibility \
  --modes hosted vendored vendored-detached
```

Use `--versions 1.4.2 --shapes workspace-nested` for a focused reproduction. Windows uses `target/debug/socket-patch.exe`. The [Bun workflow](../../.github/workflows/bun-compatibility.yml) runs Linux, macOS and Windows; releases before Bun 1.1 have no Windows binary.

The pinned matrix covers 0.8.1, 1.0.0, 1.0.36, 1.1.0, 1.1.38, 1.1.39, 1.1.45, 1.2.0, 1.2.23, 1.3.0, 1.3.14, 1.4.0 and 1.4.2. These span the binary lockfile, the first text locks (version 0), the text default (version 1), and version 2. Configurations cover direct, development, optional, peer, aliased and overridden transitive dependencies; two versions of a package; root and nested workspace dependencies; explicit registries; text-lock opt-in; production installs; projects without `node_modules`; isolated and hoisted linkers; CRLF manifests and paths containing spaces and Unicode.

Every supported case verifies:

- CLI output identifies the expected published patch.
- Fresh frozen and ordinary installs contain the patch record's exact `afterHash` bytes, with unchanged lockfiles.
- Repeated scans preserve lockfile bytes.
- A corrupted digest on the patched tuple is rejected on releases that enforce it.
- Rollback restores original manifest/lock bytes and a clean install reproduces the record's `beforeHash` bytes.

The runner captures the exact project manifests, lockfiles, optional `.socket/manifest.json`, CLI JSON, file hashes and assertion results. Socket SBOM tests import these captures through their existing fixture validation framework. Vendored artifact contents are verified by the native runner; they are not needed for SBOM lockfile annotation.

The `get-uuid` and `get-search` cases also exercise explicit patch retrieval by UUID and PURL, including refusal before manifest writes on unsupported Bun projects.

## Boundaries verified by the matrix

| Configuration | Behavior |
| --- | --- |
| Text lock 0, 1 or 2, no workspaces | Hosted and vendored rewrites supported. |
| Binary lock only | Vendored mode refuses. Hosted mode attempts Bun's native text migration and refuses when that release cannot perform it. Without installed packages, binary locks cannot supply a package inventory. |
| Version-0 workspace lock | Hosted mode refuses because frozen installs cannot preserve the rewrite. |
| Version-0/1 workspace lock | Vendored mode refuses because Bun resolves local tarballs relative to the workspace. Upgrade to Bun 1.4 or later and regenerate the lock. |
| Version-2 workspace lock | Hosted and vendored modes supported, including nested versions. |
| Bun before 1.3.14 in this matrix | Native tarball digest enforcement is absent. The runner records the limitation rather than claiming corruption was rejected. |
| Bun 0.8.1 / 1.0.0 peers or transitive overrides | These releases do not install the selected patched version in these configurations; the CLI leaves the project unchanged. |

Refused vendored downloads do not add a patch record to the manifest. Existing explicit manifest intent is preserved. Detached vendoring keeps its patch record in the vendor ledger and supplies the same lockfile annotation.
