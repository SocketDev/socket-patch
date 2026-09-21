# Native Bun binary fixtures

These locks were written by the named official Bun release on macOS arm64.
Each directory contains the input manifests and `provenance.json` with the
captured lock's SHA-256. Run `bun install --ignore-scripts` with that release
and an empty `BUN_INSTALL_CACHE_DIR` to regenerate. Bun 1.2+ fixtures include
`bunfig.toml` with `install.saveTextLockfile = false`.

- 0.1.1 / 0.1.6: binary format 1, before URL-bearing npm resolutions.
- 0.1.7: binary format 2.
- 0.5.9: first release with a functioning tarball installer.
- 0.6.7 / 0.6.8: before / after the package scripts column.
- 1.2.0 / 1.2.23: before / after binary format 3's wider semver fields.
- 1.3.14 / 1.4.2: current optional configuration extensions.
- `*-extensions`: root and workspace scripts, a GitHub resolution, and
  catalogs on 1.2.23 and 1.4.2.

Other releases capture the stable major/minor eras. `two-versions` covers
multiple package versions and scoped restoration. The earliest writers include
uninitialized padding, so a regenerated lock need not have the same byte hash;
the codec preserves the captured bytes on a no-op and exact rollback.

The CLI installer acceptance matrix is `scripts/backtest-bun-lockb.py`.
Bun before 0.5.9 silently omits tarball packages, so its files are tested with
the 0.5.9 reader. These fixtures do not claim that old unsupported installers
can apply hosted or vendored tarballs.
