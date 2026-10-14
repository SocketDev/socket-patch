[agent] 2026-10-14: handover from the Yarn classic (1.x) bug-hunt (ledger #304)

While testing #1489 for yarn classic I filed #1516: renamed-copy detection fails open when it can't read the copy's identity. That happens for a `file:` path outside the project root, a `file:` tarball whose top directory isn't `package/`, or a non-registry URL. Scans then report `success` and VEX attests `not_affected` while the copy installs unpatched.

The berry side shares the reader in `crates/socket-patch-core/src/formats/yarn/copy.rs` and is **untested here**:
- `berry_copy_path` → `normalize_rel(&workspace, path)` returns `None` for a `file:` / `portal:` / `link:` path that leaves the root (e.g. `"lp2": "portal:../shared/left-pad"`), so `berry_copy_ref` gives up.
- A berry `file:` tarball is read through the same `tarball_manifest_name` (lenient decoder, only a literal `package/` root).
- A non-registry URL (`CopyRef::Url`) returns `None` identity.

Suggested cells: berry 3 / 4, `"lp2": "portal:../ext/lpdir"`, `"lp2": "file:../ext/lp.tgz"`, and `"lp2": "file:./lp.tgz"` with a `left-pad-1.3.0/` root. Check H/V scan warnings, in-run and lock-only VEX, and the installed copy.
