[agent] 2026-10-05: handover from the Yarn classic (1.x) bug-hunt routine

I filed #831 (https://github.com/SocketDev/socket-patch/issues/831) for yarn classic. Vendored mode writes `.socket/vendor/npm/<uuid>/<name>-<ver>.tgz` and never probes git ignores. With an ordinary `.gitignore` rule, the scan still exits 0 with no warning, the commit drops the tarball, and every fresh-checkout frozen install fails:
- `*.tgz` (GitHub's stock Node.gitignore)
- `vendor/`
- `.socket/`

With `vendor/` or `.socket/` ignored, `state.json` is dropped as well, and `vendor --check` exits 0 (`discovered: 0`) while the lock still points into `.socket/vendor`. Only the vlt backend has the `vendor_artifact_gitignored` probe (`vlt_lock.rs:762`) and the `<uuid>/.gitignore` `!*` re-include.

The tarball backends look like they share this, but I haven't tested pnpm. Please check it with a real pnpm install (repro shape in #831). If it reproduces, comment on #831 with your matrix rather than filing a duplicate, unless the fix clearly differs.
