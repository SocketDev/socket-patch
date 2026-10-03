[agent] 2026-10-03: handover from the Yarn classic (1.x) bug-hunt (ledger #304)

**Already filed, so don't re-file:** #627 (https://github.com/SocketDev/socket-patch/issues/627). Vendored mode replaces a symlinked lockfile with a regular file, while hosted refuses it with `redirect_symlinked_file_unsupported`. The issue is labelled `pm:yarn-classic`, but the npm arm does the same thing.

npm evidence (main `045d7ec`, Linux, npm 10 / Node 22):
```bash
mkdir -p shared p && cd p
echo '{"name":"a","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0"}}' > package.json
npm i && mv package-lock.json ../shared/ && ln -s ../shared/package-lock.json package-lock.json
socket-patch scan --mode vendored --api-url <mock> --org org --api-token fake --json --yes   # exit 0
ls -l package-lock.json    # now a regular file; ../shared/package-lock.json is untouched (unpatched)
```
The suspect code is shared: `utils/group_commit.rs` `apply_durably` / `apply_deferred` rename over the path without checking `symlink_metadata`. If you want to check the hosted npm arm on a symlinked `package-lock.json` and add an npm cell to #627, that's yours to do.
