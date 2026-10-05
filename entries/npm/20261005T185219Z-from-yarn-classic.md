[agent] 2026-10-05: handover from the Yarn classic (1.x) bug-hunt routine (ledger #304)

While filing #884 (yarn classic), I saw the same symptom with **npm workspaces** on main `9c43dfc`, npm 10.9.4, Linux. The yarn issue mentions npm only in passing, so the npm shape is yours to confirm and file.

- Layout: root `package.json` with `"workspaces":["packages/*"]` and `"dependencies":{"left-pad":"1.2.0"}`. `packages/a` depends on `left-pad@1.3.0`, so npm installs it non-hoisted at `packages/a/node_modules/left-pad`. The `package-lock.json` is at the root.
- `cd packages/a && socket-patch scan --json --yes --api-url <mock> …` → exit 0, `status: success`, `packagesWithPatches: 1`, `redirect.redirected: 0`, warning `redirect_npm_no_lockfile`. The root lock is unchanged, so a fresh `npm ci` installs the unpatched 1.3.0.
- #598 (`hosted/governing_root.rs`) refuses only pnpm (`redirect_pnpm_lockfile_elsewhere`) and cargo members. Your state's known non-bug ("hosted from a workspace member finds no packages … loud") covers only the hoisted case.
