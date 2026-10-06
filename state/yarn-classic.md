[agent] Progress ledger for the scheduled Yarn classic (1.x) bug-hunt routine (label pm:yarn-classic).

Last updated: 2026-10-06 (run 24), main `9c43dfc`, latest release v4.0.0. Runs 5–24 added the cells in "Run 5 cells" through "Run 24 cells" below. The project-mode matrix below was measured on `f6b7fb9` (v4); cells marked "(v5)", the global matrix and the "v5 project-mode cells" list were re-run on v5.

## Coverage matrix

Cells are "pass", "fail #N", "n/a", "CI" or "untested". H = hosted, V = vendored, A = agent (`scan --apply` + `setup`). Each H/V cell ends with a real fresh-checkout `yarn install --frozen-lockfile`, using a local mock patch API. CI's `yarn-classic-matrix` (1.0.2, 1.6.0, 1.7.0, 1.9.4, 1.10.1, 1.22.22) covers the plain single-dep H/V flows plus VEX on Linux.

| OS | yarn | H baseline | H offline mirror | H/V git dep (`git+…`) | H/V multi-version workspaces + scoped | H⇄V takeover + rollback | H/V CRLF lock + rollback | V baseline | V offline mirror (+pruning, rollback) | A apply + setup |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.0.2 | pass | n/a (yarn limitation) | H pass (run 20, #363 fixed) | H pass | untested | H pass (run 16) | n/a (yarn ≤1.6 can't install `file:` tarballs) | n/a | pass |
| Linux | 1.3.2 / 1.5.1 (run 23) | pass | untested | untested | untested | untested | untested | n/a (yarn ≤1.6) | n/a | pass |
| Linux | 1.6.0 | pass | n/a (yarn limitation) | untested | H pass | untested | H pass (run 16) | n/a (yarn ≤1.6) | n/a | pass (run 17) |
| Linux | 1.7.0 | CI | fail #364 (`--offline`) | pass (run 20, #363 fixed; V git-only: #857) | pass | pass (run 16) | pass (run 16) | pass | untested | pass (run 17) |
| Linux | 1.9.4 | CI | fail #364 (`--offline`) | untested | untested | untested | untested | CI | pass (run 16) | pass (run 17) |
| Linux | 1.10.1 | pass | fail #364 | V git-only: #857 (run 20) | pass | pass | pass (run 16, + BOM) | pass | pass | pass (+ `--install.modules-folder`, run 9) |
| Linux | 1.10.0 / 1.19.0 / 1.19.1 / 1.22.0 (run 24) | pass (+ warm in-place, vex) | untested | untested | untested | untested | untested | pass (+ byte-exact rollback) | untested | pass |
| Linux | 1.17.3 | pass (in-place) | fail #364 | untested | untested | untested | untested | pass (in-place) | pass (run 16) | pass (run 17) |
| Linux | 1.22.22 | pass (v5, + hosted rollback pass) | fail #364 (v5) | pass (run 20, #363 fixed by #710; V git-only: #857; H pin + git sibling: #828) | pass | pass | pass | pass | pass | pass |
| macOS | 1.7.0 | untested | untested | fail #363 | pass | pass | pass | pass | pass (run 18) | pass (run 18) |
| macOS | 1.10.1 / 1.22.22 | pass (probe) | fail #364 | fail #363 | pass | pass | pass | pass | pass (run 18) | pass (run 18) |
| Windows | 1.7.0 / 1.10.1 / 1.22.22 | pass (probe) | fail #364 (1.10.1/1.22.22) | fail #363 (vendored: `Couldn't find the binary git`) | pass | pass | pass | pass | pass (run 18) | pass (run 18) |

### Global mode (`-g`) on v5 `2463257` (rows marked run 10 re-measured on `045d7ec`)
Report = `scan -g` report-only + no leakage; refusal = `scan -g/--global-prefix/SOCKET_GLOBAL --mode hosted` exits 2; A = agent apply + import + `vex -g` + `rollback -g` byte-exact; get-mode = `get -g --mode hosted|vendored` / `scan -g --mode vendored`; RO = read-only global folder fails loudly.

| OS | yarn | report | refusal | A apply/vex/rollback | get-mode | RO | custom global-folder (space+unicode) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.0 / 1.3.2 (run 23) | pass | untested | pass | untested | untested | untested |
| Linux | 1.0.2 | fail #437 (still on `203e092`) | pass | fail #437 | fixed (#436 closed by #446; not re-run) | n/a (nothing found) | untested |
| Linux | 1.6.0 / 1.9.4 / 1.10.1 / 1.22.22 (+ corepack 1.22.22), run 10 | pass | pass | pass | pass (#436 fixed) | pass (CI runner) | pass (all) |
| macOS | 1.0.2 | fail #437 (run 10) | pass | fail #437 | pass (run 10) | n/a | pass (run 10) |
| macOS | 1.6.0 / 1.9.4 / 1.10.1 / 1.22.22 (+ corepack), run 10 | pass (after warming the mock, see Known non-bugs) | pass | pass | pass (#436 fixed) | pass | pass |
| Windows | 1.0.2 | fail #437 (run 10; #434 fixed) | pass | fail #437 | pass (run 10) | untested | pass (run 10) |
| Windows | 1.6.0 / 1.9.4 / 1.10.1 / 1.22.22 (+ corepack), run 10 | pass (#434 fixed) | pass | pass | pass (#436 fixed) | untested | pass (space+unicode) |

GitHub deps with a real codeload install (`owner/repo#tag`, `github:`, archive URL), H and V + frozen + vex + V rollback: pass on Linux / macOS / Windows × 1.7.0 / 1.10.1 / 1.22.22 (run 22 probe).

Other cells that pass on Linux 1.22.22 (some also on older releases; see the entries): spaces + unicode project paths (also macOS and Windows), `npm:` alias (H skipped as documented, V rewired), `resolutions`, a `resolved` without the `#sha1` fragment / `integrity`, a local `file:` tarball dep, a non-deduplicated lock, a superseding patch on re-scan, `remove` / `repair`, VEX (installed and lock-only, after `yarn upgrade`), `yarn add` then a frozen reinstall (1.7.0 too), `yarn check --integrity` / `--verify-tree`, in-place reinstalls on 1.7–1.22, concurrent scans (`lock_held`), the GitHub shorthand dep on all 3 OSes.

### v5 project-mode cells (Linux, run 4)
- Mixed CRLF+LF lock, H and V: **fail #467** (line endings converted; rollback not byte-exact).
- Uniform CRLF / BOM+CRLF: H⇄V takeovers + rollback, pass. `--dry-run` byte-identity (H / V / A / rollback) on CRLF / BOM / mixed, pass.
- V service artifacts: workspaces + multi-version + merged key + `npm:` alias, vex / `vendor --check` / `repair` / frozen offline / rollback, pass (1.22.22).
- V + offline mirror + pruning: pass (1.7.0 / 1.10.1 / 1.22.22).
- No-`integrity` (1.7-style) locks, H and V: pass (1.7.0 / 1.22.22). Tarball-URL dep, H and V: pass. `file:` dir dep, H: pass.
- SIGKILL-interrupted scans, H and V: pass (recoverable by `repair` / re-scan).

### Run 5 cells (Linux, `61cfb9b`)
- `.yarnrc --modules-folder`, agent mode: fail #493 (1.7.0 / 1.10.1 / 1.22.22); fixed by #520 (see run 9).
- Workspaces with `nohoist`, A/H/V + frozen install + vex: pass (1.22.22).
- `--max-new-patches` on a workspace, A/H/V + re-run + frozen install: pass (1.22.22).
- Custom `.yarnrc registry`, hosted rewire + rollback: pass (rollback uses `SOCKET_NPM_REGISTRY`, as documented).
- Hosted over an installed tree, then an in-place frozen reinstall: pass.
- #363 re-checked: still fails (1.22.22).

### Run 6 cells (Linux, `61cfb9b`)
- PnP (`installConfig.pnp`) with a stale `.pnp.js` + hosted pin → `vex`: **fail #519** (1.12.3 / 1.17.3 / 1.22.22). PnP `scan` refusal in all modes: pass. PnP lock-only hosted + frozen install: patched.
- `--modules-folder` + stale `deps/` + hosted pin → `vex`: **fail #493** (commented; 1.10.1 / 1.22.22). `--modules-folder` hosted / vendored + frozen install: pass.
- `optionalDependencies` incl. platform-skipped `fsevents`, H/V + frozen install + vex: pass (1.22.22).
- Uppercase names (`JSONStream`), A/H/V + frozen + vex + rollback: pass. `yarn import` locks, H/V: pass.
- Hosted pin `Authorization` leakage (6 `.npmrc` auth configs): none on 1.0.2 / 1.6.0 / 1.9.4 / 1.12.3 / 1.17.3 / 1.22.22: pass.

### Run 7 cells (`61cfb9b`)
- Dev flow after scan (`yarn add`, then a frozen fresh install, `vex`, `vendor --check`, `--pure-lockfile` reinstall), H and V: pass on Linux 1.0.2 / 1.6.0 (H) and 1.7.0 / 1.10.1 / 1.22.22, Windows 1.7.0 / 1.10.1 / 1.22.22, macOS 1.7.0 / 1.22.22 (probe).
- `--production` install, hosted + vex: pass (1.22.22). `integrity sha1-` locks, H / V + rollback: pass (1.10.1 / 1.22.22).
- Odd range keys (`">= a < b"`, `||`, `x`, hyphen, `latest`, `v`-prefix), H: pass. Workspace member under `tests/` + `socket.yml` policies (A/H): pass.
- `yarn set version classic` layout (`.yarnrc.yml` yarnPath + `packageManager`), A/H/V: pass. `vendor --revert` on LF / CRLF / BOM+CRLF (1.7.0 / 1.22.22): byte-exact.

### Run 8 cells (Linux, `61cfb9b`)
- Hosted grant without `integrity.sha1` → fragmentless `resolved` → yarn cache-slot collision: **fail #558**. Warm-cache frozen install: 1.0.2 / 1.7.0 / 1.10.1 / 1.17.3 silently install unpatched bytes; 1.19.0 / 1.21.1 / 1.22.22 fail `Incorrect integrity when fetching from the cache`. v4.0.0 is affected too.
- Merge-conflict markers in yarn.lock (target outside the conflict), H: pass. `--focus` workspace install, H: pass. `yarn audit` on hosted / alias locks: pass. `.yarnclean`, H + vex: pass (1.22.22).
- Hosted rollback on an `integrity sha1-` lock: restores sha512 integrity + npmjs host (documented), frozen install OK: pass (1.10.1).

### Run 9 cells (Linux, `203e092`)
- Patch rewriting the package's own `package.json` (adds a dependency): **fail #591**. Vendored leaves a dangling `dependencies:` entry (offline frozen install fails, lock churns) on 1.7.0 / 1.10.1 / 1.22.22. Hosted never installs the new dep, and vex attests (1.10.1 / 1.22.22).
- #493 follow-ups after #520: workspace root `--modules-folder` + non-hoisted members (agent, 1.22.22) and `--install.modules-folder "./my deps"` (agent + vex + frozen-reinstall omission, 1.10.1): pass.
- Agent vex with multiple installed copies across workspaces (#517): pass (1.22.22).
- Repo suites (redirect / vendor / dev-flow, REQUIRED=1): pass on 1.0.2 / 1.7.0 / 1.22.22.
- Superseding hosted patch followed by an in-place frozen install: pass on 1.10.1 / 1.17.3 / 1.22.22. 1.0.2 / 1.7.0 skip the copy only when size+mtime match (yarn limitation, see Known non-bugs).

### Run 10 cells (`045d7ec`)
- Symlinked `yarn.lock` (`yarn.lock -> ../shared/yarn.lock`): hosted refuses (`redirect_symlinked_file_unsupported`); **vendored replaces the link with a regular file, leaving the target unpatched: fail #627** (1.7.0 / 1.10.1 / 1.22.22; npm's `package-lock.json` too). `--dry-run` gives no signal, and rollback doesn't restore the link. yarn itself writes through the link.
- `yarn.lock` file mode 600 / 444 / 755 preserved through H / V scan + rollback: pass (1.22.22).
- Patch that changes an existing dependency range (is-odd `is-number ^6 → ^7`): same as #591 (commented). Vendored leaves `^7.0.0` unpinned, and hosted installs 6.0.0 under a manifest that asks for ^7.
- Agent mode with a `link:` dep: patches the link target outside the project (the code Node loads). Design question, not filed.
- #467 re-checked: still reproduces (H and V, 1.22.22).

### Run 11 cells (Linux, `045d7ec`)
- No trailing newline (LF / CRLF, target block last) and CRLF + trailing blank lines, H and V + fresh frozen install + rollback: pass (1.22.22).
- Symlinked `.socket/` or `.socket/vendor/npm`, single project, V: pass (consistent). **Two projects sharing a symlinked `.socket/vendor/npm`: fail #664** (1.7.0 / 1.10.1 / 1.22.22).
- **`yarn remove` of a vendored package, then rollback / remove / `vendor --revert`: fail #665** (1.7.0 / 1.22.22). Hosted same flow: pass.

### Run 12 cells (`045d7ec`)
- **Vendored workspaces, installs from a member dir (`cd b && yarn install --frozen-lockfile`, `yarn --cwd b install`, `yarn workspace b add`), cold cache: fail #691** on Linux / macOS / Windows × 1.7.0 / 1.10.1 / 1.22.22 (probe run 37123949202). Root installs pass. Warm-cache member installs pass (masking).
- **Vendored block merged by yarn with a second range (`a@^1.1.0, a@^1.3.0:`) → rollback / remove / `vendor --revert`: fail #692** (Linux 1.7.0 / 1.10.1 / 1.22.22). Re-vendor says `already_vendored` and doesn't re-key.
- `yarn add`/`yarn upgrade` that re-keys or re-resolves the vendored block: the #665 shape (fix in flight, #689).

### Run 13 cells (Linux, `045d7ec`)
- Hosted with a merged key created after the scan → rollback: pass (1.22.22). Hosted isn't affected by #692.
- Vendored #692 shape: `vendor --check` reports OK and `repair` is a no-op while rollback fails: fail #692 (commented).
- Merged key already present before vendoring, V + frozen install + rollback byte-exact: pass (1.22.22).
- Scoped merged key: H frozen install on 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22 pass; V on 1.7.0 / 1.10.1 / 1.22.22 pass (rollback byte-exact); H⇄V takeover chain + re-run + rollback pass.

### Run 14 cells (Linux, `045d7ec`)
- Fork alias `"left-pad": "npm:async@1.3.0"` and the yarn-merged `left-pad@1.3.0, "left-pad@npm:async@1.3.0":` block, H/V/A: all fail-closed, pass (1.22.22).
- agent → hosted takeover + rollback: pass. **agent → vendored takeover + rollback / remove / `vendor --revert`: fail #336** (node_modules left patched, record dropped, yarn's next frozen install is "Already up-to-date"). 1.7.0 / 1.10.1 / 1.22.22.
- #591 shape: `vendor --check` OK and `repair` no-op: fail #591 (commented).
- `yarn.lock` + `package-lock.json` together, H and V: pass. Hosted `vex` before reinstall: `not_applied`, pass. `--link-duplicates` agent apply / vex / rollback: pass.

### Run 15 cells (Linux, `045d7ec`)
- **Bundled copy (`bundledDependencies`) of the patched name@version beside the normal copy: fail #758.** The scan gives no warning. The hosted in-run `--vex` attests, and vendored in-run and post-install `vex` attest, while the bundled copy stays unpatched. Hosted post-install `vex` and agent mode are correct. 1.7.0 / 1.10.1 / 1.22.22.
- `get <uuid> --mode hosted|vendored|agent` (project mode) + frozen install + vex: pass. `list` (H / V / A / CRLF+BOM merged-key workspace / `--json`): pass (1.22.22).
- `scan --mode vendored --prune` after `yarn remove`: entry kept (`keptVendoredEntries`), fail #665 (PR #689 covers the prune path).
- Vendored odd range keys merged into one block (hyphen, `||`, `>= <`, `v`-prefix) + frozen install + rollback byte-exact: pass. 20k-block lock hosted scan: 2.9 s, pass.
- vendored → agent → reinstall → `apply` → rollback → frozen reinstall: pass (1.22.22).

### Run 16 cells (`045d7ec`)
- **Windows path shapes** (probe, windows-latest, yarn 1.10.1 / 1.22.22; H/V scan + fresh frozen install + rollback, A apply + vex + rollback): a >MAX_PATH project path (345 chars), a directory-junction project dir, a `subst` drive (`--cwd X:/p` from another drive, and run inside `X:\`), cross-drive `--cwd` both ways, a backslash `--cwd`: all pass. yarn on Windows writes CRLF locks natively (`os.EOL`), and H/V rollback restores them byte-exact.
- Linux: CRLF H/V + rollback (1.0.2 / 1.6.0 H; 1.7.0 / 1.10.1 H+V), H⇄V takeover chain on 1.7.0 and BOM+CRLF on 1.10.1, V offline mirror on 1.9.4 / 1.17.3, `yarn add` (1.7.0) then rollback, a lock-only workspace with an alias, conflict markers around the target (fail-closed), a missing vendored artifact (`vex` omits it): all pass. Also a 414-char path and a symlinked project dir.

### Run 17 cells (`045d7ec`)
- **Cross-OS vendored checkout portability** (probe run 37226728998, yarn 1.22.22): a project vendored on Linux, macOS or Windows, then installed `--frozen-lockfile --offline` (cold cache), `vendor --check`, `vex --offline`, `list` and rollback on each of the three OSes. All 9 cells pass, with rollback byte-exact (CRLF for a Windows producer). Windows writes forward-slash `file:./.socket/…` paths.
- A 4-package project (prerelease `ms@3.0.0-canary.1`, dotted `lodash.isequal`, scoped `@types/left-pad`, `left-pad`): H pass on 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22, V pass (byte-exact rollback) on 1.7.0 / 1.10.1 / 1.22.22, A (apply + vex + rollback) pass on 1.6.0 / 1.7.0 / 1.9.4 / 1.17.3 / 1.22.22.
- Private-registry `resolved` URLs (Verdaccio `%2f`, Nexus, a URL with no `.tgz` basename), H and V: pass. A vendored grant without `sha1`: vendored computes `#sha1`, and the warm-cache install is patched (not #558). A tampered vendored tarball → check fails, vex omits it, repair restores: pass. Vendored re-run idempotent, and V→H→V: pass. `get <purl>` for prerelease / scoped purls (`%40` or `@`): pass.

### Run 18 cells (`045d7ec`)
- **macOS + Windows probe** (run 37248870997; yarn 1.7.0 / 1.10.1 / 1.22.22): project agent apply + vex + rollback + re-run, pass. V + offline mirror + pruning (fresh offline frozen, in-place offline, byte-exact rollback, post-rollback offline install), pass. agent → vendored takeover + rollback: **fail #336** on all 6 cells (commented).
- Linux warm-cache H / V / A (+ V / A rollback) on 1.12.3 / 1.13.0 / 1.15.2 / 1.16.0 / 1.18.0 / 1.19.2 / 1.21.1: pass.
- Multi-hash `integrity "sha1-… sha512-…"` target block, H / V: pass. Lookalike same-version blocks (`@evil/left-pad`, `my-left-pad`) untouched: pass. Hosted workspace member-dir frozen installs (`cd member`, `--cwd member`): pass.

### Run 19 cells (Linux, `045d7ec`)
- **Vendored + `.gitignore` covering the artifact** (`*.tgz`, `vendor/`, `.socket/`), then commit, fresh clone and frozen install: **fail #831** on 1.7.0 / 1.10.1 / 1.22.22. The scan exits 0 silently. With `vendor/` or `.socket/` ignored, `vendor --check` in the clone also exits 0.
- Vendored + `.gitattributes` `* text eol=lf` / `* text=auto eol=crlf`: pass (1.22.22). `* text eol=crlf` corrupts the `.tgz` (see Known non-bugs).

### Run 20 cells (Linux, `4646693`)
- #363 verified fixed on real yarn: git-only dep, H (1.0.2 / 1.7.0 / 1.22.22) and V (1.7.0 / 1.22.22), lock untouched, frozen installs OK, nothing attested: pass.
- **Hosted pin beside a git sibling (workspace registry + `git+…` copies): rollback / remove / list refuse, the takeover skips the restore, and `vendor --revert` lands on hosted: fail, #828 (commented)** on 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22. Pure vendored on the same shape: pass.
- **Vendored git-only dep: misleading `vendor_lock_entry_not_found` and the git warning dropped: fail #857** (1.7.0 / 1.10.1 / 1.22.22).
- #758 still reproduces (1.10.1 / 1.22.22). Run-18 battery (agent, V + mirror) on `4646693`: pass. #336 still fails.
- GitHub shorthand after #710: blocked (no codeload access in the sandbox).

### Run 21 cells (Linux, `9c43dfc`)
- **Hosted scan / `get --mode hosted` from a workspace member with a non-hoisted copy (version conflict or `nohoist`): exit 0 `success`, `redirected: 0`, npm-only `redirect_npm_no_lockfile`: fail #884** on 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22 (×2 each). #598 refuses only pnpm and cargo members. npm workspaces have the same symptom, handed to the npm ledger.
- #627 verified fixed (#802): vendored refuses a symlinked yarn.lock with `redirect_symlinked_file_unsupported`, and the target is untouched: pass.
- #467 still reproduces (H and V mixed-EOL rewrite / rollback not byte-exact). #692 still reproduces, and the code is now `vendor_lock_entry_removed` (commented).
- GitHub shorthand `owner/repo#tag` and `github:owner/repo#tag` (synthetic codeload lock, real yarn installs from the hosted / vendored URL): H rewire + frozen fresh install on 1.7.0 / 1.22.22 + vex: pass. V rewire + frozen install + byte-exact rollback: pass. H rollback lands on the npm **registry** tarball, not the original codeload URL (contract: "default upstream entry"); recorded as a design question.
- #858 atomic writes: yarn.lock mode 0640 preserved (H/V): pass. A hard-linked yarn.lock is split from its other link (expected for stage-and-rename; not filed).
- #865 digests: a vendored grant without `sha1` computes the right `#sha1` (it matches `sha1sum`), and frozen installs on 1.7.0 / 1.22.22 pass.
- `nohoist` workspace from the root: A apply / rollback, H and V frozen fresh installs patched in the member, vex: pass.
- Twin lock (yarn.lock + package-lock.json) after #799: vendored wires yarn.lock with `vendor_multiple_lockfiles`, and vex refuses `patched_ref_unattributable` (fail-closed, as #799 intends).

### Run 22 cells (`9c43dfc`)
- **Hosted pin on a v1 lock, then a berry (4.18.1) install: fail #907.** Berry migrates the lock and installs unpatched, and hosted gives no warning (even with `packageManager: yarn@4`). Vendored warns with `yarn_classic_berry_migration_risk`. Locks from 1.7.0 / 1.10.1 / 1.22.22.
- GitHub shorthand / `github:` / archive-URL deps with real codeload (probe run 37395884885): 27/27 pass on all 3 OSes × 1.7.0 / 1.10.1 / 1.22.22. yarn writes no `integrity` for codeload entries.
- PR #901 (unmerged) fixes #884 on yarn 1.7.0 / 1.22.22: plain, object-form + `nohoist`, and `**`-glob members are refused, and a nested separate project still pins. PR #839 (unmerged) turns #364 into a `redirect_yarn_classic_offline_mirror` skip; frozen online and `--offline` installs work, unpatched.
- Agent + `yarn add` (re-copy) then vex: `not_applied`, pass. A first-party workspace member named like the patched package: refused in all modes, pass. The vendored migration warning is suppressed by `yarn@1…` pins, pass.

### Run 23 cells (Linux, `9c43dfc`)
- **`file:` directory copy of the patched name@version beside a registry copy (workspace member `file:../forks/left-pad`): fail #921.** H / V give no warning; lock-only `vex` (H and V) and V post-install `vex` attest `not_affected` while `b/node_modules/left-pad` stays unpatched. 1.0.2 (H) / 1.7.0 / 1.10.1 / 1.22.22. H post-install vex and agent: correct. When the `file:` block is the only copy, hosted `--json` is silent (`redirected: 0`, no warning) and V says `vendor_lock_entry_not_found` (same issue).
- 1.3.2 / 1.5.1: H baseline + vex, A apply + vex + rollback: pass. Global `-g` report / agent / rollback on 1.1.0 / 1.3.2: pass.

### Run 24 cells (Linux, `9c43dfc`)
- **A registry block beside the pin for the same name@version, after `yarn add -W left-pad --exact`: fail #938.** A fresh frozen install installs only the unpatched registry copy. Lock-only `vex` (H/V), V post-install `vex` and `vendor --check` all pass it as patched. 1.7.0 / 1.10.1 / 1.22.22. Non-exact re-adds, `upgrade` and member ranges merge into the pinned block: pass.
- `--package` (name / scoped / purl ± version), `--min-severity` (+ `--package`), agent `--sync` after `yarn remove`, agent `--strict` with a local edit, vendored 3-package `remove <purl>` + byte-exact rollback: pass (1.22.22).
- Boundary releases 1.10.0 / 1.19.0 / 1.19.1 / 1.22.0, H / V / A with 3 packages incl. scoped: pass.
- A lockfile-less yarn project (`--install.no-lockfile`): hosted `success` / `redirected: 0` with the npm-only `redirect_npm_no_lockfile` text. Naming nit, not filed (see Known non-bugs).

## Backlog

1. Re-check #884 (PR #901, verified on its head in run 22) / #364 (PR #839, verified as a skip) / #831 (PR #837) / #907 (PR #917) once merged, plus #828's yarn git-sibling shape. Then #467 / #519 / #558 / #591 / #691 / #692 / #758 / #857 / #921 / #938.
2. #938 variants: a non-workspace project with a transitive dep on the pinned range; a lock merge that brings in a separately keyed block; check whether npm / pnpm have a same-lock analogue (hand over if so).
3. #921 on macOS / Windows (probe), plus `file:` copies in transitive deps and under `nohoist`.
4. `bitbucket:` / `gitlab:` shorthands (needs a package mirrored there). The GitHub forms are done (run 22).
5. Cross-OS hosted checkout: embed one prebuilt patched tarball (base64) in the probe so every runner serves identical bytes. Add workspaces to the cross-OS vendored probe.
6. #758 follow-ups: a real registry package with `bundledDependencies`.
7. **Maintainer request (global mode), what's left:** the Windows MSI install of yarn, and a read-only prefix on Windows with a non-admin user. #437 (1.0.x) is still open. macOS case-insensitive name collisions.
8. Not yet covered: `--manifest-path`, `--all-releases`, `--download-mode`, `get <CVE|GHSA>` on yarn projects.

## Known non-bugs

- `patches-api.socket.dev` isn't used here. Use a local mock API (`--api-url`). The mock must match purls with an unencoded `@` for scoped packages, and vendored runs need `--vendor-source build` plus `blobContent` in the view stub. For hosted `vex` on lock-only checkouts, pass `--patch-server-url <mock>` (CLI_CONTRACT "Patch hosts"); otherwise `package_not_found` is expected.
- **yarn 1.0.2 – 1.6.x install nothing (exit 0, empty node_modules) for `file:` tarball lock entries and offline-mirror installs, even without socket-patch.** Bisected in run 2: Node 10.24.1 / 14.21.3 / 16.20.2 / 22 all behave the same, and 1.7.0 works on all of them. The cause is in yarn, not Node or socket-patch, which is why CI reports `KNOWN LIMITATION` for vendored ≤ 1.6. Not in docs/ecosystems.md.
- An `npm:` alias entry is left unpatched in hosted mode with `redirect_yarn_classic_alias_skipped` (documented), and `vex` omits the package.
- A BOM plus no yarn header comment makes the first entry `entry_not_found`. Yarn always writes the header, so this is synthetic.
- `file:` directory and `link:` deps are skipped by design. (`file:` **tarball** deps are rewired and work.)
- The GitHub shorthand `owner/repo#tag` locks as a codeload tarball and is correctly rewired; only `git+…` patterns are #363.
- Running `scan` from a workspace member dir whose deps are all hoisted: hosted says "No packages found" (exit 0, nothing to pin). Vendored refuses `vendor_lockfile_missing` (exit 1). *Reclassified in run 21:* when the member has its own non-hoisted copy, hosted's silent success is #884 (the #590 shape), not a documented posture.
- hosted→agent / vendored→agent keep the existing wiring (`hosted_wiring_retained` / `vendored_ownership_retained`), as documented.
- Concurrent scans: the extras fail with `lock_held` (intended).
- Probe branches can't be deleted from the sandbox (the git proxy rejects ref deletion). Leftovers: `bughunt/yarn-classic/20260930-mirror-git`, `bughunt/yarn-classic/20261001-win-crlf-git`.
- **v5 hosted `rollback` / `remove` need the npm registry.** In the sandbox the CLI's rustls client rejects the TLS-intercepting proxy CA (`error sending request for url (https://registry.npmjs.org/…)`). That's a sandbox artifact. Use a local plain-HTTP registry passthrough with `env -u HTTPS_PROXY -u https_proxy SOCKET_NPM_REGISTRY=http://127.0.0.1:<port>`. With `SOCKET_NPM_REGISTRY` set, the restored `resolved` uses `dist.tarball` verbatim (registry.npmjs.org), not registry.yarnpkg.com. That's by design (`npm.rs` `yarn_classic_tarball`).
- v5 vendored mode has no local build (`--vendor-source build` is rejected). The mock must serve a `tarball` artifact from `POST …/patches/package`.
- `scan -g` also reports npm's own bundled deps (npm global root), e.g. `@isaacs/string-locale-compare`. That's correct global discovery.
- Probe branch `bughunt/yarn-classic/20261001-global-mode` is also left on the remote (the proxy blocks deletion).

- Hosted pins are recognized only on `patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. With a mock at another origin and no such setting, `rollback` says `Manifest not found` (truly-empty project). Set `SOCKET_PATCH_SERVER_URL=<mock>`.
- Hosted rollback of a lock without `integrity` lines (yarn < 1.10) adds `integrity` lines. That's the "default upstream entry", and yarn 1.7 still installs it frozen.
- Vendored mode on yarn ≤ 1.6 installs nothing. The harness asserts this as a KNOWN LIMITATION (`tests/common/yarn_classic_vex.rs:89`); it's not in the user docs.
- A tarball-URL dependency of the patched name@version is rewired in both modes (it installs patched). Whether a URL "fork" should be refused, as vlt does, is a design question.
- A SIGKILL can leave the lock wired with no `vendor/state.json`. `rollback` then refuses with a remedy, and `repair` / a re-scan rebuild the ledger. That's intended crash handling.
- Hosted rollback ignores the `.yarnrc` `registry` and queries `SOCKET_NPM_REGISTRY` (default registry.npmjs.org). That's documented (CLI_CONTRACT Hosted unwind / env table). Set `SOCKET_NPM_REGISTRY` behind a private registry.
- A nested non-workspace project (its own `yarn.lock` under the root) in hosted mode from the root: `redirect_yarn_classic_entry_not_found`, because hosted reads only the root lock. That's the documented one-project model (run with `--cwd` per project).
- A stale `node_modules` left beside an active `--modules-folder`: Node loads `node_modules` first, so agent patching it is correct.
- Yarn classic never sends `.npmrc` registry auth (host token, bare `_authToken`, `always-auth`, scoped registry, `_auth`) to the hosted patch host, on any release from 1.0.2 to 1.22.22. The berry #404 leak doesn't apply to classic.
- Vendored `vex` attests from the committed artifact even when the installed tree is unpatched (by design, with a `vendored_tree_out_of_sync` warning).
- `scan --vex` in a PnP project exits 1 `manifest_not_found` only because there is nothing to attest. Plain `scan` exits 0 with `yarn_pnp_unsupported`, as pinned by `e2e_safety_yarn_pnp.rs`.
- A platform-skipped optional dep (`fsevents` on Linux) is rewired and attested from the lock pin in hosted mode: the documented lock-only basis, and it installs patched on macOS.
- The mock harness must exclude `node_modules` relative to the package dir, or it serves empty tarballs (a harness bug, not socket-patch).
- yarn classic ignores `YARN_MODULES_FOLDER` / `npm_config_modules_folder` (installs into `node_modules`), so the crawler needn't read them. A `~/.yarnrc` `--modules-folder` resolves relative to `$HOME`, not the project.
- v5 has no `setup` subcommand. Agent cells use `apply`.
- Probe branch `bughunt/yarn-classic/20261002-dev-flow` is also left on the remote (the proxy blocks deletion).
- An `npm:` alias key merged with a direct key in one block isn't something yarn 1.22.22 writes (it emits two blocks), so don't test that shape.
- Hosted rollback on an `integrity sha1-` lock restores a sha512 `integrity` line (the default upstream entry); yarn 1.10 installs it frozen.
- `patch.socket.dev` / `patches-api.socket.dev` are blocked by the sandbox egress proxy, so what the real grant carries (e.g. whether `sha1` is present) can't be checked from here.
- yarn 1.0.x–1.9.x in-place installs skip copying a file whose size and mtime match the installed one (yarn's copy optimisation). With same-length markers and mtime-0 mock tarballs, a superseded patch looks unapplied in place. Fresh installs and 1.10+ are fine. Use different-length markers in harnesses.
- A `.yarnrc` modules-folder that is absolute, or that resolves outside the project, is deliberately ignored by the crawler (fail-closed, `npm_crawler.rs` `resolve_modules_folder`).
- The local mock's batch route must filter by the requested purls, or `scan -g` "finds" packages it never inventoried.
- **macOS probe harness:** the first TCP connects to a freshly started Python mock on a macOS runner stall for 10–30 s. Before #581 the first `scan -g` simply took ~35 s. Since #581's 10 s connect bound, those batches fail (`api_batch_failed` / "All N API batch queries failed", exit 1). This is a harness artifact: warm the mock with a `curl` loop before the first scan. Once warm, `-g` report / agent / vex pass on macOS.
- Agent mode patches a `link:` / `yarn link` dependency's target directory, even outside the project. That's the code Node loads; whether to refuse it is a design question.
- Leftover probe branches (deletion blocked): `bughunt/yarn-classic/20261003-global-rerun`, `bughunt/yarn-classic/20261003-macos-global`.
- A symlinked `.socket/` or `.socket/vendor/npm` in a *single* project works consistently in vendored mode (writes and cleans up at the link target). Only a store shared between projects is #664.
- `vex -o` is `--org`, not `--output`. Use `--output` in harnesses.
- Hosted rollback after `yarn remove` of a patched package: pass (restores the remaining blocks, removes `.socket/`).
- Leftover probe branch (deletion blocked): `bughunt/yarn-classic/20261003-member-install`.
- Quick vendored harness: a scratch cargo test using `tests/prebuilt_common` `prepare_command` (auto-mocks the service for `vendor`/`repair`) plus a staged `.socket/manifest.json` + blob, as in `e2e_vendor_yarn_classic_dev_flow.rs`. Other commands (rollback / remove / `vendor --revert` / `--check`) run offline with the plain binary.
- A plain root `yarn add <pkg>@<new range>` re-resolves a vendored block from the registry (unpatched). That's yarn's own behaviour; the follow-on rollback is #665.
- A vendored lock after a hosted→vendored takeover, rolled back, restores `registry.npmjs.org` (the hosted-unwound entry, via `SOCKET_NPM_REGISTRY`), not the original `registry.yarnpkg.com`. Documented; frozen installs are fine.
- Agent-mode mock: serve `GET /v0/orgs/<org>/patches/blob/<hash>` for both the before and the after hash. `…/patches/diff/<uuid>` may 404 (it falls back to blobs). Without the before blob, rollback reports `missing_blob`.
- `vex` in a workspace root whose `package.json` has no `version` exits `product_undetected`. Pass `--product`.
- yarn classic itself merges `left-pad@1.3.0` into an existing `left-pad@npm:async@1.3.0` block (it installs the fork for the real name). That's a yarn bug; socket-patch fails closed on that block in all modes.
- With `yarn.lock` and `package-lock.json` both present, hosted rewrites both (and writes `.npmrc` allow-remote), and vendored wires `yarn.lock` with `vendor_multiple_lockfiles`. Intended.
- After `yarn remove` of a vendored package, `list` still shows the entry as "recorded in .socket/vendor/state.json". That's accurate about the ledger; the cleanup gap is #665.
- Rebuilt the mock in run 15: the public-proxy path also calls `GET /patch/by-package/<purl>` (a `SearchResponse` with the patch summary) before `/patch/view/<uuid>`. Without it, scan says "could not fetch patch details".
- **Windows probe harness:** Git-Bash `sed` drops CR bytes, so a `sed`-normalised copy of yarn's CRLF lock never equals the original. Compare locks with raw `cmp`. Git-Bash also can't exec a program from a cwd longer than MAX_PATH; run `yarn --cwd <long path>` from a short dir.
- yarn 1.x on Windows writes *new* lockfiles with CRLF (`os.EOL`, `writeFilePreservingEol`), and keeps an existing file's EOL. CRLF locks are therefore the default on Windows, not an edge case.
- Running `scan --mode agent` from a workspace member dir finds nothing ("No packages found"), because the hoisted copies live under the root. That's the documented one-project model: run from the root.
- Leftover probe branch (deletion blocked): `bughunt/yarn-classic/20261004-win-paths`.
- **Probe harness:** `actions/upload-artifact` drops dot-directories (`.socket/`) unless you set `include-hidden-files: true`. A per-runner Python mock builds tarballs with that OS's zlib, so hashes differ across OSes. Ship one shared mock artifact for hosted cross-OS tests.
- `get name@version` (not a purl) runs the fuzzy package-name search, and against the mock it returns `no_packages`. Use a `pkg:` purl or a uuid.
- Leftover probe branch (deletion blocked): `bughunt/yarn-classic/20261004-xos-vendored`.
- Agent mode never crawls a workspace member under `vendor/`, `build/`, `dist/`, `tmp/`, `temp/`, `coverage/`, `__pycache__/` or a hidden dir (e.g. `.github/actions/*`), even when yarn `workspaces` declares it. That's the documented walk (docs/ecosystems.md "npm: which node_modules trees are crawled"); whether declared workspaces should override it is a design question.
- Leftover probe branch (deletion blocked): `bughunt/yarn-classic/20261005-agent-xos`.
- **Self-contained mock (run 18):** one Python file serving `left-pad@1.3.0` for all modes (batch, by-package, view with `blobContent`, `…/package` grant with a sha512+sha1 tarball artifact, `/artifacts/<uuid>/…`, `blob/<hash>` for before and after). It lives in the run-18 probe workflow on `bughunt/yarn-classic/20261005-agent-xos`.
- A `.gitattributes` `* text eol=crlf` (forced text for every file) corrupts the vendored `.tgz` on checkout. The same setting corrupts every binary in the repo, so it's not filed; `vendor --check` reports it (`vendor_artifact_unreadable`). vlt guards it with a `<uuid>/.gitattributes` `* -text`, and the tarball backend doesn't. `* text=auto …` and `* text eol=lf` are fine.
- #363 / #664 / #665 were closed by #710 / #666 / #689. Don't re-file the git-rewire shape; a git block is now skipped by design (docs/ecosystems.md "yarn classic git dependencies").
- yarn 1.0.2 installs a single copy (the git one, at the root) for a workspace that has both a registry block and a git block of the same `name@version`. The hosted pin then never reaches `node_modules`, but the scan's `redirect_yarn_classic_git_skipped` warning covers it and `vex` doesn't attest.
- The sandbox can't reach codeload.github.com, so GitHub-shorthand deps need a probe branch.
- Hosted rollback of a GitHub-shorthand dep (`owner/repo#tag`, codeload lock) restores the npm registry tarball, not the codeload URL. CLI_CONTRACT "Hosted unwind coverage" says pins go back to the default upstream registry entry. Vendored rollback is byte-exact. Whether a non-registry origin should be refused (as composer does) is a design question.
- Leftover probe branch (deletion blocked): `bughunt/yarn-classic/20261006-gh-shorthand`.
- yarn 1.22.x refuses to install when `package.json` declares a berry `packageManager` (corepack guard). To build a mid-migration fixture, install first and then add the `packageManager` field.
- Building two PR worktrees into one `CARGO_TARGET_DIR` can reuse the first binary unchanged ("Finished in 0.18s"). Touch the sources or use separate target dirs, and `cmp` the binaries.
- Agent-mode first-party refusal: JSON `apply.failed` is 0 while the human summary says "1 failed" (`status: partial_failure`, exit 1). Cross-ecosystem and minor; not filed.
- Keep yarn's `--cache-folder` outside the project in harnesses, or agent mode also patches the cache copies under it.
- `file:` **directory** deps are first-party source for link-based managers, but yarn 1 *copies* them into `node_modules`, and agent mode patches that copy. The hosted / vendored / VEX gap for that copy is #921, not a non-bug.
- A yarn project with no lockfile (`--install.no-lockfile`) gets hosted `success` / `redirected: 0` with `redirect_npm_no_lockfile`, whose text names only npm locks. The human stderr says nothing was switched, and vendored refuses with a message listing yarn.lock. Low-severity naming nit, not filed (pnpm has its own `redirect_pnpm_no_lockfile`).
- `--min-severity` judges severity from `vulnerabilities[].severity` in `/patch/by-package`. A mock that returns `vulnerabilities: {}` there makes every patch "unknown", so all of them are filtered. That's a harness artifact.
- `--package pkg:npm/<name>@<version not installed>` scans nothing and exits 0 `success`. That's expected filtering.
- After a hosted scan, `yarn add` / `yarn upgrade` / member installs with a range that matches the pinned version merge into the pinned block (pin kept). Only an exact root re-add (`yarn add -W <pkg> --exact`) writes a separate registry block (#938).
- Run-24 mock: a 3-package variant of the run-18 mock (left-pad high, ms low, scoped `@isaacs/string-locale-compare` medium, tarballs read from a local dir). Kill the mock in its own Bash call; `pkill -f mock.py` in a command line that also contains `mock.py` kills the calling shell.
