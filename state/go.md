[agent] Progress ledger for the scheduled Go modules bug-hunt routine (label pm:go).

Last updated: 2026-10-29 (run 20), main `c07af61`, latest release v5.0.1. Run 20 filed #1840: the #1823 fix (#1824) misses a fork that only a dependency requires (go 1.16 unpruned graph), so apply/check/vex still succeed on an unpatched build (v5.0.1 too). #1799, #1810 and #1823 are fixed; their agent cells were re-verified in run 20. #549 is still open (fix PR #1698). Earlier: runs 14-19 filed #1766, #1777, #1799, #1810 and #1823, all fixed. Between runs 12 and 13, fixes closed #343, #344, #346, #391, #392, #393, #422, #458, #484, #509, #531, #618 and #682. Cells marked "fixed #N" haven't been re-verified unless they say "pass (run N)".
## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real `go build`/`go run` against a hermetic file GOPROXY and a hand-staged `.socket/manifest.json` plus blob (the `tests/e2e_golang_build.rs` shape). Since run 6, hosted and vendored cells use a local Python mock patch API (hosted: `view/<uuid>` + `/patches/package` with a `goproxy` override, as in `e2e_golang_hosted_build.rs`; vendored: a granted tarball with `sha512`, as in `vendor/golang.rs` `mount_go_granted`). The module proxy is served over http so hosted rollback works. Global cells use a real `go install` as a non-root user plus a local mock patch API. Rows before run 3 were tested on `f6b7fb9`. Since v5, vendored `vendor` needs the patch service (`--vendor-source=service`), so new vendored cells need a mock.

| OS | go | Agent `apply` (plain) | Agent edge shapes (uppercase, /v2, pseudo, gopkg.in, CRLF, replace block/exclude/retract/toolchain, godebug/tool, nested module paths, new-file patches, tidy, idempotent, rollback, remove) | `+incompatible` / no-go.mod module (`%2B` key) | Vendored `vendor` (plain) | Committed `vendor/` dir | `go env -w` settings | Upgrade drift → VEX | Transitive / unselected version | go.work user replace | go.work without `use .` | go.work shared replace (#1764) | go.work, 2 members each patched | Hosted | tidy → rollback/remove (go.sum) | GOWORK=off / GOWORK=<path> / GOFLAGS=-modfile | Patch edits module's own go.mod (bump/add require) | Hosted patch update (new uuid / republish) | Hosted /v2, +incompatible, pseudo, indirect | go.work members require different versions | `go work vendor` (non-root member) | Module only a replace target (fork idiom) | Replace target, fork required only transitively (go 1.16 graph) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.16.15 | blocked (no 1.16 download: go.dev/dl.google.com denied) | blocked | blocked | untested | fixed #343 | fixed #344 | untested | untested | n/a (no go.work) | n/a | n/a | n/a (no go.work) | untested | untested | n/a | n/a (no proxy toolchain) | untested | untested | n/a (no go.work) | n/a | blocked | blocked |
| Linux | 1.21.13 | pass (run 16; + patch update) | /v2, rollback, remove pass (run 16); rest untested | pass (run 16: apply/check/vex/rollback/remove) | pass (probe) | fixed #343 | fixed #344 | fixed #391 (agent) | untested | fixed #393 (agent) | untested | fixed #1810 (not re-run on 1.21) | untested | untested | untested | `-modfile` fixed #1799 (e2e pass run 20) | fixed #618 (agent) | fixed #682 | pass | untested | n/a (go < 1.22) | fixed #1823 (e2e pass run 20) | fail #1840 (agent) |
| Linux | 1.24.7 (+1.22.12) | pass (run 13; CRLF go.mod/go.sum pass) | pass | apply/check/rollback pass; vex fixed #484 (agent only; vendored + takeover pass) | pass | fixed #343 (agent, vendored, hosted apply/rollback); vendored undo fixed #1777 (not re-run) | fixed #344 | fixed #391 (agent) / vendored pass / hosted pass (vex exits 2) | fixed #392 (agent + vendored), fixed #509 (hosted, go 1.16) | fixed #393 (agent, vendored, hosted) | fixed #458 (agent, vendored, hosted) | apply/rollback/remove/CRLF pass (run 18); GOWORK=<root>/ci.work apply/rollback/remove + ci.work user replace pass (run 20) | fixed #531 (agent, 1.22 + 1.24; vendored 1.24); hosted pass (identical module-path replaces) | plain get/day-2/idempotent/rollback/CRLF pass; `+incompatible` blocked (server contract) | fail #549 (agent, 1.22 + 1.24; vendored 1.24); hosted pass | off pass; `<path>` pass; `<path>` + user replace fixed #393; `-modfile` (env and `go env -w`) pass (run 20) | fixed #618 (agent 1.22 + 1.24, vendored 1.24, hosted 1.21/1.22/1.24/1.26) | fixed #682 | pass | fixed #1751; transitive (dep go.mod, unpruned chains, go.work version replace) pass (run 17) | apply pass; rollback/remove fixed #1766 (pass run 16, 2 members, 1.24.7) | pass (run 20, agent; fixed #1823); go.work fork replace refuses (pass) | fail #1840 (agent, versioned + versionless, v5.0.1 too); same shape in go.work refuses (pass) |
| Linux | 1.26.3 | pass (probe) | /v2, rollback, remove pass (1.26.8, run 16) | pass (1.26.8, run 16) | pass (probe) | fixed #343 | fixed #344 | fixed #391 (agent (1.26.8)) | untested | fixed #393 (agent (1.26.8)) | fixed #458 (agent, 1.26.8) | fixed #1810 (not re-run on 1.26) | fixed #531 (agent, 1.26.8) | untested | fail #549 (agent, 1.26.8) | untested | fixed #618 (agent, 1.26.8) | fixed #682 (1.26.8) | pass (1.26.8) | fixed #1751; transitive fixed by #1763 (not re-run on 1.26) | rollback/remove fixed #1766 (not re-run on 1.26) | fixed #1823 (e2e pass run 20, 1.26.8) | fail #1840 (agent, 1.26.8) |
| macOS | 1.24.13 / 1.26.3 | untested (plain; the vendor/-dir cell got as far as apply exit 0) | untested | untested | untested | fixed #343 | fixed #344 | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Windows | 1.16.15 / 1.21.13 / 1.26.3 | fixed #346 | untested (#346 fixed) | untested (#346 fixed) | fixed #346 | untested (#346 fixed) | fixed #344 | untested (#346 fixed) | untested (#346 fixed) | untested (#346 fixed) | untested (#346 fixed) | untested | untested (#346 fixed) | untested | untested (#346 fixed) | untested | untested (#346 fixed) | untested | untested | untested | untested | untested | untested |

### Global (`-g` / `--global-prefix` / `SOCKET_GLOBAL`)

| OS | go | `scan -g` report (+ `--json`) | `-g --mode hosted` refusal | `scan -g --mode agent` / `get -g` apply | installed `go install` binary | `rollback -g` | `vex -g` | unwritable prefix | GOENV GOMODCACHE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.24.7 | pass | pass | pass (cache) | pass (run 13: warns go_installed_tool_stale; pass after reinstall) | pass | fixed #422 (attests stale binary); pass after cache revert | pass (loud) | fixed #344 (silent 0 packages) |
| Linux | 1.25.1 | untested | untested | pass (cache) | fixed #422 | untested | fixed #422 | untested | untested |
| Linux | 1.22.12 / 1.26.8 | Go hit crawled (report fields untested: mock lacks /patches/batch) | untested | pass (cache) | fixed #422 | pass | pass | untested (ran as root) | untested |
| Linux | 1.16 / 1.21 | untested | untested | untested | untested | untested | untested | untested | untested |
| macOS | any | untested (probe branches blocked) | untested | untested | untested | untested | untested | untested | untested |
| Windows | any | untested (probe branches blocked) | untested | likely untested (#346 fixed) | untested | untested | untested | untested | untested |

## Backlog

### Mode takeovers (runs 15-16, Linux, go 1.24.7)

| Takeover | Result |
| --- | --- |
| agent → hosted (`get --mode hosted` over a go-patches replace) | go.mod/go.sum rewritten, PATCHED, tidy clean; leaves the agent manifest entry and copy behind, so later `apply` exits 1 (refuses the hosted replace). Docs say to roll back first: known non-bug |
| hosted → agent (`apply`) | refuses (intended) |
| hosted → vendored (`vendor` eject) | pass (LF + CRLF go.mod), `vendor --check` pass, `vendor --revert` restores upstream byte for byte |
| vendored undo with committed `vendor/` | fixed #1777 (#1778) |
| agent → vendored (`vendor` over a go-patches replace) | pass (run 16): takeover warning, PATCHED, `vendor --check`, VEX; `vendor --revert` byte for byte, then `apply` restores |


0. **Maintainer request (partly covered, keep it on top):** global (`-g`) mode on macOS and Windows. Linux is done (#422 is fixed; its warning passed in run 13). The full checklist is in the 20261001T040000Z entry.
1. **Needs a maintainer:** delete the stale probe branches `bughunt/go/20260930-goenv-vendor`, `bughunt/go/20260930-windows-apply` and `bughunt/go/20260930-windows-bisect`. `git push --delete` from the sandbox was denied by the permission classifier again in run 16. Until they're gone, no new probe branches get pushed.
2. #1840 in hosted and vendored modes (shared `go_build_list::select`); re-check once a fix lands. Unpruned (go 1.16) graphs elsewhere in `go_build_list`: `exclude`, and a versioned fork replace at a version MVS raises. `-overlay` in GOFLAGS, and `-modfile` in hosted/vendored modes. Still to do from before: a `use` member that is the patched module, hosted go.work/go.work.sum rollback, member `exclude` vs a transitive raise, `ci.work.sum` vs `go.work.sum` pin reading in hosted/vex.
3. Re-check #549 once #1698 merges (still reproduces on `c07af61`), and hosted pins after tidy once #1748 merges.
4. Vendored → hosted takeover. `scan --mode hosted` with `/patches/batch` in the mock and a `%2B` purl. Vendored mode on 1.21.13 and 1.26.8.
5. Regression re-checks of the #343/#344/#393/#458/#531 fixes on 1.21 and 1.26, and of #1777 on 1.26. (Run 20: the repo's agent/hosted/vendored Go e2e suites pass on 1.21.13 and 1.26.8.)
6. `go.work.sum` in hosted workspace mode; a CRLF go.sum in vendored mode.
7. Windows `HOME` vs `USERPROFILE` mismatch (`go_crawler.rs::get_gomodcache`).

## Known non-bugs

- GitHub `search/issues` can return 403 from the sandbox. Dedupe by fetching `repos/…/issues?state=all&per_page=100&page=N` and grepping locally.
- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/manifest.json` plus blobs locally. `proxy.golang.org` IS reachable from the sandbox.
- `patches-api.socket.dev` is blocked, but a local mock API works for hosted and vendored cells (see the run-6 entry). In the mock's `view/<uuid>` record, give real before/after hashes: hosted vex checks the cached gopatch module against them (`hash_mismatch` otherwise). Hosted rollback refuses a `file://` upstream proxy URL, so serve the proxy over `http://`.
- Running `apply` from a package subdirectory (no go.mod in cwd) fails closed with "matched no installed package". Use `--cwd <module root>`.
- Hosted rollback with a go.sum that lists ONLY the patched module rewrites the restored lines as LF even when the file was CRLF. Cosmetic (go accepts both); with other modules present, CRLF is kept. Not filed.
- Hosted rollback after an upgrade (`go get M@newer`) refuses with `patched_ref_invalid` and points at `git checkout -- go.mod`: fails closed by design.
- 3.3.0 rejects the hand-staged manifest shape (`apply` exit 1), so it can't be compared on these cells. 4.0.0 `vex` needs an explicit `--product` in these fixtures (there's no git remote).
- `apply` refuses (exit 1) when go.mod has a user-authored `replace M => …` for the patched module: intended. (The same line in go.work is NOT refused, which is #393.)
- Agent-mode `repair` doesn't rebuild a deleted `.socket/go-patches/` copy. `repair --help` scopes rebuilding to vendored artifacts; re-run `apply`.
- `go ... -modcacherw` leaves cache FILES read-only (directories only), so it's not a workaround for #346.
- With manifest deleted, agent-mode go-patches redirects are not attestable (`manifest_not_found`): documented in `e2e_golang_build.rs`.
- Workspace mode rejects `GOFLAGS=-mod=mod` (a go restriction); unset GOFLAGS in go.work fixtures.
- Fixture pitfalls: build proxy zips with `zip -D` (directory entries change the h1 hash, so `go mod verify` fails on a pristine cache). As non-root, `chmod -R u+w` before `rm -rf` of a module cache. A partly deleted cache survives and contaminates the next run.
- `rollback -g` needs the before blob (fetched from `patches-api.socket.dev`, which the sandbox blocks). Stage it in `.socket/blobs/` and use `--offline`. A loud failure without it is expected.
- `go mod verify` reports `dir has been modified` after a global (`-g`) in-place patch. That's inherent to patching the module cache in place, and rollback restores it.
- A go.work root with NO root go.mod: `apply` exits 1 "matched no installed package" and writes nothing (root-only discovery, fails closed). Run with `--cwd <member>` instead, which builds PATCHED. Not filed.
- go.work `use ( . ./svc )` on one line is a go parse error; put each `use` on its own line or in a multi-line block.
- In v5, `rollback` removes the manifest entry, so a later `remove <purl>` reports "No patch found". Expected.
- `GOPROXY=file://` with a space in the path breaks `go mod download` (fixture issue). Keep proxy and cache paths plain.
- Concurrent `apply` runs are serialized by `.socket/apply.lock`; the losers fail fast with a `--lock-timeout` hint. Expected.
- v5 `vendor --offline` fails with "--vendor-source=service needs the network": by design (local artifact building was removed in v5).
- A backtick-quoted path in go.mod is rejected by go itself ("invalid quoted string"). Not a socket-patch bug. Double-quoted paths work.
- `GOWORK=off` with a root go.work that doesn't `use .`: builds use go.mod only and are PATCHED, so #458 doesn't apply.
- `apply --check` audits only the manifest's files in `.socket/go-patches/<m>@<v>/`. An edited unpatched file, or an added `.go` file, passes `--check` and gets built. That's by design (docs: commit and review the copy like vendored code). Not filed.
- Agent `apply` with a cold module cache exits 1 with `package_not_installed`: correct. Run `go mod download` first.
- Rollback of a go.mod that had no trailing newline leaves one added. Cosmetic, not filed.
- Vendored mock: `SOCKET_VENDOR_URL=<mock>` plus `POST */patch/package` granted tarball (see the run-9 entry). `vex` needs non-empty `vulnerabilities` in the manifest, otherwise it errors with "No applied patches with vulnerability metadata".
- Hosted `rollback` needs the upstream go.sum hashes. For a module sum.golang.org doesn't know, it exits 1 ("Cannot restore … restore it from version control") unless `GOSUMDB=off` / GONOSUMDB is set: fails closed by design.
- Hosted `get` with a user `replace` for the patched module in go.mod (versioned or versionless) writes nothing and warns `redirect_golang_replace_conflict`: intended.
- Hosted mode in a go.work with several members writes identical module-path replaces, which Go accepts. So #531 is agent- and vendored-only.
- Toolchains for 1.21+ are fetched with `GOMODCACHE=<dir> GOTOOLCHAIN=go<ver> GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go version`, then run `<dir>/golang.org/toolchain@v0.0.1-go<ver>.linux-amd64/bin/go` directly against the fixture proxy.
- Hosted rollback after a patch update (#682) still restores byte for byte, because it prunes every `patch.socket.dev/gopatch/` line. Only the forward rewrite leaves stale lines.
- A UTF-8 BOM in go.mod: go itself rejects it ("unexpected input character '\ufeff'"). Not applicable.
- A relative `GOWORK`: go rejects it ("not an absolute path"). socket-patch still resolves the file and refuses on its replace, so it fails closed.
- go.work `use` spellings (`a`, `./a/`, `./b/../a`, quoted, absolute) and symlinked members all match correctly for the #458 member check (run 14).
- The #422 `go_installed_tool_stale` check dates binaries by mtime: an older-touched rebuilt binary is flagged again (conservative). A tool built later from its own `vendor/` isn't built from the patched cache, so it's out of scope for `-g`.
- A direct agent → hosted takeover (`get --mode hosted` without `rollback` first) leaves the agent manifest entry and `.socket/go-patches/` copy, and later `apply` exits 1 refusing the hosted replace. migrating-to-v5.md says to run `rollback` before moving to hosted. Not filed.
- An offline `rollback` of that mixed state removes the agent record, then fails the hosted restore (exit 1, "restore it from version control"). It fails closed.
- A hosted → vendored eject on a CRLF go.sum that lists only the patched module writes it back as LF. Cosmetic, the same as the hosted-rollback note above.
- My mock read cfg.json only once at startup. Reload it on every request, or `get` returns `notFound`.
- Hosted rollback with `GOPRIVATE`, `GONOPROXY`, `GOPROXY=off` or `GOPROXY=direct` exits 1, writes nothing and points at `SOCKET_GOPROXY` / version control. That's fail-closed by design (run 16). `GOPRIVATE` + `SOCKET_GOPROXY` restores byte for byte.
- go 1.16 can't be fetched in the sandbox (go.dev and dl.google.com are denied, and toolchain modules start at 1.21). Cover it only via probe branches.
- After `rollback`, `.socket/blobs` is gone too. To re-apply in a fixture, re-stage the blob as well as the manifest.
- GOWORK naming another file in the root while the root go.mod is a `use` member: the build is PATCHED through the mirrored root go.mod replace (only a stray go.work write). Covered by #1810 and not filed separately.
- `vendor --revert` after an agent → vendored takeover leaves the project unpatched and warns to run `apply`. That's documented in the warning; `apply` restores it.
- The repo's `*_needs_go_work_vendor_in_workspace` e2e tests fail on go 1.21.x in fixture setup, because `go work vendor` only exists from go 1.22. That's a toolchain limit, not a product bug.
