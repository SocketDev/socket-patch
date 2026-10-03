[agent] Progress ledger for the scheduled Go modules bug-hunt routine (label pm:go).

Last updated: 2026-10-03 (run 11), main `045d7ec` (unchanged since run 10; CLI 4.0.0), latest release 4.0.0 (previous 3.3.0). Run 11 confirmed #618 in hosted mode (1.21/1.22/1.24/1.26), passed #531's shape in hosted mode, and covered global `-g` on Linux 1.22/1.26. Run 10 filed #618 (a patch that edits the module's own go.mod breaks the default build) and re-confirmed #484 and #343. Run 9: #549 and #531 confirmed in vendored mode; a reusable vendored mock is described in the run-9 entry.
## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real `go build`/`go run` against a hermetic file GOPROXY and a hand-staged `.socket/manifest.json` plus blob (the `tests/e2e_golang_build.rs` shape). Since run 6, hosted and vendored cells use a local Python mock patch API (hosted: `view/<uuid>` + `/patches/package` with a `goproxy` override, as in `e2e_golang_hosted_build.rs`; vendored: a granted tarball with `sha512`, as in `vendor/golang.rs` `mount_go_granted`). The module proxy is served over http so hosted rollback works. Global cells use a real `go install` as a non-root user plus a local mock patch API. Rows before run 3 were tested on `f6b7fb9`. Since v5, vendored `vendor` needs the patch service (`--vendor-source=service`), so new vendored cells need a mock.

| OS | go | Agent `apply` (plain) | Agent edge shapes (uppercase, /v2, pseudo, gopkg.in, CRLF, replace block/exclude/retract/toolchain, godebug/tool, nested module paths, new-file patches, tidy, idempotent, rollback, remove) | `+incompatible` / no-go.mod module (`%2B` key) | Vendored `vendor` (plain) | Committed `vendor/` dir | `go env -w` settings | Upgrade drift → VEX | Transitive / unselected version | go.work user replace | go.work without `use .` | go.work, 2 members each patched | Hosted | tidy → rollback/remove (go.sum) | GOWORK=off / GOWORK=<path> | Patch edits module's own go.mod (bump/add require) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.16.15 | untested | untested | untested | untested | fail #343 | fail #344 | untested | untested | n/a (no go.work) | n/a | n/a (no go.work) | untested | untested | n/a | n/a (no proxy toolchain) |
| Linux | 1.21.13 | pass (probe) | untested | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | untested | untested | untested | untested | untested | fail #618 (agent) |
| Linux | 1.24.7 (+1.22.12) | pass | pass | apply/check/rollback pass; vex fail #484 (agent only; vendored + takeover pass) | pass | fail #343 (agent, vendored, hosted) | fail #344 | fail #391 (agent) / vendored pass / hosted pass (vex exits 2) | fail #392 (agent + vendored), fail #509 (hosted, go 1.16) | fail #393 (agent, vendored, hosted) | fail #458 (agent, vendored, hosted) | fail #531 (agent, 1.22 + 1.24; vendored 1.24); hosted pass (identical module-path replaces) | plain get/day-2/idempotent/rollback/CRLF pass; `+incompatible` blocked (server contract) | fail #549 (agent, 1.22 + 1.24; vendored 1.24); hosted pass | off pass; `<path>` pass; `<path>` + user replace fail #393 | fail #618 (agent 1.22 + 1.24, vendored 1.24, hosted 1.21/1.22/1.24/1.26) |
| Linux | 1.26.3 | pass (probe) | untested | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | fail #458 (agent, 1.26.8) | fail #531 (agent, 1.26.8) | untested | fail #549 (agent, 1.26.8) | untested | fail #618 (agent, 1.26.8) |
| macOS | 1.24.13 / 1.26.3 | untested (plain; the vendor/-dir cell got as far as apply exit 0) | untested | untested | untested | fail #343 | fail #344 | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Windows | 1.16.15 / 1.21.13 / 1.26.3 | fail #346 | blocked by #346 | blocked by #346 | fail #346 | blocked by #346 | fail #344 | blocked by #346 | blocked by #346 | blocked by #346 | blocked by #346 | blocked by #346 | untested | blocked by #346 | untested | blocked by #346 |

### Global (`-g` / `--global-prefix` / `SOCKET_GLOBAL`)

| OS | go | `scan -g` report (+ `--json`) | `-g --mode hosted` refusal | `scan -g --mode agent` / `get -g` apply | installed `go install` binary | `rollback -g` | `vex -g` | unwritable prefix | GOENV GOMODCACHE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.24.7 | pass | pass | pass (cache) | fail #422 | pass | fail #422 (attests stale binary); pass after cache revert | pass (loud) | fail #344 (silent 0 packages) |
| Linux | 1.25.1 | untested | untested | pass (cache) | fail #422 | untested | fail #422 | untested | untested |
| Linux | 1.22.12 / 1.26.8 | Go hit crawled (report fields untested: mock lacks /patches/batch) | untested | pass (cache) | fail #422 | pass | pass | untested (ran as root) | untested |
| Linux | 1.16 / 1.21 | untested | untested | untested | untested | untested | untested | untested | untested |
| macOS | any | untested (probe branches blocked) | untested | untested | untested | untested | untested | untested | untested |
| Windows | any | untested (probe branches blocked) | untested | likely blocked by #346 | untested | untested | untested | untested | untested |

## Backlog

0. **Maintainer request (partly covered, keep it on top):** global (`-g`) mode on macOS and Windows. Linux 1.22 / 1.24 / 1.25 / 1.26 is done (see the table and #422). The full checklist is in the 20261001T040000Z entry.
1. **Needs a maintainer:** delete the stale probe branches `bughunt/go/20260930-goenv-vendor`, `bughunt/go/20260930-windows-apply` and `bughunt/go/20260930-windows-bisect`. `git push --delete` from the sandbox is denied by the permission classifier (runs 6 and 11). Until they're gone, no new probe branches get pushed.
2. Hosted `+incompatible` and `/v2+` modules (needs the gopatch version spelling the service uses), and `scan --mode hosted` with a `%2B` purl. Add `/patches/batch` to the mock for crawl-driven scans.
3. Global as non-root on 1.22 / 1.26 (unwritable prefix); `--global-prefix` shapes (GOPATH root, multi-entry GOPATH).
4. Hosted with GOPRIVATE / GONOSUMDB / `GOFLAGS=-mod=vendor`, `go.work.sum` in hosted workspace mode, and a CRLF go.sum in vendored mode.
5. Toolchain matrix (1.22 / 1.26) for #391, #392, #393 and #509 on Linux via the proxy toolchains.
6. Windows cells once #346 is fixed.

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
