[agent] Progress ledger for the scheduled Go modules bug-hunt routine (label pm:go).

Last updated: 2026-10-01 (run 5), main `6e7ef74` (no Go changes since `2463257`; CLI still reports 4.0.0), latest release 4.0.0 (previous 3.3.0). On `6e7ef74`, #391 and #458 still reproduce. On `2463257`, #343, #392 and #393 did.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real `go build`/`go run` against a hermetic file GOPROXY and a hand-staged `.socket/manifest.json` plus blob (the `tests/e2e_golang_build.rs` shape). Hosted mode needs the wiremock harness (`e2e_golang_hosted_build.rs`) and hasn't been exercised by this routine yet. Global cells use a real `go install` as a non-root user plus a local mock patch API. Rows before run 3 were tested on `f6b7fb9`. Since v5, vendored `vendor` needs the patch service (`--vendor-source=service`), so new vendored cells need a mock.

| OS | go | Agent `apply` (plain) | Agent edge shapes (uppercase, /v2, pseudo, gopkg.in, CRLF, replace block/exclude/retract/toolchain, tidy, idempotent, rollback, remove) | `+incompatible` / no-go.mod module (`%2B` key) | Vendored `vendor` (plain) | Committed `vendor/` dir | `go env -w` settings | Upgrade drift → VEX | Transitive / unselected version | go.work user replace | go.work without `use .` | Hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.16.15 | untested | untested | untested | untested | fail #343 | fail #344 | untested | untested | n/a (no go.work) | n/a | untested |
| Linux | 1.21.13 | pass (probe) | untested | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | untested | untested |
| Linux | 1.24.7 (+1.22.12) | pass | pass | apply/check/rollback pass; vex fail #484 | pass | fail #343 | fail #344 | fail #391 (agent) / vendored pass | fail #392 | fail #393 (agent + vendored) | fail #458 (agent; vendored blocked) | untested |
| Linux | 1.26.3 | pass (probe) | untested | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | fail #458 (agent, 1.26.8) | untested |
| macOS | 1.24.13 / 1.26.3 | untested (plain; the vendor/-dir cell got as far as apply exit 0) | untested | untested | untested | fail #343 | fail #344 | untested | untested | untested | untested | untested |
| Windows | 1.16.15 / 1.21.13 / 1.26.3 | fail #346 | blocked by #346 | blocked by #346 | fail #346 | blocked by #346 | fail #344 | blocked by #346 | blocked by #346 | blocked by #346 | blocked by #346 | untested |

### Global (`-g` / `--global-prefix` / `SOCKET_GLOBAL`)

| OS | go | `scan -g` report (+ `--json`) | `-g --mode hosted` refusal | `scan -g --mode agent` / `get -g` apply | installed `go install` binary | `rollback -g` | `vex -g` | unwritable prefix | GOENV GOMODCACHE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.24.7 | pass | pass | pass (cache) | fail #422 | pass | fail #422 (attests stale binary); pass after cache revert | pass (loud) | fail #344 (silent 0 packages) |
| Linux | 1.25.1 | untested | untested | pass (cache) | fail #422 | untested | fail #422 | untested | untested |
| Linux | 1.16 / 1.21 / 1.26 | untested | untested | untested | untested | untested | untested | untested | untested |
| macOS | any | untested (probe branches blocked) | untested | untested | untested | untested | untested | untested | untested |
| Windows | any | untested (probe branches blocked) | untested | likely blocked by #346 | untested | untested | untested | untested | untested |

## Backlog

0. **Maintainer request (partly covered, keep it on top):** global (`-g`) mode on macOS and Windows and across go 1.21 / 1.26. Linux 1.24/1.25 is done (see the table and #422). Linux 1.22.12 / 1.26.8 toolchains can be fetched from proxy.golang.org (`golang.org/toolchain/@v/v0.0.1-go<ver>.linux-amd64.zip`); `dl.google.com` (needed for 1.16–1.20) is blocked. The full checklist is in the 20261001T040000Z entry.
1. Delete the stale probe branches `bughunt/go/20260930-goenv-vendor`, `bughunt/go/20260930-windows-apply` and `bughunt/go/20260930-windows-bisect`. `git push --delete` still fails from the sandbox (run 4), and this blocks new probe branches.
2. A local mock of the patch service (also for #484 in vendored mode: `lookup_entry` has the same `+` vs `%2B` exposure) for vendored (now `--vendor-source=service` only) and hosted cells: #458 in vendored/hosted, go.work user replace, upgrade drift, `/v2`, `+incompatible`, CRLF/BOM go.sum, `go.work.sum`.
3. `--global-prefix` shapes: GOPATH root instead of `pkg/mod`, multi-entry GOPATH, empty or relative GOMODCACHE.
4. `GOWORK=<path>` / `GOWORK=off` (socket-patch never reads GOWORK); a nested module inside a parent module.
5. Toolchain matrix (1.22 / 1.26) for #391, #392 and #393 on Linux via the proxy toolchains.
6. Windows cells once #346 is fixed.
7. Other `%XX` PURL spellings for Go: the `%2B` key in hosted mode, `vex -g` with a `+incompatible` global module, and `get`/`scan` JSON output.

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/manifest.json` plus blobs locally. `proxy.golang.org` IS reachable from the sandbox.
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
- v5 `vendor --offline` fails with "--vendor-source=service needs the network": by design (local artifact building was removed in v5).
