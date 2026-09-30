[agent] Progress ledger for the scheduled Go modules bug-hunt routine (label pm:go).

Last updated: 2026-09-30 (run 2), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real `go build`/`go run` against a hermetic file GOPROXY and a hand-staged `.socket/manifest.json` plus blob (the `tests/e2e_golang_build.rs` shape). Hosted mode needs the wiremock harness (`e2e_golang_hosted_build.rs`) and hasn't been exercised by this routine yet.

| OS | go | Agent `apply` (plain) | Agent edge shapes (uppercase, /v2, pseudo, gopkg.in, CRLF, replace block/exclude/retract/toolchain, tidy, idempotent, rollback, remove) | Vendored `vendor` (plain) | Committed `vendor/` dir | `go env -w` settings | Upgrade drift → VEX | Transitive / unselected version | go.work user replace | Hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.16.15 | untested | untested | untested | fail #343 | fail #344 | untested | untested | n/a (no go.work) | untested |
| Linux | 1.21.13 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | untested |
| Linux | 1.24.7 | pass | pass | pass | fail #343 | fail #344 | fail #391 (agent) / vendored pass | fail #392 | fail #393 (agent + vendored) | untested |
| Linux | 1.26.3 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested | untested | untested |
| macOS | 1.24.13 / 1.26.3 | untested (plain; the vendor/-dir cell got as far as apply exit 0) | untested | untested | fail #343 | fail #344 | untested | untested | untested | untested |
| Windows | 1.16.15 / 1.21.13 / 1.26.3 | fail #346 | blocked by #346 | fail #346 | blocked by #346 | fail #344 | blocked by #346 | blocked by #346 | blocked by #346 | untested |

## Backlog

0. Delete stale probe branches `bughunt/go/20260930-goenv-vendor`, `bughunt/go/20260930-windows-apply` and `bughunt/go/20260930-windows-bisect`: `git push --delete` gets HTTP 403 from the git proxy.
1. Hosted mode (wiremock harness) × go.work user replace, upgrade drift, `/v2`, `+incompatible`, CRLF/BOM go.sum, `go.work.sum`.
2. Toolchain matrix (1.18 / 1.21 / 1.26) for #391, #392 and #393 via a probe branch, once branch deletion works.
3. `GOFLAGS=-mod=vendor` in the env or GOENV; `go work vendor` (1.22+) with a committed vendor/.
4. go.work root without a root go.mod: `apply` fails with "matched no installed package". Decide between limitation and bug.
5. Windows cells once #346 is fixed (long paths, CRLF checkouts, drive-letter replace targets).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/manifest.json` plus blobs locally. `proxy.golang.org` IS reachable from the sandbox.
- 3.3.0 rejects the hand-staged manifest shape (`apply` exit 1), so it can't be compared on these cells. 4.0.0 `vex` needs an explicit `--product` in these fixtures (there's no git remote).
- `apply` refuses (exit 1) when go.mod has a user-authored `replace M => …` for the patched module: intended. (The same line in go.work is NOT refused, which is #393.)
- Agent-mode `repair` doesn't rebuild a deleted `.socket/go-patches/` copy. `repair --help` scopes rebuilding to vendored artifacts; re-run `apply`.
- `go ... -modcacherw` leaves cache FILES read-only (directories only), so it's not a workaround for #346.
- With manifest deleted, agent-mode go-patches redirects are not attestable (`manifest_not_found`): documented in `e2e_golang_build.rs`.
- Workspace mode rejects `GOFLAGS=-mod=mod` (a go restriction); unset GOFLAGS in go.work fixtures.
