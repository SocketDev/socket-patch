[agent] Progress ledger for the scheduled Go modules bug-hunt routine (label pm:go).

Last updated: 2026-09-30 (run 1), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real `go build`/`go run` against a hermetic file GOPROXY and a hand-staged `.socket/manifest.json` plus blob (the `tests/e2e_golang_build.rs` shape). Hosted mode needs the wiremock harness (`e2e_golang_hosted_build.rs`) and hasn't been exercised by this routine yet.

| OS | go | Agent `apply` (plain) | Agent edge shapes (uppercase, /v2, pseudo, gopkg.in, CRLF, tidy, idempotent, rollback) | Vendored `vendor` (plain) | Committed `vendor/` dir | `go env -w` settings | Upgrade drift → VEX | Hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.16.15 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested |
| Linux | 1.21.13 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested |
| Linux | 1.24.7 | pass | pass | pass | fail #343 | fail #344 | fail (agent attests; not filed yet, backlog 1) / vendored pass | untested |
| Linux | 1.26.3 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested |
| macOS | 1.24.13 / 1.26.3 | pass (probe) | untested | pass (probe) | fail #343 | fail #344 | untested | untested |
| Windows | 1.16.15 / 1.21.13 / 1.26.3 | fail #346 | blocked by #346 | fail #346 | blocked by #346 | fail #344 | untested | untested |

## Backlog

0. Delete stale probe branches `bughunt/go/20260930-goenv-vendor`, `bughunt/go/20260930-windows-apply` and `bughunt/go/20260930-windows-bisect`: `git push --delete` gets HTTP 403 from the git proxy.
1. File: agent-mode `vex` attests `not_affected` for an inert `.socket/go-patches` replace after `go get` upgrade drift, while `apply --check` flags `ResolvedVersionMismatch` (see `vex.rs:1333` `synthesize_go_patches`; the repro is in the 2026-09-30 entry).
2. A go.work root without a root go.mod: `apply` fails with "matched no installed package". Decide between limitation and bug, and check the docs.
3. Hosted mode: committed `vendor/`, `/v2` and `+incompatible` originals, CRLF/BOM go.sum, `go.work.sum`.
4. `GOFLAGS=-mod=vendor` in the env, `retract`, `exclude` directives, `toolchain` lines, and a go 1.21+ `go` directive with GOTOOLCHAIN auto.
5. Windows cells once #346 is fixed (long paths, CRLF checkouts).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/manifest.json` plus blobs locally. `proxy.golang.org` IS reachable from the sandbox.
- 3.3.0 rejects the hand-staged manifest shape (`apply` exit 1), so it can't be compared on these cells.
- `apply` refuses (exit 1) when go.mod has a user-authored `replace M => …` for the patched module: intended.
- Agent-mode `repair` doesn't rebuild a deleted `.socket/go-patches/` copy. `repair --help` scopes rebuilding to vendored artifacts; re-run `apply`.
- `go ... -modcacherw` leaves cache FILES read-only (directories only), so it's not a workaround for #346.
- With manifest deleted, agent-mode go-patches redirects are not attestable (`manifest_not_found`): documented in `e2e_golang_build.rs`.
