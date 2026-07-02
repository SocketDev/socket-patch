# Hosted redirect for Go: a deliberate no-go

**Status:** decided — golang is excluded from HOSTED (registry-redirect) mode.
**Remedy:** `socket-patch vendor` (VENDORED mode: bytes committed to
`.socket/vendor/`, offline-verified, `replace => ./path` in `go.mod`).
**Warning code:** `redirect_golang_unsupported` (emitted by both the Rust
CLI rewriter and the depscan backend's TS twin,
`workspaces/app/src/patches/registry-rewrite/golang.ts`).

HOSTED mode's contract is a *committable, per-dependency* lockfile/registry
edit: only the patched dependency resolves from `patch.socket.dev`, everything
else resolves exactly where it did before, and install-time integrity
verification stays intact. Go cannot meet that contract. The patch-server does
serve a correct GOPROXY for the patched module
(`/patch-registry/golang/...`) — the problem is not serving the bytes, it is
that every way of *pointing* a Go build at them requires machine-local
configuration or breaks Go's verification model. Three independent blockers,
any one of which is disqualifying:

## Blocker 1 — day-2 sumdb hard-fail, and the fix is uncommittable

A patched module version (e.g. `v1.2.3-socketpatch.1`) does not exist in
`sum.golang.org`. With the default `GOSUMDB=sum.golang.org`, any `go` command
that resolves the patched version hard-fails checksum verification — not on
the machine that ran the redirect (its `go.sum` could carry the patched
hashes), but on **every other machine, day 2**: CI, a teammate's fresh clone,
a Docker build. The only sanctioned escape is `GOPRIVATE`/`GONOSUMCHECK`-style
configuration — which lives in the developer's environment or `go env -w`
(machine-local), **not** in any committable project file. A redirect that
requires every future builder to mutate their machine before `go build` works
is not a redirect; it is an outage with extra steps. Committing
`GOFLAGS`/`GONOSUMDB` via `go.work` or a wrapper script was rejected as a
shim around the real boundary: Go simply has no committable per-module
sumdb exemption.

## Blocker 2 — module-path identity forces per-grant artifacts

In Go, the module path **is** the identity: the `module` directive inside the
served `.mod`/zip must byte-match the import path the consumer requests. Our
hosted patch URLs are per-grant (`/{token}/{uuid}/`), and grants are
per-organization. Serving `example.com/lib` from a grant-scoped GOPROXY path
still works only while the module path inside the zip stays
`example.com/lib` — but then the zip's `h1:` dirhash must ALSO match what the
consumer's `go.sum` pins, which means the artifact must be built once and
byte-frozen. The patch converter is deliberately **build-once**: one artifact
per patch, shared by every grant (content-addressed, cache-friendly,
attestable). A Go redirect that embedded grant/token material into the module
zip (vanity import paths, rewritten module directives) would need one artifact
*per grant*, which is incompatible with the build-once converter and would
multiply storage and attestation surface by the number of customers. Rejected.

## Blocker 3 — default GOPROXY publishes licensed bytes and leaks tokened URLs

`GOPROXY` defaults to `proxy.golang.org,direct`. The moment any machine
without our override fetches the patched pseudo-version by name, the request
goes to **Google's public mirror**, which will try to fetch and then *cache
publicly forever* whatever it can reach. Two failure shapes:

- If the patched module were reachable without auth, the public mirror would
  republish licensed patch bytes to the world — a direct license violation.
- Because it is NOT reachable without auth, the fetch fails — but the
  tokened URL (`/{token}/{uuid}/...`) has now been shipped to a third party's
  logs, burning a capability URL we treat as a bearer secret.

Either way, the default-GOPROXY world is hostile to a hosted Go patch: we
cannot control which resolver a downstream machine asks first, and both
possible outcomes (public caching, token leakage) are unacceptable.

## Sanctioned exception: ephemeral-CI GOPROXY

The one place machine-local configuration is acceptable is a **single-use,
ephemeral CI job**, where "the machine" is created and destroyed around one
build and no day-2 clone exists. Teams that cannot vendor may opt in,
explicitly and per-job:

```yaml
# CI job (ephemeral runner) — NOT for developer machines or committed config.
env:
  # Patched module resolves from Socket first, everything else falls through.
  GOPROXY: "https://patch.socket.dev/patch-registry/golang/${SOCKET_PATCH_TOKEN}/${PATCH_UUID},https://proxy.golang.org,direct"
  # The patched pseudo-version is not in sum.golang.org — exempt ONLY the
  # patched module from sumdb lookups; all other modules stay verified.
  GOPRIVATE: "example.com/patched-module"
steps:
  - run: go mod download example.com/patched-module
  - run: go build ./...
```

The token enters through the CI secret store, never a committed file; the
runner is discarded so no drifted `go env` survives; and `GOPRIVATE` is scoped
to the single patched module so sumdb verification stays on for the rest of
the graph. This recipe is documentation-only — neither `scan --redirect` nor
the backend PR flow will ever write it into a repository.

## Decision

`scan --redirect` (and the backend hosted PR flow) emit
`redirect_golang_unsupported` naming the remedy — run `socket-patch vendor`
(committable, offline-verified) — and the golang dependency is otherwise left
untouched. Vendored mode already gives Go users everything hosted mode
promises elsewhere: per-dependency, committable, verifiable at install time.
