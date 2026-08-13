# Hosted redirect for Go: the fork-replace design (free tier)

**Status:** implemented CLI-side (rewriter, golden fixture, day-2 e2e); waiting
on server-side publication (see [Server requirements](#server-requirements-depscan)).
**Supersedes:** [golang-hosted-no-go.md](golang-hosted-no-go.md) for the FREE
tier. The paid-tier analysis there (blockers 2 and 3 against tokened URLs)
still stands; paid golang references must not carry a `goproxy` override.

## The shape

`scan --mode hosted` commits exactly two files' worth of edits — no artifact
bytes, no machine-local configuration:

```text
# go.mod
replace github.com/foo/bar v1.4.2 => patch.socket.dev/gopatch/<patch-uuid> v1.4.2-socketpatch.1

# go.sum
patch.socket.dev/gopatch/<patch-uuid> v1.4.2-socketpatch.1 h1:…          (module-zip dirhash)
patch.socket.dev/gopatch/<patch-uuid> v1.4.2-socketpatch.1/go.mod h1:…   (served .mod bytes)
```

The patched module is published — grant-free and content-addressed, one
build-once artifact per patch — at a Socket-owned module path under
`patch.socket.dev/gopatch/`, served over the standard GOPROXY protocol. The
`replace` is Go's native fork mechanism; the committed `go.sum` lines are the
integrity pin. The rewriter also prunes the replaced original's two `go.sum`
lines: with the pinned replace in force, go removes the original from the
module graph entirely, and writing the tidy-stable state up front keeps the
first day-2 `go mod tidy` a byte-level no-op.

## Why this dissolves the no-go doc's blockers (free tier)

Every claim below was validated empirically against go 1.26 before the feature
was built (file-`GOPROXY` fixtures, fresh per-"machine" caches; the capstone
lives in `crates/socket-patch-cli/tests/e2e_golang_hosted_build.rs`).

**Blocker 1 — day-2 sumdb hard-fail.** The no-go analysis assumed every fresh
machine re-consults `sum.golang.org` for the patched version. In fact go
consults the checksum database **only for modules absent from `go.sum`**.
Proven with a tripwire: every day-2 command run with `GOSUMDB` set to a bogus
database name (which fails loudly the moment it is consulted) — `go build`,
`go run`, `go test`, `go vet`, `go mod download`, `go mod verify`,
`go mod tidy` all succeed on an empty cache with only the committed
`go.mod` + `go.sum`, and zero `/sumdb/` requests appear in proxy logs. The
control (deleting one go.sum line) fails with `invalid GOSUMDB`, proving the
tripwire works. Committed `go.sum` lines ARE the committable per-module sumdb
exemption the old doc said Go didn't have.

**Blocker 2 — module-path identity forces per-grant artifacts.** Only true if
grant material rides in the module path. The socket module path is
content-addressed by patch uuid and carries no token: one frozen artifact per
patch, shared by every consumer — build-once compatible. The zip's entry
prefix must be the socket path (`gopatch/<uuid>@<version>/`, go rejects any
other prefix), but its **internal `go.mod` may keep declaring the ORIGINAL
module path** — go accepts a replacement declaring either side of the arrow —
and patched sources MUST keep their original import spellings (rewriting them
to the socket path fails with `used for two different module paths`). So the
artifact is the upstream module with patched files, rezipped under a new
prefix: a zero-source-rewrite converter.

**Blocker 3 — default GOPROXY publishes licensed bytes / leaks tokens.** For
the free tier, both horns are blunt: free patches are already anonymously
fetchable (production mints free-tier grants with no auth today), so
`proxy.golang.org` caching the module is republication of something already
public — and there is no token to leak because the path is grant-free. Google's
mirror caching the bytes is a robustness *win*: after first fetch, day-2
builds succeed even if `patch.socket.dev` is down. (Also measured: with the
pinned replace in force, go never fetches or verifies the ORIGINAL module at
all — the patched graph builds even if the upstream registry is down.)

## Day-2 contract (all validated)

- Fresh clone/CI with committed `go.mod` + `go.sum`, empty caches, default
  `-mod=readonly`, no `GOPRIVATE`/`GONOSUMDB`/`GOFLAGS`: builds and links the
  patched code.
- `go.sum` verification keeps its teeth: one flipped character in the
  committed `h1:` fails the build with go's checksum `SECURITY ERROR` — a
  wrong CLI-written hash can never be silently built. (This is also why the
  rewriter fails closed unless BOTH hashes are present: a replace committed
  without its go.sum lines bricks every downstream `-mod=readonly` build.)
- `go mod tidy` is a byte-level no-op on the rewriter's output.
- `go mod vendor` vendors the PATCHED bytes under the upstream import path
  (`vendor/modules.txt` records the replace) and `-mod=vendor` builds stay
  patched — the vendored escape hatch composes.
- Proxy fetch sequence for the pinned module is exactly `.zip`, `.mod`,
  `.info` (`.info` is required even for a fully pinned build; `/@v/list` and
  `/@latest` are never requested on the pinned path).
- Module zips' `h1:` dirhash is content-derived (entry names + contents;
  compression, mtimes, ordering, modes are ignored) — but the `/go.mod h1:`
  hashes the SERVED `.mod` bytes, and go does NOT cross-check them against the
  zip's internal `go.mod`. Server contract: freeze the two together.

## Known limitations (documented, not blockers)

- **Upgrade drift** (shared with local/vendored modes): `replace` is keyed on
  module+version. `go get -u` / a require bump silently strands the pin — the
  build reverts to the vulnerable version with zero warning while the inert
  replace line stays in `go.mod`, and the next tidy strips the patch's go.sum
  lines. Reliable text-only drift signals for a future `--check`: replace LHS
  version ≠ require version; socket replace present with no matching go.sum
  line. The rewriter refuses up front when `require` already disagrees with
  the patch version (`redirect_golang_version_mismatch`).
- **Corporate proxies**: a `GOPROXY` pinned to an internal mirror (Artifactory
  etc.) that cannot reach `patch.socket.dev` will 404 the socket module unless
  the mirror passes through. Comma-fallback semantics also mean a proxy that
  answers 403/500 (rather than 404/410) blocks the fetch.
- **Pre-modules packages**: modules without a `go.mod` are rejected by the
  build pipeline (`UNSUPPORTED_ARCHIVE_FORMAT`) — same limit as vendored mode.
- **v2+ originals**: the socket module is always published in the v0/v1
  version range (a v2+ RHS version would force a `/v2` path suffix); the RHS
  version need not relate to the original's. Not yet exercised against a real
  `/v2` module — verify when the first such patch ships.
- **Paid tier**: unchanged no-go. Tokened URLs re-trigger blockers 2 and 3;
  the ephemeral-CI `GOPROXY` recipe in the old doc remains the documented
  paid workaround.

## CLI implementation

- `patch/redirect/mod.rs rewrite_golang` — pure rewriter, activates per-dep on
  `registry_override.kind == "goproxy"`; absent override falls back to the
  historical `redirect_golang_unsupported` warning. Fails closed (warning, no
  partial writes) on: missing `go.mod`, missing/malformed `goModulePath` /
  `goModuleVersion`, module path outside `patch.socket.dev/gopatch/`, missing
  either integrity hash, require-version mismatch, user-authored replace
  conflict. Warning codes: `redirect_golang_no_go_mod`,
  `redirect_golang_missing_module`, `redirect_golang_untrusted_module_path`,
  `redirect_golang_missing_integrity`, `redirect_golang_version_mismatch`,
  `redirect_golang_replace_conflict`.
- `vendor/go_mod_edit.rs` — `ReplaceOwner::Hosted` (ownership = RHS module
  path under `HOSTED_GO_MODULE_PREFIX`; go.mod and go.sum carry no other
  marker), module-target parse (`rhs_module`/`rhs_version`) and
  `upsert_hosted_replace_entry`, with in-place cross-owner takeover between
  local `.socket/go-patches/`, vendored, and hosted directives.
- `vendor/go_sum_edit.rs` — pure go.sum editing: sorted upsert of the socket
  module's two lines, prune of the replaced original's lines (removed lines
  ride in the ledger `original` for revert), prefix-keyed removal.
- `scan/hosted.rs` — `go.mod`/`go.sum` added to `REDIRECT_CANDIDATE_FILES`;
  the redirected-confirmation matcher additionally accepts the socket module
  path (a Go rewrite contains no artifact/index URL).
- Wire schema — `Integrity.goModH1` (new) alongside `dirhashH1`;
  `RegistryOverrideIdentifiers.goModuleVersion` (new) alongside the
  previously-reserved `goModulePath`.
- Cross-mode policy (adversarially reviewed): takeover into hosted (from a
  local `.socket/go-patches/` or vendored replace) and vendor-takes-over-hosted
  are supported, in-place, and ledger-recorded with the replaced directive in
  `original`; **local apply refuses** a Hosted-owned replace (taking it over
  would strand the pruned go.sum lines) and `apply --check` exempts
  hosted-owned modules from MissingReplace drift. A committed pin whose
  version `require` no longer selects is reconciled away (directive + go.sum
  lines removed) rather than left to confirm a redirect it no longer performs.
  `vendor --revert` after a hosted takeover warns to re-run
  `scan --mode hosted` or `go mod tidy`.
- Tests — unit suite in `redirect/mod.rs`; golden fixture
  `tests/fixtures/redirect/golang/gomod/basic/` (the cross-language contract
  the depscan TS twin must match byte-identically); capstone
  `e2e_golang_hosted_build.rs` (real go, file proxy, bogus-GOSUMDB tripwire,
  tidy no-op, tamper SECURITY ERROR).

## Server requirements (depscan)

What already exists (verified in code + live prod probes, 2026-08-13):

- The GOPROXY protocol implementation (`patch-serving/registry-decision.ts`
  `golangDecision`: `/@v/list`, `.info`, `.mod`, `.zip`, `/@latest`) — deployed
  and executing in prod, but token-gated
  (`/patch-registry/golang/{token}/{uuid}/…`) and serving the ORIGINAL module
  path + version.
- A byte-deterministic golang repack (STORE-only zips, epoch mtimes, sorted
  names; e2e-pinned to reproduce `sum.golang.org`'s h1 for unpatched input).
- `hashGoZip` (persisted as `package_dirhash_h1`) and `hashGoMod` (exists in
  `lib/src/go/sum.ts` but never persisted or exposed).
- Anonymous free-tier grant minting via `POST /patch/package`.

What the free-tier Go redirect needs:

1. **A second artifact flavor per golang patch**: same patched contents,
   zip entries prefixed `patch.socket.dev/gopatch/<uuid>@<version>/`
   (internal `go.mod` unchanged — keep declaring the original path). Because
   h1 covers entry names, this flavor has its OWN dirhash: persist both its
   zip h1 and its `/go.mod` h1 (`hashGoMod` of the served `.mod` bytes).
2. **A token-free route family** serving that flavor over the GOPROXY
   protocol at a stable public path for module `patch.socket.dev/gopatch/<uuid>`,
   free-tier patches only. Strictly 404/410 anything else (including bare
   parent-prefix `/@v/list` probes go issues during tidy) so comma-fallback
   proxies fall through. `.info` needs no `Time` field.
3. **`?go-get=1` discovery**: serve
   `<meta name="go-import" content="patch.socket.dev/gopatch/<uuid> mod <proxy-base-url>">`
   at the module path on `patch.socket.dev`, so `GOPROXY=direct` users and
   `proxy.golang.org` itself can resolve it (validated end-to-end with the
   `mod` VCS type; `sum.golang.org`'s own lookup does the same discovery).
4. **Reference API**: populate `registryOverride.kind = "goproxy"`,
   `indexUrl` = the proxy base, `identifiers.goModulePath` /
   `goModuleVersion` (`<version>-socketpatch.<n>`, always v0/v1-range), and
   both integrity hashes (`dirhashH1` = the gopatch-flavor zip h1, `goModH1`).
   FREE patches only — never emit a `goproxy` override for a paid-tier grant.
5. **Write-once invariant (the kill-shot risk)**: once a
   `gopatch/<uuid>@<version>` is fetchable, `proxy.golang.org` caches its
   bytes immutably and consumers commit its hashes. Any rebuild that changes
   bytes MUST bump `-socketpatch.<n>`; the existing admin
   "regenerate to populate" rebuild practice must be forbidden for published
   gopatch versions.
6. **TS twin**: replace `registry-rewrite/golang.ts`'s unconditional warning
   with the byte-identical twin of the Rust rewriter, pinned by the shared
   `golang/gomod` golden fixture.
