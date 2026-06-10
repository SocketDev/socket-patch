# yarn classic (1.22.x) vendored-tarball spike fixtures

Spike for socket-patch vendor v2: can a lock-only rewrite make yarn classic install a
patched, committed tarball from `.socket/vendor/npm/<uuid>/<name>-<version>.tgz`,
checksum-verified, with cold caches, offline?

**Answer: yes.** All claims confirmed (Y5 with one caveat about the unsatisfiable
`^1.3.2` range, see below).

## Tool versions

- node v24.12.0 (Darwin 25.5.0, arm64)
- corepack 0.34.5
- yarn 1.22.22 (via `corepack yarn`, pinned by `"packageManager": "yarn@1.22.22"`)
- yarn 4.12.0 (berry sniff fixture only)
- patched tarball built with macOS bsdtar (`tar czf`, `COPYFILE_DISABLE=1`),
  digests via `shasum -a 1` / `openssl dgst -sha512 -binary | base64`

## The patched artifact

`left-pad@1.3.0` from registry.npmjs.org, unpacked, marker line
`/* SOCKET-PATCHED left-pad@1.3.0 marker:9f6b2c4e */` prepended to
`package/index.js`, repacked with `package/` prefix.

- registry tgz sha1: `5b8a3a7765dfe001261dde915589e782f8c94d1e`
- patched tgz sha1:  `fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6`
- patched tgz sha512 SRI: `sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==`

## Lockfile entry recipe (the v2 rewrite)

```
left-pad@^1.3.0:
  version "1.3.0"
  resolved "file:./.socket/vendor/npm/<uuid>/left-pad-1.3.0.tgz#<sha1-of-tgz>"
  integrity sha512-<base64-sha512-of-tgz>
```

- `resolved` spellings that work: `file:./<path>#<sha1>` and `./<path>#<sha1>`.
  A path with **no** `./`/`file:` prefix does NOT work: yarn treats it as
  registry-relative and requests `https://registry.yarnpkg.com/.socket/...` (404).
- The `#<sha1>` fragment is the sha1 of the tgz bytes; yarn enforces it even when
  the `integrity` line is absent (substituting a wrong tarball fails
  `Integrity check failed` either way).
- yarn's own serializer round-trips this entry byte-for-byte (verified by forcing a
  lock re-save with `yarn add isarray@2.0.5` + `yarn remove isarray`): every
  `after/yarn.lock` here was emitted by yarn 1.22.22 itself, not hand-written.

## Fixture pairs

### y1-file-dep-ground-truth/
Ground truth for how yarn classic natively records a `file:` tarball dep.
`package.json` has `"lp": "file:./lp.tgz"` (lp.tgz = the patched tarball);
`yarn.lock` is exactly what `yarn install` wrote:

```
"lp@file:./lp.tgz":
  version "1.3.0"
  resolved "file:./lp.tgz#fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6"
```

Key shape `"<name>@file:./<path>"`, `file:` prefix kept in `resolved`, `#sha1`
fragment present, **no `integrity` line** for native file: deps.

### y2-lock-rewrite/ (before -> after)
- `before/`: registry project (`left-pad: ^1.3.0`), yarn-generated lock pointing at
  `https://registry.yarnpkg.com/...#5b8a3a...` with the registry sha512.
- `after/`: same package.json; lock's left-pad block rewritten to the recipe above;
  patched tarball committed at
  `.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz`.

Replay: `rm -rf node_modules && YARN_CACHE_FOLDER=$(mktemp -d) corepack yarn install --offline --frozen-lockfile`
-> exit 0, `node_modules/left-pad/index.js` carries the marker, yarn.lock
byte-unchanged. Also passes with HTTP(S)_PROXY pointed at a dead port (zero network).

### y4-tamper/ (failure fixture)
`after/` is y2's after but `.socket/.../left-pad-1.3.0.tgz` is the **unpatched
registry tarball** (valid gzip, wrong hashes). Frozen install MUST fail, exit 1:

```
error Integrity check failed for "left-pad" (computed integrity doesn't match our records, got "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA== sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4=")
```

(A raw byte-flip also fails, exit 1, but earlier and uglier — gzip error
`"invalid distance too far back". Mirror tarball appears to be corrupt.`)

### y5-merged-alias/ (before -> after)
- `before/`: root deps `left-pad: ^1.3.0`, `alias: npm:left-pad@^1.3.0`, and a
  folder dep `dep-a` (file:./dep-a) requiring `left-pad: ~1.3.0`, so yarn itself
  generates a **merged** block `left-pad@^1.3.0, left-pad@~1.3.0:` plus a separate
  alias block `"alias@npm:left-pad@^1.3.0":`.
- `after/`: both blocks' resolved+integrity rewritten to the vendored tarball
  (then re-serialized by yarn, byte-identical).

Replay: both `node_modules/left-pad` and `node_modules/alias` (an aliased copy of
left-pad@1.3.0) carry the marker; lock unchanged.

Caveat: the claim's literal `left-pad@^1.3.2` range is unsatisfiable (1.3.0 is the
last left-pad ever published), so the merged block was generated with
`^1.3.0, ~1.3.0` instead. Merging behavior is the same: one block, N keys, one
resolved — a single rewrite patches every requester.

### y8-berry-sniff/
yarn 4.12.0 project with `nodeLinker: node-modules`. Its yarn.lock starts with a
generated-file comment + `__metadata:` (version 8, cacheKey 10c0) and contains
**no** `# yarn lockfile v1` header. Classic locks always carry
`# yarn lockfile v1`. Sniff rule: `__metadata:` => berry (different rewrite
strategy needed — berry verifies `checksum:` against its own cache format);
`# yarn lockfile v1` => classic (this recipe applies).

## Behavioral claims verified without a dedicated fixture dir

- **Y3 warm-cache poisoning**: cache primed with the registry tarball
  (`v6/npm-left-pad-1.3.0-5b8a3a...-integrity`), then the vendored install run
  against the same cache -> patched bytes installed. Cache entries are keyed
  `npm-<name>-<version>-<sha1>-integrity`, so registry and vendored artifacts get
  distinct slots; no poisoning either direction.
- **Y6 offline fresh checkout**: copying only package.json + yarn.lock + .socket
  into an empty dir, empty cache, `--offline --frozen-lockfile` -> exit 0, patched.
  Re-verified with dead HTTP(S)_PROXY: no network touched for the file: dep.
- **Y7 resolution base**: `corepack yarn --cwd <project> install --frozen-lockfile`
  run from an unrelated directory containing a decoy unpatched tarball at the same
  relative path -> the decoy is ignored and the project's tarball is used (relative
  `resolved` resolves against the project/lockfile dir, not process cwd). Running
  from a nested subdir of the project (no --cwd) also resolves correctly.

## Notes for the tool design

- Write `resolved "file:./<relpath>#<sha1>"` + `integrity sha512-...`. Both hash
  layers are enforced by yarn classic on every install, frozen or not, warm or
  cold cache.
- `--frozen-lockfile` does not rewrite the lock; a plain `yarn install` keeps the
  entry stable, and forced re-serialization preserves it byte-for-byte.
- The lock-only rewrite leaves package.json untouched (`left-pad@^1.3.0` range key
  still matches), so no manifest churn.
