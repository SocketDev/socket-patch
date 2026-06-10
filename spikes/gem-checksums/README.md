# Spike: Bundler >= 2.6 CHECKSUMS for vendored (path-sourced) gem patching

Tool versions (everything ran inside docker, fresh container per step = cold caches):

- image: `ruby:3.3` (digest base `56d789a4b8e8`), aarch64-linux
- ruby 3.3.11 (2026-03-26 revision 1f2d15125a) [aarch64-linux]
- RubyGems 3.5.22
- **Bundler 2.7.2** (installed via `gem install bundler -v '~> 2.7' --no-document`)
- invocation pattern: `docker run --rm -v <dir>:/app -w /app -e BUNDLE_APP_CONFIG=/app/.bundle ruby:3.3 ...`

Every `after/Gemfile.lock` was written by Bundler itself (`bundle lock` or `bundle install`),
never hand-written. Locks were generated on aarch64-linux, so `PLATFORMS` contains
`aarch64-linux` + `ruby`; regenerating on x86_64 would add `x86_64-linux`.

Common config (committed as `.bundle/config` in each tree):

```yaml
---
BUNDLE_PATH: "vendor/bundle"
BUNDLE_LOCKFILE_CHECKSUMS: "true"
```

## Pairs

### registry-with-checksums/  (G1)
- `before/`: Gemfile (`gem "rack", "3.1.8"` from rubygems.org) + `.bundle/config`, no lock.
- `after/`: lock produced by `bundle lock` with `lockfile_checksums true` set before first lock.
  Verbatim registry CHECKSUMS grammar (2-space indent, single space before token, 64 lowercase hex):

  ```
  CHECKSUMS
    rack (3.1.8) sha256=d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1
  ```

  `bundle lock --add-checksums` on a lock created *without* the config produces the
  byte-identical CHECKSUMS section (verified).

### path-with-checksums/  (G2 — pins the emitter)
- `before/`: the registry-locked project (what socket-patch sees pre-patch).
- `after/`: Gemfile switched to `gem "rack", "3.1.8", path: "./vendored/rack-3.1.8"`;
  `vendored/rack-3.1.8/` = installed gem dir copied from `vendor/bundle/ruby/3.3.0/gems/`
  + gemspec copied from `specifications/rack-3.1.8.gemspec` to `vendored/rack-3.1.8/rack.gemspec`
  + patch marker `# socket-patch: patched rack-3.1.8 (spike marker)` as line 1 of `lib/rack.rb`.
  Lock written by `bundle lock`. The path gem is **not omitted** from CHECKSUMS — it gets a
  **bare entry with no sha256 token**:

  ```
  PATH
    remote: vendored/rack-3.1.8
    specs:
      rack (3.1.8)

  GEM
    remote: https://rubygems.org/
    specs:

  ...
  DEPENDENCIES
    rack (= 3.1.8)!

  CHECKSUMS
    rack (3.1.8)
  ```

  Notes for the emitter: Bundler strips the Gemfile's leading `./` in `remote:`;
  the DEPENDENCIES entry gains a trailing `!`; the empty `GEM ... specs:` block stays.
- Byte-stability (G3): a hand-written lock in exactly this form was diff-identical to
  Bundler's own output, and from a fresh checkout with cold caches all of
  `bundle install`, `BUNDLE_FROZEN=true bundle install`, `bundle lock` exited 0 and left the
  lock byte-identical (sha256 `3086e757...` unchanged across all three).
- Committable guarantee: cold `BUNDLE_FROZEN=true bundle install` on `after/` (committed files
  only) exits 0 and `require "rack"` loads `/app/vendored/rack-3.1.8/lib/rack.rb` whose first
  line is the patch marker. Path gems are used **in place** (never copied to vendor/bundle) and
  are **never checksum-verified** — the format has no artifact to hash.

### stale-checksum-v1-bug/  (G4)
- `before/`: same project as path-with-checksums/after but the lock (hand-edited, simulating the
  v1 emitter) keeps the REGISTRY sha256 token on the path gem's CHECKSUMS line.
- `after/`: what `bundle lock` writes given that lock — **byte-identical**; the stale token is
  silently preserved.
- Findings: `bundle install`, `BUNDLE_FROZEN=true bundle install`, and `bundle lock` all exit 0
  and never touch or verify the stale token (Bundler skips checksum verification for PATH
  sources entirely). The v1 lock is therefore *latently* divergent: deleting the lock and
  re-running `bundle lock` produces the bare `  rack (3.1.8)` form, i.e. permanent diff churn
  vs. anything Bundler would emit, but no loud failure on Bundler 2.7.2.
- Negative control proving CHECKSUMS enforcement is live for registry gems: corrupting the
  sha256 of registry-sourced rack fails cold `bundle install` with exit 37:
  `Bundler found mismatched checksums. This is a potential security risk.` (caught against the
  rubygems.org API at metadata time, before download).

### bare-checksum-registry-gem/  (reverse probe — pins the rollback emitter)
- `before/`: registry-sourced lock whose CHECKSUMS entry was stripped to the bare
  `  rack (3.1.8)` form (no token).
- `after/`: lock as rewritten by plain `bundle install` — Bundler fills the sha256 back in
  (byte-identical to registry-with-checksums/after/Gemfile.lock).
- `BUNDLE_FROZEN=true bundle install` on `before/` **fails, exit 16**:

  ```
  Your lockfile has an empty CHECKSUMS entry for "rack", but can't be updated
  because frozen mode is set
  ```

  So: bare entry is *required* for path gems but *breaks frozen installs* for registry gems —
  rollback must restore the registry sha256 token, and the patch emitter must strip it.

## G5: platform suffixes
Pure-ruby rack gets exactly one CHECKSUMS line with **no platform suffix** even though
PLATFORMS lists `aarch64-linux` + `ruby`. The suffix *does* exist for native gems: locking
`ffi 1.17.2` yields one line per platform spec, e.g.
`  ffi (1.17.2-aarch64-linux-gnu) sha256=...` alongside the bare `  ffi (1.17.2) sha256=...`
— the `(version-platform)` token mirrors the GEM specs entries exactly.
