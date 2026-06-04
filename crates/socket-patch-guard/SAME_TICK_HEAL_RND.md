# R&D: same-tick auto-heal for project-local cargo patches

**Status:** experiment complete — *positive result*. Not yet shipped (blocked only
on publishing the guard). Production behavior today is the single fail-closed
guard documented in `README.md`.

## The question

The shipped guard is **fail-closed with a one-build lag on drift**: if the
committed patched copies under `.socket/cargo-patches/` are stale, this build has
*already* compiled the stale copy by the time the guard's build script runs, so
the guard heals and then *fails* the build — the re-run is clean.

Can we instead make a manifest change take effect in the **same** `cargo build`,
so a bare `cargo build` never compiles stale sources and never has to fail?

The original worry (and why we shipped fail-closed first): cargo computes a
crate's fingerprint and *schedules its compile before build scripts run*, and
sibling units have no ordering guarantee — so a guard that heals "somewhere
during the build" can't guarantee the patched copy is recompiled afterwards.

That worry is about **siblings with no dependency edge**. The spike asks whether a
real dependency edge removes it.

## The mechanism tested

Make each patched **copy** carry a normal `[dependencies]` edge on the guard:

```
consumer ──▶ c (patched copy) ──▶ g (guard)
                                  └─ build.rs heals c's source from the manifest
```

cargo builds a crate's dependencies — *including their build scripts* — before the
crate itself, and evaluates a crate's source freshness when it gets to building
it (after its deps). So `g`'s `build.rs` rewrites `c`'s source **before** cargo
compiles `c`, and cargo then compiles `c` from the healed source. This isn't
fragile sibling timing; it's cargo's most fundamental invariant: *a crate is
built after its dependencies, from its current source.*

## Result (cargo 1.93.1, macOS — reproducible via `tests/same_tick_heal_experiment.rs`)

`g/build.rs` reads `value.txt` (stands in for `.socket/manifest.json`) and rewrites
`c/src/lib.rs` to `pub fn v() -> u32 { <value> }`; `consumer` prints `c::v()`.

| Step | On-disk `c` before build | `value.txt` | One `cargo build` prints | Recompiled `c`? |
|------|--------------------------|-------------|--------------------------|-----------------|
| #1   | `0` (stale)              | `111`       | **111**  (not `0`)       | yes             |
| #2   | `111`                    | `111`       | `111`                    | **no** (cached) |
| #3   | `111`                    | `222`       | **222**                  | yes             |

**Same-tick heal works**, and it is *free in steady state*: when the manifest is
unchanged the guard's build script is a cached no-op (`Finished in 0.00s`) and the
copy is not recompiled. A manifest change recompiles only the affected copy, in
one build.

## Why this is reasonably robust

The earlier "fingerprint is computed before build scripts" concern does not apply
here, because there is a dependency edge: cargo *must* finish `g` (build script
included) before it builds `c`, and it reads `c`'s source at that later point.
Relying on "cargo recompiles a crate whose source changed, after its deps" is
about as safe a cargo assumption as exists. The spike confirms it empirically; it
is the natural behavior, not an exploit of an internal detail.

## Costs and caveats (what productionizing would require)

1. **The guard becomes a linked dependency of every patched copy.** The guard
   lib is linked into each copy's dependency graph, so it must be buildable for
   whatever *target* the consumer compiles for. For ordinary hosted targets a
   `std` guard links fine even into `#![no_std]` copies (verified: a crate's
   `#![no_std]` governs only its own prelude/std use, not what its dependencies
   may use). Only if socket-patch must patch crates compiled for a bare-metal /
   `no_std` *target* (where the `std` crate can't be built at all — and the copy's
   own std-using deps would fail regardless) would the guard itself need to be
   `#![no_std]` + no-alloc.
2. **Publish-gated.** A copy's `Cargo.toml` must reference the guard *portably*
   (`socket-patch-guard = "x.y"`), not by `path` — path refs don't survive a fresh
   clone on another machine. So this can ship to real users **only after the guard
   is on crates.io**. Pre-publish, injecting an unresolvable guard dep into copies
   would break every build, which is exactly why production `apply_cargo_redirect`
   must **not** inject it yet.
3. **`apply` would inject the edge.** `apply_cargo_redirect` would add
   `[dependencies] socket-patch-guard = "x.y"` to each generated copy's
   `Cargo.toml`. This was deliberately left out of the shipped code.
4. **The guard would heal-and-proceed (not fail).** In this model the build script
   heals and returns `Ok`; the same-tick recompile makes "proceed" correct. The
   fail-closed guard on the user's *own* crates and the `socket-patch apply --check
   --ecosystems cargo` CI gate remain as backstops in the (unlikely) event a future
   cargo ever broke the dependency-ordered-freshness invariant.
5. **Manifest-only re-trigger — a regression vs. the shipped guard.** Heal-and-
   proceed re-fires only on `cargo:rerun-if-changed` of the manifest / `Cargo.lock`,
   so a copy that drifts *without* a manifest change (a bad merge, a partial
   checkout, a hand-edit of `.socket/cargo-patches/`) is a cached no-op for the
   build script — it compiles and ships the stale copy silently on a local build.
   The shipped fail-closed guard does **not** have this gap: its `apply --check`
   re-hashes every copy file against the manifest on every build rather than
   trusting `rerun-if-changed`. So heal-and-proceed is "no fail, no lag" only for
   *manifest-driven* changes; productionizing it would need the guard to also
   `rerun-if-changed` each copy's files (and content-verify, since an mtime touch
   alone is insufficient).

## Recommendation

Productionize **after the guard is published**. The same-tick heal is empirically
validated and rests on a fundamental cargo invariant, and it delivers the ideal
the user asked for: a bare `cargo build` applies the patch with **no fail and no
lag for manifest-driven changes**, at zero steady-state cost (modulo caveat #5 —
manifest-independent copy drift would need extra `rerun-if-changed` coverage). The
only deployment blocker is publishing the guard so copies can reference it
portably.

Until then, ship the single fail-closed guard (heal-then-fail-once on drift,
fail-closed on a missing CLI or unrecoverable state). The reproducible experiment
lives in `tests/same_tick_heal_experiment.rs` (`#[ignore]`, runs a real cargo).
