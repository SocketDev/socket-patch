# socket-patch-guard

A tiny build-time guard for [socket-patch](https://github.com/SocketDev/socket-patch)'s
**project-local cargo patch** backend.

You don't use this crate directly. Run `socket-patch setup` in a Rust project and
it adds `socket-patch-guard` to your `[dependencies]` and writes
`[env] SOCKET_PATCH_ROOT` into `.cargo/config.toml`. From then on, a bare
`cargo build` verifies your committed security patches and **fails the build if
they're out of sync** — so you can never silently ship stale or unpatched code:

- Patches are applied declaratively by committed `[patch.crates-io]` entries +
  patched-crate copies under `.socket/cargo-patches/`. In the steady state (the
  committed copies match `.socket/manifest.json`) the guard's build script is a
  cached no-op and the build proceeds with zero overhead.
- On a relevant change (`Cargo.lock` or `.socket/manifest.json`), the guard runs
  `socket-patch apply --check` (read-only). If the committed copies are stale,
  or a patched dependency resolved to an *unpatched* version, the build
  **fails** with instructions to run `socket-patch apply` and commit the
  regenerated copies. This is run-order-independent: it checks the static
  committed state, not whatever the build script happens to do mid-build.

## `SOCKET_PATCH_GUARD` modes

- *(unset / `error`)* — **fail-closed** (default): a drift fails the build.
- `warn` — heal-and-continue: regenerate the copies and emit a `cargo:warning`
  instead of failing. The regenerated sources take effect on the **next** build
  (a one-build lag), so this trades safety for local-dev convenience.
- `off` — disable the guard entirely (emits a loud warning that patches are not
  verified for this build).

## CI

Add an explicit gate that doesn't depend on the build-script guard:

```sh
socket-patch apply --check --ecosystems cargo
```

It is read-only, offline, lock-free, ignores `SOCKET_PATCH_GUARD`, and exits
non-zero on drift — including a `Cargo.lock` cross-check that catches a patched
dependency silently resolving to an unpatched version.

## Environment

- `SOCKET_PATCH_ROOT` — set by `setup` in `.cargo/config.toml`; the project root
  the guard operates on. If unset, the guard warns and does nothing.
- `SOCKET_PATCH_BIN` — override the `socket-patch` binary path (defaults to
  `socket-patch` on `PATH`).
- `SOCKET_PATCH_GUARD` — `warn` / `off` as above.

The guard is a normal `[dependencies]` entry (not a `[build-dependencies]` one)
so cargo always compiles it and runs its build script — it links one tiny empty
rlib into your crate. Your own `build.rs` is never touched.
