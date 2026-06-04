# socket-patch-guard

A tiny build-time guard for [socket-patch](https://github.com/SocketDev/socket-patch)'s
**project-local cargo patch** backend.

You don't use this crate directly. Run `socket-patch setup` in a Rust project and
it adds `socket-patch-guard` to your `[dependencies]` and writes
`[env] SOCKET_PATCH_ROOT` into `.cargo/config.toml`. From then on, a bare
`cargo build` verifies your committed security patches and **fails the build if
they're out of sync** — so you can never silently ship stale or unpatched code.

Once wired by `socket-patch setup`, there is exactly **one mode: fail-closed** —
no drift-tolerating `warn` or `off`. (Before setup runs, an unconfigured project
has no `SOCKET_PATCH_ROOT` and is simply not guarded yet — see
[Environment](#environment).)

- Patches are applied declaratively by committed `[patch.crates-io]` entries +
  patched-crate copies under `.socket/cargo-patches/`. In the steady state (the
  committed copies match `.socket/manifest.json`) the guard's build script is a
  cached no-op and the build proceeds with zero overhead. In normal use the
  guard never fires, because changing a patch goes through `socket-patch get` /
  `apply`, which regenerate the copies.
- On a relevant change (`Cargo.lock` or `.socket/manifest.json`), the guard runs
  `socket-patch apply --check` (read-only). If in sync, the build proceeds. On
  drift it runs `socket-patch apply` to regenerate the copies, then **fails the
  build** (the current build already compiled the stale copy):
  - recoverable (the heal reconciled it) → "regenerated — re-run the build"; the
    re-run is clean (it *did* apply the patch);
  - unrecoverable (a patched dependency resolved to an unpatched version, or the
    patch data is corrupt/missing) → fails with diagnostics to run
    `socket-patch apply` and inspect.
- A missing `socket-patch` CLI also **fails the build** — verification is
  mandatory. (So a repo wired with the guard requires `socket-patch` to build;
  wire it into apps/workspaces you control, not a published library.)

This is run-order-independent: it checks the static committed state, not whatever
the build script happens to do mid-build.

## CI

The guard already fails any `cargo build` on drift. As an explicit, build-free
pipeline gate you can also run:

```sh
socket-patch apply --check --ecosystems cargo
```

Read-only, offline, lock-free; exits non-zero on drift — including a `Cargo.lock`
cross-check that catches a patched dependency silently resolving to an unpatched
version.

## Environment

- `SOCKET_PATCH_ROOT` — set by `setup` in `.cargo/config.toml`; the project root
  the guard operates on. If unset, the guard warns and does nothing.
- `SOCKET_PATCH_BIN` — override the `socket-patch` binary path (defaults to
  `socket-patch` on `PATH`).

The guard is a normal `[dependencies]` entry (not a `[build-dependencies]` one)
so cargo always compiles it and runs its build script — it links one tiny empty
rlib into your crate. Your own `build.rs` is never touched.
