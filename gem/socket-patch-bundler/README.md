# socket-patch-bundler

A [Bundler plugin](https://bundler.io/guides/bundler_plugins.html) that keeps the
gem patches recorded in your project's `.socket/manifest.json` applied on every
`bundle install` — cached **and** fresh — by re-running the
[`socket-patch`](https://github.com/SocketDev/socket-patch) CLI.

> **Status: Phase 2 (scaffolding).** `socket-patch setup` currently wires the gem
> ecosystem by committing an in-tree copy of this plugin under
> `.socket/bundler-plugin/` and referencing it from the `Gemfile` via `git:`.
> This published gem is the planned replacement; once it is published to
> RubyGems, a follow-up switches the generated `Gemfile` directive to
> `plugin "socket-patch-bundler", "~> <major.minor>"`.

## Requirements

The `socket-patch` CLI must be on `PATH` (or pointed at by `SOCKET_PATCH_BIN`)
wherever `bundle install` runs — the same requirement as the in-tree plugin and
the cargo build-time guard.

## How it works

Two triggers feed one idempotent applier: a load-time pass (covers cached/no-op
installs) and an `after-install-all` hook (covers fresh installs). A digest of
the manifest + committed `.socket/` files + `Gemfile.lock` gates the work, and a
stamp under `Bundler.bundle_path` travels with the gems. On any patch failure it
raises `Bundler::BundlerError` so the build fails loudly rather than shipping
unpatched gems.

## License

MIT
