# socket-patch-bundler

> **Deprecated — no longer published.** `socket-patch setup` (which wired this
> plugin) was removed in socket-patch v5, and this gem is no longer built or
> published. In agent mode, run `socket-patch apply` in CI after
> `bundle install` instead. The source is kept for reference only.
> To remove the hook from a project, see
> [Upgrading from `setup`](https://github.com/SocketDev/socket-patch#upgrading-from-setup).

A [Bundler plugin](https://bundler.io/guides/bundler_plugins.html) that keeps the
gem patches recorded in your project's `.socket/manifest.json` applied on every
`bundle install` — cached **and** fresh — by re-running the
[`socket-patch`](https://github.com/SocketDev/socket-patch) CLI.

> **Status: Phase 2 (scaffolding).** `socket-patch setup` currently wires the gem
> ecosystem by committing an in-tree copy of this plugin under
> `.socket/bundler-plugin/` and referencing it from the `Gemfile` via a `path:`
> source (`plugin 'socket-patch', path: File.expand_path('.socket/bundler-plugin', __dir__)`).
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
the manifest + committed `.socket/` files + `Gemfile.lock` + the patch-target
files gates the work; the digest is cached in `.socket/gem-plugin-stamp`
(machine-local, safe to gitignore or delete). On a patch failure it warns
(naming the failure and the remediation) and lets `bundle install` continue;
set `SOCKET_PATCH_STRICT=1` to raise `Bundler::BundlerError` instead.

## License

MIT
