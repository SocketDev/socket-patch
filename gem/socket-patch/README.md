# socket-patch (RubyGems)

Distributes the [`socket-patch`](https://github.com/SocketDev/socket-patch) CLI
through RubyGems so it can be installed in Ruby / Bundler environments:

```sh
gem install socket-patch
socket-patch --help
```

This is a thin **launcher** gem. On first run it downloads the prebuilt binary
for your platform from the GitHub release **matching the installed gem's own
version** (so `gem install socket-patch -v 3.2.0` fetches the `v3.2.0` binary),
verifies it against the release's `SHA256SUMS`, caches it under your user cache
(`~/.cache/socket-patch/bin/` or `%LOCALAPPDATA%\socket-patch\bin\` on Windows),
and execs it. Subsequent runs use the cached binary.

## Airgapped / offline use

The launcher downloads on first run, so for offline CI either pre-warm the cache
or point it at an already-installed binary:

```sh
export SOCKET_PATCH_BIN=/usr/local/bin/socket-patch
```

When `SOCKET_PATCH_BIN` is set to an executable, the launcher skips the download
entirely and execs it. (The npm and PyPI distributions bundle the binary instead
of downloading; a future hardening may ship platform-specific gems that bundle
the binary too.)

## License

MIT
