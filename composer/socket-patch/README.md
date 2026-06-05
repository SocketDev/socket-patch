# socket-patch (Composer)

Distributes the [`socket-patch`](https://github.com/SocketDev/socket-patch) CLI
through Composer / Packagist so it can be installed in PHP environments:

```sh
composer require socketsecurity/socket-patch
vendor/bin/socket-patch --help
```

This is a thin **launcher** package. On first run `vendor/bin/socket-patch`
downloads the prebuilt binary for your platform from the matching GitHub release
(`v<version>`), verifies it against the release's `SHA256SUMS`, caches it under
your user cache (`~/.cache/socket-patch/bin/` or `%LOCALAPPDATA%\socket-patch\bin\`
on Windows), and execs it. Subsequent runs use the cached binary.

The package version maps to the release it fetches: installing the package at
tag `vX.Y.Z` downloads the `vX.Y.Z` binary.

## Airgapped / offline use

The launcher downloads on first run. For offline CI, point it at an
already-installed binary:

```sh
export SOCKET_PATCH_BIN=/usr/local/bin/socket-patch
```

When `SOCKET_PATCH_BIN` is set to an executable, the launcher skips the download
and execs it.

## License

MIT
