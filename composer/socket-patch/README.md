# socket-patch (Composer)

Distributes the [`socket-patch`](https://github.com/SocketDev/socket-patch) CLI
through Composer / Packagist so it can be installed in PHP environments:

```sh
composer require socketsecurity/socket-patch
vendor/bin/socket-patch --help
```

This is a thin **launcher** package. On first run `vendor/bin/socket-patch`
downloads the prebuilt binary for your platform from the GitHub release
**matching the installed package's own version** (read from Composer's
`InstalledVersions`), verifies it against the release's `SHA256SUMS`, caches it
under your user cache (`~/.cache/socket-patch/bin/` or
`%LOCALAPPDATA%\socket-patch\bin\` on Windows), and execs it. Subsequent runs use
the cached binary.

So `composer require socketsecurity/socket-patch:3.2.0` downloads the `v3.2.0`
binary — the binary version always tracks the installed package version.

Note: the package manifest (`composer.json`) lives at the **repository root**,
not in this directory — Packagist only publishes manifests found at the root of
the VCS repository (and `composer.json` cannot carry comments explaining that
itself). The launcher script stays here; the root manifest points its `bin` at
`composer/socket-patch/bin/socket-patch`, and the root `.gitattributes`
export-ignore allowlist keeps the rest of the repository out of the Packagist
dist zip.

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
