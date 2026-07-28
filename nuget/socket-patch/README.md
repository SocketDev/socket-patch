# socket-patch (NuGet)

Distributes the [`socket-patch`](https://github.com/SocketDev/socket-patch) CLI
through NuGet as a .NET tool so it can be installed in .NET environments:

```sh
dotnet tool install -g SocketSecurity.SocketPatch
socket-patch --help
```

Or pin it per-repository with a tool manifest (restored by
`dotnet tool restore`):

```sh
dotnet new tool-manifest   # once per repo
dotnet tool install SocketSecurity.SocketPatch
dotnet tool run socket-patch -- --help
```

This is a thin **launcher** package. On first run it downloads the prebuilt
binary for your platform from the GitHub release **matching the installed
package's own version** (so `dotnet tool install -g SocketSecurity.SocketPatch
--version 3.2.0` fetches the `v3.2.0` binary), verifies it against the
release's `SHA256SUMS`, caches it under your user cache
(`~/.cache/socket-patch/bin/` or `%LOCALAPPDATA%\socket-patch\bin\` on
Windows), and runs it. Subsequent runs use the cached binary.

## Airgapped / offline use

The launcher downloads on first run, so for offline CI either pre-warm the
cache or point it at an already-installed binary:

```sh
export SOCKET_PATCH_BIN=/usr/local/bin/socket-patch
```

When `SOCKET_PATCH_BIN` is set to an existing executable, the launcher skips
the download entirely and runs it. (The npm and PyPI distributions bundle the
binary instead of downloading.)

## License

MIT
