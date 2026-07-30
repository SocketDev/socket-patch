# socket-patch (Maven Central)

Distributes the [`socket-patch`](https://github.com/SocketDev/socket-patch) CLI
through Maven Central (`dev.socket:socket-patch`) so it can be run in
Java / JVM environments:

```sh
mvn dependency:copy -Dartifact=dev.socket:socket-patch:3.3.0 -DoutputDirectory=.
java -jar socket-patch-3.3.0.jar apply
```

With [jbang](https://www.jbang.dev/):

```sh
jbang dev.socket:socket-patch:3.3.0 --help
```

Or fetch the jar directly (it has no dependencies):

```sh
curl -fsSLO https://repo1.maven.org/maven2/dev/socket/socket-patch/3.3.0/socket-patch-3.3.0.jar
java -jar socket-patch-3.3.0.jar --help
```

(Replace `3.3.0` with the release you want.)

This is a thin **launcher** jar. On first run it downloads the prebuilt binary
for your platform from the GitHub release **matching the jar's own version**
(read from the jar manifest's `Implementation-Version`, so resolving
`dev.socket:socket-patch:3.2.0` fetches the `v3.2.0` binary), verifies it
against the release's `SHA256SUMS`, caches it under your user cache
(`~/.cache/socket-patch/bin/` or `%LOCALAPPDATA%\socket-patch\bin\` on Windows),
and runs it. Subsequent runs use the cached binary.

Behind an egress proxy, the launcher honors the `https_proxy` / `HTTPS_PROXY` /
`all_proxy` / `ALL_PROXY` environment variables (like the other socket-patch
launchers); explicit JVM proxy properties (`-Dhttps.proxyHost=...`) take
precedence when set.

## Airgapped / offline use

The launcher downloads on first run, so for offline CI either pre-warm the cache
or point it at an already-installed binary:

```sh
export SOCKET_PATCH_BIN=/usr/local/bin/socket-patch
```

When `SOCKET_PATCH_BIN` is set to an executable, the launcher skips the download
entirely and runs it. (The npm and PyPI distributions bundle the binary instead
of downloading.)

## License

MIT
