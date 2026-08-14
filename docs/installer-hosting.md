# Hosting the installer at install.socket.dev

The documented one-liner is

```sh
curl -fsSL https://install.socket.dev/patch | sh
```

`install.socket.dev/patch` serves a **byte-for-byte copy of
[`scripts/install.sh`](../scripts/install.sh)** — not a rendered template, not a
different script. The README says so, so it has to stay true.

## Why a Socket domain

The one-liner used to point at `raw.githubusercontent.com`. That asks a user to
trust a third-party CDN for a script they pipe into a shell, and it is the first
URL a locked-down egress policy blocks. `install.socket.dev` is a name Socket
controls, already inside the trust boundary a customer grants `socket.dev`, and
it stays stable if the artifacts ever move.

The GitHub URL still works and still serves the same bytes. Anyone who would
rather not add a dependency on the Socket domain can keep using it.

## Installing without reaching github.com

By default the script downloads archives from the GitHub release. Point it
somewhere else with `SOCKET_PATCH_BASE_URL` — a releases base that answers
GitHub's two asset paths, `<base>/latest/download/<file>` and
`<base>/download/v<ver>/<file>`:

```sh
curl -fsSL https://install.socket.dev/patch \
  | SOCKET_PATCH_BASE_URL=https://install.socket.dev/patch/SocketDev/socket-patch/releases sh
```

`install.socket.dev` relays those exact paths from the GitHub release, which is
why one template covers both origins and the script needs no branching. It also
exposes a cleaner shape for humans and for scripts that want the version:

| Endpoint | Serves |
|---|---|
| `install.socket.dev/patch/latest` | the latest version as plain text (`3.4.0`) |
| `install.socket.dev/patch/dl/v3.4.0/<asset>` | that release's asset, immutably cached |
| `install.socket.dev/patch/dl/latest/<asset>` | the same asset from whatever is latest |

**A new release needs no publish for any of this.** "Latest" is resolved per
request against the upstream release, so cutting 3.4.0 makes it installable from
`install.socket.dev` immediately — nothing runs at release time.

`socket-patch --update` can use the same host today, with no changes to the CLI,
via the endpoint override it already has:

```sh
SOCKET_UPDATE_BASE_URL=https://install.socket.dev/patch socket-patch --update
```

One caveat worth knowing before standardizing on that: a non-default
`SOCKET_UPDATE_BASE_URL` intentionally downgrades the downloaded binary's
version self-check from hard-fail to a warning, because the override is meant
for mirrors that may repackage. Making Socket's host a first-class endpoint set
that keeps the strict check is a CLI change, not a hosting one.

## What the trust model actually is

Unchanged by the hosting move, and worth being precise about:

- **The script** is fetched over HTTPS from a Socket-controlled host. Its SHA-256
  is published alongside it at `install.socket.dev/patch.sha256`, and it can be
  diffed against `scripts/install.sh` in this repo.
- **The binary** is fetched from the GitHub release and verified against that
  release's `SHA256SUMS` before it is unpacked. Neither the script nor the
  checksums are signed — this is checksum integrity rooted in HTTPS plus GitHub,
  the same model `--update` and the gem/composer launchers use (see
  [CLI_CONTRACT.md](../crates/socket-patch-cli/CLI_CONTRACT.md)).
- Nothing in the install path sends a Socket API token anywhere.

Hosting the script on a Socket domain moves *who serves the script*. It does not
add a signature, and the docs should not imply that it does.

## How a change to the installer reaches the domain

The publish path lives in [depscan][depscan], which vendors this repository as
`submodules/socket-patch`:

1. A change to `scripts/install.sh` merges **here**.
2. depscan's `submodules/socket-patch` pin is bumped to that commit.
3. depscan's prod deploy runs its **Publish install.socket.dev site** step,
   which copies `submodules/socket-patch/scripts/install.sh` to
   `gs://socket-install-prod/patch`, publishes its sha256 and the landing page,
   then re-reads the object and fails the deploy if the bytes do not match.
4. `install-server` (a `gcs-bucket-server` instance, `tanka/lib/depscan/install-server.libsonnet`)
   serves that bucket at `install.socket.dev`.

So an installer change needs a depscan submodule bump plus a deploy. That
indirection is deliberate: this repository is public and needs no write
credentials into a Socket bucket, and a submodule bump is a reviewed change, so
nothing reaches a `curl | sh` endpoint without review on the depscan side too.

**A new socket-patch release needs none of this.** The script resolves the latest
release itself at run time (`/releases/latest/download`), so cutting 3.4.0
changes what the hosted installer *installs* without changing the hosted
installer. Only edits to the script itself require a publish.

## The drift check

`.github/workflows/installer-drift.yml` (weekly, plus `workflow_dispatch`)
fetches `install.socket.dev/patch` and diffs it against `scripts/install.sh` on
`main`.

- **Different** → the job fails. The fix is a depscan submodule bump + deploy
  (steps 2–3 above). Expect this to be red in the window between merging an
  installer change here and bumping the pin there.
- **Host does not resolve** → the job reports "not deployed yet" and passes, so
  the check is inert until the domain exists.

The check also runs `shellcheck` and `sh -n` against the *fetched* copy, so a
mangled publish is caught even when the hash somehow matches expectations.

## Known gaps

- **No Windows installer.** The script is POSIX `sh`; native Windows users go
  through a package manager or a release archive. A `patch.ps1` object on the
  same host would be the natural addition — the hosting side already supports
  it, nothing here does yet.
- **Objects must stay flat** — for the *bucket-backed* paths only (`patch`,
  `patch.sha256`, `index.html`). `gcs-bucket-server` interpolates the object name
  into the GCS JSON API URL unencoded, so only bucket-root keys resolve. This
  does not affect `/patch/dl/**`, which is relayed by a separate service and
  never touches the bucket.
- **The default download origin is still GitHub.** The `SOCKET_PATCH_BASE_URL`
  mechanism ships first; flipping the default to `install.socket.dev` is a
  one-line change, deliberately held until the relay is verified in prod. A
  script that defaults to a host which does not answer yet is a broken installer
  for everyone running it from a git checkout or the raw GitHub URL.

[depscan]: https://github.com/SocketDev/depscan
