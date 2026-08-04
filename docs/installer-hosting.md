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
- **Objects must stay flat.** `gcs-bucket-server` interpolates the object name
  into the GCS JSON API URL unencoded, so only bucket-root keys resolve
  (`patch`, `patch.sha256`, `index.html`). A nested path like
  `/patch/3.3.0/install.sh` would 404 until that is fixed on the depscan side.

[depscan]: https://github.com/SocketDev/depscan
