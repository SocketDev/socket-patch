# socket-patch-hook

A tiny, package-manager-agnostic **post-install hook** for
[`socket-patch`](https://pypi.org/project/socket-patch/).

Python package managers (pip, uv, poetry, pdm, hatch) have no universal
post-install step, so a `pip install` / `--force-reinstall` can silently revert
files that `socket-patch` previously patched. This package closes that gap.

## How it works

Installing this wheel lays down a startup `.pth` file in `site-packages`
(RECORD-tracked, so `pip uninstall` removes it cleanly). At interpreter startup
the hook does a microsecond-cheap check of whether the set of installed
distributions changed since the last run; only then does it re-apply your
project's **committed** patches by invoking `socket-patch apply --offline`. All
real patching (hash verification, atomic writes, locking) is done by the
`socket-patch` binary — this package only *triggers* it.

Because it rides on Python's interpreter-startup `.pth` mechanism (not on any
one installer's hooks), it works the same under every Python package manager.

## Activating it

Don't add this by hand. Run, in your project:

```
socket-patch setup
```

That commits a `socket-patch[hook]` dependency to your repo — the `[hook]`
extra on the main `socket-patch` package, which pulls in both the CLI and this
wheel (you never reference `socket-patch-hook` directly). The committed
dependency is the source of truth — there's no separate marker file. The hook
then activates automatically in CI after install. Remove it with `socket-patch
setup --remove` followed by `pip uninstall socket-patch-hook`. (Classic Poetry
can't express an extra as a bare key, so there `setup` writes the equivalent
`socket-patch = { extras = ["hook"] }`.)

## Disabling at runtime

Set `SOCKET_PATCH_HOOK=off` (or `SOCKET_NO_HOOK=1`) to fully bypass the hook for
a given interpreter — checked before any hook code runs.
