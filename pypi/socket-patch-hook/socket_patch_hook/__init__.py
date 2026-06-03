"""socket-patch post-install hook (package-manager-agnostic).

This module is imported at Python interpreter startup by a wheel-shipped
``socket_patch_hook.pth`` file (the same ``.pth`` ``import``-line mechanism
coverage.py uses). When the set of installed distributions has changed since the
last run -- e.g. ``pip install`` / ``--force-reinstall`` / ``uv sync`` reverted a
file that Socket had patched -- it re-applies the project's committed patches by
invoking the hardened ``socket-patch apply`` binary in offline mode. All actual
patching (hash verification, atomic writes, locking) stays in that binary; this
module only *triggers* it.

Hard safety contract:
  * ``run()`` must NEVER raise into ``site.py`` (a raise here would hit every
    interpreter start in the environment). Every step is failure-swallowing.
  * The common, no-change path must cost only a few syscalls (it does: a bounded
    parent walk, one ``scandir`` of site-packages, and one small file read).
  * The worst outcome of any bug here is that patches are simply not re-applied.

Disable entirely with ``SOCKET_PATCH_HOOK=off`` (also checked in the ``.pth``
line before this module is even imported) or ``SOCKET_NO_HOOK=1``.
"""

import os
import sys

__all__ = ["run"]

# Set in the environment of the spawned ``apply`` process so a nested
# interpreter started underneath it does not re-trigger the hook. (The apply
# binary itself is native Rust, but it -- or a tool it shells out to -- may
# invoke ``python``, which would re-process the ``.pth``.)
_REENTRANCY_ENV = "_SOCKET_PATCH_HOOK_ACTIVE"

# Upper bound on the parent-directory walk used to locate the project root.
_MAX_PARENTS = 40

# Generous safety net for a single hook-triggered apply. The apply is offline
# and local, so this only ever fires if something is badly wrong; it exists so a
# hung apply can never wedge interpreter startup forever.
_APPLY_TIMEOUT_SECONDS = 120


def _truthy(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _disabled():
    """True if the user has switched the hook off via env var."""
    if _truthy(os.environ.get("SOCKET_NO_HOOK")):
        return True
    return os.environ.get("SOCKET_PATCH_HOOK", "").strip().lower() in (
        "off",
        "0",
        "false",
        "no",
    )


def _site_packages_dir():
    # __file__ == <site-packages>/socket_patch_hook/__init__.py
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_project_root():
    """Locate the project whose committed ``.socket/manifest.json`` this
    environment opted into. Returns ``None`` (hook no-ops) if none is found.

    SECURITY — which manifest do we trust? When running inside a virtualenv we
    anchor the search to the **venv** (``sys.prefix``), NOT the current working
    directory: the committed ``socket-patch[hook]`` dependency installed this
    hook into THIS venv, so the owning project is an ancestor of the venv (e.g.
    ``<project>/.venv``). Anchoring to the venv ties the patches we apply to the
    project that opted in, instead of whatever ``.socket/`` happens to sit above
    the cwd — which could belong to an unrelated or hostile parent/sibling
    project (a `python` started from elsewhere must not pull in a foreign
    manifest). Only when there is no venv (a system / container interpreter,
    where there is nothing to anchor to) do we fall back to the cwd.
    """
    in_venv = getattr(sys, "prefix", "") != getattr(sys, "base_prefix", getattr(sys, "prefix", ""))
    anchors = []
    if in_venv:
        anchors.append(sys.prefix)
        env_venv = os.environ.get("VIRTUAL_ENV")
        if env_venv:
            anchors.append(env_venv)
    else:
        try:
            anchors.append(os.getcwd())
        except OSError:
            pass

    seen = set()
    for start in anchors:
        try:
            d = os.path.abspath(start)
        except OSError:
            continue
        for _ in range(_MAX_PARENTS):
            if d in seen:
                break
            seen.add(d)
            if os.path.isfile(os.path.join(d, ".socket", "manifest.json")):
                return d
            parent = os.path.dirname(d)
            if parent == d:  # reached the filesystem root
                break
            d = parent
    return None


def _fingerprint(site_dir):
    """Cheap signature of the installed distributions in ``site_dir``.

    A SHA-1 of the sorted ``(name, mtime)`` of every ``*.dist-info`` /
    ``*.egg-info`` entry. This changes on any install / reinstall / uninstall,
    but is deliberately immune to:
      * our own patch writes (which touch package *files*, not the metadata
        dirs), so the fingerprint is stable across an apply -- no re-apply loop;
      * the stamp file (kept in a user cache, outside site-packages);
      * ``__pycache__`` / ``.pyc`` churn.
    Returns ``"?"`` on error so we fail toward a (harmless, idempotent) re-apply.
    """
    import hashlib

    try:
        items = []
        with os.scandir(site_dir) as it:
            for entry in it:
                name = entry.name
                if name.endswith(".dist-info") or name.endswith(".egg-info"):
                    try:
                        mtime = entry.stat().st_mtime_ns
                    except OSError:
                        mtime = 0
                    items.append("%s:%d" % (name, mtime))
        items.sort()
        return hashlib.sha1(
            "\n".join(items).encode("utf-8", "replace")
        ).hexdigest()
    except OSError:
        return "?"


def _cache_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
    return os.path.join(base, "socket-patch", "hook-stamps")


def _stamp_path(site_dir):
    """Per-site-packages stamp file, in a user cache so writing it never
    perturbs the site-packages fingerprint and never dirties the repo."""
    import hashlib

    key = hashlib.sha1(
        os.path.abspath(site_dir).encode("utf-8", "replace")
    ).hexdigest()
    return os.path.join(_cache_dir(), key)


def _read_stamp(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def _write_stamp(path, value):
    tmp = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = "%s.%d.tmp" % (path, os.getpid())
        with open(tmp, "w") as f:
            f.write(value)
        os.replace(tmp, path)
    except OSError:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _resolve_binary():
    """Locate the ``socket-patch`` binary to run.

    SECURITY — order matters. We prefer the binary **bundled in the installed
    ``socket_patch`` package** (the one `socket-patch[hook]` pulls in: a
    RECORD-tracked file resolved by the dependency solver) and only fall back to
    ``PATH`` if that package isn't present. Resolving via ``PATH`` first would
    let a malicious ``socket-patch`` placed earlier on ``PATH`` (or `.` on PATH)
    be executed at every interpreter startup. Returns ``None`` if neither is
    found, in which case the hook no-ops.
    """
    try:
        import socket_patch

        resolver = getattr(socket_patch, "_resolve_binary", None)
        if resolver is not None:
            path = resolver()
            if path:
                return path
    except Exception:
        pass
    try:
        import shutil

        return shutil.which("socket-patch")
    except Exception:
        return None


def _apply(binary, project_root):
    """Run ``socket-patch apply`` synchronously, offline, best-effort.

    Synchronous so the patched bytes are in place before the interpreter
    proceeds to user imports. Offline so it only ever re-heals from the
    committed ``.socket/`` cache and never blocks startup on the network.
    ``--lock-timeout 0`` so a parallel interpreter that loses the apply lock
    (e.g. under ``pytest -n``) skips instantly instead of piling up.

    Returns ``True`` only if apply exited 0. A non-zero exit (e.g. losing the
    apply lock to a sibling interpreter) returns ``False`` so the caller does
    NOT stamp the state as handled and the heal is retried on the next start.
    """
    import subprocess

    argv = [
        binary,
        "apply",
        "--offline",
        "--silent",
        "--ecosystems",
        "pypi",
        "--cwd",
        project_root,
        "--lock-timeout",
        "0",
    ]
    env = dict(os.environ)
    env[_REENTRANCY_ENV] = "1"
    kwargs = {
        "cwd": project_root,
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "timeout": _APPLY_TIMEOUT_SECONDS,
    }
    # Don't flash a console window for a pythonw-hosted (no-console) app.
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(argv, **kwargs).returncode == 0
    except Exception:
        # Includes TimeoutExpired and OSError (binary vanished mid-run).
        return False


def run():
    """Entry point invoked by the ``.pth`` line. Never raises."""
    try:
        # Cheapest possible bail-outs first.
        if os.environ.get(_REENTRANCY_ENV):
            return
        if _disabled():
            return
        project_root = _find_project_root()
        if project_root is None:
            return
        site_dir = _site_packages_dir()
        fp = _fingerprint(site_dir)
        stamp_path = _stamp_path(site_dir)
        if _read_stamp(stamp_path) == fp:
            return  # nothing installed/reinstalled since the last apply
        binary = _resolve_binary()
        if not binary:
            return
        # Stamp only on a successful apply. The dist-info fingerprint is
        # unchanged by an apply (which patches package files, not metadata
        # dirs), so storing the pre-apply value is correct -- and gating on
        # success means a lock-contended / failed apply is retried next start
        # rather than being silently marked as handled.
        if _apply(binary, project_root):
            _write_stamp(stamp_path, fp)
    except Exception:
        # Final backstop. The .pth wrapper also guards, but a raise here would
        # hit every interpreter start, so never rely on a single layer.
        return
