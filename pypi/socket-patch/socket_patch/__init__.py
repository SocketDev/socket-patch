import os
import sys
import subprocess


def _resolve_binary():
    """Locate the bundled socket-patch binary, or return ``None``.

    Single source of truth for binary discovery, reused by both ``main()`` (the
    console-script entry point) and the ``socket_patch_hook`` startup hook. Never
    raises: returns ``None`` if the binary can't be found, so callers that run at
    interpreter startup stay safe.
    """
    bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
    try:
        entries = os.listdir(bin_dir)
    except OSError:
        return None
    bins = [e for e in entries if e.startswith("socket-patch")]
    if len(bins) != 1:
        return None
    bin_path = os.path.join(bin_dir, bins[0])
    try:
        if not os.access(bin_path, os.X_OK):
            os.chmod(bin_path, os.stat(bin_path).st_mode | 0o111)
    except OSError:
        return None
    return bin_path


def main():
    bin_path = _resolve_binary()
    if bin_path is None:
        bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
        try:
            count = len([e for e in os.listdir(bin_dir) if e.startswith("socket-patch")])
        except OSError:
            count = 0
        print(
            f"Expected exactly one socket-patch binary in {bin_dir}, found {count}",
            file=sys.stderr,
        )
        sys.exit(1)
    raise SystemExit(subprocess.call([bin_path] + sys.argv[1:]))
