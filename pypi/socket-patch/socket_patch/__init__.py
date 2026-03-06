import os
import sys
import subprocess


def main():
    bin_dir = os.path.join(os.path.dirname(__file__), "bin")
    try:
        entries = os.listdir(bin_dir)
    except OSError:
        entries = []
    bins = [e for e in entries if e.startswith("socket-patch")]
    if len(bins) != 1:
        print(
            f"Expected exactly one socket-patch binary in {bin_dir}, found {len(bins)}",
            file=sys.stderr,
        )
        sys.exit(1)
    bin_path = os.path.join(bin_dir, bins[0])
    if not os.access(bin_path, os.X_OK):
        os.chmod(bin_path, os.stat(bin_path).st_mode | 0o111)
    raise SystemExit(subprocess.call([bin_path] + sys.argv[1:]))
