import os
import sys
import subprocess
import platform

BINARIES = {
    ("darwin", "arm64"): "socket-patch-darwin-arm64",
    ("darwin", "x86_64"): "socket-patch-darwin-x64",
    ("linux", "x86_64"): "socket-patch-linux-x64",
    ("linux", "aarch64"): "socket-patch-linux-arm64",
    ("win32", "amd64"): "socket-patch-win32-x64.exe",
}


def main():
    machine = platform.machine().lower()
    key = (sys.platform, machine)
    bin_name = BINARIES.get(key)
    if not bin_name:
        print(f"Unsupported platform: {sys.platform} {machine}", file=sys.stderr)
        sys.exit(1)
    bin_path = os.path.join(os.path.dirname(__file__), "bin", bin_name)
    raise SystemExit(subprocess.call([bin_path] + sys.argv[1:]))
