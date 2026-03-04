#!/usr/bin/env python3
"""Build platform-tagged PyPI wheels for socket-patch.

Each wheel contains only the binary for a single platform, so users download
only the ~4 MB they need instead of ~40 MB for all platforms.
"""

import argparse
import csv
import hashlib
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from base64 import urlsafe_b64encode
from pathlib import Path

# Mapping from Rust target triple to:
#   (wheel platform tag(s), archive extension, binary name inside archive)
# Android is omitted — no standard PyPI platform tag exists for it.
TARGETS = {
    "aarch64-apple-darwin": {
        "platform_tag": "macosx_11_0_arm64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "x86_64-apple-darwin": {
        "platform_tag": "macosx_10_12_x86_64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "x86_64-unknown-linux-musl": {
        "platform_tag": "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "aarch64-unknown-linux-gnu": {
        "platform_tag": "manylinux_2_17_aarch64.manylinux2014_aarch64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "arm-unknown-linux-gnueabihf": {
        "platform_tag": "manylinux_2_17_armv7l.manylinux2014_armv7l",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "i686-unknown-linux-gnu": {
        "platform_tag": "manylinux_2_17_i686.manylinux2014_i686",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "x86_64-pc-windows-msvc": {
        "platform_tag": "win_amd64",
        "archive_ext": "zip",
        "binary_name": "socket-patch.exe",
    },
    "i686-pc-windows-msvc": {
        "platform_tag": "win32",
        "archive_ext": "zip",
        "binary_name": "socket-patch.exe",
    },
    "aarch64-pc-windows-msvc": {
        "platform_tag": "win_arm64",
        "archive_ext": "zip",
        "binary_name": "socket-patch.exe",
    },
}

DIST_NAME = "socket_patch"
PKG_NAME = "socket-patch"


def sha256_digest(data: bytes) -> str:
    """Return the URL-safe base64 SHA-256 digest for RECORD."""
    h = hashlib.sha256(data)
    return "sha256=" + urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")


def extract_binary(artifacts_dir: Path, target: str, info: dict) -> bytes:
    """Extract the binary from the artifact archive and return its contents."""
    ext = info["archive_ext"]
    archive_path = artifacts_dir / f"socket-patch-{target}.{ext}"
    if not archive_path.exists():
        raise FileNotFoundError(f"Artifact not found: {archive_path}")

    binary_name = info["binary_name"]
    if ext == "tar.gz":
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tf:
            member = tf.getmember(binary_name)
            f = tf.extractfile(member)
            if f is None:
                raise ValueError(f"Could not extract {binary_name} from {archive_path}")
            return f.read()
    elif ext == "zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            return zf.read(binary_name)
    else:
        raise ValueError(f"Unknown archive extension: {ext}")


def read_pyproject_metadata(pyproject_dir: Path) -> dict:
    """Read metadata fields from pyproject.toml (simple parser, no toml dep)."""
    pyproject_path = pyproject_dir / "pyproject.toml"
    text = pyproject_path.read_text()

    def extract_field(name: str) -> str:
        m = re.search(rf'^{name}\s*=\s*"(.*?)"', text, re.MULTILINE)
        if not m:
            raise ValueError(f"Could not find {name} in {pyproject_path}")
        return m.group(1)

    return {
        "name": extract_field("name"),
        "version": extract_field("version"),
        "description": extract_field("description"),
        "license": extract_field("license"),
        "requires_python": extract_field("requires-python"),
    }


def read_init_py(pyproject_dir: Path) -> bytes:
    """Read the __init__.py file for inclusion in wheels."""
    init_path = pyproject_dir / "socket_patch" / "__init__.py"
    return init_path.read_bytes()


def build_wheel(
    target: str,
    info: dict,
    version: str,
    metadata: dict,
    init_py: bytes,
    binary_data: bytes,
    dist_dir: Path,
) -> Path:
    """Build a single platform-tagged wheel and return the path."""
    platform_tag = info["platform_tag"]
    binary_name = info["binary_name"]

    # Wheel filename: {name}-{version}-{python tag}-{abi tag}-{platform tag}.whl
    wheel_name = f"{DIST_NAME}-{version}-py3-none-{platform_tag}.whl"
    wheel_path = dist_dir / wheel_name

    dist_info = f"{DIST_NAME}-{version}.dist-info"

    # Build file entries: (archive_name, data, is_executable)
    files = []

    # __init__.py
    files.append((f"{DIST_NAME}/__init__.py", init_py, False))

    # Binary
    files.append((f"{DIST_NAME}/bin/{binary_name}", binary_data, True))

    # METADATA
    metadata_content = (
        f"Metadata-Version: 2.1\n"
        f"Name: {metadata['name']}\n"
        f"Version: {version}\n"
        f"Summary: {metadata['description']}\n"
        f"License: {metadata['license']}\n"
        f"Requires-Python: {metadata['requires_python']}\n"
    ).encode()
    files.append((f"{dist_info}/METADATA", metadata_content, False))

    # WHEEL
    wheel_content = (
        f"Wheel-Version: 1.0\n"
        f"Generator: build-pypi-wheels.py\n"
        f"Root-Is-Purelib: false\n"
        f"Tag: py3-none-{platform_tag}\n"
    ).encode()
    files.append((f"{dist_info}/WHEEL", wheel_content, False))

    # entry_points.txt
    entry_points_content = (
        "[console_scripts]\n" "socket-patch = socket_patch:main\n"
    ).encode()
    files.append((f"{dist_info}/entry_points.txt", entry_points_content, False))

    # Build RECORD (must be last, references all other files)
    record_lines = []
    for name, data, _ in files:
        record_lines.append(f"{name},{sha256_digest(data)},{len(data)}")
    # RECORD itself has no hash
    record_name = f"{dist_info}/RECORD"
    record_lines.append(f"{record_name},,")
    record_content = "\n".join(record_lines).encode()
    files.append((record_name, record_content, False))

    # Write the zip
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, is_exec in files:
            info_obj = zipfile.ZipInfo(name)
            # Set external_attr for executable files (unix permissions)
            if is_exec:
                info_obj.external_attr = (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
            else:
                info_obj.external_attr = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) << 16
            info_obj.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info_obj, data)

    return wheel_path


def main():
    parser = argparse.ArgumentParser(
        description="Build platform-tagged PyPI wheels for socket-patch"
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Package version (e.g., 1.5.0)",
    )
    parser.add_argument(
        "--artifacts",
        required=True,
        help="Directory containing build artifacts",
    )
    parser.add_argument(
        "--dist",
        default="dist",
        help="Output directory for wheels (default: dist)",
    )
    parser.add_argument(
        "--pyproject-dir",
        default=None,
        help="Directory containing pyproject.toml (default: pypi/socket-patch relative to script)",
    )
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts)
    dist_dir = Path(args.dist)
    dist_dir.mkdir(parents=True, exist_ok=True)

    if args.pyproject_dir:
        pyproject_dir = Path(args.pyproject_dir)
    else:
        pyproject_dir = Path(__file__).resolve().parent.parent / "pypi" / "socket-patch"

    metadata = read_pyproject_metadata(pyproject_dir)
    init_py = read_init_py(pyproject_dir)

    built = []
    skipped = []

    for target, info in TARGETS.items():
        archive_ext = info["archive_ext"]
        archive_path = artifacts_dir / f"socket-patch-{target}.{archive_ext}"
        if not archive_path.exists():
            skipped.append(target)
            continue

        print(f"Building wheel for {target} ({info['platform_tag']})...")
        binary_data = extract_binary(artifacts_dir, target, info)
        wheel_path = build_wheel(
            target=target,
            info=info,
            version=args.version,
            metadata=metadata,
            init_py=init_py,
            binary_data=binary_data,
            dist_dir=dist_dir,
        )
        size_mb = wheel_path.stat().st_size / (1024 * 1024)
        print(f"  -> {wheel_path.name} ({size_mb:.1f} MB)")
        built.append(wheel_path)

    print(f"\nBuilt {len(built)} wheel(s) in {dist_dir}/")
    if skipped:
        print(f"Skipped {len(skipped)} target(s) (artifact not found): {', '.join(skipped)}")

    if not built:
        print("ERROR: No wheels were built!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
