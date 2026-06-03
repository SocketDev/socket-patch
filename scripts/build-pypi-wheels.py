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
    "x86_64-unknown-linux-gnu": {
        "platform_tag": "manylinux_2_17_x86_64.manylinux2014_x86_64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "x86_64-unknown-linux-musl": {
        "platform_tag": "musllinux_1_1_x86_64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "aarch64-unknown-linux-gnu": {
        "platform_tag": "manylinux_2_17_aarch64.manylinux2014_aarch64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "aarch64-unknown-linux-musl": {
        "platform_tag": "musllinux_1_1_aarch64",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "arm-unknown-linux-gnueabihf": {
        "platform_tag": "manylinux_2_17_armv7l.manylinux2014_armv7l",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "arm-unknown-linux-musleabihf": {
        "platform_tag": "musllinux_1_1_armv7l",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "i686-unknown-linux-gnu": {
        "platform_tag": "manylinux_2_17_i686.manylinux2014_i686",
        "archive_ext": "tar.gz",
        "binary_name": "socket-patch",
    },
    "i686-unknown-linux-musl": {
        "platform_tag": "musllinux_1_1_i686",
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

    readme_path = pyproject_dir / "README.md"
    readme = readme_path.read_text() if readme_path.exists() else ""

    return {
        "name": extract_field("name"),
        "version": extract_field("version"),
        "description": extract_field("description"),
        "license": extract_field("license"),
        "requires_python": extract_field("requires-python"),
        "readme": readme,
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
    metadata_header = (
        f"Metadata-Version: 2.1\n"
        f"Name: {metadata['name']}\n"
        f"Version: {version}\n"
        f"Summary: {metadata['description']}\n"
        f"License: {metadata['license']}\n"
        f"Requires-Python: {metadata['requires_python']}\n"
        # `pip install socket-patch[hook]` additionally installs the
        # package-manager-agnostic .pth post-install hook (a separate
        # pure-python wheel). Unpinned so the hook can update independently.
        f"Provides-Extra: hook\n"
        f'Requires-Dist: socket-patch-hook; extra == "hook"\n'
    )
    if metadata.get("readme"):
        metadata_header += "Description-Content-Type: text/markdown\n"
        metadata_header += f"\n{metadata['readme']}"
    metadata_content = metadata_header.encode()
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


DIST_NAME_HOOK = "socket_patch_hook"
PKG_NAME_HOOK = "socket-patch-hook"


def build_hook_wheel(version: str, hook_dir: Path, dist_dir: Path) -> Path:
    """Build the pure-python ``socket-patch-hook`` wheel (``py3-none-any``).

    Unlike the platform wheels, this ships no binary. It contains the
    ``socket_patch_hook`` package and — crucially — a top-level
    ``socket_patch_hook.pth`` that pip installs into the site-packages root, so
    Python executes it at interpreter startup. It depends on ``socket-patch``
    (the binary wheel) for the actual ``apply``.
    """
    init_path = hook_dir / "socket_patch_hook" / "__init__.py"
    pth_path = hook_dir / "socket_patch_hook.pth"
    readme_path = hook_dir / "README.md"
    init_py = init_path.read_bytes()
    pth = pth_path.read_bytes()
    readme = readme_path.read_text() if readme_path.exists() else ""

    wheel_name = f"{DIST_NAME_HOOK}-{version}-py3-none-any.whl"
    wheel_path = dist_dir / wheel_name
    dist_info = f"{DIST_NAME_HOOK}-{version}.dist-info"

    files = []
    # The package module.
    files.append((f"{DIST_NAME_HOOK}/__init__.py", init_py, False))
    # The startup hook — at the wheel root so it installs to site-packages.
    files.append(("socket_patch_hook.pth", pth, False))

    # No Requires-Dist on socket-patch: the hook is version-agnostic and finds
    # whatever `socket-patch` CLI is on PATH at runtime (provisioned separately).
    metadata_content = (
        f"Metadata-Version: 2.1\n"
        f"Name: {PKG_NAME_HOOK}\n"
        f"Version: {version}\n"
        f"Summary: Package-manager-agnostic post-install patch hook for socket-patch\n"
        f"License: MIT\n"
        f"Requires-Python: >=3.8\n"
    )
    if readme:
        metadata_content += "Description-Content-Type: text/markdown\n"
        metadata_content += f"\n{readme}"
    files.append((f"{dist_info}/METADATA", metadata_content.encode(), False))

    # Pure-python: Root-Is-Purelib true so the .pth lands in site-packages.
    wheel_content = (
        "Wheel-Version: 1.0\n"
        "Generator: build-pypi-wheels.py\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode()
    files.append((f"{dist_info}/WHEEL", wheel_content, False))

    record_lines = []
    for name, data, _ in files:
        record_lines.append(f"{name},{sha256_digest(data)},{len(data)}")
    record_name = f"{dist_info}/RECORD"
    record_lines.append(f"{record_name},,")
    files.append((record_name, "\n".join(record_lines).encode(), False))

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, _ in files:
            info_obj = zipfile.ZipInfo(name)
            info_obj.external_attr = (
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            ) << 16
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
        default=None,
        help="Directory containing build artifacts (required unless --hook-only)",
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
    parser.add_argument(
        "--hook-dir",
        default=None,
        help="Directory of the socket-patch-hook package (default: pypi/socket-patch-hook)",
    )
    parser.add_argument(
        "--hook-only",
        action="store_true",
        help="Build only the pure-python socket-patch-hook wheel (no binary artifacts needed)",
    )
    parser.add_argument(
        "--skip-hook",
        action="store_true",
        help="Skip building the socket-patch-hook wheel",
    )
    args = parser.parse_args()

    dist_dir = Path(args.dist)
    dist_dir.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parent.parent
    hook_dir = Path(args.hook_dir) if args.hook_dir else repo_root / "pypi" / "socket-patch-hook"

    built = []
    skipped = []

    # The pure-python hook wheel needs no platform artifacts.
    if args.hook_only:
        wheel_path = build_hook_wheel(args.version, hook_dir, dist_dir)
        size_kb = wheel_path.stat().st_size / 1024
        print(f"Built hook wheel: {wheel_path.name} ({size_kb:.1f} KB)")
        return

    if not args.artifacts:
        parser.error("--artifacts is required unless --hook-only is given")

    artifacts_dir = Path(args.artifacts)

    if args.pyproject_dir:
        pyproject_dir = Path(args.pyproject_dir)
    else:
        pyproject_dir = repo_root / "pypi" / "socket-patch"

    metadata = read_pyproject_metadata(pyproject_dir)
    init_py = read_init_py(pyproject_dir)

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

    if not args.skip_hook:
        hook_wheel = build_hook_wheel(args.version, hook_dir, dist_dir)
        size_kb = hook_wheel.stat().st_size / 1024
        print(f"  -> {hook_wheel.name} ({size_kb:.1f} KB)  [pure-python hook]")
        built.append(hook_wheel)

    print(f"\nBuilt {len(built)} wheel(s) in {dist_dir}/")
    if skipped:
        print(f"Skipped {len(skipped)} target(s) (artifact not found): {', '.join(skipped)}")

    if not built:
        print("ERROR: No wheels were built!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
