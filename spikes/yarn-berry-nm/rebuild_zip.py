#!/usr/bin/env python3
"""Rebuild a yarn berry 4.x (cacheKey 10c0, compressionLevel 0) cache zip
from an npm-style tarball, byte-identically. Offline; stdlib only.

Usage: rebuild_zip.py <tarball.tgz> <package-name> <out.zip>

Recipe (empirically derived from yarn 4.12.0 cache zips, libzip-wasm output):
- Entry order   : tar order. Parent dirs are emitted on first need (mkdirp),
                  i.e. `node_modules/` + `node_modules/<name>/` appear before
                  the first entry that needs them; deeper dirs appear at the
                  tar position that first references them.
- Name mapping  : strip the first path component of each tar entry (npm uses
                  `package/`), prefix with `node_modules/<name>/`.
- Compression   : 0 (stored) for every entry  -> cacheKey suffix `c0`.
- mtime         : DOS time of 1984-06-22 21:50:00 (yarn SAFE_TIME=456789000),
                  written as UTC -> dosdate=0x08D6 dostime=0xAE40.
- Flags         : 0x0000 (no data descriptor, no UTF-8 flag for ASCII names).
- Local header  : version-needed = 10 for files, 20 for directories;
                  no extra field, sizes+crc inline (crc=0/sizes=0 for dirs).
- Central dir   : version-made-by = 0x033F (UNIX, spec 6.3 -> (3<<8)|63);
                  internal attrs = 0; external attrs = (unix mode) << 16,
                  files NORMALIZED to 0o100644, or 0o100755 if tar mode has
                  any exec bit (yarn discards other perm bits); dirs always
                  0o40755 regardless of tar mode;
                  no extra field, no comment.
- EOCD          : single disk, no zip64, no archive comment.
"""
import sys, tarfile, struct

DOSTIME = 0xAE40  # 21:50:00
DOSDATE = 0x08D6  # 1984-06-22

def rebuild(tgz_path, pkg_name, out_path):
    prefix = f"node_modules/{pkg_name}"
    entries = []          # (name, is_dir, mode, data)
    seen_dirs = set()

    def mkdirp(dirpath):  # dirpath WITHOUT trailing slash
        parts = dirpath.split('/')
        for i in range(1, len(parts) + 1):
            d = '/'.join(parts[:i]) + '/'
            if d not in seen_dirs:
                seen_dirs.add(d)
                entries.append((d, True, 0o40755, b''))

    with tarfile.open(tgz_path, 'r:gz') as tf:
        for m in tf:
            stripped = '/'.join(m.name.split('/')[1:]).rstrip('/')
            if m.isdir():
                mkdirp(prefix + ('/' + stripped if stripped else ''))
            elif m.isfile():
                target = f"{prefix}/{stripped}"
                mkdirp(target.rsplit('/', 1)[0])
                data = tf.extractfile(m).read()
                mode = 0o100755 if (m.mode & 0o111) else 0o100644
                entries.append((target, False, mode, data))

    import zlib
    blob = bytearray(); central = bytearray(); offsets = []
    for name, is_dir, mode, data in entries:
        offsets.append(len(blob))
        crc = 0 if is_dir else zlib.crc32(data) & 0xFFFFFFFF
        vneed = 20 if is_dir else 10
        nb = name.encode()
        blob += struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', vneed, 0, 0,
                            DOSTIME, DOSDATE, crc, len(data), len(data),
                            len(nb), 0) + nb + data
    for (name, is_dir, mode, data), lho in zip(entries, offsets):
        crc = 0 if is_dir else zlib.crc32(data) & 0xFFFFFFFF
        vneed = 20 if is_dir else 10
        nb = name.encode()
        central += struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', 0x033F,
                               vneed, 0, 0, DOSTIME, DOSDATE, crc, len(data),
                               len(data), len(nb), 0, 0, 0, 0, mode << 16,
                               lho) + nb
    eocd = struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, len(entries),
                       len(entries), len(central), len(blob), 0)
    with open(out_path, 'wb') as f:
        f.write(blob + central + eocd)

if __name__ == '__main__':
    rebuild(sys.argv[1], sys.argv[2], sys.argv[3])
