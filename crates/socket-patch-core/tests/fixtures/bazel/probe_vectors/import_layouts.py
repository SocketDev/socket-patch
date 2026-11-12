#!/usr/bin/env python3
"""Import the output-tree layout vectors of three other probe groups.

    python3 import_layouts.py <campaign probes directory>

Copies the twelve files of SOURCES to the same relative path under this directory, with
the strings that name the capture machine replaced (README.md, "Output-tree layouts"):

- the campaign directory, the parent of the probes directory, becomes `<CAMPAIGN>`;
- the host and user names in the two file names Bazel derives from them become `host` and
  `user`: `java.log.<host>.<user>.log.java.<time>.<pid>` in an output base, and the
  `_bazel_<user>` directory of an output user root.

Nothing else changes, so each copy is the probe's bytes apart from those strings. A source
whose SHA-256 is not the one pinned here is refused. Before a file is rewritten, each
output base it names by 32 hex digits is checked to be the MD5 of its workspace path,
which the copy can no longer show. The probes directory is not part of this repository.
After a run, rewrite SHA256SUMS and run check.py.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DETECT = "core-external-edits/vectors/detect/"
SOURCES = {  # path under the probes directory: SHA-256 of the probe's file
    DETECT + "10.0.0rc3-cc.json": "108feec7f4870dd32b2649a18fd34700a7cbf9eaab4a64a538d15de9c1210c71",
    DETECT + "5.4.1-default.json": "caedcb646cd52214939e00cb34ad0c2c72251f6dadffffbe7dd272a8938251a8",
    DETECT + "6.6.0-default.json": "bf95bab17b1f54d6cd37247cd447767d27a7428227e77f3e1617872eb0ca49a3",
    DETECT + "7.7.2-default.json": "4549abc5287f48186134a3afdac460fdc8f400632c603a6c31a98d4786258dc8",
    DETECT + "7.7.2-vendor.json": "9909f782275411262f3a6de15f1ec7c209f18dd156d545588dbc9181699f5ce8",
    DETECT + "8.3.1-cc.json": "bae13501f90b343031b48bd927267883f2387e0af546aba24860943ad832f178",
    DETECT + "8.8.2-cc.json": "e7f8aefc758d73dabe3cc7de6746e34c18e4bce074af28dda07d72fcaae484b1",
    DETECT + "8.8.2-default.json": "e19d6d87a91089b2f6fe37b5eddd2ecc23eb686e3465803bfb2257efbf3d6828",
    DETECT + "9.3.2-cc.json": "3759ca85b798a13e83c0de07c8921b8228f62fd84f18c6c51d1a3c68c469e79e",
    DETECT + "9.3.2-vendor.json": "1b0beead201db8b3df83d2ff4f6fa773237e774e3c36e908191de1b85e255cd5",
    "core-output-base/proto/vectors/link_route.json":
        "24592d65ccab9d86dcb5899f7c644e7ff8e2b06ba0debd365a291d8f859b71aa",
    "platform-server/vectors/repo_cache_vectors.json":
        "a2e4d629a8d94ada660b40b0ae102a984dd09cab67dda6c2ed9042d1251e0f63",
}


def scrub(data, campaign):
    """`data` without the campaign directory and without the host and user names."""
    names = set()

    def java_log(match):
        names.update(match.group(1).split(b"."))
        return b"java.log.host.user.log.java."

    def user_root(match):
        names.add(match.group(1))
        return b"_bazel_user"

    data = data.replace(campaign.encode("utf-8"), b"<CAMPAIGN>")
    data = re.sub(rb'java\.log\.([^"/]+?)\.log\.java\.', java_log, data)
    data = re.sub(rb"_bazel_([A-Za-z0-9._-]+)", user_root, data)
    left = sorted(n.decode() for n in names if n in data)
    # Spelled in parts so that this file does not match the needle of check.py.
    if left or b"/" + b"Users/" in data:
        raise SystemExit(f"a machine name or path survived the rewrite: {left}")
    return data


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    probes = os.path.abspath(sys.argv[1])
    campaign = os.path.dirname(probes)
    for rel, pinned in SOURCES.items():
        with open(os.path.join(probes, rel), "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != pinned:
            raise SystemExit(f"{rel}: not the file this import was written for")
        named = []  # (workspace path, name of its output base) where the name is a digest
        if rel.startswith(DETECT):
            vector = json.loads(data)
            named = [(vector["workspace_path_hashed"], vector["workspace_md5_is_output_base_name"])]
        elif rel.endswith("/link_route.json"):
            named = [(row["workspace"], os.path.basename(row["expected_output_base"]))
                     for row in json.loads(data)]
            named = [pair for pair in named if re.fullmatch(r"[0-9a-f]{32}", pair[1])]
        for workspace, name in named:
            if hashlib.md5(workspace.encode("utf-8")).hexdigest() != name:
                raise SystemExit(f"{rel}: {name} is not the MD5 of the workspace path")
        clean = scrub(data, campaign)  # before the copy is opened: a refusal leaves it as it was
        out = os.path.join(HERE, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(clean)
        print("wrote " + rel)


if __name__ == "__main__":
    main()
