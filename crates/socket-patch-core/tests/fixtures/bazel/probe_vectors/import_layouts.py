#!/usr/bin/env python3
"""Import the output-tree layout vectors of four other probe groups.

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
which the copy can no longer show.

The thirteenth file is a sample, not a copy: SAMPLED names a probe file that is too large
to commit (880 downloads, 0.5 MB) and the file its sample is written to. The sample holds
the first PER_SHAPE rows of each shape, unchanged and in the probe's order, and the row
count of every shape in the whole file. The probe file is refused unless each of its rows
follows the repository-cache rule, and the sample is refused if it names the machine.

The probes directory is not part of this repository. After a run, rewrite SHA256SUMS and
run check.py.
"""
import base64
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
REPO_CACHE = "test-infra-offline/vectors/repo_cache/"
SAMPLED = {  # path under the probes directory: (SHA-256 of the probe's file, the sample's path)
    REPO_CACHE + "observed.json": (
        "b020bf4a90eabac4b70838088ebeb5d0e85febe20873371504eea3c1e81b9731",
        REPO_CACHE + "observed.sample.json",
    ),
}
PER_SHAPE = 3


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


def shape(row):
    """What tells one kind of download from another: the run, the host, the digest kind of
    the entry (None when the download is in no cache directory) and whether the entry has
    an `id-` file."""
    host = re.fullmatch(r"https://([^/]+)/.*", row["url"]).group(1)
    return (row["run"], host, row["key_type"], bool(row.get("id_markers_present")))


def follows_the_rule(row):
    """Whether the entry and the `id-` file of a download are where its checksum and its
    URL put them: `content_addressable/<kind>/<hex>/file`, and beside it either nothing or
    the one file `id-<the entry's own hash function over the URL>`."""
    kind, _, b64 = row["integrity"].partition("-")
    digest = base64.b64decode(b64).hex()
    entry = f"content_addressable/{kind}/{digest}/"
    marker = "id-" + hashlib.new(kind, row["url"].encode("utf-8")).hexdigest()
    return (kind == row["key_type"]
            and len(digest) == 2 * hashlib.new(kind).digest_size
            and row["cache_file"] == entry + "file"
            and row["id_marker_if_canonical_id_is_url"] == entry + marker
            and row["id_markers_present"] in ([], [marker])
            and row["canonical_id_is_url"] == bool(row["id_markers_present"]))


def sample(data, rel, pinned):
    """The committed sample of the probe file `data`: its bytes."""
    rows = json.loads(data)
    counts, picked = {}, []
    for row in rows:
        if row["key_type"] is None:
            if sorted(row) != ["bytes", "key_type", "run", "url"]:
                raise SystemExit(f"{rel}: a download in no cache directory names an entry: {row['url']}")
        elif not follows_the_rule(row):
            raise SystemExit(f"{rel}: {row['url']} ({row['run']}) does not follow the cache rule")
        key = shape(row)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= PER_SHAPE:
            picked.append(row)
    cached = [row for row in rows if row["key_type"] is not None]
    with_id = sum(1 for row in cached if row["id_markers_present"])
    doc = {
        "source": {"path": rel, "sha256": pinned, "rows": len(rows)},
        "selection": f"the first {PER_SHAPE} rows of each shape (run, host of the URL, key_type, "
                     "whether id_markers_present is empty), unchanged and in the order of the source",
        "source_totals": {
            "in_a_cache_directory": len(cached),
            "with_an_id_file": with_id,
            "without_an_id_file": len(cached) - with_id,
            "in_no_cache_directory": len(rows) - len(cached),
            "by_key_type": {kind: sum(1 for row in cached if row["key_type"] == kind)
                            for kind in sorted({row["key_type"] for row in cached})},
        },
        "source_shapes": [
            {"run": run, "host": host, "key_type": kind, "id_file": has_id, "rows": n,
             "sampled": min(n, PER_SHAPE)}
            for (run, host, kind, has_id), n in counts.items()
        ],
        "rows": picked,
    }
    return (json.dumps(doc, indent=1) + "\n").encode("utf-8")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    probes = os.path.abspath(sys.argv[1])
    campaign = os.path.dirname(probes)
    for rel, (pinned, out_rel) in SAMPLED.items():
        with open(os.path.join(probes, rel), "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != pinned:
            raise SystemExit(f"{rel}: not the file this import was written for")
        clean = sample(data, rel, pinned)
        # The rows are public URLs and digests. Nothing is rewritten: a row that the
        # rewrite would touch is refused, because its `id-` name is a hash of the URL.
        if scrub(clean, campaign) != clean:
            raise SystemExit(f"{rel}: a sampled row matches a machine-name pattern")
        out = os.path.join(HERE, out_rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(clean)
        print(f"wrote {out_rel} (sample of {rel})")
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
