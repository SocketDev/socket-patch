#!/usr/bin/env python3
"""Reduce the Bazel-support campaign's probe vectors to the files of this directory.

    python3 reduce.py <campaign probes directory> <output directory>

Run with this directory as the output it rewrites the five JSON files byte for byte and
then SHA256SUMS over every file here. The probe directory is not part of this repository;
README.md names the vector files it reads.
"""
import glob, hashlib, json, os, re, sys

PROBES, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)


def dump(name, value):
    with open(os.path.join(OUT, name), "w", newline="\n") as f:
        json.dump(value, f, indent=1, ensure_ascii=True)
        f.write("\n")


def ver_key(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:rc(\d+))?", v)
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 10**6)


# ---- S8: lexer -------------------------------------------------------------------------
s8 = {}
for path in glob.glob(PROBES + "/rc-ignore-substitution/s8/vectors/*.compact.json"):
    d = json.load(open(path))
    s8[d["bazel"]] = d
versions = sorted(s8, key=ver_key)

lex = {}
bep_releases = []
for ver in versions:
    for case in s8[ver]["cases"]:
        if case["id"] != "LEX":
            continue
        for lc in case["lexer_cases"]:
            row = lex.setdefault(lc["id"], {"id": lc["id"], "rc_hex": lc["rc_hex"]})
            assert row["rc_hex"] == lc["rc_hex"]
            if lc.get("match") is True:
                assert row.setdefault("tokens", lc["observed_tokens"]) == lc["observed_tokens"], lc["id"]
                if ver not in bep_releases:
                    bep_releases.append(ver)
            elif "announce_rc_joined" in lc:
                row["announce_rc_10.0.0rc3"] = lc["announce_rc_joined"]
            else:
                raise SystemExit("unexpected lexer row %s %s" % (ver, lc["id"]))
assert len(lex) == 31 and all("tokens" in r and "announce_rc_10.0.0rc3" in r for r in lex.values())
dump("s8-lexer.json", {
    "source": "probe S8 (rc-ignore-substitution/s8/vectors/*.compact.json, LEX.lexer_cases)",
    "note": "rc_hex is the rc file's bytes. tokens: section keyword -> words, as the Bazel client "
            "reported them in the build event protocol (--default_override) on every release of "
            "bep_releases; each character of a string is one byte (Latin-1). "
            "announce_rc_10.0.0rc3: the words of each section Bazel 10.0.0rc3 printed under "
            "--announce_rc, joined by one space and decoded as UTF-8; a section whose keyword is "
            "not a command is not printed.",
    "bep_releases": bep_releases,
    "cases": [lex[k] for k in sorted(lex)],
})

# ---- S8: whole invocations -------------------------------------------------------------
order, startup, effective = [], [], []
for ver in versions:
    for case in s8[ver]["cases"]:
        cid = case["id"]
        if cid == "LEX" or case.get("exit") != 0:
            continue
        files = {("HOME/.bazelrc" if k == "~/.bazelrc" else k): v for k, v in case["files"].items()}
        if cid.startswith("C_") or cid == "G_version_import":
            tops = [".bazelrc"]
            if "--nohome_rc" not in case["startup"] and "HOME/.bazelrc" in files:
                tops.append("HOME/.bazelrc")
            if case["env"].get("BAZELRC") and ver_key(ver) >= (9, 0, 0, 0):
                tops.append(case["env"]["BAZELRC"].replace("<WS>/", ""))
            for s in case["startup"]:
                if s.startswith("--bazelrc="):
                    tops.append(s[len("--bazelrc="):].replace("<WS>/", ""))
            assert case["order_match"] is True
            order.append({
                "id": cid, "bazel": ver, "command": case["command"], "tops": tops, "files": files,
                "order_source": "announce_rc" if case["order_source"].startswith("announce_rc") else "bep",
                "observed_order": case["observed_order"],
            })
        elif cid == "G_startup_os2":
            startup.append({
                "id": cid, "bazel": ver, "files": files,
                "observed_host_jvm_args": [s.split("=", 1)[1] for s in case["startup_connect_timeout"]],
            })
        elif cid.startswith("R_"):
            (flag, val), = case["effective"].items()
            effective.append({"id": cid, "bazel": ver, "command": case["command"], "cli": case["cli"],
                              "files": files, "flag": flag, "observed": val["observed"]})
dump("s8-invocations.json", {
    "source": "probe S8 (rc-ignore-substitution/s8/vectors/*.compact.json), exit-0 invocations only",
    "note": "order: every rc line carries --distdir=/sp/<tag>; observed_order is the tag order of one "
            "real invocation, from the canonical command line of the build event protocol (bep) or from "
            "--announce_rc (sections in applied order, a --config token printed unexpanded). tops: the rc "
            "files the client read, in its order (workspace, home, $BAZELRC from 9.0.0, --bazelrc=); the "
            "run was started in the workspace root on macOS. startup: the -Dsp.t values among the server's "
            "startup options. effective: the value Bazel reported for the flag with cli on the command line.",
    "order": order, "startup": startup, "effective": effective,
})

# ---- C15: .bazelversion ----------------------------------------------------------------
def outcome(text):
    if text.startswith("bazel "):
        return text
    if text.startswith("WRAPPER-RAN"):
        return "tools/bazel ran instead"
    if "more than one slash" in text:
        return "error: more than one slash"
    if "invalid version" in text:
        return "error: invalid version"
    if "unable to determine latest version" in text:
        return "error: needs the network"
    if "failed to download bazel" in text:
        return "error: fork download failed"
    raise SystemExit("unclassified bazelisk output: " + text[:120])

c15 = json.load(open(PROBES + "/core-output-base/proto/vectors/bazelversion.json"))
assert len(c15) == 35
rows = []
for v in c15:
    rows.append({
        "id": v["id"], "note": v["note"], "bazelversion_hex": v["bazelversion_hex"],
        "bazeliskrc": v["bazeliskrc"], "env_USE_BAZEL_VERSION": v["env_USE_BAZEL_VERSION"],
        "expected_source": v["expected_source"], "expected_label": v["expected_label"],
        "expected_kind": v["expected_kind"], "expected_static": v["expected_static"],
        "bazelisk_online": outcome(v["bazelisk_online"]), "bazelisk_offline": outcome(v["bazelisk_offline"]),
    })
dump("bazelversion.json", {
    "source": "probe C15 (core-output-base/proto/vectors/bazelversion.json), bazelisk v1.30.0",
    "note": "bazelversion_hex is the .bazelversion bytes (null = no such file; in dir-named-bazelversion "
            "a directory has that name). expected_*: what the port bazelversion.py reads; "
            "bazelisk_online / bazelisk_offline: what the real bazelisk did, reduced to its first cause "
            "(timestamps and machine paths removed). subdir-wins ran in sub/ beside a sub/.bazelversion "
            "of 8.8.2. fallback-error ran with USE_BAZEL_FALLBACK_VERSION=error.",
    "vectors": rows,
})

# ---- T3: downloader config -------------------------------------------------------------
t3 = json.load(open(PROBES + "/test-infra-offline/vectors/url_rewriter/cases.json"))
assert len(t3) == 34
assert "/Users/" not in json.dumps(t3)
dump("url-rewriter-cases.json", {
    "source": "probe T3 (test-infra-offline/vectors/url_rewriter/cases.json), Bazel 5.4.1 - 10.0.0rc3",
    "note": "config is a downloader config file; expect_urls is what Bazel fetched for urls, in order "
            "(empty = every URL blocked, with the error text Bazel printed).",
    "cases": t3,
})

# ---- L7 gv11: module version order -----------------------------------------------------
vo = json.load(open(PROBES + "/versions-hybrid/vectors/version-order.json"))
pairs = []
for p in vo["pairs"]:
    sel = set(p["bazel_selected"].values())
    row = {"id": p["id"], "a": p["a"], "b": p["b"]}
    if p.get("skip_check"):
        row["skip"] = p["note"]
    else:
        assert len(sel) == 1 and sel == {p["prototype_max"]}, p["id"]
        row["selected"] = p["prototype_max"]
    pairs.append(row)
assert sum("selected" in p for p in pairs) == 27
dump("version-order.json", {
    "source": "probe L7 gv11 (versions-hybrid/vectors/version-order.json)",
    "note": "selected is the higher of a and b under Bazel's module version ordering: the version "
            "`bazel mod graph` selected on every run of bazel_runs.",
    "bazel_runs": vo["bazel_runs"],
    "pairs": pairs,
})

names = sorted(n for n in os.listdir(OUT) if n not in ("SHA256SUMS",))
with open(os.path.join(OUT, "SHA256SUMS"), "w", newline="\n") as f:
    for n in names:
        f.write("%s  %s\n" % (hashlib.sha256(open(os.path.join(OUT, n), "rb").read()).hexdigest(), n))
print("wrote", names)
