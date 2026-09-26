#!/usr/bin/env python3
"""Check a real-vlt capstone run against the committed leg manifest.

Every real-vlt leg prints one line
``VLT-LEG <vlt-version> <os> <suite> <leg> ran|skip:<reason>`` (DESIGN §8).
This script reads the libtest output of one or more capstone binaries and
fails when:

* a binary reports ``0 passed`` (a filter that matched nothing), or any
  binary failed;
* a leg the manifest expects is missing, ran where it must skip, skipped
  where it must run, skipped for another reason, or printed twice;
* a leg is unknown to the manifest, or the run mixed vlt versions or OSes.

The expected status of each leg is computed from the manifest's rules for
the vlt version and OS the lines name and the run's knobs
(``SOCKET_PATCH_VLT_E2E_STORE_LINKER``, ``_CACHE_ROOT`` and
``_UPGRADE_JS``/``_UPGRADE_VERSION``, or the matching flags).

``--derive DOC`` prints the manifest generated from the leg inventory and
boundary tables of ``docs/testing/vlt-compatibility.md``; the manifest is
never written by hand.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from functools import total_ordering
from pathlib import Path

LEG_RE = re.compile(
    r"VLT-LEG (?P<version>\S+) (?P<os>\S+) (?P<suite>[a-z]+) (?P<leg>[a-z0-9_]+) "
    r"(?P<status>ran|skip:[a-z0-9-]+)"
)
RUNNING_RE = re.compile(r"^\s*Running (?:tests/)?(?P<name>[A-Za-z0-9_]+)(?:\.rs)?\b")
RESULT_RE = re.compile(r"test result: (?P<outcome>\w+)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed")


# ── versions ─────────────────────────────────────────────────────────────


@total_ordering
class Version:
    def __init__(self, key: tuple):
        self.key = key

    def __eq__(self, other) -> bool:
        return isinstance(other, Version) and self.key == other.key

    def __lt__(self, other: "Version") -> bool:
        return self.key < other.key

    def __hash__(self) -> int:
        return hash(self.key)

    def __repr__(self) -> str:
        return f"Version({self.key})"

    @staticmethod
    def parse(raw: str) -> "Version":
        raw = raw.strip()
        if raw.startswith("rc."):
            raw = "1.0.0-" + raw
        core, _, pre = raw.partition("-")
        parts = core.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError(f"not a vlt version: {raw!r}")
        major, minor, patch = (int(p) for p in parts)
        if pre:
            num = pre[3:] if pre.startswith("rc.") else pre
            if not num.isdigit():
                raise ValueError(f"not a vlt version: {raw!r}")
            return Version((major, minor, patch, 0, int(num)))
        return Version((major, minor, patch, 1, 0))


def version_matches(spec: dict, v: Version) -> bool:
    op = spec["op"]
    if op == "all":
        return True
    a = Version.parse(spec["a"])
    if op == "<":
        return v < a
    if op == "<=":
        return v <= a
    if op == ">":
        return v > a
    if op == ">=":
        return v >= a
    if op == "==":
        return v == a
    if op == "range":
        return a <= v <= Version.parse(spec["b"])
    raise ValueError(f"unknown version op {op!r}")


def parse_versions(text: str) -> dict:
    text = text.strip().strip("`").strip()
    if text in ("all", "every release"):
        return {"op": "all"}
    for sep in ("…", "..."):
        if sep in text:
            a, b = (t.strip().strip("`") for t in text.split(sep, 1))
            Version.parse(a)
            Version.parse(b)
            return {"op": "range", "a": a, "b": b}
    m = re.fullmatch(r"(<=|>=|==|<|>)\s*`?([^`\s]+)`?", text)
    if not m:
        raise ValueError(f"unparseable versions cell {text!r}")
    Version.parse(m.group(2))
    return {"op": m.group(1), "a": m.group(2)}


# ── conditions ───────────────────────────────────────────────────────────

COND_RE = re.compile(
    r"(?P<key>os|linker|cache_root|upgrade)\s*(?P<op>!=|=|<|>=| in | notin )\s*(?P<val>\S+)"
)


def parse_conditions(text: str) -> list:
    text = text.strip().strip("`")
    if text in ("", "—", "-"):
        return []
    out = []
    for term in text.split(","):
        term = term.strip().strip("`")
        m = COND_RE.fullmatch(term)
        if not m:
            raise ValueError(f"unparseable condition {term!r}")
        cond = {"key": m.group("key"), "op": m.group("op").strip(), "value": m.group("val")}
        if cond["op"] in ("in", "notin"):
            cond["value"] = cond["value"].split("+")
        if cond["key"] == "upgrade" and cond["op"] in ("<", ">="):
            Version.parse(cond["value"])
        out.append(cond)
    return out


class Knobs:
    def __init__(self, os: str, linker: str, cache_root: bool, upgrade):
        self.os = os
        self.linker = linker
        self.cache_root = cache_root
        self.upgrade = upgrade

    def value(self, key: str):
        return {
            "os": self.os,
            "linker": self.linker,
            "cache_root": "set" if self.cache_root else "unset",
            "upgrade": "set" if self.upgrade else "unset",
        }[key]


def condition_holds(cond: dict, knobs: Knobs) -> bool:
    key, op, value = cond["key"], cond["op"], cond["value"]
    if key == "upgrade" and op in ("<", ">="):
        if not knobs.upgrade:
            return False
        up = Version.parse(knobs.upgrade)
        return up < Version.parse(value) if op == "<" else up >= Version.parse(value)
    actual = knobs.value(key)
    if op == "=":
        return actual == value
    if op == "!=":
        return actual != value
    if op == "in":
        return actual in value
    if op == "notin":
        return actual not in value
    raise ValueError(f"unknown condition op {op!r}")


# ── the manifest ─────────────────────────────────────────────────────────


def expected_status(manifest: dict, suite: str, leg: str, v: Version, knobs: Knobs) -> str:
    for rule in manifest["rules"]:
        if rule["suite"] != suite:
            continue
        legs = rule["legs"]
        if legs != "*" and leg not in legs:
            continue
        if leg in rule.get("except", []):
            continue
        if not version_matches(rule["versions"], v):
            continue
        if all(condition_holds(c, knobs) for c in rule["conditions"]):
            return f"skip:{rule['reason']}"
    return "ran"


def _cells(line: str) -> list:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _table(doc: str, heading: str) -> list:
    lines = doc.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == heading)
    except StopIteration:
        raise ValueError(f"{heading!r} not found")
    rows = []
    i = start + 1
    while i < len(lines) and not lines[i].lstrip().startswith("|"):
        i += 1
    header = _cells(lines[i])
    i += 2
    while i < len(lines) and lines[i].lstrip().startswith("|"):
        cells = _cells(lines[i])
        if len(cells) != len(header):
            raise ValueError(f"row with {len(cells)} cells under {heading}: {lines[i]!r}")
        rows.append(dict(zip(header, cells)))
        i += 1
    return rows


def _names(cell: str) -> list:
    return [n.strip().strip("`") for n in cell.split(",") if n.strip().strip("`")]


def _version_list(cell: str) -> list:
    out = []
    for name in _names(cell):
        Version.parse(name)
        out.append(name)
    return out


def derive(doc: str) -> dict:
    """The manifest the tables of ``docs/testing/vlt-compatibility.md`` define."""
    binaries: dict = {}
    legs: dict = {}
    for row in _table(doc, "## Leg inventory"):
        binary = row["Binary"].strip("`")
        suite = row["Suite"].strip("`")
        names = _names(row["Legs"])
        legs.setdefault(suite, [])
        for n in names:
            if n in legs[suite]:
                raise ValueError(f"leg {suite}/{n} listed twice")
            legs[suite].append(n)
        binaries.setdefault(binary, {})[suite] = names
    rules = []
    for row in _table(doc, "## Boundary table"):
        reason = row["Skip reason"].strip("`")
        if reason in ("—", "-", ""):
            continue
        suite = row["Suite"].strip("`")
        if suite not in legs:
            raise ValueError(f"boundary row names unknown suite {suite!r}")
        cell = row["Legs"].replace("`", "").strip()
        except_: list = []
        if cell.startswith("*"):
            leg_set: object = "*"
            rest = cell[1:].strip()
            if rest.startswith("except"):
                except_ = _names(rest[len("except"):])
        else:
            leg_set = _names(cell)
        for n in (leg_set if leg_set != "*" else []) + except_:
            if n not in legs[suite]:
                raise ValueError(f"boundary row names unknown leg {suite}/{n}")
        rules.append(
            {
                "boundary": row["Boundary"],
                "suite": suite,
                "legs": leg_set,
                "except": except_,
                "versions": parse_versions(row["Versions"]),
                "conditions": parse_conditions(row["Condition"]),
                "reason": reason,
            }
        )
    releases = _table(doc, "## Releases")
    supported = [n for r in releases if r["Status"] == "supported" for n in _version_list(r["Versions"])]
    excluded = [n for r in releases if r["Status"] != "supported" for n in _names(r["Versions"])]
    return {
        "comment": "Generated from docs/testing/vlt-compatibility.md by "
        "`scripts/check-vlt-legs.py --derive`; never edit by hand.",
        "binaries": binaries,
        "legs": legs,
        "rules": rules,
        "supported": supported,
        "excluded": excluded,
    }


# ── checking a log ───────────────────────────────────────────────────────


def parse_log(text: str):
    running = []
    results = []
    lines = []
    for raw in text.splitlines():
        m = RUNNING_RE.match(raw)
        if m:
            running.append(m.group("name"))
        m = RESULT_RE.search(raw)
        if m:
            results.append(
                (m.group("outcome"), int(m.group("passed")), int(m.group("failed")))
            )
        for m in LEG_RE.finditer(raw):
            lines.append(m.groupdict())
    return running, results, lines


def check(manifest: dict, text: str, knobs_env: dict, binaries: list) -> list:
    errors = []
    running, results, lines = parse_log(text)
    for outcome, passed, failed in results:
        if passed == 0:
            errors.append("a test binary reported `0 passed` (vacuous run)")
        if failed or outcome != "ok":
            errors.append(f"a test binary failed ({passed} passed, {failed} failed)")
    if not results:
        errors.append("no libtest `test result:` line in the log")
    if not lines:
        errors.append("no VLT-LEG line in the log")
        return errors
    versions = {l["version"] for l in lines}
    oses = {l["os"] for l in lines}
    if len(versions) != 1 or len(oses) != 1:
        errors.append(f"one run must use one vlt and one OS; saw {sorted(versions)} on {sorted(oses)}")
        return errors
    raw_version = versions.pop()
    if raw_version in manifest["excluded"]:
        errors.append(f"vlt {raw_version} is excluded from support")
    try:
        v = Version.parse(raw_version)
    except ValueError as e:
        errors.append(str(e))
        return errors
    knobs = Knobs(
        os=oses.pop(),
        linker=knobs_env.get("linker") or "unset",
        cache_root=bool(knobs_env.get("cache_root")),
        upgrade=knobs_env.get("upgrade") or None,
    )
    ran_binaries = [b for b in running + binaries if b in manifest["binaries"]]
    if not ran_binaries:
        suites = {l["suite"] for l in lines}
        ran_binaries = [
            b for b, s in manifest["binaries"].items() if set(s) & suites and all(
                x in suites for x in s
            )
        ]
    expected = {}
    for b in dict.fromkeys(ran_binaries):
        for suite, legs in manifest["binaries"][b].items():
            for leg in legs:
                expected[(suite, leg)] = expected_status(manifest, suite, leg, v, knobs)
    seen: dict = {}
    for l in lines:
        key = (l["suite"], l["leg"])
        if key in seen:
            errors.append(f"{key[0]}/{key[1]} printed more than one VLT-LEG line")
        seen[key] = l["status"]
    for key, want in sorted(expected.items()):
        got = seen.get(key)
        if got is None:
            errors.append(f"{key[0]}/{key[1]}: no VLT-LEG line (expected {want})")
        elif got != want:
            errors.append(f"{key[0]}/{key[1]}: {got}, expected {want}")
    for key in sorted(seen):
        if key not in expected:
            errors.append(f"{key[0]}/{key[1]}: not a leg the manifest expects from this run")
    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", help="crates/socket-patch-cli/tests/vlt-leg-manifest.json")
    ap.add_argument("--derive", metavar="DOC", help="print the manifest DOC defines")
    ap.add_argument("--binary", action="append", default=[], help="a capstone the log ran")
    ap.add_argument("--store-linker", default=os.environ.get("SOCKET_PATCH_VLT_E2E_STORE_LINKER", ""))
    ap.add_argument("--cache-root", default=os.environ.get("SOCKET_PATCH_VLT_E2E_CACHE_ROOT", ""))
    ap.add_argument(
        "--upgrade-version",
        default=os.environ.get("SOCKET_PATCH_VLT_E2E_UPGRADE_VERSION", "")
        if os.environ.get("SOCKET_PATCH_VLT_E2E_UPGRADE_JS")
        else "",
    )
    ap.add_argument("logs", nargs="*")
    args = ap.parse_args(argv)
    if args.derive:
        print(json.dumps(derive(Path(args.derive).read_text(encoding="utf-8")), indent=2))
        return 0
    if not args.manifest or not args.logs:
        ap.error("--manifest and at least one log are required")
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    text = "\n".join(Path(p).read_text(encoding="utf-8", errors="replace") for p in args.logs)
    knobs = {
        "linker": args.store_linker,
        "cache_root": args.cache_root,
        "upgrade": args.upgrade_version,
    }
    errors = check(manifest, text, knobs, args.binary)
    _, _, lines = parse_log(text)
    ran = sum(1 for l in lines if l["status"] == "ran")
    skipped = len(lines) - ran
    if errors:
        for e in errors:
            print(f"check-vlt-legs: {e}", file=sys.stderr)
        print(f"check-vlt-legs: FAILED ({ran} ran, {skipped} skipped)", file=sys.stderr)
        return 1
    print(f"check-vlt-legs: ok ({ran} ran, {skipped} skipped, manifest diff clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
