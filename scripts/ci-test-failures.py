#!/usr/bin/env python3
"""Surface failing `cargo test` cases as GitHub annotations.

A `cargo test --workspace --no-fail-fast` log runs to ~16k lines, and the
only annotation a failure leaves is "Process completed with exit code 101".
The panic of a failing test sits thousands of lines above the end, past
the tail that log viewers and log APIs return, so an intermittent failure
can't be diagnosed after the fact. This prints one `::error` per failing
test, titled with the test target and name and carrying its panic output,
and appends the same to the job summary when $GITHUB_STEP_SUMMARY is set.

Usage: ci-test-failures.py LOG
"""

import os
import re
import sys
from collections import deque

# `     Running tests/foo.rs (target/debug/deps/foo-0123abcd)`; the binary
# name tells crates apart where the source path (`src/lib.rs`) doesn't.
# The path group is required so a child process's own "Running ..." line
# can't pass for a cargo header.
RUNNING = re.compile(r"^\s+Running (?:unittests )?\S+ \((\S+)\)$")
DOCTESTS = re.compile(r"^\s+Doc-tests (\S+)$")
SECTION = re.compile(r"^---- (.+) stdout ----$")
# A binary that dies (signal, abort, stack overflow) prints no section, only
# cargo's `error: test failed, to rerun pass ...` and the exit status.
RERUN = re.compile(r"^error: test failed, to rerun pass ")
# GitHub shows at most 10 error annotations per step.
MAX_ANNOTATIONS = 10
MAX_LINES = 40
MAX_LINE_CHARS = 500
MAX_SUMMARY_CHARS = 512 * 1024
CRASH_CONTEXT = 25
CRASH_TAIL = 4
# Log lines read back from the Actions API carry this prefix (7 fractional
# digits); tracing's own timestamps (6 digits) are left alone.
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z ?")


def failures(lines):
    """Yield (target, test, body lines) for each failing test or dead binary."""
    target, test, body = "", None, []
    seen = False  # a section was reported for the current binary
    recent = deque(maxlen=CRASH_CONTEXT)
    crash = None  # (target, lines before, cargo's cause after) of a dead binary
    for raw in lines:
        line = TIMESTAMP.sub("", raw.rstrip("\r\n"))
        if crash is not None:
            # Keep cargo's `Caused by: ... (signal: 6, SIGABRT ...)` lines.
            header = RUNNING.match(line) or DOCTESTS.match(line) or line.startswith("error: ")
            if not header and len(crash[2]) < CRASH_TAIL:
                crash[2].append(line)
                continue
            yield crash[0], "(test binary exited without a test report)", crash[1] + crash[2]
            crash = None
        if test is not None:
            if SECTION.match(line) or line == "failures:":
                yield target, test, body
                test, body = None, []
            else:
                body.append(line)
                continue
        running = RUNNING.match(line)
        doctests = DOCTESTS.match(line)
        if running or doctests:
            if running:
                target = re.sub(r"-[0-9a-f]+(\.exe)?$", "", os.path.basename(running.group(1)))
            else:
                target = f"{doctests.group(1)} doctests"
            seen = False
            recent.clear()
        section = SECTION.match(line)
        if section:
            test, seen = section.group(1), True
        elif RERUN.match(line) and not seen:
            crash = (target, list(recent) + [line], [])
        recent.append(line)
    if test is not None:
        yield target, test, body
    if crash is not None:
        yield crash[0], "(test binary exited without a test report)", crash[1] + crash[2]


def trim(body):
    while body and not body[0].strip():
        body = body[1:]
    while body and not body[-1].strip():
        body = body[:-1]
    body = [
        line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " ...(cut)"
        for line in body
    ]
    if len(body) > MAX_LINES:
        body = body[:MAX_LINES] + [f"... ({len(body) - MAX_LINES} more lines in the log)"]
    return body


def fence(body):
    longest = max((len(run) for line in body for run in re.findall(r"`+", line)), default=0)
    return "`" * max(3, longest + 1)


def escape(text, prop=False):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def main(argv):
    with open(argv[1], encoding="utf-8", errors="replace") as log:
        found = [(t, n, trim(b)) for t, n, b in failures(log)]
    for target, test, body in found[:MAX_ANNOTATIONS]:
        title = f"{target} {test}" if target else test
        print(f"::error title={escape(title, prop=True)}::{escape(chr(10).join(body))}")
    if len(found) > MAX_ANNOTATIONS:
        print(f"::error::{len(found) - MAX_ANNOTATIONS} more failing tests; see the job summary")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and found:
        parts = [f"## Failing tests ({len(found)})\n\n"]
        size = len(parts[0])
        for i, (target, test, body) in enumerate(found):
            f = fence(body)
            part = f"### `{test}`\n\n{target}\n\n{f}\n" + "\n".join(body) + f"\n{f}\n\n"
            if size + len(part) > MAX_SUMMARY_CHARS:
                parts.append(f"... {len(found) - i} more failing tests are in the log.\n")
                break
            parts.append(part)
            size += len(part)
        with open(summary, "a", encoding="utf-8") as out:
            out.write("".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
