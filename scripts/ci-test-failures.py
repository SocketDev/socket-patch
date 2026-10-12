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

# `     Running tests/foo.rs (target/debug/deps/foo-0123abcd)`; the binary
# name tells crates apart where the source path (`src/lib.rs`) doesn't.
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+)(?: \((\S+)\))?")
SECTION = re.compile(r"^---- (.+) stdout ----$")
# GitHub shows at most 10 error annotations per step.
MAX_ANNOTATIONS = 10
MAX_LINES = 40
# Actions log lines carry a timestamp prefix when read back from the API.
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ?")


def failures(lines):
    """Yield (target, test, body lines) for each `---- test stdout ----`."""
    target, test, body = "", None, []
    for raw in lines:
        line = TIMESTAMP.sub("", raw.rstrip("\r\n"))
        if test is not None:
            if SECTION.match(line) or line == "failures:":
                yield target, test, body
                test, body = None, []
            else:
                body.append(line)
                continue
        running = RUNNING.match(line)
        if running:
            binary = running.group(2)
            target = (
                re.sub(r"-[0-9a-f]+$", "", os.path.basename(binary))
                if binary
                else running.group(1)
            )
        section = SECTION.match(line)
        if section:
            test = section.group(1)
    if test is not None:
        yield target, test, body


def trim(body):
    while body and not body[0].strip():
        body = body[1:]
    while body and not body[-1].strip():
        body = body[:-1]
    if len(body) > MAX_LINES:
        body = body[:MAX_LINES] + [f"... ({len(body) - MAX_LINES} more lines in the log)"]
    return body


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
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and found:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Failing tests ({len(found)})\n\n")
            for target, test, body in found:
                out.write(f"### `{test}`\n\n{target}\n\n```\n" + "\n".join(body) + "\n```\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
