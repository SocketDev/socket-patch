#!/usr/bin/env python3
"""Skip re-testing a PR push that only merged the base branch.

With a merge queue, a PR never has to be up to date with main: the queue
re-tests every entry on top of the latest main before it lands. Merging main
into a PR branch therefore re-runs the whole PR tier on a diff that already
passed. This reports `unchanged=true` only when all of these hold:

- the PR targets main, the only branch with a merge queue;
- the PR head is a two-parent merge commit;
- the PR's own diff (merge-base with the base branch to head) is the same,
  hunk for hunk, as the diff of its first parent, the previous head;
- this workflow completed successfully on that previous head, for the same
  head repository, and its clippy job ran (a draft run skips everything).

A conflict resolution changes a hunk, and a merge of anything other than the
base branch adds files or hunks, so both run the full tier. Any API error,
oversized or binary diff, or missing evidence also runs the full tier.
"""

import json
import os
import re
import subprocess
from pathlib import Path

# The compare API lists at most 300 files and leaves out the patch of a
# binary or very large file. Either way the diff cannot be proven unchanged.
MAX_FILES = 300
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE)


def api(endpoint):
    result = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True,
                            text=True, timeout=15)
    return json.loads(result.stdout)


def diff_signature(compare):
    """The PR diff with line numbers dropped, like `git patch-id --stable`."""
    files = compare["files"]
    if not files or len(files) >= MAX_FILES:
        return None
    signature = []
    for entry in files:
        patch = entry.get("patch")
        if patch is None:
            return None
        signature.append((entry["filename"], entry.get("previous_filename"), entry["status"],
                          HUNK_HEADER.sub("@@", patch)))
    return sorted(signature, key=repr)


def passed_run(runs, jobs_of, head_sha, head_repository):
    for run in runs["workflow_runs"]:
        if (run.get("event") == "pull_request"
                and run.get("head_sha") == head_sha
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("head_repository", {}).get("full_name") == head_repository):
            # The run's success already covers ci-ok. A draft run also ends in
            # success with every job skipped, so clippy must have run. It is
            # the first job, so it is on the first page even of a full run.
            jobs = {job.get("name"): job.get("conclusion") for job in jobs_of(run["id"])["jobs"]}
            if jobs.get("clippy") == "success":
                return run["id"]
    return None


def reusable_run(env):
    # Only main has a merge queue to re-test the PR before it lands.
    if env.get("GITHUB_EVENT_NAME") != "pull_request" or env.get("PR_BASE_REF") != "main":
        return None
    try:
        repository, head = env["GITHUB_REPOSITORY"], env["PR_HEAD_SHA"]
        head_repository = env["PR_HEAD_REPOSITORY"]
        parents = api(f"repos/{repository}/commits/{head}")["parents"]
        if len(parents) != 2:
            return None
        previous = parents[0]["sha"]
        # The cheap evidence first: most merge pushes follow a cancelled run.
        runs = api(f"repos/{repository}/actions/workflows/ci.yml/runs"
                   f"?event=pull_request&head_sha={previous}&per_page=20")
        run = passed_run(runs, lambda run_id: api(
            f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"),
            previous, head_repository)
        if run is None:
            return None
        # Three-dot compares diff from the merge-base, which is what the PR
        # shows. per_page=1 keeps the commit list short; files stay complete.
        now = diff_signature(api(f"repos/{repository}/compare/main...{head}?per_page=1"))
        before = diff_signature(api(f"repos/{repository}/compare/main...{previous}?per_page=1"))
        return run if now is not None and now == before else None
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError,
            AttributeError, IndexError) as error:
        # Do not print response bodies or stderr, which may contain credentials.
        print(f"::notice::Could not compare with the previous PR head ({type(error).__name__}); "
              "running all checks.")
        return None


def main():
    run = reusable_run(os.environ)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"unchanged={'true' if run is not None else 'false'}\n")
    if run is not None:
        print(f"This push only merged {os.environ['PR_BASE_REF']}; the PR diff is unchanged and "
              f"CI run {run} passed the previous head. The merge queue re-tests it on the "
              "latest base, so only the preflight runs here.")
    else:
        print("Not a clean base-branch merge onto a passing head; running all checks.")


if __name__ == "__main__":
    main()
