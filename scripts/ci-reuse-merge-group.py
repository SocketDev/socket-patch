#!/usr/bin/env python3
"""Reuse CI only after the merge queue passed this exact main commit.

One bounded, workflow-scoped API read; any missing or unreadable evidence
falls back to running CI. PRs, nightlies and manual runs never reuse results.
"""

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlencode


def successful_run(payload, repository, sha):
    for run in payload["workflow_runs"]:
        if (run.get("event") == "merge_group"
                and run.get("head_sha") == sha
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("head_repository", {}).get("full_name") == repository
                and run.get("head_branch", "").startswith("gh-readonly-queue/main/")):
            return run["id"]
    return None


def reusable_run(env):
    if env.get("GITHUB_EVENT_NAME") != "push" or env.get("GITHUB_REF") != "refs/heads/main":
        return None
    try:
        repository, sha = env["GITHUB_REPOSITORY"], env["GITHUB_SHA"]
        query = urlencode({"event": "merge_group", "head_sha": sha, "per_page": 100})
        endpoint = f"repos/{repository}/actions/workflows/ci.yml/runs?{query}"
        result = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True,
                                text=True, timeout=15)
        return successful_run(json.loads(result.stdout), repository, sha)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError) as error:
        # Do not print response bodies or stderr, which may contain credentials.
        print(f"::notice::Could not verify merge-queue CI ({type(error).__name__}); running all checks.")
        return None


def main():
    run = reusable_run(os.environ)
    reuse = run is not None
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"reuse={'true' if reuse else 'false'}\n")
    if reuse:
        print(f"Merge-queue CI run {run} passed this SHA; retaining cache builds and the full tier.")
    else:
        print("No verified merge-queue CI result for this push; running all checks.")


if __name__ == "__main__":
    main()
