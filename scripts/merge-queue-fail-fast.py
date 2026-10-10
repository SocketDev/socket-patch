#!/usr/bin/env python3
"""Cancel a merge-queue entry's CI run as soon as one of its jobs fails.

`ci-ok`, the queue's required check, `needs:` every CI job, so it only
reports once the slowest leg finishes: a compile error at minute 2 kept
the entry, and every entry built on top of it, in the queue for the
~45 minutes the Gradle e2e legs take, burning macOS and Windows runners
on a run that could no longer pass.

No CI job sets `continue-on-error`, so one failed or timed-out job means
`ci-ok` will fail. Cancelling the run then changes only *when* it fails:
`ci-ok` is `if: always()`, so it still runs on the cancelled run, sees the
failed and cancelled `needs`, and reports failure within seconds, and the
queue evicts the entry and rebuilds the ones behind it.

A job whose runner died is the exception (see `runner_lost`): it says
nothing about the PR, and cancelling the run for it turned one dead runner
into an eviction plus a burst of cancelled jobs. Those are left alone, so
`ci-ok` decides when the run finishes. The job can't be re-run instead:
`POST .../actions/jobs/{id}/rerun` is refused until the whole run has
completed, and by then `ci-ok` has already reported.

The script never fails its own job: any API error is a warning and the
watch carries on (or gives up), leaving the run to finish as before.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
GATE = "ci-ok"
# Job conclusions that make `ci-ok` fail. `cancelled` is left out: it
# means someone (the queue, a janitor, a person) is already cancelling.
FATAL = {"failure", "timed_out"}
# Check-run annotations that mean the job's runner went away, not that a
# step failed. On Depot runners these arrive as a job `failure` (its step
# shows `cancelled`) about a minute into the job, whatever the job runs;
# "lost communication" is the same death noticed by GitHub's 10-minute
# heartbeat. Matched case-insensitively against failure-level messages.
RUNNER_LOSS = ("lost communication", "shutdown signal", "step canceled by github")


def fatal_jobs(jobs):
    """Names of the completed jobs whose conclusion dooms `ci-ok`."""
    return sorted(j["name"] for j in failed_jobs(jobs))


def failed_jobs(jobs):
    return [
        j
        for j in jobs
        if j.get("status") == "completed" and j.get("conclusion") in FATAL and j.get("name") != GATE
    ]


def runner_lost(annotations):
    """True when a job's failure annotations say its runner died."""
    return any(
        a.get("annotation_level") == "failure" and any(m in (a.get("message") or "").lower() for m in RUNNER_LOSS)
        for a in annotations
    )


def request(method, path, token):
    req = urllib.request.Request(
        f"{API}/{path}",
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
    return json.loads(body) if body else None


def find_run(repo, sha, token):
    runs = request(
        "GET", f"repos/{repo}/actions/workflows/ci.yml/runs?event=merge_group&head_sha={sha}&per_page=10", token
    )["workflow_runs"]
    return max(runs, key=lambda r: r["id"]) if runs else None


def list_jobs(repo, run_id, token):
    jobs, page = [], 1
    while True:
        batch = request("GET", f"repos/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}", token)["jobs"]
        jobs += batch
        if len(batch) < 100:
            return jobs
        page += 1


def annotations(repo, job_id, token):
    # A job's id is also its check-run id.
    return request("GET", f"repos/{repo}/check-runs/{job_id}/annotations?per_page=100", token)


def summary(text):
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["HEAD_SHA"]
    token = os.environ["GH_TOKEN"]
    interval = int(os.environ.get("POLL_SECONDS", "30"))
    deadline = time.monotonic() + int(os.environ.get("WATCH_MINUTES", "100")) * 60
    run = None
    lost = {}  # job id -> runner_lost verdict; a completed job's annotations don't change
    while time.monotonic() < deadline:
        try:
            if run is None:
                run = find_run(repo, sha, token)
                if run is None:
                    time.sleep(interval)
                    continue
                print(f"watching CI run {run['html_url']}")
            if request("GET", f"repos/{repo}/actions/runs/{run['id']}", token)["status"] == "completed":
                print("CI run completed; nothing to do")
                return 0
            failed = []
            for j in failed_jobs(list_jobs(repo, run["id"], token)):
                if j["id"] not in lost:
                    lost[j["id"]] = runner_lost(annotations(repo, j["id"], token))
                    if lost[j["id"]]:
                        summary(f"Not cancelling for `{j['name']}`: its runner died ({j.get('html_url', '')}); `ci-ok` decides.")
                if not lost[j["id"]]:
                    failed.append(j["name"])
            failed.sort()
            if failed:
                request("POST", f"repos/{repo}/actions/runs/{run['id']}/cancel", token)
                summary(
                    f"Cancelled CI run {run['html_url']}: `ci-ok` cannot pass after these jobs failed:\n"
                    + "".join(f"- {name}\n" for name in failed)
                )
                return 0
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            # 409: the run is already finishing or being cancelled.
            print(f"::warning title=merge-queue fail-fast::{e}")
        time.sleep(interval)
    print("::warning title=merge-queue fail-fast::watch window ended before the CI run finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
