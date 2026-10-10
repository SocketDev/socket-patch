#!/usr/bin/env bash
# Event stream of a PR's CI, for Claude Code's Monitor tool (or a terminal).
#
#   scripts/ci-watch.sh [PR] [--merge] [--interval SECONDS]
#
# PR defaults to the current branch's PR. Prints one line per event and
# nothing while nothing changes, so it stays quiet enough for Monitor:
#   start: #<pr> <sha>, <p> pass <f> fail <q> pending
#   fail: <check name>                            -- one line per failed check
#   progress: <settled>/<total> settled, <f> fail -- at most every 5th poll
#   queue: entered at <n> | position <n> <state> | left the queue
#   DONE checks pass|fail (<p> pass, <f> fail)   -- exits here without --merge
#   DONE merged|closed|dequeued                  -- exits here with --merge
#   warn: ...                                    -- a failed poll; keeps going
#
# Every agent on this account shares one GitHub API budget, so each poll
# is one small GraphQL query; the full check list (several pages for a PR
# here) is fetched only when the rollup state changes or every 5th poll.
# A rate-limited poll pauses for 10 minutes instead of retrying.
# Exit status: 0 on pass/merged, 1 on fail/closed/dequeued, 2 on bad usage.
set -uo pipefail

pr="" merge=0 interval=120
while [ $# -gt 0 ]; do
  case "$1" in
    --merge) merge=1 ;;
    --interval) interval="$2"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    [0-9]*) pr="$1" ;;
    *) echo "usage: $0 [PR] [--merge] [--interval SECONDS]" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "$pr" ]; then
  pr=$(gh pr view --json number -q .number 2>/dev/null) || { echo "no PR for the current branch" >&2; exit 2; }
fi
repo=$(gh repo view --json nameWithOwner -q .nameWithOwner) || exit 2
owner=${repo%/*} name=${repo#*/}

# shellcheck disable=SC2016 # GraphQL variables, not shell
query='query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){
  state headRefOid mergeQueueEntry{position state}
  commits(last:1){nodes{commit{statusCheckRollup{state}}}}}}}'

errf=$(mktemp) || exit 2
trap 'rm -f "$errf"' EXIT
seen="" head="" queued="" was_in_queue=0 settled_before=-1 rollup_before="" polls=0
total=0 pending=1 fail=0
while true; do
  if ! json=$(gh api graphql -f query="$query" -F o="$owner" -F n="$name" -F p="$pr" 2>&1); then
    if grep -qiE 'rate limit|HTTP 403|HTTP 429' <<<"$json"; then
      echo "warn: GitHub rate limit hit; pausing 10 minutes"; sleep 600; continue
    fi
    echo "warn: gh ${json%%$'\n'*}"; sleep "$interval"; continue
  fi
  state=$(jq -r '.data.repository.pullRequest.state' <<<"$json")
  sha=$(jq -r '.data.repository.pullRequest.headRefOid' <<<"$json")
  if [ "$sha" != "$head" ]; then
    [ -n "$head" ] && echo "push: head now ${sha:0:9}, checks restart"
    head=$sha seen="" settled_before=-1
  fi

  rollup=$(jq -r '.data.repository.pullRequest.commits.nodes[0].commit.statusCheckRollup.state // "NONE"' <<<"$json")
  polls=$((polls + 1))
  if [ "$settled_before" = -1 ] || [ "$rollup" != "$rollup_before" ] || [ $((polls % 5)) = 0 ]; then
    # gh pr checks pages through every check; its exit status is 8 while any
    # is pending and 1 when one failed, so only its output is trusted.
    checks=$(gh pr checks "$pr" -R "$repo" --json name,bucket 2>"$errf")
    if ! jq -e 'type == "array"' <<<"$checks" >/dev/null 2>&1; then
      # Keep the last counts and retry this fetch on the next poll; the
      # paginated call is the expensive one, so back off on a rate limit.
      rollup_before=""
      if grep -qiE 'rate limit|HTTP 403|HTTP 429' "$errf"; then
        echo "warn: GitHub rate limit hit; pausing 10 minutes"; sleep 600; continue
      fi
      echo "warn: gh pr checks returned no JSON"; sleep "$interval"; continue
    fi
    total=$(jq 'length' <<<"$checks")
    pending=$(jq '[.[] | select(.bucket == "pending")] | length' <<<"$checks")
    fail=$(jq '[.[] | select(.bucket == "fail" or .bucket == "cancel")] | length' <<<"$checks")
    failed=$(jq -r '.[] | select(.bucket == "fail" or .bucket == "cancel") | .name' <<<"$checks" | sort -u)
    settled_now=$((total - pending))
    if [ "$settled_before" = -1 ]; then
      echo "start: #$pr ${sha:0:9}, $((settled_now - fail)) pass $fail fail $pending pending"
      printf '%s\n' "$failed" | grep -v '^$' | sed 's/^/fail: /'
    else
      comm -13 <(printf '%s\n' "$seen") <(printf '%s\n' "$failed") | grep -v '^$' | sed 's/^/fail: /'
      [ "$settled_now" != "$settled_before" ] && [ "$pending" != 0 ] \
        && echo "progress: $settled_now/$total settled, $fail fail"
    fi
    seen=$failed settled_before=$settled_now
  fi
  rollup_before=$rollup

  entry=$(jq -r '.data.repository.pullRequest.mergeQueueEntry | if . then "\(.position) \(.state | ascii_downcase)" else "" end' <<<"$json")
  if [ -n "$entry" ] && [ "$entry" != "$queued" ]; then
    [ "$was_in_queue" = 1 ] && echo "queue: position $entry" || echo "queue: entered at $entry"
    queued=$entry was_in_queue=1
  elif [ -z "$entry" ] && [ "$was_in_queue" = 1 ] && [ "$state" = OPEN ]; then
    echo "queue: left the queue"; queued="" was_in_queue=0
    [ "$merge" = 1 ] && { echo "DONE dequeued"; exit 1; }
  fi

  case "$state" in
    MERGED) echo "DONE merged"; exit 0 ;;
    CLOSED) echo "DONE closed"; exit 1 ;;
  esac

  # gh pr checks lists only check runs that exist; the rollup also counts
  # expected and re-queued ones, so both must agree before calling it done.
  if [ "$merge" = 0 ]; then
    if [ "$total" -gt 0 ] && [ "$pending" = 0 ] \
      && { [ "$rollup" = SUCCESS ] || [ "$rollup" = FAILURE ] || [ "$rollup" = ERROR ]; }; then
      if [ "$fail" = 0 ]; then echo "DONE checks pass ($total checks)"; exit 0; fi
      echo "DONE checks fail ($fail of $total failed)"; exit 1
    fi
  fi
  sleep "$interval"
done
