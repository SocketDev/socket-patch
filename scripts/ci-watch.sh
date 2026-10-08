#!/usr/bin/env bash
# Event stream of a PR's CI, for Claude Code's Monitor tool (or a terminal).
#
#   scripts/ci-watch.sh [PR] [--merge] [--interval SECONDS]
#
# PR defaults to the current branch's PR. Prints one line per event and
# nothing while nothing changes:
#   check <name>: pass|fail|cancelled|skipped
#   queue: entered at <n> | position <n> <state> | left the queue
#   DONE checks pass|fail (<p> pass, <f> fail)   -- exits here without --merge
#   DONE merged|closed|dequeued                  -- exits here with --merge
#   warn: gh ...                                 -- a failed poll; keeps going
# Exit status: 0 on pass/merged, 1 on fail/closed/dequeued, 2 on bad usage.
set -uo pipefail

pr="" merge=0 interval=60
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
  state headRefOid mergeQueueEntry{position state}}}}'

seen="" head="" queued="" was_in_queue=0 settled_before=-1
while true; do
  if ! json=$(gh api graphql -f query="$query" -F o="$owner" -F n="$name" -F p="$pr" 2>&1); then
    echo "warn: gh ${json%%$'\n'*}"; sleep "$interval"; continue
  fi
  state=$(jq -r '.data.repository.pullRequest.state' <<<"$json")
  sha=$(jq -r '.data.repository.pullRequest.headRefOid' <<<"$json")
  if [ "$sha" != "$head" ]; then
    [ -n "$head" ] && echo "push: head now ${sha:0:9}, checks restart"
    head=$sha seen="" settled_before=-1
  fi

  # gh pr checks pages through every check; its exit status is 8 while any
  # is pending and 1 when one failed, so only its output is trusted.
  checks=$(gh pr checks "$pr" -R "$repo" --json name,bucket 2>/dev/null)
  if ! jq -e 'type == "array"' <<<"$checks" >/dev/null 2>&1; then
    echo "warn: gh pr checks returned no JSON"; checks='[]'
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

  if [ "$merge" = 0 ]; then
    if [ "$total" -gt 0 ] && [ "$pending" = 0 ]; then
      if [ "$fail" = 0 ]; then echo "DONE checks pass ($total checks)"; exit 0; fi
      echo "DONE checks fail ($fail of $total failed)"; exit 1
    fi
  fi
  sleep "$interval"
done
