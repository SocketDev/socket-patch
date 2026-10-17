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
#                                                -- "building" for <n> over REST
#   DONE checks pass|fail (<p> pass, <f> fail)   -- exits here without --merge
#   DONE merged|closed|dequeued                  -- exits here with --merge
#   warn: ...                                    -- a failed poll; keeps going
#
# Every agent on this account shares one GitHub API budget, so each poll
# is one small GraphQL query; the full check list (several pages for a PR
# here) is fetched only when the rollup state changes or every 5th poll.
# A rate-limited poll pauses for 10 minutes instead of retrying.
#
# Claude Code cloud sessions can't reach GraphQL (gh pr view, gh pr checks
# and gh api graphql all get a 403 there), so the first such 403 switches
# the script to REST for good: each poll then reads the PR, its check runs
# and commit statuses, and the base branch's required checks stand in for
# the rollup. REST has no merge-queue entry, so with --merge the queue
# lines track the PR's merge_group runs instead and carry no position.
# Exit status: 0 on pass/merged, 1 on fail/closed/dequeued, 2 on bad usage.
set -uo pipefail

pr="" merge=0 interval=120
while [ $# -gt 0 ]; do
  case "$1" in
    --merge) merge=1 ;;
    --interval) interval="$2"; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    [0-9]*) pr="$1" ;;
    *) echo "usage: $0 [PR] [--merge] [--interval SECONDS]" >&2; exit 2 ;;
  esac
  shift
done

repo=${GH_REPO:-}
if [ -z "$repo" ]; then
  url=$(git remote get-url origin 2>/dev/null) || url=""
  repo=$(sed -nE 's#^.*[:/]([^/:]+/[^/:]+)$#\1#p' <<<"${url%.git}")
fi
[ -n "$repo" ] || repo=$(gh repo view --json nameWithOwner -q .nameWithOwner) || exit 2
owner=${repo%/*} name=${repo#*/}
if [ -z "$pr" ]; then
  pr=$(gh pr view --json number -q .number 2>/dev/null) \
    || pr=$(gh api "repos/$repo/pulls?head=$owner:$(git branch --show-current)&state=open" -q '.[0].number // empty' 2>/dev/null)
  [ -n "$pr" ] || { echo "no PR for the current branch" >&2; exit 2; }
fi

# shellcheck disable=SC2016 # GraphQL variables, not shell
query='query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){
  state headRefOid mergeQueueEntry{position state}
  commits(last:1){nodes{commit{statusCheckRollup{state}}}}}}}'

# REST stand-ins for the GraphQL poll and for gh pr checks. Both leave
# the gh error text in $json / $errf on failure, like the calls they replace.
rest_poll() {
  json=$(gh api "repos/$repo/pulls/$pr" 2>&1) || return 1
  state=$(jq -r 'if .merged then "MERGED" elif .state == "closed" then "CLOSED" else "OPEN" end' <<<"$json")
  sha=$(jq -r '.head.sha' <<<"$json")
  base=$(jq -r '.base.ref' <<<"$json")
  # Until the required checks are known the rollup stays pending, so an
  # unreadable rule set never lets DONE through before ci-ok reports.
  if [ -z "$required" ]; then
    required=$(gh api "repos/$repo/rules/branches/$base" \
      -q '[.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context]' 2>/dev/null) \
      || { required=""; [ -n "$rules_warned" ] || echo "warn: can't read $base's required checks; retrying"; rules_warned=1; }
  fi
  entry=""
  [ "$merge" = 1 ] || return 0
  # A queue entry being built has unfinished merge_group runs on
  # gh-readonly-queue/<base>/pr-<n>-<sha>. Once they all pass the PR merges
  # moments later, so that is not a dequeue unless it is still open 10
  # minutes on; a rebuild starts new runs at once, so any other gap counts
  # as leaving the queue only on the second miss in a row.
  local group
  group=$(gh api "repos/$repo/actions/runs?event=merge_group&per_page=30" -q "[.workflow_runs[]
    | select(.head_branch | startswith(\"gh-readonly-queue/$base/pr-$pr-\"))]
    | (.[0].head_branch // \"\") as \$latest | map(select(.head_branch == \$latest))
    | if any(.status != \"completed\") then \"building\"
      elif length > 0 and all(.conclusion | IN(\"success\", \"neutral\", \"skipped\")) then \"passed\"
      else \"idle\" end" 2>/dev/null) || group=""
  case "$group" in
    building) entry="building" misses=0 passed_at="" ;;
    passed) [ "$was_in_queue" = 1 ] || return 0
      entry=$queued misses=0 passed_at=${passed_at:-$SECONDS}
      [ $((SECONDS - passed_at)) -lt 600 ] || entry="" ;;
    *) [ "$was_in_queue" = 1 ] && { [ -z "$group" ] || [ "$((misses += 1))" -lt 2 ]; } \
      && entry=$queued ;;
  esac
  return 0
}
rest_checks() {
  local runs statuses
  runs=$(gh api --paginate "repos/$repo/commits/$sha/check-runs?per_page=100" -q '.check_runs[]
    | {name, bucket: (if .status != "completed" then "pending"
        elif (.conclusion | IN("success", "neutral", "skipped")) then "pass"
        elif .conclusion == "cancelled" then "cancel" else "fail" end)}' 2>"$errf") || return 0
  statuses=$(gh api "repos/$repo/commits/$sha/status?per_page=100" -q '.statuses[]
    | {name: .context, bucket: (if .state == "pending" then "pending"
        elif .state == "success" then "pass" else "fail" end)}' 2>"$errf") || return 0
  jq -s '.' <<<"$runs$statuses"
}

errf=$(mktemp) || exit 2
trap 'rm -f "$errf"' EXIT
seen="" head="" queued="" was_in_queue=0 settled_before=-1 rollup_before="" polls=0
total=0 pending=1 fail=0 rest=0 required="" misses=0 passed_at="" rules_warned="" base=""
while true; do
  if [ "$rest" = 1 ]; then
    rest_poll
  else
    json=$(gh api graphql -f query="$query" -F o="$owner" -F n="$name" -F p="$pr" 2>&1)
  fi
  # shellcheck disable=SC2181 # both branches above set the status
  if [ $? != 0 ]; then
    if [ "$rest" = 0 ] && grep -q 'GraphQL is not available' <<<"$json"; then
      echo "warn: GraphQL unavailable here; polling over REST"; rest=1; continue
    fi
    if grep -qiE 'rate limit|HTTP 403|HTTP 429' <<<"$json"; then
      echo "warn: GitHub rate limit hit; pausing 10 minutes"; sleep 600; continue
    fi
    echo "warn: gh ${json%%$'\n'*}"; sleep "$interval"; continue
  fi
  if [ "$rest" = 0 ]; then
    state=$(jq -r '.data.repository.pullRequest.state' <<<"$json")
    sha=$(jq -r '.data.repository.pullRequest.headRefOid' <<<"$json")
  fi
  if [ "$sha" != "$head" ]; then
    [ -n "$head" ] && echo "push: head now ${sha:0:9}, checks restart"
    head=$sha seen="" settled_before=-1
  fi

  if [ "$rest" = 1 ]; then
    rollup=REST # the check list is the only signal, so it is read every poll
  else
    rollup=$(jq -r '.data.repository.pullRequest.commits.nodes[0].commit.statusCheckRollup.state // "NONE"' <<<"$json")
  fi
  polls=$((polls + 1))
  if [ "$rest" = 1 ] || [ "$settled_before" = -1 ] || [ "$rollup" != "$rollup_before" ] || [ $((polls % 5)) = 0 ]; then
    # gh pr checks pages through every check; its exit status is 8 while any
    # is pending and 1 when one failed, so only its output is trusted.
    if [ "$rest" = 1 ]; then
      checks=$(rest_checks)
    else
      checks=$(gh pr checks "$pr" -R "$repo" --json name,bucket 2>"$errf")
    fi
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
  if [ "$rest" = 1 ]; then
    # Settled once every required check has reported; REST lists only
    # check runs that exist, like gh pr checks.
    rollup=PENDING
    [ -n "$required" ] && jq -e --argjson req "$required" '($req - map(.name)) == []' <<<"$checks" >/dev/null 2>&1 \
      && rollup=SUCCESS
  else
    entry=$(jq -r '.data.repository.pullRequest.mergeQueueEntry | if . then "\(.position) \(.state | ascii_downcase)" else "" end' <<<"$json")
  fi
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
