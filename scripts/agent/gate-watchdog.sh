#!/usr/bin/env bash
# Merge-campaign gate watchdog.
#
# Snapshots every open PR (merge state, auto-merge armed?, unresolved-thread count)
# every ~2 minutes and EXITS the moment any actionable change appears — which, run
# as a background task by an agent, wakes the agent to handle it. Relaunch after
# each handling round. See ../../AGENTS.md §4 "The autonomy loop".
#
# Exits on:
#   - a PR merged/closed (advance the queue / run stack-retarget choreography)
#   - an ARMED PR gaining unresolved threads (triage + resolve)
#   - an ARMED PR going BEHIND/DIRTY (update-branch / conflict-resolve)
#   - an ARMED PR stuck BLOCKED ~50 min with 0 threads (suspect a CI failure)
#
# Requires: gh (authenticated), jq (via gh --jq).
set -u
REPO="${ENVDRIFT_REPO:-jainal09/envdrift}"
OWNER="${REPO%%/*}"
NAME="${REPO##*/}"
QUERY="query { repository(owner: \"$OWNER\", name: \"$NAME\") { pullRequests(states: OPEN, first: 60) { nodes { number mergeStateStatus autoMergeRequest { mergeMethod } reviewThreads(first: 100) { nodes { isResolved } } } } } }"

snapshot() {
  gh api graphql -f query="$QUERY" --jq '
    .data.repository.pullRequests.nodes[] |
    "\(.number):\(.mergeStateStatus):\(if .autoMergeRequest then "ARMED" else "-" end):\([.reviewThreads.nodes[] | select(.isResolved | not)] | length)"' 2>/dev/null | sort
}

prev="$(snapshot)"
[ -z "$prev" ] && { echo "WATCHDOG_ERROR: initial snapshot failed"; exit 1; }
echo "watchdog armed over:"; echo "$prev"
blocked_cycles=0

while true; do
  sleep 120
  cur="$(snapshot)"
  [ -z "$cur" ] && continue  # transient API failure — keep the baseline

  events=""

  # PRs that left the open set (merged or closed)
  gone=$(comm -23 <(echo "$prev" | cut -d: -f1) <(echo "$cur" | cut -d: -f1))
  for n in $gone; do events+="CLOSED_OR_MERGED: PR $n\n"; done

  # Armed PRs that stalled
  while IFS=: read -r n mss armed unres; do
    [ "$armed" = "ARMED" ] || continue
    if [ "$unres" -gt 0 ]; then events+="ARMED_STALL_THREADS: PR $n has $unres unresolved (state $mss)\n"; fi
    if [ "$mss" = "BEHIND" ] || [ "$mss" = "DIRTY" ]; then events+="ARMED_STALL_BASE: PR $n is $mss (needs update-branch)\n"; fi
  done <<< "$cur"

  # Backstop: armed + BLOCKED + 0 threads persisting ~50 min → likely a CI failure
  stuck=$(echo "$cur" | awk -F: '$3=="ARMED" && $2=="BLOCKED" && $4==0 {print $1}')
  if [ -n "$stuck" ]; then blocked_cycles=$((blocked_cycles+1)); else blocked_cycles=0; fi
  if [ "$blocked_cycles" -ge 25 ]; then events+="ARMED_LONG_BLOCKED (~50min, check CI failure): PRs $stuck\n"; fi

  if [ -n "$events" ]; then
    echo "=== WATCHDOG EVENTS ==="
    printf "%b" "$events"
    echo "=== CURRENT SNAPSHOT ==="
    echo "$cur"
    exit 0
  fi
  prev="$cur"
done
