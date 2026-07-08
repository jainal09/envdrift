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

# Per-PR count of consecutive cycles spent armed+BLOCKED+0-threads, so one PR's
# long block never mis-attributes the "~50 min" backstop to a freshly-blocked one.
declare -A blocked_cycles

# The line for PR $n in the previous snapshot (empty if it wasn't present), so the
# ARMED stall checks fire on a CHANGE rather than on any matching current state.
prev_line() { echo "$prev" | grep -m1 "^$1:" || true; }

while true; do
  sleep 120
  cur="$(snapshot)"
  [ -z "$cur" ] && continue  # transient API failure — keep the baseline

  events=""
  declare -A seen_stuck=()

  # PRs that left the open set (merged or closed)
  gone=$(comm -23 <(echo "$prev" | cut -d: -f1) <(echo "$cur" | cut -d: -f1))
  for n in $gone; do events+="CLOSED_OR_MERGED: PR $n\n"; done

  while IFS=: read -r n mss armed unres; do
    [ "$armed" = "ARMED" ] || continue
    changed=0; [ "$n:$mss:$armed:$unres" != "$(prev_line "$n")" ] && changed=1

    # Armed PRs whose stalled state is NEW this cycle (not already stalled last cycle)
    if [ "$changed" = 1 ] && [ "$unres" -gt 0 ]; then
      events+="ARMED_STALL_THREADS: PR $n has $unres unresolved (state $mss)\n"
    fi
    if [ "$changed" = 1 ] && { [ "$mss" = "BEHIND" ] || [ "$mss" = "DIRTY" ]; }; then
      events+="ARMED_STALL_BASE: PR $n is $mss (needs update-branch)\n"
    fi

    # Per-PR backstop: armed + BLOCKED + 0 threads persisting ~50 min → likely CI failure
    if [ "$mss" = "BLOCKED" ] && [ "$unres" -eq 0 ]; then
      seen_stuck[$n]=1
      blocked_cycles[$n]=$(( ${blocked_cycles[$n]:-0} + 1 ))
      if [ "${blocked_cycles[$n]}" -eq 25 ]; then
        events+="ARMED_LONG_BLOCKED (~50min, check CI failure): PR $n\n"
      fi
    fi
  done <<< "$cur"

  # Reset the per-PR block counter for any PR no longer armed+BLOCKED+0-threads
  for n in "${!blocked_cycles[@]}"; do [ -z "${seen_stuck[$n]:-}" ] && unset 'blocked_cycles[$n]'; done

  if [ -n "$events" ]; then
    echo "=== WATCHDOG EVENTS ==="
    printf "%b" "$events"
    echo "=== CURRENT SNAPSHOT ==="
    echo "$cur"
    exit 0
  fi
  prev="$cur"
done
