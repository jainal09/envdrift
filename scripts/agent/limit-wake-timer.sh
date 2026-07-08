#!/usr/bin/env bash
# Session-limit wake timer.
#
#   limit-wake-timer.sh "4:10am" [attempt]
#
# Sleeps until ~5 minutes past the given America/New_York reset time (today, or
# tomorrow if already past), plus exponential backoff by `attempt`, then EXITS —
# waking the agent to resume subagents that were killed by a session limit.
# See ../../AGENTS.md §4. NOTE: this is only for time-based "session limit · resets
# <time>" kills. "Out of usage credits" is model-scoped — switch models and resume,
# a timer would just wake into the same wall.
set -u
RESET_RAW="${1:?usage: limit-wake-timer.sh '4:10am' [attempt]}"
ATTEMPT="${2:-0}"

target=$(TZ=America/New_York date -d "today $RESET_RAW" +%s 2>/dev/null) || {
  echo "WAKE_TIMER_ERROR: cannot parse '$RESET_RAW'"; exit 1; }
now=$(date +%s)
# If the reset already passed today, it means tomorrow.
[ "$target" -le "$now" ] && target=$(TZ=America/New_York date -d "tomorrow $RESET_RAW" +%s)

# +5 min grace, plus exponential backoff by attempt (capped ~2h past the reset).
case "$ATTEMPT" in
  0) extra=300 ;; 1) extra=1200 ;; 2) extra=2100 ;; 3) extra=3900 ;; *) extra=7500 ;;
esac
target=$((target + extra))

echo "WAKE_TIMER: sleeping until $(TZ=America/New_York date -d @"$target" '+%a %H:%M ET') (attempt $ATTEMPT)"
until [ "$(date +%s)" -ge "$target" ]; do sleep 240; done
echo "WAKE_TIMER_FIRED: reset '$RESET_RAW' attempt $ATTEMPT — resume limit-killed agents now"
