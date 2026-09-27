#!/bin/sh
# Best-effort: seal each ZCode tool action (Write/Edit/Bash) into the NoireBox
# journal. The session must never block on the flight recorder, so failures
# still exit 0 — but stderr passes through and is printed loudly in the
# session: a silent failure would leave an unexplained gap in the journal.
# Disable entirely with NOIREBOX_HOOK_DISABLE=1.
[ -n "$NOIREBOX_HOOK_DISABLE" ] && exit 0
PLUGIN_ROOT="$1"
NB_HOME="${NOIREBOX_HOME:-/Users/samlabbe/.zcode/workspace/default/noirebox}"
PY="$NB_HOME/.venv/bin/python"
[ -x "$PY" ] || exit 0
[ -f "$PLUGIN_ROOT/hooks/seal_tool_use.py" ] || exit 0
"$PY" "$PLUGIN_ROOT/hooks/seal_tool_use.py" >/dev/null || true

# Trajectory part (ADR 012): seal ZCode's own flight recorder — the per-call
# model-io JSONL files — as digests only. Same best-effort contract: the
# session never blocks, failures stay loud on stderr. Toggles:
#   NOIREBOX_TRAJECTORY_SEAL=0        this part off (tool-use seals stay)
#   NOIREBOX_TRAJECTORY_INTERVAL_MIN  minutes between scans (default 10)
#   NOIREBOX_ROLLOUT_DIR              where the model-io files live
if [ "$NOIREBOX_TRAJECTORY_SEAL" != "0" ]; then
  ROLLOUT="${NOIREBOX_ROLLOUT_DIR:-$HOME/.zcode/cli/rollout}"
  INTERVAL="${NOIREBOX_TRAJECTORY_INTERVAL_MIN:-10}"
  DB="${NOIREBOX_DB:-$NB_HOME/data/noirebox.db}"
  "$PY" -m noirebox.cli seal-trajectory --rollout "$ROLLOUT" \
        --interval "$INTERVAL" --db "$DB" >/dev/null || true
fi
exit 0
