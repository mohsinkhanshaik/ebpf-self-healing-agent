#!/usr/bin/env bash
# Runs healerd against the real kernel and triggers each signal type.
# Uses exec actions that write marker files, so nothing on the host changes.
set -uo pipefail

BIN=${BIN:-./bin/healerd}
work=$(mktemp -d)
agent=""
trap '[[ -n "$agent" ]] && kill "$agent" 2>/dev/null; rm -rf "$work"' EXIT

cat >"$work/healerd.yaml" <<EOF
metrics_addr: "127.0.0.1:19464"
rules:
  - name: exit-watch
    signal: process_exit
    match: { comm: smoke-victim, only_failures: true }
    action: { type: exec, command: ["touch", "$work/exit.fired"] }
  - name: segv-watch
    signal: crash_signal
    match: { comm: smoke-victim, signals: [11] }
    action: { type: exec, command: ["touch", "$work/segv.fired"] }
EOF

"$BIN" -config "$work/healerd.yaml" >"$work/agent.log" 2>&1 &
agent=$!
for _ in $(seq 50); do
  curl -fs http://127.0.0.1:19464/healthz >/dev/null && break
  sleep 0.2
done

# A process named smoke-victim that segfaults (kill -SEGV generates the signal).
cp "$(command -v sleep)" "$work/smoke-victim"
"$work/smoke-victim" 30 &
victim=$!
sleep 0.5
kill -SEGV "$victim"
wait "$victim" 2>/dev/null
sleep 1

fail=0
for f in exit segv; do
  if [[ -e "$work/$f.fired" ]]; then echo "PASS  $f rule fired"; else echo "FAIL  $f rule did not fire"; fail=1; fi
done
curl -fs http://127.0.0.1:19464/metrics | grep healer_ || true
[[ $fail -eq 0 ]] || { echo "--- agent log"; cat "$work/agent.log"; exit 1; }
