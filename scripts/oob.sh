#!/usr/bin/env bash
# oob.sh — out-of-band interaction helper for the Umbra engagement (Module A).
#
# Detects blind SSRF/XXE/RCE/blind-XSS by giving agents an OOB payload domain and
# polling for callbacks. Runs HOST-SIDE on purpose: the Kali sandbox egress is
# scope-locked, so the callback listener cannot live inside it.
#
# Backends (auto-resolved, most-preferred first):
#   burp       - Burp Collaborator, when UMBRA_OOB=burp (requires the user's Burp Pro + MCP).
#                (Payload generation/poll for Burp is driven via the MCP client, not this script;
#                 `backend` just reports it so engagement.js routes correctly.)
#   interactsh - projectdiscovery interactsh-client. NOTE: the free public OAST servers are
#                deprecated/unreliable, so a server must be provided via:
#                  UMBRA_OOB_SERVER  - self-hosted interactsh server URL (e.g. https://oob.example.com)
#                  UMBRA_OOB_TOKEN   - auth token for that server / interactsh cloud (optional)
#                If neither is set, `start` still tries the client defaults but will report failure.
#   none       - nothing available; OOB module stays dormant (engagement runs without OOB).
#
# Usage:
#   oob.sh ensure            # install interactsh-client if missing (needs `go`)
#   oob.sh backend           # print resolved backend: burp | interactsh | none
#   oob.sh start             # launch interactsh-client in background; capture base payload domain
#   oob.sh payload           # print the base OOB domain (agents use <marker>.<base>)
#   oob.sh poll [marker]     # print interactions seen so far (optionally filtered by marker substring)
#   oob.sh stop              # stop the client and clear session
#
# State lives in $UMBRA_OOB_DIR (default ./.umbra/oob).
set -euo pipefail

OOB_DIR="${UMBRA_OOB_DIR:-${PWD}/.umbra/oob}"
SESSION="${OOB_DIR}/session.env"
LOG="${OOB_DIR}/interactions.jsonl"
STARTLOG="${OOB_DIR}/startup.log"
PIDFILE="${OOB_DIR}/client.pid"

client_bin() {
  if command -v interactsh-client >/dev/null 2>&1; then command -v interactsh-client; return; fi
  local gp; gp="$(go env GOPATH 2>/dev/null || true)"
  [ -n "$gp" ] && [ -x "$gp/bin/interactsh-client" ] && { echo "$gp/bin/interactsh-client"; return; }
  return 1
}

cmd_ensure() {
  if client_bin >/dev/null 2>&1; then echo "interactsh-client: present ($(client_bin))"; return 0; fi
  command -v go >/dev/null 2>&1 || { echo "oob: interactsh-client missing and 'go' not available — install go or Burp Collaborator." >&2; return 1; }
  echo "oob: installing interactsh-client via go install ..." >&2
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  client_bin >/dev/null 2>&1 && echo "interactsh-client: installed ($(client_bin))" || { echo "oob: install failed." >&2; return 1; }
}

cmd_backend() {
  if [ "${UMBRA_OOB:-}" = "burp" ]; then echo "burp"; return; fi
  # interactsh is only usable if the client is present AND a server is configured (public OAST is
  # deprecated). Without a server we report 'none' so the module stays dormant instead of pretending.
  if client_bin >/dev/null 2>&1 && [ -n "${UMBRA_OOB_SERVER:-}" ]; then echo "interactsh"; return; fi
  echo "none"
}

cmd_start() {
  mkdir -p "$OOB_DIR"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    echo "oob: already running (pid $(cat "$PIDFILE"))." >&2; cmd_payload; return 0
  fi
  local bin; bin="$(client_bin)" || { echo "oob: no interactsh-client; run 'oob.sh ensure' first." >&2; return 1; }
  : > "$LOG"; : > "$STARTLOG"
  local srv=() ; [ -n "${UMBRA_OOB_SERVER:-}" ] && srv+=(-server "${UMBRA_OOB_SERVER}")
  [ -n "${UMBRA_OOB_TOKEN:-}" ] && srv+=(-token "${UMBRA_OOB_TOKEN}")
  # -json writes structured interactions to the log; -o also mirrors there. Poll interval 5s.
  nohup "$bin" "${srv[@]}" -json -o "$LOG" -pi 5 >"$STARTLOG" 2>&1 &
  echo $! > "$PIDFILE"
  local domain=""
  for _ in $(seq 1 30); do
    domain="$(grep -oiE '[a-z0-9]{20,}\.oast\.[a-z]+' "$STARTLOG" 2>/dev/null | head -1 || true)"
    [ -n "$domain" ] && break
    sleep 0.5
  done
  [ -z "$domain" ] && { echo "oob: client started but no payload domain captured (network/OAST issue)." >&2; return 1; }
  { echo "OOB_BACKEND=interactsh"; echo "OOB_DOMAIN=$domain"; echo "OOB_PID=$(cat "$PIDFILE")"; } > "$SESSION"
  echo "$domain"
}

cmd_payload() {
  [ -f "$SESSION" ] || { echo "oob: no session; run 'oob.sh start'." >&2; return 1; }
  # shellcheck disable=SC1090
  . "$SESSION"; echo "${OOB_DOMAIN:-}"
}

cmd_poll() {
  local marker="${1:-}"
  [ -f "$LOG" ] || { echo "oob: no interactions log; is the client started?" >&2; return 1; }
  python3 - "$LOG" "$marker" <<'PY'
import json,sys
log,marker=sys.argv[1],sys.argv[2]
n=0
for line in open(log,errors="ignore"):
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except Exception: continue
    fid=str(d.get("full-id") or d.get("unique-id") or "")
    if marker and marker not in fid and marker not in line: continue
    proto=d.get("protocol","?"); ra=d.get("remote-address","?"); ts=d.get("timestamp","?")
    print(f"HIT proto={proto} id={fid} from={ra} at={ts}")
    n+=1
print(f"[{n} interaction(s){' matching '+marker if marker else ''}]")
PY
}

cmd_stop() {
  if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null || true; rm -f "$PIDFILE"; fi
  rm -f "$SESSION"
  echo "oob: stopped."
}

case "${1:-}" in
  ensure) cmd_ensure ;;
  backend) cmd_backend ;;
  start) cmd_start ;;
  payload) cmd_payload ;;
  poll) shift; cmd_poll "${1:-}" ;;
  stop) cmd_stop ;;
  *) echo "usage: oob.sh {ensure|backend|start|payload|poll [marker]|stop}" >&2; exit 2 ;;
esac
