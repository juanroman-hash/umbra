#!/usr/bin/env bash
# Disposable Docker engagement sandbox — all offensive tooling runs in here,
# never on the host. An isolated, disposable worker node.
#
# Usage:
#   sandbox.sh up                 # build + start the container (egress-locked)
#   sandbox.sh exec "<command>"   # run a command inside the container
#   sandbox.sh shell              # interactive shell in the container
#   sandbox.sh egress             # (re)apply the in-scope egress allowlist
#   sandbox.sh down               # stop + remove the container
#   sandbox.sh status             # is it running?
#
# SECURITY MODEL
#   * The container runs on its OWN user-defined bridge network (isolated from
#     the default bridge and other containers), NOT on host networking.
#   * Egress is DEFAULT-DENY: at start we program the container's iptables
#     OUTPUT chain from .umbra/scope.txt so it can reach ONLY in-scope
#     destinations (plus loopback, its DNS resolver, and the Docker host gateway
#     for host-exposed in-scope apps). Everything else is dropped, IPv4 and
#     IPv6. This still lets us pentest arbitrary IN-SCOPE hosts.
#   * Hardening: --cap-drop=ALL, --security-opt no-new-privileges, --pids-limit,
#     --memory. NET_ADMIN is added only so the startup firewall can be written;
#     add NET_RAW (for `nmap -sS` etc.) via UMBRA_SANDBOX_CAPS=NET_RAW.
#   * agent-browser runs on the HOST and is unaffected by container egress; the
#     container can still reach host-exposed localhost apps via the host gateway.
#
# ENV KNOBS
#   UMBRA_SANDBOX_BASE     base image (default kalilinux/kali-rolling)
#   UMBRA_SANDBOX_HEAVY=1  also install metasploit-framework (large)
#   UMBRA_SANDBOX_EGRESS   'off' disables the egress firewall (full net on the
#                            dedicated bridge); default on
#   UMBRA_SANDBOX_CAPS     comma list of extra caps to --cap-add (e.g. NET_RAW)
#   UMBRA_SANDBOX_MEMORY   memory limit (default 2g)
#   UMBRA_SANDBOX_PIDS     pids limit (default 512)
#   UMBRA_SANDBOX_USER     run tools as this user (default root; root is
#                            required for the firewall and raw sockets)
set -euo pipefail

CONTAINER="umbra-sandbox"
IMAGE="umbra-sandbox:latest"
NETWORK="umbra-net"
# Kali rolling gives the usual offensive toolset; swap for your own base if desired.
BASE_IMAGE="${UMBRA_SANDBOX_BASE:-kalilinux/kali-rolling}"
WORKDIR="$(pwd)/.umbra/sandbox-work"
SCOPE_SRC="$(pwd)/.umbra/scope.txt"

EGRESS="${UMBRA_SANDBOX_EGRESS:-on}"
MEMORY="${UMBRA_SANDBOX_MEMORY:-2g}"
PIDS="${UMBRA_SANDBOX_PIDS:-512}"
EXTRA_CAPS="${UMBRA_SANDBOX_CAPS:-}"
RUN_USER="${UMBRA_SANDBOX_USER:-}"

build_image() {
  mkdir -p "$WORKDIR"
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  echo "[sandbox] building $IMAGE from $BASE_IMAGE ..."
  # Base offensive toolset + iptables/dns tooling required for the egress lock.
  # metasploit-framework is large, so it is opt-in via UMBRA_SANDBOX_HEAVY=1.
  local heavy=""
  if [ "${UMBRA_SANDBOX_HEAVY:-0}" = "1" ]; then
    heavy="metasploit-framework"
  fi
  docker build -t "$IMAGE" -f - . <<EOF
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nikto whatweb gobuster ffuf sqlmap hydra masscan \
    netcat-traditional curl wget dnsutils iputils-ping telnet \
    exploitdb iptables ca-certificates ${heavy} && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
EOF
}

ensure_network() {
  if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    docker network create "$NETWORK" >/dev/null
    echo "[sandbox] created isolated network $NETWORK"
  fi
}

# Program the container's OUTPUT firewall from .umbra/scope.txt so it may only
# reach in-scope destinations. Runs inside the container (needs NET_ADMIN).
apply_egress() {
  if [ "$EGRESS" = "off" ]; then
    echo "[sandbox] UMBRA_SANDBOX_EGRESS=off — egress NOT restricted"
    return 0
  fi
  docker exec -i "$CONTAINER" bash -s <<'SEED'
set -u
if ! command -v iptables >/dev/null 2>&1; then
  echo "[sandbox] iptables missing in image; egress NOT restricted (rebuild: sandbox.sh down && docker rmi umbra-sandbox:latest && sandbox.sh up)" >&2
  exit 0
fi
# Confirm we can actually program netfilter (root + NET_ADMIN); otherwise every
# rule would silently fail and we would falsely claim the egress was locked.
if ! iptables -L OUTPUT >/dev/null 2>&1; then
  echo "[sandbox] cannot program iptables (need root + NET_ADMIN); egress NOT restricted" >&2
  exit 1
fi
SCOPE=/umbra/scope.txt

# Start permissive so hostnames in scope can be resolved, then lock down.
iptables -F OUTPUT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Baseline allowances: loopback (incl. Docker embedded DNS 127.0.0.11) and
# already-established connections.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# DNS to whatever resolvers the container is configured with.
for ns in $(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null); do
  iptables -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT 2>/dev/null || true
  iptables -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT 2>/dev/null || true
done

# Docker host gateway — lets us reach host-exposed in-scope apps (localhost:PORT).
hg="$(getent ahostsv4 host.docker.internal 2>/dev/null | awk '{print $1; exit}')"
if [ -n "${hg:-}" ]; then
  iptables -A OUTPUT -d "$hg" -j ACCEPT
  echo "[egress] allow host-gateway $hg"
fi

# In-scope destinations.
if [ -f "$SCOPE" ]; then
  while IFS= read -r raw; do
    line="$(printf '%s' "$raw" | sed -E 's/#.*//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
    [ -z "$line" ] && continue
    [ "$line" = "localhost" ] && continue
    if printf '%s' "$line" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
      iptables -A OUTPUT -d "$line" -j ACCEPT && echo "[egress] allow $line"
    else
      resolved=0
      for ip in $(getent ahostsv4 "$line" 2>/dev/null | awk '{print $1}' | sort -u); do
        iptables -A OUTPUT -d "$ip" -j ACCEPT && echo "[egress] allow $line -> $ip" && resolved=1
      done
      [ "$resolved" = "0" ] && echo "[egress] note: '$line' did not resolve in-container (reachable via host-gateway if host-exposed)"
    fi
  done < "$SCOPE"
else
  echo "[sandbox] no $SCOPE mounted — locking egress to loopback/DNS/host-gateway only" >&2
fi

# Default deny for everything else.
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null \
  || iptables -A OUTPUT -j DROP
iptables -P OUTPUT DROP 2>/dev/null || true

# Lock down IPv6 egress entirely (loopback + established only) to prevent a
# v6 bypass of the v4 allowlist.
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -F OUTPUT 2>/dev/null || true
  ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  ip6tables -P OUTPUT DROP 2>/dev/null || true
fi

echo "[sandbox] egress locked to in-scope destinations"
SEED
}

start_container() {
  build_image
  ensure_network

  # Assemble hardened run args.
  RUN_ARGS=(run -d --name "$CONTAINER" --network "$NETWORK")
  RUN_ARGS+=(--cap-drop=ALL --security-opt no-new-privileges)
  RUN_ARGS+=(--pids-limit "$PIDS" --memory "$MEMORY")
  RUN_ARGS+=(--add-host host.docker.internal:host-gateway)
  RUN_ARGS+=(-v "$WORKDIR:/work")
  # Mount scope read-only so the egress firewall can seed itself.
  if [ -f "$SCOPE_SRC" ]; then
    RUN_ARGS+=(-v "$SCOPE_SRC:/umbra/scope.txt:ro")
  fi
  # NET_ADMIN is needed to write the startup firewall.
  if [ "$EGRESS" != "off" ]; then
    RUN_ARGS+=(--cap-add=NET_ADMIN)
  fi
  # Extra opt-in caps (e.g. NET_RAW for SYN scans).
  if [ -n "$EXTRA_CAPS" ]; then
    local c
    for c in $(printf '%s' "$EXTRA_CAPS" | tr ',' ' '); do
      [ -n "$c" ] && RUN_ARGS+=(--cap-add="$c")
    done
  fi
  # Optional non-root user (root is the default; required for firewall/raw).
  if [ -n "$RUN_USER" ]; then
    RUN_ARGS+=(--user "$RUN_USER")
  fi
  RUN_ARGS+=("$IMAGE" sleep infinity)

  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker "${RUN_ARGS[@]}" >/dev/null
  echo "[sandbox] started $CONTAINER"
  apply_egress
}

cmd="${1:-status}"
case "$cmd" in
  up)
    if docker ps -q -f name="^${CONTAINER}$" | grep -q .; then
      echo "[sandbox] already running"
    else
      start_container
    fi
    ;;
  exec)
    shift
    docker exec "$CONTAINER" bash -lc "$*"
    ;;
  shell)
    docker exec -it "$CONTAINER" bash
    ;;
  egress)
    apply_egress
    ;;
  down)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    echo "[sandbox] removed"
    ;;
  status)
    if docker ps -q -f name="^${CONTAINER}$" | grep -q .; then
      echo "running"
    else
      echo "stopped"
    fi
    ;;
  *)
    echo "usage: sandbox.sh {up|exec \"<cmd>\"|shell|egress|down|status}" >&2
    exit 2
    ;;
esac
