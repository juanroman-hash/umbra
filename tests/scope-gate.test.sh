#!/usr/bin/env bash
# Regression tests for hooks/scope-gate.sh.
#
# The scope gate is a guardrail: it exists to stop a KNOWN network binary
# (nmap/curl/ssh/...) from touching a host outside the authorized allowlist.
# Commands with no network binary are none of its business and must pass — this
# suite exists because the gate used to mis-parse ordinary dev tokens
# (.gitignore, git ref ranges, Package.swift) as "hosts" and block plain git.
#
# Usage: bash tests/scope-gate.test.sh   (needs bash + jq)
set -u

HOOK="$(cd "$(dirname "$0")/.." && pwd)/hooks/scope-gate.sh"
pass=0; fail=0

# run <expected_exit> <workdir> <command>
run() {
  local want="$1" dir="$2" cmd="$3" got
  ( cd "$dir" && printf '%s' "$cmd" | jq -Rs '{tool_input:{command:.}}' | bash "$HOOK" >/dev/null 2>&1 )
  got=$?
  if [ "$got" -eq "$want" ]; then
    pass=$((pass+1)); # printf 'ok   (exit %s) %s\n' "$got" "$cmd"
  else
    fail=$((fail+1)); printf 'FAIL want=%s got=%s : %s\n' "$want" "$got" "$cmd"
  fi
}

ALLOW=0; DENY=2

# ---- Scenario 1: NOT an engagement (no .umbra/scope.txt). ---------------------
NOSCOPE="$(mktemp -d)"
# Commands with no network binary must ALWAYS pass, dotted dev tokens and all.
run $ALLOW "$NOSCOPE" 'git commit -m "fix stuff"'
run $ALLOW "$NOSCOPE" 'git add .gitignore'
run $ALLOW "$NOSCOPE" 'git log fd92d82..HEAD'
run $ALLOW "$NOSCOPE" 'git commit -m "bump Package.swift and app.module.ts"'
run $ALLOW "$NOSCOPE" 'git clone https://github.com/foo/bar'
run $ALLOW "$NOSCOPE" 'ls -la'
run $ALLOW "$NOSCOPE" 'cat notes.md'
run $ALLOW "$NOSCOPE" 'python3 build.py --out dist.app'
# A real network binary with no established scope must still be refused.
run $DENY  "$NOSCOPE" 'nmap stagingbox'
run $DENY  "$NOSCOPE" 'curl http://evil.example'

# ---- Scenario 2: active engagement with a scope allowlist. --------------------
SCOPED="$(mktemp -d)"
mkdir -p "$SCOPED/.umbra"
printf 'stagingbox\n10.10.0.0/24\napp.example.com\n' > "$SCOPED/.umbra/scope.txt"
# In-scope network usage is allowed.
run $ALLOW "$SCOPED" 'nmap stagingbox'
run $ALLOW "$SCOPED" 'nmap -p 80 stagingbox'
run $ALLOW "$SCOPED" 'curl http://app.example.com/health'
run $ALLOW "$SCOPED" 'nmap 10.10.0.5'
run $ALLOW "$SCOPED" 'ssh ::1'
# Out-of-scope / unresolvable / file-list targets are blocked.
run $DENY  "$SCOPED" 'nmap internalbox'
run $DENY  "$SCOPED" 'curl http://evil.example'
run $DENY  "$SCOPED" 'nmap 10.20.0.5'
run $DENY  "$SCOPED" 'nmap -iL hosts.txt'
run $DENY  "$SCOPED" 'nmap'
# Ordinary dev commands stay allowed mid-engagement too.
run $ALLOW "$SCOPED" 'git add .gitignore'
run $ALLOW "$SCOPED" 'git commit -m "touch Package.swift"'

echo "----------------------------------------"
printf 'passed: %s   failed: %s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
