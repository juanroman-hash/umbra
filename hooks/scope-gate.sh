#!/usr/bin/env bash
# PreToolUse hook (matcher: Bash). Enforces the engagement scope allowlist.
#
# Reads the tool call from stdin (JSON on the hook's stdin). Extracts the Bash
# command, pulls out anything that looks like a host / IP / URL, and blocks the
# call if a target is present that is NOT covered by .umbra/scope.txt.
#
# Exit 0 = allow. Exit 2 = block (message on stderr shown to the model).
#
# DEFAULT-DENY MODEL (hardened):
#   * A curated list of "network binaries" (nmap, nc, ssh, curl, wget, hydra,
#     sqlmap, nikto, gobuster, ffuf, masscan, telnet, ping, dig, host,
#     metasploit/msfconsole, ...) is recognised anywhere in the command.
#   * When a network binary is invoked we extract candidate targets INCLUDING
#     bare single-label hosts (e.g. `nmap internalbox`) and IPv6 literals
#     (e.g. `ssh ::1`), not just dotted FQDNs / IPv4 / URLs.
#   * Every extracted target must resolve in-scope (or be loopback) or we BLOCK.
#   * If a network binary runs but NO in-scope target can be resolved at all, we
#     BLOCK rather than falling through to allow (this closes the old bypass
#     where an undetected target silently exited 0).
#   * File-list target args (-iL / -iR / --target-file / nmap|masscan -i) are
#     refused outright: their contents cannot be scope-checked inline.
#   * Loopback / localhost is always permitted (agent-browser + sandbox reach it).
#
# Non-network commands with no detectable target (e.g. `ls`, `cat`) are allowed.
# Any dotted host / IP / URL out of scope is blocked regardless of the binary.
#
# Expected behaviour (inline test cases):
#   nmap stagingbox                 -> ALLOW  (stagingbox in scope, single-label)
#   nmap internalbox               -> DENY   (single-label, not in scope)
#   nmap -p 80 stagingbox           -> ALLOW  (port skipped, host in scope)
#   ssh ::1                        -> ALLOW  (IPv6 loopback)
#   ssh fe80::1                    -> DENY   (IPv6 literal, not in scope)
#   curl http://stagingbox:3000     -> ALLOW  (URL host in scope)
#   curl stagingbox:3000            -> ALLOW  (host:port, host in scope)
#   nmap -iL hosts.txt             -> DENY   (file-list target arg refused)
#   nmap -iR 100                   -> DENY   (random targets refused)
#   nmap stagingbox evilbox         -> DENY   (evilbox not in scope)
#   nmap 10.10.0.5                 -> DENY   (unless 10.10.0.5 / a CIDR in scope)
#   nmap                           -> DENY   (network binary, no in-scope target)
#   ls -la                         -> ALLOW  (no network binary, no target)
set -euo pipefail

SCOPE_FILE=".umbra/scope.txt"

# Known network binaries. Basename-matched anywhere in the command so that
# `/usr/bin/nmap`, `sudo nmap`, and `sandbox.sh exec "nmap ..."` all trip it.
NET_BINS=" nmap ncat nc ssh curl wget hydra sqlmap nikto gobuster ffuf masscan telnet ping ping6 dig host metasploit msfconsole nping "

# Flags whose FOLLOWING token is a value (wordlist / output file / header / user
# / etc.), not a target host. Used to avoid mistaking a flag value for a host.
VALUE_FLAGS=" -oN -oX -oG -oA -oS -o -w -e -g -S -D -b -H -X -u -d -l -L -U -P -x -T -c -r -m -a -f -k -I --script --data --data-string --data-binary "

# Bare positional keywords that are subcommands / service modules / config keys,
# NOT hosts (gobuster `dir`, hydra `ssh`/`http-post-form`, msf `set`/`rhosts`…).
# Compared case-insensitively so `RHOSTS` matches. Prevents these words from
# being mistaken for out-of-scope single-label hosts.
POS_SKIP=" dir dns vhost fuzz s3 gcs tftp ssh ftp sftp http https http-get http-head http-post http-post-form http-get-form http-form smb smb2 rdp ldap ldap2 ldap3 mysql mssql postgres oracle vnc telnet smtp pop3 imap snmp sip rlogin rsh rexec redis mongodb use set setg run exploit check sessions search info back rhost rhosts lhost lport rport srvhost payload options show "

# Read hook payload
payload="$(cat)"

# Extract the command string (best-effort; works with jq if present)
if command -v jq >/dev/null 2>&1; then
  command_str="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null || true)"
else
  command_str="$payload"
fi
[ -z "$command_str" ] && exit 0

# ---------------------------------------------------------------------------
# Tokenise the command (bash-3.2 safe: no mapfile / no associative arrays).
# Quote and backtick characters become spaces so quoted sub-commands such as
# sandbox.sh exec "nmap stagingbox" split into individual tokens.
# ---------------------------------------------------------------------------
cleaned="$(printf '%s' "$command_str" | tr '"'"'"'`\t\n' '     ')"
TOKENS=()
set -f
old_ifs=$IFS
IFS=' '
for tok in $cleaned; do
  [ -n "$tok" ] && TOKENS+=("$tok")
done
IFS=$old_ifs
set +f

# Is a network binary present anywhere?
net_bin=""
if [ ${#TOKENS[@]} -gt 0 ]; then
  for tok in "${TOKENS[@]}"; do
    base="${tok##*/}"                     # strip any path -> basename
    case "$NET_BINS" in *" $base "*) net_bin="$base"; break;; esac
  done
fi

# Local-file extensions that are NOT valid TLDs. A schemeless dotted token that
# ends in one of these is a filename operand (notes.txt, wordlist.json), not a
# host, so it is NOT treated as a network target. Real ccTLD/gTLD suffixes
# (.sh, .md, .io, .app, .dev, .com, ...) are deliberately absent, so a genuine
# out-of-scope host such as `curl http://evil.sh` is still enforced.
FILE_EXTS=" txt log json yaml yml conf cfg ini csv tsv pcap bak tmp lock sql out html htm css xml toml env pem key crt gz tgz tar bz2 xz zip db sqlite dat bin so class jar war sh py js ts rb pl go rs php md yaml "

# ---------------------------------------------------------------------------
# (a) IPv4 + URL-host extraction (existing logic). URL hosts are captured via
#     the scheme-anchored grep so `http://evil.sh` is always scope-checked even
#     though `.sh` is excluded from the schemeless filename filter below.
# ---------------------------------------------------------------------------
url_ipv4="$( {
    printf '%s' "$command_str" \
      | grep -oE '(https?://)?([0-9]{1,3}\.){3}[0-9]{1,3}'
    printf '%s' "$command_str" \
      | grep -oE 'https?://[a-zA-Z0-9_.-]+'
  } | sed -E 's#https?://##; s#[:/].*$##' | sort -u || true )"

# Bracketed IPv6 host inside a URL: http://[::1]:8080 -> ::1
url_ipv6="$( printf '%s' "$command_str" \
    | grep -oE 'https?://\[[0-9A-Fa-f:]+\]' \
    | sed -E 's#https?://\[##; s#\]$##' | sort -u || true )"

TARGETS=()
while IFS= read -r line; do
  [ -n "$line" ] && TARGETS+=("$line")
done <<EOF
$url_ipv4
$url_ipv6
EOF

# Schemeless multi-label FQDN extraction, per token, so we can skip path/file
# operands. A token is treated as a host only when it: has no '/' (not a path),
# has no scheme (URLs handled above), is a dotted multi-label name, and does not
# end in a known local-file extension. This prevents filenames like
# `scripts/sandbox.sh`, `notes.txt`, `/usr/share/wl.txt` from being mistaken for
# hosts (which previously blocked every `sandbox.sh exec "..."` call).
if [ ${#TOKENS[@]} -gt 0 ]; then
  for tok in "${TOKENS[@]}"; do
    case "$tok" in
      */*|*://*) continue ;;                       # path or scheme -> handled elsewhere
    esac
    h="$tok"
    case "$h" in *:*) p="${h##*:}"; case "$p" in ''|*[!0-9]*) : ;; *) h="${h%:*}" ;; esac ;; esac
    case "$h" in
      *.*) : ;;                                     # must be dotted
      *) continue ;;
    esac
    # Reject anything with illegal host characters.
    case "$h" in *[!A-Za-z0-9.-]*) continue ;; esac
    # Final label must be alphabetic (a TLD), length >= 2.
    ext="${h##*.}"
    case "$ext" in *[!A-Za-z]*) continue ;; esac
    [ "${#ext}" -lt 2 ] && continue
    lext="$(printf '%s' "$ext" | tr 'A-Z' 'a-z')"
    case "$FILE_EXTS" in *" $lext "*) continue ;; esac  # local filename -> not a host
    TARGETS+=("$h")
  done
fi

# ---------------------------------------------------------------------------
# (b) Active-window scan: only arguments that belong to a network binary are
#     inspected for bare single-label hosts / IPv6 literals / file-list args.
#     A shell separator (; | & && || > <) closes the window; the next network
#     binary re-opens it. This way `nmap stagingbox | grep open` and
#     `nmap stagingbox; ls` are fine, while `nmap a && nmap evilbox` still has
#     `evilbox` checked. (A quoted resource-script's internal `;`, e.g.
#     msfconsole -x "...; set RHOSTS x; run", also closes the window — such
#     one-liners are conservatively refused; run them via `sandbox.sh shell`.)
# ---------------------------------------------------------------------------
if [ ${#TOKENS[@]} -gt 0 ]; then
  active=0        # inside a network binary's argument list?
  cur=""          # which network binary owns the current window
  skipval=0       # previous token was a value-taking flag: consume its value
  i=0
  n=${#TOKENS[@]}
  while [ $i -lt $n ]; do
    raw="${TOKENS[$i]}"

    # Split off the segment before any glued/standalone shell separator.
    seg="$raw"
    had_sep=0
    case "$raw" in *[\;\|\&\>\<]*) seg="${raw%%[;|&><]*}"; had_sep=1;; esac
    t="$seg"

    # Consume a value token belonging to a previous value-taking flag.
    if [ "$skipval" -eq 1 ] && [ -n "$t" ]; then
      skipval=0
      [ "$had_sep" -eq 1 ] && active=0
      i=$((i+1)); continue
    fi

    if [ -n "$t" ]; then
      base="${t##*/}"
      if case "$NET_BINS" in *" $base "*) true;; *) false;; esac; then
        # A network binary opens (or re-opens) the window.
        active=1; cur="$base"
        [ -z "$net_bin" ] && net_bin="$base"
        [ "$had_sep" -eq 1 ] && active=0
        i=$((i+1)); continue
      fi

      if [ "$active" -eq 1 ]; then
        # Refuse file-list / random-target args: their contents can't be
        # scope-checked inline, and -iR asks for *random* hosts.
        case "$t" in
          -iL|-iL=*|-iR|--target-file|--target-file=*|--infile|--infile=*)
            echo "scope-gate: BLOCKED — file-list target arg '$t' is not allowed; enumerate in-scope hosts explicitly (contents cannot be scope-checked)." >&2
            exit 2 ;;
        esac
        case "$cur" in
          nmap|masscan)
            case "$t" in
              -i|--input-file|--input-file=*)
                echo "scope-gate: BLOCKED — file-list target arg '$t' is not allowed for $cur; enumerate in-scope hosts explicitly." >&2
                exit 2 ;;
            esac ;;
        esac

        case "$t" in
          -*)
            # Flag: if value-taking, consume its value token next iteration.
            case "$VALUE_FLAGS" in *" $t "*) skipval=1;; esac ;;
          *)
            # Positional candidate. Unwrap [ipv6]:port, strip trailing :PORT.
            c="$t"
            case "$c" in \[*\]*) c="${c#\[}"; c="${c%%\]*}" ;; esac
            case "$c" in
              *::*) : ;;                               # IPv6 — keep colons
              *:*) p="${c##*:}"; case "$p" in ''|*[!0-9]*) : ;; *) c="${c%:*}" ;; esac ;;
            esac
            case "$c" in
              "") : ;;
              *::*)                                    # compressed IPv6 literal
                case "$c" in *[!0-9A-Fa-f:]*) : ;; *) TARGETS+=("$c") ;; esac ;;
              *[!0-9]*)                                # not purely numeric
                case "$c" in
                  *.*|*:*|*/*) : ;;                    # dotted/pathy/colon -> regex handled it
                  [A-Za-z0-9]*)                        # bare single-label host
                    case "$c" in
                      *[!A-Za-z0-9-]*) : ;;            # illegal host chars -> ignore
                      *)
                        lc="$(printf '%s' "$c" | tr 'A-Z' 'a-z')"
                        case "$POS_SKIP" in
                          *" $lc "*) : ;;              # subcommand/service/config key
                          *) TARGETS+=("$c") ;;
                        esac ;;
                    esac ;;
                esac ;;
              *) : ;;                                  # purely numeric -> port, skip
            esac ;;
        esac
      fi
    fi

    # A separator closes the current window.
    [ "$had_sep" -eq 1 ] && { active=0; skipval=0; }
    i=$((i+1))
  done
fi

# ---------------------------------------------------------------------------
# Load scope + matchers.
# ---------------------------------------------------------------------------
if [ ! -f "$SCOPE_FILE" ]; then
  if [ -n "$net_bin" ] || [ ${#TARGETS[@]} -gt 0 ]; then
    echo "scope-gate: no $SCOPE_FILE found, but command uses network tooling. Establish authorized scope first (see /pentest)." >&2
    exit 2
  fi
  exit 0
fi

# Portable read loop — avoids `mapfile`, which is bash 4+ (macOS ships bash 3.2).
scope=()
while IFS= read -r line; do
  [ -n "$line" ] && scope+=("$line")
done < <(grep -vE '^[[:space:]]*(#|$)' "$SCOPE_FILE" || true)

# Pure-bash IPv4 -> 32-bit int (empty on non-dotted-quad input).
ip2int() {
  local ip="$1" a b c d
  case "$ip" in
    *.*.*.*) IFS=. read -r a b c d <<< "$ip"
             for o in "$a" "$b" "$c" "$d"; do
               case "$o" in ''|*[!0-9]*) return 1;; esac
               [ "$o" -gt 255 ] && return 1
             done
             echo $(( (a<<24) + (b<<16) + (c<<8) + d )) ;;
    *) return 1 ;;
  esac
}

# True if IPv4 $1 is inside CIDR $2 (e.g. 10.0.0.5 in 10.0.0.0/24). Pure bash.
in_cidr() {
  local ip="$1" cidr="$2" net bits ipi neti mask
  net="${cidr%/*}"; bits="${cidr#*/}"
  case "$bits" in ''|*[!0-9]*) return 1;; esac
  [ "$bits" -gt 32 ] && return 1
  ipi="$(ip2int "$ip")" || return 1
  neti="$(ip2int "$net")" || return 1
  if [ "$bits" -eq 0 ]; then return 0; fi
  mask=$(( 0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF ))
  [ $(( ipi & mask )) -eq $(( neti & mask )) ]
}

in_scope() {
  local t="$1" entry
  [ ${#scope[@]} -eq 0 ] && return 1
  for entry in "${scope[@]}"; do
    # exact host/ip match
    [ "$t" = "$entry" ] && return 0
    # subdomain match (entry is a parent domain)
    case "$t" in *".$entry") return 0;; esac
    # IPv4 CIDR match (pure bash, no ipcalc dependency)
    case "$entry" in */*) in_cidr "$t" "$entry" && return 0;; esac
  done
  return 1
}

is_loopback() {
  case "$1" in localhost|127.0.0.1|::1|0:0:0:0:0:0:0:1) return 0;; esac
  case "$1" in 127.*) return 0;; esac
  return 1
}

# ---------------------------------------------------------------------------
# Enforce: every target must be in scope (or loopback), AND a network binary
# must resolve at least one in-scope/loopback target (default-deny).
# ---------------------------------------------------------------------------
inscope_hits=0
if [ ${#TARGETS[@]} -gt 0 ]; then
  # De-duplicate.
  uniq_targets="$(printf '%s\n' "${TARGETS[@]}" | sort -u)"
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    if is_loopback "$t"; then
      inscope_hits=$((inscope_hits+1)); continue
    fi
    if in_scope "$t"; then
      inscope_hits=$((inscope_hits+1))
    else
      echo "scope-gate: BLOCKED — '$t' is not in $SCOPE_FILE. In-scope only: ${scope[*]:-<empty>}" >&2
      exit 2
    fi
  done <<EOF
$uniq_targets
EOF
fi

# A network binary with no resolvable in-scope target is refused (default-deny):
# this catches bare single-label hosts we could not parse, stdin-fed targets, etc.
if [ -n "$net_bin" ] && [ "$inscope_hits" -eq 0 ]; then
  echo "scope-gate: BLOCKED — '$net_bin' invoked with no in-scope target resolved. Name an authorized host from $SCOPE_FILE explicitly. In-scope only: ${scope[*]:-<empty>}" >&2
  exit 2
fi

exit 0
