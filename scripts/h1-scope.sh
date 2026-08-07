#!/usr/bin/env bash
# Pull a HackerOne program's structured scope into Umbra's engagement config.
#
#   HACKERONE_API_USERNAME=<token identifier> \
#   HACKERONE_API_TOKEN=<token value> \
#   scripts/h1-scope.sh <program-handle>
#
# Writes (into ./.umbra, which is gitignored):
#   .umbra/scope.txt  — in-scope, submittable URL/DOMAIN/IP/CIDR assets (wildcards
#                        are written commented-out; enumerate them to concrete hosts)
#   .umbra/rules.md   — a DRAFT Rules-of-Engagement from the program policy
#
# The token is read from the ENVIRONMENT ONLY — never hardcode it, never commit it.
# HackerOne uses HTTP Basic auth: identifier = username, value = password. Read-only.
# The API does NOT expose an "automation allowed" flag — you must read the policy and
# confirm automated testing is permitted before running an engagement.
set -euo pipefail

handle="${1:-}"
if [ -z "$handle" ]; then
  echo "usage: HACKERONE_API_USERNAME=… HACKERONE_API_TOKEN=… $0 <program-handle>" >&2
  exit 1
fi
# Convenience: load the token from a gitignored .umbra/h1.env if not already in the
# environment. Keep the secret in that file (never in a committed file or in chat).
if [ -f .umbra/h1.env ] && { [ -z "${HACKERONE_API_USERNAME:-}" ] || [ -z "${HACKERONE_API_TOKEN:-}" ]; }; then
  set -a; . .umbra/h1.env; set +a
fi
: "${HACKERONE_API_USERNAME:?set HACKERONE_API_USERNAME (your API token identifier) — in the env or .umbra/h1.env}"
: "${HACKERONE_API_TOKEN:?set HACKERONE_API_TOKEN (your API token value) — in the env or .umbra/h1.env}"
command -v jq >/dev/null 2>&1 || { echo "h1-scope: jq is required." >&2; exit 1; }

API="https://api.hackerone.com/v1/hackers"
AUTH=(-u "${HACKERONE_API_USERNAME}:${HACKERONE_API_TOKEN}" -H "Accept: application/json")

# Allow offline testing of the parser: H1_SCOPE_FIXTURE=<prog.json>:<scopes.json>
prog="" ; scopes_raw=""
if [ -n "${H1_SCOPE_FIXTURE:-}" ]; then
  prog="$(cat "${H1_SCOPE_FIXTURE%%:*}")"
  scopes_raw="$(jq -c '.data[]' "${H1_SCOPE_FIXTURE##*:}")"
else
  prog="$(curl -fsS "${AUTH[@]}" "${API}/programs/${handle}")" || {
    echo "h1-scope: could not fetch program '${handle}'. Check the handle, that your token is valid, and that you have access." >&2
    exit 1; }
  # structured_scopes is paginated (JSON:API) — follow links.next.
  url="${API}/programs/${handle}/structured_scopes?page%5Bsize%5D=100"
  while [ -n "$url" ] && [ "$url" != "null" ]; do
    page="$(curl -fsS "${AUTH[@]}" "$url")" || { echo "h1-scope: structured_scopes fetch failed." >&2; exit 1; }
    scopes_raw="${scopes_raw}$(printf '%s' "$page" | jq -c '.data[]')
"
    url="$(printf '%s' "$page" | jq -r '.links.next // ""')"
  done
fi

name="$(printf '%s' "$prog" | jq -r '.data.attributes.name // ""')"
state="$(printf '%s' "$prog" | jq -r '.data.attributes.submission_state // "unknown"')"
bounties="$(printf '%s' "$prog" | jq -r '.data.attributes.offers_bounties // false')"
policy="$(printf '%s' "$prog" | jq -r '.data.attributes.policy // "(no policy text returned by the API)"')"

mkdir -p .umbra

# In-scope, submittable, network-testable asset types → scope candidates (keep type).
IN_TYPES='["URL","DOMAIN","IP_ADDRESS","CIDR","OTHER_APK"]'
in_lines="$(printf '%s' "$scopes_raw" | jq -rs --argjson t "$IN_TYPES" '
  map(select(type=="object"))
  | map(select(.attributes.eligible_for_submission == true))
  | map(.attributes.asset_type as $a
        | select($a=="WILDCARD" or ($t|index($a)))
        | "\(.attributes.asset_type)\t\(.attributes.asset_identifier)")
  | unique | .[]' 2>/dev/null || true)"

oos_lines="$(printf '%s' "$scopes_raw" | jq -rs '
  map(select(type=="object"))
  | map(select(.attributes.eligible_for_submission == false)
        | "- \(.attributes.asset_type): \(.attributes.asset_identifier)")
  | unique | .[]' 2>/dev/null || true)"

# Normalize identifiers to hosts/CIDRs the sandbox egress can consume.
{
  echo "# Auto-generated from HackerOne program: ${handle} (${name})"
  echo "# submission_state=${state}  offers_bounties=${bounties}"
  echo "# REVIEW before use. Wildcards are commented out — enumerate them to concrete hosts."
  printf '%s\n' "$in_lines" | while IFS="$(printf '\t')" read -r typ id; do
    [ -z "${id:-}" ] && continue
    case "$typ" in
      WILDCARD) echo "# WILDCARD (enumerate): ${id}" ;;
      CIDR|IP_ADDRESS) echo "$id" ;;
      URL|DOMAIN)
        h="${id#*://}"; h="${h%%/*}"; h="${h%%:*}"
        case "$h" in *'*'*) echo "# WILDCARD (enumerate): ${h}" ;; "" ) : ;; *) echo "$h" ;; esac ;;
      *) echo "# ${typ} (review): ${id}" ;;
    esac
  done
} > .umbra/scope.txt

{
  echo "# Rules of Engagement — HackerOne: ${handle} (${name})"
  echo
  echo "> DRAFT auto-pulled from the HackerOne API. VERIFY every line against the live program"
  echo "> policy before testing. The API does NOT expose whether automated testing is allowed —"
  echo "> read the policy below and set the flag. Umbra must not run if automation is disallowed."
  echo
  echo "- submission_state: ${state}"
  echo "- offers_bounties: ${bounties}"
  echo "- Automated testing permitted? <READ POLICY BELOW — set YES / NO>"
  echo "- Required attribution header (if any): <put in .umbra/bounty.env>"
  echo "- Rate limit (if stated): <put in .umbra/bounty.env>"
  echo
  echo "## Out of scope (never touch)"
  if [ -n "$oos_lines" ]; then printf '%s\n' "$oos_lines"; else echo "- (none listed via API — still confirm in the policy)"; fi
  echo
  echo "## Program policy (verbatim from API)"
  echo
  printf '%s\n' "$policy"
} > .umbra/rules.md

n="$(grep -cvE '^[[:space:]]*(#|$)' .umbra/scope.txt || true)"
echo "h1-scope: wrote .umbra/scope.txt (${n} concrete in-scope entr$( [ "$n" = 1 ] && echo y || echo ies )) and .umbra/rules.md for '${handle}'."
echo "h1-scope: NEXT — review both files, confirm automated testing is permitted, fill .umbra/bounty.env, then run /pentest-bounty."
