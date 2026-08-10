#!/usr/bin/env bash
# whitebox.sh — white-box source preparation for the Umbra engagement (Module C).
#
# Gives agents read-only access to a target's source so recon/solvers can do
# source-level review and variant analysis (find a bug, then sweep for its siblings).
#
# Usage:
#   whitebox.sh prepare <repo-url-or-local-path> [ref]   # -> prints the read-only source path
#   whitebox.sh info <path>                              # -> compact inventory (langs, LOC, manifests)
#
# Clones (git URL) go to $UMBRA_SRC_DIR/<name> (default ./.umbra/src). Local paths are used in place.
set -euo pipefail

SRC_ROOT="${UMBRA_SRC_DIR:-${PWD}/.umbra/src}"

cmd_prepare() {
  local repo="${1:-}" ref="${2:-}"
  [ -n "$repo" ] || { echo "usage: whitebox.sh prepare <repo-url-or-local-path> [ref]" >&2; exit 2; }
  # Local path: use in place (read-only intent).
  if [ -d "$repo" ]; then
    (cd "$repo" && pwd); return 0
  fi
  command -v git >/dev/null 2>&1 || { echo "whitebox: git not available." >&2; exit 1; }
  mkdir -p "$SRC_ROOT"
  local name; name="$(basename "${repo%.git}")"
  local dest="$SRC_ROOT/$name"
  if [ -d "$dest/.git" ]; then
    echo "whitebox: already cloned at $dest (reusing)." >&2; echo "$dest"; return 0
  fi
  local args=(clone --depth 1 --single-branch)
  [ -n "$ref" ] && args+=(--branch "$ref")
  echo "whitebox: cloning $repo${ref:+ @ $ref} (shallow) ..." >&2
  if ! git "${args[@]}" "$repo" "$dest" >&2 2>&1; then
    # ref may be a commit SHA (can't --branch to it): full-ish clone then checkout
    rm -rf "$dest"
    git clone "$repo" "$dest" >&2 2>&1 || { echo "whitebox: clone failed." >&2; exit 1; }
    [ -n "$ref" ] && (cd "$dest" && git checkout -q "$ref") || true
  fi
  echo "$dest"
}

cmd_info() {
  local path="${1:-}"
  [ -d "$path" ] || { echo "usage: whitebox.sh info <existing-path>" >&2; exit 2; }
  python3 - "$path" <<'PY'
import os,sys,collections
root=sys.argv[1]
SKIP={'.git','node_modules','vendor','dist','build','.venv','venv','__pycache__','.next','target'}
ext=collections.Counter(); loc=collections.Counter(); files=0; total_loc=0
manifests=[]
MAN={'package.json','requirements.txt','pyproject.toml','go.mod','Gemfile','pom.xml','build.gradle',
     'composer.json','Cargo.toml','pom.properties','Dockerfile','requirements-dev.txt'}
for dp,dns,fns in os.walk(root):
    dns[:]=[d for d in dns if d not in SKIP]
    for f in fns:
        files+=1
        if f in MAN: manifests.append(os.path.relpath(os.path.join(dp,f),root))
        e=os.path.splitext(f)[1].lower() or '(none)'
        ext[e]+=1
        if e in {'.py','.js','.ts','.jsx','.tsx','.go','.rb','.java','.php','.rs','.c','.cpp','.cs','.sh','.html'}:
            try:
                with open(os.path.join(dp,f),errors='ignore') as fh:
                    n=sum(1 for _ in fh); loc[e]+=n; total_loc+=n
            except Exception: pass
print(f"path: {root}")
print(f"files: {files}   code LOC (approx): {total_loc}")
print("top extensions: "+", ".join(f"{k}:{v}" for k,v in ext.most_common(10)))
print("code LOC by lang: "+", ".join(f"{k}:{v}" for k,v in loc.most_common(8)))
print("manifests: "+(", ".join(sorted(set(manifests))[:12]) or "(none found)"))
PY
}

case "${1:-}" in
  prepare) shift; cmd_prepare "${1:-}" "${2:-}" ;;
  info) shift; cmd_info "${1:-}" ;;
  *) echo "usage: whitebox.sh {prepare <repo|path> [ref]|info <path>}" >&2; exit 2 ;;
esac
