#!/usr/bin/env bash
# Prints code=false only if every file changed since $1 is documentation that no build or test step reads;
# anything else, or any doubt, prints code=true so CI runs everything. Used by .github/workflows/ci.yml.
set -euo pipefail
base="${1:-}"
all() { echo "ci-changes: $1, running everything" >&2; echo code=true; exit 0; }
[ -n "$base" ] && [ "$base" != 0000000000000000000000000000000000000000 ] || all "no base"
git cat-file -e "$base^{commit}" 2>/dev/null || all "base $base not in clone"
changed=$(git diff --name-only "$base" HEAD)
[ -n "$changed" ] || all "empty diff"
while IFS= read -r f; do
  case "$f" in
    *.md | docs/* | LICENSE | *.png | *.jpg | *.jpeg | *.gif | *.webp) ;;
    *) all "$f is not docs" ;;
  esac
done <<< "$changed"
echo code=false
