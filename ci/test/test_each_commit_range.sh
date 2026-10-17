#!/usr/bin/env bash
# Return original PR ancestors (oldest first), excluding the separately-tested
# final head. Never rebase/rewrite the detached checkout used by Actions.
set -euo pipefail

base=${1:?base commit is required}
head=${2:?head commit is required}
max_count=${3:-6}
[[ "$base" =~ ^[0-9a-fA-F]{40}$ && "$head" =~ ^[0-9a-fA-F]{40}$ ]] ||
  { echo "Expected full base and head commit hashes" >&2; exit 1; }
[[ "$max_count" =~ ^([1-9]|[1-9][0-9]|100)$ ]] ||
  { echo "Invalid maximum commit count" >&2; exit 1; }
git cat-file -e "$head^{commit}"

# Checkout depth normally includes the PR and its fork point. Fetch the
# explicit base as well: a shallow checkout need not contain a merge commit.
depth=32
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth="$depth" origin "$base" "$head" >&2
fi
for attempt in 1 2 3 4 5 6 7 8; do
  incomplete=false
  git merge-base "$base" "$head" >/dev/null || incomplete=true
  shallow_file=$(git rev-parse --git-path shallow)
  if [[ -s "$shallow_file" ]] &&
     git rev-list "$head" "^$base" -- | grep -Fxf "$shallow_file" >/dev/null; then
    incomplete=true
  fi
  if [[ "$incomplete" == false ]]; then
    git rev-list --topo-order --reverse --max-count="$max_count" "$head^@" "^$base" --
    exit 0
  fi
  if [[ "$(git rev-parse --is-shallow-repository)" != true ]]; then
    echo "Base and head do not have a common ancestor" >&2
    exit 1
  fi
  git fetch --no-tags --deepen="$depth" origin "$base" "$head" >&2
  depth=$((depth * 2))
done
echo "Could not establish the complete PR range within the fetch budget" >&2
exit 1

