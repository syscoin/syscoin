#!/usr/bin/env bash
# Exercise range selection against disposable shallow repositories, not Core.
set -euo pipefail
script=$(cd "$(dirname "$0")" && pwd)/test_each_commit_range.sh
sandbox=$(mktemp -d "${TMPDIR:-/tmp}/sentry-commit-range.XXXXXX")
trap 'rm -rf -- "$sandbox"' EXIT
source_repo="$sandbox/source"
git init -q -b main "$source_repo"
git -C "$source_repo" config user.name "Range test"
git -C "$source_repo" config user.email "range-test@example.invalid"
git -C "$source_repo" config commit.gpgsign false
commit() { git -C "$source_repo" commit -q --allow-empty -m "$1"; git -C "$source_repo" rev-parse HEAD; }
base=$(commit base)
one=$(commit one)
check() {
  local name=$1 head=$2 limit=$3 expected=$4 clone="$sandbox/$1"
  git -C "$source_repo" branch -f "$name" "$head"
  git clone -q --no-local --depth=2 --branch "$name" "file://$source_repo" "$clone"
  local actual
  actual=$(cd "$clone" && bash "$script" "$base" "$head" "$limit")
  [[ "$actual" == "$expected" ]] || {
    printf '%s range mismatch\nExpected:\n%s\nActual:\n%s\n' "$name" "$expected" "$actual" >&2
    exit 1
  }
  if (cd "$clone" && bash "$script" "$base" "$head" 999999999999999999999) >/dev/null 2>&1; then
    echo "Invalid maximum count was accepted" >&2
    exit 1
  fi
  while read -r selected; do
    [[ -n "$selected" ]] || continue
    git -C "$clone" checkout -q --detach "$selected"
    [[ "$(git -C "$clone" rev-parse HEAD)" == "$selected" ]]
  done <<< "$actual"
  git -C "$clone" checkout -q --detach "$head"
  [[ "$(git -C "$clone" rev-parse HEAD)" == "$head" ]]
  printf '%s: passed\n' "$name"
}
check single "$one" 6 ""
two=$(commit two)
three=$(commit three)
check linear "$three" 6 "$(printf '%s\n%s' "$one" "$two")"
history=("$one" "$two" "$three")
for i in 4 5 6 7 8 9; do history+=("$(commit "commit-$i")"); done
check bounded "${history[8]}" 3 "$(printf '%s\n%s\n%s' "${history[5]}" "${history[6]}" "${history[7]}")"
git -C "$source_repo" checkout -q -b feature "$two"
feature=$(commit feature)
git -C "$source_repo" checkout -q main
git -C "$source_repo" merge -q --no-ff -m merge-feature feature
merged=$(git -C "$source_repo" rev-parse HEAD)
expected=$(git -C "$source_repo" rev-list --topo-order --reverse --max-count=6 "$merged^@" "^$base" --)
check merged "$merged" 6 "$expected"

# Deterministic fetch-budget boundary: the missing merge base appears only
# after the eighth deepen. Export a shell function instead of creating a large
# history or reaching a network remote.
(
  git() {
    case "$1" in
      cat-file) return 0 ;;
      merge-base) [[ "$RANGE_TEST_FETCHES" -ge 8 ]] ;;
      rev-parse)
        if [[ "$2" == --git-path ]]; then printf '/dev/null\n';
        else printf 'true\n'; fi ;;
      fetch) RANGE_TEST_FETCHES=$((RANGE_TEST_FETCHES + 1)) ;;
      rev-list) printf '%040d\n' 2 ;;
      *) echo "Unexpected fake git command: $*" >&2; return 1 ;;
    esac
  }
  export -f git
  export RANGE_TEST_FETCHES=0
  actual=$(bash "$script" "$(printf '%040d' 1)" "$(printf '%040d' 3)" 6)
  [[ "$actual" == "$(printf '%040d' 2)" ]]
  printf 'last-budgeted-fetch: passed\n'
)

