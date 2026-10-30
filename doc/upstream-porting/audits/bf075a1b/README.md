# Marker audit after the pruning annotations

Bitcoin comparison baseline: `e4fef4ae65c68ebd34774700dc4801c24313d469` (26.0rc3).
Syscoin source target: `bf075a1b7848be48d856338cacd5ac53f4cca9f9`.
Immediate pre-marker target: `ece75c4059cc2d48c4f9a0a390ad5ad328c9aa55`.

This snapshot refreshes the fork-marker inventory after the comment-only
pruning annotations. It does not replace the [original audit](../d5fc88ad/README.md)
or the [original annotation snapshot](../6f325c40/README.md).
The scan is pinned to the source commit before these documentation and report
files were added; its file count intentionally excludes this new snapshot.

- [Current summary](results/summary.json)
- [Candidate file index](results/inventory.md)
- [Full before/after inventory, gzip-compressed JSON](results/audit.json.gz)
- [Immediate pre-marker summary](results/pre-marker-summary.json)
- [Comment-only verification](annotation-verification.json)

The scanner inventories 3,582 files and reports 1,403 production review
candidates: 803 with no detected marker, 506 partly marked or ambiguous, and
94 removals without marker context. The immediate pre-marker scan reports
1,410 candidates. Both scans report zero marker-structure issues.

All 95,541 non-comment C++ tokens in the three files changed by the marker
commit are identical at both endpoints. The scanner's 13 regression tests
pass. This is marker coverage, not runtime test coverage or proof that every
remaining candidate needs a tag. The count reduction reflects lexical hunk
classification; it is not a count of fixed runtime defects.

Reproduce the source comparison from the repository root:

```sh
python3 -B contrib/devtools/syscoin-upstream-audit/audit.py \
  --repo . \
  --upstream e4fef4ae65c68ebd34774700dc4801c24313d469 \
  --target bf075a1b7848be48d856338cacd5ac53f4cca9f9 \
  --output /tmp/syscoin-marker-bf075a1b
python3 -B contrib/devtools/syscoin-upstream-audit/test_audit.py
```

Use the immediate pre-marker target above to reproduce the comparison summary.
The compressed inventory uses an empty gzip filename and zero timestamp.
Its hashes and the scanner hash are recorded in `annotation-verification.json`.
