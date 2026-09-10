# Syscoin upstream marker audit

At Syscoin `d5fc88adc9992a25f26641ddb174a76e7bf64407`, the effective Bitcoin source baseline is **26.0rc3**, `e4fef4ae65c68ebd34774700dc4801c24313d469`, plus later selective imports. Existing SYSCOIN tags are incomplete: this audit manually confirmed **38 groups of missing or ambiguous boundaries** across consensus, network/storage/startup, RPC, wallet, and GUI code.

This is a provenance and merge-preparation audit. The findings do not assert runtime defects. The original audit was read-only. Its 38 verified groups were subsequently annotated; see the [annotation status](../../annotation-status.md). This snapshot preserves the findings and counts before those annotations.

## Read the results

- [baseline.md](baseline.md): exact Bitcoin/Syscoin import mapping, why merge-base is misleading, and known later backports.
- [consensus-review.md](consensus-review.md): 13 confirmed groups in validation, consensus, primitives, and mempool handling.
- [network-storage-review.md](network-storage-review.md): 15 confirmed groups in networking, storage, startup, and ZMQ.
- [rpc-wallet-review.md](rpc-wallet-review.md): 10 confirmed groups in wallet/PQ key handling, RPC schemas, AuxPoW, and peer details.
- [results/inventory.md](results/inventory.md): shared production files ranked by candidate hunk count.
- [results/porting-ledger.md](results/porting-ledger.md): moved/deleted Bitcoin context, all missing upstream paths, fork-only paths, and files needing separate non-C++ review.
- [results/audit.json.gz](results/audit.json.gz): complete file inventory and all substantive shared C/C++ candidate/marked hunks, including exact before/after text and line locations at both pinned commits.
- [results/summary.json](results/summary.json): machine-readable counts.
- [audit.py](../../../../contrib/devtools/syscoin-upstream-audit/audit.py) and [test_audit.py](../../../../contrib/devtools/syscoin-upstream-audit/test_audit.py): reproducible read-only scanner and focused regression fixtures.

All manual finding line numbers refer to the pinned Syscoin commit, so later comment insertions will shift them. Use the named function and the pinned diff together when applying changes.

## What the scan covered

The file inventory covers all **3,454 tracked files** at the target. Exact-path matches and Bitcoin-to-Syscoin product-path renames are compared. File content is classified as follows:

| Comparison result | All tracked files | Production C/C++ files, excluding vendor trees |
| --- | ---: | ---: |
| Changed beyond product renaming | 687 | 244 |
| Identical contents | 1,113 | 130 |
| Product-name substitutions only | 779 | 297 |
| No matching upstream path | 856 | 216 |
| Binary difference | 19 | 0 |

The 244 shared production files have differences beyond product renaming; this includes files whose remaining differences are only comments or formatting. Substantive C/C++ hunk analysis then removes those comment/format-only differences. Tests receive a separate hunk inventory.

The production hunk scan reports **862 candidates with no detected marker**, **473 partly marked or ambiguous hunks**, and **94 removed-code hunks without detected marker context**. These total **1,429 review candidates**, not 1,429 proven missing tags. It also records 672 hunks with a local syntax-bounded marker, 57 inside explicit regions, and 13 removals with detected marker context. Marked hunks remain in the JSON because the actual diff, not the presence of a tag, is the evidence a future merge needs.

The manual 38-group review is a verified subset, not a complete disposition of the 1,429 candidates. A group can cover multiple hunks. Bare legacy tags, hunk boundaries, relocated code, and later upstream imports require judgment.

## Highest-value annotation work

| Area | Examples confirmed by manual review | Why the boundary matters during a merge |
| --- | --- | --- |
| Consensus and block representation | Bitcoin-specific BIP30 checks removed/disabled; AuxPoW header split; money/asset accounting; PoDA size/rejection rules | A syntactically successful merge could otherwise restore Bitcoin assumptions that this fork intentionally changes. |
| NEVM recovery and storage | Startup candidate filtering; repair APIs and dispatch; payload replacement/adoption; reindex completion moved after activation | Both the additions and their ordering relative to retained Bitcoin operations must remain visible. |
| Networking and ZMQ | Governance-page methods, variable-size headers, masternode connection hooks, NEVM request-socket lifecycle | New helpers need boundaries, and the integration points inside upstream functions need their own small annotations. |
| Wallet and RPC | PQ voting-key persistence/encryption/salvage rules, verifychain restriction, AuxPoW JSON, fork transaction schemas | A distant include marker does not cover these independent adaptations. |

There is also one explicit marker-structure issue: `src/validation.cpp:5676` has a legacy `// END SYSCOIN` without an explicit BEGIN. The intended block appears to start at the descriptive SYSCOIN comment near line 5600. Normalize that pair only after confirming its scope; the tool does not invent a broad region.

## Conventions for a later annotation pass

Use an explicit pair for a complete fork addition or a coherent replacement of upstream behavior:

```cpp
// SYSCOIN BEGIN: Explain the fork rule or integration point.
// Existing implementation, with no runtime changes in a tagging pass.
// SYSCOIN END: Explain the fork rule or integration point.
```

For a changed signature, enum entry, include, or one-line call, an adjacent or inline SYSCOIN comment can be enough. Keep upstream code recognizable inside a modified function. When a region wraps retained Bitcoin processing, say that it modifies the processing rather than suggesting all the enclosed code was newly authored by Syscoin.

For deleted or relocated Bitcoin code, retain a concise comment at the former location explaining what happened, with the old call commented out when useful and the new location named. The latest pruning cleanup marker already does this. Do not reintroduce old executable code. The exact original code is also preserved in the pinned before/after hunk ledger.

Use SYSCOIN here as a fork-maintenance marker, not as an authorship claim. Preserve existing Bitcoin, Dash, AuxPoW, and third-party attribution. Later Bitcoin backports should carry upstream provenance instead of being blindly labelled as fork behavior.

## Reproduce or update the scan

The full JSON snapshot is stored with deterministic gzip compression to avoid checking out several megabytes of duplicated source text. Decompress it with `gzip -dc results/audit.json.gz > /tmp/syscoin-audit-d5fc88ad.json`, or regenerate it with the scanner.

The scanner uses only Python's standard library and local Git objects. It never fetches, checks out, edits, commits, or pushes source. Obtain the Bitcoin objects separately if they are absent:

```sh
git -C /path/to/syscoin fetch --no-tags https://github.com/bitcoin/bitcoin.git refs/tags/v26.0:refs/audit/bitcoin-v26.0
python3 -B /path/to/audit.py \
  --repo /path/to/syscoin \
  --upstream e4fef4ae65c68ebd34774700dc4801c24313d469 \
  --target d5fc88adc9992a25f26641ddb174a76e7bf64407 \
  --output /path/to/new-audit-results
python3 -B /path/to/test_audit.py
```

The Syscoin target commit must also be available locally. For a later source revision, set `--target` to that commit; it defaults to HEAD. For another Bitcoin comparison, pass a locally available commit using `--upstream`. The scanner regenerates `audit.json`, `summary.json`, and `inventory.md`; the human review documents and curated porting ledger are snapshots that must be revisited separately.

Keep the historical baseline fixed while assessing how the fork changed. Before merging a newer Bitcoin version, inspect the changes from the historical Bitcoin baseline to the proposed new Bitcoin target alongside the fork-difference inventory. Retire a fork adaptation only after deciding how the new upstream behavior replaces it.

## Limits and verification

- Name normalization covers only `SYSCOIN/BITCOIN`, `Syscoin/Bitcoin`, and `syscoin/bitcoin`; currency amounts, BTC/SYS tokens, consensus constants, and network parameters are not normalized away.
- Marker coverage uses a lexical and syntax-boundary heuristic, not a C++ compiler or proof of semantic ownership. It handles comments, strings/raw strings, digit separators, nested markers, and deletion context. An explicit marker is evidence of an intended boundary, not proof that its scope is correct.
- Non-C++ files, build/configuration, translations, binary assets, and recognized vendor trees have a complete path/content-status inventory but no automatic semantic marker audit. Files without an upstream path are listed separately; some are moves or inherited third-party code, not necessarily original Syscoin additions. Path matching does not attempt arbitrary move detection.
- File-status classification concerns contents. It is not an executable-mode, licensing, dependency, security, or runtime behavior audit.
- The full comparison was rerun after scanner fixes, and all 13 focused scanner regression tests pass. Manual reports checked actual source and selected history. Production builds/tests were not rerun because the audit changes no production code.
