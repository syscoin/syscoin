# Porting newer Bitcoin changes into Syscoin

The effective Bitcoin source baseline for the audited Syscoin commit `d5fc88adc9992a25f26641ddb174a76e7bf64407` is **Bitcoin 26.0rc3**, `e4fef4ae65c68ebd34774700dc4801c24313d469`, plus later selective imports. The [baseline ledger](audits/d5fc88ad/baseline.md) records the import mapping and known backport exceptions.

Use this history when identifying Syscoin adaptations. A normal merge-base points back to 2015 because later Bitcoin changes were replayed with different commit identities; it does not identify the source generation currently in this fork.

## Audit and annotation status

- [Historical audit at d5fc88ad](audits/d5fc88ad/README.md): 3,454 files inventoried, with hunk analysis of shared C/C++ production and test code. It records 38 manually verified groups of missing or ambiguous marker boundaries and a broader candidate queue.
- [Annotation status](annotation-status.md): disposition of those 38 groups, the comments-only change, verification, and the remaining candidate counts.
- [Porting ledger](audits/d5fc88ad/results/porting-ledger.md): removed/moved Bitcoin operations, unmatched paths, and non-C++ files that need a separate review.
- [Full historical inventory](audits/d5fc88ad/results/audit.json.gz): exact before/after source and pinned line locations, stored with deterministic gzip compression. This remains the original pre-annotation evidence.

The historical findings use line numbers at `d5fc88ad`. Later annotations shift those lines. Follow function names, the pinned commit, and the annotation record together; do not treat the old missing-marker descriptions as an assertion about the current source.

## Markers for fork adaptations

Mark a coherent fork addition or replacement with a short explanation and an explicit pair:

```cpp
// SYSCOIN BEGIN: Explain the fork rule or integration point.
// Existing implementation.
// SYSCOIN END: Explain the fork rule or integration point.
```

Use an adjacent or inline SYSCOIN comment for an isolated include, signature, enum entry, or call. In a modified upstream function, identify the individual integration points. If a region wraps retained Bitcoin processing, explain that modification rather than attributing the whole implementation to Syscoin.

When removing or moving a Bitcoin operation, keep a concise explanation at its former location. Preserve the original call as commented code where useful, and identify the replacement location or behavior. This is particularly important for persistence and activation ordering. Do not restore a deleted operation merely to make an upstream diff smaller.

SYSCOIN is a fork-maintenance marker, not an original-authorship claim. Preserve Bitcoin, Dash, AuxPoW, and third-party attribution. A later Bitcoin backport should retain its upstream provenance. A difference from rc3 alone does not prove it is a fork rule.

## Reproduce a comparison

The scanner uses Python's standard library and local Git objects. It reads committed source and writes reports to the chosen output directory. It does not fetch, check out, edit, commit, or push source.

If the Bitcoin objects are missing, fetch them separately:

```sh
git fetch --no-tags https://github.com/bitcoin/bitcoin.git refs/tags/v26.0:refs/audit/bitcoin-v26.0
```

From the repository root, compare the current committed source with the historical Bitcoin baseline:

```sh
python3 -B contrib/devtools/syscoin-upstream-audit/audit.py \
  --repo . \
  --upstream e4fef4ae65c68ebd34774700dc4801c24313d469 \
  --target HEAD \
  --output /tmp/syscoin-upstream-audit
python3 -B contrib/devtools/syscoin-upstream-audit/test_audit.py
```

Set `--target d5fc88adc9992a25f26641ddb174a76e7bf64407` to reproduce the archived audit. The target commit must be available locally. To compare with a different Bitcoin revision, pass its locally available commit using `--upstream`.

The outputs are `audit.json`, `summary.json`, and `inventory.md`. The human review documents and curated porting ledger are pinned snapshots; the scanner does not rewrite their conclusions. To read the archived full JSON without rerunning the comparison:

```sh
gzip -dc doc/upstream-porting/audits/d5fc88ad/results/audit.json.gz > /tmp/syscoin-audit-d5fc88ad.json
```

## Using the audit during a future port

1. Establish the new Bitcoin target and review its changes from the historical baseline.
2. Reconcile the known selective imports first, so an already imported patch is not mistaken for new fork behavior.
3. Compare changes in shared files against the annotated integration points and the original before/after ledger. Preserve or consciously replace each fork rule, especially removed operations and ordering constraints.
4. Review the remaining unmarked/ambiguous candidates. Keep generic or uncertain provenance unresolved until source history establishes its origin.
5. Run the tests appropriate to the actual port and create a new pinned audit snapshot after the source changes settle.

Marker detection is a lexical and syntax-boundary heuristic, not a compiler or proof of complete coverage. Candidate counts can change when hunk boundaries or marker scopes change. The scanner excludes pure product renames and comment/format-only hunks; build/configuration, Python tests, translations, vendor trees, binaries, and files without a matching upstream path are inventoried separately. The [historical report](audits/d5fc88ad/README.md) describes these limits in detail.
