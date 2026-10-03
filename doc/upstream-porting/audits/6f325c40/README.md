# Audit after the verified annotation pass

Bitcoin baseline: `e4fef4ae65c68ebd34774700dc4801c24313d469`.
Syscoin target: `6f325c40e36e907cca735f70dc47ad00e4322f4b`.

This comparison follows the comments-only implementation of the 38 verified groups. See [annotation status](../../annotation-status.md) for their disposition and verification, and the [original audit](../d5fc88ad/README.md) for manual findings and provenance history.

- [Summary](results/summary.json)
- [Candidate file index](results/inventory.md)
- [Full before/after inventory, gzip-compressed JSON](results/audit.json.gz)

There are 1303 remaining production review candidates. They are not all proven missing tags. The full JSON retains marked hunks as well as candidates for future merge review. The source scan uses the annotated commit before the audit documentation and scanner were added to the repository.

Reproduce it from the repository root with:

```sh
python3 -B contrib/devtools/syscoin-upstream-audit/audit.py --repo . --target 6f325c40e36e907cca735f70dc47ad00e4322f4b --output /tmp/syscoin-annotated-audit
```
