Superblock budget consistency
----------------------------

An accepted scheduled superblock now records its inherited adaptive budget when
payments are disabled by `SPORK_9_SUPERBLOCKS_ENABLED`. This makes live processing
perform the same budget transition as historical sync and replay. The ordinary
reward limit still applies while payments are disabled, and check-only validation
does not record a transition. Updates use the existing budget cache and persistence
barriers; no new per-block synchronization or Geth change is introduced.

This corrects an inherited validation-state defect. Older live nodes could omit
the budget row and later use the default instead of a non-default inherited value,
changing a subsequent superblock's amount limit. The fix applies when blocks are
connected or reconnected; it does not automatically repair existing missing rows
or later budgets derived from them. Historical public-chain occurrence has not
been established.

Before rollout, potentially affected live stores need comparison against a
controlled full `-reindex` or clean resync from validated history, with agreement
on the resulting budget. Reindexing also rebuilds paired auxiliary state. Do not
assume that upgrading the binary alone reconciles existing budget histories, or
that mixed old and new live nodes necessarily enforce the same later amount limit.
