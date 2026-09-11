# NEVM connect results

Core uses the trusted NEVM engine's request/reply endpoint configured by
`-zmqpubnevm`. This is separate from the public block and transaction PUB
notifications described in [zmq.md](zmq.md).

Before every `nevmconnect` request, Core sends the `nevmcomms` topic with the
serialized string `connect-v1` (CompactSize length byte `0x0a`, then ten ASCII
bytes). The engine must reply with exactly two frames: `nevmcomms` and
`connect-v1`. A generic `ack` does not establish support. Checking each time
also detects an engine replaced or restarted between requests.

The engine responds to `nevmconnect` with two frames. The first is
`nevmconnect`; the second is one of:

| Response | Meaning |
| --- | --- |
| `connected` | The engine accepted this request. During buffered sync this may only queue it; use `flush` and `nevmblockinfo` to verify the applied pair. |
| `invalid:<nevm-hash>:<sys-hash>` | A positively classified consensus failure for the indicated pair. |
| `payload-invalid:<nevm-hash>:<sys-hash>:<fingerprint>` | A rejected payload representation bound to the pair and exact supplied bytes; authorizes payload recovery, not block invalidation. |
| `error:<diagnostic>` | An operational or unclassified failure. The diagnostic is for logging, not classification. |

Both hashes use Core's 64-character lowercase `uint256::GetHex()` display
order, which reverses their 32 serialized bytes. This applies to the NEVM
hash too; it is not Geth's usual `common.Hash.Hex()` order. No prefixes,
suffixes, or extra fields are allowed in an `invalid` response.

An entire `invalid` response matching both requested hashes establishes
invalidity of that candidate. Buffered insertion may fail on an earlier pair,
so Geth reports the pair at the failing insertion index. Core handles that
ancestor separately as described below; the current request is not marked
independently invalid. Malformed results, unbound identities, legacy error
text and unknown results remain operational errors.

For `nevmcomms` with the serialized string `flush`, the second response frame
is `flushed`, the same `invalid` or `payload-invalid` token, or
`flush-failed: <diagnostic>`. Only the complete canonical token carries a
rejected pair; diagnostic text is never parsed as a validation verdict.

Geth classifies errors at their validation origin. Storage and local execution
read failures take precedence over computed validation mismatches. Mutable
payload failures do not establish invalidity of a committed block hash.

## Rejected payload recovery

The fingerprint is a single SHA256 over the ASCII string
`syscoin-nevm-payload-v1` followed by one NUL byte, then the raw 32-byte NEVM
hash, transaction root, receipt root, Syscoin hash, and the exact NEVM payload
without its CompactSize length. The fingerprint in the response uses the same
reversed display order as the two hashes. Core accepts only the complete
canonical token and matches it to the stored commitment and payload.

Before checking a replacement, Core negotiates the serialized string
`payload-v1` on `nevmcomms`. Exactly two response frames, `nevmcomms` and
`payload-v1`, establish support. It then sends `nevmvalidate` with the existing
connect envelope: committed header, payload, Syscoin hash, empty version-hash
vector, default masternode diff, and zero BTC cursor. Exactly two reply frames
are required: `nevmvalidate` and `payload-valid`, a canonical `payload-invalid`
token, or an error diagnostic. Send and receive timeouts are five seconds.
This check decodes the payload and verifies its header and body commitments;
it does not import, execute, buffer, or pair the block.

Core persists a repair obligation before requesting replacement bytes from one
designated peer. Only that payload is substituted into the existing stored
Syscoin block. The configured engine must approve it before Core appends the
replacement, durably publishes its disk positions, and replays the missing
NEVM prefix. Transactions, AuxPoW, validity, chain work and undo are preserved.
The obligation remains until replay completes. Restart verifies the stored
representation, including a crash after disk replacement; reindex checks
differing payload duplicates before choosing the surviving record. Recovery
requires a compatible engine with `payload-v1` support, including these restart
and reindex cases.

Healthy new imports add no payload fingerprint, parser or body-validation
pass. Pending rejection handling uses index metadata to stop repeated
activation of the same branch before block reads or engine calls. Persistence
retries and peer requests are rate limited; an authenticated rejection can
still incur a recovery flush and replacement validation. Undrained retired
requests close their connection so a fresh connection can retry without
confusing late responses. A valid branch that supersedes the rejected branch
clears its obsolete repair obligation.

When best-chain selection, administrative invalidation or ChainLock enforcement
removes an active suffix during pending payload repair, Core first flushes
Geth and binds its fresh applied endpoint to the active Core ancestry.
Only blocks above that endpoint omit external
disconnects; blocks Geth applied still receive ordinary exact-pair disconnects.
An unavailable, inconsistent or different-branch endpoint stops the switch
before undo. This reuses normal local rollback, including durable root and
coins updates, and preserves finality and activation-handoff checks. The
repair marker itself never authorizes skipping a disconnect.

## Live recovery

After an operational connect failure, Core flushes Geth's remaining buffer
and queries `nevmblockinfo` for its applied count and paired Syscoin hash.
The reported pair must match an ancestor of the pending block, or that exact
pending block if its successful reply was lost. A different branch or an
unexpected ahead pair stops recovery with an operational error.

A recovery flush can also reject the pending request whose reply was lost.
If both rejected hashes match that request, Core uses its normal current-block
verdict handling without retrying it or unwinding its valid parent.

Core resends only the missing, already-connected predecessors. It reconstructs
their historical NEVM payload, PoDA version hashes and masternode address
diffs without reconnecting Core's coins or republishing its local caches.
Existing BTC receipt authorization still applies. Each batch of at most 64
blocks is flushed and checked against its exact expected applied pair before
proceeding. Core then retries the pending block once. A rejection of a
predecessor does not independently mark the pending block consensus-invalid.

This recovery also runs after replacing an unavailable managed Geth process.
Template checks, startup coins recovery and authenticated deferred BTCC replay
retain their own behavior. An unsupported connect protocol requires a compatible
engine, and a matching consensus-invalid result is not retried. Missing replay
inputs or another engine failure leave the candidate retryable. This path
handles connect failures; engine loss first encountered during a normal reorg
disconnect still follows the separate disconnect error path.

Before issuing fresh or cached mining work after unresolved ordinary prefix
recovery, Core retries that replay and requires a flushed applied count/hash
matching the active Core tip. A buffered connect acknowledgement, networking
acknowledgement or template response cannot clear this obligation. Startup also
classifies a behind engine, including an empty one, so reopening Core does not
bypass the gate. Healthy block connections and template requests add no recovery
probe. A failed replay leaves mining unavailable and local coins, roots and mint
markers unchanged; existing activation paths retain rejection reconciliation.

## Delayed buffered rejection

A consensus `invalid` rejection received during live connect, predecessor replay or deferred BTCC
replay may identify a block Core previously accepted. Core binds both hashes
to that active block's stored commitment, then flushes and requires Geth's
fresh applied pair to match its exact predecessor. Zero applied blocks require
a zero paired hash and rejection of the first NEVM block. An unknown identity,
different branch, farther-behind endpoint or unavailable status stops the
operation without authorizing invalidation.

Once bound, Core uses its normal invalidation routine to remove the rejected
block and accepted descendants. External disconnect notifications are omitted
only for this verified unapplied suffix; coins, roots, mint authority, local
indexes and mempool cleanup still run. Durable finality and the PQ activation
handoff remain enforced. Core checks completion and persists the result before
selecting another known branch. An interrupted unwind cannot report success.

Deferred replay retains its original marker and does not call its finalizer
after reconciliation, because the original target was not applied. Replacement
selection runs after releasing the replay activation lock.

## Root ownership during rollback

A receipt-deferred suffix can repeat a NEVM hash already carried by the retained
branch. Before undoing a carrier, Core authenticates the retained ancestry and
finds that key's latest surviving tuple. Clean completion restores that tuple
through the existing root-disconnect journal; it erases the key only after
establishing that no canonical carrier remains. Missing or corrupt evidence
stops rollback before undo or root revocation. The coins durability barrier,
pending-root masking, and consumed-proof cleanup ordering still apply.

This lookup runs on rollback, including local undo of unapplied blocks, and
shares startup recovery's block/proof reader. It adds no work to healthy block
extensions and retains no additional records. A lookup may scan back to NEVM
activation; a multi-block rollback can repeat that scan for each removed key.

## Interrupted mint rollback

Core keeps the root-disconnect journal until both parent coins and consumed-proof
marker deletions are durable. Startup reconstructs pending mint cleanup from
authenticated discarded block bodies, even when the coins database has already
finished its rollback. It preserves any proof consumed in the recovered
replacement suffix, including mints whose outputs have since been spent. Missing
or inconsistent carrier data stops recovery with a local error. Healthy block
connections require no additional reads or writes for this cleanup.

## Root recovery with pruning

Before deleting a block file, Core synchronously retains each indexed NEVM
carrier's coinbase and its Merkle inclusion proof in the block index database.
The proof binds the coinbase to the carrier's indexed Merkle root and transaction
count. Recovery uses these proofs to find the latest surviving canonical owner
of an affected NEVM root key, including aliases whose block bodies were pruned.
It still requires block bodies for the recent discarded and replacement suffixes
and for an unfinished disconnect journal's carrier. Missing or corrupt evidence
stops recovery without completing its metadata.

Pruning adds no proof generation to healthy block imports. It does add retained
metadata outside the block-file prune target. Startup authenticates the retained
proofs before completing deletion of previously pruned files. An orphan-only key
can still require scanning canonical commitment metadata back to NEVM activation;
this recovery work is proportional to history length, even for a shallow rollback.
On an archive node, historical carriers without retained proofs are read from
their block bodies.

An older database that already pruned NEVM bodies without retaining these proofs
cannot backfill them locally. Startup rejects missing or corrupt pruning evidence
with instructions to use full `-reindex` and redownload the missing history.
`-reindex-chainstate` cannot recover this data and is incompatible with prune mode.
Unpruned databases need no backfill: proofs are created when their files are pruned.

## Upgrade order

Upgrade Core before Geth, or stop both and upgrade them together. Updated Core
refuses connects to an engine without `connect-v1`. Older Core may classify
arbitrary engine errors as invalid blocks and cannot safely consume the new
error contract. Keep the pair on compatible versions when downgrading.

With managed `--exitwhensynced`, Core preserves its clean shutdown callback
before classifying a failed connect as an operational error, including a
matching invalid response. It does not persist a failed-block flag on that
shutdown path.
