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
confusing late responses. A valid branch that
supersedes the rejected branch clears its obsolete repair obligation.

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

## Upgrade order

Upgrade Core before Geth, or stop both and upgrade them together. Updated Core
refuses connects to an engine without `connect-v1`. Older Core may classify
arbitrary engine errors as invalid blocks and cannot safely consume the new
error contract. Keep the pair on compatible versions when downgrading.

With managed `--exitwhensynced`, Core preserves its clean shutdown callback
before classifying a failed connect as an operational error, including a
matching invalid response. It does not persist a failed-block flag on that
shutdown path.
