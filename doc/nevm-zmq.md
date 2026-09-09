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
| `error:<diagnostic>` | An operational, payload, or unclassified failure. The diagnostic is for logging, not classification. |

Both hashes use Core's 64-character lowercase `uint256::GetHex()` display
order, which reverses their 32 serialized bytes. This applies to the NEVM
hash too; it is not Geth's usual `common.Hash.Hex()` order. No prefixes,
suffixes, or extra fields are allowed in an `invalid` response.

Core permanently rejects a candidate only when the entire `invalid` response
matches both hashes in that request. Buffered insertion may fail on an earlier
pair, so Geth reports the pair at the failing insertion index. A different
pair, malformed result, legacy error text, or unknown result remains an
operational error, leaving the candidate available for retry.

Geth classifies errors at their validation origin. Storage and local execution
read failures take precedence over computed validation mismatches. Mutable
payload failures do not establish invalidity of a committed block hash.

## Upgrade order

Upgrade Core before Geth, or stop both and upgrade them together. Updated Core
refuses connects to an engine without `connect-v1`. Older Core may classify
arbitrary engine errors as invalid blocks and cannot safely consume the new
error contract. Keep the pair on compatible versions when downgrading.

With managed `--exitwhensynced`, Core preserves its clean shutdown callback
before classifying a failed connect as an operational error, including a
matching invalid response. It does not persist a failed-block flag on that
shutdown path.
