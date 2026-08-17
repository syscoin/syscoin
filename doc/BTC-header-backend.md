# Bitcoin header policy, managed node, and BTCC receipts

Syscoin uses an independently operated Bitcoin RPC view for two live policy
decisions:

- a merge miner selects and checks the `BTCPREV` committed by a scheduled
  candidate block; and
- every PQ ChainLock signer re-derives that candidate from its Syscoin branch
  and checks the exact committed hash against its own Bitcoin view before
  emitting a `BTCCAdvance::ADVANCE` share.

The live Bitcoin view is intentionally **not block-consensus input**. Block
validation binds the coinbase commitment to the AuxPoW parent header, and PQ
certificate validation binds the cursor to indexed Syscoin ancestry. AuxPoW
does not prove that the parent header's previous hash is on Bitcoin's active
chain: a winning miner can choose an arbitrary value without producing a
Bitcoin fork. The independent miner/sentry views close that live-policy gap.
Full-node block and certificate validation never invoke Bitcoin RPC. An
unavailable or disagreeing backend therefore stops scheduled
candidate-template creation and makes local signers choose the canonical
`KEEP` statement instead of `ADVANCE`. Ordinary full nodes and replay never
call Bitcoin RPC.

This separation does not mean a BTCC receipt can be trusted without a PQ
certificate. A non-null carrier at Syscoin height `C` can reference only the
`ADVANCE` certificate for target/cursor `H = C - 10`. Before forwarding its
Bitcoin hash to NEVM, a live node verifies the exact certificate. Missing data
is one bounded, non-punitive block dependency and is requested by logical ID;
a null carrier remains valid. Historical releases pin a separate BTCC receipt
assumption anchor (block hash, cursor, and cumulative receipt-state hash), so
pre-anchor receipt crypto can be assumed without changing the immutable PQ
migration anchor. All base blocks, AuxPoW, deterministic-masternode state, and
post-anchor receipt transitions are still checked.

The receipt assumption record is mandatory whenever the PQ BTCC schedule is
enabled. At first activation it may be a distinct record at the migration
checkpoint before the first carrier, but only with the canonical empty cursor
and accumulator. Once carriers exist, release-updated boundaries must name an
exact carrier and its recomputed state. The compiled `defaultAssumeValid`
height must not exceed this receipt boundary; a custom `-assumevalid` above it
causes catch-up admission to remain fail-closed.

Ordinary network catch-up is limited to the latest eligible ChainLock target
plus its seven immediate eligible predecessors. A crash-durable V2 pre-seal
marker supplies the separate, narrowly bound prolonged-outage recovery
described below; it does not turn arbitrary historical certificates into valid
catch-up objects.

Until a release pins that complete profile, public networks remain in an
explicit pre-activation state and start without the PQ finality service.
Regtest behaves the same only when no PQ deployment option is supplied; any
single PQ option opts into all-or-none startup validation.

## Managed mode (default)

For a miner or sentry role that needs BTCC policy, `-btcheadermanaged=1` starts
the pinned, patched Bitcoin v30.2 headers-only node bundled in official Linux
and macOS packages. It uses a dedicated data directory and P2P/RPC ports. The
patch validates Bitcoin proof of work and maintains the best header tree while
skipping block-body download.

Managed mode is unavailable on Windows. A Windows miner or sentry must use an
independently supervised external backend.

Startup is fail-closed for those roles: the helper must start (or an orphan
from the same authenticated dedicated instance must be safely adopted), report
the correct network and `headersonly=true`, and become RPC-ready. Syscoin never
stops or signals a process based only on a PID, port, or datadir. Ownership is
bound to canonical binary paths, the dedicated datadir, network/ports, RPC
cookie, and a random instance token. Symlinked or unsafe datadirs are rejected.

The watchdog checks process ownership, RPC readiness, IBD progress, and
post-IBD tip progress. A stopped or stalled owned child is restarted with a
cooldown; repeated failures may trigger one headers reindex. If an
authenticated stop cannot be completed, replacement/adoption is refused. A
later outage refuses `ADVANCE`, while exactly 267 positions in each of any
three of the four 400-member rosters converging on `KEEP` can still finalize
the base ChainLock. An arbitrary split between the two statements can delay a
ChainLock until views converge.

The last observed Bitcoin tip height, hash, and progress wall time are written
atomically into the authenticated owner record. Restarting or adopting the
helper therefore cannot reset the no-progress/eclipse window. A corrupt,
partially populated, future-dated, or configuration-mismatched record is a
startup error, not permission to create a fresh observation window.

Managed `-headersonly=1` forcibly implies `-blocksonly=1`; both the Syscoin
launcher and patched helper reject/override conflicting child arguments. The
helper neither relays transactions nor advertises block-serving network
services. The official macOS app stores the deeply signed helper under
`Contents/Resources/btcheadernode/bin`; Linux/macOS release builds generate an
explicit CMake target toolchain so compiler target, SDK/sysroot, deployment,
and depends paths survive cross compilation.

Managed signet is deliberately unsupported. A headers-only view cannot verify
the block-body coinbase solution that authenticates signet, even when its
challenge bytes match Bitcoin's default. Signet operators must use
`-btcheadermanaged=0` with an independently supervised, fully validating
Bitcoin signet node.

Lifecycle RPCs are:

- `syscoinbtcheaderstatus`
- `syscoinstartbtcheadernode`
- `syscoinstopbtcheadernode`

Status works in either mode. Start performs a managed restart/readiness check,
and both start and stop are unavailable in external mode.

## External-node mode

Operators may use an independently supervised Bitcoin node by disabling the
managed backend explicitly:

```ini
btcheadermanaged=0
btcheadercmd=/usr/local/bin/bitcoin-cli
btcheaderarg=-datadir=/srv/bitcoin
btcheaderarg=-rpcwait=0
```

`btcheadercmd` is an executable path. Each `btcheaderarg` is one literal argv
element and may be repeated. `-btcheadercmd` without
`-btcheadermanaged=0` is rejected as ambiguous. Syscoin appends only fixed,
allow-listed RPC methods and validated hash/height arguments. It never invokes
a shell. Each child has bounded output and an explicit timeout. External mode
requires a build with Boost.Process support.

Available policy settings are:

| Setting | Default | Meaning |
| --- | ---: | --- |
| `-btcheadermanaged` | 1 | Start/supervise the bundled headers-only backend |
| `-btcheaderbinary` | searched | Managed `bitcoind` path |
| `-btcheaderclibinary` | beside `bitcoind`/searched | Managed `bitcoin-cli` path |
| `-btcheaderdatadir` | network datadir `/btcheader` | Dedicated managed state |
| `-btcheaderport` | 18544/19444/20444/21444 | Managed P2P port for main/test/signet/regtest |
| `-btcheaderrpcport` | 18543/19443/20443/21443 | Managed RPC port for main/test/signet/regtest |
| `-btcheadercommandline` | none | Repeatable literal managed-child argument; lifecycle-critical overrides are rejected |
| `-btcheadercmd` | none | External executable path; required when managed mode is disabled |
| `-btcheaderarg` | none | Repeatable literal external-backend base argument |
| `-btcheadercmdtimeout` | 10 | Per-command timeout in seconds (1–60) |
| `-btcheaderstartuptimeout` | 30 | Initial RPC readiness timeout (1–300) |
| `-btcheaderwatchdog` | 1 | Supervise and recover the managed child |
| `-btcheaderwatchdogprobeinterval` | 15 | Health-probe interval |
| `-btcheaderwatchdogrestartcooldown` | 60 | Minimum interval between managed restarts |
| `-btcheaderwatchdogstalltimeout` | 1800 | IBD no-progress restart timeout |
| `-btcheaderwatchdogreindexafter` | 3 | Failed managed restarts before one reindex; 0 disables |
| `-btcheadertipmaxnoprogress` | 1800 | Post-IBD no-progress policy timeout; 0 disables |
| `-btcheaderminconfirmations` | 1 | Required active-chain confirmations |
| `-btcheadertipmaxage` | 7200 | Maximum active-tip age; 0 disables |
| `-btcheadermaxlagblocks` | 36 | Maximum candidate lag; 0 disables |
| `-btcheaderrecentforkdepth` | 2 | Pause near a valid competing tip; 0 disables |
| `-btcheaderpolicyondemand` | 0 | Enable policy on regtest/mine-on-demand networks |

The backend network returned by `getblockchaininfo` must match the Syscoin
network (`main`, `test`, `signet`, or `regtest`). When BTCC policy is active, a
PQ sentry or applicable miner requires the executable/helper and matching RPC
endpoint to become ready during startup. Bitcoin IBD itself is allowed to
continue after Syscoin starts, but candidate selection and `ADVANCE` signing
remain paused until the policy query reports `initialblockdownload=false`.
Ordinary full nodes do not start or require the backend.

## Miner behavior

At a scheduled BTCPREV height, omitting `btcprevhash` from `createauxblock` or
zero-argument `getauxblock` selects the active Bitcoin hash at the configured
confirmation depth. Supplying the hash explicitly does not bypass policy. A
backend failure returns an RPC error and creates no template. Calls outside a
scheduled height do not contact the backend.

Mine-on-demand networks preserve explicit-BTCPREV test behavior unless
`-btcheaderpolicyondemand=1` is set.

## Sentry behavior and reorgs

Before signing an `ADVANCE`, a sentry independently:

1. locates the exact ChainLock target on its active Syscoin branch;
2. re-runs deterministic BTCC selection from the certified previous cursor;
3. checks that the scheduled source block hash and indexed `BTCPREV` exactly
   match the proposed statement;
4. requires the Bitcoin candidate to be confirmed on its active chain, fresh,
   and within the configured lag; and
5. checks that the previous certified Bitcoin height does not move backward.

A recent valid Bitcoin fork pauses signing. Once it falls outside the local
fork-depth policy, a replacement active branch may advance from a now-stale
previous Bitcoin hash without rewriting the prior checkpoint. Consumers still
choose how many BTCCs and Bitcoin confirmations their application requires;
Syscoin does not claim to make a single BTCC immune to Bitcoin reorganization.

The independent view is checked once immediately before each local signing pass.
An approval is not retained across later retries, so a Bitcoin reorganization
between attempts cannot inherit an earlier positive result. Denial messages
alone are deduplicated for logging.

For one target/predecessor there are exactly two statement IDs: canonical
`ADVANCE` and canonical `KEEP`. A signer selects one before its durable
anti-equivocation reservation and can never switch at that height, even if its
Bitcoin backend later recovers. Collectors may track both bounded contexts;
the first valid final certificate atomically evicts the loser. With a threshold
of 267 positions in each of three 400-member rosters, safety assumes at most
133 Byzantine positions per roster. Liveness requires at least 267 positions
per roster to converge on the same variant.

## Carrier and NEVM rules

Candidates occur every 10 blocks. The target can be ChainLocked five blocks
later, and its fixed carrier slot is `H + 10`. The carrier contains a
versioned 138-byte receipt: either null, or the exact logical ID, target, and
accepted Bitcoin cursor of that slot's `ADVANCE`. Old certificates never roll
forward into later carrier slots.

A non-null receipt updates a branch-local cumulative receipt-state hash. The
next descendant ChainLock signs that compact state, after which the large
receipt certificate can be pruned under the protocol's anchor/retention rules.
Until then the exact certificate is persisted and served across restart.
`KEEP` and null receipts never clear or advance NEVM's prior Bitcoin checkpoint.

## Prolonged-outage recovery

If historical sync encounters a post-anchor non-null carrier whose certificate
is unavailable, it does not download every prior CLSIG. It durably records a V2
pre-seal marker containing the earliest carrier/hash, the receipt state just
before it, the terminal carrier/hash, that terminal carrier's exact non-null
receipt, and a monotonic revision. Further missing receipts on the same branch
advance the terminal dependency without moving the earliest replay boundary.
Active and prospective-most-work markers are separate so a crash or branch
activation cannot discard the obligation belonging to the winning branch;
legacy V1 markers fail closed.

Ordinary catch-up remains latest plus seven. An uncovered durable marker can
authorize only one of these additional forms:

- the terminal receipt's exact `ADVANCE` certificate at
  `T = terminalCarrier - 10`, archived when below the durable winner or accepted
  as catch-up when newer; or
- a fully valid certificate on the active branch whose target is at or above
  the terminal carrier and descends through every uncovered marker terminal on
  that active branch.

Normal predecessor/durable-winner ancestry still applies. The node reconstructs
the exact four rosters and verifies all 801 signatures before any retained-body
or chain-age-dependent receipt scan. A covering certificate then authorizes
recomputation from the durable state before the earliest carrier through the
candidate; every receipt transition is reread and the result must exactly match
the indexed and signed state. The marker neither creates a certificate nor
waives quorum validation, so recovery still depends on an honest peer serving
the exact terminal or a valid covering certificate.

Crash durability is ordered. Marker creation first synchronously flushes
pending DMN and PQ registry snapshots. Historical certificate publication
fsyncs block-index `BTCPREV`/receipt metadata first, rechecks the stable active
branch and the token over the complete active/prospective marker revisions,
then holds the marker mutex on that exact revision through the synchronous
DMN/PQ snapshot flush and certificate/catch-up fsync. A revision, branch, or
context change, or any failed barrier, aborts publication.

The earliest active/prospective carrier installs a lower-only block-pruning
floor. Later terminal revisions cannot move it forward and a deep reorg may
move it farther back; it is removed only after the replay obligation clears.
While that obligation is live, DMN snapshots are synchronously written and
maintenance retains every persisted fork-local DMN/PQ snapshot. PQ snapshot
commits are write-through, preserving prospective/side branches and a
null-receipt tail even beyond the 1,728-entry normal DMN cache. Durable
best/unsealed certificates separately retain only their required roster
snapshot floors. Outside replay, exact roster-cutoff DMN snapshots at or above
those floors are synchronously written on every branch, while ordinary
non-cutoff snapshots remain in the bounded, lossy cache; more than 1,728
same-height non-cutoff branch writes cannot evict the persisted cutoffs but need
not all survive restart. In-flight verification/publication temporarily
prevents pruning. Normal compaction resumes when those owners release their
obligations; this is not a permanent historical CLSIG archive.

Base Syscoin validation and sync continue while the prefix is uncovered, and
an already durable ChainLock remains enforced. New signing and every paired
Geth execution notification from the earliest marker onward pause fail-closed;
no non-null receipt is replaced with zero. After an exact or covering
certificate is fully verified and durable, base finality/signing may resume
even with Geth offline. The replay marker remains until Geth receives the exact
carrier sequence, reports the matching applied height and last Syscoin hash,
and catches the active tip. A peer/quorum outage can therefore stall signing
and Geth indefinitely while base Syscoin advances. Keeping that later recovery
possible intentionally allows unbounded block-file and DMN/PQ database growth,
and synchronous DMN writes add I/O latency; disk or fsync failure stops progress
fail-closed.
