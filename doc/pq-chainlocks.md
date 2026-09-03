# Post-quantum ChainLocks: consensus and migration design

Status: design specification; disabled pending the complete required test matrix
and independent security review

This document specifies the intended replacement for Syscoin's BLS/DKG
ChainLock stack. It is implementation guidance for the consensus, wire, state,
and migration work. It does not claim that the scheduled Merkle-WOTS+ child
signature profile is standardized, audited, or ready for mainnet.

The final activated implementation has no BLS cryptography and no DKG. It keeps
only byte-exact, non-cryptographic legacy decoders needed to replay blocks below
the configured activation height `A`. `A` is a rule boundary, not a block-hash
or reconstructed-state checkpoint.

## 1. Decisions and non-goals

The design fixes the following decisions:

- Existing ECDSA owner, voting, collateral, and base masternode identities
  remain. This migration replaces BLS operator authentication and quorum
  signing; it is not a complete post-quantum conversion of every Syscoin
  authorization path.
- Each deterministic masternode has a long-lived global
  **FIPS 205 SLH-DSA-SHAKE-128s** public key. This is the category-1 `128s`
  profile, not a category-5 profile.
- The global key authenticates long-lived operator duties, direct MNAUTH, and
  one fixed-depth Merkle commitment to automatically derived short-lived
  ChainLock keys.
- Each member has a distinct **scheduled Merkle-WOTS+** child key for each
  quorum epoch. The child profile has an explicit protocol-assigned leaf for
  every authorized signing purpose and is never used for MNAUTH, provider
  updates, governance, or another epoch.
- Quorums are selected deterministically from chain state. There is no shared
  secret, contribution phase, complaint phase, justification phase,
  verification vector, threshold-key recovery, or mined DKG commitment.
- A final ChainLock contains raw signatures: exactly 267 member signatures from
  each of exactly three of the four active quorums.
- The final ChainLock is carried by the existing `CLSIG`/`GETCLSIG` live P2P
  path. No DA service, SNARK, Flock proof, or historical signature archive is
  part of the security model.
- ChainLocks continue to target one absolute eligible height every five blocks.
  A syncing node needs the latest valid ChainLock, not every historical
  ChainLock, because that ChainLock fixes its Syscoin ancestry.
- Bitcoin checkpoint acceptance is a cursor in the ChainLock transcript. A
  ChainLock may keep the previous cursor (a null advance), so a missing bound
  candidate does not halt Syscoin finality.
- A scheduled candidate can reach NEVM only through its fixed `H + 10`
  on-chain receipt. Live admission verifies the receipt's exact `KEEP` or
  `ADVANCE` CLSIG; only `ADVANCE` forwards a new Bitcoin hash to NEVM.
  Historical sync authenticates a recomputed compact receipt prefix
  with a release anchor and either current-window catch-up or the narrowly
  marker-bound prolonged-outage recovery below, instead of retaining every old
  multi-megabyte certificate.
- A payment-audit certificate is required while its receipt is live, but it is
  not a permanent historical dependency. `PaymentAuditReceipt` commits the
  classified 400-member bitmap on chain; historical IBD may replay that compact
  prefix provisionally, then authenticate it with a normally verified covering
  CLSIG and prune the covered full audit certificates.
- The first PQ-only block is selected by height `A`. Below it, opaque legacy
  replay follows the ordinary valid-most-work chain. At and above it, legacy
  authority is retired and PQ roots are required. Before the first durable PQ
  certificate, the active PoW branch supplies the block at `A-1`; the first
  fully verified certificate binds that branch through signed ancestry. The
  independently updateable exact receipt assumption `R` authenticates only
  compact BTCC receipt history.

The design does not attempt to:

- make ECDSA-protected coins, collateral, or governance post-quantum;
- provide encrypted or channel-bound transport through MNAUTH;
- prove historical Bitcoin best-chain membership from AuxPoW alone;
- make the scheduled child profile production-ready by specification fiat; or
- preserve any post-activation BLS/DKG RPC or P2P compatibility.

## 2. Consensus constants

The current quorum geometry remains the starting point:

| Constant | Proposed value | Meaning |
| --- | ---: | --- |
| `PQ_QUORUM_SIZE` | 400 | Ordered roster slots per epoch |
| `PQ_QUORUM_MIN_VALID` | 300 | Minimum valid child roots in a selected recovery roster; a normal roster requires all 400 |
| `PQ_QUORUM_THRESHOLD` | 267 | Required signatures in one quorum (`2f+1`, `f=133`) |
| `PQ_ACTIVE_QUORUMS` | 4 | Consecutive active epochs |
| `PQ_REQUIRED_QUORUMS` | 3 | Quorums required in a final CLSIG |
| `PQ_EPOCH_BLOCKS` | 288 | Blocks between quorum epochs |
| `PQ_CL_PERIOD` | 5 | Absolute eligible ChainLock-height cadence |
| `PQ_CL_SIGN_LAG` | 5 | Local generation delay; not part of certificate validity |
| `SCHEDULED_WOTS_TREE_HEIGHT` | 8 | Height of each child key's 256-leaf WOTS+ Merkle tree |
| `SCHEDULED_WOTS_TREE_LEAF_COUNT` | 256 | Complete physical leaf domain |
| `SCHEDULED_WOTS_CHAINLOCK_LEAF_COUNT` | 231 | Leaves 0 through 230 reserved for ordinary ChainLocks |
| `SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE` | 231 | First of four payment-audit leaves |
| `SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_COUNT` | 4 | Leaves 231 through 234 reserved for audits |
| `SCHEDULED_WOTS_USAGE_CAP` | 235 | Exact authorized leaf domain; leaves 235 through 255 are invalid |
| `CHILD_KEY_TREE_DEPTH` | 16 | One commitment covers 65,536 consecutive epochs |
| `CHILD_KEY_TREE_MAX_GENERATION` | 16 | One initial root plus at most 15 exceptional replacements per operator |
| `MAX_PQ_USED_TREE_IDS` | 1,000,000 | Branch-local append-only tree-ID safety bound |
| `CHILD_KEY_PROOF_SIZE` | 544 bytes | 32-byte key plus sixteen 32-byte siblings |
| `MAX_PQ_CLSIG_BYTES` | 4,000,000 | Hard wire and allocation limit, including framing |

The deployment-specific epoch origin is `PQ_EPOCH_ORIGIN`. For height `h`:

```text
epoch(h) = floor((h - PQ_EPOCH_ORIGIN) / PQ_EPOCH_BLOCKS)
base(e)  = PQ_EPOCH_ORIGIN + e * PQ_EPOCH_BLOCKS
```

An epoch is a fixed time interval. It advances even if too few members publish
keys or sign. A failed epoch is not extended and an older quorum is not kept
alive to preserve liveness. This fixed expiry is required for the child-key
leaf schedule.

`PQ_EPOCH_ORIGIN` should be aligned to both the 288-block rotation and the
five-block ChainLock cadence. Their least common multiple is 1,440 blocks.

Key-registry deployment is fail-closed behind three additional values:
the first tx86 preparation height, the registration-cutoff lag, and the
maximum future epoch horizon. Preparation must be at or above DIP3, strictly
before activation, and strictly before epoch zero's cutoff.
The roster snapshot lag used for deterministic selection is a
different consensus constant and must not be reused as the registration
cutoff.

### 2.1 Scheduled leaf allocation

A quorum remains in a four-quorum active window for at most:

```text
4 * 288 = 1,152 blocks
```

With one eligible absolute height every five blocks, any 1,152-block interval
contains at most:

```text
ceil(1,152 / 5) = 231 eligible heights
```

For an ordinary ChainLock, `EligibleTargetsForEpoch(config, childEpoch)`
defines the child's complete eligible span. The leaf is the zero-based ordinal
of `targetHeight` within that span:

```text
chainLockLeaf = (targetHeight - firstEligibleHeight) / PQ_CL_PERIOD
```

The result must be an exact cadence point in the span and in `0..230`. Thus the
first eligible target uses leaf 0 and the maximum 231st target uses leaf 230.
The leaf is derived independently by signer and verifier; it is not selected by
the signer and is not serialized in the signature.

Payment audits use the four remaining authorized leaves. With the full
payment-audit schedule validated and `sealEpoch = epoch(sealHeight)`:

```text
paymentAuditLeaf = 231 + (sealEpoch - childEpoch)
```

Only the four active child epochs at the exact audit seal are accepted, so the
result is exactly 231 through 234. Leaves 235 through 255 are always invalid.
There is no runtime usage tally: protocol scheduling assigns a physical leaf,
and the burn-before-sign journal prevents that leaf from being reused.

If a future protocol changes the active lifetime, cadence, or audit purposes,
it must introduce a new child-profile ID and leaf schedule. It must not silently
reuse `CHILD_SCHEDULED_WOTS_SHAKE_128_V1` with a wider authorized domain.

## 3. Cryptographic key hierarchy

### 3.1 ECDSA base identity

The current deterministic masternode owner/voting identities and collateral
rules remain. Initial registration of a global PQ key is authorized by the
applicable existing ECDSA owner/registration rules.

In the legacy protocol, `ProRegTx.pubKeyOperator` stored the BLS operator
public key and an owner-signed `ProUpRegTx` could replace it. After the PQ
preparation boundary, both PQ `ProRegTx` and `ProUpRegTx` require that legacy
field to be null. The owner-signed registrar update remains available for the
voting and payout metadata only; it cannot rotate the global PQ operator key.
The first tx86 record is the explicit owner-authorized bootstrap, with a
proof-of-possession by the new SLH key. Subsequent active-key rotation is tx86
authorized by the current SLH key, while owner recovery is available only
after the separately defined revocation delay.

After a global PQ key is active, ECDSA alone must not be able to replace it.
Otherwise a future attacker that forges the ECDSA authorization could replace
the PQ trust root. Active rotation and revocation require a valid signature
from the currently active global SLH-DSA key. Revocation marks it inactive in
the containing block and clears that snapshot's retained child-key material;
the append-only used-tree-ID history remains. Recovery is delayed for one full
four-quorum active window and then requires both the ECDSA owner signature and
a proof of possession by a different new key at exactly the revoked key's
version plus one. It also starts a fresh child-tree generation; owner
authorization alone cannot rotate an active key.

New masternodes registered after activation necessarily bootstrap their first
global key through the remaining base-identity rules. This is an explicit limit
of retaining ECDSA identities, not a property supplied by PQ ChainLocks.

### 3.2 Global operator key

The global profile is exactly the FIPS 205 parameter set:

```text
GLOBAL_PROFILE_V1 = SLH-DSA-SHAKE-128s
public key bytes  = 32
signature bytes   = 7,856
```

It is used for:

- authorization of the fixed-depth child-key commitment;
- global-key rotation authorization;
- post-activation operator-authorized provider service/revocation operations;
- governance trigger and trigger-vote authorization;
- direct MNAUTH; and
- any other long-lived operator duty explicitly assigned a separate domain.

It is not a category-5 key. Applications that need a stronger global identity
profile require a new profile ID and migration; verifiers must never infer a
profile from key length.

The implementation uses pure SLH-DSA and the FIPS context mechanism over
canonical consensus digests. All protocol signing call sites use the FIPS 205
deterministic option; selecting the available hedged API instead would be a
deliberate profile change, not a runtime deployment choice. Verification
follows FIPS 205 exactly.

### 3.3 Scheduled Merkle-WOTS+ child key

`CHILD_SCHEDULED_WOTS_SHAKE_128_V1` is a short-lived,
per-member/per-epoch profile with algorithm identifier
`SYS-SCHEDULED-WOTS+-SHAKE-N16-W16-H8-V1`. Its fixed parameters and encodings
are:

```text
n = 16, w = 16, len = 35, h = 8
public key           = PK.seed[16] || PK.root[16]              = 32 bytes
secret-key encoding  = SK.seed[16] || SK.prf[16] || public key = 64 bytes
key-generation seed  = SK.seed[16] || SK.prf[16] || PK.seed[16] = 48 bytes
signature            = R[16] || WOTS[560] || auth[128]         = 704 bytes
authorized leaves    = 0..234                                 = 235 leaves
```

The leaf index is implicit protocol state. It is supplied to the vendored
FIPS 205 SHAKE WOTS+ and tree-hash primitives, bound into deterministic `R` and
the message digest, and omitted from the 704-byte signature. Verification
rejects a message or public key of the wrong length, a signature not exactly
704 bytes, and every leaf outside `0..234`.

Each child key owns an immutable height-8 public tree. Its warm signing cache
contains all 511 16-byte nodes, exactly 8,176 bytes per child, is public data,
and is rebuilt when a 64-byte secret-key encoding is imported. The secret-key
owner is move-only and signing is deterministic for one `(leaf, message)`.

This scheduled construction is not itself a FIPS 205 parameter set. It reuses
the vendored FIPS 205 SHAKE primitives but still requires independent review of
the composition, explicit-leaf schedule, multi-user bounded-use argument, and
domain separation before public activation. The superseded draft child
implementation and its wire decoder are absent; no compatibility path selects
an earlier child algorithm.

### 3.4 Separation requirements

Every child secret must be distinct by tree generation and epoch. The global
signature certifies the Merkle root; it does not make a shared quorum key. A
child key must
never sign:

- a different epoch;
- an ineligible ChainLock height;
- two block hashes at the same absolute height;
- MNAUTH or an arbitrary RPC payload;
- a provider/governance transaction; or
- a BTCC-only message outside the ChainLock transcript.

The reference signer imports an independent 32-byte `chainlockSeed`. It hashes
the network genesis hash, a nonzero random 256-bit `treeId`, tree generation,
absolute epoch, and child profile under `SYS_PQ_SWOTS_CHILD_ID_V1`. Three
label-separated HMAC-SHA256 derivations under `SYS_PQ_SWOTS_CHILD_KDF_V1`
produce `SK.seed`, `SK.prf`, and `PK.seed`; the first 16 bytes of each form the
exact 48-byte child key-generation seed. The actual `proTxHash` is
independently bound by every frozen roster leaf and share transcript; `treeId`
is never a substitute for operator identity. This pre-transaction identity
lets a public tree be built before a new transaction hash exists without
creating a transferable signing authority.

The ChainLock seed is never derived from the global SLH secret, so a key-only
global rotation preserves the current child commitment and cannot strand
frozen quorums. A root rotation requires current-PQ authorization, increments the
generation, uses a fresh `treeId` and root, and begins exactly at the first
mutable epoch. Owner recovery has the same fresh-root rules after its delay.
Consensus keeps an exact, branch-local append-only set of every accepted
`treeId`; an operator removal or revocation never makes an ID reusable.
Generation starts at one and is consensus-bounded at 16 for the lifetime of a
`proTxHash`. Thus one depth-16 root may be replaced exceptionally at most 15
times. Key-only global rotations remain valid at generation 16, but another
root-changing rotation or owner recovery does not. An exhausted or revoked
operator must use normal deterministic-masternode replacement rather than
bypassing the append-only tree-ID history.

## 4. Canonical serialization and domains

All integers below are fixed-width little-endian unless stated otherwise.
`uint256` uses Syscoin's existing consensus serialization. Variable-length
collections must have a consensus maximum before allocation. A domain is an
ASCII byte string including the terminating version shown below, followed by
the genesis hash and canonical fields. Implementations must not substitute a
human-readable JSON encoding or a generic concatenation.

The consensus and authorization domains used below include:

```text
SYS_PQ_GLOBAL_REGISTER_V1
SYS_PQ_GLOBAL_OWNER_REGISTER_V1
SYS_PQ_GLOBAL_ROTATE_V1
SYS_PQ_PROVIDER_SERVICE_V1
SYS_PQ_PROVIDER_REVOKE_V1
SYS_PQ_GOV_TRIGGER_V1
SYS_PQ_GOV_VOTE_V1
SYS_PQ_SWOTS_CHILD_ID_V1
SYS_PQ_SWOTS_CHILD_KDF_V1
SYS_PQ_CHILD_TREE_LEAF_V1
SYS_PQ_CHILD_TREE_NODE_V1
SYS_PQ_CHILD_ROOT_LEAF_V1
SYS_PQ_CHAINLOCK_SHARE_V1
SYS_PQ_CHAINLOCK_SHARE_ID_V1
SYS_PQ_CHAINLOCK_LOGICAL_ID_V1
SYS_PQ_CHAINLOCK_WITNESS_ID_V1
SYS_PQ_MNAUTH_V1
SYS_PQ_QUORUM_MODIFIER_V1
SYS_PQ_QUORUM_CONTEXT_V1
SYS_PQ_QUORUM_MEMBER_LEAF_V1
SYS_PQ_QUORUM_MEMBER_PAD_V1
SYS_PQ_QUORUM_MEMBER_NODE_V1
SYS_PQ_QUORUM_CHILD_ABSENT_V1
SYS_PQ_QUORUM_CHILD_PAD_V1
SYS_PQ_QUORUM_CHILD_NODE_V1
SYS_PQ_BTCC_RECEIPT_STATE_V1
SYS_PQ_OPERATOR_KEY_STATE_V1
SYS_PQ_KEY_CONSENSUS_STATE_V1
SYS_PQ_USED_TREE_ID_SET_V1
```

The final implementation must define one helper for each transcript and publish
cross-language test vectors. Domains are independent even when the same global
key is used.

All child-profile, message, record, and journal format numbers remain version
1. This is an in-place correction of an unreleased protocol: no public network
or supported datadir contains the superseded draft encoding, and the old child
implementation is absent. A version bump or migration reader would therefore
create a compatibility state that never existed.

## 5. On-chain PQ key state

### 5.1 Global key record

The deterministic masternode state gains:

```text
PQGlobalKeyRecord {
    uint16  version;            // record format
    uint16  profile;            // GLOBAL_SLH_SHAKE_128S_V1
    uint32  keyVersion;         // monotonic for this proTxHash
    bytes32 publicKey;           // FIPS 205 PK.seed || PK.root
    ChildKeyTreeCommitment childCommitment;
    uint32  activatedHeight;
}

ChildKeyTreeCommitment {
    uint16  version;             // exactly 1
    uint16  profile;             // CHILD_SCHEDULED_WOTS_SHAKE_128_V1
    uint16  usageCap;            // exactly 235
    uint16  depth;               // exactly 16
    uint32  generation;          // 1..16, increments on root change
    uint32  firstEpoch;          // first covered absolute epoch
    uint256 treeId;              // nonzero random, never reused on the branch
    uint256 root;                // complete 2^16-leaf Merkle root
}
```

The registration transcript binds:

```text
domain, genesisHash, proTxHash, recordVersion, profile,
keyVersion, publicKey, completeChildCommitment, transactionInputsHash
```

An `INITIAL` version-86 payload also carries one canonical 65-byte Bitcoin
compact ECDSA signature verified against `keyIDOwner` from the previous
deterministic-masternode snapshot. Its distinct transcript is:

```text
SYS_PQ_GLOBAL_OWNER_REGISTER_V1,
genesisHash,
transactionVersion, payloadVersion, operation,
proTxHash,
recordVersion, profile, keyVersion, publicKey, completeChildCommitment,
activatedHeight,
transactionInputsHash
```

The owner signature bytes are excluded from the digest. `INITIAL` requires a
recoverable compact signature with header 27 through 34 plus the independent
new-global-key SLH-DSA proof of possession. The same transcript recovers an
inactive key only at exact version +1. `ROTATE` requires the owner field to be
all zero and is authorized by the current global SLH-DSA key; this avoids
reintroducing an ECDSA-only PQ trust-root replacement path.

Rotation additionally binds the complete old record and is signed by the old
global key. A key-only rotation preserves the child commitment. A root-changing
rotation must be a generation successor with a fresh tree ID/root and starts at
the schedule's first mutable epoch. It never changes a root frozen into an
active or already selected quorum.

`protx_rotate_operator_key` therefore preserves the root by default. An
optional replacement 32-byte ChainLock seed performs an exceptional
root-changing rotation; the seed is wiped after the successor commitment is
built and must also replace the sentry's configured ChainLock seed when the new
global key is installed. The RPC refuses another seed-driven root replacement
once generation 16 is active; ordinary key-only rotation remains available.

### 5.2 Fixed-depth child-key commitment

There is no per-epoch registry or recurring wallet/controller transaction. One
tx86 registration or recovery authorizes a complete depth-16 Merkle root. A
normal global-key rotation preserves that root unless the current PQ key
explicitly authorizes its generation successor.

For leaf index `i`:

```text
epoch = firstEpoch + i
childSeed[48] = SWOTS_KDF(chainlockSeed[32], genesisHash, treeId,
                         generation, epoch,
                         CHILD_SCHEDULED_WOTS_SHAKE_128_V1)
publicKey = ScheduledWOTS.PublicKey(childSeed)
leaf = Hash(SYS_PQ_CHILD_TREE_LEAF_V1,
            genesisHash, treeId, generation, epoch,
            CHILD_SCHEDULED_WOTS_SHAKE_128_V1, 235, publicKey)
```

The complete binary tree has 65,536 leaves and uses a distinct tagged internal
node hash. Its serialized outer public cache is approximately 4 MiB, separate
from each child's 8,176-byte height-8 signing cache. Neither cache is consensus
state or contains secret material; the 80-byte commitment is.
Every sentry derives the same leaf secret and proof automatically from its
independent seed, without a wallet on the sentry and without an external call
per epoch.

Production cache construction is an asynchronous setup task capped at sixteen
workers. The signing and network paths may load an already validated cache but
must never synchronously rebuild it. Cache loading recomputes every internal
layer and the root even if an attacker also rewrote the unkeyed file checksum.
Proof extraction verifies its own result against the committed root before a
one-time signing slot can be burned.

At each registration cutoff, operator state freezes the exact root metadata for
that absolute epoch. The bounded active history retains old root records while
they can still appear in one of the four active rosters. A later key/root
rotation cannot rewrite them. Revocation makes the current operator ineligible
and clears its live frozen records, while an exact earlier branch snapshot
remains independently reconstructible.

The PQ registry stores sorted operator states and an exact, sorted,
branch-local append-only set of accepted tree IDs. A disk checkpoint contains
the full sets; intermediate blocks contain only changed/removed operators and
new tree IDs. Every sparse link binds its parent block hash, previous state
root, schedule revision, and resulting state root. Reorg rollback selects the
immutable parent snapshot. Removing an operator does not remove a used tree ID.
The 16-generation per-operator consensus limit prevents one funded identity
from consuming the registry's global one-million-ID safety bound through cheap
successive root rotations. Root rotation still pays and validates an ordinary
tx86 transaction; there is no periodic transaction or coordinator.

Every registry snapshot is branch-local and authenticated by its parent link,
block identity, and resulting state root. No one snapshot is elevated into a
release-pinned migration commitment. The registry schema intentionally differs
from the abandoned per-key prototype, so stale databases fail closed instead
of being reinterpreted.

## 6. Deterministic quorum construction

There is no quorum-creation transaction or consensus ceremony.

For epoch `e`:

1. Determine `baseHeight = base(e)` and a fixed roster `snapshotHeight` that
   precedes it by the deployment's snapshot lag. The independently configured
   registration cutoff must be at or before this snapshot (`cutoffLag >=
   snapshotLag`), so every key resolved from the snapshot is already frozen.
2. Derive a non-serialized authorization mask from the statement's exact
   predecessor boundary. For bootstrap epochs zero through three, the
   authorization point is the descriptor's exact epoch-base block; for every
   later epoch it is the exact roster-snapshot block. A slot is authorized only
   when that point is on the predecessor's ancestry. Authorized slots must form
   an oldest-to-newest prefix and at least three slots must be authorized. Thus
   normal operation uses `1111`, while one in-flight rotation uses `0111` and
   still has the unchanged three older rosters needed for a certificate;
   `0011` fails closed. The block at `A-1` is at or after the fourth bootstrap
   base, and configuration checks ensure that every roster active at the first
   eligible target is already authorized by that predecessor height.
3. Load the deterministic masternode list at the snapshot.
4. Use the existing deterministic score ordering with a domain-separated
   modifier that commits the frozen roster snapshot, epoch, canonical BTCPREV
   anchor, and delayed Bitcoin `H+37` hash to select 400 roster slots. The
   miner-influenced epoch-base block hash remains descriptor context but is
   deliberately excluded from the score modifier.
5. For every slot, resolve the child-root metadata already frozen at the
   independent registration cutoff from the exact PQ-registry state at the
   roster snapshot.
6. Mark a slot valid only if the masternode is eligible and has exactly the
   required profile and cap.
7. Commit the ordered roster and keys into a deterministic descriptor.

The descriptor is derived state, not a miner-chosen commitment:

```text
PQQuorumDescriptor {
    uint16  version;
    uint32  epoch;
    int32   baseHeight;
    uint256 baseHash;
    int32   snapshotHeight;
    uint256 snapshotHash;
    uint16  profile;              // CHILD_SCHEDULED_WOTS_SHAKE_128_V1
    uint16  usageCap;             // 235
    bitset400 validMembers;
    uint256 memberRoot;           // ordered proTxHash leaves
    uint256 childKeyRoot;         // ordered child-root authorization leaves
    uint16  validCount;
}
```

A child-root authorization leaf binds:

```text
epoch, slot, proTxHash, globalKeyVersion,
commitmentVersion, childProfile, usageCap, depth,
generation, firstEpoch, treeId, root
```

`memberRoot` and `childKeyRoot` use separately tagged, fully specified Merkle
constructions. The implementation uses a 512-leaf complete binary tree, fills
unused leaves with a tagged empty-slot hash, hashes leaves and internal nodes
under distinct tags, and binds the tree kind, epoch, and slot in every leaf.
Leaves include the slot index to prevent reordering and duplicate counting.

A normal epoch materializes only when its selected 400 identities all have
usable child roots. Recovery first fixes the selected 400 identities from the
authenticated source universe and then resolves their child roots; unavailable
entries are never replaced or backfilled. A selected recovery roster with fewer
than 300 valid child roots is unusable and cannot contribute to a ChainLock.
No old quorum lifetime is extended. Missing commitments do not recreate DKG
PoSe punishment unless a separate future consensus rule explicitly defines
such punishment.

The four active quorum slots at target height are the four fixed epochs selected
by the consensus epoch function, not "the last four successful quorums." This
property makes lifetime and leaf assignment deterministic.

Recovery keeps the last authenticated normal delayed-beacon source fixed while
ordinary finality is unavailable. That source fixes both the entropy and the
pre-reveal deterministic-masternode identity universe. The universe contains
only identities that were valid and already had an authenticated PQ global-key
lineage in that exact source snapshot; a first-time registration
after the delayed Bitcoin value is known cannot enter the outage. Each absolute
recovery epoch then selects a fresh 400-member identity roster from that same
universe with a domain-separated modifier that binds the epoch and source
snapshot; child-root availability is deliberately excluded from selection and
ordering.

All recovery epochs in one four-roster group use the registration cutoff of the
group's oldest epoch as a common key cutoff. A selected identity may register
or repair its scheduled child root before that cutoff. The exact identity and
root captured there are immutable for the attempt. State at the ChainLock
target can only disable that slot when the identity is no longer valid or its
root differs; it cannot replace, reorder, or backfill the slot. A later recovery
group changes the absolute epochs and therefore selects fresh deterministic
rosters from the same authenticated universe. Once a normal rotation succeeds,
the recovery seeds drain from the four-slot window and a later normal source
can replace the retained source. No materialized recovery-authority table or
Bitcoin RPC is part of this construction.

The quorum-context hash is:

```text
Hash(SYS_PQ_QUORUM_CONTEXT_V1,
     genesisHash,
     targetHeight,
     targetBlockHash,
     descriptor[oldest], ... descriptor[newest])
```

The target block hash makes the context branch-self-contained. An unrelated
active-chain descendant at `targetHeight + PQ_CL_SIGN_LAG` is never an input to
the transcript. The lag is only a sentry policy for waiting until the target
has been fully validated; a verifier does not require that descendant to be
known or active.

where each descriptor is serialized completely in the prescribed order.

## 7. ChainLock messages

### 7.1 Share transcript

Every valid member signs a member-specific transcript:

```text
PQChainLockShareTranscript {
    uint16  chainLockVersion;
    uint16  childProfile;
    int32   height;
    uint256 blockHash;
    int32   previousChainLockHeight;
    uint256 previousChainLockHash;
    uint256 quorumContextHash;
    uint8   rosterTransition;
    RosterBeaconWindow rosterBeacons;
    uint256 rosterAuthorizationStateHash;
    RosterAuthorizationBaseIdentity rosterAuthorizationBase;
    uint32  quorumEpoch;
    uint256 quorumBaseHash;
    uint16  memberIndex;
    uint256 memberProTxHash;
    BTCCursor previousBTCCursor;
    BTCCursor acceptedBTCCursor;
    uint8   btccAdvance;
    BTCCReceiptState btccReceiptState;
    PaymentAuditReceiptState paymentAuditReceiptState;
    uint256 paymentProbationStateHash;
}
```

The signature input is the canonical transcript prefixed with
`SYS_PQ_CHAINLOCK_SHARE_V1` and the genesis hash. Binding the epoch, base hash,
member index, and proTxHash prevents a signature from being counted in another
quorum or slot.

`height` is eligible only when it is on the absolute five-block schedule. The
signer waits `PQ_CL_SIGN_LAG` blocks and signs only a block locally valid through
scripts and all consensus-special processing. Post-initialization signing also
requires the branch-objective receipt mode described below. Fresh receipt
progress permits the next normal target; stale progress pauses ordinary rounds
and permits only the canonical phase-3 recovery target. The exact receipted
certificate is the roster-state source, while the durable local winner remains
the wire predecessor and ancestry floor.

The canonical `PQChainLockShare`, including its member identity, outer
depth-16 child-key proof, and scheduled signature, is exactly 2,614 bytes.

### 7.2 Final raw CLSIG

Every selected signature carries the exact 32-byte child public key and its
fixed sixteen-sibling authorization proof. A verifier obtains the commitment
from the deterministic frozen roster and needs no auxiliary registry object, DA
object, SNARK, or external lookup:

```text
PQChainLock {
    uint16  version;
    uint16  childProfile;
    int32   height;
    uint256 blockHash;
    int32   previousChainLockHeight;
    uint256 previousChainLockHash;
    uint256 quorumContextHash;
    uint8   rosterTransition;
    RosterBeaconWindow rosterBeacons;
    uint256 rosterAuthorizationStateHash;
    RosterAuthorizationBaseIdentity rosterAuthorizationBase;
    BTCCursor previousBTCCursor;
    BTCCursor acceptedBTCCursor;
    uint8   btccAdvance;              // KEEP or ADVANCE
    BTCCReceiptState btccReceiptState;
    PaymentAuditReceiptState paymentAuditReceiptState;
    uint256 paymentProbationStateHash;
    uint8   selectedQuorumMask;       // exactly three of four bits
    bitset400 signerBitmap[4];        // 50 bytes each
    uint16  signatureCount;           // exactly 801
    AuthenticatedChildSignature signatures[signatureCount]; // canonical order below
}

AuthenticatedChildSignature {
    bytes32 childPublicKey;
    bytes32 merkleSibling[16];
    bytes704 signature;               // R[16] || WOTS[560] || auth[128]
}
```

Canonical order is quorum-slot order from bit 0 through bit 3, skipping the one
unselected slot, then ascending member index for every set bit. An unselected
quorum's bitmap is all zero. Every selected bitmap contains exactly 267 bits.
There are no per-signature lengths or member indices in the signature array.

Authenticated-signature and complete wire sizes are:

```text
proof bytes per signer = 32 + 16 * 32 = 544
authenticated signer   = 544 + 704 = 1,248 bytes
3 * 267 * 1,248        = 999,648 bytes
statement/mask/bitmaps/count = 1,499 bytes
complete fixed wire    = 1,001,147 bytes
```

The fixed header and four 50-byte bitmaps keep the complete canonical encoding
well below the hard 4,000,000-byte limit. Deserialization rejects a larger
message before allocating signature storage.

Exactly 267 signatures are accepted per selected quorum, not "at least 267."
Exactly three distinct active quorum slots are accepted, not "at least three."

Different collectors can produce valid witness encodings for the same logical
ChainLock by choosing different 267-member subsets or different three-quorum
subsets. This is not a consensus conflict. Define:

```text
logicalChainLockId = Hash(common statement excluding mask, bitmaps, signatures)
witnessId          = Hash(full canonical PQChainLock)
```

Conflict and finality logic operates on the logical statement. P2P invalid-data
caches operate on `witnessId` so one invalid witness cannot suppress another
witness for the same statement.

### 7.3 Verification order

A verifier performs cheap checks before any scheduled-WOTS+ work:

1. Enforce the 4,000,000-byte message limit and exact fixed encoding.
2. Check version/profile, eligible height, known fully validated block, previous
   ChainLock, and absence of a conflicting accepted logical statement.
3. Rebuild the four-epoch context at the signing snapshot and compare
   `quorumContextHash`. Derive the authorization mask from the declared
   predecessor's exact candidate-branch ancestry; all four descriptors remain
   structurally and cryptographically bound even when the newest is not yet
   authorized.
4. Require a three-bit selection mask that is a subset of the authorization
   mask, zero unselected bitmap, and exactly 267 bits in every selected bitmap.
5. Require every selected member to be valid in that descriptor, verify its
   canonical child-key proof against the frozen root, and reconstruct the exact
   share transcript.
6. Validate BTCC cursor structure and chain ancestry.
7. Derive each implicit schedule leaf and verify the 801 scheduled-WOTS+
   signatures in a bounded parallel worker pool.
8. Recheck the target-branch/context snapshot before publishing the result.
9. Atomically accept the first valid logical statement for the height and apply
   existing ChainLock fork/finality semantics.

No cryptographic verification holds `cs_main`. Exact-size admission,
witness-hash deduplication, one global in-flight final-certificate job, no
pending-job queue, randomized serial preflight checks, and bounded caches limit
CPU and memory exhaustion. The remaining independent checks are parallelized
only after the preflight succeeds. Relay occurs only after complete
verification.

The threshold is the standard `2f+1` for `n=400`, `f=133`. Within a common
roster, two 267-member sets intersect in at least 134 slots, which is greater
than `f`; conflicting thresholds therefore require at least one non-Byzantine
signer to equivocate when that selected roster contains at most 133 Byzantine
members. Any two three-of-four quorum masks over the same four rosters share at
least two rosters, yielding at least 268 double-signing member/epoch slots.
This is not a claim of 801 unique operators: active rosters may overlap, which
is why the burn journal is keyed operator-wide and branch conflicts remain
correlated.

That deterministic intersection proof does not extend across differently
composed normal rotations or recovery views. Cross-view safety uses the same
bounded-certificate-propagation model as the one-phase ChainLock protocol: a
complete valid certificate must reach honest participants before they sign a
later view on a conflicting branch, and every selected roster is assumed to
contain at most 133 Byzantine members. A global population fraction below one
third does not by itself deterministically imply that per-roster bound.
Same-branch delayed certificates converge through the exact-base/current-state
projection rule; fully asynchronous conflicting-branch safety would require a
separate transferable view-lock or prepare/commit protocol and is not claimed
here.

### 7.4 P2P availability

Individual `PQCLSHARE` messages are sent only over authenticated quorum links
and to explicitly participating collectors. Any node may assemble the canonical
final object after collecting sufficient valid shares; there is no elected or
trusted aggregator.

The live message does not repeat the 1,296-byte statement in every share. Its
fixed 1,282-byte envelope contains the 32-byte logical statement ID, one
`uint16` packing `quorumSlot * 400 + memberIndex`, and the 1,248-byte
authenticated child signature. A recipient accepts the ID only when it names
one of its at-most-two already-published immutable signing contexts, then
reconstructs the complete signed transcript from that statement and its frozen
roster. The self-contained 2,614-byte `ChainLockShare` remains the historical
form embedded in payment-audit evidence.

All eligible child-key members across the four active rosters form one
deterministic union relay overlay keyed by the quorum-context hash. A separate
overlay per roster is insufficient: four disjoint 400-member selections would
otherwise have no path by which one collector could obtain three thresholds.
The union has at most 1,600 identities and uses a successor ring plus
power-of-two shortcuts, giving each participant logarithmic fan-out while
remaining connected even when the four rosters do not overlap.

The authenticated P2P sender is a transport relay, not necessarily the member
that created the share. Admission requires the relay to be an eligible
child-key member in the active union; the transcript independently names the
original roster, slot, and signer. The collector verifies that original
identity and its scheduled-WOTS+ signature against frozen state before relaying
the share once. After one witness verifies, any later witness for that member slot is
discarded before cryptography, and an invalid first witness never reserves the
slot.

Share acceptance, rejection, duplication, an incomplete threshold, final
certificate publication, and overlay or probe availability are runtime
finality events only. They never call `PoSePunish` or `PoSeDecrease` and never
mutate `nPoSePenalty`, `nPoSeBanHeight`, or `nPoSeRevivedHeight`.
`validMembers` records frozen child-key eligibility; it is not a blame bitmap.

The final `CLSIG` is available to ordinary full nodes and through `GETCLSIG`.
Durable CLSIG storage contains exactly one best certificate, at most one fully
verified exact-slot `KEEP` or `ADVANCE` certificate awaiting its fixed BTCC
carrier, and at most 128 exact fully verified roster-authorization records.
The last category includes a payment-audit seal fetched only to reconstruct an
audit roster. It is servable by an exact targeted `GETCLSIG`, but does not
advance finality, enforcement, receipt state, or recent-winner order. Ordinary
inventory dedup treats that retained witness as already present; if it later
becomes currently admissible, the handler promotes the local verified object
after rederiving its current branch and authorization context instead of
downloading or verifying its 801 signatures again. The live store separately
keeps the most recent eight applied certificates in RAM for bounded relay and
exact lookup; it is not a historical signature archive.

Normal `LIVE` admission requires the receiver's exact durable winner as the
block-finality predecessor, including the exact accepted BTCC cursor, and the
target must be the first eligible height after that predecessor. The signed
roster-authorization base is a separate certificate identity selected from
the candidate branch's authenticated receipt state. The latest non-null
carrier names the exact already-verified certificate whose roster state may
authorize the next statement. A higher same-ancestry local winner remains the
wire predecessor and the ancestry, receipt-state, and cursor floor; it cannot
replace that objective authorization base. When the two differ, admission
also projects from the current winner and requires the resulting active roster
bundle and next-beacon state to converge.

Every post-initialization target derives one mode from the latest receipted
target on its own fully validated branch:

- `NORMAL` when receipt progress is in the target epoch or its predecessor;
- `RECOVER` only at the unique phase-3 recovery target when receipt progress
  is more than one epoch stale; or
- `PAUSE` at every other target, including while the first initialization
  certificate has not yet been receipted.

The modes are mutually exclusive and apply equally to local signing and peer
verification. A candidate's signatures or claimed roster fields cannot select
its mode or authorization base.

At a `RECOVER` target, the latest receipted certificate supplies the exact
normal pre-reveal source. That source fixes the entropy and identity snapshot;
only source-snapshot identities with an already established authenticated PQ
global-key lineage participate. The absolute epochs of the new four-roster group
domain-separate fresh roster selections. Root availability never affects
selection or ordering. The oldest
epoch's registration cutoff freezes each selected identity's child root, and
target state may only disable a fixed entry, never replace or backfill it. The
recovery statement must retain the receipted Bitcoin cursor with `KEEP`.

A verified recovery certificate remains non-objective until its exact
non-null `KEEP` receipt is carried at `H+10`. Before that receipt, all other
targets remain paused, so a hidden certificate cannot privately switch the
roster state or trigger a competing normal rotation. Once receipted, normal
signing resumes and ordinary rotations drain the recovery rosters. If an
attempt never reaches threshold, the next phase-3 group selects four fresh
absolute-epoch rosters from the same authenticated source. Recovery therefore
needs neither Bitcoin RPC on full nodes nor approval from the failed active
rosters.
Before the first winner, the only admissible target is the first eligible
target after `A-1`, which configuration also requires to be the canonical
phase-3 BTCC target. Its predecessor hash is obtained from the fully validated
candidate branch and its predecessor BTCC cursor is canonically null. The four
initial roster snapshots and registration cutoffs are at or below `A-1`; all
four ordinary `NORMAL` roster seeds use that one target's exact BTCPREV anchor
and its real Bitcoin `H+37` hash. Initialization has no fixed activation
authority, no alternate target or seed menu, and no epoch rollover. A pending
initializer may follow a same-height active-branch replacement before it is
READY, but after READY it remains bound to the exact target block and Bitcoin
range. If the first certificate is delayed, base-chain mining and most-work
fork choice continue while initialization remains pinned to that target.

A distinct current `CATCHUP` admission handles an already participating node
that was offline or missed one or more certificates, or the rolling recovery
statement above. It is allowed only after base block sync has completed on a
fully executed best-work AuxPoW branch, ordinary assume-valid shortcuts are no
longer in the candidate range, and any snapshot background validation has
completed. Public IBD may remain true while this final authentication tail is
resolved. The candidate
must be exactly the latest signable target and share the active chain's
`H - sign_lag` boundary. It may be the active target or a current competing
branch, so the first valid recovery certificate can cause the same bounded
reorg as a `LIVE` certificate. Its declared predecessor must be an ancestor of
the candidate at or beyond the node's durable winner, and that durable winner
must also be its ancestor. The candidate is still the first eligible target
after its own declared predecessor. Catch-up can therefore skip certificates
missing from the local store, but no certificate skips forward within its
signed predecessor view and no expired certificate becomes valid merely
because it is locally known or active.

An older authorization base is evidence, not authority by itself. The receiver
must possess the exact fully verified base certificate and derive both the
wire transition from that base and the canonical transition from its current
winner. Both derivations must authorize the selected quorum mask and produce
the identical active roster bundle, including the recovery source. The
next-beacon states must also match, except that current `CATCHUP` may remove one
provisional `PENDING`/`READY` observation only through the existing
candidate-bound null-carrier reconciliation proof. A carried cursor, a
different recovery source, or an unrelated future-beacon result never rebases.

An uncovered crash-durable BTCC pre-seal marker adds only two
prolonged-outage admissions outside that ordinary current window:

- the exact terminal receipt's `KEEP` or `ADVANCE` certificate, whose target
  is `T = terminalCarrier - 10`; below the durable winner it is stored only as
  the receipt archive, while above that winner it follows catch-up acceptance;
  or
- a certificate whose target is on the active branch at or above the terminal
  carrier and descends through every uncovered durable marker whose terminal
  lies on that active branch.

The second case still obeys the normal declared-predecessor and durable-winner
ancestry rules. The marker cannot authorize another old certificate, invent a
certificate, waive a signature, or turn a losing branch into the active one.
Truncated or incomplete marker records lack the terminal dependency and fail
closed rather than being upgraded by inference.

Ordinary current catch-up derives the unique normal roster transition from the
exact receipt-selected authorization predecessor `S`; objective recovery
derives the canonical target-epoch recovery view from that same independently
authenticated boundary. Neither path treats the candidate's own roster
statement as an authorization edge. Each path then rebuilds the four exact rosters from the
candidate branch and verifies all 801 signatures under the single bounded
verifier. An unselected unauthorized
newest descriptor may have a snapshot above that predecessor, but it remains
fully structure-, root-, and context-bound and its slot cannot contribute a
share or final signature. Only then may admission read retained carrier bodies
or perform other chain-age-dependent receipt I/O. Ordinary current catch-up accepts the exact
indexed receipt state only after proving every index after the receipt
assumption boundary in range was fully validated without an assume-valid
shortcut. A marker-authorized covering certificate additionally starts from
the durable state immediately before the earliest carrier, rereads and
validates every retained carrier through the candidate, recomputes the
accumulator, and requires exact equality with the candidate's indexed and
signed state.

If catch-up skips an accepted roster-state transition that a later fixed
carrier still needs, persistence retains one bounded authorization edge: the
exact old durable predecessor, the catch-up winner that consumed it, and the
logical/witness identity of the current durable winner covering that owner.
The record contains no certificate witness and is created only from the
database's actual old best during the catch-up fsync; a peer cannot nominate
it. An ordinary network receipt archive must derive its roster transition from
that predecessor under `EXACT_NETWORK`. The requested carrier or replay token
is only an exact source/TOCTOU capability and never roster authority. Later
ordinary winners roll the covering identity forward atomically. The edge is
removed atomically either when the exact archive is fsynced or when a normal
`LIVE` winner, fully validated from the owner through the fixed carrier range,
proves the same indexed receipt state. A second unresolved catch-up gap cannot
overwrite it. This preserves late-receipt liveness without retaining a
megabyte certificate per epoch or consulting Bitcoin RPC during consensus
verification.

Durable publication orders the block-index `BTCPREV`/receipt fsync before the
DMN/PQ snapshot and certificate fsyncs. A marker-authorized preparation carries
a token over the complete active/prospective marker tuple and its monotonic
revision across the index fsync; the branch, context, and token are rechecked
after that fsync, then the marker mutex pins that exact revision through the
synchronous DMN/PQ snapshot flush and final certificate/catch-up fsync. A
marker change or any failed barrier aborts publication. A later gap may use the
same constrained process again; neither the ordinary catch-up audit record nor
the pre-seal marker is a one-use permission bit.

The live winner's final branch recheck, block-index flush, certificate fsync,
and store publication share the active-chain transition lock with forced
invalidation. An invalidation therefore either completes before the final
recheck, causing publication to retry, or observes the newly durable winner
and cannot cross its active target, invalidate that target's side-branch
ancestry, or cross the active fork of a validated winner whose enforcement was
interrupted by a crash.

Historical catch-up is not a portable proof that every omitted quorum
transition produced a certificate. Its security claim is the intersection of
a fully validated branch inside the current bounded fork window, the exact
receipt-selected authorization boundary, and a valid three-of-four
certificate from the deterministically derived target rosters. A preseal
exception is additionally bound to the exact durable carrier range that caused
execution to pause. It does not retroactively recover historical ChainLock
transition security. Catch-up still requires an honest peer to serve either
the exact terminal certificate or a valid active-branch certificate covering
the terminal carrier; the marker is not a substitute for those 801
signatures. The separate release-pinned receipt anchor bounds this relaxation
and is mandatory whenever BTCC receipts are enabled.

Restart restoration from the node's own checksummed, fsynced latest-winner
database remains separate from network catch-up. It revalidates the target
branch, exact indexed receipt state, frozen rosters, roots, and all 801
signatures. Durable acceptance orders the receipt-state index flush before the
certificate record, so a crash cannot publish a winner whose branch metadata
was never made durable. After restoration or catch-up, exact `LIVE`
predecessor chaining resumes.

A node that already completed IBD does not reopen historical authentication
merely because a peer advertises a header ahead of its tip. An exact missing
certificate may move `READY` back to `PENDING` only after the best header
descends through the branch-local carrier and reaches the first height at which
that certificate may have left the bounded serving set. For a BTCC receipt at
target `T`, that height is
`T + recentCapacity * chainlockPeriod + signLag`; the signing lag is required
because a newer target cannot evict `T` before its own certificate can exist.
For a payment audit it is the audit window's exclusive carrier end. Once
entered, the exact crash-durable marker may sustain `PENDING` while the node
catches up, but unrelated ancestry and an early header fail closed.

The exact 1,001,147-byte certificate every five blocks is a material bandwidth
and verification cost. It must be benchmarked under adversarial load. Its size
being below a protocol cap is not evidence of production viability.

## 8. Crash-safe signer leaf journal

Consensus assigns an explicit leaf but cannot observe signatures a compromised
signer generated privately. Every sentry therefore enforces a persistent,
leaf-keyed burn-before-sign journal for each child key.

The physical one-time slot key is:

```text
(genesisHash, childProfile, proTxHash, quorumEpoch, childPublicKeyHash,
 leafIndex)
```

The durable value also stores the logical purpose and absolute height:

```text
EMPTY -> RESERVED(purpose, absoluteHeight, messageHash)
      -> SIGNED(purpose, absoluteHeight, messageHash, signatureBytes)
```

Required behavior:

- Validate the complete schedule and require `leafIndex < 235` before any
  mutation. Leaves 235 through 255 never reserve a slot.
- Reserve and fsync the physical leaf before invoking the signer.
- After signing, atomically persist and fsync the message hash and exact
  signature bytes before announcing the share.
- A repeated request with the same leaf, logical metadata, and message returns
  the stored signature without generating another.
- The same physical leaf presented with a different purpose, absolute height,
  or message conflicts permanently, even if the alternate logical metadata
  would otherwise look valid.
- A reorg never deletes, rolls back, or refunds a reserved or signed leaf.
- Restoring an old chainstate, wallet backup, or EvoDB snapshot must not restore
  an older journal. The local journal therefore lives outside those databases.
- `RESERVED` after a crash is treated as consumed unless the signer can prove
  that no signature operation occurred. Safety takes precedence over one leaf
  of liveness.
- Once the node is synchronized, each journal process captures one startup tip
  per active `proTxHash`. Before the corresponding local signer can run, it
  fsyncs a batch of tombstones for absent physical slots in the ChainLock
  target or audit seal context whose signing opportunity had opened by that
  tip. Existing `SIGNED` entries retain exact replay, and existing `RESERVED`
  or conflicting entries remain untouched. This idempotent check runs for
  every eligible signing context, including a replacement context introduced
  by a same-height or deeper reorg.
- The startup quarantine does not proactively fill historical leaves: it only
  checks a signing context that is live now and was no later than the captured
  floor. It does not chase targets that become signable later in the same
  process. Under the supported sequential-signer model those later leaves could
  not have been used by the prior process; treating every new tip as another
  recovery floor would consume fresh leaves indefinitely.
- Network input, an invalid block, an ineligible height, an invalid audit seal,
  and generic RPC calls cannot reserve a leaf.

The journal has no per-child usage tally and no reservation migration. The 235
authorized physical keys are the bound. Its database format remains version 1
because this schema is unreleased; a nonempty schema-less or mismatched database
fails closed rather than being interpreted as an older layout.

There is no generic post-activation `quorum sign` RPC for child keys. The only
signing entry points accept fully constructed, internally validated ChainLock
or payment-audit candidates and their derived leaf.

Journal corruption, an unauthorized leaf, or uncertain rollback status makes
that member fail closed for the epoch. It can reduce ChainLock liveness but
never invalidates base-chain blocks.

The local LevelDB implementation provides atomic synchronous writes and crash
recovery, while the ordinary datadir lock prevents two node processes from
using one live datadir. Supported operation uses one active signer datadir and
does not clone it. After an honestly synchronized sequential restore, the
startup quarantine may sacrifice that operator's current ChainLock and audit
shares before later schedule slots resume. A coordinated restart can therefore
make the network miss one current ChainLock round or audit opportunity. An
HSM/TPM monotonic register or remote signer lease remains necessary to detect
concurrent clones or rollback behind a stale/eclipsed tip, and is optional
hardening rather than a consensus rule or activation prerequisite.

That operational constraint is not part of quorum counting. Shares are keyed by the
frozen quorum slot, member index, and proTxHash, and a collector retains at most
one share for that slot. Cloning one sentry therefore cannot manufacture extra
weight: same-message deterministic signatures are exact duplicates, while
different-message signatures are equivocation by one Byzantine identity. The
three-of-four, 267-of-400 threshold and intersection arguments continue to
apply without multiplying that identity.

Accepted-certificate reconciliation pins a live journal to the latest durable
PQ ChainLock and prevents an older local vote from reopening an adjudicated
branch. It cannot detect a snapshot that rolls back the certificate database,
the journal, and the process together. Such unsupported cloning can violate the
scheduled profile's one-signature-per-authorized-leaf assumption for that one
identity, but cannot create another roster slot or additional quorum weight.

## 9. Direct global-SLH MNAUTH

MNAUTH uses the global SLH-DSA-SHAKE-128s key directly, as a deliberate design
choice. It remains peer identity/DoS protection, not an encrypted secure
channel.

```text
PQMNAUTH {
    uint16  version;
    uint256 signerProTxHash;
    uint32  signerGlobalKeyVersion;
    uint8   signerRole;
    bytes7856 signature;
}
```

The transcript binds:

```text
SYS_PQ_MNAUTH_V1,
genesisHash,
networkMagic,
initiatorProTxHash,
responderProTxHash,
both global key records and public-key hashes,
both VERSION cookies and challenges,
both VERSION nonces, protocol versions, and service flags,
both deterministic masternode service endpoints,
signerRole
```

The receiver resolves the current global key from its deterministic masternode
tip state. Existing duplicate-connection and key-change disconnection behavior
is retained using the global key hash.

Because an inbound attacker can trigger expensive global signatures and
verification, implementation requires all of the following:

- MNAUTH only after successful VERSION/VERACK and service negotiation;
- the VERSION masternode identity is scoped to an explicitly dedicated
  masternode transport; ordinary relay and manual connections carry a random
  cookie but no operator identity and never enter the MNAUTH state machine;
- the transport role is immutable after VERSION. An exact-address ordinary
  collision is never upgraded in place: an explicit connection request is
  refused, while automatic quorum/probe intent remains pending until the
  ordinary socket is retired and a dedicated transport can be opened;
- one challenge and one accepted MNAUTH per connection;
- a fresh unpredictable challenge bound to that connection and direction;
- the connection initiator signs first; the inbound responder signs only after
  verifying that proof, and at most one local signing attempt is reserved;
- bounded asynchronous verification and signing executors; neither SLH operation
  runs on a net-processing thread;
- reconnect-resistant actual-keyed-netgroup and global admission before
  verification; outbound initiator signing is admitted only when the connected
  service exactly matches the remote registry endpoint and is charged to that
  registry-attributed proTxHash/keyed-netgroup/global budget, while inbound
  responder signing additionally requires the authenticated proTxHash and uses
  the same budget dimensions, so an unauthenticated claim cannot debit an
  arbitrary operator's budget and connection churn cannot reset an
  expensive-work allowance;
- cheap structure, service-bit, proTxHash, key-version, and duplicate checks
  before SLH verification;
- mandatory random VERSION cookies plus initiator-first response gating before
  the expensive inbound signing path;
- hard disconnect/misbehavior handling for malformed or repeated messages; and
- metrics for signing latency, verify latency, verification/signing queue depth,
  in-flight work, executor saturation, reconnect drops, and rate-limit drops.

Exact rate and queue limits are deployment constants. Exhausting either limit
refuses or disconnects the MNAUTH connection, including a probe; it must not
affect consensus.

## 10. Bitcoin checkpoint cursor

### 10.1 Candidate binding

At a scheduled Syscoin candidate height, the coinbase commits `BTCPREV` and
consensus requires:

```text
committed BTCPREV == AuxPoW parent header hashPrevBlock
```

The validated value is persisted in `CBlockIndex`. This binds the BTC hash to
the Syscoin block hash through the coinbase Merkle root. AuxPoW alone does not
prove that the value is on Bitcoin's best-work chain.

Mining RPCs obtain the parent-prev hash before constructing a candidate
template. With live policy enabled, `createauxblock` and zero-argument wallet
`getauxblock` auto-select it from the miner's independent Bitcoin active-chain
view; an explicitly supplied value is checked against that same view rather
than bypassing policy. Wallet `getauxblock` retains its two-argument submit
mode. Submitting the AuxPoW still verifies the committed value against the
actual parent header.

```text
BTCCursor {
    int32   sysHeight;  // -1 only for the genesis/null cursor
    uint256 sysHash;
    uint256 btcHash;
}
```

Every ChainLock transcript contains the complete currently accepted cursor,
even when it does not advance. A syncing node can learn the advertised cursor
from one recent CLSIG. Normal `LIVE` still requires the exact durable
block-finality predecessor. `LIVE` and the constrained current-quorum
`CATCHUP` path in Section 7.4 may use an older explicitly named
roster-authorization base only after the dual-derivation convergence proof;
this never weakens the durable receipt or cursor floor.

`btccAdvance` has two canonical values:

- `KEEP`: the cursor is byte-for-byte equal to the previous accepted
  ChainLock's cursor.
- `ADVANCE`: `sysHeight` is a scheduled candidate, `sysHash` is the ancestor of
  the ChainLocked block at that height, and `btcHash` equals that ancestor's
  stored `btcpPrevCommitment`.

An advance must be strictly later than the previous cursor and satisfy the
configured spacing/continuity rules. A signer advances only when the ChainLock
target itself is a scheduled, AuxPoW-bound candidate. At an intervening
five-block ChainLock target, or if that exact candidate is absent, it signs
`KEEP`; it never searches backwards for an older candidate.

AuxPoW authenticates the work and the merge-mining commitment, but does not by
itself prove that `hashPrevBlock` is on Bitcoin's active chain. A winning miner
can construct an otherwise valid AuxPoW parent with an arbitrary previous hash
without causing a Bitcoin fork. Miners therefore consult a local Bitcoin view
when creating candidates, and each sentry independently requires the exact
scheduled, indexed `BTCPREV` to be confirmed on its own fresh active-chain view
before emitting a ChainLock share that carries `ADVANCE`.

This Bitcoin policy is deliberately outside full-node consensus and replay.
It never changes the deterministic statement, and an unavailable view affects
only local template creation or an `ADVANCE` signing attempt. Ordinary block
validation, certificate verification, and `KEEP` ChainLocks do not invoke the
backend. A threshold certificate attests that independent sentries accepted
the live Bitcoin view; a consumer still chooses its safety level by supplying
a hash-linked Bitcoin-header proof from one or more accepted cursors and
waiting its required Bitcoin and/or Syscoin confirmation depth. Reorganization
handling remains explicit consumer policy rather than a claim that one BTCC is
immune to Bitcoin reorgs.

### 10.2 Authenticated fixed carrier and NEVM replay

A Bitcoin cursor is not sent to NEVM merely because a miner placed `BTCPREV` in
an AuxPoW block. If candidate height `H` is also the ChainLock target, sentries
can first sign it at `H + 5`. Five more blocks are reserved for certificate
propagation, so its only carrier is `C = H + 10`. A later carrier may not roll
an old certificate forward.

Every carrier coinbase contains one canonical fixed-width slot:

```text
BTCCReceipt {                      // 138 bytes
    uint16  version;
    int32   chainLockTargetHeight;
    uint256 chainLockTargetHash;
    uint256 chainLockLogicalId;
    BTCCursor acceptedCursor;
}
```

The default body is the exact null receipt. A non-null body is valid only when
it names the exact certificate for `H = C - 10` and its target is that branch's
ancestor. An `ADVANCE` certificate must accept the cursor at `H`; a `KEEP`
certificate must retain the exact cursor in the carrier parent's receipt
state. In either case that cursor's Syscoin ancestor and persisted
`btcpPrevCommitment` are checked. Scheduled BTCPREV heights require AuxPoW; a
direct-mined block cannot omit the parent binding. A missing certificate at
its one carrier slot or an unauthenticated backend result produces a null
receipt. A non-null `KEEP` authenticates finality progress but remains a
zero/no-op toward NEVM, so an already-applied Bitcoin checkpoint is not sent
again.

An off-chain winner may temporarily carry an accepted Bitcoin cursor that is
newer than the indexed receipt cursor. Before that cursor's fixed carrier, the
next signing round keeps using the durable cursor; a descendant tip cannot be
used as premature evidence. At or after the carrier, the ChainLock target's own
ancestry makes the outcome objective. Every non-null carrier advances the
authenticated receipt prefix; only `ADVANCE` changes its Bitcoin cursor, while
`KEEP` retains it. A canonical null carrier instead leaves the whole receipt
state unchanged. A node whose durable winner is still ahead may
accept that reconciliation only after reconstructing the exact null carrier
from fully validated block-index provenance and binding the resulting proof to
the candidate, store recheck, and certificate fsync. This also covers a node
that learned a later `KEEP` winner without retaining the original `ADVANCE`;
it never makes an expired certificate or deeper fork admissible.

Live block admission verifies the exact certificate selected by
`chainLockLogicalId`, including all 801 signatures and the complete
target/cursor statement already accepted by the finality store. If the bytes
have not arrived, the most-work block becomes one bounded, non-punitive
dependency: the node requests that exact logical ID and retries activation when
it is accepted. It never substitutes zero for a non-null receipt, and ordinary
block or certificate validation never calls the Bitcoin RPC backend.

Each carrier updates a branch-local state:

```text
BTCCReceiptState {
    BTCCursor cursor;
    uint256   cumulativeHash;
    int32     latestChainLockTargetHeight;
    int32     latestReceiptCarrierHeight;
}
```

The hash commits the prior state, carrier height/hash, and exact receipt. Every
ChainLock statement signs the indexed state at its target. Once a fully
verified descendant ChainLock covers the carrier, that threshold statement
seals the ordered prefix. A non-null outcome makes the original 1,001,147-byte
receipt certificate prunable; a canonical null outcome objectively retires the
unreceipted cursor. Until the carrier outcome is covered, a locally accepted
exact `KEEP` or `ADVANCE` remains durably retained and servable. The block index retains
each carrier's exact receipt logical ID beside the cumulative cursor/state,
allowing the receipt bytes to be
reconstructed and checked against that accumulator after the block body is
pruned. No covered full certificate is retained for audit seeding.

Historical sync starts from a separate release-pinned receipt-assumption
record containing an exact block hash, cursor, and cumulative hash. Above that
boundary all base blocks, AuxPoW, deterministic-masternode/PQ state, receipt
structure, ancestry, and accumulator transitions are executed. If an old
post-boundary non-null carrier no longer has its exact certificate, IBD durably
records a pre-seal marker and continues base Syscoin validation and sync.
The marker commits the earliest carrier and the receipt state immediately
before it, plus the terminal carrier, that carrier's exact non-null receipt,
and a monotonic revision. Another missing non-null receipt on the same branch
advances only the terminal dependency while preserving the earliest replay
boundary. Separate active and prospective-most-work markers are persisted
atomically so a crash between best-work selection and activation cannot erase
the branch that actually wins.

Before a non-empty marker becomes durable, pending DMN and PQ registry
snapshots are synchronously flushed. Its earliest active/prospective carrier
also installs the named block-pruning floor. That floor is lower-only for the
life of the obligation: later marker revisions cannot move it forward, while a
reorg may move it farther back; normal pruning resumes only after the durable
replay obligation clears. While the marker is live, every DMN snapshot produced
under its replay-retention state is synchronously written and maintenance
retains every persisted fork-local DMN/PQ snapshot, including prospective and
side-branch state. PQ registry snapshots are themselves write-through. A crash
test deliberately crosses the 1,728-entry DMN cache with a
greater-than-1,728-block null-receipt tail and proves the marker's earliest and
latest snapshots survive restart.

This retention is temporary and purpose-specific. The replay marker owns the
lower-only block floor and replay snapshot retention. Before the first durable
PQ certificate, the activation floor retains the four initialization roster
snapshots. Each accepted durable certificate thereafter stores its exact
verified four-roster context. Every durable record whose active roster window
names a recovery-authority source also owns the exact deduplicated capsule of
that authenticated source identity universe, regardless of the record's
transition kind. The capsule replaces only the old source-identity snapshot:
each recovery group's registration-cutoff snapshot and signed-target liveness
snapshot remain retained while required. These objects replace an indefinitely
old source roster-snapshot floor without turning candidate fields into
authority. Ownership is capped at 131 distinct source IDs: at most 128 retained
authorization bases plus the durable best, unsealed BTCC, and receipt-archive
owner; referenced predecessors and seals are already retained rows. Startup
accepts exactly the capsules reachable from those owners and fails closed on a
missing, mismatched, or orphaned capsule. Outside replay, ordinary non-cutoff
snapshots remain in the bounded, lossy cache. More than 1,728 same-height
non-cutoff side-branch writes therefore need not survive restart. An in-flight
verification/publication temporarily suppresses snapshot pruning. Once all
durable obligations clear, normal compaction may discard old snapshots and
sealed certificates. The design does not retain every historical CLSIG forever.

The 1,728 full-list entries are a random-access availability and performance
window, not a rollback-depth limit. Every connected post-DIP3 child also writes
one branch-local inverse record to `evodb_dmn_inverse`. The record
binds the network genesis, child and parent identities, both stable DMN-state
hashes, the exact parent registration count, a chained history commitment, and
an inverse diff proportional to the DMNs changed by that block. It is written
asynchronously, then ordered by the same synchronous DMN/PQ barrier that must
precede publication of a durable UTXO best-block marker. `ReplayBlocks` uses the
same ordering.

Sequential disconnect verifies each link and reconstructs a missing parent
before mutating the PQ registry. An active disconnect also restores the one
older full snapshot entering the 1,728-entry random-access window before an
alternate branch can request a historical roster. Startup verifies the durable
tip seal and can reconstruct a contiguous missing window prefix. Missing,
conflicting, or unreadable records fail closed and require reindex; arbitrary
post-write LevelDB key deletion is detected when the affected link is used.
Fresh sync, full reindex, and `-reindex-chainstate` build the inverse database
inductively. Existing pre-journal datadirs cannot prove or backfill the pruned
prefix from the bounded full-list cache and must reindex once with this format.

The physical inverse and PQ snapshot histories are not append-only. Once an
active `ENFORCED_DURABLE_CHAINLOCK` authorizes irreversible maintenance, the
DMN store can prune an inverse prefix below an exact authenticated boundary.
The full boundary snapshot and its inverse closure remain durable, binding the
state hash, history commitment, and record hash. The PQ store similarly prunes
historical snapshot records below authenticated interval checkpoints whose
rooted lineage commitments and bounded erase manifests are verified before
deletion. The logical branch-local set of accepted tree IDs remains append-only
and capped by `MAX_PQ_USED_TREE_IDS`; deleting historical snapshot records never
permits reuse of a tree ID.

Both stores use the same versioned crash-durable `INTENT`/`WATERMARK` journal.
Bounded erase batches resume after restart, while malformed, non-monotonic, or
incompletely authenticated state fails closed. Replay floors, in-flight
finality verification or publication, ambiguous/off-branch finality, invalid
retained windows, and pre-DIP3 recovery veto destructive GC. The active and
recovery random-access windows and every fixed durable dependency survive.
Normal disk growth is therefore checkpointed and compacted; an unresolved
replay or finality obligation deliberately suspends deletion and may grow
without bound until that obligation clears.

This does not synthesize deleted Core history. Sequential rollback still needs
the corresponding `blk` and `rev` records, so the arbitrary-depth property is
for nodes that retain those records. Standard prune mode remains bounded by its
block/undo horizon except where a durable replay obligation installs its own
lower-only prune floor. Geth startup alignment rolls back only a Core suffix
that Geth never applied and does not emit Geth disconnects for that suffix. It
must not cross a durable ChainLock finality floor; if Geth is behind finalized
Core state, operators must rebuild or bootstrap Geth instead.

The separate `preseal_snapshot_window <= 1,728` deployment check remains
intentional. Before the first durable missing-certificate marker exists, all
four historical quorum rosters must be available by arbitrary block lookup.
The inverse journal supports sequential parent reconstruction and is not a
replacement for those random-access roster snapshots.

After base IBD, recovery follows Section 7.4. Ordinary catch-up is limited to
the current latest signable target on the active branch or a competing branch
that shares its `H - sign_lag` boundary. An older uncovered
marker can instead be authenticated only by its exact terminal `KEEP` or `ADVANCE` at
`T = C - 10`, or by a fully valid active-branch certificate at or above `C`
that descends through the terminal carrier. For the covering form, the node
recomputes the retained receipt range from the marker's recorded predecessor
state and requires the result to equal the candidate's indexed and signed
state. In either form, all 801 signatures are verified before the retained
carrier scan, and the marker revision remains part of the crash-durable
publication authorization described in Section 7.4.

Base Syscoin sync and enforcement of an already durable ChainLock continue
while the prefix is uncovered, but new signing is paused and the paired Geth
path skips all execution notifications from the earliest marker onward. It
fails closed rather than substituting a zero checkpoint. Once the exact or
covering certificate is fully verified and durably accepted, base finality and
signing may resume even if Geth is absent. The NEVM replay obligation remains
until Geth is available: Syscoin replays exact carrier values from the earliest
active boundary, proceeds beyond the authenticated terminal only through null
or individually verified receipts, and clears the marker only after Geth
reports the exact applied height and last Syscoin block hash and reaches the
active tip. Count alone is insufficient because an equal-height Geth state may
be on another branch. Disconnect/reorg notifications observe the same applied
boundary, and replay rechecks the exact branch around external notifications.

The marker supplies authorization bounds, not the missing certificate. An
honest peer must still serve the exact terminal or a valid covering certificate;
withholding or a prolonged quorum outage can therefore pause signing and Geth
indefinitely while base Syscoin continues. Keeping recovery possible during
that outage intentionally permits unbounded block-file and DMN/PQ database
growth, and synchronous DMN persistence adds per-block I/O and latency. Disk
exhaustion or an fsync failure stops the affected transition fail-closed.

Old `CBTCCheckpointSig`, BLS BTCC shares, `BTCCSIG`, and aggregate BLS
verification are removed. The compact PQ receipt described above replaces the
legacy carrier proof. Public-network BTCC activation remains disabled until the
activation height, candidate schedule, and independent receipt assumption
boundary are assigned.

### 10.3 Payment-only participation audit

The payment audit discourages registered operators from collecting rewards
while remaining unavailable to the PQ finality network. It is deliberately not
PoSe: its state never changes `nPoSePenalty`, `nPoSeBanHeight`, deterministic
masternode validity, MNAUTH eligibility, quorum thresholds, or collateral
validity. Beginning at `A`, the exact parent registry must give a payee an
active global key and a `FROZEN_PRESENT` child root for the payment's target
epoch. Preparation and legacy payments below `A` are unchanged. Payment
probation then filters only that root-capable deterministic queue. If every
root-capable payee is withheld, selection falls back to the same root-capable
queue so an audit outage cannot remove its last payee. A post-activation state with no
root-capable valid payee is rejected rather than paying a rootless operator.

One audit is attempted per 288-block epoch, about twelve hours at the nominal
2.5-minute spacing. Its subject is the newest frozen 400-member roster, not
every registered masternode. The epoch contains 24
retrospective response rows `A[0]..A[23]`, ten blocks apart. Every row is both
an eligible ChainLock target and a BTCC candidate; its observation deadline is
`A[i] + 20`. A subject's ordinary `ADVANCE` ChainLock share is its positive
response, so the subjects produce no extra signature type. A response is valid
only for the exact epoch, row, frozen descriptor, member slot, ordinary
ChainLock statement, and child-key proof.

Authenticated roster peers reconcile each open row with a fixed 125-byte
`PQPOSEHAVE` bitmap and 2,653-byte `PQPOSERESP` objects. A response is written
to the staging WAL before relay. At the deadline the store issues a real fsync
barrier, replaces raw shares with a checksummed local 400-bit summary, and
refuses later mutation. At most two raw rows are open and 24 summaries are
retained for the epoch. Restart discards a row that never reached its durable
freeze barrier; it never moves a deadline.

After all row deadlines, an ordinary strict-fresh `ADVANCE` target `K` commits
the Bitcoin anchor. Live K signing applies the configured candidate policy
with an effective maximum lag of 36 Bitcoin blocks. The audit seal `B` is the
first non-BTCC ChainLock target at least 240 Syscoin blocks after K. Before
signing the audit, each node rechecks K on the active Bitcoin chain, selects
the exact active Bitcoin header at `H(K)+37`, and requires at least six
confirmations (or the larger configured minimum). The audit seed is the exact
non-null BTCC receipt carried at `K+10`, not a retained copy of K's full
certificate. Its logical ID, target, and accepted cursor are reconstructed
from the branch-local receipt index and checked against the cumulative receipt
state; a null K+10 receipt means that epoch produces no audit. That future
Bitcoin hash, receipt-bound K, the network genesis, and the subject descriptor
select one already frozen row. An operator cannot wait for row selection and
then back-sign the selected old response.

The audit uses a separate purpose-domain scheduled-WOTS+ certificate. For each
reporter child, signer and verifier validate the full payment-audit schedule and
derive `231 + (sealEpoch - childEpoch)` at the exact seal B; the four active
reporter epochs therefore use leaves 231 through 234. Its common statement
binds the exact K+10 receipt projection, the selected row and deadline, the
ordinary B statement, the subject descriptor and valid-member bitmap, and the
previous payment-state root.
Observation is deliberately not a common bitmap: every one of the 801 audit
signers carries its own frozen 400-bit report. This avoids fragmenting the
one-time audit slot when honest signers observed slightly different response
sets. Each audit share is 3,013 bytes. Each final report witness is exactly
1,298 bytes: one 50-byte report bitmap plus one 1,248-byte authenticated child
signature. The final `PQPOSECERT` is 1,041,546 bytes: exactly 267
reporter/signature witnesses from each of three selected active rosters,
announced and requested by exact witness ID.

Reporter-roster authorization is portable with the audit statement: it is
derived from `B`'s declared previous ChainLock on `B`'s branch, using the same
`0111`/`1111` prefix rule as the ordinary seal. Caching the full `B`
certificate does not widen that mask. `B` plus each retained response share
must name the unique eligible successor of its own declared predecessor before
crypto or staging. Audit shares from an unauthorized slot are discarded before
signature verification or signer-journal reservation, and the final audit
selection must be a subset of the derived mask.

For each subject and selected reporter roster, at least 134 positive reports
classify the subject online in that roster. The subject is online if any of the
three selected rosters reaches that threshold and missed only if none does.
With fewer than 134 positive reporters in every roster, a fully absent subject
cannot escape by choosing another valid 267-member witness. Delivery to at
least 267 reporters in any two of the four active rosters is unframeable under
any valid three-of-four mask, because every selected mask includes one of those
two rosters. Delivery in the 134..266 range remains a documented degraded
region in which witness selection can affect classification; it cannot create
two accepted states because the receipt binds one exact witness.

New misses apply only when at least 300 subject members that are still
consensus-valid classify online. A positive always clears that operator's
prior miss, even when the audit is otherwise inconclusive. A current-valid
subject missed by two consecutive conclusive audits reaches the capped miss
count of two and has payments withheld. One miss does not affect payments.
The state is keyed by collateral `proTxHash`; reconnecting, changing IP,
restarting, or deleting local runtime state cannot reset it.

Payment probation affects payment selection only. It never enters finality
membership or ordering, so withholding or recovery never removes or reorders an
operator in a frozen finality roster. Recovery from the capped two-miss state
sets payment eligibility to the positive receipt's carrier height, placing the
operator at the back of the deterministic payment queue. All 400 roster seats
continue to use the existing root-first, epoch-hash score, and collateral
ordering; probation state never enters that selection. Under an unbiased
epoch-score model, `N = 3000` confirmed, valid, root-capable candidates give
each operator a `400/3000` marginal selection rate and a 7.5-epoch/3.75-day
long-run mean roster-appearance interval. That expectation is not a consensus
timing guarantee, and payment withholding still requires two conclusive missed
appearances. Missing or inconclusive audits never create a bounded penalty or
recovery time.

The only on-chain audit data is `pqar || PaymentAuditReceipt`, a fixed
261-byte tagged segment (four-byte marker plus 257-byte receipt) placed before
the ordinary `btcr` receipt and optional `btcp` suffix. Each receipt slot from
the first carrier at least ten blocks after B until the next audit seal may
carry the oldest applicable audit; honest miners retry throughout the roughly
27/28-carrier window. Null is an explicit fail-open no-op and has an all-zero
bitmap. A non-null receipt names the logical ID, exact report-witness ID,
commitment hash, result hash, seal block, carrier height, next probation-state
root, and the appended 50-byte `online_members` bitmap. The receipt-state
accumulator hashes the entire canonical receipt, so the classified 400-member
bitmap is part of the on-chain hash-linked commitment.

Live validation requires the full `PQPOSECERT`: it verifies all 801 signatures,
rederives the exact subject roster, classifies the reports, requires
exact equality with `online_members`, and replays the transition against the
carrier parent's deterministic-MN and probation state. The receipt updates a
branch-local audit accumulator and hash-addressed probation state; later
ordinary ChainLocks sign both the cumulative receipt state and probation root.
Reorg undo is exact and branch-local, and payment selection reads the parent
state so the transition begins at the following payment. A missing live witness
defers only the dependent branch. Store or database corruption is a local error
and is never converted into peer misbehavior or permanent block invalidity.

If an exact requested historical audit is present but the ordinary seal needed
to derive its reporter rosters is no longer in the recent winner set, that
pending carrier owns one `PAYMENT_AUDIT_SEAL` request lane. The immutable audit
statement supplies the exact seal statement and logical ID; any objective
authorization base it requires must already be locally verified.
`GETCLSIG(id)` may return
only that exact certificate. The receiver rebuilds the current branch-bound
context, verifies all 801 signatures, rechecks the carrier/source token at the
fsync boundary, and stores the seal as authorization only. If recovery rosters
were used, the same atomic record retains their exact authenticated source
universe. A replaced carrier, authorization base, branch, or token cannot clear
or reuse the lane. If another path installed the byte-identical seal while the
audit response was being checked, staging succeeds without a peer-failure
cooldown and the audit is retried immediately from the local row.

Every audit-window owner and the authorization base named by its seal remain
servable until that window's exclusive carrier end. Expiry is clocked only by
the durable best ChainLock; an authorization-only or archive-only certificate
at a future height cannot age out older live dependencies. The fixed 128-record
cap exceeds the protocol maximum of simultaneously live owners and bases, and
startup imports are order-independent. Once durable finality crosses the
carrier end, ordinary bounded eviction may remove both records.

Historical IBD and marker-bound replay do not require an already pruned
1,041,546-byte certificate. If the full witness is absent, the node rederives
the subject roster from the historical snapshot, applies the committed
`online_members` bitmap, and requires both
the resulting probation root and cumulative receipt state to match the block
index. This compact replay is provisional, not quorum authentication. Before
publishing the provisional transition, the node fsyncs a checksummed pre-seal
containing the earliest carrier and predecessor receipt/probation roots, the
terminal carrier and receipt, and a monotonic revision. Active and prospective
branches have separate markers, and the block/DMN/PQ inputs needed to replay
either prefix remain protected from pruning.

The prefix becomes authenticated only when a descendant CLSIG is verified with
all 801 signatures under its ordinary deterministic rosters, lies on the
accepted active branch at or above the terminal carrier, descends through that
carrier and the durable predecessor, and signs the exactly recomputed cumulative
receipt state and probation root. The marker supplies replay bounds, never
quorum authority. After that covering CLSIG and the reconstructed state are
durable, the node first forces the active chainstate to disk, ordering the DMN,
PQ-registry, payment-state, and UTXO best-block markers before any irreversible
GC. It then atomically persists a monotonic audit checkpoint and deletes every
full audit certificate at or below the checkpoint epoch; hash-addressed
probation-state GC follows as a separately committed, idempotent step. A crash
can therefore leave extra data to prune, but cannot restart below a state root
that GC already removed. The checkpoint binds the terminal carrier's receipt
epoch and cumulative hash to the covering winner's target height/hash and exact
logical/witness IDs; regressions and same-epoch conflicts fail closed. Reads,
admissions, and pins for the retired prefix are rejected, while the
live/uncovered suffix remains servable.

A completion record in the probation-state database binds the immutable
authenticated deletion boundary. The periodic finality scheduler therefore
does not flush chainstate, rewrite the archive, rescan probation state, or issue
an fsync when revisiting the same boundary, including under a newer authorizing
winner. One synchronous chainstate-and-GC sequence runs only when the boundary
advances or when a crash or `-reindex-chainstate` leaves that completion record
behind the durable archive checkpoint.

While either marker is unresolved, base block sync and enforcement of an
already durable ChainLock continue, as do inbound CLSIG verification and
`GETCLSIG` recovery. New local finality signing/publication, payment-audit
production, fully authenticated readiness, covered-prefix pruning, and paired
NEVM notifications from the provisional boundary are gated fail-closed. A
crash, marker revision, branch change, or failed state/checkpoint/certificate
fsync cannot clear the obligation or expose provisional state as authenticated.

Consequently, an already authorized participating node that restarts or falls
behind replays the on-chain receipt chain, obtains one later covering CLSIG
through the ordinary P2P path, and discards covered audit certificates; it does
not download or retain a permanent 1,041,546-byte-per-epoch audit archive. A
fresh, full-reindex, or snapshot-reconstruction node may perform the same replay
only provisionally inside historical-replay quarantine. It cannot request or
restore the covering CLSIG or become authoritative until a separately
authenticated checkpoint or snapshot release ends that quarantine. Full
certificates are stored and served only while live or not yet covered. Null or
inconclusive audits remain fail-open no-ops for new misses.

The protocol proves possession and use of the registered child key during one
of 24 deadlines selected only later. It does not mathematically prove that an
operator ran a Bitcoin process continuously. The deterrent makes a free rider
remain ready for all 24 retrospective opportunities, while BTCC safety
continues to rely on the threshold of independent sentries that validate
`ADVANCE` against their Bitcoin views. Payment-audit activation is part of the
same currently unshipped PQ/BTCC consensus launch; no released chain contains
any payment-audit history.

## 11. Height-only activation and legacy replay

### 11.1 Activation boundary `A`

Each network assigns one consensus height:

```text
nPQActivationHeight = A   // first PQ-only block
```

The boundary has deliberately narrow meaning:

- Blocks below `A` replay legacy provider and quorum data through fixed-size
  opaque codecs. Their BLS/DKG cryptographic validity is assumed, while all
  non-BLS structure and deterministic state effects are still checked.
- Block `A` and every descendant use only PQ provider authorization,
  root-qualified payments, deterministic PQ rosters, and PQ finality rules.
- `A` carries no configured block hash, deterministic-MN root, PQ-registry
  root, or special minimum-work commitment. Before PQ finality exists, normal
  valid-most-work fork choice selects history.
- The configured initial predecessor height is `A-1`. Its hash is read from
  the fully validated candidate branch, never from configuration or the first
  message observed on the network.
- The first fully verified certificate is written durably before enforcement.
  Its signed predecessor and target ancestry bind the actual branch. Invalid,
  incomplete, or merely first-seen data cannot pin a hash.
- If finality is unavailable at activation, base-chain mining and fork choice
  continue. The initializer remains pinned to the first target and may finish
  once its real Bitcoin `H+37` value and threshold shares are available; it
  cannot roll to a later attacker-selectable roster. The rolling `RECOVER`
  path exists only after a durable PQ winner already exists.
- Destructive DMN/PQ history GC is disabled until a durable enforced winner
  exists. Thereafter normal branch snapshots, inverse undo, rooted checkpoint
  segments, and restart journals provide the authenticated pruning boundary.

Configuration checks require `A > 0`, `A >= DIP3`, registry preparation
strictly before `A`, complete bootstrap-roster authorization by `A-1`, and the
first target after `A-1` to be the canonical phase-3 BTCC target. Regtest exposes only
`-pqactivationheight`; there are no migration block-hash or state-root options.
Public-network overrides remain forbidden and activation is release-disabled
until a complete profile is compiled for that network.

The release-updatable BTCC receipt assumption `R` remains a separate exact
record containing a block hash, cursor, and cumulative receipt-state hash. It
does not become the ChainLock predecessor and need not be at or after `A`.
Before the first carrier it is valid only with the canonical empty state;
afterward it must land on an exact carrier and match the recomputed state. The
compiled assume-valid boundary must remain below `A` and strictly
below `R`.

This model adds no wire field or block-index serialization version. The local
finality schema commits `A-1`, all schedules, `R`, genesis, and the signature
profile, but no activation block hash. A persisted winner carries its own
signed branch identity and is fully reverified on restart. Public profiles are
still disabled, so there is no released production database migration to infer.

### 11.2 Local activation handoff

The final BLS-free binary consumes a separate, fsynced handoff record written by
the legacy-validating transition release at `A-1`. This record is deployment
provenance, not consensus state and not a configured activation hash. The
BLS-free process can verify an imported pin but cannot manufacture or replace
one from structurally replayed legacy history.

- A public datadir without an imported pin remains sync-only. Below `A-1` it is
  deferred; at `A-1` it cannot create block `A`, and it fails closed if asked to
  cross the activation boundary. Producers therefore run the transition release
  through `A-1`, let it fsync the exact predecessor, and only then start the
  BLS-free release. A loaded tip at or above `A` must have both that matching pin
  and block `A`'s strong complete-PQ-validation provenance.
- An empty datadir, full reindex, `-reindex-chainstate`, or snapshot/background
  validation starts in historical-replay quarantine. Blocks and headers may be
  reconstructed for inspection, but mining, provider admission, MNAUTH,
  governance, PQ share/certificate traffic, certificate restoration, and
  ChainLock enforcement remain disabled. Validating block `A` in this mode does
  not promote the process or create a pin. A later authenticated checkpoint or
  snapshot release is required to make a fresh BLS-free reconstruction live.
- The imported `A-1` pin is a local transition checkpoint. This BLS-free process
  rejects any disconnection that would cross it, even before the first durable
  PQ ChainLock. Operators must return to the transition release to validate a
  replacement legacy branch and produce its handoff. Reorganizations strictly
  above `A-1` remain subject to the ordinary PoW and PQ-finality rules.
- A public all-sentinel profile remains sync-only and never advertises live
  authority. Regtest bypasses this deployment handoff so activation fixtures
  retain their existing behavior.

`A` must not be a superblock height. Historical replay intentionally does not
consume live governance authority before the pin, while the strong provenance
needed to unlock quarantine requires exact validation of block `A`; selecting
a superblock would make those requirements circular.

### 11.3 Opaque legacy codecs

Blocks and deterministic state below `A` still contain BLS-shaped fields.
The final implementation retains fixed-size opaque types only:

```text
LegacyBLSPublicKeyBytes  = 48 bytes
LegacyBLSSignatureBytes  = 96 bytes
```

The codecs preserve legacy/basic version selection, exact byte order,
serialization hashes, zero-byte null representation, dynamic bitsets, provider
payloads, final-commitment payloads, deterministic-MN state/diffs, and EvoDB
records. They never parse a curve point, perform subgroup/canonical checks, or
call a BLS library.

For blocks below `A`, compatibility replay assumes historical BLS/DKG
cryptographic validity. It still performs non-BLS deterministic state effects
needed by descendant consensus, including:

- provider registration/update/removal and uniqueness rules;
- bounded commitment height/hash/schedule and bitmap decoding;
- payments, confirmations, bans/revivals, and collateral removals; and
- byte-identical transaction, block, and state serialization.

Although legacy commitment cryptography is assumed, a node syncing from
genesis still reproduces the narrow deterministic `validMembers` PoSe
transition below `A`. Those bounded opaque bitmaps affect ban state, payee
eligibility, seniority, and therefore state needed to validate later blocks.
Replay performs no BLS operation and is
retired at `A`. Provider, collateral, payment, and PoSe state continues
normally into the post-activation deterministic-masternode list.

At and above `A`, legacy provider versions that require BLS, BLS final-commitment
coinbases, DKG messages, BLS recovered signatures, and BLS ChainLocks are
invalid or unsupported as specified by their layer. No post-activation code
path can deserialize a BLS field into a cryptographic object.

The final production build removes chiabls/dashbls, BLS workers, verification
vectors, secret shares, recovered-signature databases, DKG session code,
`QFCOMMITMENT`, DKG contribution/complaint/justification messages, BLS signing
RPCs, and DKG spork control. Old auxiliary DKG/vvec/secret-share databases use
retired namespaces and are ignored. Deterministic state databases must remain
readable through the opaque codecs.

## 12. Rollout versus final activation

Pre-registration and shadow operation are rollout requirements. They are not
features retained in the final activated protocol. This implementation is
BLS-free. Its current public-network parameters deliberately select an
all-sentinel compatibility-replay profile: legacy chain data remains replayable
for sync and reindex, but no legacy or PQ ChainLock finality service starts. It
is not an authoritative public-network upgrade, and supplying only part of a
public activation profile remains a startup error.

Regtest additionally exposes one explicit preparation-only configuration: the
registry/quorum schedule is complete, `-pqfinalitypreparation=1` is present,
and activation, BTCC candidate, and receipt-assumption fields remain
unassigned. That state constructs no finality store and cannot sign, accept,
restore, or enforce a PQ ChainLock.

Stages A and B require a future, explicitly supported BLS-free public
preparation profile. It is a complete rollout state in its own right, not a
partial activation profile inferred by filling selected fields in this release.
It starts from already-known accepted public-chain data and enables registry
and shadow operation without finality authority. The regtest preparation state
remains the deterministic harness for that rollout behavior.

### Stage A: preparatory release

The future preparatory release contains no BLS or DKG implementation. It keeps
only opaque compatibility replay for accepted legacy chain data and adds:

- global SLH-DSA registration/rotation state;
- fixed-depth scheduled-WOTS+ child-root commitments and automatic sentry
  caches;
- deterministic PQ quorum descriptors;
- signer journals and shadow share/certificate generation;
- PQ MNAUTH negotiation in non-authoritative test/shadow mode;
- metrics and RPC inspection for key coverage, shadow thresholds, certificate
  size, latency, and verification cost.

Operators register each global key and its child root once before the required
cutoff. There is no periodic key-maintenance transaction. Shadow PQ
certificates are verified and compared across implementations but do not affect
fork choice. The release starts no ChainLock finality service and must not be
operated as though it enforces either legacy or PQ finality.

### Stage B: four complete shadow epochs

The network must complete at least four consecutive usable shadow epochs so the
later activation boundary has a full four-quorum PQ active set. Each normal
roster must have all 400 selected identities backed by valid registered roots
and repeatedly demonstrate 267-member shares. Activation remains unassigned
during this phase. Missing the
coverage/readiness criteria delays selecting `A` and the complete activation
profile; it does not alter the eventual fixed epoch rules.

### Stage C: activation release

After four complete shadow epochs, choose a future height `A` that leaves
operators time to install the activation release. The profile fixes only the
height, schedules, roster parameters, and separate receipt assumption `R`; it
does not predict a future block hash or state root. `A-1` must cover every
initial roster authorization point and precede the first BTCC candidate source.
`defaultAssumeValid` must remain below both `A` and `R`. All four initial
registration cutoffs and roster snapshots must be at or below `A-1`.

The boundary is unambiguous:

- legacy BLS/DKG chain-derived objects are replayed below `A` with opaque
  codecs and assumed cryptographic validity;
- no legacy DKG/BLS object is produced or accepted for live authority after
  `A`;
- block `A` is the first block requiring PQ-only authorization and
  root-qualified payments; and
- the first normal ChainLock target is the unique first eligible target after
  `A-1`, uses the actual active-branch block at `A-1` as predecessor, and builds
  its four ordinary rosters from one exact BTCPREV/Bitcoin-`H+37` seed. It does
  not roll to a later target. Later rolling recovery is available only after a
  durable PQ winner exists.

### Stage D: final BLS-free activation release

Publish the BLS-free activation release only with the complete manifest. The
only remaining legacy support is the isolated opaque decoder/state-transition
module for heights below `A`. A transition-release datadir may validate from
genesis, import the fsynced `A-1` handoff, and follow valid-most-work history
until a fully verified durable PQ certificate establishes finality. A clean
BLS-free datadir may reconstruct the same history only in quarantine until a
separately authenticated checkpoint or snapshot release makes it live. An
all-sentinel release remains a non-authoritative compatibility-replay/sync
build, and a partially populated public profile must never start. The future
preparation release must identify its no-finality profile explicitly rather
than weakening that partial-profile check.

Old peers may remain ordinary block-relay peers if otherwise compatible, but
they cannot authenticate as quorum peers or contribute to ChainLocks after
activation. There is no downgrade path back to BLS.

## 13. Failure behavior and safety invariants

The implementation must preserve these invariants:

1. There is exactly one deterministic descriptor per epoch and no miner- or
   network-chosen quorum commitment.
2. Epochs and child-key expiry advance on schedule even when finality stalls.
3. Active quorum membership and keys are frozen at their cutoff/snapshot.
4. A child key is authorized for one epoch, one profile, and exactly the
   scheduled leaf domain 0 through 234; leaves 235 through 255 are invalid.
5. A sentry never generates two child signatures from the same physical leaf.
6. A reorg cannot refund a journal entry or cross an accepted durable ChainLock.
7. A final CLSIG proves exactly 267 valid distinct slots in each of exactly
   three distinct active quorums for one common statement.
8. Failure to form a CLSIG affects finality/bridge liveness, not base-chain
   block validity or mining.
9. A missing scheduled BTC candidate keeps the prior cursor and does not stop a
   Syscoin ChainLock.
10. Historical base-chain replay depends on valid-most-work chain data below
    height `A`; there is no configured historical block or state commitment.
    Assuming pruned receipt certificates requires exact release-pinned `R`;
    resuming after a gap requires exact current-window block-predecessor
    chaining, bounded-current `CATCHUP`, or the exact-terminal/covering
    exception bound by a durable pre-seal marker. An older roster-state base is
    usable only when retained as a fully verified certificate and its result
    converges with a canonical projection from the current winner.
11. ECDSA alone cannot replace an already active global PQ key.
12. No final-production code path invokes BLS or DKG cryptography.
13. Every `LIVE` CLSIG names the exact locally durable block predecessor. Its
    roster-authorization base normally names that certificate; a higher
    same-branch statement may name an older exact verified base only when dual
    derivation preserves the current active authority and future-beacon state,
    apart from the candidate-bound null-carrier exception. Before the first
    certificate, normal `LIVE` names height `A-1`, the actual candidate-branch
    block at that height, and a null BTCC cursor.
    Trusted startup restoration may reinstall only this node's checksummed,
    fsynced winner; network `CATCHUP` is a distinct admission that authenticates
    either an ordinary certificate inside the current fork window or the
    marker-bound prolonged-outage proof described above.
14. An uncovered pre-seal never weakens base block validation. It pauses signing
    and paired Geth execution, durably retains the exact replay inputs, and
    permits base Syscoin sync to continue until an exact or covering certificate
    is supplied and verified.
15. An authoritative public finality deployment has a complete, internally
    consistent `A`/`R`, schedule, and roster profile. The current
    all-sentinel profile is non-authoritative compatibility replay/sync, and
    current partial public profiles fail startup. A future BLS-free public
    preparation profile must be explicitly defined as a complete no-finality
    rollout state; it is never inferred from a partial activation profile.
16. Payment-audit state is keyed by collateral identity and branch history.
    Process restart, connection churn, IP changes, and local cache loss never
    erase a miss, while an authenticated later positive may clear it.
17. Payment-audit results never mutate PoSe, deterministic-masternode validity,
    collateral validity, MNAUTH, or finality membership/order. Roster selection
    never consults probation state; at and after `A`, payment selection first requires
    the target epoch's frozen PQ child root, and an all-withheld fallback remains
    confined to that root-capable queue.
18. Compact payment-audit replay is provisional until one fully verified,
    durable descendant CLSIG authenticates its cumulative receipt state and
    probation root. A marker or checkpoint is never quorum authority, and no
    covered full-audit prefix remains a permanent archive.

Expected failures are fail-closed:

| Failure | Required behavior |
| --- | --- |
| Missing/late child-root commitment or cache in a normal roster | Normal roster construction fails; epoch still advances and no filler is selected |
| Fewer than 300 valid roots after resolving a selected recovery roster | Recovery quorum unusable; no replacement, backfill, or lifetime extension |
| Fewer than 267 shares | That quorum cannot contribute; with exactly 300 valid recovery roots only 33 may be offline |
| Fewer than three usable active quorums | ChainLock finality and bridge pause; base chain continues |
| Journal uncertainty/corruption | Affected signer stops for the child epoch |
| Same physical leaf with changed logical metadata or message | Return the exact cached original only; otherwise refuse |
| Unauthorized or mismapped child leaf | Refuse without reserving; never borrow a global or future child key |
| Child-root generation 16 reached | Preserve the root for key-only rotation; reject another root rotation or recovery |
| Missing scheduled BTCPREV candidate | Use `KEEP`; do not search older candidates |
| Malformed/oversize CLSIG | Reject before expensive verification/allocation |
| Context changes during verification | Discard result and rebuild against current snapshot |
| Missing `LIVE` predecessor | Reject normal admission; current `CATCHUP` admits only the latest signable target on the active branch or a branch sharing its `H - sign_lag` boundary after full validation |
| Missing live non-null BTCC receipt certificate | Hold one bounded, non-punitive block dependency and request its exact logical ID |
| Null K+10 BTCC receipt for a payment-audit anchor | Produce no audit for that epoch; never substitute K's retained certificate or the prior cursor |
| Missing historical BTCC receipt certificate during IBD | Fsync the earliest/terminal pre-seal and required snapshots, retain replay data, continue base Syscoin sync, and pause signing/Geth from the earliest carrier |
| Prolonged-outage recovery certificate absent or withheld | Keep requesting the exact terminal logical ID or a valid covering active-branch CLSIG; the marker alone grants no recovery, so signing/Geth remain paused while base sync continues |
| Old, off-branch, below-terminal, or wrong terminal certificate | Reject; a marker authorizes only its exact terminal `KEEP`/`ADVANCE` at `T=C-10` or an active-branch certificate covering its terminal carrier |
| Marker revision/branch changes across historical verification or fsync | Abort publication and rebuild; never persist a winner under a stale marker token |
| Replay marker survives a prolonged outage | Keep the lower-only block floor and retained DMN/PQ branch snapshots; accept unbounded disk growth and synchronous DMN write latency until recovery |
| Geth unavailable or reports the wrong applied hash | Keep the replay marker and skip paired execution notifications; never substitute a null checkpoint, while base Syscoin may continue |
| Replay/snapshot/index/certificate fsync fails or disk fills | Stop the affected transition and finality/signing fail-closed; never clear the marker or publish partially durable recovery |
| Audit has fewer than 300 current-valid positive subjects | Clear misses for classified-positive subjects only; add no misses |
| Subject has one conclusive audit miss | Persist miss count one; leave payments unchanged |
| Subject has two unrecovered conclusive audit misses | Cap at two and withhold payments until a later authenticated positive; never alter finality membership/order, quorum validity, or MNAUTH |
| Live payment-audit certificate is missing at a non-null carrier | Quarantine only the dependent branch, request the exact audit witness ID, and activate an available valid sibling |
| Covered payment-audit certificate is absent during historical IBD/replay | Recompute the bitmap transition, fsync an active/prospective marker before provisional use, continue base sync, and gate signing/readiness until a covering CLSIG is durable |
| Covering payment-audit CLSIG is absent, off-branch, below-terminal, or invalid | Keep requesting a valid descendant; the marker grants no authority and no covered certificate may be pruned |
| Payment-audit state, pre-seal, checkpoint, certificate, or prune-batch fsync fails | Keep the obligation and gates active; never publish provisional state, clear a marker, advance a checkpoint, or infer an empty audit |
| All root-capable valid payees are payment-withheld | Use the ordinary root-capable deterministic payee as the explicit liveness fallback |
| No root-capable valid payee exists at or after `A` | Reject the block; never redirect the masternode reward to a rootless operator or the miner |
| Regtest preparation profile supplies activation, candidate, or receipt fields | Fail startup; preparation has registry/quorum history only and no finality state |
| Partial public or full regtest deployment profile | Fail startup; never infer missing activation, receipt state, or schedule values |
| No durable winner yet | Continue ordinary valid-most-work fork choice and forbid destructive auxiliary-state GC |

## 14. Required test matrix

### Cryptographic and wire tests

- Official FIPS 205 SLH-DSA-SHAKE-128s ACVP/KAT vectors for key generation,
  signature generation, and signature verification against the exact pinned,
  minimized implementation.
- Scheduled-WOTS+ KATs and differential vectors for key generation, public-key
  derivation, deterministic signing, and verification at every authorized
  leaf; mutate `R`, WOTS elements, authentication nodes, message, public key,
  and implicit leaf independently.
- Golden bytes for global registration, rotation, child commitments/proofs,
  MNAUTH, quorum descriptors, share transcripts, and final CLSIG.
- Exact size tests for the 704-byte child signature, 1,248-byte authenticated
  signer, 1,282-byte live share envelope, 2,614-byte self-contained share, and
  1,001,147-byte final CLSIG; reject
  one-byte-over, truncated, and length-confusion encodings.
- Bitmap tests for 266/267/268 bits, including non-byte-aligned residual bits,
  duplicate/reordered slots, selected masks with 2/3/4 bits, and non-zero
  unselected bitmaps.
- Cross-domain replay tests among global/root, MNAUTH, ChainLock, and provider
  operations.

### Deterministic state and quorum tests

- Roster/key-root agreement across implementations and architectures.
- Initial tx86 authorization requires both the existing ECDSA owner and the new
  SLH key's proof of possession; active rotation requires the current SLH key,
  while owner recovery is rejected before PQ revocation plus the full
  1,152-block delay.
- Registration immediately before/after cutoff; wrong depth/profile/cap,
  generation, first epoch, zero/reused tree ID, and root encodings.
- Key-only and root-changing global rotation before/after cutoff, owner recovery
  delay, fresh-root enforcement, generation 15-to-16 acceptance,
  generation-17 rotation/recovery rejection, and losing-fork
  registration/rotation.
- Active/frozen root immutability after global rotation/revocation.
- Normal-roster 399/400 rooted boundaries, recovery-roster 299/300 valid-key
  boundaries, and networks with fewer than 400 eligible members.
- Fixed epoch advance when an epoch is unusable; no fallback to last successful
  quorum.
- Four-epoch bootstrap and all epoch-boundary/reorg positions. Bootstrap
  descriptors must authorize their exact base height/hash through `A-1`; epochs
  after bootstrap must authorize their exact roster snapshot through an
  accepted ChainLock, and neither path may accept a branch-derived substitute.
- Depth-16 tree build/cache round-trip, internal-node mutation with a recomputed
  file checksum, proof/public-key/sibling mutation, and refusal to build on a
  consensus or network-processing thread.
- Reject live CLSIGs naming an eligible but unaccepted predecessor, including
  the exact predecessor BTCC cursor mismatch case.
- Restart-import one checksummed durable latest winner only into an empty store,
  fully reverify its branch/rosters/signatures, and prove that P2P admission
  cannot invoke the import exception.
- Recovery-capsule tests compare raw-source and capsule-derived rosters after
  source pruning, retain each required registration-cutoff and signed-target
  snapshot, enforce the 131-source cap with atomic last-owner eviction, reject
  missing, mismatched, and orphaned startup capsules, and restart an
  authorization-only recovery audit seal from its exact persisted context.

### Signer journal tests

- Reserve-before-sign crash at every write/fsync boundary.
- Restart from `EMPTY`, `RESERVED`, and `SIGNED` states.
- Same-message retransmission returns byte-identical stored signature without a
  signer call.
- Competing block at the same absolute height is permanently refused.
- Reorg, reindex, chainstate rollback, restored datadir, and restored wallet do
  not roll the journal back.
- Heights that are ineligible, too early, too late, or not fully validated
  consume no leaf.
- Ordinary leaf mapping at ordinals 0 and 230, audit mapping at leaves 231
  through 234, refusal of leaves 235 through 255, and invalid schedule cases
  that consume no leaf.
- Same physical leaf with different logical purpose, height, or message
  conflicts; restart keeps both reserved and signed leaves consumed. Exercise
  the unreleased version-1 schema directly, with no usage tally or migration.
- Generic RPC and unauthenticated P2P input cannot invoke the child signer.

### ChainLock/finality tests

- Default CI P2P coverage must negotiate protocol 70018, enforce authenticated
  share admission, exercise CLSIG inventory/request tracking, and decode an
  exact 1,001,147-byte certificate with 801 authenticated signature slots
  without changing the 400/267/3-of-4 consensus geometry.
- Exactly 267 valid signatures in each of any three active quorums.
- Parallel verification produces identical results at every thread count.
- One bad signature at the beginning/middle/end of each quorum.
- Same logical statement with different valid witness subsets is non-conflicting;
  invalid witness caching does not suppress a valid witness.
- Conflicting statements, previous-ChainLock mismatch, stale context, unknown
  block, headers-only block, and block not valid through scripts.
- A target that skips the first eligible successor of its declared predecessor
  is rejected in live, raw-storage, trusted-persistence import, archive, and
  catch-up admission. Advancing into a new signing window expires the old
  collector and relay roster and creates the unique current `H = N(P)` view;
  accepting its winner clears stale statement variants while preserving any
  concurrently created exact-successor view.
- Reorg before signing lag, during parallel verification, after witness receipt,
  and after accepted finality.
- Ordinary catch-up accepts exactly the latest signable active target or a
  competing target sharing its `H - sign_lag` boundary, and rejects an expired
  prior target, a future target, and a deeper fork, as well as admission before
  base sync, during incomplete snapshot validation, or with assume-valid above
  the receipt anchor. Marker
  cases do not widen this set except for the exact terminal or covering forms
  specified above.
- Historical admission verifies all 801 signatures before any retained-body or
  chain-age-dependent receipt I/O; an invalid first/middle/last signature
  performs no such scan. It then rechecks the exact branch, rosters, marker
  token, receipt state, and persistence order before publication.
- A fully authenticated catch-up object that fails only because of local disk,
  validation-state, or concurrent-context conditions does not punish its peer;
  exact `LIVE` predecessor chaining resumes after acceptance.
- With a common durable base `S`, deliver a valid height-`H` `KEEP` certificate
  to only one store, then deliver a valid height-`H+5` statement based on `S`
  to both. The store that retained `H` must dual-derive the same active roster
  bundle, preserve every durable side-state floor, and converge on `H+5`.
  Reject a missing exact base, a divergent active/recovery source, an
  unrelated next-beacon mutation, and provisional-observation rollback without
  the exact candidate-bound reconciliation proof.
- Verification queue, per-peer bytes, duplicate flood, and cancellation DoS
  tests under ASan, UBSan, and TSan.
- End-to-end CPU, memory, and bandwidth benchmarks on minimum supported hardware
  with 801 valid signatures and adversarial invalid bundles.
- `pq_chainlock_integration_tests` deterministically constructs all four
  400-member rosters and completes production collector/verifier acceptance
  with 801 real scheduled-WOTS+ signatures and the exact 1,001,147-byte wire
  object.
  `feature_pq_chainlocks.py` separately loads a checksummed, exact-branch
  regtest roster fixture, forwards real shares between authenticated peers,
  proves that 800 shares cannot publish a winner, and accepts only the 801st
  share through the production collector/verifier/store path. It then checks
  CLSIG retrieval, restart import, transaction finality, and rejection of a
  previously validated greater-work competing branch. Neither layer reduces
  the 400/267/3-of-4 geometry or injects a prebuilt final certificate.

### MNAUTH tests

- Inbound/outbound direction, challenge replay, version downgrade, nonce mix-up,
  wrong network/genesis, wrong proTxHash/key version, duplicate authentication,
  and key rotation disconnect.
- Actual-keyed-netgroup/global pre-verification limits, exact-registry-service-
  attributed proTxHash/keyed-netgroup/global initiator-signing limits, and
  authenticated-proTxHash/keyed-netgroup/global responder-signing limits that
  survive reconnect, plus bounded asynchronous verify/sign executor saturation
  and cancellation.
- Connection teardown during signing/verifying, reconnect-resistant signing
  admission, and cache correctness after reconnect.
- MNAUTH failure never changes consensus state.

### Payment-audit tests

- Twenty-four retrospective `ADVANCE` rows, exact row deadlines, strict-fresh
  `K`, the exact non-null K+10 BTCC receipt projection, exact active Bitcoin
  `H(K)+37`, the non-BTCC `B`, the bounded carrier window,
  `KEEP`/null-receipt/stale-Bitcoin-hash skips, and every epoch edge.
- Full-schedule audit mapping at `231 + (sealEpoch - childEpoch)` for leaves
  231 through 234, with wrong subject, seal, child epoch, candidate origin, and
  active-epoch count rejected before reservation.
- Capture valid row responses before their ordinary certificates exist,
  reconcile HAVE/RESP sets, fsync each local bitmap at its height deadline
  rather than local wall time, select only after all 24 rows are frozen, and
  reject duplicate, malformed, or context-invalid responses within fixed
  admission limits.
- Exact 400-member subject descriptor, 300-member conclusiveness gate, one miss
  remaining payable, second unrecovered miss withholding payment, and the
  all-withheld deterministic fallback.
- Probation state remains exact and branch-pinned but is absent from roster
  selection inputs. Snapshots that differ only in misses/withholding build
  byte-identical rosters, and a reorg restores probation and roster state
  independently.
- Exact full-roster selection above and below 400 root-capable candidates:
  preserve root-first ordering, rank all candidates by the existing
  epoch-hash score and collateral tie break, and take the first 400 without a
  predictable reserved suffix. Roster construction remains byte-identical
  when snapshots differ only in payment-probation state.
- A positive clearing one or two misses even when the overall audit is
  inconclusive; an absent or inconclusive audit never adds a miss.
- Exactly 267 audit signatures in each of exactly three active rosters, with
  one common base statement, 801 signer-bound report bitmaps, exact 134-of-267
  per-roster classification, and no common-bitmap convergence requirement.
- Exact 2,653-byte response, 3,013-byte share, 1,298-byte report witness, and
  1,041,546-byte final audit bounds; exact-witness-ID
  requested retrieval, at most four live unapplied witness candidates (one per
  three-of-four reporter mask), one-large-object-per-pass upload accounting,
  timeout, and wrong-ID handling.
- Exact 257-byte null/non-null receipt and 261-byte tagged coinbase segment,
  with the canonical 50-byte `online_members` suffix and fixed ordering before
  BTCC/BTCPREV. The null bitmap must be zero; unsupported versions, truncation,
  a mutated bitmap, certificate/bitmap disagreement, off-branch, stale-epoch,
  wrong-seal,
  wrong-root, and conflicting receipts are rejected. Differential accumulator
  tests prove that every bitmap bit changes the cumulative hash.
- Live carriers require and fully verify the exact certificate before applying
  the bitmap transition; missing-certificate branch quarantine/requeue, reorg
  undo, and local store corruption remain non-punitive.
- Synchronous restart of a miss/withheld state proves that process restart,
  database reopen, and connection churn cannot reset probation.
- Missing covered witnesses during IBD create checksummed active/prospective
  payment-audit pre-seals before provisional state is usable. Restart and reorg
  tests preserve the earliest carrier and predecessor roots, advance only the
  terminal carrier/receipt with a monotonic revision, retain every required
  block/DMN/PQ input, and fail closed at every marker/state fsync cut.
- A covering CLSIG must pass ordinary 801-signature verification, be the exact
  accepted active-branch descendant at/above the terminal carrier, and sign the
  recomputed cumulative receipt state and probation root. Wrong predecessor,
  off-branch/below-terminal targets, a marker alone, or either root mismatch
  cannot authenticate the prefix, clear a gate, or prune a witness.
- Checkpoint tests bind the terminal receipt epoch/hash to the exact durable
  covering target and logical/witness IDs. Persist-and-prune is one synchronous
  batch; exact replay is idempotent, regressions and equal-epoch conflicts are
  rejected, every certificate/index at or below the boundary disappears, and
  the live suffix remains readable after crash/restart.
- An already participating roll-forward recovery replays a long on-chain
  receipt prefix without its covered full witnesses, remains
  signing/readiness-gated until one later P2P CLSIG covers the prefix, and
  reproduces the same accumulator, probation root, and checkpoint as a node
  that originally verified every certificate. Fresh sync, full reindex,
  `-reindex-chainstate`, and snapshot reconstruction reproduce those values
  provisionally but remain P2P/restoration-gated until a separately
  authenticated checkpoint or snapshot release ends quarantine.
- The six-epoch storage-bound regression seals and checkpoints five audit
  prefixes, rejects retrieval/admission/pinning of their retired epochs, and
  leaves only the sixth live/uncovered suffix after restart. This exercises the
  bounded-key lifecycle over a short horizon; a true multi-year storage and
  physical-compaction run remains required. Independently, restart accounting
  retains one durable best CLSIG plus at most one unsealed BTCC `ADVANCE`, with
  eight recent CLSIGs in the bounded RAM store.

### BTCC/NEVM tests

- `KEEP` exactly repeats the prior cursor; malformed keep is rejected.
- `ADVANCE` references the exact ChainLocked ancestor and stored BTCPREV.
- Bad, stale, shallow, non-best-chain, competing-fork, duplicate, and
  non-descendant BTC candidates cause no advance.
- BTC backend outage still permits a ChainLock with `KEEP`.
- Deterministic candidate injection at lag on fresh sync, reindex, pruned nodes,
  and reorgs.
- Receipt-anchor records are all-or-none, are either the canonical empty state
  before the first carrier or land on an exact carrier, and reject a compiled
  assume-valid height above the boundary.
- A missing historical non-null receipt creates a checksummed pre-seal with
  the earliest carrier/predecessor state, terminal carrier/exact receipt, and
  increasing revision. A later missing receipt advances only the terminal;
  malformed, truncated, or incomplete state fails closed.
- The marker admits the exact terminal `KEEP` or `ADVANCE` at `T=C-10` as archive below
  the durable winner or catch-up above it, and admits a later certificate only
  when its active-branch target is at/above and descends through every uncovered
  marker terminal on that branch. Wrong logical ID/receipt, arbitrary old,
  below-terminal, off-branch, and losing prospective-branch certificates are
  rejected.
- Marker-authorized covering catch-up recomputes every retained receipt from
  the earliest marker's predecessor state through the candidate and rejects a
  missing body, malformed receipt, accumulator mismatch, assumed-valid index,
  or branch/context change.
- Crash cuts at the block-index, DMN, PQ, and certificate fsync boundaries
  never publish partial recovery. Mutating or promoting the marker between
  preparation and publication changes its token and forces a retry; the marker
  mutex pins the accepted revision through the snapshot/certificate barrier.
- A failed EvoDB value or tombstone batch keeps the exact staged chunk
  retryable; retry neither loses a snapshot update nor resurrects a pruned one.
- The replay block-prune floor can move only lower (including across a deep
  reorg), never forward on a terminal revision, and is removed only when the
  corresponding durable obligations clear.
- Replay snapshot recovery survives a null-receipt tail longer than the
  1,728-entry DMN cache and restart proves its oldest/newest states remain
  readable. Separately, more than 1,728 same-height non-cutoff side-branch writes
  cannot evict exact branch-local roster-cutoff DMN/PQ snapshots, while ordinary
  non-cutoff snapshots remain bounded and may be discarded. Maintenance keeps
  the protected persisted snapshots until replay/finality retention clears.
- A non-empty deterministic-MN chain writes an inverse link for every block,
  crosses the 1,728-full-snapshot horizon, flushes and restarts, then
  reconstructs exact parent hashes, IDs, registration count, unique-property
  transfers, payee/PoSe state, and the newly entering random-access boundary.
  Missing tip/interior links and conflicting persisted parents fail closed.
  A disk-backed Chainstate regression repeats the greater-than-1,728 rollback
  through `InvalidateBlock` and verifies the resulting DMN, PQ-registry, and
  payment-probation roots across restart without live 801-signature crypto.
- With the historical certificate withheld, base Syscoin reaches and validates
  its tip while signing and all paired Geth notifications after the earliest
  carrier remain paused. Supplying an exact or covering certificate resumes
  base finality independently of Geth, but no test may inject a certificate or
  treat the marker itself as quorum authority.
- Deferred NEVM replay starts at the earliest durable boundary, is idempotent
  in bounded batches, and clears only when Geth reports the exact applied
  `(height, last Syscoin block hash)`. Crash/reorg tests cover both active and
  prospective pre-seal markers and never substitute a zero checkpoint.
- Prolonged-outage tests exercise unbounded block/DMN/PQ retention accounting,
  synchronous DMN write-through failure, disk exhaustion, and post-recovery
  compaction; every storage failure remains local and fail-closed.
- NEVM candidate visibility is distinct from bridge promotion by the accepted
  live cursor.

### Migration and legacy tests

- Exact `A-1`, `A`, and `A+1` boundaries for every legacy and PQ payload,
  provider authorization rule, and root-qualified payment rule.
- Before the first winner, accept the valid-most-work branch without a
  configured hash; prove that first-seen invalid data cannot pin `A-1`, while a
  fully verified durable certificate binds its candidate ancestry.
- Prove that `INITIALIZE` accepts only the first canonical post-`A-1` target,
  uses four ordinary pre-activation frozen snapshots with one exact delayed
  Bitcoin seed, rejects activation authority and alternate targets, and never
  rolls epochs. Separately prove that durable-prior `RECOVER` still rolls only
  after its pending Bitcoin anchor is stably inactive.
- Exercise higher-work pre-winner reorgs with `-checkpoints=0`, normal sync,
  headers-first sync, reindex, `-reindex-chainstate`, VerifyDB, roll-forward,
  and restart. After a winner is enforced, conflicting ancestry is rejected.
- Reject `A <= 0`, `A < DIP3`, preparation at or after `A`, `A-1` before an initial
  roster authorization point, a first post-`A-1` target that is not the
  canonical phase-3 BTCC target, and a non-null initial predecessor cursor.
- Differential replay below `A`: a legacy BLS build and opaque-codec build must
  produce identical transaction/block hashes, deterministic MN state, and PoSe
  state without consulting a release-pinned state root.
- Legacy/basic 48-byte and 96-byte golden vectors, including all-zero values,
  malformed non-curve bytes, state diffs, provider payloads, commitments, and
  existing EvoDB records. Opaque replay must never attempt curve validation.
- Existing datadir upgrade with retired DKG/vvec/secret-share databases.
- Old/new peer interoperability below `A` and deterministic rejection or
  ordinary-peer downgrade at and above `A`.
- Fresh genesis sync without an externally supplied deterministic-MN snapshot.
- Public all-sentinel parameters replay historical commitments and legacy
  provider payloads through sync/reindex while starting no ChainLock finality
  service; any current partial public profile fails startup.
- The future BLS-free public preparation profile starts from known chain data,
  admits registry/shadow operation without finality authority, completes four
  usable epochs without assigning an activation hash or state root. Regtest
  with no PQ argument stays disabled; explicit regtest preparation accepts only
  registry/quorum fields and proves
  that no finality store/signing/admission/enforcement exists; full regtest
  activation requires complete `A`, `R`, and schedule fields.

## 15. Unresolved deployment constants and activation blockers

The following must be resolved in code and release artifacts before activation:

- each supported public network's future activation height `A`;
- the receipt assumption `R` and independently reproduced cursor/accumulator,
  without imposing an artificial `R >= A` ordering;
- `PQ_EPOCH_ORIGIN`, registration cutoff lag, snapshot lag, and the precise
  first eligible ChainLock height after `A-1`, including proof that `A-1` covers
  every initially active roster authorization point and precedes the first
  BTCC candidate source;
- global-key registration start and shadow-protocol start heights;
- maximum future registry horizon and transaction fee/relay policy for the
  8,112-byte tx86 payload;
- official FIPS 205 SLH-DSA-SHAKE-128s ACVP/KAT evidence for key generation,
  signature generation, and signature verification using the exact pinned,
  minimized implementation on every supported platform;
- independent review of the exact scheduled-WOTS+ construction, its vendored
  FIPS 205 SHAKE primitive boundary, 32-byte public key, 704-byte encoding,
  explicit 235-leaf schedule, KAT hashes, source revision, bounded-use argument,
  and audit results;
- production resource targets for the fixed protocol-70018 share/CLSIG relay,
  verification caches, and bounded worker pools;
- production resource bounds and independent review for the payment-audit
  compact-replay, active/prospective pre-seal, covering-CLSIG checkpoint, and
  atomic pruning lifecycle, including proof that normal multi-year operation
  retains only a live/uncovered certificate suffix rather than accumulating
  1,041,546 bytes every epoch;
- operational sizing, alerts, and recovery tests for synchronous replay-snapshot
  writes and the intentionally unbounded block/DMN/PQ retention during a
  prolonged certificate or Geth outage;
- independent review and whole-chain soak evidence for the implemented
  restart-safe deterministic-MN inverse journal. With the corresponding Core
  block and undo records retained, sequential post-DIP3 rollback reconstructs
  DMN parents beyond the bounded 1,728-full-snapshot window; a missing or
  corrupt link fails closed and requires reindex. Retain the non-empty deep
  rollback/restart and disk-backed Chainstate root regressions. Standard prune
  mode remains bounded by retained `blk`/`rev` data, while live replay markers
  separately retain ranges owned by their durable obligations;
- a frozen inverse-journal encoder/decoder and explicit format migration or
  reindex policy before any deterministic-MN record/state layout changes; the
  current field mask rejects later state fields, but mutable DMN serializers
  must never acquire new disk meaning under the existing schema number;
- operational sizing, metrics, alerts, corruption drills, and adversarial soak
  evidence for the implemented journaled DMN-inverse and rooted PQ-snapshot GC.
  Validate normal update rates, mass-PoSe/state-update amplification, bounded
  batch restart, moving-tip progress, and every finality/replay veto; never
  reduce retained rollback history to the 1,728 full-snapshot cache horizon;
- recovery-capsule RAM and disk sizing at the 6,553,782-byte encoded per-source
  maximum and the 131-source ownership ceiling (858,545,442 bytes, about
  819 MiB, before database and container overhead);
- production benchmark calibration, independent review, metrics/alert policy,
  and adversarial soak evidence for the implemented bounded asynchronous
  MNAUTH executors, reconnect-resistant actual-keyed-netgroup/global
  pre-verification admission, exact-registry-service-attributed initiator-signing
  admission, and authenticated-proTxHash responder-signing admission, covering
  latency, queue depth, in-flight work, executor saturation, reconnect drops,
  and rate-limit drops;
- network-specific BTCC candidate origin, initial/assumption cursor, and
  compatibility of the consumer-facing header-proof/checkpoint interface;
- bridge behavior before the first valid live PQ CLSIG;
- reproducible real-chain migration evidence: differential replay below `A`
  comparing a known-good pre-migration release and the opaque-codec build,
  upgrade of an existing datadir containing retired DKG/vvec/secret-share
  databases, proof that `A-1` covers all bootstrap roster authorization points,
  and independent reproduction of `R` from public chain data;
- an explicitly supported BLS-free public preparation/shadow release, with
  reproducible evidence that it begins from already-known chain data, has no
  finality authority, completes four usable shadow epochs, and coordinates a
  future activation height with adequate operator notice; and
- the single-signer backup and recovery procedure for scheduled child-key
  journals, including rotation to a fresh child-tree generation after loss.

The depth-16 outer commitment provides the fixed epoch horizon described above.
Separately, each derived child key owns an 8,176-byte public height-8 warm
cache. These are engineering properties, not a security review.

Activation remains disabled until the complete Section 14 matrix passes on all
supported platforms, the payment-audit replay/checkpoint rules receive
independent consensus/security review, the scheduled-WOTS+ construction
receives independent cryptographic review, and the 801-signature/proof verifier
and 1,001,147-byte relay path meet explicit resource targets. Shadow success
alone is not cryptographic validation.

## 16. References and security caveat

- NIST, [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.205), August 2024.
- NIST, [FIPS 202: SHA-3 Standard](https://doi.org/10.6028/NIST.FIPS.202).
- Dash, [DIP-0008: ChainLocks](https://github.com/dashpay/dips/blob/master/dip-0008.md), for the ancestry-finality model from which the existing Syscoin flow derives.

FIPS 205 standardizes the global SLH-DSA-SHAKE-128s profile. The scheduled
Merkle-WOTS+ child construction reuses vendored FIPS 205 SHAKE primitives but
is not itself a standardized FIPS 205 parameter set; its explicit-index,
bounded-use composition and this raw multi-quorum protocol still require
independent review. This document is an engineering design to make assumptions,
state, wire behavior, and failure modes reviewable; it is not a
production-readiness claim.
