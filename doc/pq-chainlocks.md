# Post-quantum ChainLocks: consensus and migration design

Status: design specification; disabled pending the complete required test matrix
and independent security review

This document specifies the intended replacement for Syscoin's BLS/DKG
ChainLock stack. It is implementation guidance for the consensus, wire, state,
and migration work. It does not claim that the proposed C11-SHA child signature
profile is standardized, audited, or ready for mainnet.

The final activated implementation has no BLS cryptography and no DKG. It keeps
only byte-exact, non-cryptographic legacy decoders needed to replay the chain up
to the mandatory migration-state boundary `H`; the later immutable finality
predecessor `F` is a separate block-only anchor.

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
- Each member has a distinct **C11-SHA** child key for each quorum epoch. The
  child profile is usage-limited and is never used for MNAUTH, provider updates,
  governance, or another epoch.
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
  on-chain receipt. Live admission verifies the receipt's exact `ADVANCE`
  CLSIG; historical sync authenticates a recomputed compact receipt prefix
  with a release anchor and either current-window catch-up or the narrowly
  marker-bound prolonged-outage recovery below, instead of retaining every old
  multi-megabyte certificate.
- A payment-audit certificate is required while its receipt is live, but it is
  not a permanent historical dependency. `PaymentAuditReceipt` commits the
  classified 400-member bitmap on chain; historical IBD may replay that compact
  prefix provisionally, then authenticate it with a normally verified covering
  CLSIG and prune the covered full audit certificates.
- The immutable migration-state anchor `H` pins one block plus the reconstructed
  deterministic-masternode and PQ-registry roots that authorize opaque legacy
  replay. The distinct immutable finality anchor `F` pins the initial PQ
  ChainLock predecessor and its bootstrap-roster ancestry. The independently
  updateable receipt assumption `R` authenticates only compact BTCC receipt
  history. `defaultAssumeValid` and ordinary optional checkpoints are not
  substitutes for any of these rules.

The design does not attempt to:

- make ECDSA-protected coins, collateral, or governance post-quantum;
- provide encrypted or channel-bound transport through MNAUTH;
- prove historical Bitcoin best-chain membership from AuxPoW alone;
- make C11-SHA production-ready by specification fiat; or
- preserve any post-activation BLS/DKG RPC or P2P compatibility.

## 2. Consensus constants

The current quorum geometry remains the starting point:

| Constant | Proposed value | Meaning |
| --- | ---: | --- |
| `PQ_QUORUM_SIZE` | 400 | Ordered roster slots per epoch |
| `PQ_QUORUM_MIN_VALID` | 300 | Minimum certified child keys for a usable quorum |
| `PQ_QUORUM_THRESHOLD` | 267 | Required signatures in one quorum (`2f+1`, `f=133`) |
| `PQ_ACTIVE_QUORUMS` | 4 | Consecutive active epochs |
| `PQ_REQUIRED_QUORUMS` | 3 | Quorums required in a final CLSIG |
| `PQ_EPOCH_BLOCKS` | 288 | Blocks between quorum epochs |
| `PQ_CL_PERIOD` | 5 | Absolute eligible ChainLock-height cadence |
| `PQ_CL_SIGN_LAG` | 5 | Local generation delay; not part of certificate validity |
| `C11_USAGE_CAP` | 256 | Maximum authorized heights per member/epoch child key |
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
usage bound.

`PQ_EPOCH_ORIGIN` should be aligned to both the 288-block rotation and the
five-block ChainLock cadence. Their least common multiple is 1,440 blocks.

Key-registry deployment is fail-closed behind three additional pinned values:
the first tx86 preparation height, the registration-cutoff lag, and the
maximum future epoch horizon. Preparation must be at or above DIP3, no later
than the mandatory migration anchor, and strictly before epoch zero's cutoff.
The roster snapshot lag used for deterministic selection is a
different consensus constant and must not be reused as the registration
cutoff.

### 2.1 Why the cap is 256

A quorum remains in a four-quorum active window for at most:

```text
4 * 288 = 1,152 blocks
```

With one eligible absolute height every five blocks, any 1,152-block interval
contains at most:

```text
ceil(1,152 / 5) = 231 eligible heights
```

The rule is one generated share per `(childKeyId, absoluteHeight)`, regardless
of reorgs, retries, peer requests, or competing blocks. Therefore a cap of 256
leaves 25 slots of arithmetic margin while remaining close to the intended
usage. A cap of 512 is not safer cryptographically; it only hides an accidental
lifetime/cadence extension and doubles the authorized use. The recommendation
is 256.

If a future protocol changes the active lifetime or makes ChainLocks more
frequent, it must introduce a new child-profile ID and usage cap. It must not
silently reuse `C11_SHA_V1` with a higher effective budget. If implementation
testing shows that a deployed rule can extend an epoch, 512 would be the safer
liveness setting, but that extension must first be made explicit in consensus.

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

### 3.3 C11-SHA child key

`C11_SHA_V1` is a short-lived per-member/per-epoch ChainLock-only profile. The
intended parameter tuple is:

```text
n = 16, h = 16, d = 2, a = 11, k = 13, w = 8
fixed signature bytes = 3,976
authorized uses       = 256
serialized WOTS count = uint32 big-endian, canonically < 10,000,000
```

The in-tree research profile uses the same exclusive `10,000,000` search
bound for deterministic `R` grinding and WOTS+C counter grinding. Verification
can enforce the bound only for the two serialized WOTS counters and rejects
larger values. The private `R` nonce is not serialized; the resulting 16-byte
`R` is checked through the ordinary message-digest constraint.

The nickname `C11-SHA` is not a sufficient consensus specification. Before a
profile ID can be activated, a normative document and two independent
implementations must pin all of the following:

- the exact SPHINCS-/SPHINCS+C construction and security claim;
- every hash and PRF invocation, padding rule, address format, and endianness;
- public/private key and signature encodings and exact byte lengths;
- signature generation randomness/determinism;
- rejection and canonicality rules;
- domain-separation inputs;
- the maximum-use security analysis at 256 signatures; and
- KAT files plus hashes of the normative source revision.

The projected CLSIG size below assumes the fixed 3,976-byte encoding. If the
normative C11-SHA profile does not produce that encoding, the profile cannot be
activated under this wire plan without revisiting the 4 MB envelope.

C11-SHA is not FIPS 205. It is research cryptography and is an activation
blocker until independently reviewed. The standardized SHAKE global key does
not confer standardization or security on the child construction.

Syscoin's zkSYS/Pali verifier work is useful implementation prior art for
strict parsing, fixed-cost verification, mutation vectors, and differential
testing. It implements the distinct draft `SLH-DSA-SHA2-128-24` profile with a
3,856-byte signature. Neither its wire format nor its security argument is
reused implicitly here: C11-SHA has a 3,976-byte signature and must retain a
separate profile ID, KAT set, implementation, and review record.

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

The reference signer imports an independent 32-byte ChainLock master seed. It
derives each C11 secret under `SYS_PQ_CHAINLOCK_CHILD_KDF_V1`, binding the
network genesis hash, a nonzero random 256-bit `treeId`, tree generation,
absolute epoch, and child profile. The actual `proTxHash` is independently
bound by every frozen roster leaf and share transcript; `treeId` is never a
substitute for operator identity. This pre-transaction identity lets a public
tree be built before a new transaction hash exists without creating a
transferable signing authority.

The C11 seed is never derived from the global SLH secret, so a key-only global
rotation preserves the current child commitment and cannot strand frozen
quorums. A root rotation requires current-PQ authorization, increments the
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
SYS_PQ_CHAINLOCK_CHILD_KDF_V1
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
    uint16  profile;             // C11_SHA_V1
    uint16  usageCap;            // exactly 256
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

`protx_rotate_operator_key` therefore preserves the root by default. Its
optional trailing `newC11Seed` performs an exceptional root-changing rotation;
the seed is wiped after the successor commitment is built and must also replace
the sentry's configured C11 seed when the new global key is installed. The RPC
refuses `newC11Seed` once generation 16 is active; ordinary key-only rotation
remains available.

### 5.2 Fixed-depth child-key commitment

There is no per-epoch registry or recurring wallet/controller transaction. One
tx86 registration or recovery authorizes a complete depth-16 Merkle root. A
normal global-key rotation preserves that root unless the current PQ key
explicitly authorizes its generation successor.

For leaf index `i`:

```text
epoch = firstEpoch + i
publicKey = C11.PublicKey(KDF(masterSeed, genesisHash, treeId,
                             generation, epoch, C11_SHA_V1))
leaf = Hash(SYS_PQ_CHILD_TREE_LEAF_V1,
            genesisHash, treeId, generation, epoch,
            C11_SHA_V1, usageCap, publicKey)
```

The complete binary tree has 65,536 leaves and uses a distinct tagged internal
node hash. Its serialized public cache is approximately 4 MiB. The cache is not
consensus state and contains no secret material; the 80-byte commitment is.
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

The immutable migration-state anchor `H` commits the canonically sorted
deterministic-masternode state and this complete PQ registry state at the same
height. It does not double as the initial ChainLock predecessor. The registry
schema intentionally differs from the abandoned per-key prototype, so stale
databases fail closed instead of being reinterpreted.

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
   `0011` fails closed. `F` is at or after the fourth bootstrap base and the
   configured first eligible target after `F` is checked to ensure every
   initially active authorization point is already on `F`'s ancestry.
3. Load the deterministic masternode list at the snapshot.
4. Use the existing deterministic score ordering, with the epoch base block
   hash as modifier, to select 400 roster slots.
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
    uint16  profile;              // C11_SHA_V1
    uint16  usageCap;             // 256
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

An epoch always materializes. If it has fewer than 300 valid child roots, its
descriptor is retained but the quorum is unusable and can never contribute to
a ChainLock. No old quorum lifetime is extended. Missing commitments do not
recreate DKG PoSe punishment unless a separate future consensus rule explicitly
defines such punishment.

The four active quorum slots at target height are the four fixed epochs selected
by the consensus epoch function, not "the last four successful quorums." This
property makes lifetime and usage bounds deterministic.

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
    uint32  quorumEpoch;
    uint256 quorumBaseHash;
    uint16  memberIndex;
    uint256 memberProTxHash;
    BTCCursor previousBTCCursor;
    BTCCursor acceptedBTCCursor;
    uint8   btccAdvance;
    BTCCReceiptState btccReceiptState;
}
```

The signature input is the canonical transcript prefixed with
`SYS_PQ_CHAINLOCK_SHARE_V1` and the genesis hash. Binding the epoch, base hash,
member index, and proTxHash prevents a signature from being counted in another
quorum or slot.

`height` is eligible only when it is on the absolute five-block schedule. The
signer waits `PQ_CL_SIGN_LAG` blocks and signs only a block locally valid through
scripts and all consensus-special processing. For a durable predecessor `S`,
the normal signable height is its first eligible successor while that height is
current. If the round expires without a durable certificate, signing advances
to the latest target `H` with active immediate scheduled predecessor
`P = H - chainlock_period`; `S` remains the state and ancestry floor for the
recovery statement.

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
    BTCCursor previousBTCCursor;
    BTCCursor acceptedBTCCursor;
    uint8   btccAdvance;              // KEEP or ADVANCE
    BTCCReceiptState btccReceiptState;
    uint8   selectedQuorumMask;       // exactly three of four bits
    bitset400 signerBitmap[4];        // 50 bytes each
    AuthenticatedC11 signatures[801]; // canonical order described below
}

AuthenticatedC11 {
    bytes32 childPublicKey;
    bytes32 merkleSibling[16];
    bytes3976 signature;
}
```

Canonical order is quorum-slot order from bit 0 through bit 3, skipping the one
unselected slot, then ascending member index for every set bit. An unselected
quorum's bitmap is all zero. Every selected bitmap contains exactly 267 bits.
There are no per-signature lengths or member indices in the signature array.

Authenticated-signature and complete wire sizes are:

```text
proof bytes per signer = 32 + 16 * 32 = 544
authenticated signer   = 544 + 3,976 = 4,520 bytes
3 * 267 * 4,520        = 3,620,520 bytes
complete fixed wire    = 3,621,236 bytes
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

A verifier performs cheap checks before any C11 work:

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
7. Verify the 801 C11-SHA signatures in a bounded parallel worker pool.
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
signer to equivocate under the `<1/3` assumption. Any two three-of-four quorum
masks share at least two rosters, yielding at least 268 double-signing
member/epoch slots. This is not a claim of 801 unique operators: active rosters
may overlap, which is why the burn journal is keyed operator-wide and branch
conflicts remain correlated.

### 7.4 P2P availability

Individual `PQCLSHARE` messages are sent only over authenticated quorum links
and to explicitly participating collectors. Any node may assemble the canonical
final object after collecting sufficient valid shares; there is no elected or
trusted aggregator.

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
identity and its C11 signature against frozen state before relaying the share
once. After one witness verifies, any later witness for that member slot is
discarded before cryptography, and an invalid first witness never reserves the
slot.

Share acceptance, rejection, duplication, an incomplete threshold, final
certificate publication, and overlay or probe availability are runtime
finality events only. They never call `PoSePunish` or `PoSeDecrease` and never
mutate `nPoSePenalty`, `nPoSeBanHeight`, or `nPoSeRevivedHeight`.
`validMembers` records frozen child-key eligibility; it is not a blame bitmap.

The final `CLSIG` is available to ordinary full nodes and through `GETCLSIG`.
Durable CLSIG storage is exactly one best certificate plus at most one fully
verified `ADVANCE` certificate that has not yet been sealed by a descendant
BTCC receipt. The live store keeps the most recent eight certificates in RAM
for bounded relay and exact lookup; it is not a historical signature archive.
Normal `LIVE` admission requires the receiver's exact durable winner as
predecessor, including the exact accepted BTCC cursor, and requires the target
to be the first eligible height after that predecessor. It also restores the
released bounded-reorg rule: the target must be the latest signable height for
the active tip, and the candidate and active chain must share the block at one
signing lag before the target. With the fixed five-block cadence and lag, a
target is 5--9 blocks behind the tip and the shared boundary is 10--14 blocks
behind it. A withheld certificate expires when the next signing window opens.
The same predecessor-to-successor relation is checked for trusted-persistence
import, archive, and catch-up admission. Collectors and their deterministic relay
overlay follow the current signing window. If the immediate successor of the
durable winner misses its window, nodes do not keep signing that expired
height: they move to the latest target `H`, declare the active block at
`H - chainlock_period` as `P`, and produce the unique `H = N(P)` recovery
statement. The durable winner remains the ancestry, receipt-state, and cursor
floor. This prevents multiple valid target heights in one declared-predecessor
view without making a missed round permanent.
Before the first winner, `F` is that durable predecessor and its BTCC cursor is
canonically null. The deployment therefore requires `F` to precede the first
BTCC candidate source rather than silently inventing cursor state at `F`.

A distinct current `CATCHUP` admission handles a fresh node, a node that missed
one or more certificates, or the rolling recovery statement above. It is
allowed only after base block sync has completed on a fully executed best-work
AuxPoW branch, ordinary assume-valid shortcuts are no longer in the candidate
range, and any snapshot background validation has completed. Public IBD may
remain true while this final authentication tail is resolved. The candidate
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

An uncovered crash-durable BTCC pre-seal marker adds only two
prolonged-outage admissions outside that ordinary current window:

- the exact terminal receipt's `ADVANCE` certificate, whose target is
  `T = terminalCarrier - 10`; below the durable winner it is stored only as the
  receipt archive, while above that winner it follows catch-up acceptance; or
- a certificate whose target is on the active branch at or above the terminal
  carrier and descends through every uncovered durable marker whose terminal
  lies on that active branch.

The second case still obeys the normal declared-predecessor and durable-winner
ancestry rules. The marker cannot authorize another old certificate, invent a
certificate, waive a signature, or turn a losing branch into the active one.
Truncated or incomplete marker records lack the terminal dependency and fail
closed rather than being upgraded by inference.

Every historical admission first rebuilds the four exact rosters from the
candidate branch, derives the same contiguous authorization prefix from the
certificate's declared predecessor on that branch, and verifies all 801
signatures under the single bounded verifier. An unselected unauthorized
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

This is intentionally a current-quorum bootstrap, not a portable proof that
every historical quorum transition produced a certificate. Its security claim
is the intersection of a fully validated branch inside the current bounded
fork window and a valid three-of-four certificate from the rosters
deterministically derived at the catch-up target. The exception is additionally bound to the exact durable
carrier range that caused execution to pause. It does not retroactively recover
historical ChainLock transition security. Recovery still requires an honest
peer to serve either the exact terminal certificate or a valid active-branch
certificate covering the terminal carrier; the marker is not a substitute for
those 801 signatures. The separate release-pinned receipt anchor bounds this
relaxation and is mandatory whenever BTCC receipts are enabled.

Restart restoration from the node's own checksummed, fsynced latest-winner
database remains separate from network catch-up. It revalidates the target
branch, exact indexed receipt state, frozen rosters, roots, and all 801
signatures. Durable acceptance orders the receipt-state index flush before the
certificate record, so a crash cannot publish a winner whose branch metadata
was never made durable. After restoration or catch-up, exact `LIVE`
predecessor chaining resumes.

The exact 3,621,236-byte certificate every five blocks is a material bandwidth
and verification cost. It must be benchmarked under adversarial load. Its size
being below a protocol cap is not evidence of production viability.

## 8. Crash-safe signer usage journal

Consensus limits authorized heights; it cannot observe signatures a compromised
signer generated privately. Every sentry therefore enforces a persistent
burn-before-sign journal for each child key.

The key is:

```text
(genesisHash, childProfile, proTxHash, quorumEpoch, childPublicKeyHash,
 absoluteEligibleHeight)
```

The durable value contains:

```text
EMPTY -> RESERVED(messageHash) -> SIGNED(messageHash, signatureBytes)
```

Required behavior:

- Reserve and fsync the height before invoking the signer.
- After signing, atomically persist and fsync the message hash and exact
  signature bytes before announcing the share.
- A repeated request for the same message returns the stored signature without
  generating another.
- A different message at the same absolute height is refused permanently.
- A reorg never deletes, rolls back, or refunds a reserved/signed height.
- Restoring an old chainstate, wallet backup, or EvoDB snapshot must not restore
  an older journal. The local journal therefore lives outside those databases
  under a separately versioned schema.
- `RESERVED` after a crash is treated as consumed unless the signer can prove
  that no signature operation occurred. Safety takes precedence over one slot
  of liveness.
- Network input, an invalid block, an ineligible height, and generic RPC calls
  cannot reserve a slot.
- A child refuses signing after 256 distinct reserved heights even if consensus
  would still accept a signature.

There is no generic post-activation `quorum sign` RPC for C11 child keys. The
only signing entry point accepts a fully constructed, internally validated
ChainLock candidate.

Journal corruption, cap exhaustion, or uncertain rollback status makes that
member fail closed for the epoch. It can reduce ChainLock liveness but never
invalidates base-chain blocks.

The local LevelDB implementation provides atomic synchronous writes and crash
recovery, but cannot prove that its complete directory was not rolled back or
cloned. Before public activation, the signing deployment must bind every
reservation to an external rollback-resistant generation and a single-active
fence, such as an HSM/TPM monotonic counter or a remote signer lease. Starting
two sentries from the same journal snapshot must fail closed. This is an
activation requirement, not a property inferred from `fsync`.

That operational fence is not part of quorum counting. Shares are keyed by the
frozen quorum slot, member index, and proTxHash, and a collector retains at most
one share for that slot. Cloning one sentry therefore cannot manufacture extra
weight: same-message deterministic signatures are exact duplicates, while
different-message signatures are equivocation by one Byzantine identity. The
three-of-four, 267-of-400 threshold and intersection arguments continue to
apply without multiplying that identity.

Accepted-certificate reconciliation pins a live journal to the latest durable
PQ ChainLock and prevents an older local vote from reopening an adjudicated
branch. It cannot detect a snapshot that rolls back the certificate database,
the journal, and the process together. The external fence exists to preserve
the research profile's 256-use assumption and to keep an otherwise honest
operator from becoming a split-brain equivocator; it is not a claim that
consensus can detect copied secret material.

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
from one recent CLSIG. Normal `LIVE` admission still requires the exact durable
predecessor; only the constrained current-quorum `CATCHUP` path in Section 7.4
may rebase across a missing certificate interval.

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
it names the `ADVANCE` certificate for `H = C - 10`, its target is that branch's
ancestor, and its accepted cursor names the same source block and persisted
`btcpPrevCommitment`. Scheduled BTCPREV heights require AuxPoW; a direct-mined
block cannot omit the parent binding. `KEEP`, a missing certificate at its one
carrier slot, or a backend outage therefore produces a null receipt and leaves
the previously accepted NEVM Bitcoin checkpoint unchanged.

An off-chain winner may temporarily carry an accepted Bitcoin cursor that is
newer than the indexed receipt cursor. Before that cursor's fixed carrier, the
next signing round keeps using the durable cursor; a descendant tip cannot be
used as premature evidence. At or after the carrier, the ChainLock target's own
ancestry makes the outcome objective. A non-null carrier advances the indexed
cursor normally. A canonical null carrier instead makes current-window signers
resume from the indexed cursor. A node whose durable winner is still ahead may
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
}
```

The hash commits the prior state, carrier height/hash, and exact receipt. Every
ChainLock statement signs the indexed state at its target. Once a fully
verified descendant ChainLock covers the carrier, that threshold statement
seals the ordered prefix. A non-null outcome makes the original 3,621,236-byte
receipt certificate prunable; a canonical null outcome objectively retires the
unreceipted cursor. Until the carrier outcome is covered, a locally accepted
exact `ADVANCE` remains durably retained and servable. The block index retains
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
lower-only block floor and replay snapshot retention; durable best/unsealed
certificates separately own the roster snapshot floors needed to reverify
them. Outside replay, only exact roster-cutoff DMN snapshots at or above that
floor are synchronously written on every branch; ordinary non-cutoff snapshots
remain in the bounded, lossy cache. More than 1,728 same-height non-cutoff
side-branch writes therefore cannot evict the persisted branch-local roster
cutoffs, but need not themselves survive restart. An in-flight
verification/publication temporarily suppresses snapshot pruning. Once those
obligations clear, normal compaction may discard old snapshots and sealed
certificates. The design does not retain every historical CLSIG forever.

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

The inverse database is append-only today, including accepted side branches.
Measured records are 245 bytes with no DMN changes and 251 bytes for one small
state update before LevelDB overhead; a three-DMN 1,731-block test occupied
about 301 bytes per record. This is roughly 63 MB/year at 2.5-minute blocks for
that light workload, but it is not a fixed bound: mass PoSe/state updates can
touch thousands of DMNs and plausibly raise journal growth into gigabytes per
year. The append-only PQ-registry history and its full periodic checkpoints can
also dominate this cost. Production activation therefore requires metrics,
capacity policy, compaction evidence, and finality-safe checkpoint/GC design;
pruning either history back to 1,728 would recreate the rollback defect.

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
marker can instead be authenticated only by its exact terminal `ADVANCE` at
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
candidate schedule, both immutable block anchors, and the receipt assumption
boundary are release-pinned.

### 10.3 Payment-only participation audit

The payment audit discourages registered operators from collecting rewards
while remaining unavailable to the PQ finality network. It is deliberately not
PoSe: its state never changes `nPoSePenalty`, `nPoSeBanHeight`, deterministic
masternode validity, MNAUTH eligibility, quorum thresholds, or collateral
validity. It filters only the deterministic payment queue. If every otherwise
valid payee is withheld, selection falls back to the unfiltered queue so an
audit outage cannot make a valid block impossible to construct.

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
`PQPOSEHAVE` bitmap and 5,142-byte `PQPOSERESP` objects. A response is written
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

The audit uses a separate purpose-domain C11 certificate. Its common statement
binds the exact K+10 receipt projection, the selected row and deadline, the
ordinary B statement, the subject descriptor and valid-member bitmap, and the
previous payment-state root.
Observation is deliberately not a common bitmap: every one of the 801 audit
signers carries its own frozen 400-bit report. This avoids fragmenting the
one-time audit slot when honest signers observed slightly different response
sets. Each audit share is 5,502 bytes. The final `PQPOSECERT` is 3,661,635
bytes: exactly 267 reporter/signature witnesses from each of three selected
active rosters, announced and requested by exact witness ID.

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
operator at the back of the deterministic payment queue. The finality roster
instead reserves a probation-independent 32-seat audit-coverage rotation when more
than 400 root-capable operators compete. Let `N` be their canonical
`proTxHash`-sorted count. For `N > 400`, the coverage window starts at
`(epoch * 32) mod N`; those 32 cyclic members are removed from the ordinary
candidates, 368 members are selected by the existing root-first, score, and
collateral ordering, and the 32 coverage members are appended as the roster
suffix. For `N <= 400`, no seats are reserved because ordinary root-first
selection already includes every root-capable operator. A static set is covered
within `ceil(N/32)` epochs; a membership change defines a new interval without
consulting probation state. The same 24 response rows and report certificate
cover these seats, so there is no `PQPOSEREC` message or extra signature type.
Even if all 32 coverage members are offline, 368 roster positions remain; the
ordinary 300-valid-key usability floor and 267-share threshold are unchanged.
For `N = 3000`, the suffix therefore gives a 94-epoch/47-day static-set maximum
to first forced exposure. Under an unbiased epoch-score model, all 400 subject
seats instead give a `400/3000` marginal selection rate and a 7.5-epoch/3.75-day
long-run mean roster-appearance interval; that expectation is not a consensus
guarantee, and payment withholding still requires two conclusive missed
appearances. The fixed 32-seat suffix deliberately preserves 68 positions of
incidental-offline slack above the 300-member audit-conclusiveness floor.
Membership churn starts a new coverage interval, and missing or inconclusive
audits never create a bounded penalty time.

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
rederives the exact subject and coverage seats, classifies the reports, requires
exact equality with `online_members`, and replays the transition against the
carrier parent's deterministic-MN and probation state. The receipt updates a
branch-local audit accumulator and hash-addressed probation state; later
ordinary ChainLocks sign both the cumulative receipt state and probation root.
Reorg undo is exact and branch-local, and payment selection reads the parent
state so the transition begins at the following payment. A missing live witness
defers only the dependent branch. Store or database corruption is a local error
and is never converted into peer misbehavior or permanent block invalidity.

Historical IBD and marker-bound replay do not require an already pruned
3,661,635-byte certificate. If the full witness is absent, the node rederives
the subject roster and probation-independent coverage seats from the historical
snapshot, applies the committed `online_members` bitmap, and requires both
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

Consequently, a fresh node replays the on-chain receipt chain, obtains one
later covering CLSIG through the ordinary P2P path, and discards covered audit
certificates; it does not download or retain a permanent 3.66 MB-per-epoch
audit archive. Full certificates are stored and served only while live or not
yet covered. Null or inconclusive audits remain fail-open no-ops for new misses.

The protocol proves possession and use of the registered child key during one
of 24 deadlines selected only later. It does not mathematically prove that an
operator ran a Bitcoin process continuously. The deterrent makes a free rider
remain ready for all 24 retrospective opportunities, while BTCC safety
continues to rely on the threshold of independent sentries that validate
`ADVANCE` against their Bitcoin views. Payment-audit activation is part of the
same currently unshipped PQ/BTCC consensus launch; no released chain contains
any payment-audit history.

## 11. Immutable anchors and legacy replay

### 11.1 Migration state `H` and finality predecessor `F`

The activation release hardcodes two different immutable block boundaries per
network:

```text
PQMigrationStateAnchor {
    int32   height;                 // H
    uint256 blockHash;              // exact hash at H
    uint256 deterministicMNRoot;    // canonical DMN state after connecting H
    uint256 pqRegistryRoot;         // canonical PQ key state after connecting H
    uint256 minimumChainWork;
}

PQChainLockAnchor {
    int32   height;                 // F
    uint256 blockHash;              // exact initial PQ ChainLock predecessor
}
```

Both rules are mandatory and are not controlled by `-checkpoints`:

- A header/block at `H` must have exactly `blockHash`.
- Every accepted header/block above `H` must have that block as ancestor at
  height `H`.
- Connecting `H` must reconstruct both pinned state roots exactly.
- `F` must be at or after `H` and, when they are equal, name the same block.
- A header/block at `F` must have exactly the configured finality-anchor hash,
  and every accepted branch above or below it must agree with that immutable
  prefix once the exact anchor is known.
- `F` must cover the exact authorization points for every roster active at the
  first eligible target after `F`. In the normal bootstrap geometry it is at
  or after the epoch-three base block.
- `F` must precede the first configured BTCC candidate source. Its initial
  ChainLock predecessor cursor is therefore canonically null; a deployment
  cannot silently infer a non-null cursor from earlier receipt history.
- The checks run during normal header acceptance, block connection, reindex,
  `-reindex-chainstate`, roll-forward recovery, and VerifyDB paths.
- A reorg that conflicts with either immutable prefix is invalid.

`defaultAssumeValid` may also be set to `H`, and `nMinimumChainWork` must be
updated, but neither supplies the mandatory ancestry/state rule.

Regtest exposes `H` through four debug arguments that must be set together:
`-pqlegacyanchorheight`, `-pqlegacyanchorblockhash`,
`-pqlegacydmnstatehash`, and `-pqlegacypqregistrystatehash`. It exposes `F`
through the atomic pair `-pqchainlockanchorheight` and
`-pqchainlockanchorblockhash`. Hashes are exactly 64 hexadecimal characters
and non-zero. Partial, malformed, pre-DIP3, inconsistent, or public-network
overrides fail during chain-parameter construction. Registry tests must
additionally configure preparation height, epoch origin, registration cutoff,
snapshot lag, and future horizon; setting either anchor alone does not
implicitly enable finality.

The release-updatable BTCC receipt assumption `R` remains a third, separate
record containing an exact block, cursor, and cumulative receipt-state hash. It
does not become the ChainLock predecessor and need not be at or after `F`.
Before the first carrier it is valid only with the canonical empty state;
afterward it must land on an exact carrier and match the recomputed state. The
compiled assume-valid boundary must not exceed `H` and must remain strictly
below `R`.

This split adds no wire field and no block-index serialization version. The
existing finality database configuration record already commits its initial
anchor height and hash, so an unshipped regtest database created with `H` in
that slot fails the configuration check and must be rebuilt with the staged
`F` profile. Public profiles are still disabled, so there is no released
production database migration to infer or accept.

The canonical state root includes at least:

- the deterministic masternode list and all state that affects roster scoring;
- ECDSA identity references and active global PQ key records;
- active and frozen child-root commitments needed by the four transition
  epochs;
- the exact append-only used-tree-ID set;
- the four PQ quorum descriptors that become active at transition;
- the last accepted legacy ChainLock/BTCC cursor migration value, if any; and
- explicit serialization/version tags for every component.

The root algorithm and ordering require independent tooling and a published
mainnet reproduction manifest before `H` can be assigned. The same manifest
must independently derive `F`, prove that it descends from `H`, and enumerate
the bootstrap roster authorization points covered by its ancestry.

### 11.2 Opaque legacy codecs

Blocks and deterministic state through `H` still contain BLS-shaped fields.
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

For blocks at or below `H`, the mandatory anchor assumes historical BLS/DKG
cryptographic validity. Replay still performs non-BLS deterministic state
effects needed to reproduce the pinned anchor, including:

- provider registration/update/removal and uniqueness rules;
- bounded commitment height/hash/schedule and bitmap decoding;
- payments, confirmations, bans/revivals, and collateral removals; and
- byte-identical transaction, block, and state serialization.

The anchor assumes the cryptographic validity of legacy commitments, but a node
syncing from genesis must still reproduce their narrow deterministic
`validMembers` PoSe transition through `H`. Those bounded opaque bitmaps affect
ban state, payee eligibility, seniority, and therefore later coinbase validity;
a root checked only at `H` cannot recover state that was needed to validate
earlier blocks. This replay performs no BLS operation and is disabled above
`H`. Provider/collateral/payment state likewise remains live input to the `H`
state roots and the post-`H` deterministic-masternode list.

Above `H`, legacy provider versions that require BLS, BLS final-commitment
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
features retained in the final activated protocol. The code described by this
document is already the final BLS-free target, not the BLS-authoritative
preparatory binary. Its public-network parameters are deliberately the complete
all-sentinel disabled profile. Supplying only part of a public profile is a
startup error. Regtest additionally exposes one explicit preparation-only
configuration: `H` plus the registry/quorum schedule are complete,
`-pqfinalitypreparation=1` is present, and every `F`, BTCC candidate, and
receipt-assumption field remains unassigned. That state constructs no finality
store and cannot sign, accept, restore, or enforce a PQ ChainLock.

Consequently Stages A and B require a separate, BLS-capable preparation line
(or another explicitly specified migration mechanism). They cannot be enabled
on a public network by partially assigning parameters in this BLS-free binary.
The regtest preparation state exists to exercise the same H-authenticated
registry history and to derive an exact `F` before restarting with the complete
finality profile.

### Stage A: preparatory release

The preparatory release still contains the legacy BLS/DKG implementation because
BLS remains authoritative while the network prepares. It adds:

- global SLH-DSA registration/rotation state;
- fixed-depth C11 child-root commitments and automatic sentry caches;
- deterministic PQ quorum descriptors;
- signer journals and shadow share/certificate generation;
- PQ MNAUTH negotiation in non-authoritative test/shadow mode;
- state-root reproduction tooling; and
- metrics and RPC inspection for key coverage, shadow thresholds, certificate
  size, latency, and verification cost.

Operators register each global key and its child root once before the required
cutoff. There is no periodic key-maintenance transaction. Shadow PQ
certificates are verified and compared across implementations but do not affect
fork choice.

### Stage B: four complete shadow epochs

The network must complete at least four consecutive usable shadow epochs so the
finality boundary already has a full four-quorum PQ active set. Each must have
at least 300 valid registered roots and repeatedly demonstrate 267-member
shares. Missing the coverage/readiness criteria delays assigning `F` and the
complete activation manifest; it does not alter the eventual fixed epoch
rules.

### Stage C: anchor release

After `H` and four complete shadow epochs are known, choose a deeply finalized
`F` that descends from `H`, covers the initial roster authorization points, and
precedes the first BTCC candidate source. Freeze a complete activation manifest
that pins `H`, its exact block hash and both state roots, `F` and its exact block
hash, minimum chainwork, epoch/BTCC origins, roster parameters, and the separate
BTCC receipt assumption `R`. `defaultAssumeValid` must not exceed `H` and must
remain strictly below `R`. Reproducible tools must independently derive every
value from the public chain.

The boundary is unambiguous:

- legacy BLS/DKG chain-derived objects are replayed through `H` with opaque
  codecs and assumed cryptographic validity;
- no legacy DKG/BLS object is produced or accepted for live authority after
  `H`;
- the interval from `H` through `F` continues the authenticated provider and
  PQ-registry history without PQ finality; and
- the first eligible target after `F` uses `F` as its exact predecessor and the
  already-shadowed four quorum descriptors selected by the specified snapshot
  rule.

### Stage D: final BLS-free activation release

Publish the BLS-free activation release only with the complete manifest. The
only remaining legacy support is the isolated opaque decoder/state-transition
module for heights through `H`. Nodes sync from genesis without a centrally
distributed state snapshot, verify the mandatory block and state roots at `H`,
then verify the separate immutable block at `F` before finality can start. A
release that still has the all-sentinel profile remains intentionally disabled;
a partially populated profile must never start.

Old peers may remain ordinary block-relay peers if otherwise compatible, but
they cannot authenticate as quorum peers or contribute to ChainLocks after
activation. There is no downgrade path back to BLS.

## 13. Failure behavior and safety invariants

The implementation must preserve these invariants:

1. There is exactly one deterministic descriptor per epoch and no miner- or
   network-chosen quorum commitment.
2. Epochs and child-key expiry advance on schedule even when finality stalls.
3. Active quorum membership and keys are frozen at their cutoff/snapshot.
4. A child key is authorized for one epoch, one profile, and at most 256
   absolute eligible heights.
5. A sentry never generates two child signatures at the same absolute height.
6. A reorg cannot refund a journal entry or cross an accepted ChainLock or
   conflict with either immutable block anchor.
7. A final CLSIG proves exactly 267 valid distinct slots in each of exactly
   three distinct active quorums for one common statement.
8. Failure to form a CLSIG affects finality/bridge liveness, not base-chain
   block validity or mining.
9. A missing scheduled BTC candidate keeps the prior cursor and does not stop a
   Syscoin ChainLock.
10. Historical base-chain replay depends on chain data and the immutable `H`
    migration-state anchor. The first finality predecessor and bootstrap roster
    ancestry depend separately on immutable `F`. Assuming pruned historical
    receipt certificates requires release-pinned `R`; resuming after a gap
    requires exact current-window `LIVE` predecessor chaining, bounded-current
    `CATCHUP`, or the exact-terminal/covering exception bound by a durable
    pre-seal marker.
11. ECDSA alone cannot replace an already active global PQ key.
12. No final-production code path invokes BLS or DKG cryptography.
13. Every `LIVE` CLSIG names the exact locally durable predecessor certificate.
    Before the first certificate, it names exact `F` with a null BTCC cursor.
    Trusted startup restoration may reinstall only this node's checksummed,
    fsynced winner; network `CATCHUP` is a distinct admission that authenticates
    either an ordinary certificate inside the current fork window or the
    marker-bound prolonged-outage proof described above.
14. An uncovered pre-seal never weakens base block validation. It pauses signing
    and paired Geth execution, durably retains the exact replay inputs, and
    permits base Syscoin sync to continue until an exact or covering certificate
    is supplied and verified.
15. A public deployment is either the deliberate all-sentinel disabled profile
    or a complete, internally consistent `H`/`F`/`R`, schedule, and roster
    profile. Preparation-only configuration is regtest-scoped and creates no
    finality service.
16. Payment-audit state is keyed by collateral identity and branch history.
    Process restart, connection churn, IP changes, and local cache loss never
    erase a miss, while an authenticated later positive may clear it.
17. Payment-audit results never mutate PoSe, deterministic-masternode validity,
    collateral validity, MNAUTH, or finality membership/order. The 32-seat
    coverage suffix is derived only from epoch and the canonical root-capable
    set, never probation; if every valid payee is withheld, the ordinary
    deterministic payee remains the consensus fallback.
18. Compact payment-audit replay is provisional until one fully verified,
    durable descendant CLSIG authenticates its cumulative receipt state and
    probation root. A marker or checkpoint is never quorum authority, and no
    covered full-audit prefix remains a permanent archive.

Expected failures are fail-closed:

| Failure | Required behavior |
| --- | --- |
| Missing/late child-root commitment or cache | Member invalid/offline for that epoch; epoch still advances |
| Fewer than 300 valid roots | Quorum unusable; no lifetime extension |
| Fewer than 267 shares | That quorum cannot contribute; with exactly 300 valid roots only 33 may be offline |
| Fewer than three usable active quorums | ChainLock finality and bridge pause; base chain continues |
| Journal uncertainty/corruption | Affected signer stops for the child epoch |
| Conflicting same-height signing request | Return cached original only, otherwise refuse |
| Child cap exhausted | Refuse; never borrow a global or future child key |
| Child-root generation 16 reached | Preserve the root for key-only rotation; reject another root rotation or recovery |
| Missing scheduled BTCPREV candidate | Use `KEEP`; do not search older candidates |
| Malformed/oversize CLSIG | Reject before expensive verification/allocation |
| Context changes during verification | Discard result and rebuild against current snapshot |
| Missing `LIVE` predecessor | Reject normal admission; current `CATCHUP` admits only the latest signable target on the active branch or a branch sharing its `H - sign_lag` boundary after full validation |
| Missing live non-null BTCC receipt certificate | Hold one bounded, non-punitive block dependency and request its exact logical ID |
| Null K+10 BTCC receipt for a payment-audit anchor | Produce no audit for that epoch; never substitute K's retained certificate or the prior cursor |
| Missing historical BTCC receipt certificate during IBD | Fsync the earliest/terminal pre-seal and required snapshots, retain replay data, continue base Syscoin sync, and pause signing/Geth from the earliest carrier |
| Prolonged-outage recovery certificate absent or withheld | Keep requesting the exact terminal logical ID or a valid covering active-branch CLSIG; the marker alone grants no recovery, so signing/Geth remain paused while base sync continues |
| Old, off-branch, below-terminal, or wrong terminal certificate | Reject; a marker authorizes only exact terminal `ADVANCE` at `T=C-10` or an active-branch certificate covering its terminal carrier |
| Marker revision/branch changes across historical verification or fsync | Abort publication and rebuild; never persist a winner under a stale marker token |
| Replay marker survives a prolonged outage | Keep the lower-only block floor and retained DMN/PQ branch snapshots; accept unbounded disk growth and synchronous DMN write latency until recovery |
| Geth unavailable or reports the wrong applied hash | Keep the replay marker and skip paired execution notifications; never substitute a null checkpoint, while base Syscoin may continue |
| Replay/snapshot/index/certificate fsync fails or disk fills | Stop the affected transition and finality/signing fail-closed; never clear the marker or publish partially durable recovery |
| All 32 probation-independent coverage seats are offline | Their offline status does not trigger reselection or change the 400-seat roster size or 267-share threshold; the remaining 368 positions can still supply 267 shares |
| Audit has fewer than 300 current-valid positive subjects | Clear misses for classified-positive subjects only; add no misses |
| Subject has one conclusive audit miss | Persist miss count one; leave payments unchanged |
| Subject has two unrecovered conclusive audit misses | Cap at two and withhold payments until a later authenticated positive; never alter finality membership/order, quorum validity, or MNAUTH |
| Live payment-audit certificate is missing at a non-null carrier | Quarantine only the dependent branch, request the exact audit witness ID, and activate an available valid sibling |
| Covered payment-audit certificate is absent during historical IBD/replay | Recompute the bitmap transition, fsync an active/prospective marker before provisional use, continue base sync, and gate signing/readiness until a covering CLSIG is durable |
| Covering payment-audit CLSIG is absent, off-branch, below-terminal, or invalid | Keep requesting a valid descendant; the marker grants no authority and no covered certificate may be pruned |
| Payment-audit state, pre-seal, checkpoint, certificate, or prune-batch fsync fails | Keep the obligation and gates active; never publish provisional state, clear a marker, advance a checkpoint, or infer an empty audit |
| All valid payees are payment-withheld | Use the ordinary deterministic payee as the explicit liveness fallback |
| Regtest preparation profile supplies `F`, candidate, or receipt fields | Fail startup; preparation has registry/quorum history only and no finality state |
| Partial public or full regtest deployment profile | Fail startup; never infer missing anchors, cursor state, or schedule values |
| `H` block/state-root or `F` block mismatch | Reject the incompatible branch and halt synchronization if no compatible branch remains |

## 14. Required test matrix

### Cryptographic and wire tests

- Official FIPS 205 SLH-DSA-SHAKE-128s ACVP/KAT vectors for key generation,
  signature generation, and signature verification against the exact pinned,
  minimized implementation.
- Two independent C11-SHA implementations with identical KATs and negative
  vectors for every field, length, padding, endianness, and address rule.
- Golden bytes for global registration, rotation, child commitments/proofs,
  MNAUTH, quorum descriptors, share transcripts, and final CLSIG.
- Exact size test demonstrating the complete maximum CLSIG is below 4,000,000
  bytes; reject one-byte-over, truncated, and length-confusion encodings.
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
- Exactly 299/300 valid keys and networks with fewer than 400 eligible members.
- Fixed epoch advance when an epoch is unusable; no fallback to last successful
  quorum.
- Four-epoch bootstrap and all epoch-boundary/reorg positions. Bootstrap
  descriptors must authorize their exact base height/hash through `F`; epochs
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
- State-root reproduction from genesis by two independent tools.

### Signer journal tests

- Reserve-before-sign crash at every write/fsync boundary.
- Restart from `EMPTY`, `RESERVED`, and `SIGNED` states.
- Same-message retransmission returns byte-identical stored signature without a
  signer call.
- Competing block at the same absolute height is permanently refused.
- Reorg, reindex, chainstate rollback, restored datadir, and restored wallet do
  not roll the journal back.
- Heights that are ineligible, too early, too late, or not fully validated
  consume no slot.
- Exact 231-lifetime maximum, 256-cap boundary, and refusal at 257.
- Generic RPC and unauthenticated P2P input cannot invoke the child signer.

### ChainLock/finality tests

- Default CI P2P coverage must negotiate protocol 70018, enforce authenticated
  share admission, exercise CLSIG inventory/request tracking, and decode an
  exact 3,621,236-byte certificate with 801 authenticated signature slots
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
- Verification queue, per-peer bytes, duplicate flood, and cancellation DoS
  tests under ASan, UBSan, and TSan.
- End-to-end CPU, memory, and bandwidth benchmarks on minimum supported hardware
  with 801 valid signatures and adversarial invalid bundles.
- `pq_chainlock_integration_tests` deterministically constructs all four
  400-member rosters and completes production collector/verifier acceptance
  with 801 real C11 signatures and the exact 3,621,236-byte wire object.
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
- Exact probation-independent coverage selection at `N=399/400/401` and larger:
  zero reserved seats for `N <= 400`; otherwise start at `(epoch * 32) mod N`,
  remove exactly 32 canonical root-capable members, select the ordinary 368 by
  root/score/collateral order, and append the cyclic 32-member suffix. Cover
  wraparound, static-set `ceil(N/32)` coverage, membership changes, and all 32
  coverage members failing to sign without changing the 267 threshold.
- A positive clearing one or two misses even when the overall audit is
  inconclusive; an absent or inconclusive audit never adds a miss.
- Exactly 267 audit signatures in each of exactly three active rosters, with
  one common base statement, 801 signer-bound report bitmaps, exact 134-of-267
  per-roster classification, and no common-bitmap convergence requirement.
- Exact 5,502-byte share and 3,661,635-byte final audit bounds, exact-witness-ID
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
- Fresh sync, full reindex, `-reindex-chainstate`, and roll-forward recovery
  replay a long on-chain receipt prefix without its covered full witnesses,
  remain signing/readiness-gated until one later P2P CLSIG covers the prefix,
  and reproduce the same accumulator, probation root, and checkpoint as a node
  that originally verified every certificate.
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
- The marker admits the exact terminal `ADVANCE` at `T=C-10` as archive below
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

- Exact `H-1`, `H`, and `H+1` boundaries for all legacy and PQ payloads.
- Exact `F-1`, `F`, and `F+1` ancestry checks, including a higher-work fork
  that ends before `F`, a branch with the wrong block at `F`, and startup where
  `F` does not descend from `H`.
- Mandatory `H` and `F` enforcement with `-checkpoints=0`, normal sync,
  headers-first sync, reindex, `-reindex-chainstate`, VerifyDB, and roll-forward
  recovery.
- Reject `F < H`, `F` before an initially active roster authorization point,
  `F` at or after the first BTCC candidate source, and a non-null initial
  predecessor cursor.
- Differential replay through `H`: a legacy BLS build and opaque-codec build
  must produce identical transaction/block hashes, deterministic MN state,
  PoSe state, and activation state root.
- Legacy/basic 48-byte and 96-byte golden vectors, including all-zero values,
  malformed non-curve bytes, state diffs, provider payloads, commitments, and
  existing EvoDB records. Opaque replay must never attempt curve validation.
- Existing datadir upgrade with retired DKG/vvec/secret-share databases.
- Old/new peer interoperability before `H` and deterministic rejection or
  ordinary-peer downgrade after `H`.
- Fresh genesis sync without an externally supplied deterministic-MN snapshot.
- Public all-sentinel parameters start with PQ finality disabled and any
  partial public profile fails. Regtest with no PQ argument stays disabled;
  explicit preparation accepts only complete `H` plus registry/quorum fields
  and proves that no finality store/signing/admission/enforcement exists; full
  regtest activation requires complete `H`, `F`, `R`, and schedule fields.

## 15. Unresolved deployment constants and activation blockers

The following must be resolved in code and release artifacts before activation:

- each supported public network's `H`, exact block hash, both state roots,
  minimum chainwork, and a distinct exact `F` that descends from `H`;
- the receipt assumption `R` and independently reproduced cursor/accumulator,
  without imposing an artificial `R >= F` ordering;
- `PQ_EPOCH_ORIGIN`, registration cutoff lag, snapshot lag, and the precise
  first eligible ChainLock height after `F`, including proof that `F` covers
  every initially active roster authorization point and precedes the first
  BTCC candidate source;
- global-key registration start and shadow-protocol start heights;
- maximum future registry horizon and transaction fee/relay policy for the
  8,112-byte tx86 payload;
- official FIPS 205 SLH-DSA-SHAKE-128s ACVP/KAT evidence for key generation,
  signature generation, and signature verification using the exact pinned,
  minimized implementation on every supported platform;
- the exact normative C11-SHA document, public-key length, fixed 3,976-byte
  encoding confirmation, profile ID, KAT hashes, source revision, independent
  implementation, cryptanalysis, and audit results;
- canonical activation-state-root serialization and independent tree/root test
  vectors;
- production resource targets for the fixed protocol-70018 share/CLSIG relay,
  verification caches, and bounded worker pools;
- production resource bounds and independent review for the payment-audit
  compact-replay, active/prospective pre-seal, covering-CLSIG checkpoint, and
  atomic pruning lifecycle, including proof that normal multi-year operation
  retains only a live/uncovered certificate suffix rather than accumulating
  3,661,635 bytes every epoch;
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
- operational sizing, metrics, alerts, corruption drills, and a
  finality-safe checkpoint/GC policy for the append-only DMN inverse and PQ
  registry histories. Validate both normal update rates and adversarial
  mass-PoSe/state-update amplification; never reduce retained rollback history
  to the 1,728 full-snapshot cache horizon;
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
- reproducible real-chain migration evidence: differential replay through `H`
  comparing the legacy BLS-capable and opaque-codec builds, upgrade of an
  existing datadir containing retired DKG/vvec/secret-share databases, and
  independent reproduction of the exact `H` block and state roots, `F` block
  and covered bootstrap roster bases, and `R` receipt state from public chain
  data;
- reproducible evidence from the separate BLS-capable preparation/shadow line
  before publishing the already BLS-free activation build; and
- the rollback-resistant signer fence and operational recovery procedure that
  prevents datadir/VM clones from sharing one C11 child-key budget.

Depth 16 was selected after the M5-class benchmark measured approximately
34.6 seconds and 4 MiB for the one-time parallel public-tree setup; the extra
46,080 bytes per certificate over depth 14 buys a roughly 89.7-year epoch
horizon at the fixed cadence. These measurements are engineering inputs, not a
security review.

Activation remains disabled until the complete Section 14 matrix passes on all
supported platforms, the payment-audit replay/checkpoint and 32-seat coverage
rules receive independent consensus/security review, C11-SHA receives
independent cryptographic review, and the 801-signature/proof verifier and
3,621,236-byte relay path meet explicit resource targets. Shadow success alone
is not cryptographic validation.

## 16. References and security caveat

- NIST, [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.205), August 2024.
- NIST, [FIPS 202: SHA-3 Standard](https://doi.org/10.6028/NIST.FIPS.202).
- M. Kudinov, A. Hülsing, E. Ronen, and E. Yogev,
  [SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost](https://eprint.iacr.org/2022/778).
- R. Perlner, J. Kelsey, and D. Cooper,
  [Breaking Category Five SPHINCS+ with SHA-256](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=935143).
- NIST PQC Forum,
  [discussion of the SHA-256 attack at truncated output lengths](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/FVItvyRea28/m/mGaRi5iZBwAJ).
- SPHINCS+ team, [reference specification and implementation](https://github.com/sphincs/sphincsplus).
- Experimental SPHINCS- work,
  [implementation repository](https://github.com/nconsigny/SPHINCs-) and
  [C-series design discussion](https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165).
- Dash, [DIP-0008: ChainLocks](https://github.com/dashpay/dips/blob/master/dip-0008.md), for the ancestry-finality model from which the existing Syscoin flow derives.

The Perlner-Kelsey-Cooper result concerns submitted category-5 SHA-256
SPHINCS+ parameter sets and reports an approximately 40-bit concrete-security
reduction for those targets. It is not an automatic result about the FIPS 205
SLH-DSA-SHAKE-128s global profile. In the linked NIST forum analysis, the
attack authors and SPHINCS+ team explain that its internal-state collision
advantage disappears for a 16-byte hash output because the SHA-256 internal
state is twice as wide as that output. That removes this specific claimed
category-5 reduction from the C11-SHA threat model; it does not establish the
security of C11-SHA. Custom parameters and modified WOTS+C/FORS+C
constructions still require independent multi-user, multi-target, quantum,
and bounded-use analysis.

FIPS 205 standardizes the global profile only. The C11-SHA child profile and
this raw multi-quorum composition remain research proposals. This document is
an engineering design to make assumptions, state, wire behavior, and failure
modes reviewable; it is not a production-readiness claim.
