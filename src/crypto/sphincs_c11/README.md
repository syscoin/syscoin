# SPHINCS− C11-SHA research port

This directory is an isolated C++ port of the **C11-SHA** parameter set from
[`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-) at commit
`55b2f3e25d8d7cc0df33ccdb13becca1a168b26f` (2026-07-30). The upstream
algorithm and reference implementation are MIT licensed; see `LICENSE`.

## Status and security boundary

This is a research construction, not FIPS 205 SLH-DSA, not an audited
cryptographic library, and not ready for consensus use. Upstream gives the same
warning. It combines WOTS+C and FORS+C counter grinding with a one-shot
`H_msg`; those mechanisms have no FIPS 205 analogue. Before activation it needs
independent cryptanalysis, constant-time review, cross-platform vectors,
fuzzing, misuse-resistant key storage, and a frozen consensus specification.

The published category-5 SHA-256 SPHINCS+ attack is not a generic 40-bit loss
for every SHA-2 construction. The authors' NIST PQC Forum discussion explains
that the relevant internal-state collision advantage disappears at `n=16`,
where SHA-256's internal state is twice the output width. This rules out that
specific transfer argument only. It does not analyze or validate C11-SHA's
custom parameters, WOTS+C/FORS+C compression, bounded-use composition, or
multi-user setting. See
<https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/FVItvyRea28/m/mGaRi5iZBwAJ>
and <https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=935143>.

The intended scope is intentionally narrow:

* `n=16, h=16, d=2, a=11, k=13, w=8, len=43, target_sum=203`;
* 32-byte messages, 32-byte public keys, 64-byte secret keys, and 3976-byte
  signatures only;
* deterministic signing, including secret-keyed `R` grinding;
* no RNG, networking, quorum policy, key counters, persistent storage, or
  consensus wiring in this directory;
* reentrant verification with no mutable global state. `VerifyBatch` is a
  sequential convenience API; callers may parallelize independent inputs.

The public-key layout is `PK.seed[16] || PK.root[16]`. The private-key layout is
`SK.seed[32] || PK.seed[16] || PK.root[16]`. Parsers reject every other length;
the private-key parser recomputes the root.

## Exact construction choices

The F/H/T family is

```
SHA-256(PK.seed[16] || zero[48] || ADRSc[22] || payload)[0..15]
```

with the FIPS 205 SHA-2 compressed-address byte layout. Message and WOTS digit
fields are parsed MSB first. In parity with the pinned reference, secret WOTS
and FORS values and deterministic `R` use legacy Keccak-256, not SHA3-256. `R`
is ground from `SK.seed || "R_grind" || message || nonce_be256`; WOTS and FORS
PRF input framing is also byte-for-byte fixed by the reference implementation.
WOTS+C message compression uses the distinct SPHINCS+C address type 7; chain
hashing remains FIPS WOTS_HASH type 0. The pinned reference currently reuses
type 0 for both, so the differential-vector tool applies the paper's type-7
correction explicitly before generating the consensus fixture.

Signature offsets are canonical:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 16 | `R` |
| 16 | 208 | 13 FORS values |
| 224 | 2112 | 12 FORS authentication paths |
| 2336 | 820 | hypertree layer 0 |
| 3156 | 820 | hypertree layer 1 |

Each hypertree layer is `43*16` WOTS bytes, a four-byte big-endian grinding
counter, then `8*16` Merkle authentication bytes. The consensus profile fixes
the counter search space to `[0, 10,000,000)` and verification rejects larger
serialized counters; signer and verifier therefore define the same canonical
encoding subset. Deterministic `R` grinding uses the same exclusive search
bound, although its private nonce is not serialized.

## Bounded-use requirement

The parameter proposal's security analysis is explicitly bounded by the number
of signatures made by one key. The pinned upstream table estimates C11 at 128
security bits for 2^14 signatures, about 104.5 bits at 2^18, and about 86.1
bits at 2^20; its hypertree has only 2^16 positions. Those are upstream research
estimates, not a guarantee or an independent review. The SHA twin preserves the
construction but also needs its own analysis.

A production caller must enforce a durable, rollback-resistant per-key cap
chosen below an independently approved bound and rotate before it. The
implementation deliberately does not hide that policy in volatile process
memory. Syscoin's contemplated ChainLock profile fixes this cap at exactly 256
authorized absolute heights. That value follows the four-epoch lifetime and
five-block cadence; it is an engineering bound, not a cryptographic result
supplied by this code. The cold signer performs roughly 292,000 hash calls per
upstream's C11 accounting.

Reorganizations, restored backups, cloned nodes, and concurrent signers must
not reset or fork the counter. Exhaustion must fail closed and affect liveness,
never authorize a new key or silently reuse an exhausted one.

The in-process Syscoin LevelDB journal supplies atomic burn-before-sign writes
and ordinary crash recovery only. It cannot detect rollback of the whole
datadir, a cloned virtual machine, or two hosts started from the same disk
image. Public activation therefore additionally requires a rollback-resistant
external fence (for example an HSM/TPM monotonic generation or a single-active
remote signing lease). A local journal by itself is not a production claim.

This fence does not give an operator more or less consensus weight. A final
certificate counts at most one signature for each frozen `(quorum, member)`
slot, so any number of copies of one secret key still represents one Byzantine
identity. The fence instead preserves the bounded-use assumption for an
otherwise honest key and prevents an accidental split-brain deployment from
authorizing two messages at one height. The deterministic signer produces the
same signature for the same message; replaying that signature does not consume
another distinct-message use.

## Protocol binding

`Message` is an already prepared 32-byte protocol digest; this module does not
invent its transcript. A consensus integration must specify one unambiguous,
canonical preimage containing a scheme/version tag, network or chain ID,
quorum purpose, quorum/epoch identifier, and the object being authorized. Keys
must not be reused for MNAUTH, provider operations, quorum commitments, or any
role other than the single ChainLock child-key epoch named by the transcript.
The frozen transcript and signature-count rules are part of the consensus
specification, not application metadata.

`SerializeSecretKey` necessarily returns an ordinary byte-array copy. Its
caller owns that copy and must securely erase it after protected persistence;
the `SecretKey` object itself is move-only and cleanses its storage.

## Central build and standalone parity test

The module is wired into Syscoin's central build, unit tests, fuzz targets, and
the gated PQ ChainLock implementation. That integration does not change the
research-security boundary above. For an implementation-independent build
path, the isolated parity test can still be compiled from the repository root:

```
c++ -std=c++20 -O2 -Isrc \
  src/crypto/sphincs_c11/sphincs_c11.cpp \
  src/crypto/sphincs_c11/tests/standalone_test.cpp \
  src/crypto/sha256.cpp src/crypto/sha3.cpp src/support/cleanse.cpp \
  -o /tmp/sphincs_c11_test
```

The test vector records a public root and SHA-256 signature digest generated by
the pinned Python signer using explicit seeds. `tools/differential.py` can also
regenerate reference material from a clean checkout of that exact commit and,
when passed the C++ test executable, compare all 3976 signature bytes directly.

```
python3 src/crypto/sphincs_c11/tools/differential.py \
  --upstream /path/to/nconsigny-SPHINCS-minus \
  --cpp /tmp/sphincs_c11_test
```

The Python reference requires PyCryptodome. The fixed fixture uses
`SK.seed=000102...1f`, `PK.seed=a0a1...af`, and message bytes
`message[i]=(3+7*i) mod 256`. Its public key is
`a0a1...aeaf || a3d1b4ec763f8be45e4a56375774efe9`; the full 3976-byte signature is
committed by SHA-256
`99c0656fccd9353d4b68db3f4d09afc1485c9cc59381ff5603208a25be026886`.
Byte parity demonstrates faithful porting, not security: the pinned Python
signer is an upstream research oracle, not an independent cryptographic
implementation or certification.
