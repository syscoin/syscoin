// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_VERIFY_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_VERIFY_H

#include <checkqueue.h>
#include <crypto/scheduled_wots/scheduled_wots.h>
#include <llmq/pq_child_key_tree.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_types.h>
#include <llmq/pq_roster_beacon.h>
#include <random.h>
#include <sync.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace llmq {
class CChainLocksHandler;
}

namespace llmq::pq {

class FrozenQuorumRosterCache;
class ScheduledWOTSSuccessCache;

/**
 * Deterministic state for one roster slot at the epoch snapshot.
 *
 * Eligibility is kept separate from child-key availability: a key can remain
 * committed in historical state even when its owner is ineligible to sign.
 */
struct FrozenQuorumMember {
    uint256 pro_tx_hash;
    bool eligible{false};
    std::optional<FrozenChildRootRecord> child_root;

    friend bool operator==(const FrozenQuorumMember&,
                           const FrozenQuorumMember&) = default;
};

struct FrozenQuorumRoster {
    QuorumDescriptor descriptor;
    std::array<FrozenQuorumMember, QUORUM_SIZE> members;

    friend bool operator==(const FrozenQuorumRoster&,
                           const FrozenQuorumRoster&) = default;
};

using FrozenQuorumRosters =
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>;
// The complete roster set is roughly 500 KiB. Network and scheduler paths must
// share an immutable heap allocation instead of embedding it in stack values.
using FrozenQuorumRostersPtr = std::shared_ptr<const FrozenQuorumRosters>;

enum class ChainLockVerificationError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_CHAINLOCK,
    INVALID_DESCRIPTOR,
    INVALID_ROSTER,
    DUPLICATE_MEMBER,
    DUPLICATE_CHILD_KEY,
    MEMBER_ROOT_MISMATCH,
    CHILD_KEY_ROOT_MISMATCH,
    INVALID_ROSTER_BEACON,
    QUORUM_CONTEXT_MISMATCH,
    INVALID_AUTHORIZATION,
    INVALID_SIGNER,
    INVALID_CHILD_PROOF,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE,
};

/**
 * The only contexts allowed to introduce a discontinuous roster-beacon
 * state. Ordinary live verification admits neither exception.
 */
enum class RosterAuthorizationAdmission : uint8_t {
    LIVE = 0,
    INITIALIZE = 1,
    RECOVER = 2,
    /** Exact latest winner loaded from this node's authenticated fsynced DB. */
    TRUSTED_PERSISTENCE = 3,
    /** Exact receipt-selected historical statement; never a live admission. */
    POW_HISTORY = 4,
};

/** Local deployment constants that make reset admission objective. */
struct RosterResetVerificationPolicy {
    ChainLockScheduleConfig chainlock_schedule;
    BTCCScheduleConfig btcc_schedule;
    int32_t activation_predecessor_height{-1};

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RosterResetVerificationPolicy&,
                           const RosterResetVerificationPolicy&) = default;
};

/**
 * Proof of the handler's independent selected-history checks. The verifier
 * cannot manufacture one from a peer's statement or an arbitrary hash.
 */
class VerifiedPoWHistoricalBoundary final {
public:
    [[nodiscard]] const uint256& GenesisHash() const noexcept;
    [[nodiscard]] const ChainLockScheduleConfig& Schedule() const noexcept;
    [[nodiscard]] const uint256& StatementLogicalId() const noexcept;
    [[nodiscard]] const uint256& BoundaryCommitment() const noexcept;

private:
    VerifiedPoWHistoricalBoundary(
        const uint256& genesis_hash,
        ChainLockScheduleConfig schedule,
        const uint256& statement_logical_id,
        const uint256& boundary_commitment);

    uint256 m_genesis_hash;
    ChainLockScheduleConfig m_schedule;
    uint256 m_statement_logical_id;
    uint256 m_boundary_commitment;
    friend class ::llmq::CChainLocksHandler;
};

/**
 * Exact predecessor state supplied by the branch/finality layer. Only live
 * normal transitions and RECOVER require it. INITIALIZE alone starts without
 * a prior authorization state.
 */
struct RosterAuthorizationVerificationContext {
    RosterAuthorizationAdmission admission{
        RosterAuthorizationAdmission::LIVE};
    int32_t predecessor_height{-1};
    uint256 predecessor_block_hash;
    /** Exact fully verified certificate supplying `previous`. */
    RosterAuthorizationBaseIdentity authorization_base;
    /** Required for every network admission; omitted only for trusted DB replay. */
    std::optional<RosterResetVerificationPolicy> reset_policy;
    std::optional<RosterAuthorizationPriorState> previous;
    /**
     * Exact chain/BTC facts prevalidated by the live handler. The verifier
     * rederives the sole permitted normal transition from this input; a
     * caller cannot authorize LIVE by supplying only a matching state hash.
     */
    std::optional<NormalRosterAuthorizationInput> normal_input;

    [[nodiscard]] bool HasPoWHistoryAuthorization(
        const uint256& genesis_hash,
        const ChainLockStatement& statement) const;
    [[nodiscard]] bool HasPoWHistorySchedule(
        const ChainLockScheduleConfig& schedule) const noexcept;
    [[nodiscard]] uint256 PoWHistoryBoundaryCommitment() const noexcept;

private:
    // A raw admission enum cannot grant historical trust. Only the handler's
    // independently selected/replayed boundary can mint this exact binding.
    std::shared_ptr<const VerifiedPoWHistoricalBoundary> m_pow_history;
    friend class PreparedChainLockContext;
};

/**
 * Validate the statement's complete roster state transition and return its
 * consensus authorization mask. ROTATE authorizes the old three rosters;
 * every other admitted transition authorizes all four.
 */
[[nodiscard]] std::optional<uint8_t> ValidateRosterAuthorizationState(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const RosterAuthorizationVerificationContext& context,
    ChainLockVerificationError* error = nullptr);

/**
 * Immutable capability proving one exact roster set satisfies all intrinsic
 * descriptor, membership, uniqueness, bitmap, and Merkle-root checks. Raw
 * bytes are detached and validated; the canonical builder may instead
 * transfer its exclusively owned result through a private boundary.
 * Statement height, authorization, and context-hash checks remain per use.
 */
class VerifiedRosterSet final {
public:
    ~VerifiedRosterSet();
    [[nodiscard]] static std::shared_ptr<const VerifiedRosterSet>
    Create(const uint256& genesis_hash,
           FrozenQuorumRostersPtr rosters,
           ChainLockVerificationError* error = nullptr);

    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_genesis_hash;
    }
    [[nodiscard]] const FrozenQuorumRosters& Rosters() const noexcept
    {
        return *m_rosters;
    }
    [[nodiscard]] const FrozenQuorumRostersPtr& RostersPtr() const noexcept
    {
        return m_rosters;
    }
    [[nodiscard]] bool HasCanonicalBuildProvenance() const noexcept
    {
        return static_cast<bool>(m_build_provenance);
    }
private:
    class BuildProvenance;
    using BuildProvenancePtr = std::shared_ptr<const BuildProvenance>;

    VerifiedRosterSet(uint256 genesis_hash,
                      FrozenQuorumRostersPtr rosters,
                      BuildProvenancePtr build_provenance = nullptr);

    [[nodiscard]] static BuildProvenancePtr NewBuildProvenance();
    [[nodiscard]] static std::shared_ptr<const VerifiedRosterSet>
    MintCanonicalBuild(std::unique_ptr<FrozenQuorumRosters> rosters,
                       const FrozenQuorumRosterCache& cache);
    [[nodiscard]] bool WasBuiltBy(
        const FrozenQuorumRosterCache& cache) const noexcept;

    uint256 m_genesis_hash;
    FrozenQuorumRostersPtr m_rosters;
    BuildProvenancePtr m_build_provenance;

    friend class FrozenQuorumRosterCache;
    friend class DurableRosterContext;
    friend class PreparedChainLockContext;
    friend class ChainLockStoreTestContextFactory;
};

using VerifiedRosterSetPtr = std::shared_ptr<const VerifiedRosterSet>;

class PreparedChainLockContext;

/**
 * Local, versioned copy of the exact rosters that authenticated one durable
 * certificate. This format is never accepted from the network. Its strict
 * decoder is the sole bridge from an authenticated fsynced record back into
 * an intrinsically verified roster capability after raw snapshot GC.
 */
class DurableRosterContext final {
public:
    static constexpr uint16_t FORMAT_VERSION{1};
    static constexpr std::size_t DESCRIPTOR_SIZE{
        4 * sizeof(uint16_t) + sizeof(uint32_t) +
        2 * sizeof(int32_t) + 5 * 32 + BITMAP_SIZE};
    static constexpr std::size_t CHILD_ROOT_SIZE{
        32 + 2 * sizeof(uint32_t) + ChildKeyTreeCommitment::WIRE_SIZE};
    static constexpr std::size_t MEMBER_MIN_SIZE{32 + 2 * sizeof(uint8_t)};
    static constexpr std::size_t MEMBER_MAX_SIZE{
        MEMBER_MIN_SIZE + CHILD_ROOT_SIZE};
    static constexpr std::size_t MIN_SERIALIZED_SIZE{
        sizeof(uint16_t) + 32 +
        ACTIVE_QUORUMS *
            (DESCRIPTOR_SIZE + QUORUM_SIZE * MEMBER_MIN_SIZE)};
    static constexpr std::size_t MAX_SERIALIZED_SIZE{
        sizeof(uint16_t) + 32 +
        ACTIVE_QUORUMS *
            (DESCRIPTOR_SIZE + QUORUM_SIZE * MEMBER_MAX_SIZE)};

    /** Capture only bytes already bound by a fully prepared context. */
    [[nodiscard]] static DurableRosterContext Capture(
        const PreparedChainLockContext& context);

    /** Decode only a value obtained from the authenticated local DB. */
    [[nodiscard]] static std::optional<DurableRosterContext>
    DecodeTrustedPersistence(
        Span<const uint8_t> encoded,
        ChainLockVerificationError* error = nullptr);

    [[nodiscard]] std::vector<uint8_t> Encode() const;
    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_roster_set->GenesisHash();
    }
    [[nodiscard]] const FrozenQuorumRosters& Rosters() const noexcept
    {
        return m_roster_set->Rosters();
    }
    [[nodiscard]] const FrozenQuorumRostersPtr& RostersPtr() const noexcept
    {
        return m_roster_set->RostersPtr();
    }

private:
    explicit DurableRosterContext(VerifiedRosterSetPtr roster_set)
        : m_roster_set{std::move(roster_set)}
    {
    }

    VerifiedRosterSetPtr m_roster_set;

    friend class PreparedChainLockContext;
};

static_assert(DurableRosterContext::DESCRIPTOR_SIZE == 230);
static_assert(DurableRosterContext::CHILD_ROOT_SIZE == 120);
static_assert(DurableRosterContext::MIN_SERIALIZED_SIZE == 55'354);
static_assert(DurableRosterContext::MAX_SERIALIZED_SIZE == 247'354);

/** Current immutable roster capabilities and in-flight verifier payload. */
struct PQVerificationMemoryStats {
    std::size_t live_roster_contexts{0};
    std::size_t verification_worker_pinned_bytes{0};
};

[[nodiscard]] PQVerificationMemoryStats GetPQVerificationMemoryStats()
    noexcept;

/**
 * Immutable capability proving that one exact statement/roster binding passed
 * statement, authorization, and context-hash checks against an intrinsically
 * verified roster set. Share hot paths consume this token instead of repeating
 * either validation layer.
 */
class PreparedChainLockContext final {
public:
    [[nodiscard]] static std::shared_ptr<const PreparedChainLockContext>
    Create(ChainLockScheduleConfig schedule,
           ChainLockStatement statement,
           VerifiedRosterSetPtr roster_set,
           const RosterAuthorizationVerificationContext& authorization,
           ChainLockVerificationError* error = nullptr);

    /**
     * Rebind a roster capsule read from the authenticated local DB. This does
     * not mint live canonical-builder provenance and is valid only for the
     * existing TRUSTED_PERSISTENCE authorization boundary.
     */
    [[nodiscard]] static std::shared_ptr<const PreparedChainLockContext>
    CreateFromTrustedPersistence(
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        const DurableRosterContext& durable_rosters,
        const RosterAuthorizationVerificationContext& authorization,
        ChainLockVerificationError* error = nullptr);

    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_roster_set->GenesisHash();
    }
    [[nodiscard]] const ChainLockScheduleConfig& Schedule() const noexcept
    {
        return m_schedule;
    }
    [[nodiscard]] const ChainLockStatement& Statement() const noexcept
    {
        return m_statement;
    }
    [[nodiscard]] const uint256& StatementLogicalId() const noexcept
    {
        return m_statement_logical_id;
    }
    [[nodiscard]] const FrozenQuorumRosters& Rosters() const noexcept
    {
        return m_roster_set->Rosters();
    }
    [[nodiscard]] const FrozenQuorumRostersPtr& RostersPtr() const noexcept
    {
        return m_roster_set->RostersPtr();
    }
    [[nodiscard]] const VerifiedRosterSetPtr& RosterSetPtr() const noexcept
    {
        return m_roster_set;
    }
    [[nodiscard]] uint8_t AuthorizationMask() const noexcept
    {
        return m_authorization_mask;
    }
    [[nodiscard]] const RosterAuthorizationVerificationContext&
    Authorization() const noexcept
    {
        return m_authorization;
    }
    [[nodiscard]] std::optional<std::size_t> FindQuorumSlot(
        const ChainLockShareTranscript& transcript) const noexcept;

private:
    [[nodiscard]] static std::shared_ptr<const PreparedChainLockContext>
    CreateFromPoWHistory(
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        VerifiedRosterSetPtr roster_set,
        const VerifiedPoWHistoricalBoundary& boundary,
        ChainLockVerificationError* error = nullptr);

    [[nodiscard]] static std::shared_ptr<const PreparedChainLockContext>
    CreateInternal(
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        VerifiedRosterSetPtr roster_set,
        const RosterAuthorizationVerificationContext& authorization,
        bool trusted_persistence_rosters,
        ChainLockVerificationError* error);

    PreparedChainLockContext(
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        VerifiedRosterSetPtr roster_set,
        RosterAuthorizationVerificationContext authorization,
        uint8_t authorization_mask);

    ChainLockScheduleConfig m_schedule;
    ChainLockStatement m_statement;
    VerifiedRosterSetPtr m_roster_set;
    uint256 m_statement_logical_id;
    RosterAuthorizationVerificationContext m_authorization;
    uint8_t m_authorization_mask{0};

    friend class ChainLockStoreTestContextFactory;
    friend class ::llmq::CChainLocksHandler;
};

using PreparedChainLockContextPtr =
    std::shared_ptr<const PreparedChainLockContext>;

/** One self-contained scheduled-WOTS verification job. */
class ScheduledWOTSCheck {
public:
    ScheduledWOTSCheck(scheduled_wots::PublicKey public_key,
                       uint8_t leaf_index,
                       scheduled_wots::Message message,
                       scheduled_wots::Signature signature);

    [[nodiscard]] bool operator()() const;

    [[nodiscard]] const scheduled_wots::PublicKey& GetPublicKey() const noexcept;
    [[nodiscard]] uint8_t GetLeafIndex() const noexcept { return m_leaf_index; }
    [[nodiscard]] const scheduled_wots::Message& GetMessageBytes() const noexcept;
    [[nodiscard]] const scheduled_wots::Signature& GetSignature() const noexcept;

private:
    void UseSuccessCache(ScheduledWOTSSuccessCache* cache) noexcept;
    void AccumulateResult(std::atomic<bool>* result) noexcept;

    scheduled_wots::PublicKey m_public_key;
    uint8_t m_leaf_index{0};
    scheduled_wots::Message m_message;
    scheduled_wots::Signature m_signature;
    uint256 m_success_cache_key;
    uint256 m_success_cache_signature_hash;
    ScheduledWOTSSuccessCache* m_success_cache{nullptr};
    std::atomic<bool>* m_accumulated_result{nullptr};

    friend class ChainLockVerifier;
};

using ScheduledWOTSCheckQueue = CCheckQueue<ScheduledWOTSCheck>;

struct PreparedChainLockVerification {
    std::vector<ScheduledWOTSCheck> checks;
};

/** Prepare one share against an already fully validated exact context. */
[[nodiscard]] std::optional<ScheduledWOTSCheck>
PrepareChainLockShareVerification(
    const ChainLockShare& share,
    const PreparedChainLockContext& context,
    ChainLockVerificationError* error = nullptr);

/**
 * Canonical fixed-width Merkle commitments for frozen quorum state.
 *
 * Both trees contain exactly 512 leaves. Slots [0, 399] commit the roster;
 * slots [400, 511] are domain-separated padding leaves. Leaf and internal-node
 * hashes bind the genesis hash, epoch, slot or level, and tree position.
 */
[[nodiscard]] uint256 ComputeQuorumMemberRoot(const uint256& genesis_hash,
                                              const FrozenQuorumRoster& roster);
[[nodiscard]] uint256 ComputeQuorumChildKeyRoot(const uint256& genesis_hash,
                                                const FrozenQuorumRoster& roster);

/** Monotonic operation count used by deterministic performance regressions. */
[[nodiscard]] uint64_t GetQuorumRootTaggedHashCountForTesting() noexcept;

[[nodiscard]] ChainLockShareTranscript BuildChainLockShareTranscript(
    const FinalChainLock& chainlock,
    const QuorumDescriptor& descriptor,
    uint16_t member_index,
    const uint256& member_pro_tx_hash);

[[nodiscard]] std::optional<CompactChainLockShare>
BuildCompactChainLockShare(
    const ChainLockShare& share,
    const PreparedChainLockContext& context);

[[nodiscard]] std::optional<ChainLockShare> ExpandCompactChainLockShare(
    const CompactChainLockShare& compact,
    const PreparedChainLockContext& context);

/**
 * Perform every bounded structural, roster, root, context, and signer mapping
 * check and produce exactly FINAL_SIGNATURE_COUNT independent WOTS+ jobs.
 * No WOTS+ hash computation is performed by this function.
 */
/** Prepare a final certificate against an intrinsically verified roster set. */
[[nodiscard]] std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerification(
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const VerifiedRosterSet& roster_set,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error = nullptr);

/** Prepare a final witness against an already validated exact statement. */
[[nodiscard]] std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerification(
    const FinalChainLock& chainlock,
    const PreparedChainLockContext& context,
    ChainLockVerificationError* error = nullptr);

/**
 * Execute independent signature jobs. A null queue selects fail-fast serial
 * verification. A caller-supplied queue may have zero or more worker threads;
 * its start/stop lifetime must contain this call.
 */
[[nodiscard]] bool VerifyScheduledWOTSChecks(std::vector<ScheduledWOTSCheck>&& checks,
                                            ScheduledWOTSCheckQueue* queue = nullptr);

/** RAII-owned queue. Destruction joins all workers; callers must not race it. */
class ChainLockVerifier final {
public:
    static constexpr std::size_t DEFAULT_SUCCESS_CACHE_CAPACITY{4'096};

    explicit ChainLockVerifier(
        std::size_t worker_threads,
        unsigned int batch_size = 8,
        std::size_t success_cache_capacity = DEFAULT_SUCCESS_CACHE_CAPACITY);
    ~ChainLockVerifier();

    ChainLockVerifier(const ChainLockVerifier&) = delete;
    ChainLockVerifier& operator=(const ChainLockVerifier&) = delete;
    ChainLockVerifier(ChainLockVerifier&&) = delete;
    ChainLockVerifier& operator=(ChainLockVerifier&&) = delete;

    [[nodiscard]] bool VerifyChecks(std::vector<ScheduledWOTSCheck>&& checks)
        EXCLUSIVE_LOCKS_REQUIRED(!m_preflight_mutex);

    [[nodiscard]] uint64_t GetSuccessCacheMissCountForTesting() const;

private:
    mutable Mutex m_preflight_mutex;
    FastRandomContext m_preflight_rng GUARDED_BY(m_preflight_mutex);
    // Declared before the queue so it outlives destruction of queued checks.
    std::unique_ptr<ScheduledWOTSSuccessCache> m_success_cache;
    ScheduledWOTSCheckQueue m_queue;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_VERIFY_H
