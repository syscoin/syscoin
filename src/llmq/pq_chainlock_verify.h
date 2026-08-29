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
#include <random.h>
#include <sync.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace llmq::pq {

class FrozenQuorumRosterCache;

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
};

struct FrozenQuorumRoster {
    QuorumDescriptor descriptor;
    std::array<FrozenQuorumMember, QUORUM_SIZE> members;
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
    QUORUM_CONTEXT_MISMATCH,
    INVALID_AUTHORIZATION,
    INVALID_SIGNER,
    INVALID_CHILD_PROOF,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE,
};

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
    friend class PreparedChainLockContext;
};

using VerifiedRosterSetPtr = std::shared_ptr<const VerifiedRosterSet>;

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
    Create(const uint256& genesis_hash,
           ChainLockScheduleConfig schedule,
           ChainLockStatement statement,
           FrozenQuorumRostersPtr rosters,
           uint8_t authorization_mask,
           ChainLockVerificationError* error = nullptr);

    [[nodiscard]] static std::shared_ptr<const PreparedChainLockContext>
    Create(ChainLockScheduleConfig schedule,
           ChainLockStatement statement,
           VerifiedRosterSetPtr roster_set,
           uint8_t authorization_mask,
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
    [[nodiscard]] std::optional<std::size_t> FindQuorumSlot(
        const ChainLockShareTranscript& transcript) const noexcept;

private:
    PreparedChainLockContext(
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        VerifiedRosterSetPtr roster_set,
        uint8_t authorization_mask);

    ChainLockScheduleConfig m_schedule;
    ChainLockStatement m_statement;
    VerifiedRosterSetPtr m_roster_set;
    uint8_t m_authorization_mask{0};
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
    scheduled_wots::PublicKey m_public_key;
    uint8_t m_leaf_index{0};
    scheduled_wots::Message m_message;
    scheduled_wots::Signature m_signature;
};

using ScheduledWOTSCheckQueue = CCheckQueue<ScheduledWOTSCheck>;

struct PreparedChainLockVerification {
    std::vector<ScheduledWOTSCheck> checks;
};

/** Validate all four immutable rosters and their statement context. */
[[nodiscard]] bool ValidateFrozenQuorumContext(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error = nullptr);

/** Cheap/contextual preparation for one private quorum share. */
[[nodiscard]] std::optional<ScheduledWOTSCheck> PrepareChainLockShareVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error = nullptr);

/** Prepare one share against an already fully validated exact context. */
[[nodiscard]] std::optional<ScheduledWOTSCheck>
PrepareChainLockShareVerification(
    const ChainLockShare& share,
    const PreparedChainLockContext& context,
    ChainLockVerificationError* error = nullptr);

[[nodiscard]] bool VerifyChainLockShare(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
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

/**
 * Perform every bounded structural, roster, root, context, and signer mapping
 * check and produce exactly FINAL_SIGNATURE_COUNT independent WOTS+ jobs.
 * No WOTS+ hash computation is performed by this function.
 */
[[nodiscard]] std::optional<PreparedChainLockVerification> PrepareFinalChainLockVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error = nullptr);

/** Prepare a final certificate against an intrinsically verified roster set. */
[[nodiscard]] std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerification(
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const VerifiedRosterSet& roster_set,
    uint8_t authorization_mask,
    ChainLockVerificationError* error = nullptr);

/**
 * Execute independent signature jobs. A null queue selects fail-fast serial
 * verification. A caller-supplied queue may have zero or more worker threads;
 * its start/stop lifetime must contain this call.
 */
[[nodiscard]] bool VerifyScheduledWOTSChecks(std::vector<ScheduledWOTSCheck>&& checks,
                                            ScheduledWOTSCheckQueue* queue = nullptr);

[[nodiscard]] bool VerifyFinalChainLock(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ScheduledWOTSCheckQueue* queue = nullptr,
    ChainLockVerificationError* error = nullptr);

/** RAII-owned queue. Destruction joins all workers; callers must not race it. */
class ChainLockVerifier final {
public:
    explicit ChainLockVerifier(std::size_t worker_threads, unsigned int batch_size = 8);
    ~ChainLockVerifier();

    ChainLockVerifier(const ChainLockVerifier&) = delete;
    ChainLockVerifier& operator=(const ChainLockVerifier&) = delete;
    ChainLockVerifier(ChainLockVerifier&&) = delete;
    ChainLockVerifier& operator=(ChainLockVerifier&&) = delete;

    [[nodiscard]] bool Verify(
        const uint256& genesis_hash,
        const ChainLockScheduleConfig& schedule,
        const FinalChainLock& chainlock,
        const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
        uint8_t authorization_mask,
        ChainLockVerificationError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_preflight_mutex);

    [[nodiscard]] bool VerifyChecks(std::vector<ScheduledWOTSCheck>&& checks)
        EXCLUSIVE_LOCKS_REQUIRED(!m_preflight_mutex);

private:
    mutable Mutex m_preflight_mutex;
    FastRandomContext m_preflight_rng GUARDED_BY(m_preflight_mutex);
    ScheduledWOTSCheckQueue m_queue;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_VERIFY_H
